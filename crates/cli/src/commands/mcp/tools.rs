//! Horus MCP knowledge tools (HOR-295). Port of `packages/cli/src/commands/mcp/tools.ts`.
//!
//! A transport-agnostic tool layer over the local `.horus/index/` snapshot — the same query
//! layer behind `horus knowledge`. Each tool is a pure function of (args, repo root); every
//! result carries provenance + staleness. Offline / local-only — never touches Horus Cloud.

use std::path::Path;

use horus_core::{get_head_sha, is_working_tree_dirty};
use horus_engine::router::{route, RouterCommand, RouterConditions};
use horus_engine::types::RouteStep;
use horus_knowledge::{create_json_knowledge_store, search_snapshot, KnowledgeManifest, KnowledgeSnapshot, SearchOptions};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::commands::report_issue::{build_issue, IssueOpts};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Staleness {
    pub indexed_sha: Option<String>,
    pub current_sha: Option<String>,
    pub stale: bool,
    pub dirty: bool,
}

pub struct ToolResult {
    pub ok: bool,
    /// One-line human summary.
    pub summary: String,
    /// Structured payload (includes staleness + provenance-bearing items).
    pub data: Option<Value>,
    /// HOR-386 — deterministic next-tool suggestions from the SHARED router.
    pub suggested_next_tools: Option<Vec<RouteStep>>,
}

impl ToolResult {
    pub fn fail(summary: impl Into<String>) -> Self {
        Self { ok: false, summary: summary.into(), data: None, suggested_next_tools: None }
    }
    fn ok(summary: String, data: Value) -> Self {
        Self { ok: true, summary, data: Some(data), suggested_next_tools: None }
    }
}

/// A JSON-Schema property: (name, type, description, required).
pub type Prop = (&'static str, &'static str, Option<&'static str>, bool);

pub struct KnowledgeTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input: &'static [Prop],
    pub handler: fn(&Map<String, Value>, &Path) -> ToolResult,
}

struct Ctx {
    snapshot: KnowledgeSnapshot,
    manifest: Option<KnowledgeManifest>,
    staleness: Staleness,
}

fn staleness(root: &Path, manifest: Option<&KnowledgeManifest>) -> Staleness {
    let indexed_sha = manifest.and_then(|m| m.git.as_ref()).and_then(|g| g.sha.clone());
    let current_sha = get_head_sha(Some(root));
    let stale = matches!((&indexed_sha, &current_sha), (Some(a), Some(b)) if !a.is_empty() && !b.is_empty() && a != b);
    Staleness { indexed_sha, current_sha, stale, dirty: is_working_tree_dirty(Some(root)) == Some(true) }
}

/// Load the index; read failures are treated like a missing index (TS would throw from the store).
fn load(root: &Path) -> Option<Ctx> {
    let store = create_json_knowledge_store(root);
    if !store.exists() {
        return None;
    }
    let snapshot = store.read_snapshot().ok().flatten()?;
    let manifest = store.read_manifest().ok().flatten();
    let staleness = staleness(root, manifest.as_ref());
    Some(Ctx { snapshot, manifest, staleness })
}

fn conditions(command: RouterCommand, empty: bool, query: Option<String>, stale: bool) -> RouterConditions {
    RouterConditions {
        command,
        intent: None,
        empty,
        low_confidence: false,
        top_gap: None,
        any_runtime_connector: false,
        host_unreachable: false,
        stale_index: stale,
        degraded_source_intelligence: false,
        metrics_null: false,
        seed_name: None,
        query,
    }
}

fn no_index() -> ToolResult {
    ToolResult {
        ok: false,
        summary: "No local project-knowledge index found. Build it with `horus init` (or import one).".into(),
        data: None,
        // No index at all ⇒ the router's index remedy (rule #1 fires on `staleIndex`).
        suggested_next_tools: Some(route(&conditions(RouterCommand::McpSearch, false, None, true))),
    }
}

/// Router suggestions, or None when it has nothing to add (a healthy result stays clean).
fn suggest(command: RouterCommand, empty: bool, query: &str, st: &Staleness) -> Option<Vec<RouteStep>> {
    let steps = route(&conditions(command, empty, Some(query.to_string()), st.stale));
    (!steps.is_empty()).then_some(steps)
}

fn s<'a>(args: &'a Map<String, Value>, k: &str) -> &'a str {
    args.get(k).and_then(Value::as_str).unwrap_or("")
}

fn sv(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn match_name(item: &Value, needle: &str) -> bool {
    ["name", "subject", "slug", "id"].iter().any(|k| sv(item, k).to_lowercase().contains(needle))
}

fn values<T: Serialize>(items: &[T]) -> Vec<Value> {
    items.iter().filter_map(|i| serde_json::to_value(i).ok()).collect()
}

fn st(ctx: &Ctx) -> Value {
    serde_json::to_value(&ctx.staleness).unwrap_or(Value::Null)
}

fn matches_json(snapshot: &KnowledgeSnapshot, query: &str, limit: usize) -> Vec<Value> {
    search_snapshot(snapshot, query, &SearchOptions { categories: None, limit: Some(limit) })
        .into_iter()
        .map(|m| json!({ "category": m.category, "id": m.id, "name": m.name, "provenance": m.item.get("provenance") }))
        .collect()
}

/// Build an object omitting `None` values (JSON.stringify drops `undefined`).
fn obj(pairs: Vec<(&str, Option<Value>)>) -> Value {
    Value::Object(pairs.into_iter().filter_map(|(k, v)| v.map(|v| (k.to_string(), v))).collect())
}

fn knowledge_status(_: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    let m = ctx.manifest.as_ref();
    let sha: String = ctx.staleness.indexed_sha.clone().unwrap_or_else(|| "—".into()).chars().take(8).collect();
    let summary = format!(
        "Index for {} @ {sha}{}",
        m.and_then(|m| m.project.clone()).unwrap_or_else(|| "project".into()),
        if ctx.staleness.stale { " (STALE)" } else { "" }
    );
    let to = |v: Option<Value>| v.filter(|v| !v.is_null());
    let data = obj(vec![
        ("project", to(m.and_then(|m| m.project.clone()).map(Value::from))),
        ("schemaVersion", m.map(|m| json!(m.schema_version))),
        ("generatedAt", m.map(|m| json!(m.generated_at))),
        ("generator", m.and_then(|m| serde_json::to_value(&m.generator).ok())),
        ("branch", to(m.and_then(|m| m.git.as_ref()).and_then(|g| g.branch.clone()).map(Value::from))),
        ("counts", m.and_then(|m| serde_json::to_value(&m.counts).ok())),
        ("staleness", Some(st(&ctx))),
    ]);
    ToolResult::ok(summary, data)
}

fn project_landscape(_: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    ToolResult::ok(
        format!("{} repository profile(s).", ctx.snapshot.repositories.len()),
        json!({ "repositories": values(&ctx.snapshot.repositories), "staleness": st(&ctx) }),
    )
}

fn search_knowledge(args: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    let q = s(args, "query");
    let limit = args.get("limit").and_then(Value::as_f64).map_or(25, |n| n.max(0.0) as usize);
    let matches = matches_json(&ctx.snapshot, q, limit);
    ToolResult {
        ok: true,
        summary: format!("{} match(es) for \"{q}\".", matches.len()),
        suggested_next_tools: suggest(RouterCommand::McpSearch, matches.is_empty(), q, &ctx.staleness),
        data: Some(json!({ "matches": matches, "staleness": st(&ctx) })),
    }
}

fn ask_question(args: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    let q = s(args, "question");
    let lower = q.to_lowercase();
    let mut terms = vec![q.to_string()];
    terms.extend(lower.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')).filter(|t| t.len() >= 4).map(str::to_string));
    let mut seen: Vec<String> = Vec::new();
    let mut hits: Vec<Value> = Vec::new();
    for term in &terms {
        for m in matches_json(&ctx.snapshot, term, 10) {
            let id = sv(&m, "id");
            if !seen.contains(&id) {
                seen.push(id);
                hits.push(m);
            }
        }
        if hits.len() >= 8 {
            break;
        }
    }
    hits.truncate(8);
    ToolResult {
        ok: true,
        summary: if hits.is_empty() { "No indexed knowledge matched.".into() } else { format!("Grounded in {} indexed item(s).", hits.len()) },
        suggested_next_tools: suggest(RouterCommand::McpAsk, hits.is_empty(), q, &ctx.staleness),
        data: Some(json!({ "question": q, "grounded": true, "matches": hits, "staleness": st(&ctx) })),
    }
}

fn get_contract(args: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    let needle = s(args, "name").to_lowercase();
    let pick = |v: Vec<Value>| v.into_iter().filter(|i| match_name(i, &needle)).collect::<Vec<_>>();
    let sn = &ctx.snapshot;
    let (ops, types, enums, auth) =
        (pick(values(&sn.operations)), pick(values(&sn.types)), pick(values(&sn.enums)), pick(values(&sn.auth_rules)));
    let total = ops.len() + types.len() + enums.len() + auth.len();
    ToolResult {
        ok: true,
        summary: format!("{total} contract item(s) matching \"{}\".", s(args, "name")),
        suggested_next_tools: suggest(RouterCommand::McpContract, total == 0, s(args, "name"), &ctx.staleness),
        data: Some(json!({ "operations": ops, "types": types, "enums": enums, "authRules": auth, "staleness": st(&ctx) })),
    }
}

fn domain_concept(args: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    let needle = s(args, "name").to_lowercase();
    let concepts: Vec<Value> = values(&ctx.snapshot.domain_concepts).into_iter().filter(|i| match_name(i, &needle)).collect();
    ToolResult {
        ok: true,
        summary: format!("{} domain concept(s) matching \"{}\".", concepts.len(), s(args, "name")),
        suggested_next_tools: suggest(RouterCommand::McpDomain, concepts.is_empty(), s(args, "name"), &ctx.staleness),
        data: Some(json!({ "concepts": concepts, "staleness": st(&ctx) })),
    }
}

fn frontend_pattern(args: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    let needle = s(args, "query").to_lowercase();
    let patterns: Vec<Value> = values(&ctx.snapshot.frontend_patterns)
        .into_iter()
        .filter(|i| match_name(i, &needle) || sv(i, "kind").to_lowercase().contains(&needle))
        .collect();
    ToolResult::ok(
        format!("{} frontend pattern(s) matching \"{}\".", patterns.len(), s(args, "query")),
        json!({ "patterns": patterns, "staleness": st(&ctx) }),
    )
}

fn runtime_map(_: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    let sn = &ctx.snapshot;
    ToolResult::ok(
        format!("{} runtime component(s), {} integration(s).", sn.runtime_components.len(), sn.external_integrations.len()),
        json!({
            "runtimeComponents": values(&sn.runtime_components),
            "externalIntegrations": values(&sn.external_integrations),
            "staleness": st(&ctx),
        }),
    )
}

fn trace_data_flow(args: &Map<String, Value>, root: &Path) -> ToolResult {
    let Some(ctx) = load(root) else { return no_index() };
    let q = s(args, "query").to_lowercase();
    let sn = &ctx.snapshot;
    let find = |arr: Vec<Value>| arr.into_iter().find(|i| sv(i, "name").to_lowercase().contains(&q) || sv(i, "slug").to_lowercase().contains(&q));
    let concepts = values(&sn.domain_concepts);
    if let Some(concept) = find(concepts.clone()) {
        return ToolResult::ok(
            format!("Concept \"{}\" → operations/types.", sv(&concept, "name")),
            json!({
                "kind": "concept",
                "relatedOperations": concept.get("relatedOperations").cloned().unwrap_or(json!([])),
                "relatedTypes": concept.get("relatedTypes").cloned().unwrap_or(json!([])),
                "concept": concept,
                "staleness": st(&ctx),
            }),
        )
        .reorder(&["kind", "concept", "relatedOperations", "relatedTypes", "staleness"]);
    }
    if let Some(op) = find(values(&sn.operations)) {
        let name = sv(&op, "name");
        let used_by: Vec<Value> = concepts
            .iter()
            .filter(|c| c.get("relatedOperations").and_then(Value::as_array).is_some_and(|a| a.iter().any(|x| x.as_str() == Some(name.as_str()))))
            .map(|c| c.get("name").cloned().unwrap_or(Value::Null))
            .collect();
        return ToolResult::ok(
            format!("Operation \"{name}\" → returnType, ← concepts."),
            json!({ "kind": "operation", "operation": op, "usedByConcepts": used_by, "staleness": st(&ctx) }),
        );
    }
    if let Some(flow) = find(values(&sn.data_flows)) {
        return ToolResult::ok(
            format!("Data flow \"{}\".", sv(&flow, "name")),
            json!({ "kind": "dataFlow", "flow": flow, "staleness": st(&ctx) }),
        );
    }
    ToolResult::ok(format!("Nothing to trace for \"{}\".", s(args, "query")), json!({ "matches": [], "staleness": st(&ctx) }))
}

impl ToolResult {
    /// Reorder `data`'s keys (json! sorts nothing, but building borrowed + moved values forces
    /// a different insertion order than TS in one case).
    fn reorder(mut self, keys: &[&str]) -> Self {
        if let Some(Value::Object(m)) = self.data.take() {
            let mut out = Map::new();
            let mut m = m;
            for k in keys {
                if let Some(v) = m.shift_remove(*k) {
                    out.insert((*k).to_string(), v);
                }
            }
            out.extend(m);
            self.data = Some(Value::Object(out));
        }
        self
    }
}

fn report_issue(args: &Map<String, Value>, _root: &Path) -> ToolResult {
    let opt = |k: &str| Some(s(args, k)).filter(|v| !v.is_empty());
    let issue = build_issue(&IssueOpts { title: opt("title"), body: opt("body"), labels: opt("labels"), hint: opt("hint") });
    ToolResult::ok(
        "GitHub issue URL prepared — open it or share with the user.".into(),
        json!({
            "url": issue.url,
            "title": issue.title,
            "labels": issue.labels,
            "environment": {
                "horusVersion": issue.environment.horus_version,
                "sourceVersion": issue.environment.source_version,
                "platform": issue.environment.platform,
                "nodeVersion": issue.environment.node_version,
            },
        }),
    )
}

/// The Horus knowledge MCP tools (bound to a repo root at call time).
pub const KNOWLEDGE_TOOLS: &[KnowledgeTool] = &[
    KnowledgeTool {
        name: "get_knowledge_status",
        description: "Check whether Horus has a fresh local project-knowledge index for this repo. Call this FIRST: it reports schema version, the indexed commit, item counts, and staleness (whether the repo moved past the index or has uncommitted changes).",
        input: &[],
        handler: knowledge_status,
    },
    KnowledgeTool {
        name: "get_project_landscape",
        description: "Get the project landscape: each repository/codebase with its role, frameworks, languages, data sources, auth, and integrations — so you understand the system before reading files.",
        input: &[],
        handler: project_landscape,
    },
    KnowledgeTool {
        name: "search_project_knowledge",
        description: "Ask Horus FIRST, before grepping the repo: keyword-search the indexed operations, types, enums, domain concepts, frontend patterns, and runtime components. Returns items with provenance (file/source) and staleness.",
        input: &[("query", "string", Some("keyword or phrase"), true), ("limit", "integer", None, false)],
        handler: search_knowledge,
    },
    KnowledgeTool {
        name: "ask_project_question",
        description: "Answer a natural-language project question from indexed knowledge ONLY (grounded, no guessing): returns the most relevant indexed items with provenance. Prefer this over reading the whole repo for \"what owns X / which operation handles Y\" questions.",
        input: &[("question", "string", Some("natural-language question"), true)],
        handler: ask_question,
    },
    KnowledgeTool {
        name: "get_contract",
        description: "Get the exact API contract for a name — operations (args, return type, auth), types (fields), enums (valid values), and auth rules — verbatim from the index. Use this instead of guessing field/enum values.",
        input: &[("name", "string", Some("operation/type/enum/rule name"), true)],
        handler: get_contract,
    },
    KnowledgeTool {
        name: "get_domain_concept",
        description: "Get a domain concept / business rule by name: its summary, details, and the operations + types it relates to. Use this to understand a feature before changing it.",
        input: &[("name", "string", Some("concept name or slug"), true)],
        handler: domain_concept,
    },
    KnowledgeTool {
        name: "search_frontend_pattern",
        description: "Find an existing frontend pattern (hook, store, provider, server function, component) before writing a new one. Returns matches with their file paths.",
        input: &[("query", "string", Some("keyword (e.g. hook name or purpose)"), true)],
        handler: frontend_pattern,
    },
    KnowledgeTool {
        name: "get_runtime_component_map",
        description: "Get the runtime component map: services, workers, queues, cron jobs, and external integrations the project runs — so you know which worker/queue/service handles a job.",
        input: &[],
        handler: runtime_map,
    },
    KnowledgeTool {
        name: "trace_data_flow",
        description: "Trace known links for a topic: a domain concept → its operations/types, an operation ← the concepts that use it, or a named data flow → its steps. Use to follow how data moves across frontend/backend/runtime.",
        input: &[("query", "string", Some("concept, operation, or data-flow name"), true)],
        handler: trace_data_flow,
    },
    KnowledgeTool {
        name: "report_issue",
        description: "File a Horus bug or capability gap. When you detect that Horus is missing a capability, returns wrong results, or errors, call this to prepare a PRE-FILLED GitHub issue URL (meritt-dev/horus) with an Environment block — then open it or share it with the user. No auth, no data is sent automatically, no dedup.",
        input: &[
            ("title", "string", Some("issue title (default: derived from hint)"), false),
            ("body", "string", Some("issue body describing the bug or gap"), false),
            ("labels", "string", Some("comma-separated GitHub labels (e.g. bug,cli)"), false),
            ("hint", "string", Some("short context, e.g. the investigation or command that hit the gap"), false),
        ],
        handler: report_issue,
    },
];
