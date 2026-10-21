//! `horus knowledge` — query the local `.horus/index/` project-knowledge snapshot built by
//! `horus init` (HOR-294). Offline / local-only: never touches Cloud (except `status --cloud`,
//! which appends the knowledge-cloud comparison). Port of `packages/cli/src/commands/knowledge.ts`.
//!
//! Snapshot items are walked as JSON values, mirroring the TS `Record<string, unknown>` access.

use std::path::{Path, PathBuf};

use anyhow::Result;
use horus_core::{find_repo_root, get_head_sha, is_working_tree_dirty};
use horus_knowledge::{
    create_json_knowledge_store, knowledge_path, search_snapshot, KnowledgeFile, KnowledgeManifest, KnowledgeSnapshot,
    SearchOptions, KNOWLEDGE_CATEGORIES,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, cyan, dim, green, red, yellow};

pub async fn run(args: &KnowledgeArgs) -> Result<()> {
    let code = match &args.command {
        KnowledgeCommand::Status(a) => {
            let local = run_knowledge_status(None)?;
            let cloud = if a.cloud { i32::from(crate::commands::knowledge_cloud::run_knowledge_cloud_status().await?) } else { 0 };
            if local != 0 { local } else { cloud }
        }
        KnowledgeCommand::Search { query } => run_knowledge_search(query, None)?,
        KnowledgeCommand::Contracts { name } => run_knowledge_contracts(name, None)?,
        KnowledgeCommand::Trace { query } => run_knowledge_trace(query, None)?,
        KnowledgeCommand::Ask { question } => run_knowledge_ask(question, None)?,
        KnowledgeCommand::Validate => run_knowledge_validate()?,
        // push/pull are dispatched to knowledge_cloud by commands::dispatch.
        _ => unreachable!("knowledge push/pull are handled by knowledge_cloud"),
    };
    if code != 0 {
        return Err(SilentExit(code as u8).into());
    }
    Ok(())
}

fn resolve_root() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_default();
    find_repo_root(&cwd).unwrap_or(cwd)
}

fn no_index_message(root: &Path) {
    println!("{}", yellow("No project-knowledge index found."));
    println!("{}", dim(&format!("  Expected {}/.horus/index/. Run {} to build one.", root.display(), bold("horus init"))));
}

struct Loaded {
    root: PathBuf,
    snapshot: Value,
    typed: KnowledgeSnapshot,
    manifest: Option<KnowledgeManifest>,
}

fn load() -> Result<Option<Loaded>> {
    let root = resolve_root();
    let store = create_json_knowledge_store(&root);
    if !store.exists() {
        return Ok(None);
    }
    let Some(typed) = store.read_snapshot()? else { return Ok(None) };
    let manifest = store.read_manifest()?;
    Ok(Some(Loaded { root, snapshot: serde_json::to_value(&typed)?, typed, manifest }))
}

fn short(sha: Option<&str>) -> String {
    match sha {
        Some(s) if !s.is_empty() => s.chars().take(8).collect(),
        _ => "—".into(),
    }
}

/// Staleness/dirty warnings comparing the index's git state to the working tree.
fn staleness_warnings(root: &Path, manifest: Option<&KnowledgeManifest>) -> Vec<String> {
    let mut warnings = Vec::new();
    let indexed = manifest.and_then(|m| m.git.as_ref()).and_then(|g| g.sha.clone()).filter(|s| !s.is_empty());
    let current = get_head_sha(Some(root)).filter(|s| !s.is_empty());
    if let (Some(i), Some(c)) = (&indexed, &current) {
        if i != c {
            warnings.push(format!(
                "index is stale: built at {}, repo is now at {} — re-run `horus init`",
                short(Some(i)),
                short(Some(c))
            ));
        }
    }
    if is_working_tree_dirty(Some(root)) == Some(true) {
        warnings.push("working tree is dirty (uncommitted changes) — knowledge may not reflect local edits".into());
    }
    warnings
}

fn print_warnings(warnings: &[String]) {
    for w in warnings {
        println!("{}", yellow(&format!("⚠ {w}")));
    }
}

/// JS truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// JS `String(v)` / template interpolation (`undefined` for a missing key).
fn js(v: &Value) -> String {
    match v {
        Value::Null => "undefined".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(|x| if x.is_null() { String::new() } else { js(x) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
        other => horus_core::json::to_js_json(other).unwrap_or_default(),
    }
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or_default()
}

fn str_list(v: &Value) -> Vec<String> {
    arr(v).iter().map(js).collect()
}

fn provenance_ref(item: &Value) -> String {
    let p = &item["provenance"];
    if !p.is_object() {
        return String::new();
    }
    let mut parts = Vec::new();
    if let Some(s) = p["filePath"].as_str() {
        parts.push(s.to_string());
    }
    if let Some(s) = p["sourceType"].as_str() {
        parts.push(s.to_string());
    }
    if let Some(s) = p["confidence"].as_str() {
        parts.push(format!("{s} confidence"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        dim(&format!("    ↳ {}", parts.join(" · ")))
    }
}

fn print_ref(item: &Value) {
    let r = provenance_ref(item);
    if !r.is_empty() {
        println!("{r}");
    }
}

// ── status ──────────────────────────────────────────────────────────────────

pub fn run_knowledge_status(root: Option<&Path>) -> Result<i32> {
    let root = root.map(Path::to_path_buf).unwrap_or_else(resolve_root);
    let store = create_json_knowledge_store(&root);
    if !store.exists() {
        no_index_message(&root);
        return Ok(0);
    }
    let (Some(manifest), Some(_snapshot)) = (store.read_manifest()?, store.read_snapshot()?) else {
        println!("{}", red("Knowledge index is present but unreadable. Run `horus knowledge validate`."));
        return Ok(1);
    };

    println!("{}", bold("Project knowledge index"));
    if let Some(p) = manifest.project.as_deref().filter(|p| !p.is_empty()) {
        println!("  project:        {p}");
    }
    let version = manifest.generator.version.as_deref().filter(|v| !v.is_empty()).map(|v| format!("@{v}")).unwrap_or_default();
    println!("  generator:      {}{version}", manifest.generator.tool);
    println!("  schema version: {}", manifest.schema_version);
    println!("  generated:      {}", manifest.generated_at);
    let git = manifest.git.as_ref();
    let branch = git.and_then(|g| g.branch.as_deref()).filter(|b| !b.is_empty()).map(|b| format!(" ({b})")).unwrap_or_default();
    println!("  last commit:    {}{branch}", short(git.and_then(|g| g.sha.as_deref())));

    let counts: Vec<String> = manifest.counts.iter().filter(|(_, n)| **n > 0).map(|(k, n)| format!("{k}: {n}")).collect();
    let total: u64 = manifest.counts.values().sum();
    let counts = if counts.is_empty() { "empty".to_string() } else { counts.join(", ") };
    println!("  items:          {total} ({counts})");

    let warnings = staleness_warnings(&root, Some(&manifest));
    if warnings.is_empty() {
        println!("{}", green("  ✓ up to date with HEAD"));
    } else {
        println!();
        print_warnings(&warnings);
    }
    println!(
        "{}",
        dim(&format!("\nNext: {} · {}", bold("horus knowledge search \"<query>\""), bold("horus knowledge validate")))
    );
    Ok(0)
}

// ── search ──────────────────────────────────────────────────────────────────

pub fn run_knowledge_search(query: &str, limit: Option<usize>) -> Result<i32> {
    let Some(loaded) = load()? else {
        no_index_message(&resolve_root());
        return Ok(1);
    };
    let matches = search_snapshot(&loaded.typed, query, &SearchOptions { categories: None, limit: Some(limit.unwrap_or(25)) });
    if matches.is_empty() {
        println!("{}", yellow(&format!("No matches for \"{query}\".")));
        println!("{}", dim("Try a broader term, or run `horus init` if the project changed."));
        return Ok(0);
    }
    println!("{}", bold(&format!("{} match(es) for \"{query}\":", matches.len())));
    for m in &matches {
        println!("  {} {} {}", cyan(&format!("[{}]", m.category.as_str())), bold(&m.name), dim(&m.id));
        print_ref(&m.item);
    }
    let warnings = staleness_warnings(&loaded.root, loaded.manifest.as_ref());
    if !warnings.is_empty() {
        println!();
        print_warnings(&warnings);
    }
    Ok(0)
}

// ── contracts ─────────────────────────────────────────────────────────────────

fn auth_suffix(required: &Value, roles: &Value) -> String {
    let roles = str_list(roles);
    let roles = if roles.is_empty() { String::new() } else { format!(" [{}]", roles.join(", ")) };
    format!("{}{roles}", if truthy(required) { "required" } else { "public" })
}

fn typed_field(f: &Value) -> String {
    format!("{}: {}{}", js(&f["name"]), js(&f["type"]), if f["nullable"] == Value::Bool(false) { "!" } else { "" })
}

fn kind_suffix(v: &Value) -> String {
    if truthy(&v["kind"]) { dim(&format!(" ({})", js(&v["kind"]))) } else { String::new() }
}

pub fn run_knowledge_contracts(name: &str, _limit: Option<usize>) -> Result<i32> {
    let Some(loaded) = load()? else {
        no_index_message(&resolve_root());
        return Ok(1);
    };
    let needle = name.trim().to_lowercase();
    let snap = &loaded.snapshot;
    let field_has = |item: &Value, k: &str| {
        let s = if item[k].is_null() { String::new() } else { js(&item[k]) };
        s.to_lowercase().contains(&needle)
    };
    let matches = |item: &Value| field_has(item, "name") || field_has(item, "subject") || field_has(item, "id");
    let mut found = 0;

    for o in arr(&snap["operations"]).iter().filter(|o| matches(o)) {
        println!("  {} {}{}", cyan("operation"), bold(&js(&o["name"])), kind_suffix(o));
        if truthy(&o["domain"]) {
            println!("{}", dim(&format!("    domain: {}", js(&o["domain"]))));
        }
        let args = arr(&o["args"]);
        if !args.is_empty() {
            println!("    args: {}", args.iter().map(typed_field).collect::<Vec<_>>().join(", "));
        }
        if truthy(&o["returnType"]) {
            println!("    returns: {}", js(&o["returnType"]));
        }
        if o["auth"].is_object() {
            println!("    auth: {}", auth_suffix(&o["auth"]["required"], &o["auth"]["roles"]));
        }
        print_ref(o);
        found += 1;
    }
    for t in arr(&snap["types"]).iter().filter(|t| matches(t)) {
        println!("  {} {}{}", cyan("type"), bold(&js(&t["name"])), kind_suffix(t));
        for f in arr(&t["fields"]) {
            println!("    {}", typed_field(f));
        }
        print_ref(t);
        found += 1;
    }
    for e in arr(&snap["enums"]).iter().filter(|e| matches(e)) {
        println!("  {} {}", cyan("enum"), bold(&js(&e["name"])));
        let values = str_list(&e["values"]);
        println!("    values: {}", if values.is_empty() { "—".to_string() } else { values.join(" | ") });
        print_ref(e);
        found += 1;
    }
    for a in arr(&snap["authRules"]).iter().filter(|a| matches(a)) {
        println!("  {} {} — {}", cyan("auth rule"), bold(&js(&a["subject"])), auth_suffix(&a["required"], &a["roles"]));
        found += 1;
    }

    if found == 0 {
        println!("{}", yellow(&format!("No contracts matching \"{name}\".")));
        println!("{}", dim("`horus knowledge search` searches all categories."));
        return Ok(0);
    }
    print_warnings(&staleness_warnings(&loaded.root, loaded.manifest.as_ref()));
    Ok(0)
}

// ── trace ─────────────────────────────────────────────────────────────────────

pub fn run_knowledge_trace(query: &str, _limit: Option<usize>) -> Result<i32> {
    let Some(loaded) = load()? else {
        no_index_message(&resolve_root());
        return Ok(1);
    };
    let snap = &loaded.snapshot;
    let q = query.trim().to_lowercase();
    let lc = |v: &Value| if v.is_null() { String::new() } else { js(v).to_lowercase() };
    let named = |a: &Value| arr(a).iter().find(|i| lc(&i["name"]).contains(&q) || lc(&i["slug"]).contains(&q)).cloned();
    let warnings = || print_warnings(&staleness_warnings(&loaded.root, loaded.manifest.as_ref()));

    // Prefer a domain concept (it carries explicit related links), else an operation.
    if let Some(c) = named(&snap["domainConcepts"]) {
        println!("{}", bold(&format!("Concept: {}", js(&c["name"]))));
        if truthy(&c["summary"]) {
            println!("{}", dim(&format!("  {}", js(&c["summary"]))));
        }
        let ops = str_list(&c["relatedOperations"]);
        let types = str_list(&c["relatedTypes"]);
        if !ops.is_empty() {
            println!("  → operations: {}", ops.join(", "));
        }
        if !types.is_empty() {
            println!("  → types: {}", types.join(", "));
        }
        warnings();
        return Ok(0);
    }

    if let Some(op) = named(&snap["operations"]) {
        let op_name = js(&op["name"]);
        println!("{}", bold(&format!("Operation: {op_name}")));
        if truthy(&op["returnType"]) {
            println!("  → returns: {}", js(&op["returnType"]));
        }
        let used_by: Vec<String> = arr(&snap["domainConcepts"])
            .iter()
            .filter(|c| c["relatedOperations"].is_array() && str_list(&c["relatedOperations"]).contains(&op_name))
            .map(|c| js(&c["name"]))
            .collect();
        if !used_by.is_empty() {
            println!("  ← concepts: {}", used_by.join(", "));
        }
        warnings();
        return Ok(0);
    }

    // Fall back to any data flow whose name matches.
    if let Some(flow) = named(&snap["dataFlows"]) {
        println!("{}", bold(&format!("Data flow: {}", js(&flow["name"]))));
        for s in arr(&flow["steps"]) {
            let action = if truthy(&s["action"]) { format!(": {}", js(&s["action"])) } else { String::new() };
            println!("  → {}{action}", js(&s["component"]));
        }
        return Ok(0);
    }

    println!("{}", yellow(&format!("Nothing to trace for \"{query}\".")));
    println!("{}", dim("Trace walks domain concepts, operations, and data flows. Try `horus knowledge search`."));
    Ok(0)
}

// ── ask ───────────────────────────────────────────────────────────────────────

pub fn run_knowledge_ask(question: &str, limit: Option<usize>) -> Result<i32> {
    let Some(loaded) = load()? else {
        no_index_message(&resolve_root());
        return Ok(1);
    };
    let limit = limit.unwrap_or(8);
    // Grounded retrieval: answer ONLY from indexed items. Search the whole question, then each
    // significant term (split on /[^a-z0-9_]+/, ≥4 chars), merging by id.
    let lower = question.to_lowercase();
    let mut terms = vec![question.to_string()];
    terms.extend(
        lower
            .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .filter(|t| t.encode_utf16().count() >= 4)
            .map(str::to_string),
    );
    let mut seen = std::collections::HashSet::new();
    let mut hits = Vec::new();
    for term in &terms {
        for m in search_snapshot(&loaded.typed, term, &SearchOptions { categories: None, limit: Some(10) }) {
            if seen.insert(m.id.clone()) {
                hits.push(m);
            }
        }
        if hits.len() >= limit {
            break;
        }
    }

    println!("{}", bold(&format!("Q: {question}")));
    if hits.is_empty() {
        println!("{}", yellow("No indexed knowledge matched this question."));
        println!("{}", dim("This answer is grounded only in the local index. Run `horus init` or try `horus knowledge search`."));
        return Ok(0);
    }
    println!("{}", dim("Grounded in the local knowledge index (no external model):"));
    for m in hits.iter().take(limit) {
        println!("  {} {}", cyan(&format!("[{}]", m.category.as_str())), bold(&m.name));
        print_ref(&m.item);
    }
    let first = hits.first().map_or("", |m| m.name.as_str());
    println!("{}", dim(&format!("\nNext: {} for exact fields.", bold(&format!("horus knowledge contracts \"{first}\"")))));
    print_warnings(&staleness_warnings(&loaded.root, loaded.manifest.as_ref()));
    Ok(0)
}

// ── validate ──────────────────────────────────────────────────────────────────

pub fn run_knowledge_validate() -> Result<i32> {
    let root = resolve_root();
    let store = create_json_knowledge_store(&root);
    if !store.exists() {
        no_index_message(&root);
        return Ok(1);
    }
    let mut issues = Vec::new();

    // Snapshot parses against the schema.
    let snapshot = store.read_snapshot().unwrap_or_else(|err| {
        issues.push(format!("knowledge-base.json failed schema validation: {err:#}"));
        None
    });
    // Manifest parses.
    let manifest = store.read_manifest().unwrap_or_else(|err| {
        issues.push(format!("manifest.json failed schema validation: {err:#}"));
        None
    });

    if let (Some(manifest), Some(snapshot)) = (&manifest, &snapshot) {
        // Content hash of knowledge-base.json matches the manifest.
        let recorded = manifest.files.iter().find(|f| f.name == "knowledge-base.json").and_then(|f| f.content_hash.as_deref());
        if let Some(recorded) = recorded.filter(|r| !r.is_empty()) {
            let raw = std::fs::read_to_string(knowledge_path(&root, KnowledgeFile::KnowledgeBase))?;
            if hex::encode(Sha256::digest(raw.as_bytes())) != recorded {
                issues.push("knowledge-base.json content hash does not match the manifest (file modified after write)".into());
            }
        }
        // Counts agree.
        let snap = serde_json::to_value(snapshot)?;
        for cat in KNOWLEDGE_CATEGORIES {
            let key = cat.as_str();
            let actual = arr(&snap[key]).len() as u64;
            if let Some(expected) = manifest.counts.get(key) {
                if *expected != actual {
                    issues.push(format!("count mismatch for {key}: manifest says {expected}, snapshot has {actual}"));
                }
            }
        }
    }

    if !issues.is_empty() {
        println!("{}", red(&format!("✗ knowledge index invalid ({} issue(s)):", issues.len())));
        for i in &issues {
            println!("{}", red(&format!("  - {i}")));
        }
        return Ok(1);
    }

    let schema = manifest.as_ref().map_or("undefined".to_string(), |m| m.schema_version.to_string());
    let total: u64 = manifest.as_ref().map_or(0, |m| m.counts.values().sum());
    println!("{}{}", green("✓ knowledge index is valid"), dim(&format!(" (schema v{schema}, {total} items)")));
    print_warnings(&staleness_warnings(&root, manifest.as_ref()));
    Ok(0)
}
