//! Port of `packages/cli/src/commands/investigate.ts`.

use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{anyhow, bail, Result};
use horus_ai::contract::{
    NarrativeCauseItem, NarrativeEvidenceItem, NarrativeFinding, NarrativeHypothesisItem, NarrativeInput,
    NarrativeOutput, RenderNarrativeOptions,
};
use horus_ai::{render_narrative, AnthropicNarrativeProvider, AnthropicProviderOptions};
use horus_core::json::{to_js_json, to_js_json_pretty, to_js_value};
use horus_core::{load_config, resolve_ai_settings, resolve_environment, ResolveOptions, ShopifyQueryKind, ShopifyQuerySpec};
use horus_engine::js::{iso_now, slice_chars, to_fixed};
use horus_engine::render::{render_report, report_to_json, report_to_markdown};
use horus_engine::types::{provider_kind_name, InvestigationReport, StoredAIJudgment};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::cloud::context_store::{is_cloud_active, read_cloud_config};
use crate::lib::cloud::session::{authed_client, repo_root_or_cwd};
use crate::lib::command_failure::fail_command;
use crate::lib::format::{bold, dim, green, red, yellow};
use crate::lib::freshness::{commits_since, compute_freshness, read_index_meta, render_freshness, FreshnessEvidence, FreshnessOpts};
use crate::lib::investigation_runner::{
    build_investigation_context, dispose_investigation_context, js_number, run_one_investigation, BuildContextOptions,
    RunInvestigationInput,
};

static WINDOW_VAR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$(from|to)\b").expect("static regex"));
static EXT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.[^.]+$").expect("static regex"));

/// Resolve `--shopify-query` values into query specs supplied to the investigation. Each value
/// is `@path` (read the file), `-` (read stdin), or a raw GraphQL string. `--shopify-variables`
/// (`@file` or inline JSON object) applies to every query. `bind_window` auto-enables when a
/// query references `$from`/`$to`, so the engine injects the investigation window. The query
/// text is executed verbatim — never rewritten. Errors on an unreadable file / bad JSON.
pub fn resolve_shopify_queries(values: &[String], variables_raw: Option<&str>) -> Result<Vec<ShopifyQuerySpec>> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let variables = parse_shopify_variables(variables_raw)?;
    let mut stdin_cache: Option<String> = None;
    values
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let value = raw.trim();
            let mut name = format!("q{}", i + 1);
            let query = if value == "-" {
                if stdin_cache.is_none() {
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s)?;
                    stdin_cache = Some(s);
                }
                name = "stdin".into();
                stdin_cache.clone().unwrap_or_default()
            } else if let Some(path) = value.strip_prefix('@') {
                let q = std::fs::read_to_string(path).map_err(|e| anyhow!("{e}: {path}"))?;
                let base = Path::new(path).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
                let stem = EXT_RE.replace(&base, "").into_owned();
                if !stem.is_empty() {
                    name = stem;
                }
                q
            } else {
                raw.clone()
            };
            let bind_window = WINDOW_VAR_RE.is_match(&query).then_some(true);
            Ok(ShopifyQuerySpec {
                name,
                query,
                variables: variables.clone(),
                kind: ShopifyQueryKind::State,
                relevance: None,
                bind_window,
            })
        })
        .collect()
}

/// Parse `--shopify-variables` (`@file` or inline JSON) into a variables object, or None.
fn parse_shopify_variables(raw: Option<&str>) -> Result<Option<Map<String, Value>>> {
    let Some(raw) = raw.filter(|r| !r.trim().is_empty()) else { return Ok(None) };
    let trimmed = raw.trim();
    let text = match trimmed.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).map_err(|e| anyhow!("{e}: {path}"))?,
        None => raw.to_string(),
    };
    let parsed: Value = serde_json::from_str(&text).map_err(|_| anyhow!("--shopify-variables is not valid JSON"))?;
    match parsed {
        Value::Object(m) => Ok(Some(m)),
        _ => bail!("--shopify-variables must be a JSON object"),
    }
}

fn extract_evidence_excerpt(payload: &Value) -> Option<String> {
    let p = payload.as_object()?;
    ["pattern", "message", "label", "summary", "valueLabel"]
        .iter()
        .find_map(|k| p.get(*k).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(|s| slice_chars(s, 120))
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

pub fn build_narrative_input(report: &InvestigationReport) -> NarrativeInput {
    NarrativeInput {
        investigation_id: report.id.clone(),
        hint: report.input.hint.clone(),
        report_confidence: report.confidence,
        evidence: report
            .evidence
            .iter()
            .map(|e| NarrativeEvidenceItem {
                id: e.id.clone(),
                kind: enum_str(&e.kind),
                title: e.title.clone(),
                service: None,
                excerpt: extract_evidence_excerpt(&e.payload),
            })
            .collect(),
        known_services: report.input.service.iter().filter(|s| !s.is_empty()).cloned().collect(),
        suspected_causes: report
            .suspected_causes
            .iter()
            .map(|c| NarrativeCauseItem { label: c.title.clone(), score: c.final_score, evidence_ids: c.source_evidence_ids.clone() })
            .collect(),
        deterministic_summary: report.summary.clone(),
        findings: report
            .findings
            .iter()
            .map(|f| NarrativeFinding { title: f.title.clone(), evidence_ids: f.evidence_ids.clone() })
            .collect(),
        hypotheses: Some(
            report
                .hypotheses
                .iter()
                .filter_map(|h| {
                    Some(NarrativeHypothesisItem {
                        id: h.id.clone(),
                        category: h.category.clone(),
                        statement: h.statement.clone(),
                        deterministic_verdict: serde_json::from_value(json!(h.verdict.as_str())).ok()?,
                        deterministic_confidence: h.confidence,
                        supporting_evidence_ids: h.supporting_evidence_ids.clone(),
                    })
                })
                .collect(),
        ),
    }
}

/// Map a NarrativeOutput to the StoredAIJudgment shape for persistence.
pub fn narrative_output_to_stored_judgment(output: &NarrativeOutput, provider: &str) -> Result<StoredAIJudgment> {
    let mut j = json!({
        "what": output.what,
        "why": output.why,
        "whereNext": output.where_next,
        "citations": output.citations,
        "confidence": output.confidence,
        "provider": provider,
        "generatedAt": iso_now(),
    });
    let o = j.as_object_mut().expect("object literal");
    if let Some(v) = &output.mentioned_services {
        o.insert("mentionedServices".into(), serde_json::to_value(v)?);
    }
    if let Some(v) = &output.hypothesis_judgments {
        o.insert("hypothesisJudgments".into(), serde_json::to_value(v)?);
    }
    if let Some(v) = &output.root_cause_assessment {
        o.insert("rootCauseAssessment".into(), serde_json::to_value(v)?);
    }
    Ok(serde_json::from_value(j)?)
}

/// Render a stored AI judgment to the console.
pub fn render_stored_ai_judgment(judgment: &StoredAIJudgment, write: &dyn Fn(&str)) {
    let pct = |c: f64| to_fixed(c * 100.0, 0);
    let sep = "─".repeat(60);
    write(&format!("\n{sep}"));
    write(&format!(
        "{}{}",
        bold("AI Judgment"),
        dim(&format!(" (confidence: {}%, provider: {})", pct(judgment.confidence), judgment.provider))
    ));
    write(&sep);

    if let Some(hj) = judgment.hypothesis_judgments.as_ref().filter(|h| !h.is_empty()) {
        write(&bold("Hypothesis verdicts:"));
        for j in hj {
            let color: fn(&str) -> String = match j.verdict.as_str() {
                "supported" => green,
                "weakened" => yellow,
                "eliminated" => red,
                _ => dim,
            };
            write(&format!("  {} {}{}", color(&format!("[{}]", j.verdict)), j.category, dim(&format!(" ({}%)", pct(j.confidence)))));
            write(&dim(&format!("    {}", j.rationale)));
        }
        write("");
    }

    if let Some(rca) = &judgment.root_cause_assessment {
        let color: fn(&str) -> String = match rca.uncertainty.as_str() {
            "low" => green,
            "medium" => yellow,
            _ => red,
        };
        write(&format!("{}{}", bold("Root cause assessment:"), dim(&format!(" uncertainty: {}", color(&rca.uncertainty)))));
        write(&rca.summary);
        if !rca.cited_evidence_ids.is_empty() {
            write(&dim(&format!("  Cited: {}", rca.cited_evidence_ids.join(", "))));
        }
        write("");
    }

    write(&format!("{} {}", bold("What:"), judgment.what));
    write(&format!("{} {}", bold("Why:"), judgment.why));
    if !judgment.where_next.is_empty() {
        write(&bold("Next steps:"));
        for step in &judgment.where_next {
            write(&format!("  • {step}"));
        }
    }
    if !judgment.citations.is_empty() {
        let ids: Vec<&str> = judgment.citations.iter().map(|c| c.evidence_id.as_str()).collect();
        write(&dim(&format!("\nCited evidence: {}", ids.join(", "))));
    }
}

static AI_KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)401|unauthorized|api.key|api key").expect("re"));
static AI_REQ_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)invalid.request|model|not.found").expect("re"));
static AI_NET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)econnrefused|enotfound|network|fetch|abort").expect("re"));

/// Classify an AI provider failure reason into a user-readable string.
pub fn classify_ai_failure(first_error: Option<&str>) -> String {
    let Some(e) = first_error.filter(|e| !e.is_empty()) else { return "provider unavailable".into() };
    if AI_KEY_RE.is_match(e) {
        return "missing or invalid API key — set ANTHROPIC_API_KEY".into();
    }
    if AI_REQ_RE.is_match(e) {
        return format!("invalid model or request — {e}");
    }
    if AI_NET_RE.is_match(e) {
        return "network error — check connectivity".into();
    }
    e.to_string()
}

/// Insert `key` only when `v` is present — JSON.stringify drops `undefined`-valued keys.
fn put(o: &mut Map<String, Value>, key: &str, v: Option<&Value>) {
    if let Some(v) = v {
        o.insert(key.into(), v.clone());
    }
}

fn arr_len(v: Option<&Value>) -> Option<usize> {
    v.and_then(Value::as_array).map(Vec::len)
}

/// Compact the JSON projection of an investigation report IN PLACE — the agent-facing default.
/// Keeps counts + bounded tops + truncation metadata; `--full` skips this and restores the raw
/// report.
pub fn compact_investigate_json(obj: &mut Map<String, Value>) {
    // Evidence payloads/snippets carry raw source strings — keep citable metadata only.
    // `{ ...rest, payload: '…' }` moves `payload` to the END of each object.
    if let Some(Value::Array(ev)) = obj.get_mut("evidence") {
        for e in ev.iter_mut() {
            if let Value::Object(m) = e {
                m.shift_remove("payload");
                m.insert("payload".into(), json!("[omitted — re-run with --full]"));
            }
        }
    }

    // recentChanges → bounded projection: counts, top commits WITHOUT file lists, and the top
    // changed files by churn (from fileStats).
    let compact_rc = obj.get("recentChanges").and_then(Value::as_object).and_then(|rc| {
        let commits_all = rc.get("commits")?.as_array()?;
        const COMMIT_CAP: usize = 10;
        const FILE_CAP: usize = 15;
        let commits: Vec<Value> = commits_all
            .iter()
            .take(COMMIT_CAP)
            .map(|c| {
                let short = c.get("shortSha").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| {
                    let sha = c.get("sha").and_then(Value::as_str).unwrap_or("");
                    json!(sha.chars().take(7).collect::<String>())
                });
                let mut m = Map::new();
                m.insert("shortSha".into(), short);
                put(&mut m, "dateIso", c.get("dateIso"));
                put(&mut m, "author", c.get("author"));
                put(&mut m, "subject", c.get("subject"));
                m.insert("fileCount".into(), json!(arr_len(c.get("files")).unwrap_or(0)));
                Value::Object(m)
            })
            .collect();
        let churn = |f: &Value| {
            f.get("insertions").and_then(Value::as_f64).unwrap_or(0.0) + f.get("deletions").and_then(Value::as_f64).unwrap_or(0.0)
        };
        let mut top: Vec<Value> = rc.get("fileStats").and_then(Value::as_array).cloned().unwrap_or_default();
        // Stable sort, churn desc (Array#sort is stable).
        top.sort_by(|a, b| churn(b).partial_cmp(&churn(a)).unwrap_or(std::cmp::Ordering::Equal));
        top.truncate(FILE_CAP);
        let omitted = commits_all.len() - commits.len();

        let mut out = Map::new();
        put(&mut out, "window", rc.get("window"));
        out.insert("commitCount".into(), json!(commits_all.len()));
        let changed = arr_len(rc.get("changedFiles")).or_else(|| arr_len(rc.get("fileStats"))).unwrap_or(0);
        out.insert("changedFileCount".into(), json!(changed));
        put(&mut out, "totalInsertions", rc.get("totalInsertions"));
        put(&mut out, "totalDeletions", rc.get("totalDeletions"));
        put(&mut out, "degenerate", rc.get("degenerate"));
        out.insert("commits".into(), Value::Array(commits));
        out.insert("topChangedFiles".into(), Value::Array(top));
        if omitted > 0 {
            out.insert("truncated".into(), json!(true));
            out.insert("truncatedCount".into(), json!(omitted));
            out.insert("hint".into(), json!("re-run with --full for the complete structure"));
        } else {
            put(&mut out, "truncated", rc.get("truncated"));
        }
        put(&mut out, "truncatedReason", rc.get("truncatedReason"));
        Some(Value::Object(out))
    });
    if let Some(rc) = compact_rc {
        obj.insert("recentChanges".into(), rc);
    }

    // graph → counts only; the full node/edge lists are a --full concern.
    let graph = obj.get("graph").and_then(Value::as_object).and_then(|g| {
        let (nodes, edges) = (arr_len(g.get("nodes")), arr_len(g.get("edges")));
        (nodes.is_some() || edges.is_some()).then(|| {
            json!({
                "nodeCount": nodes.unwrap_or(0),
                "edgeCount": edges.unwrap_or(0),
                "hint": "re-run with --full for nodes/edges",
            })
        })
    });
    if let Some(g) = graph {
        obj.insert("graph".into(), g);
    }
}

pub async fn run(args: &InvestigateArgs) -> Result<()> {
    let json_mode = args.json || args.format == "json";
    // Validate the output format BEFORE any work — `--format xml` used to silently fall back
    // to text after a full investigation ran (dogfood).
    let requested = if args.json { "json" } else { args.format.as_str() };
    if !["text", "json", "markdown", "md"].contains(&requested) {
        eprintln!("{}", red(&format!("Unknown format \"{requested}\". Valid: text, json, markdown.")));
        return Err(SilentExit(1).into());
    }
    match run_inner(args).await {
        Ok(()) => Ok(()),
        Err(e) if e.downcast_ref::<SilentExit>().is_some() => Err(e),
        Err(e) => {
            // Never fail silently: surface a message even when the error carries none, and
            // include the chain under HORUS_DEBUG. Route through the shared machine-JSON failure
            // contract so `--json` still emits ONE parseable object on stdout.
            let msg = format!("{e:#}");
            let detail = if msg.trim().is_empty() { "Investigation failed (unknown error).".to_string() } else { msg };
            let code = fail_command(anyhow!(detail), json_mode);
            if std::env::var_os("HORUS_DEBUG").is_some() {
                eprintln!("{}", dim(&format!("{e:?}")));
            }
            Err(code)
        }
    }
}

async fn run_inner(args: &InvestigateArgs) -> Result<()> {
    let json_mode = args.json || args.format == "json";
    let config = load_config(args.config.as_deref().map(Path::new), None)?;

    // Resolve any invocation-time Shopify queries before wiring — a bad path or malformed
    // variables JSON should fail fast with a clear message, not mid-run.
    let shopify_queries = match resolve_shopify_queries(&args.shopify_query, args.shopify_variables.as_deref()) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("{}", red(&format!("--shopify-query: {e}")));
            return Err(SilentExit(1).into());
        }
    };

    // --repo selects a repository/project WITHIN this config; default = cwd inference.
    let renv = match resolve_environment(
        &config,
        &ResolveOptions { project: args.repo.as_deref(), env: args.env.as_deref(), cwd: None },
    ) {
        Ok(r) => r,
        Err(e) => return Err(fail_command(e, json_mode)),
    };

    let repo_root = repo_root_or_cwd(Some(Path::new(&renv.path)));
    let cloud_cfg = read_cloud_config(&repo_root);
    let cloud_active = is_cloud_active(cloud_cfg.as_ref());
    let cloud_session = if cloud_active { authed_client() } else { None };
    if cloud_active && cloud_session.is_none() {
        // Horus Cloud is OPTIONAL — never block a local investigation on it.
        eprintln!(
            "{}",
            yellow(&format!(
                "This repo is linked to Horus Cloud but you are not logged in — running locally only. Run {} to also sync results to the cloud.",
                bold("horus login")
            ))
        );
    }

    // Build the connector deps + open the DB via the shared runner: self-heals a down source
    // host, degrades to runtime-only when it stays down, and resolves every runtime connector.
    // `horus watch` reuses the exact same wiring — do not duplicate it.
    let ctx = match build_investigation_context(
        renv,
        BuildContextOptions { database_url: &config.database.url, service: args.service.clone(), ..Default::default() },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return Err(fail_command(e, json_mode)),
    };

    let cloud = match (&cloud_session, &cloud_cfg) {
        (Some(sess), Some(cfg)) if cloud_active => Some((&sess.client, cfg)),
        _ => None,
    };
    let result = investigate_with(args, &ctx, shopify_queries, &config, &repo_root, cloud).await;
    // Close EVERY connector + the DB.
    dispose_investigation_context(ctx).await;
    result
}

async fn investigate_with(
    args: &InvestigateArgs,
    ctx: &crate::lib::investigation_runner::InvestigationContext,
    shopify_queries: Vec<ShopifyQuerySpec>,
    config: &horus_core::HorusConfig,
    repo_root: &Path,
    cloud: Option<(&crate::lib::cloud::api::CloudClient, &crate::lib::cloud::context_store::CloudConfig)>,
) -> Result<()> {
    // Overall deadline so an unreachable/slow connector can never hang the investigation.
    let timeout_sec = {
        let flag = args.timeout.as_deref().map(js_number).unwrap_or(0.0);
        let env = std::env::var("HORUS_INVESTIGATE_TIMEOUT_S").map(|v| js_number(&v)).unwrap_or(f64::NAN);
        let truthy = |n: f64| !n.is_nan() && n != 0.0;
        if truthy(flag) { flag } else if truthy(env) { env } else { 120.0 }
    };
    let mut report = run_one_investigation(
        RunInvestigationInput {
            hint: args.hint.clone(),
            scope: args.scope.clone(),
            since: args.since.clone(),
            logs_since: args.logs_since.clone(),
            shopify_queries: (!shopify_queries.is_empty()).then_some(shopify_queries),
            ..Default::default()
        },
        ctx,
        Some((timeout_sec * 1000.0) as u64),
    )
    .await?;

    // --json is back-compat for --format json.
    let format = if args.json { "json" } else { args.format.as_str() };
    // HOR-362: how fresh are the inputs behind this report?
    let fmeta = read_index_meta(repo_root);
    let commits_since_index = match fmeta.as_ref().and_then(|m| m.last_indexed_at.as_deref()).filter(|s| !s.is_empty()) {
        Some(at) => commits_since(repo_root, at).await,
        None => None,
    };
    let evidence: Vec<FreshnessEvidence> = report
        .evidence
        .iter()
        .map(|e| FreshnessEvidence { source: Some(provider_kind_name(e.source).to_string()), timestamp: e.timestamp.clone() })
        .collect();
    let now = iso_now();
    let freshness = compute_freshness(FreshnessOpts {
        repo_root,
        evidence: &evidence,
        now_iso: &now,
        meta: Some(fmeta),
        commits_since_index,
        any_runtime_connector: Some(report.source_status.as_ref().is_some_and(|s| s.sources.iter().any(|x| x.configured))),
    });

    if format == "json" {
        let mut obj: Map<String, Value> = serde_json::from_str(&report_to_json(&report))?;
        obj.insert("freshness".into(), to_js_value(&freshness)?);
        // Compact by default (agent-facing) — `--full` restores the raw report.
        if !args.full {
            compact_investigate_json(&mut obj);
        }
        println!("{}", to_js_json_pretty(&obj)?);
    } else {
        println!("{}", if format == "markdown" || format == "md" { report_to_markdown(&report) } else { render_report(&report) });
        println!();
        println!("{}", render_freshness(&freshness));
    }

    if args.ai && format != "json" {
        // AI settings saved via `horus connect ai` (key + model), ANTHROPIC_API_KEY as fallback.
        // CLI --ai-model overrides the saved model.
        let ai = resolve_ai_settings(config);
        let model = args.ai_model.clone().or(ai.model).unwrap_or_else(|| "claude-opus-4-8".into());
        let provider = AnthropicNarrativeProvider::new(AnthropicProviderOptions {
            api_key: ai.anthropic_api_key,
            model: Some(model.clone()),
            base_url: None,
        });
        println!("{}", dim(&format!("[ai] model: {model}")));

        let narrative_input = build_narrative_input(&report);
        let res = render_narrative(&narrative_input, RenderNarrativeOptions { provider: Some(&provider), confidence_ceiling: None }).await;

        if res.from_provider {
            // Persist AI judgment in the report and update DB (HOR-198).
            let stored = narrative_output_to_stored_judgment(&res.output, "anthropic")?;
            report.ai_judgment = Some(stored.clone());
            if let Ok(body) = to_js_json(&report) {
                // best-effort — display still works even if DB update fails
                let _ = horus_db::update_investigation_report(&ctx.db, &report.id, &body).await;
            }
            render_stored_ai_judgment(&stored, &|l| println!("{l}"));
        } else if res.degraded == Some(true) {
            // The model produced usable prose that didn't fully validate — show it in a
            // clearly-labeled unstructured section rather than discarding it (HOR-213).
            if res.validation_errors.as_ref().is_some_and(|v| !v.is_empty()) {
                eprintln!("{}", yellow("[ai] structured validation incomplete — showing raw AI narrative"));
            }
            println!();
            println!("{}", dim(&"─".repeat(60)));
            println!("{}{}", bold("AI narrative "), yellow("(unstructured — not validated)"));
            if !res.output.what.trim().is_empty() {
                println!("{} {}", bold("\nWhat:"), res.output.what.trim());
            }
            if !res.output.why.trim().is_empty() {
                println!("{} {}", bold("\nWhy:"), res.output.why.trim());
            }
            if !res.output.where_next.is_empty() {
                println!("{}", bold("\nNext:"));
                for a in &res.output.where_next {
                    println!("  - {a}");
                }
            }
        } else {
            let first = res.validation_errors.as_ref().and_then(|v| v.first()).map(String::as_str);
            eprintln!("{}", yellow(&format!("[ai] fallback to deterministic — {}", classify_ai_failure(first))));
        }
    }

    // Tier-A usage signal: shape + confidence + gaps only, no report bodies (HOR-324).
    {
        let rv = serde_json::to_value(&report)?;
        let len = |k: &str| rv.get(k).and_then(serde_json::Value::as_array).map_or(0, Vec::len);
        let confidence = rv.get("confidence").filter(|v| v.is_number()).cloned().unwrap_or(serde_json::Value::Null);
        let truthy = |v: Option<&serde_json::Value>| match v {
            None | Some(serde_json::Value::Null) | Some(serde_json::Value::Bool(false)) => false,
            Some(serde_json::Value::String(s)) => !s.is_empty(),
            Some(serde_json::Value::Number(n)) => n.as_f64() != Some(0.0),
            Some(_) => true,
        };
        crate::lib::telemetry::client::track(serde_json::json!({
            "type": "investigation.completed",
            "investigationId": rv.get("id"),
            "confidence": confidence,
            "evidenceCount": len("evidence"),
            "findingCount": len("findings"),
            "suspectedCauseCount": len("suspectedCauses"),
            "degraded": truthy(rv.get("degraded")),
            "gapCount": rv.pointer("/gapAnalysis/gaps").and_then(serde_json::Value::as_array).map_or(0, Vec::len),
            "hasAi": truthy(rv.get("aiJudgment")),
        }));

        // Tier-B (explicit content opt-in): redacted inputs/outputs (HOR-325). Every field is
        // scrubbed; the hint is fail-closed (dropped if a secret survives) → send nothing.
        if crate::lib::telemetry::consent::is_content_sharing_enabled() {
            let hint = horus_core::redact_or_drop(rv.pointer("/input/hint").and_then(serde_json::Value::as_str).unwrap_or(""));
            if !hint.dropped {
                let titles = |k: &str| -> Vec<String> {
                    rv.get(k)
                        .and_then(serde_json::Value::as_array)
                        .map(|a| {
                            a.iter()
                                .take(20)
                                .map(|f| horus_core::redact_content(f.get("title").and_then(serde_json::Value::as_str).unwrap_or("")))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                crate::lib::telemetry::client::track(serde_json::json!({
                    "type": "investigation.content",
                    "investigationId": rv.get("id"),
                    "hint": hint.value.unwrap_or_default(),
                    "summary": horus_core::redact_content(rv.get("summary").and_then(serde_json::Value::as_str).unwrap_or("")),
                    "findingTitles": titles("findings"),
                    "suspectedCauseTitles": titles("suspectedCauses"),
                    "confidence": confidence,
                }));
            }
        }

        if cloud.is_some() && !crate::lib::cloud::api::cloud_writes_enabled() {
            // Writes switched off (HORUS_RUST_CLOUD_WRITE=0): keep the run local instead of failing it like an outage.
            eprintln!("{}", dim("[cloud] upload skipped — Cloud writes are off (HORUS_RUST_CLOUD_WRITE=0)"));
        } else if let Some((client, cfg)) = cloud {
            // Pass the local db so a recorded human outcome label (HOR-390) rides the sync.
            let upload = crate::lib::cloud::investigation_sync::upload_investigation_to_cloud(
                client,
                cfg,
                &rv,
                crate::lib::cloud::investigation_sync::UploadOpts { db: Some(&ctx.db), ..Default::default() },
            )
            .await;
            match upload {
                Ok(refs) => {
                    // Never write the human notice to STDOUT under --json — it corrupts the output.
                    let note = dim(&format!("[cloud] investigation saved: {}", refs.investigation_id));
                    if format == "json" {
                        eprintln!("{note}");
                    } else {
                        println!("{note}");
                    }
                }
                Err(err) => {
                    let code = crate::commands::context::report_cloud_error(&err);
                    return Err(crate::commands::SilentExit(code).into());
                }
            }
        }
    }

    // HOR-319 (Bug 1): point the user at the id that `horus ask` accepts.
    if format != "json" {
        if report.persisted == Some(false) {
            // DB-resilient degrade (HOR-319): the store was unreachable, so the report wasn't saved.
            eprintln!("{}", yellow("\n⚠ Results were not saved — the investigation database was unreachable."));
            eprintln!(
                "{}",
                dim("  This report is display-only; `horus ask` won't find it. Start the database and re-run to persist.")
            );
        } else {
            println!("{}", dim(&format!("\nAsk a follow-up:  horus ask {} \"<question>\"", report.id)));
        }
        // Shared footer nudge (HOR-431 / HOR-439).
        println!("{}", dim("  Wrong cause? Teach Horus:  horus feedback"));
        println!("{}", dim("  Bug or gap? File an issue:  horus report"));
    }
    Ok(())
}
