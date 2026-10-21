//! Port of `packages/cli/src/commands/queues.ts` — static queue topology (local DB) plus live
//! BullMQ / broker state (`--live`).

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use horus_ai::InterpretationPromptKind;
use horus_connectors::{
    additional_queues_for_env, queue_database_for_env, queue_for_env, BullMQRuntimeProvider, Provider, QueueCounts,
    QueueRuntimeProvider,
};
use horus_core::json::{to_js_json_pretty, to_js_value};
use horus_core::{filter_queue_edges, load_config, redact_error_message, resolve_environment, HorusConfig, ResolveOptions, ResolvedEnvironment};
use horus_db::{is_db_unavailable, list_queue_edges, open_db, QueueEdge};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use crate::lib::cloud::session::repo_root_or_cwd;
use crate::lib::command_failure::fail_command;
use crate::lib::format::{bold, dim, red, yellow};
use crate::lib::freshness::read_index_meta;

pub const QUEUES_AI_CONTRACT: &str = "Provide a clearly separated AI evidence narration with:

Evidence used
- Queue names, waiting/active/failed/delayed counts, and producer/worker mappings Horus found

What stands out
- Queues with high failed counts, unexpected backlog, or paused state
- Runtime-only queues (live in Redis, no static producer/worker mapping)
- Producer/worker mismatches or orphaned queues

What this may indicate
- Use \"may suggest\", \"is consistent with\", or \"could indicate\" — never \"proves\"
- Do not invent queue names, Redis keys, or job data not in the evidence

What is not proven
- Claims about job contents, specific error messages, or data inside failed jobs

Next checks
- Exact Horus commands or Redis/BullMQ checks to inspect next";

/// Dim note shown when this build ships without local persistence.
const DB_UNAVAILABLE_NOTE: &str = "local persistence unavailable in this build — static queue topology skipped (install via npm or Homebrew for it; --live still reads Redis)";

/// How --live explains a missing queue connector — a statement of what the config needs.
const NO_QUEUE_CONNECTOR_MSG: &str = "Live queue state needs a queues-role Redis connector in the config (a connectors.redis stanza with a bullmq/queues database role).";

const ALL_FILTERED_NOTE: &str = "No production queues detected — the indexed queue edges look like test fixtures or implausible names.";

pub async fn run(args: &QueuesArgs) -> Result<()> {
    match run_inner(args).await {
        Ok(()) => Ok(()),
        Err(e) => Err(fail_command(e, args.json)),
    }
}

async fn run_inner(args: &QueuesArgs) -> Result<()> {
    let config = load_config(args.config.as_deref().map(Path::new), None)?;
    let db = open_db().await?;
    let result = run_with_db(args, &config, &db).await;
    db.end().await;
    result
}

async fn run_with_db(args: &QueuesArgs, config: &HorusConfig, db: &horus_db::DbHandle) -> Result<()> {
    let name = args.name.as_deref();
    // Scope the topology to the ACTIVE project (unscoped when unresolvable).
    let project = resolve_environment(config, &ResolveOptions::default()).ok().map(|r| r.project);

    // The static topology lives in the local database; a display-only DB degrades to none.
    let mut db_unavailable = false;
    let raw_rows: Vec<QueueEdge> = match list_queue_edges(db, project.as_deref(), name).await {
        Ok(r) => r,
        Err(e) if is_db_unavailable(&e) => {
            db_unavailable = true;
            vec![]
        }
        Err(e) => return Err(e),
    };
    let raw_len = raw_rows.len();
    // Queue-edge hygiene (canonical rules in horus-core's queue_hygiene).
    let rows = filter_queue_edges(raw_rows);
    let all_filtered = raw_len > 0 && rows.is_empty();
    // Zero rows over an EXISTING index = no production queues; only an unindexed repo is told to init.
    let has_fresh_index = read_index_meta(&repo_root_or_cwd(None)).is_some();

    // HOR-343: a named queue with no static topology is likely dynamically registered.
    let show_live = args.live || (name.is_some() && rows.is_empty());
    let by_queue = build_queue_map(&rows);

    if args.json {
        let mut out = Map::new();
        out.insert("project".into(), json!(project));
        out.insert("topology".into(), topology_to_json(&by_queue));
        if db_unavailable {
            out.insert("note".into(), json!(DB_UNAVAILABLE_NOTE));
        } else if all_filtered {
            out.insert("note".into(), json!(ALL_FILTERED_NOTE));
        } else if raw_len == 0 && has_fresh_index {
            out.insert("note".into(), json!("No production queues found in this repo."));
        }
        if show_live {
            out.insert("live".into(), gather_live_state(config, &by_queue, name).await?);
        }
        println!("{}", to_js_json_pretty(&Value::Object(out))?);
        return Ok(());
    }

    // ── Source topology ──
    println!(
        "{}{}",
        bold("Queue topology"),
        dim("  ·  source: code / source intelligence  ·  static (run horus init to refresh)")
    );
    println!();

    if rows.is_empty() {
        let msg = if db_unavailable {
            format!("  {DB_UNAVAILABLE_NOTE}")
        } else if let Some(n) = name {
            format!("  No static topology for \"{n}\" — it may be dynamically registered; showing live state below.")
        } else if all_filtered {
            format!("  {ALL_FILTERED_NOTE}")
        } else if has_fresh_index {
            "  No production queues found in this repo.".into()
        } else {
            "  No queue edges indexed. Run: horus init".into()
        };
        println!("{}", dim(&msg));
    } else {
        print_topology(&by_queue);
    }

    // ── Live queue state ──
    println!();
    if show_live {
        run_live_mode(config, &by_queue, name, args).await?;
    } else if has_queue_connector(config) {
        // Only suggest --live when the config actually has a queue-capable connector.
        println!("{}", dim("  Tip: run horus queues --live to show real-time queue counts and consumer offsets."));
        if args.ai {
            println!("{}", dim("  Tip: --ai is most useful with --live (horus queues --live --ai)."));
        }
    }
    Ok(())
}

/// Whether the loaded config has a Redis connector with a queue-capable DB (or Kafka / Service Bus).
fn has_queue_connector(config: &HorusConfig) -> bool {
    match resolve_environment(config, &ResolveOptions::default()) {
        Ok(renv) => {
            renv.connectors.kafka.is_some()
                || renv.connectors.azure_service_bus.is_some()
                || (renv.connectors.redis.is_some() && queue_database_for_env(&renv).is_some())
        }
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Topology helpers
// ---------------------------------------------------------------------------

/// Edges grouped by queue name, first-seen order (JS `Map`).
fn build_queue_map(rows: &[QueueEdge]) -> IndexMap<String, Vec<&QueueEdge>> {
    let mut by_queue: IndexMap<String, Vec<&QueueEdge>> = IndexMap::new();
    for row in rows {
        by_queue.entry(row.queue_name.clone()).or_default().push(row);
    }
    by_queue
}

/// Distinct `{symbol, file}` pairs for a queue's producers or workers (first file wins).
fn endpoints(edges: &[&QueueEdge], worker: bool) -> Value {
    let mut seen: IndexMap<String, Value> = IndexMap::new();
    for e in edges {
        let (sym, file) = if worker { (&e.worker_symbol, &e.worker_file) } else { (&e.producer_symbol, &e.producer_file) };
        let Some(sym) = sym.as_deref().filter(|s| !s.is_empty()) else { continue };
        seen.entry(sym.to_string()).or_insert_with(|| json!({ "symbol": sym, "file": file }));
    }
    Value::Array(seen.into_values().collect())
}

/// Structured static topology for --json.
fn topology_to_json(by_queue: &IndexMap<String, Vec<&QueueEdge>>) -> Value {
    Value::Array(
        by_queue
            .iter()
            .map(|(q, edges)| json!({ "queueName": q, "producers": endpoints(edges, false), "workers": endpoints(edges, true) }))
            .collect(),
    )
}

fn print_topology(by_queue: &IndexMap<String, Vec<&QueueEdge>>) {
    for (queue_name, edges) in by_queue {
        println!("{}", bold(queue_name));
        for (label, worker) in [("producers", false), ("workers", true)] {
            // Distinct symbols in first-seen order; the LAST non-null file per symbol wins (TS Map.set).
            let mut files: IndexMap<String, Option<String>> = IndexMap::new();
            for e in edges {
                let (sym, file) = if worker { (&e.worker_symbol, &e.worker_file) } else { (&e.producer_symbol, &e.producer_file) };
                let Some(sym) = sym.as_deref().filter(|s| !s.is_empty()) else { continue };
                let slot = files.entry(sym.to_string()).or_insert(None);
                if let Some(f) = file.as_deref().filter(|f| !f.is_empty()) {
                    *slot = Some(f.to_string());
                }
            }
            if files.is_empty() {
                println!("  {label}: {}", dim("none"));
            } else {
                let list: Vec<String> =
                    files.iter().map(|(s, f)| match f { Some(f) => format!("{s} ({f})"), None => s.clone() }).collect();
                println!("  {label}: {}", list.join(", "));
            }
        }
        println!();
    }
}

// ---------------------------------------------------------------------------
// Live mode
// ---------------------------------------------------------------------------

struct BrokerState {
    id: String,
    ok: bool,
    evidence: Vec<horus_core::Evidence>,
    error: Option<String>,
}

impl BrokerState {
    fn to_json(&self) -> Result<Value> {
        let mut o = Map::new();
        o.insert("id".into(), json!(self.id));
        o.insert("ok".into(), json!(self.ok));
        o.insert("evidence".into(), to_js_value(&self.evidence)?);
        if let Some(e) = &self.error {
            o.insert("error".into(), json!(e));
        }
        Ok(Value::Object(o))
    }
}

/// Kafka / Service Bus evidence, filtered to `name` (or `name/…`) when given.
async fn gather_broker_state(renv: &ResolvedEnvironment, name: Option<&str>) -> Result<Vec<BrokerState>> {
    let mut out = Vec::new();
    for p in additional_queues_for_env(renv)? {
        out.push(match p.collect().await {
            Ok(ev) => BrokerState {
                id: p.id().to_string(),
                ok: true,
                evidence: ev
                    .into_iter()
                    .filter(|e| match (name, e.links.queue_name.as_deref()) {
                        (None, _) => true,
                        (Some(n), Some(q)) => q == n || q.starts_with(&format!("{n}/")),
                        (Some(_), None) => false,
                    })
                    .collect(),
                error: None,
            },
            Err(e) => BrokerState { id: p.id().to_string(), ok: false, evidence: vec![], error: Some(redact_error_message(&e)) },
        });
    }
    Ok(out)
}

/// Queue names to probe: the filter, else the UNION of static + live-discovered names (static
/// first, JS Set order), else None (= provider discovers).
async fn probe_names(provider: &BullMQRuntimeProvider, static_names: &[String], name: Option<&str>) -> Option<Vec<String>> {
    if let Some(n) = name {
        return Some(vec![n.to_string()]);
    }
    let discovered = provider.discover_queues().await.unwrap_or_default();
    let mut seen: HashSet<String> = HashSet::new();
    let union: Vec<String> = static_names.iter().chain(discovered.iter()).filter(|n| seen.insert((*n).clone())).cloned().collect();
    if union.is_empty() { None } else { Some(union) }
}

fn queues_json(queues: &[QueueCounts], static_names: &HashSet<&str>) -> Result<Value> {
    let mut out = Vec::new();
    for q in queues {
        let mut v = to_js_value(q)?;
        if let Value::Object(o) = &mut v {
            o.insert("runtimeOnly".into(), json!(!static_names.contains(q.queue_name.as_str())));
        }
        out.push(v);
    }
    Ok(Value::Array(out))
}

/// Gather live BullMQ state as structured data (shared by --live --json).
async fn gather_live_state(config: &HorusConfig, by_queue: &IndexMap<String, Vec<&QueueEdge>>, name: Option<&str>) -> Result<Value> {
    let renv = match resolve_environment(config, &ResolveOptions::default()) {
        Ok(r) => r,
        Err(e) => return Ok(json!({ "ok": false, "error": format!("{e:#}") })),
    };
    let queue_provider = queue_for_env(&renv)?;
    let providers = gather_broker_state(&renv, name).await?;
    let providers_ok = providers.iter().all(|p| p.ok);
    let providers_json: Vec<Value> = providers.iter().map(BrokerState::to_json).collect::<Result<_>>()?;

    let Some(qp) = queue_provider else {
        return Ok(if providers.is_empty() {
            json!({ "ok": false, "error": NO_QUEUE_CONNECTOR_MSG })
        } else {
            json!({ "ok": providers_ok, "providers": providers_json })
        });
    };
    let result = async {
        let health = qp.health().await;
        if !health.ok {
            let mut o = Map::new();
            o.insert("ok".into(), json!(false));
            o.insert("error".into(), json!(health.detail));
            if !providers_json.is_empty() {
                o.insert("providers".into(), Value::Array(providers_json.clone()));
            }
            return Ok(Value::Object(o));
        }
        let static_list: Vec<String> = by_queue.keys().cloned().collect();
        let static_names: HashSet<&str> = static_list.iter().map(String::as_str).collect();
        let names = probe_names(&qp, &static_list, name).await;
        let state = qp.analyze_queues(names.as_deref()).await?;
        let mut o = Map::new();
        o.insert("ok".into(), json!(providers_ok));
        if !providers_json.is_empty() {
            o.insert("providers".into(), Value::Array(providers_json.clone()));
        }
        o.insert("prefix".into(), json!(state.prefix));
        o.insert("collectedAt".into(), json!(state.collected_at));
        o.insert("queues".into(), queues_json(&state.queues, &static_names)?);
        Ok::<_, anyhow::Error>(Value::Object(o))
    }
    .await;
    qp.close().await;
    result
}

fn live_header_plain() -> String {
    format!("{}{}", bold("Live queue state"), dim("  ·  source: Redis/BullMQ"))
}

/// `new Date(iso).toLocaleTimeString()` (en-US: `4:06:12 PM`).
fn locale_time(iso: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|d| d.with_timezone(&chrono::Local).format("%-I:%M:%S %p").to_string())
        .unwrap_or_else(|_| "Invalid Date".into())
}

async fn run_live_mode(config: &HorusConfig, by_queue: &IndexMap<String, Vec<&QueueEdge>>, name: Option<&str>, args: &QueuesArgs) -> Result<()> {
    let renv = match resolve_environment(config, &ResolveOptions::default()) {
        Ok(r) => r,
        Err(e) => {
            println!("{}", live_header_plain());
            println!("{}", yellow(&format!("  ⚠ Cannot resolve environment: {e:#}")));
            return Ok(());
        }
    };
    let ai_opts = |evidence: Value| AiInterpretationOpts {
        command: "queues",
        evidence,
        prompt_kind: InterpretationPromptKind::EvidenceSummary,
        output_contract: QUEUES_AI_CONTRACT,
        user_intent: None,
        config: args.config.as_deref(),
        model_override: args.ai_model.as_deref(),
    };

    let queue_provider = queue_for_env(&renv)?;
    let providers = gather_broker_state(&renv, name).await?;
    for p in &providers {
        println!("{}", bold(&format!("Live queue state · {}", p.id)));
        if let Some(err) = p.error.as_deref().filter(|_| !p.ok) {
            println!("{}", red(&format!("  {err}")));
        }
        for e in &p.evidence {
            println!("  {}\n  {}", e.title, horus_core::json::to_js_json(&e.payload)?);
        }
    }
    if queue_provider.is_none() && !providers.is_empty() {
        if args.ai {
            let evidence = Value::Array(providers.iter().map(BrokerState::to_json).collect::<Result<_>>()?);
            let result = crate::lib::ai_provider::render_ai_interpretation(ai_opts(evidence)).await;
            println!("{}", horus_ai::render_interpretation(&result));
        }
        return Ok(());
    }
    let Some(qp) = queue_provider else {
        println!("{}", live_header_plain());
        println!("{}", yellow(&format!("  ○ {NO_QUEUE_CONNECTOR_MSG}")));
        return Ok(());
    };

    let mut header_printed = false;
    let outcome = async {
        let health = qp.health().await;
        if !health.ok {
            println!("{}", live_header_plain());
            println!("{}", red(&format!("  ✗ Redis unreachable: {}", health.detail)));
            return Ok(None);
        }
        // Probe the UNION of statically-known and live-discovered queues (see probe_names).
        let static_list: Vec<String> = by_queue.keys().cloned().collect();
        let names = probe_names(&qp, &static_list, name).await;
        let state = qp.analyze_queues(names.as_deref()).await?;
        println!(
            "{}{}",
            bold("Live queue state"),
            dim(&format!("  ·  source: Redis/BullMQ (prefix: {})  ·  collected: {}", state.prefix, locale_time(&state.collected_at)))
        );
        header_printed = true;
        println!();
        if state.queues.is_empty() {
            println!("{}", dim("  No queues found in Redis."));
            println!("{}", dim("  If queues exist under a custom prefix, set the BullMQ prefix in your connector config."));
            return Ok(None);
        }
        let static_names: HashSet<&str> = static_list.iter().map(String::as_str).collect();
        print_live_table(&state.queues, &static_names);
        Ok::<_, anyhow::Error>(Some((state, static_list)))
    }
    .await;

    match outcome {
        Ok(Some((state, static_list))) if args.ai => {
            let static_names: HashSet<&str> = static_list.iter().map(String::as_str).collect();
            let evidence = json!({
                "prefix": state.prefix,
                "collectedAt": state.collected_at,
                "queues": queues_json(&state.queues, &static_names)?,
            });
            print_ai_interpretation(ai_opts(evidence)).await;
        }
        Ok(_) => {}
        Err(e) => {
            if !header_printed {
                println!("{}", live_header_plain());
            }
            println!("{}", red(&format!("  ✗ {e:#}")));
        }
    }
    qp.close().await;
    Ok(())
}

fn print_live_table(queues: &[QueueCounts], static_names: &HashSet<&str>) {
    let name_width = queues.iter().map(|q| q.queue_name.chars().count()).max().unwrap_or(0).max(10);
    let w = 7;
    let header = format!(
        "  {:<name_width$}  {:>w$}  {:>w$}  {:>w$}  {:>w$}  {:>w$}",
        "queue", "waiting", "active", "failed", "delayed", "paused"
    );
    println!("{}", dim(&header));
    println!("{}", dim(&format!("  {}", "─".repeat(header.chars().count() - 2))));

    for q in queues {
        let has_issue = q.failed > 0 || q.waiting > 100 || q.delayed > 50 || q.is_paused;
        let paused = if q.is_paused { yellow("paused") } else { format!("{:>w$}", q.paused) };
        let row = format!(
            "  {:<name_width$}  {:>w$}  {:>w$}  {:>w$}  {:>w$}  {paused}",
            q.queue_name, q.waiting, q.active, q.failed, q.delayed
        );
        println!("{}", if has_issue { yellow(&row) } else { row });

        // Live in Redis but no static producer/worker mapping.
        if !static_names.contains(q.queue_name.as_str()) {
            println!("{}", dim("    runtime-only · no static producer/worker mapping"));
        }
        if let Some(ms) = q.oldest_waiting_ms {
            println!("{}", dim(&format!("    oldest waiting: {}", format_age(ms))));
        }
        // Newest failure age tells a live failure from a stale pile (HOR-217); 1h cutoff.
        if let Some(ms) = q.newest_failed_age_ms {
            let line = format!("    most recent failure: {} ago", format_age(ms));
            println!("{}", if ms > 3_600_000.0 { yellow(&format!("{line} [STALE]")) } else { dim(&line) });
        }
        for fb in q.failed_breakdown.iter().flatten().take(3) {
            let mut suffix = String::new();
            if let Some(ms) = fb.last_failed_age_ms {
                suffix = dim(&format!(" (last {} ago)", format_age(ms)));
                if ms > 3_600_000.0 {
                    suffix.push_str(&yellow(" [STALE]"));
                }
            }
            println!("{}{suffix}", red(&format!("    ✗ [{}x] {}", fb.count, fb.reason)));
        }
    }
    println!();
}

fn format_age(ms: f64) -> String {
    let round = |x: f64| horus_engine::js::int_string(horus_engine::js::math_round(x));
    if ms < 60_000.0 {
        format!("{}s", round(ms / 1000.0))
    } else if ms < 3_600_000.0 {
        format!("{}m", round(ms / 60_000.0))
    } else if ms < 86_400_000.0 {
        format!("{}h", round(ms / 3_600_000.0))
    } else {
        format!("{}d", round(ms / 86_400_000.0))
    }
}
