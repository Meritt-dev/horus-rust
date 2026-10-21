//! HOR-21 / HOR-204 — `horus ask`: answer a follow-up question about a saved investigation, or
//! apply a deterministic topic-filter directive. Port of `packages/cli/src/commands/ask.ts`.
//!
//! Q&A ("what evidence contradicts <topic>?", …) answers directly from the saved report; any
//! other directive is a topic filter. Code-locating questions (HOR-331) first try a FRESH lookup
//! against the source host with file:line citations.

use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::Result;
use horus_connectors::{code_for_repo, CodeProvider, Provider};
use horus_core::{load_config, resolve_environment, ResolveOptions, Symbol, SymbolContext};
use horus_db::{get_investigation, open_db};
use horus_engine::migrate_report::migrate_report;
use horus_engine::qa::{answer_question, qa_to_json, render_qa_answer};
use horus_engine::refine::refine_investigation;
use horus_engine::render_refine::{refined_to_json, render_refined};
use horus_engine::types::InvestigationReport;
use regex::Regex;
use serde_json::{Map, Value};

use crate::cli::*;
use crate::commands::context::{exit, report_cloud_error};
use crate::lib::cloud::api::cloud_status;
use crate::lib::cloud::context_store::{is_cloud_active, read_cloud_config};
use crate::lib::cloud::investigation_sync::fetch_investigation_report_from_cloud;
use crate::lib::cloud::memory_sync::{memory_sync_context, restore_memory_report};
use crate::lib::cloud::session::{authed_client, repo_root_or_cwd};
use crate::lib::format::{bold, dim, green, red};

fn render_answer(report: &InvestigationReport, directive: &str, json: bool) -> u8 {
    if let Some(answer) = answer_question(report, directive) {
        println!("{}", if json { qa_to_json(&answer) } else { render_qa_answer(&answer) });
        return 0;
    }
    let v = refine_investigation(report, directive);
    println!("{}", if json { refined_to_json(report, &v) } else { render_refined(report, &v) });
    if let (false, Some(j)) = (json, &report.ai_judgment) {
        println!();
        println!("{}", dim(&"─".repeat(60)));
        println!("{}", dim(&format!("Stored AI judgment ({}, {}):", j.provider, j.generated_at)));
        match &j.root_cause_assessment {
            Some(rca) => {
                println!("{} {}", bold("Root cause (AI):"), rca.summary);
                println!("{}", dim(&format!("Uncertainty: {}", rca.uncertainty)));
            }
            None => println!("{} {}", bold("AI Why:"), j.why),
        }
    }
    0
}

/// Classified result of a local-DB investigation lookup.
enum LocalLookup {
    Found(Box<InvestigationReport>),
    NotFound,
    NoReport,
    Error(String),
}

fn typed(report: Value) -> Result<InvestigationReport> {
    migrate_report(report)
}

/// Look up a locally-persisted report by id (the id `investigate` prints is this local id). An
/// imported or missing row first tries the authorized Cloud restore via memory sync.
async fn lookup_local_investigation(id: &str, config: Option<&str>) -> LocalLookup {
    let db = match open_db().await {
        Ok(db) => db,
        Err(e) => return LocalLookup::Error(e.to_string()),
    };
    let result: Result<LocalLookup> = async {
        let row = get_investigation(&db, id).await?;
        let imported = row
            .as_ref()
            .and_then(|r| serde_json::from_str::<Value>(&r.incident_input).ok())
            .is_some_and(|i| i.get("_horusCloudScope").is_some());
        if row.is_none() || imported {
            let restored: Result<Option<LocalLookup>> = async {
                let cfg = load_config(config.map(Path::new), None)?;
                let env = resolve_environment(&cfg, &ResolveOptions::default())?;
                let ctx = memory_sync_context(Path::new(&env.path), &env.project, Some(Instant::now() + Duration::from_millis(15_000)));
                let restored = match &ctx {
                    Some(ctx) => restore_memory_report(&db, ctx, id).await?,
                    None => None,
                };
                if let Some(r) = restored {
                    return Ok(Some(LocalLookup::Found(Box::new(typed(r)?))));
                }
                Ok((ctx.is_some() && row.is_some()).then_some(LocalLookup::NotFound))
            }
            .await;
            // Ordinary Cloud fallback below reports unavailable references.
            if let Ok(Some(found)) = restored {
                return Ok(found);
            }
            if row.is_none() {
                return Ok(LocalLookup::NotFound);
            }
        }
        let Some(report) = row.and_then(|r| r.report).and_then(|r| serde_json::from_str::<Value>(&r).ok()).filter(|r| !r.is_null())
        else {
            return Ok(LocalLookup::NoReport);
        };
        Ok(LocalLookup::Found(Box::new(typed(report)?)))
    }
    .await;
    db.end().await;
    result.unwrap_or_else(|e| LocalLookup::Error(e.to_string()))
}

// ---------------------------------------------------------------------------
// HOR-331 — fresh source lookup for code-locating questions
// ---------------------------------------------------------------------------

/// Phrases that signal a "where/how does this code live" question.
static CODE_LOCATING_PHRASES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)\bwhere\b.*\b(is|are|does|do|can\s+i\s+find|defined|declared|implemented|located|live[s]?)\b",
        r"(?i)\b(which|what)\s+file\b",
        r"(?i)\bhow\s+is\b.+\b(defined|implemented|declared|structured)\b",
        r"(?i)\bfind\b.*\b(definition|symbol|function|class|method|file)\b",
        r"(?i)\blocate\b",
    ]
    .iter()
    .map(|p| Regex::new(p).expect("valid regex"))
    .collect()
});

/// Strip surrounding punctuation that clings to a word (`processOrder?` → `processOrder`).
fn clean_token(t: &str) -> String {
    t.trim_end_matches(|c| "?.,!:;'\"()".contains(c)).trim_start_matches(|c| "?.,!:;'\"".contains(c)).to_string()
}

static RE_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\w\(\)$").unwrap());
static RE_CAMEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z][A-Z]").unwrap());
static RE_PASCAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z][a-zA-Z0-9]*[A-Z]").unwrap());
static RE_SNAKE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z]\w*_\w+$").unwrap());

/// Does `raw` look like a code identifier rather than an ordinary English word?
fn looks_like_symbol(raw: &str) -> bool {
    let t = raw.trim_end_matches(|c| "?.,!:;".contains(c));
    if RE_CALL.is_match(t) {
        return true; // foo()
    }
    let w: String = t.chars().filter(|c| !"()'\"".contains(*c)).collect();
    if w.encode_utf16().count() < 2 {
        return false;
    }
    RE_CAMEL.is_match(&w) || RE_PASCAL.is_match(&w) || RE_SNAKE.is_match(&w)
}

/// HOR-331 — a question asking WHERE/HOW code lives, or naming a symbol-like token.
pub fn is_code_locating_question(directive: &str) -> bool {
    let q = directive.trim();
    if q.is_empty() {
        return false;
    }
    CODE_LOCATING_PHRASES.iter().any(|re| re.is_match(q)) || q.split_whitespace().any(looks_like_symbol)
}

const LOCATE_STOPWORDS: &[&str] = &[
    "where", "is", "are", "was", "were", "does", "do", "did", "has", "have", "the", "a", "an", "how", "which", "what",
    "file", "files", "defined", "define", "declared", "implemented", "located", "find", "locate", "can", "i", "in", "code",
    "to", "of", "for", "that", "this", "it", "function", "class", "method", "symbol", "definition",
];

/// Reduce a natural-language question to the best `search_symbols` query.
pub fn extract_symbol_query(directive: &str) -> String {
    let raw: Vec<&str> = directive.split_whitespace().collect();
    let symbols: Vec<String> = raw.iter().filter(|t| looks_like_symbol(t)).map(|t| clean_token(t)).filter(|t| !t.is_empty()).collect();
    if !symbols.is_empty() {
        return symbols.join(" ");
    }
    let rest: Vec<String> = raw
        .iter()
        .map(|t| clean_token(t))
        .filter(|t| !t.is_empty() && !LOCATE_STOPWORDS.contains(&t.to_lowercase().as_str()))
        .collect();
    if rest.is_empty() { directive.trim().to_string() } else { rest.join(" ") }
}

/// A symbol's `file:line` (or `file:start-end`) citation.
fn symbol_location(s: &Symbol) -> String {
    let mut loc = s.file_path.clone();
    if let Some(start) = s.start_line.filter(|l| *l != 0) {
        loc += &format!(":{start}");
        if let Some(end) = s.end_line.filter(|e| *e != 0 && *e != start) {
            loc += &format!("-{end}");
        }
    }
    loc
}

fn code_answer_to_json(directive: &str, query: &str, symbols: &[Symbol], ctx: Option<&SymbolContext>) -> Value {
    let matches: Vec<Value> = symbols
        .iter()
        .map(|s| {
            let mut m = Map::new();
            m.insert("name".into(), Value::String(s.name.clone()));
            m.insert("location".into(), Value::String(symbol_location(s)));
            m.insert("filePath".into(), Value::String(s.file_path.clone()));
            if let Some(l) = s.start_line {
                m.insert("startLine".into(), l.into());
            }
            if let Some(l) = s.end_line {
                m.insert("endLine".into(), l.into());
            }
            if let Some(sig) = &s.signature {
                m.insert("signature".into(), Value::String(sig.clone()));
            }
            Value::Object(m)
        })
        .collect();
    let mut out = serde_json::json!({ "question": directive, "query": query, "source": "source-host", "matches": matches });
    if let Some(snippet) = ctx.and_then(|c| c.snippet.clone()) {
        out["snippet"] = Value::String(snippet);
    }
    out
}

fn render_code_answer(directive: &str, symbols: &[Symbol], ctx: Option<&SymbolContext>) {
    let Some(top) = symbols.first() else { return };
    println!();
    println!("{}", bold(directive));
    println!("  {} {}  {}", green("→"), bold(&top.name), dim(&symbol_location(top)));
    if let Some(sig) = top.signature.as_deref().filter(|s| !s.is_empty()) {
        println!("    {}", dim(sig));
    }
    if let Some(snippet) = ctx.and_then(|c| c.snippet.as_deref()).filter(|s| !s.is_empty()) {
        for line in snippet.split('\n').take(3) {
            println!("{}", dim(&format!("    {line}")));
        }
    }
    if symbols.len() > 1 {
        println!();
        println!("{}", dim("  Other matches:"));
        for s in &symbols[1..] {
            println!("    - {}  {}", s.name, dim(&symbol_location(s)));
        }
    }
    println!();
    println!("{}", dim("  (fresh source lookup — re-queried the source host)"));
}

/// HOR-331 — answer a code-locating question with a NEW lookup against the source host. None when
/// no host is configured / reachable / matched, so the caller falls back to the saved report.
async fn answer_from_source(directive: &str, config: Option<&str>, json: bool) -> Result<Option<u8>> {
    let Ok(cfg) = load_config(config.map(Path::new), None) else { return Ok(None) };
    let Ok(code) = code_for_repo(&cfg, None) else { return Ok(None) };
    if !Provider::health(&code).await.ok {
        return Ok(None); // host unreachable → fall back
    }
    let query = extract_symbol_query(directive);
    let symbols = match code.search_symbols(&query, Some(5)).await {
        Ok(s) if !s.is_empty() => s,
        _ => return Ok(None), // host-miss → fall back
    };
    // Citations from search_symbols are enough; context is best-effort.
    let ctx = code.context(&symbols[0].id).await.ok();
    if json {
        println!("{}", horus_core::json::to_js_json_pretty(&code_answer_to_json(directive, &query, &symbols, ctx.as_ref()))?);
    } else {
        render_code_answer(directive, &symbols, ctx.as_ref());
    }
    Ok(Some(0))
}

pub async fn run_ask(id: &str, directive: &str, config: Option<&str>, json: bool) -> Result<u8> {
    // HOR-331: a code-locating question deserves a FRESH answer from the source host; fall back
    // to the saved report on any miss.
    if is_code_locating_question(directive) {
        if let Some(code) = answer_from_source(directive, config, json).await? {
            return Ok(code);
        }
    }
    let repo_root = repo_root_or_cwd(None);
    let cloud_cfg = read_cloud_config(&repo_root).filter(|c| is_cloud_active(Some(c)));

    if let Some(cloud_cfg) = cloud_cfg {
        // HOR-319: resolve LOCAL first (the visible id), then fall back to cloud.
        if let LocalLookup::Found(report) = lookup_local_investigation(id, config).await {
            return Ok(render_answer(&report, directive, json));
        }
        let Some(session) = authed_client() else {
            eprintln!(
                "{}",
                red(&format!("This repo is linked to Horus Cloud but you are not logged in. Run {} first.", bold("horus login")))
            );
            return Ok(1);
        };
        return match fetch_investigation_report_from_cloud(&session.client, &cloud_cfg, id).await {
            Ok(Some(report)) => Ok(render_answer(&typed(report)?, directive, json)),
            Ok(None) => {
                eprintln!(
                    "{}",
                    red(&format!(
                        "Investigation {id} has no saved report locally or in Horus Cloud. Run {} first.",
                        bold("horus investigate")
                    ))
                );
                Ok(1)
            }
            // A 404 here just means `id` isn't a cloud id either; local also missed.
            Err(err) if cloud_status(&err) == Some(404) => {
                eprintln!(
                    "{}",
                    red(&format!(
                        "No investigation found for \"{id}\" locally or in Horus Cloud. Use the id printed at the top of `horus investigate` output."
                    ))
                );
                Ok(1)
            }
            Err(err) => Ok(report_cloud_error(&err)),
        };
    }

    // Local mode — resolve against the local DB only.
    match lookup_local_investigation(id, config).await {
        LocalLookup::Found(report) => Ok(render_answer(&report, directive, json)),
        LocalLookup::NoReport => {
            eprintln!("{}", red(&format!("Investigation {id} has no stored report.")));
            Ok(1)
        }
        LocalLookup::Error(message) => {
            eprintln!("{}", red(&message));
            Ok(1)
        }
        LocalLookup::NotFound => {
            eprintln!("{}", red(&format!("No investigation found: {id}")));
            Ok(1)
        }
    }
}

pub async fn run(args: &AskArgs) -> Result<()> {
    exit(run_ask(&args.id, &args.directive, args.config.as_deref(), args.json).await?)
}
