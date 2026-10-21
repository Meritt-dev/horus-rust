//! Port of `packages/cli/src/commands/logs.ts` — `horus logs`: logs as EVIDENCE (HOR-10). The
//! default view synthesizes error signatures (count, first/last, services, NEW/spike); `--raw`
//! dumps lines; `--group-by` aggregates error counts by a structured field. Project/env-scoped
//! (HOR-34): there is no global Elasticsearch default.

use std::path::Path;

use anyhow::{anyhow, Result};
use chrono::{Duration, SecondsFormat, Utc};
use horus_ai::InterpretationPromptKind;
use horus_connectors::elasticsearch::{
    extract_context_fields, short_ts, CompatibilityOptions, IssueSeverity, LogLevel, LogQuery, LogsProvider, WhereClause,
};
use horus_connectors::cloud_logs::{CollectOptions, StructuredLogSource};
use horus_connectors::{cloud_logs_for_env, logs_for_env, Provider};
use horus_core::json::{to_js_json_pretty, to_js_value};
use horus_core::{load_config, resolve_environment, ResolveOptions, ResolvedEnvironment};
use horus_engine::js::{number_string, to_fixed};
use regex::Regex;
use serde_json::{json, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use crate::lib::format::{bold, dim, red, yellow};

pub const LOGS_AI_CONTRACT: &str = "Provide a clearly separated AI evidence narration with:

Evidence used
- Exact error signatures, counts, first/last timestamps, and affected services Horus found

What stands out
- The most frequent or newest signatures
- Services appearing disproportionately across signatures

What this may indicate
- Use \"may suggest\", \"is consistent with\", or \"could indicate\" — not \"proves\" or \"caused by\"
- Correlation hints only (e.g. \"the spike overlaps with the deployment window\")

What is not proven
- Claims that cannot be made from error logs alone (root cause, user impact, fix)

Next checks
- Exact Horus commands, dashboards, or files to inspect next";

fn iso(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse "24h" / "7d" / "30m" into an ISO "now minus that"; pass anything else through.
fn since_to_iso(since: Option<&str>) -> Option<String> {
    let since = since?;
    let re = Regex::new(r"^(\d+)(m|h|d)$").unwrap();
    let Some(c) = re.captures(since) else { return Some(since.to_string()) };
    let amount: i64 = c[1].parse().unwrap_or(0);
    let ms = match &c[2] {
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => 60_000,
    };
    Some(iso(Utc::now() - Duration::milliseconds(ms * amount)))
}

fn default_from() -> String {
    iso(Utc::now() - Duration::milliseconds(7 * 86_400_000))
}

/// Parse a level name the way the TS cast does, rejecting labels the connector can't map.
fn parse_level(s: &str) -> Result<LogLevel> {
    LogLevel::from_label(s).ok_or_else(|| anyhow!("Unknown log level \"{s}\" — expected trace|debug|info|warn|error|fatal"))
}

/// Severity floor for `--raw` (HOR-209): `error` by default, `--level` overrides, `--all-levels` removes it.
fn resolve_raw_level(args: &LogsArgs) -> Result<Option<LogLevel>> {
    if args.all_levels {
        return Ok(None);
    }
    Ok(Some(parse_level(args.level.as_deref().unwrap_or("error"))?))
}

/// Parse repeatable `--where field=value` into structured filters (HOR-344).
pub fn parse_where(raw: &[String]) -> Result<Vec<WhereClause>> {
    raw.iter()
        .map(|entry| match entry.find('=') {
            Some(eq) if eq > 0 => Ok(WhereClause { field: entry[..eq].trim().to_string(), value: entry[eq + 1..].trim().to_string() }),
            _ => Err(anyhow!("Invalid --where \"{entry}\" — expected field=value, e.g. --where context.brand_id=42")),
        })
        .collect()
}

fn where_label(w: &[WhereClause]) -> String {
    w.iter().map(|w| format!("{}={}", w.field, w.value)).collect::<Vec<_>>().join(", ")
}

fn level_color(level: LogLevel, text: &str) -> String {
    match level {
        LogLevel::Error | LogLevel::Fatal => red(text),
        LogLevel::Warn => yellow(text),
        _ => dim(text),
    }
}

pub enum ServiceMatch {
    Unique(String),
    Ambiguous(Vec<String>),
    None,
}

/// Resolve a requested service name against the labels that actually appear in the logs: exact
/// match wins, else a unique case-insensitive substring match (HOR-319 Bug 3).
pub fn match_service_label(requested: &str, candidates: &[String]) -> ServiceMatch {
    if candidates.iter().any(|c| c == requested) {
        return ServiceMatch::Unique(requested.to_string());
    }
    let needle = requested.to_lowercase();
    let subs: Vec<String> = candidates.iter().filter(|c| c.to_lowercase().contains(&needle)).cloned().collect();
    match subs.len() {
        1 => ServiceMatch::Unique(subs[0].clone()),
        0 => ServiceMatch::None,
        _ => ServiceMatch::Ambiguous(subs),
    }
}

/// JS template-literal rendering of a JSON field (`${row.fields.x}`).
fn js_tpl(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.as_f64().map(number_string).unwrap_or_else(|| n.to_string()),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(a)) => a.iter().map(|x| if x.is_null() { String::new() } else { js_tpl(Some(x)) }).collect::<Vec<_>>().join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

fn chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn fail(msg: &str) -> anyhow::Error {
    eprintln!("{}", red(msg));
    SilentExit(1).into()
}

pub async fn run(args: &LogsArgs) -> Result<()> {
    match run_inner(args).await {
        Err(e) if e.downcast_ref::<SilentExit>().is_none() => Err(fail(&format!("{e:#}"))),
        other => other,
    }
}

async fn run_inner(args: &LogsArgs) -> Result<()> {
    let where_ = parse_where(&args.r#where).map_err(|e| fail(&e.to_string()))?;
    let has_where = !where_.is_empty();
    let where_arg = has_where.then(|| where_.clone());

    let config = load_config(args.config.as_deref().map(Path::new), None)?;
    let renv = resolve_environment(&config, &ResolveOptions { env: args.env.as_deref(), ..Default::default() })
        .map_err(|e| fail(&format!("{e:#}")))?;

    let Some(logs) = logs_for_env(&renv)? else {
        let cloud = cloud_logs_for_env(&renv)?;
        if !cloud.is_empty() {
            return run_cloud(args, &renv, cloud, has_where).await;
        }
        return Err(fail(&format!(
            "No Elasticsearch connector configured for {}/{} (set ES_URL / ES_USERNAME / ES_PASSWORD)",
            renv.project, renv.env
        )));
    };

    let health = logs.health().await;
    if !health.ok {
        return Err(fail(&format!("Elasticsearch unreachable: {}", health.detail)));
    }

    let es = renv.connectors.elasticsearch.as_ref();
    let resolved_service = args.service.clone().or_else(|| es.and_then(|e| e.service_name.clone()));
    let index_pattern = es.map(|e| e.index_pattern.clone()).unwrap_or_else(|| "*".into());

    // Validate the field mapping against the index before querying; errors block, warnings advise.
    let aggregates_event_code = !args.raw && args.group_by.is_none();
    match logs
        .check_compatibility(Some(CompatibilityOptions {
            requires_service: resolved_service.is_some(),
            requires_service_aggregation: aggregates_event_code,
            requires_event_code: aggregates_event_code,
        }))
        .await
    {
        Ok(compat) => {
            for w in compat.issues.iter().filter(|i| i.severity == IssueSeverity::Warning) {
                eprintln!("{}", yellow(&format!("[warn] {}: {}", w.field, w.message)));
            }
            let errors: Vec<_> = compat.issues.iter().filter(|i| i.severity == IssueSeverity::Error).collect();
            if !errors.is_empty() {
                eprintln!("{}", red("Elasticsearch field mapping is incompatible with the index:"));
                for e in errors {
                    eprintln!("{}", red(&format!("  {}: {}", e.field, e.message)));
                }
                eprintln!("{}", dim("Fix fields.* overrides in your connector config or choose the correct preset."));
                return Err(SilentExit(1).into());
            }
        }
        // Best-effort: network/auth errors must not prevent legitimate queries.
        Err(_) => eprintln!("{}", dim("[warn] Elasticsearch compatibility check unavailable — proceeding.")),
    }

    // Default to 7 days to match the investigation engine's default window.
    let from = since_to_iso(args.since.as_deref()).unwrap_or_else(default_from);
    let from_display = chars(&from, 16).replace('T', " ");
    let broad = Some(args.grep.is_some());
    let base_query = |service: Option<String>| LogQuery {
        service,
        from: Some(from.clone()),
        text: args.grep.clone(),
        broad_text: broad,
        where_: where_arg.clone(),
        ..Default::default()
    };

    // ── --raw: line dump (error+ by default, HOR-209) ──
    if args.raw {
        // A --where lookup targets specific records often emitted at INFO/DEBUG (HOR-344).
        let raw_level = if has_where && args.level.is_none() { None } else { resolve_raw_level(args)? };
        let default_limit = if has_where { 200.0 } else { 20.0 };
        let limit = match args.limit.as_deref() {
            Some(l) => l.trim().parse::<f64>().unwrap_or(f64::NAN).min(1000.0),
            None => default_limit,
        };
        let limit_n = if limit.is_finite() && limit > 0.0 { limit.floor() as usize } else { 0 };
        let records = logs.search_logs(&LogQuery { level: raw_level, limit: Some(limit_n), ..base_query(resolved_service.clone()) }).await?;
        let truncated = records.len() as f64 == limit;
        let level_label = raw_level.map(|l| l.as_str()).unwrap_or("all");

        if args.json {
            let recs: Vec<Value> = records
                .iter()
                .map(|r| {
                    json!({
                        "timestamp": r.timestamp, "level": r.level, "service": r.service, "component": r.component,
                        "eventCode": r.event_code, "message": r.message, "context": r.context, "detail": r.detail,
                        "traceId": r.trace_id, "requestId": r.request_id,
                    })
                })
                .collect();
            let out = json!({
                "scope": {
                    "project": renv.project, "env": renv.env, "service": resolved_service, "index": index_pattern,
                    "from": from, "level": level_label, "grep": args.grep, "where": where_arg, "truncated": truncated,
                },
                "records": recs,
            });
            println!("{}", to_js_json_pretty(&out)?);
            return Ok(());
        }
        // Scope goes to stderr so it never pollutes piped stdout (HOR-344).
        eprintln!(
            "{}",
            dim(&format!(
                "logs: {}/{}{} · from {from_display} UTC · level {level_label}{}{}{}",
                renv.project,
                renv.env,
                resolved_service.as_ref().map(|s| format!(" · service {s}")).unwrap_or_default(),
                if has_where { format!(" · where {}", where_label(&where_)) } else { String::new() },
                args.grep.as_ref().filter(|g| !g.is_empty()).map(|g| format!(" · grep \"{g}\"")).unwrap_or_default(),
                if raw_level == Some(LogLevel::Error) && !has_where { "  (error+ only — use --all-levels for info/debug)" } else { "" },
            ))
        );
        if records.is_empty() {
            println!("{}", dim("No logs matched."));
            return Ok(());
        }
        for r in &records {
            let ts = if r.timestamp.is_empty() { " ".repeat(23) } else { chars(&r.timestamp, 23) };
            let lvl = format!("[{:<5}]", r.level.as_str().to_uppercase());
            let comp = chars(&format!("{:<30}", r.component.as_deref().or(r.service.as_deref()).unwrap_or("")), 30);
            println!("{}", level_color(r.level, &format!("{ts}  {lvl}  {comp}  {}", chars(&r.message, 120))));
            // Structured context beneath the line so the raw view is debuggable (HOR-215).
            for f in extract_context_fields(r, None) {
                println!("{}", dim(&format!("    {}: {}", f.key, chars(&f.value, 200))));
            }
        }
        if truncated {
            eprintln!(
                "{}",
                yellow(&format!(
                    "[warn] showing the first {} record(s) — results may be truncated. Narrow with --where/--since/--level or raise --limit (max 1000).",
                    number_string(limit)
                ))
            );
        }
        return Ok(());
    }

    // ── --group-by: top entities by error count (HOR-215) ──
    if let Some(field) = args.group_by.as_deref() {
        let buckets = logs.aggregate_errors(&base_query(resolved_service.clone()), Some(field)).await?;
        if args.json {
            let out = json!({
                "scope": {
                    "project": renv.project, "env": renv.env, "service": resolved_service, "index": index_pattern,
                    "from": from, "severity": "error+", "grep": args.grep, "where": where_arg, "groupBy": field,
                },
                "buckets": to_js_value(&buckets)?,
            });
            println!("{}", to_js_json_pretty(&out)?);
            return Ok(());
        }
        println!(
            "{}{}",
            bold(&format!("Top {field}")),
            dim(&format!(
                " — {}/{}{}{}{}",
                renv.project,
                renv.env,
                resolved_service.as_ref().map(|s| format!(" · service {s}")).unwrap_or_default(),
                args.grep.as_ref().filter(|g| !g.is_empty()).map(|g| format!(" · grep \"{g}\"")).unwrap_or_default(),
                if has_where { format!(" · where {}", where_label(&where_)) } else { String::new() },
            ))
        );
        println!("{}", dim(&format!("  index: {index_pattern} · from: {from_display} UTC · severity: error+")));
        println!();
        if buckets.is_empty() {
            println!("{}", dim(&format!("  No error logs with field \"{field}\" in the window.")));
            println!("{}", dim(&format!("  Tip: ensure \"{field}\" is an aggregatable (keyword) field.")));
            return Ok(());
        }
        for b in &buckets {
            println!("  {}  {}", red(&format!("{:>6}", number_string(b.count))), b.key);
        }
        println!();
        println!("{}", dim(&format!("  {} distinct {field} value(s) shown (top by error count).", buckets.len())));
        return Ok(());
    }

    // ── Default: synthesize error evidence ──
    let mut analysis = logs.analyze_errors(&base_query(resolved_service.clone()), None).await?;
    let mut scope_service = resolved_service.clone();
    let mut broadening_note: Option<String> = None;

    // Broader discovery (HOR-157): a service filter with 0 signatures retries unfiltered, first
    // trying to resolve the name against the labels that actually carry errors (HOR-319).
    if analysis.signatures.is_empty() {
        if let Some(requested) = resolved_service.as_deref() {
            let broader = logs.analyze_errors(&base_query(None), None).await?;
            if !broader.signatures.is_empty() {
                let all_note = format!("No errors found for service \"{requested}\" — showing all services");
                match match_service_label(requested, &broader.affected_services) {
                    ServiceMatch::Unique(m) if m != requested => {
                        let scoped = logs.analyze_errors(&base_query(Some(m.clone())), None).await?;
                        if !scoped.signatures.is_empty() {
                            analysis = scoped;
                            broadening_note = Some(format!("No exact match for service \"{requested}\" — matched \"{m}\""));
                            scope_service = Some(m);
                        } else {
                            analysis = broader;
                            scope_service = None;
                            broadening_note = Some(all_note);
                        }
                    }
                    ServiceMatch::Ambiguous(c) => {
                        analysis = broader;
                        scope_service = None;
                        broadening_note = Some(format!(
                            "\"{requested}\" matches multiple services: {} — showing all; re-run with a full label",
                            c.join(", ")
                        ));
                    }
                    _ => {
                        analysis = broader;
                        scope_service = None;
                        broadening_note = Some(all_note);
                    }
                }
            }
        }
    }

    if args.json {
        let out = json!({
            "scope": {
                "project": renv.project, "env": renv.env, "service": scope_service, "index": index_pattern,
                "from": from, "severity": "error+", "grep": args.grep, "where": where_arg,
            },
            "totalErrors": analysis.total_errors,
            "signatures": to_js_value(&analysis.signatures)?,
            "newSignatures": analysis.new_signatures,
            "affectedServices": analysis.affected_services,
        });
        println!("{}", to_js_json_pretty(&out)?);
        return Ok(());
    }

    println!(
        "{}{}",
        bold("Error analysis"),
        dim(&format!(
            " — {}/{}{}{}{}",
            renv.project,
            renv.env,
            scope_service.as_ref().map(|s| format!(" · service {s}")).unwrap_or_default(),
            args.grep.as_ref().filter(|g| !g.is_empty()).map(|g| format!(" · grep \"{g}\"")).unwrap_or_default(),
            if has_where { format!(" · where {}", where_label(&where_)) } else { String::new() },
        ))
    );
    println!("{}", dim(&format!("  index: {index_pattern} · from: {from_display} UTC · severity: error+")));
    if let Some(note) = &broadening_note {
        println!("{}", yellow(&format!("  {note}")));
    }
    let total = number_string(analysis.total_errors);
    println!(
        "  {total} error(s) · {} signature(s) · {} new",
        analysis.signatures.len(),
        yellow(&analysis.new_signatures.len().to_string())
    );
    println!();

    if analysis.signatures.is_empty() {
        // Be honest about which case this is — never "no errors" when the count says otherwise.
        println!(
            "{}",
            dim(&if analysis.total_errors > 0.0 {
                format!("  {total} error-level log(s) matched, but none could be grouped into a signature (missing the code field). Try --raw to see the lines.")
            } else {
                "  No error-level logs in the window.".into()
            })
        );
        println!(
            "{}",
            dim(&format!(
                "  Searched: {} · index: {index_pattern} · from: {from_display} UTC",
                scope_service.as_ref().map(|s| format!("service \"{s}\"")).unwrap_or_else(|| "all services".into())
            ))
        );
        println!("{}", dim("  Tip: use --since to widen the window (e.g. --since 30d)."));
        return Ok(());
    }

    for s in &analysis.signatures {
        let mut tags: Vec<String> = Vec::new();
        if s.is_new == Some(true) {
            tags.push(red("NEW"));
        } else if let Some(ratio) = s.ratio.filter(|r| r.is_finite() && *r >= 1.5) {
            tags.push(yellow(&format!("spike x{}", to_fixed(ratio, 1))));
        }
        let svc = if s.services.is_empty() {
            String::new()
        } else {
            dim(&format!(" · {}", s.services.iter().take(3).cloned().collect::<Vec<_>>().join(", ")))
        };
        let tag_str = if tags.is_empty() { String::new() } else { format!("  [{}]", tags.join(", ")) };
        println!(
            "  {}  {}  {}{svc}{tag_str}",
            red(&format!("{:>6}", number_string(s.count))),
            bold(&chars(&format!("{:<14}", s.key), 14)),
            dim(&format!("first {} · last {}", short_ts(&s.first_seen), short_ts(&s.last_seen))),
        );
    }

    if !analysis.affected_services.is_empty() {
        println!();
        println!("  {} {}", bold("Affected services:"), analysis.affected_services.join(", "));
    }
    println!();
    println!("{}", dim("  (use --raw to see individual log lines)"));

    if args.ai {
        print_ai_interpretation(AiInterpretationOpts {
            command: "logs",
            evidence: json!({
                "totalErrors": analysis.total_errors,
                "signatures": to_js_value(&analysis.signatures)?,
                "newSignatures": analysis.new_signatures,
                "affectedServices": analysis.affected_services,
            }),
            prompt_kind: InterpretationPromptKind::EvidenceSummary,
            output_contract: LOGS_AI_CONTRACT,
            user_intent: scope_service.as_ref().map(|s| format!("service: {s}")),
            config: args.config.as_deref(),
            model_override: args.ai_model.as_deref(),
        })
        .await;
    }
    Ok(())
}

/// Cloud-log providers (Azure Monitor / CloudWatch / GCP Logging) when Elasticsearch is absent:
/// a bounded sample, filtered by severity floor and service substring.
async fn run_cloud(
    args: &LogsArgs,
    renv: &ResolvedEnvironment,
    providers: Vec<horus_connectors::cloud_logs::CloudLogsProvider>,
    has_where: bool,
) -> Result<()> {
    if args.group_by.as_deref().is_some_and(|g| !g.is_empty()) || has_where {
        return Err(anyhow!("--group-by and --where require Elasticsearch; use --grep or a configured cloud log filter"));
    }
    let from = since_to_iso(args.since.as_deref()).unwrap_or_else(default_from);
    let limit = 200f64.min(1f64.max(args.limit.as_deref().map(|l| l.trim().parse().unwrap_or(f64::NAN)).unwrap_or(20.0)));
    if !limit.is_finite() {
        return Err(anyhow!("Invalid log limit"));
    }
    let severity = |s: &str| -> Option<i32> {
        Some(match s {
            "trace" => 0,
            "debug" => 1,
            "info" => 2,
            "warn" | "warning" => 3,
            "error" => 4,
            "fatal" | "critical" => 5,
            _ => return None,
        })
    };
    let minimum = if args.all_levels { None } else { Some(args.level.clone().unwrap_or_else(|| "error".into())) };
    let mut results: Vec<Value> = Vec::new();
    let mut text_blocks: Vec<(String, Vec<String>)> = Vec::new();
    for provider in &providers {
        let rows = provider
            .collect(&CollectOptions { from: Some(from.clone()), hint_terms: args.grep.clone().map(|g| vec![g]), ..Default::default() })
            .await?;
        let min = match &minimum {
            Some(m) => Some(severity(m).ok_or_else(|| anyhow!("Unknown severity level"))?),
            None => None,
        };
        let records: Vec<_> = rows
            .into_iter()
            .filter(|r| {
                min.is_none_or(|m| severity(&js_tpl(r.fields.get("level"))).unwrap_or(-1) >= m)
                    && args.service.as_deref().is_none_or(|svc| js_tpl(r.fields.get("service")).to_lowercase().contains(&svc.to_lowercase()))
            })
            .take(limit as usize)
            .collect();
        let lines = records
            .iter()
            .map(|r| format!("{} [{}] {}", r.timestamp.as_deref().unwrap_or(""), js_tpl(r.fields.get("level")), js_tpl(r.fields.get("message"))))
            .collect();
        text_blocks.push((format!("{}: {} records (bounded sample)", provider.id(), records.len()), lines));
        results.push(json!({ "provider": provider.id(), "from": from, "boundedSample": true, "sampleLimit": 200, "records": to_js_value(&records)? }));
    }
    if args.json {
        println!("{}", to_js_json_pretty(&json!({ "project": renv.project, "environment": renv.env, "providers": results }))?);
    } else {
        for (title, lines) in &text_blocks {
            println!("{}", bold(title));
            for l in lines {
                println!("{l}");
            }
        }
    }
    if args.ai && !args.json {
        let result = crate::lib::ai_provider::render_ai_interpretation(AiInterpretationOpts {
            command: "logs",
            evidence: Value::Array(results),
            prompt_kind: InterpretationPromptKind::EvidenceSummary,
            output_contract: LOGS_AI_CONTRACT,
            user_intent: None,
            config: args.config.as_deref(),
            model_override: args.ai_model.as_deref(),
        })
        .await;
        println!("{}", horus_ai::render_interpretation(&result));
    }
    Ok(())
}
