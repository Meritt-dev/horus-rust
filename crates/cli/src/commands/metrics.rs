//! Port of `packages/cli/src/commands/metrics.ts` — `horus metrics`: Grafana metrics evidence
//! (HOR-11). Discovers dashboards/panels, fetches series via the datasource proxy, and surfaces
//! latency spikes, error-rate changes, throughput drops and queue growth. `--query` is a raw
//! PromQL escape hatch.

use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use horus_ai::InterpretationPromptKind;
use horus_connectors::grafana::{extract_hint_tokens, summarize, AnalyzeOptions, Anomaly, Labels};
use horus_connectors::metrics_provider_from_config;
use horus_core::json::{to_js_json_pretty, to_js_value};
use horus_core::load_config;
use horus_engine::js::{number_string, to_fixed};
use indexmap::IndexSet;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use crate::lib::format::{bold, cyan, dim, green, red, yellow};

pub const METRICS_AI_CONTRACT: &str = "Provide a clearly separated AI evidence narration with:

Evidence used
- Exact panel names, anomaly types, baseline vs. current values, and ratios Horus found

What stands out
- The most severe or highest-ratio anomalies
- Any metric dimensions with correlated movement (e.g. error rate + latency both spiking)

What this may indicate
- Use \"may suggest\", \"is consistent with\", or \"could indicate\" — never \"proves\"
- Do not invent dashboard panels or panel names not in the evidence

What is not proven
- Claims that cannot be made from metric anomalies alone (root cause, data loss, user scope)

Next checks
- Exact Horus commands or Grafana dashboards to inspect next";

fn now_secs() -> i64 {
    Utc::now().timestamp_millis().div_euclid(1000)
}

/// "1h" / "30m" / "2d" / "90s" → seconds; 3600 (1h) for anything unrecognised.
fn since_secs(s: Option<&str>) -> i64 {
    let Some(s) = s else { return 3600 };
    let re = Regex::new(r"^(\d+)(s|m|h|d)$").unwrap();
    let Some(c) = re.captures(s) else { return 3600 };
    let amount: i64 = c[1].parse().unwrap_or(0);
    let unit = match &c[2] {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => 1,
    };
    unit * amount
}

fn label_str(labels: &Labels) -> String {
    labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect::<Vec<_>>().join(", ")
}

fn fmt_num(n: f64) -> String {
    if n.is_finite() { to_fixed(n, 4) } else { number_string(n) }
}

fn anomaly_color(a: Anomaly, s: &str) -> String {
    match a {
        Anomaly::LatencySpike | Anomaly::ErrorRateChange | Anomaly::ThroughputDrop => red(s),
        Anomaly::QueueGrowth | Anomaly::Change => yellow(s),
        _ => s.to_string(),
    }
}

fn anomaly_label(a: Anomaly) -> &'static str {
    match a {
        Anomaly::LatencySpike => "LATENCY-SPIKE",
        Anomaly::ErrorRateChange => "ERROR-RATE-CHANGE",
        Anomaly::ThroughputDrop => "THROUGHPUT-DROP",
        Anomaly::QueueGrowth => "QUEUE-GROWTH",
        Anomaly::Change => "CHANGE",
        Anomaly::BimodalPopulation => "BIMODAL-POPULATION",
        Anomaly::None => "OK",
    }
}

fn iso_secs(secs: i64) -> String {
    DateTime::<Utc>::from_timestamp(secs, 0).map(|d| d.to_rfc3339_opts(SecondsFormat::Millis, true)).unwrap_or_default()
}

fn fail(msg: &str) -> anyhow::Error {
    eprintln!("{}", red(msg));
    SilentExit(1).into()
}

pub async fn run(args: &MetricsArgs) -> Result<()> {
    match run_inner(args).await {
        Err(e) if e.downcast_ref::<SilentExit>().is_none() => Err(fail(&format!("{e:#}"))),
        other => other,
    }
}

async fn run_inner(args: &MetricsArgs) -> Result<()> {
    let config = load_config(args.config.as_deref().map(Path::new), None)?;
    let Some(metrics) = metrics_provider_from_config(&config)? else {
        return Err(fail("Grafana not configured — set GRAFANA_URL + GRAFANA_USER + GRAFANA_PASSWORD"));
    };

    let health = metrics.health().await;
    if !health.ok {
        return Err(fail(&format!("Grafana unreachable: {}", health.detail)));
    }

    // `Number(opts.step)`: NaN for a non-numeric value, like TS.
    let step = args.step.as_deref().map(|s| s.trim().parse::<f64>().unwrap_or(f64::NAN));
    let to = now_secs();
    let from = to - since_secs(args.since.as_deref());
    let hint = args.hint.as_deref();

    // --query: raw escape hatch — a single PromQL expression.
    if let Some(query) = args.query.as_deref().filter(|q| !q.is_empty()) {
        let series = metrics.raw_range(query, from as f64, to as f64, step).await?;
        if args.json {
            // Respect --json on the query path too (HOR-210). `step` is omitted when unset.
            let mut out = Map::new();
            out.insert("query".into(), json!(query));
            out.insert("from".into(), json!(from));
            out.insert("to".into(), json!(to));
            if let Some(s) = step {
                out.insert("step".into(), if s.is_finite() { json!(s) } else { Value::Null });
            }
            let rows: Vec<Value> = series
                .iter()
                .map(|s| {
                    let sum = summarize(s);
                    json!({ "labels": s.labels, "last": sum.last, "avg": sum.avg })
                })
                .collect();
            out.insert("series".into(), Value::Array(rows));
            println!("{}", to_js_json_pretty(&Value::Object(out))?);
            return Ok(());
        }
        if series.is_empty() {
            println!("{}", dim("No series returned."));
            return Ok(());
        }
        for s in &series {
            let sum = summarize(s);
            let label = label_str(&s.labels);
            println!(
                "  {}  last={}  avg={}",
                cyan(if label.is_empty() { "(no labels)" } else { &label }),
                bold(&fmt_num(sum.last)),
                fmt_num(sum.avg)
            );
        }
        return Ok(());
    }

    // Default: Grafana panel discovery + anomaly detection.
    let findings = metrics
        .analyze(&AnalyzeOptions { hint: hint.map(str::to_string), from: from as f64, to: to as f64, step, deadline: None })
        .await?;

    if args.json {
        println!("{}", to_js_json_pretty(&to_js_value(&findings)?)?);
        return Ok(());
    }

    let flagged: Vec<_> = findings.iter().filter(|f| f.anomaly != Anomaly::None).collect();
    let ok_count = findings.len() - flagged.len();

    if findings.is_empty() {
        match hint {
            Some(h) => {
                let tokens = extract_hint_tokens(h);
                println!("{}", dim(&format!("No panels matched hint \"{h}\".")));
                if !tokens.is_empty() {
                    println!("{}", dim(&format!("  Searched for panels containing: {}", tokens.join(", "))));
                }
                println!(
                    "{}",
                    dim(&format!(
                        "  Tip: run {} (no hint) to see all available panels, then use a panel title or keyword directly.",
                        bold("horus metrics")
                    ))
                );
            }
            None => println!("{}", dim("No panels found in configured Grafana dashboards.")),
        }
        return Ok(());
    }

    let hint_suffix = hint.map(|h| format!(" (hint: \"{h}\")")).unwrap_or_default();
    // Show how the hint matched so users understand which field drove the result.
    let match_sources: IndexSet<String> = if hint.is_some() {
        findings
            .iter()
            .filter_map(|f| f.match_source.flatten())
            .filter_map(|m| serde_json::to_value(m).ok().and_then(|v| v.as_str().map(str::to_string)))
            .collect()
    } else {
        IndexSet::new()
    };
    let match_suffix = if match_sources.is_empty() {
        String::new()
    } else {
        dim(&format!(" [matched via {}]", match_sources.into_iter().collect::<Vec<_>>().join(", ")))
    };
    println!("{}{match_suffix}", bold(&format!("Grafana metrics{hint_suffix} — {} series across panels", findings.len())));
    println!("{}", dim(&format!("  window: {} – {}", iso_secs(from), iso_secs(to))));
    println!();

    if flagged.is_empty() {
        println!("{}", green("  No anomalies detected."));
    } else {
        for f in &flagged {
            let ratio = if f.ratio.is_finite() { format!("x{}", to_fixed(f.ratio, 2)) } else { "xinf".into() };
            let labels = label_str(&f.labels);
            let title: String = format!("{:<40}", f.panel_title).chars().take(40).collect();
            let line = format!(
                "  {:<22}  {title}  {} -> {} ({ratio}){}",
                anomaly_label(f.anomaly),
                fmt_num(f.baseline_avg),
                fmt_num(f.current_avg),
                if labels.is_empty() { String::new() } else { format!("  {}", dim(&labels)) }
            );
            println!("{}", anomaly_color(f.anomaly, &line));
        }
    }

    if ok_count > 0 {
        println!();
        println!("{}", dim(&format!("  {ok_count} panel series with no anomaly.")));
    }

    if args.ai {
        print_ai_interpretation(AiInterpretationOpts {
            command: "metrics",
            evidence: to_js_value(&findings)?,
            prompt_kind: InterpretationPromptKind::EvidenceSummary,
            output_contract: METRICS_AI_CONTRACT,
            user_intent: hint.map(|h| format!("hint: {h}")),
            config: args.config.as_deref(),
            model_override: args.ai_model.as_deref(),
        })
        .await;
    }
    Ok(())
}
