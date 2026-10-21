//! Port of `packages/cli/src/commands/replay.ts`.
//!
//! Also hosts `buildNarrativeInput`, `narrativeOutputToStoredJudgment` and
//! `renderStoredAIJudgment` (ported-from `commands/investigate.ts`, which owns them in TS) so
//! replay and postmortem work before `investigate` is ported. PENDING: move to investigate.rs.

use anyhow::Result;
use horus_ai::{render_narrative, NarrativeInput, NarrativeOutput, RenderNarrativeOptions};
use horus_db::{get_investigation, open_db, update_investigation_report};
use horus_engine::migrate_report::migrate_report;
use horus_engine::render::{render_report, report_to_json, report_to_markdown};
use horus_engine::types::{InvestigationReport, StoredAIJudgment};
use serde_json::{json, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::ai_provider::build_narrative_provider;
use crate::lib::format::{bold, dim, green, red, yellow};

/// First string among `pattern|message|label|summary|valueLabel` in the payload, ≤120 chars.
fn extract_evidence_excerpt(payload: &Value) -> Option<String> {
    let p = payload.as_object()?;
    ["pattern", "message", "label", "summary", "valueLabel"]
        .iter()
        .find_map(|k| p.get(*k).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(|s| s.encode_utf16().take(120).collect::<Vec<u16>>())
        .map(|u| String::from_utf16_lossy(&u))
}

/// ported-from: commands/investigate.ts `buildNarrativeInput`.
pub(crate) fn build_narrative_input(report: &InvestigationReport) -> Result<NarrativeInput> {
    let r = serde_json::to_value(report)?;
    let arr = |k: &str| r.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let input = json!({
        "investigationId": r["id"],
        "hint": r["input"]["hint"],
        "reportConfidence": r["confidence"],
        "evidence": arr("evidence").iter().map(|e| {
            let mut o = json!({ "id": e["id"], "kind": e["kind"], "title": e["title"] });
            if let Some(x) = extract_evidence_excerpt(&e["payload"]) { o["excerpt"] = json!(x); }
            o
        }).collect::<Vec<_>>(),
        "knownServices": match r["input"]["service"].as_str() { Some(s) if !s.is_empty() => json!([s]), _ => json!([]) },
        "suspectedCauses": arr("suspectedCauses").iter().map(|c| json!({
            "label": c["title"], "score": c["finalScore"], "evidenceIds": c["sourceEvidenceIds"],
        })).collect::<Vec<_>>(),
        "deterministicSummary": r["summary"],
        "findings": arr("findings").iter().map(|f| json!({ "title": f["title"], "evidenceIds": f["evidenceIds"] })).collect::<Vec<_>>(),
        "hypotheses": arr("hypotheses").iter().map(|h| json!({
            "id": h["id"], "category": h["category"], "statement": h["statement"],
            "deterministicVerdict": h["verdict"], "deterministicConfidence": h["confidence"],
            "supportingEvidenceIds": h["supportingEvidenceIds"],
        })).collect::<Vec<_>>(),
    });
    Ok(serde_json::from_value(input)?)
}

/// ported-from: commands/investigate.ts `narrativeOutputToStoredJudgment`.
/// The ai/engine shapes are the same JSON, so fields cross via a serde round-trip.
pub(crate) fn narrative_output_to_stored_judgment(output: &NarrativeOutput, provider: &str) -> Result<StoredAIJudgment> {
    let o = serde_json::to_value(output)?;
    let mut j = json!({
        "what": o["what"], "why": o["why"], "whereNext": o["whereNext"], "citations": o["citations"],
        "confidence": o["confidence"], "provider": provider,
        "generatedAt": horus_db::format_ts(&chrono::Utc::now()),
    });
    for k in ["mentionedServices", "hypothesisJudgments", "rootCauseAssessment"] {
        if !o[k].is_null() {
            j[k] = o[k].clone();
        }
    }
    Ok(serde_json::from_value(j)?)
}

fn pct(x: f64) -> String {
    horus_engine::js::to_fixed(x * 100.0, 0)
}

/// ported-from: commands/investigate.ts `renderStoredAIJudgment`.
pub(crate) fn render_stored_ai_judgment(j: &StoredAIJudgment, write: &mut dyn FnMut(String)) {
    let sep = "─".repeat(60);
    write(format!("\n{sep}"));
    write(format!("{}{}", bold("AI Judgment"), dim(&format!(" (confidence: {}%, provider: {})", pct(j.confidence), j.provider))));
    write(sep);

    if let Some(hj) = j.hypothesis_judgments.as_ref().filter(|v| !v.is_empty()) {
        write(bold("Hypothesis verdicts:"));
        for h in hj {
            let tag = format!("[{}]", h.verdict);
            let colored = match h.verdict.as_str() {
                "supported" => green(&tag),
                "weakened" => yellow(&tag),
                "eliminated" => red(&tag),
                _ => dim(&tag),
            };
            write(format!("  {colored} {}{}", h.category, dim(&format!(" ({}%)", pct(h.confidence)))));
            write(dim(&format!("    {}", h.rationale)));
        }
        write(String::new());
    }

    if let Some(rca) = &j.root_cause_assessment {
        let u = match rca.uncertainty.as_str() {
            "low" => green(&rca.uncertainty),
            "medium" => yellow(&rca.uncertainty),
            _ => red(&rca.uncertainty),
        };
        write(format!("{}{}", bold("Root cause assessment:"), dim(&format!(" uncertainty: {u}"))));
        write(rca.summary.clone());
        if !rca.cited_evidence_ids.is_empty() {
            write(dim(&format!("  Cited: {}", rca.cited_evidence_ids.join(", "))));
        }
        write(String::new());
    }

    write(format!("{} {}", bold("What:"), j.what));
    write(format!("{} {}", bold("Why:"), j.why));
    if !j.where_next.is_empty() {
        write(bold("Next steps:"));
        for step in &j.where_next {
            write(format!("  • {step}"));
        }
    }
    if !j.citations.is_empty() {
        let ids: Vec<&str> = j.citations.iter().map(|c| c.evidence_id.as_str()).collect();
        write(dim(&format!("\nCited evidence: {}", ids.join(", "))));
    }
}

pub(crate) fn print_line(s: String) {
    println!("{s}");
}

pub async fn run(args: &ReplayArgs) -> Result<()> {
    let db = open_db().await?;
    let result = replay(&db, args).await;
    db.end().await;
    result
}

async fn replay(db: &horus_db::DbHandle, args: &ReplayArgs) -> Result<()> {
    let id = &args.id;
    let Some(row) = get_investigation(db, id).await? else {
        eprintln!("{}", red(&format!("No investigation found: {id}")));
        return Err(SilentExit(1).into());
    };
    let Some(raw) = row.report else {
        eprintln!("{}", red(&format!("Investigation {id} has no stored report (run a newer investigation).")));
        return Err(SilentExit(1).into());
    };
    let mut report = migrate_report(serde_json::from_str(&raw)?)?;
    let fmt = args.format.as_str();
    let out = match fmt {
        "json" => report_to_json(&report),
        "markdown" | "md" => report_to_markdown(&report),
        _ => render_report(&report),
    };
    println!("{out}");

    if args.ai && fmt != "json" {
        // Use the stored judgment unless --refresh-ai is set (HOR-198).
        if let (Some(j), false) = (&report.ai_judgment, args.refresh_ai) {
            render_stored_ai_judgment(j, &mut print_line);
            println!("{}", dim("[ai] Stored judgment replayed. Use --refresh-ai to regenerate."));
            return Ok(());
        }
        let input = build_narrative_input(&report)?;
        let (provider, _) = build_narrative_provider(args.config.as_deref(), args.ai_model.as_deref());
        let res = render_narrative(&input, RenderNarrativeOptions { provider: Some(&provider), confidence_ceiling: None }).await;
        let errors = res.validation_errors.unwrap_or_default();
        if !res.from_provider && res.degraded == Some(true) {
            // Usable AI prose that didn't fully validate — labeled raw section (HOR-213).
            if !errors.is_empty() {
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
        } else if !res.from_provider {
            eprintln!("{}", yellow("[ai] Provider unavailable — deterministic output shown above."));
            if let Some(e) = errors.first() {
                eprintln!("{}", dim(&format!("    {e}")));
            }
        } else {
            let stored = narrative_output_to_stored_judgment(&res.output, "anthropic")?;
            report.ai_judgment = Some(stored.clone());
            // best-effort
            if let Ok(s) = horus_core::json::to_js_json(&report) {
                let _ = update_investigation_report(db, &report.id, &s).await;
            }
            render_stored_ai_judgment(&stored, &mut print_line);
        }
    }
    Ok(())
}
