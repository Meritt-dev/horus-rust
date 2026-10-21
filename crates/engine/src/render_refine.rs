//! HOR-21 — Renderers for a RefinedView of an InvestigationReport. Pure, no I/O.

use crate::js::to_fixed;
use crate::refine::{RefineMode, RefinedView};
use crate::render::short_id;
use crate::types::{evidence_kind_name, provider_kind_name, InvestigationReport};
use serde_json::json;

/// Render a refined investigation view as a terminal-friendly text block.
pub fn render_refined(r: &InvestigationReport, v: &RefinedView) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push(format!("# Refined investigation — {}", r.input.hint));
    lines.push("".into());

    let mode_label = match v.mode {
        RefineMode::Focus => format!("focus: {}", v.topics.join(", ")),
        RefineMode::Ignore => format!("ignore: {}", v.topics.join(", ")),
        RefineMode::Mixed => format!("focus+ignore{}", if v.topics.is_empty() { String::new() } else { format!(": {}", v.topics.join(", ")) }),
        RefineMode::None => "none (all evidence returned)".to_string(),
    };
    lines.push(format!("  [mode: {mode_label}] reusing saved evidence, no re-query"));
    lines.push("".into());

    lines.push("## Hypotheses".into());
    if v.hypotheses.is_empty() {
        lines.push("_(nothing matches this directive)_".into());
    } else {
        for h in &v.hypotheses {
            lines.push(format!("  [{}] [{}] {}: {}", h.verdict.as_str(), to_fixed(h.confidence, 2), h.category, h.statement));
        }
    }
    lines.push("".into());

    lines.push("## Suspected causes".into());
    if v.suspected_causes.is_empty() {
        lines.push("_(nothing matches this directive)_".into());
    } else {
        for (i, c) in v.suspected_causes.iter().enumerate() {
            lines.push(format!("{}. [{} / {}] {}", i + 1, to_fixed(c.final_score, 2), c.band.as_str(), c.title));
        }
    }
    lines.push("".into());

    lines.push("## Evidence".into());
    if v.evidence.is_empty() {
        lines.push("_(nothing matches this directive)_".into());
    } else {
        for e in &v.evidence {
            lines.push(format!("- {} [{}/{}] {}", short_id(&e.id), provider_kind_name(e.source), evidence_kind_name(e.kind), e.title));
        }
    }
    lines.push("".into());

    lines.push(format!("> {}", v.note));

    lines.join("\n")
}

/// Stable JSON serialization of the refined view alongside its source report id.
pub fn refined_to_json(r: &InvestigationReport, v: &RefinedView) -> String {
    horus_core::json::to_js_json_pretty(&json!({
        "investigationId": r.id,
        "hint": r.input.hint,
        "directive": v.directive,
        "mode": v.mode,
        "topics": v.topics,
        "hypotheses": v.hypotheses,
        "suspectedCauses": v.suspected_causes,
        "evidence": v.evidence,
        "note": v.note,
    }))
    .unwrap_or_default()
}
