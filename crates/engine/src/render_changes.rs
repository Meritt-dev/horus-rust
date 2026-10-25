//! Human-facing renderers for a ChangeImpactReport. Pure, deterministic, no I/O.

use crate::changes::ChangeImpactReport;
use horus_core::Symbol;
use serde_json::{json, Map, Value};

const LIST_CAP: usize = 15;

fn symbol_line(s: &Symbol) -> String {
    format!("{} ({})", s.name, s.file_path)
}

fn render_symbol_list(label: &str, symbols: &[Symbol]) -> Vec<String> {
    if symbols.is_empty() {
        return vec![];
    }
    let mut lines = vec![format!("### {label}")];
    let shown = &symbols[..symbols.len().min(LIST_CAP)];
    for s in shown {
        lines.push(format!("- {}", symbol_line(s)));
    }
    let remaining = symbols.len() - shown.len();
    if remaining > 0 {
        lines.push(format!("  +{remaining} more"));
    }
    lines
}

/// First `n` characters of `t`.
pub(crate) fn head(t: &str, n: usize) -> String {
    t.chars().take(n).collect()
}

fn clip(t: &str, n: usize) -> String {
    if t.chars().count() > n {
        format!("{}…", head(t, n - 1))
    } else {
        t.to_string()
    }
}

/// Sectioned text report for terminal output.
pub fn render_change_impact(r: &ChangeImpactReport) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push(format!("# Change Impact: {}..{}", r.base, r.compare));
    lines.push("".into());

    lines.push("## Summary".into());
    lines.push(r.summary.clone());
    lines.push("".into());

    let added = render_symbol_list("Added", &r.added);
    if !added.is_empty() {
        lines.extend(added);
        lines.push("".into());
    }

    let modified_afters: Vec<Symbol> = r.modified.iter().map(|m| m.after.clone()).collect();
    let modified = render_symbol_list("Modified", &modified_afters);
    if !modified.is_empty() {
        lines.extend(modified);
        lines.push("".into());
    }

    let removed = render_symbol_list("Removed", &r.removed);
    if !removed.is_empty() {
        lines.extend(removed);
        lines.push("".into());
    }

    if let Some(related) = r.related_incidents.as_ref().filter(|r| !r.is_empty()) {
        lines.push("## Past incidents in this code".into());
        for i in related {
            let symbols: Vec<&str> = i.matched_symbols.iter().map(|id| id.rsplit(':').next().unwrap_or(id)).collect();
            lines.push(format!("- {} {} ({})", head(&i.created_at, 10), clip(&i.hint, 100), i.investigation_id));
            lines.push(format!("  touches {}; cause then: {}", symbols.join(", "), clip(&i.top_cause, 140)));
        }
        lines.push("".into());
    }

    lines.push("## Affected flows".into());
    if r.affected_flows.is_empty() {
        lines.push("none".into());
    } else {
        for f in &r.affected_flows {
            lines.push(format!("- {} — changed: {}", f.flow_name, f.changed_symbols.join(", ")));
        }
    }

    lines.join("\n")
}

// Caps for the compact (default) JSON projection — the raw report reached multiple MB on
// fixture-heavy repos. Compact keeps citable identity (name + filePath) and marks what was omitted.
const JSON_SYMBOL_CAP: usize = 25;
const JSON_FLOW_CAP: usize = 20;
const JSON_FLOW_SYMBOL_CAP: usize = 10;

/// Compact object projection of a ChangeImpactReport — shared by `changes --json` and the
/// timeline/what-changed serializers. Always carries full `counts`; sets `truncated`/
/// `truncatedCount` when lists were capped.
pub fn change_impact_to_compact_object(r: &ChangeImpactReport) -> Value {
    let sym = |s: &Symbol| json!({ "name": s.name, "filePath": s.file_path });
    let added: Vec<Value> = r.added.iter().take(JSON_SYMBOL_CAP).map(sym).collect();
    let removed: Vec<Value> = r.removed.iter().take(JSON_SYMBOL_CAP).map(sym).collect();
    let modified: Vec<Value> = r.modified.iter().take(JSON_SYMBOL_CAP).map(|m| sym(&m.after)).collect();
    let affected_flows: Vec<Value> = r
        .affected_flows
        .iter()
        .take(JSON_FLOW_CAP)
        .map(|f| {
            json!({
                "flowName": f.flow_name,
                "changedSymbols": f.changed_symbols.iter().take(JSON_FLOW_SYMBOL_CAP).collect::<Vec<_>>(),
            })
        })
        .collect();
    let truncated_count = (r.added.len() - added.len())
        + (r.removed.len() - removed.len())
        + (r.modified.len() - modified.len())
        + (r.affected_flows.len() - affected_flows.len());
    let mut out = Map::new();
    out.insert("base".into(), json!(r.base));
    out.insert("compare".into(), json!(r.compare));
    out.insert("summary".into(), json!(r.summary));
    out.insert(
        "counts".into(),
        json!({
            "added": r.added.len(),
            "removed": r.removed.len(),
            "modified": r.modified.len(),
            "affectedFlows": r.affected_flows.len(),
        }),
    );
    out.insert("added".into(), Value::Array(added));
    out.insert("removed".into(), Value::Array(removed));
    out.insert("modified".into(), Value::Array(modified));
    out.insert("affectedFlows".into(), Value::Array(affected_flows));
    if let Some(related) = r.related_incidents.as_ref().filter(|r| !r.is_empty()) {
        out.insert("relatedIncidents".into(), serde_json::to_value(related).unwrap_or_default());
    }
    if truncated_count > 0 {
        out.insert("truncated".into(), json!(true));
        out.insert("truncatedCount".into(), json!(truncated_count));
        out.insert("hint".into(), json!("re-run with --full for the complete structure"));
    }
    Value::Object(out)
}

/// Stable JSON serialization — compact by default; `full` restores the raw report.
pub fn change_impact_to_json(r: &ChangeImpactReport, full: bool) -> String {
    if full {
        return horus_core::json::to_js_json_pretty(r).unwrap_or_default();
    }
    horus_core::json::to_js_json_pretty(&change_impact_to_compact_object(r)).unwrap_or_default()
}
