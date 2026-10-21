//! Renderers for `ArchitectureModel`. Pure, deterministic, no I/O.

use crate::architecture::{is_testy_community, ArchitectureModel, SymFile};

/// Render a queue's producers/workers with files so same-named ones don't read as `x -> x` (HOR-368).
pub(crate) fn fmt_endpoints(endpoints: &[SymFile]) -> String {
    if endpoints.is_empty() {
        return "(unknown)".to_string();
    }
    endpoints
        .iter()
        .map(|e| match e.file.as_deref().filter(|f| !f.is_empty()) {
            Some(f) => format!("{} ({})", e.symbol, f.rsplit('/').next().unwrap_or("")),
            None => e.symbol.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn render_architecture(m: &ArchitectureModel) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push("# Architecture (discovered)".into());
    lines.push("".into());

    lines.push(m.summary.clone());
    lines.push("".into());

    lines.push("## Subsystems (most central first)".into());
    if m.subsystems.is_empty() {
        lines.push("(none)".into());
    } else {
        for s in &m.subsystems {
            // Mark test/example clusters so a large one lower in the list doesn't read as a
            // contradiction of the "largest" (product) subsystem in the summary (HOR-377).
            let tag = if s.testy.unwrap_or_else(|| is_testy_community(&s.name)) { " (tests)" } else { "" };
            lines.push(format!("- {} — {} members{tag}", s.name, s.members));
        }
    }
    lines.push("".into());

    lines.push("## Async boundaries".into());
    if m.async_boundaries.is_empty() {
        lines.push("(none)".into());
    } else {
        for b in &m.async_boundaries {
            lines.push(format!("- {}: {} -> {}", b.queue_name, fmt_endpoints(&b.producers), fmt_endpoints(&b.workers)));
        }
    }
    lines.push("".into());

    lines.push("## External systems".into());
    if m.external_systems.is_empty() {
        lines.push("(none)".into());
    } else {
        for e in &m.external_systems {
            lines.push(format!("- {} ({} files)", e.name, e.files));
        }
    }
    lines.push("".into());

    lines.push("## Key flows".into());
    if m.key_flows.is_empty() {
        lines.push("(none)".into());
    } else {
        for f in &m.key_flows {
            lines.push(format!("- {f}"));
        }
    }
    lines.push("".into());

    lines.push("## Graph".into());
    if m.node_stats.is_empty() {
        lines.push("(no data)".into());
    } else {
        for s in &m.node_stats {
            lines.push(format!("{} × {}", s.label, s.count));
        }
    }
    lines.push("".into());

    lines.push("## Fragility".into());
    lines.push(format!("- Unreferenced symbols: {}", m.fragile.dead_code));
    lines.push(format!("- High-coupling pairs (co-changes ≥ 3): {}", m.fragile.high_coupling_pairs));

    lines.join("\n")
}

pub fn architecture_to_json(m: &ArchitectureModel) -> String {
    horus_core::json::to_js_json_pretty(m).unwrap_or_default()
}
