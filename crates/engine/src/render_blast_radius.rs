//! Renderers for `BlastRadiusReport`.

use crate::blast_radius::BlastRadiusReport;
use crate::render::symbol_display_name;

pub fn render_blast_radius(r: &BlastRadiusReport) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push(format!("# Blast radius: {}", r.seed.name));
    lines.push("".into());
    lines.push(r.summary.clone());
    lines.push("".into());
    lines.push(format!("> {}", r.note));
    lines.push("".into());

    lines.push("## Upstream (where failure could originate — what the seed depends on)".into());
    if r.upstream.is_empty() && r.async_upstream.is_empty() {
        lines.push("  (none)".into());
    } else {
        for sym in r.upstream.iter().take(15) {
            let file = if sym.file_path.is_empty() { "unknown" } else { sym.file_path.as_str() };
            lines.push(format!("  {} ({file})", symbol_display_name(sym)));
        }
        for dep in &r.async_upstream {
            lines.push(format!(
                "  async: {} ({}) [via queue: {}]",
                dep.counterpart,
                dep.counterpart_file.as_deref().unwrap_or("unknown"),
                dep.queue_name
            ));
        }
    }
    lines.push("".into());

    lines.push("## Downstream (affected if the seed fails)".into());
    if r.downstream.is_empty() && r.async_downstream.is_empty() {
        lines.push("  (none)".into());
    } else {
        for layer in &r.downstream {
            let names: Vec<String> = layer.symbols.iter().take(12).map(symbol_display_name).collect();
            let extra = if layer.symbols.len() > 12 { format!(" +{} more", layer.symbols.len() - 12) } else { String::new() };
            lines.push(format!("  depth {}: {}{extra}", layer.depth, names.join(", ")));
        }
        for dep in &r.async_downstream {
            lines.push(format!(
                "  async worker: {} ({}) [via queue: {}]",
                dep.counterpart,
                dep.counterpart_file.as_deref().unwrap_or("unknown"),
                dep.queue_name
            ));
        }
    }
    lines.push("".into());

    lines.push("## Async boundaries".into());
    if r.async_upstream.is_empty() && r.async_downstream.is_empty() {
        lines.push("  (none)".into());
    } else {
        let file_part = |f: &Option<String>| match f.as_deref().filter(|f| !f.is_empty()) {
            Some(f) => format!(" ({f})"),
            None => String::new(),
        };
        for dep in &r.async_upstream {
            lines.push(format!("  {}: upstream producer -> {}{}", dep.queue_name, dep.counterpart, file_part(&dep.counterpart_file)));
        }
        for dep in &r.async_downstream {
            lines.push(format!("  {}: downstream worker -> {}{}", dep.queue_name, dep.counterpart, file_part(&dep.counterpart_file)));
        }
    }
    lines.push("".into());

    lines.push("## Blast radius".into());
    lines.push(format!("  {} symbol(s) affected — criticality: {}", r.blast_radius, r.criticality.as_str()));

    lines.join("\n")
}

pub fn blast_radius_to_json(r: &BlastRadiusReport) -> String {
    horus_core::json::to_js_json_pretty(r).unwrap_or_default()
}
