//! Renderers for `OnboardingGuide`.

use crate::js::to_fixed;
use crate::onboard::OnboardingGuide;
use crate::render_architecture::fmt_endpoints;

pub fn render_onboarding(g: &OnboardingGuide) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push(match &g.area {
        Some(a) => format!("# Onboarding: {a}"),
        None => "# Onboarding".into(),
    });
    lines.push("".into());
    lines.push(g.summary.clone());
    lines.push("".into());

    lines.push("## How this system works".into());
    lines.push("".into());
    let subsystems: Vec<_> = g.architecture.subsystems.iter().take(8).collect();
    if subsystems.is_empty() {
        lines.push("No subsystem data available.".into());
    } else {
        for s in subsystems {
            lines.push(format!("- **{}** — {} members", s.name, s.members));
        }
    }
    lines.push("".into());
    if !g.architecture.external_systems.is_empty() {
        lines.push("External systems:".into());
        for e in &g.architecture.external_systems {
            lines.push(format!("- {} ({} files)", e.name, e.files));
        }
    } else {
        lines.push("No external systems detected.".into());
    }
    lines.push("".into());

    lines.push("## Critical paths".into());
    lines.push("".into());
    let key_flows: Vec<_> = g.architecture.key_flows.iter().take(10).collect();
    if key_flows.is_empty() {
        lines.push("No key flows detected.".into());
    } else {
        for f in key_flows {
            lines.push(format!("- {f}"));
        }
    }
    lines.push("".into());
    if !g.architecture.async_boundaries.is_empty() {
        lines.push("Async boundaries:".into());
        for b in &g.architecture.async_boundaries {
            lines.push(format!("- {}: {} -> {}", b.queue_name, fmt_endpoints(&b.producers), fmt_endpoints(&b.workers)));
        }
    } else {
        lines.push("No async boundaries detected.".into());
    }
    lines.push("".into());

    lines.push("## What usually breaks".into());
    lines.push("".into());
    lines.push(format!("- Unreferenced symbols: {}", g.architecture.fragile.dead_code));
    lines.push(format!("- High-coupling pairs (co-changes ≥ 3): {}", g.architecture.fragile.high_coupling_pairs));
    lines.push("".into());
    if !g.architecture.async_boundaries.is_empty() {
        lines.push("Async boundaries are the usual failure points:".into());
        for b in &g.architecture.async_boundaries {
            lines.push(format!("- {}", b.queue_name));
        }
    }
    lines.push("".into());

    lines.push("## Who owns this area".into());
    lines.push("".into());
    match g.ownership.as_ref().and_then(|o| o.file.as_deref().map(|f| (o, f))) {
        Some((o, file)) => {
            let pct = to_fixed(o.confidence * 100.0, 0);
            lines.push(format!("File: {file}"));
            lines.push(format!("Likely maintainer: {} ({pct}% confidence)", o.likely_maintainer.as_deref().unwrap_or("(unknown)")));
        }
        None => lines.push("_Pass an area (e.g. horus onboard zoho) or run: horus owner <symbol>_".into()),
    }
    lines.push("".into());

    lines.push("## Past incidents".into());
    lines.push("".into());
    if g.past_incidents.is_empty() {
        lines.push("_none on record_".into());
    } else {
        for inc in &g.past_incidents {
            lines.push(format!("- {} {}", inc.created_at.as_deref().unwrap_or("(no date)"), inc.title));
        }
    }
    lines.push("".into());

    lines.push("_Generated from live code structure + git + investigation history — deterministic, no AI._".into());

    lines.join("\n")
}

pub fn onboarding_to_json(g: &OnboardingGuide) -> String {
    horus_core::json::to_js_json_pretty(g).unwrap_or_default()
}
