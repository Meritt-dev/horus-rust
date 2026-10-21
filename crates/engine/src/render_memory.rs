//! Renderers for `horus memory show <scope>` (HOR). Markdown + machine JSON, modeled on
//! render_architecture / render_onboard. Pure — no I/O.

use crate::architecture::SymFile;
use crate::js;
use crate::memory_view::MemoryView;

/// Render a queue's producers/workers with files so same-named ones don't read as `x -> x`.
fn fmt_endpoints(endpoints: &[SymFile]) -> String {
    if endpoints.is_empty() {
        return "(unknown)".to_string();
    }
    endpoints
        .iter()
        .map(|e| match e.file.as_deref().filter(|f| !f.is_empty()) {
            Some(file) => format!("{} ({})", e.symbol, file.rsplit('/').next().unwrap_or("")),
            None => e.symbol.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn render_memory_view(v: &MemoryView) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut push = |s: &str| lines.push(s.to_string());

    push(&format!("# Memory: {}", v.scope));
    push("");
    push(&format!("Project: {} · area: {}", v.project, if v.area.is_empty() { "(repo)" } else { &v.area }));
    push("");
    push(&v.summary);
    push("");
    if !v.source_available {
        push("> ⚠ Source-intelligence host unreachable — run `horus init`.");
        push("> Showing **incident memory only**; code structure (owned areas, runtime paths, external systems) is unavailable, not absent.");
        push("");
    }

    // --- Owned areas ------------------------------------------------------
    push("## Owned areas");
    push("");
    if v.owned_areas.subsystems.is_empty() {
        push(if v.source_available { "No scope-matched subsystems." } else { "_Unavailable — source host unreachable (run `horus init`)._" });
    } else {
        for s in &v.owned_areas.subsystems {
            let tag = if s.testy { " (tests)" } else { "" };
            push(&format!("- {} — {} members{tag}", s.name, s.members));
        }
    }
    push("");
    if let Some(seed) = &v.owned_areas.seed_symbol {
        push(&format!("Seed symbol: {} ({})", seed.name, seed.file));
    }
    match v.owned_areas.ownership.as_ref().filter(|o| o.file.is_some()) {
        Some(own) => {
            let pct = js::to_fixed(own.confidence * 100.0, 0);
            push(&format!("Likely maintainer: {} ({pct}% confidence)", own.likely_maintainer.as_deref().unwrap_or("(unknown)")));
            if let Some(m) = &own.most_active_recent {
                push(&format!("Most active recently: {m}"));
            }
            push("_Probabilistic — git commit history only, not an org chart._");
        }
        None => push(if v.source_available {
            "_Ownership unavailable — no source symbol matched the scope._"
        } else {
            "_Ownership unavailable — source host unreachable._"
        }),
    }
    push("");

    // --- Runtime paths & queues -------------------------------------------
    push("## Runtime paths & queues");
    push("");
    if v.runtime_paths.async_boundaries.is_empty() {
        push(if v.source_available { "No scope-matched async boundaries." } else { "_Unavailable — source host unreachable._" });
    } else {
        for b in &v.runtime_paths.async_boundaries {
            push(&format!("- {}: {} -> {}", b.queue_name, fmt_endpoints(&b.producers), fmt_endpoints(&b.workers)));
        }
    }
    push("");
    if !v.runtime_paths.key_flows.is_empty() {
        push("Key flows:");
        for f in &v.runtime_paths.key_flows {
            push(&format!("- {f}"));
        }
        push("");
    }
    if !v.runtime_paths.queues_seen_in_incidents.is_empty() {
        push("Queues seen in past incidents:");
        for q in &v.runtime_paths.queues_seen_in_incidents {
            push(&format!("- {q}"));
        }
        push("");
    }

    // --- External systems --------------------------------------------------
    push("## External systems");
    push("");
    if v.external_systems.is_empty() {
        push(if v.source_available { "No scope-matched external systems." } else { "_Unavailable — source host unreachable._" });
    } else {
        for e in &v.external_systems {
            push(&format!("- {} ({} files)", e.name, e.files));
        }
    }
    push("");

    // --- Past investigations ----------------------------------------------
    push("## Past investigations");
    push("");
    if v.past_investigations.is_empty() {
        push("_none on record_");
    } else {
        for p in &v.past_investigations {
            push(&format!("- {} — {}", p.date.as_deref().unwrap_or("(no date)"), p.title));
            if let Some(c) = &p.suspected_cause {
                push(&format!("  - suspected cause: {} [{}, {}]", c.title, c.category, c.band));
            }
            let conf = match p.confidence {
                Some(c) => format!("{}%", js::to_fixed(c * 100.0, 0)),
                None => "n/a".to_string(),
            };
            push(&format!("  - confidence: {conf}; confirmed (proxy): {}", if p.confirmed_proxy { "yes" } else { "no" }));
            if !p.sources.is_empty() {
                push(&format!("  - evidence channels: {}", p.sources.join(", ")));
            }
        }
    }
    push("");
    if !v.recurring_patterns.is_empty() {
        push("Recurring patterns (same incident shape, repeated):");
        for r in &v.recurring_patterns {
            push(&format!("- {} ×{}", r.signature, r.count));
        }
        push("");
    }

    // --- Useful evidence sources ------------------------------------------
    push("## Useful evidence sources");
    push("");
    if !v.evidence_sources.channels.is_empty() {
        push("Channels that have produced evidence for this area before:");
        for c in &v.evidence_sources.channels {
            push(&format!("- {c}"));
        }
    } else {
        push("No incident-evidence channels recorded for this area yet.");
    }
    push("");
    push("Always available:");
    for a in &v.evidence_sources.always_available {
        push(&format!("- {a}"));
    }
    push("");

    // --- Weak spots --------------------------------------------------------
    push("## Weak spots");
    push("");
    push(&format!("- Unreferenced symbols (repo-wide): {}", v.weak_spots.fragile.dead_code));
    push(&format!("- High-coupling pairs, co-changes ≥ 3 (repo-wide): {}", v.weak_spots.fragile.high_coupling_pairs));
    if !v.weak_spots.test_light_subsystems.is_empty() {
        push(&format!("- Test/example-heavy subsystems: {}", v.weak_spots.test_light_subsystems.join(", ")));
    }
    if v.weak_spots.low_prior_evidence {
        push(&format!("- Low prior evidence: {}", v.weak_spots.low_prior_evidence_reason));
    }
    push("");

    push("_Generated from live code structure + git + deterministic incident memory — no AI. Past incidents are context only; \"confirmed\" is a display proxy, not a stored fact._");

    lines.join("\n")
}

pub fn memory_view_to_json(v: &MemoryView) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}
