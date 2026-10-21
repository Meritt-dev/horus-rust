//! Human-facing renderers for an InvestigationReport. Pure, deterministic, no I/O.

use crate::js::{number_string, slice_chars, to_fixed};
use crate::source_status::RuntimeSourceStatus;
use crate::types::{evidence_kind_name, provider_kind_name, InvestigationReport, RouteStep};
use horus_core::{Evidence, EvidenceKind, ProviderKind};
use indexmap::IndexMap;
use crate::git_collector::BoundedGitChange;
use crate::memory::SimilarIncident;

/// Serialized name of a cause-chain step role (`'trigger' | 'propagation' | 'symptom' | 'impact'`).
pub(crate) fn role_name(role: crate::cause_chain::CauseChainStepRole) -> &'static str {
    use crate::cause_chain::CauseChainStepRole as R;
    match role {
        R::Trigger => "trigger",
        R::Propagation => "propagation",
        R::Symptom => "symptom",
        R::Impact => "impact",
    }
}

/// Short, citable evidence id (first 8 chars).
pub(crate) fn short_id(id: &str) -> String {
    slice_chars(id, 8)
}

use crate::router::format_route_step;

/// HOR-386 — the human form of the router's `RouteStep[]`; `bullet` differs only by section style.
fn render_route_steps(steps: Option<&Vec<RouteStep>>, bullet: &str) -> Vec<String> {
    match steps {
        Some(steps) if !steps.is_empty() => steps.iter().map(|s| format!("{bullet} {}", format_route_step(s))).collect(),
        _ => vec![],
    }
}

/// Display name for a symbol (HOR-214): qualifies class members with their owning class so
/// caller lists don't render bare `constructor, constructor`; never double-qualifies a dotted name.
pub fn symbol_display_name(sym: &horus_core::Symbol) -> String {
    match sym.class_name.as_deref() {
        Some(c) if !c.is_empty() && !sym.name.contains('.') => format!("{c}.{}", sym.name),
        _ => sym.name.clone(),
    }
}

/// Format a symbol location (HOR-211): `path:start-end`, `path:start`, or bare `path` —
/// never the meaningless `path:0`.
pub fn format_symbol_location(file_path: &str, start_line: Option<i64>, end_line: Option<i64>) -> String {
    match start_line {
        None => file_path.to_string(),
        Some(s) if s <= 0 => file_path.to_string(),
        Some(s) => match end_line {
            Some(e) if e > s => format!("{file_path}:{s}-{e}"),
            _ => format!("{file_path}:{s}"),
        },
    }
}

// ── Queue runtime rendering helpers (HOR-13) ─────────────────────────────────

/// True for queue-state evidence that represents a "summary" signal (raw counts).
fn is_queue_summary(e: &Evidence) -> bool {
    e.payload.get("isPaused").is_some()
}

fn payload_count(e: &Evidence, key: &str) -> String {
    match e.payload.get(key) {
        None | Some(serde_json::Value::Null) => "0".into(),
        Some(serde_json::Value::Number(n)) => number_string(n.as_f64().unwrap_or(0.0)),
        Some(v) => v.to_string(),
    }
}

/// Format summary counts as a compact inline string.
fn fmt_queue_counts(e: &Evidence) -> String {
    [
        format!("{} waiting", payload_count(e, "waiting")),
        format!("{} active", payload_count(e, "active")),
        format!("{} failed", payload_count(e, "failed")),
        format!("{} delayed", payload_count(e, "delayed")),
    ]
    .join(" · ")
}

/// Remove the "{queueName}: " prefix from a signal title for grouped display.
fn strip_queue_name(title: &str, name: &str) -> String {
    let pfx = format!("{name}: ");
    title.strip_prefix(&pfx).unwrap_or(title).to_string()
}

/// Group queue-state evidence by queue name, anomaly signals first and the summary last.
pub fn group_queue_evidence(evidence: &[Evidence]) -> IndexMap<String, Vec<&Evidence>> {
    let mut map: IndexMap<String, Vec<&Evidence>> = IndexMap::new();
    for e in evidence {
        if e.source != ProviderKind::Queue || e.kind != EvidenceKind::QueueState {
            continue;
        }
        let name = e.links.queue_name.clone().unwrap_or_else(|| "unknown".into());
        map.entry(name).or_default().push(e);
    }
    for evs in map.values_mut() {
        evs.sort_by(|a, b| {
            let (as_, bs_) = (is_queue_summary(a), is_queue_summary(b));
            if as_ && !bs_ {
                return std::cmp::Ordering::Greater;
            }
            if !as_ && bs_ {
                return std::cmp::Ordering::Less;
            }
            crate::js::cmp_f64(b.relevance, a.relevance)
        });
    }
    map
}

/// Set of IDs for all queue-state evidence in the report.
fn queue_evidence_ids(evidence: &[Evidence]) -> std::collections::HashSet<&str> {
    evidence
        .iter()
        .filter(|e| e.source == ProviderKind::Queue && e.kind == EvidenceKind::QueueState)
        .map(|e| e.id.as_str())
        .collect()
}

/// Confidence at or above this value suppresses the "why not higher" section.
pub const CONFIDENCE_EXPLAIN_THRESHOLD: f64 = 0.80;

/// Human-readable reasons why confidence is below the threshold, or `None` when it meets the bar.
pub fn explain_low_confidence(r: &InvestigationReport) -> Option<Vec<String>> {
    if r.confidence >= CONFIDENCE_EXPLAIN_THRESHOLD {
        return None;
    }
    let mut reasons: Vec<String> = vec![];

    if let Some(status) = r.source_status.clone() {
        let not_configured: Vec<&str> =
            status.sources.iter().filter(|s| s.status == RuntimeSourceStatus::NotConfigured).map(|s| s.source.as_str()).collect();
        if !not_configured.is_empty() {
            reasons.push(format!("no runtime data — {} not configured", not_configured.join(", ")));
        }
    }

    if !r.gap_analysis.gaps.is_empty() {
        let mut sorted: Vec<_> = r.gap_analysis.gaps.iter().collect();
        sorted.sort_by(|a, b| crate::js::cmp_f64(b.confidence_impact, a.confidence_impact));
        let top = sorted[0];
        reasons.push(format!("top gap: {} (−{} conf) — {}", top.dimension, to_fixed(top.confidence_impact, 2), top.why));
    }

    if let Some(m) = r.correlation.missing.first() {
        reasons.push(format!("missing evidence: {}", m.note));
    }

    if r.gap_analysis.confidence_ceiling < 1.0 {
        reasons.push(format!(
            "confidence ceiling: {} — filling gaps above would raise it",
            number_string(r.gap_analysis.confidence_ceiling)
        ));
    }

    if reasons.is_empty() {
        None
    } else {
        Some(reasons)
    }
}

/// A short caveat when no runtime source contributed evidence; `None` when runtime data is
/// present or when sourceStatus is absent (pre-HOR-70 reports).
pub fn runtime_source_caveat(r: &InvestigationReport) -> Option<String> {
    let status = r.source_status.clone()?;
    if status.sources.iter().any(|s| s.status == RuntimeSourceStatus::Contributed) {
        return None;
    }
    let unavailable: Vec<&str> =
        status.sources.iter().filter(|s| s.status == RuntimeSourceStatus::Unavailable).map(|s| s.source.as_str()).collect();
    if !unavailable.is_empty() {
        return Some(format!(
            "{} configured but unavailable in this run (missing credentials or URL) — see `horus doctor`",
            unavailable.join(", ")
        ));
    }
    let not_configured: Vec<&str> =
        status.sources.iter().filter(|s| s.status == RuntimeSourceStatus::NotConfigured).map(|s| s.source.as_str()).collect();
    if not_configured.is_empty() {
        return None;
    }
    Some(format!(
        "no runtime evidence — {} not in this config; findings rest on code, git, and topology",
        not_configured.join(", ")
    ))
}

fn similar_incidents(r: &InvestigationReport) -> Vec<&SimilarIncident> {
    r.similar_incidents.iter().collect()
}

fn truncate_summary(s: &str) -> String {
    if s.chars().count() > 80 {
        format!("{}...", slice_chars(s, 77))
    } else {
        s.to_string()
    }
}

pub(crate) fn recent_changes(r: &InvestigationReport) -> Option<&BoundedGitChange> {
    r.recent_changes.as_ref()
}

/// A clean, sectioned text report suitable for a terminal or a log.
pub fn render_report(r: &InvestigationReport) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push(format!("# Investigation {}", r.id));
    lines.push(format!("Hint: {}", r.input.hint));
    if let Some(repo) = r.input.repo.as_deref().filter(|s| !s.is_empty()) {
        lines.push(format!("Repo: {repo}"));
    }
    if let Some(service) = r.input.service.as_deref().filter(|s| !s.is_empty()) {
        lines.push(format!("Service: {service}"));
    }
    if let Some(since) = r.input.since.as_deref().filter(|s| !s.is_empty()) {
        lines.push(format!("Since: {since}"));
    }
    // Gap #5: a behavioral "how does X work" report renders the flow walkthrough and skips the
    // incident pipeline entirely.
    if let Some(b) = &r.behavioral {
        lines.push("".into());
        lines.push("## Summary".into());
        lines.push(r.summary.clone());
        lines.push("".into());
        lines.push(format!("## Flow{}", b.entry.as_ref().map(|e| format!(" — {}", e.name)).unwrap_or_default()));
        if b.steps.is_empty() {
            lines.push("(no execution flow could be reconstructed from the source graph)".into());
        } else {
            for (i, s) in b.steps.iter().take(20).enumerate() {
                lines.push(format!("  {}. {} ({})", i + 1, s.name, format_symbol_location(&s.file_path, s.start_line, s.end_line)));
            }
            if b.steps.len() > 20 {
                lines.push(format!("  … and {} more", b.steps.len() - 20));
            }
        }
        if !b.external_calls.is_empty() || !b.persistence.is_empty() {
            lines.push("".into());
        }
        if !b.external_calls.is_empty() {
            lines.push(format!("External calls: {}", b.external_calls.join(", ")));
        }
        if !b.persistence.is_empty() {
            lines.push(format!("Persistence: {}", b.persistence.join(", ")));
        }
        lines.push("".into());
        if !r.next_actions.is_empty() {
            lines.push("## Next actions".into());
            for a in &r.next_actions {
                lines.push(format!("- {a}"));
            }
            lines.push("".into());
        }
        let behavioral_steps = render_route_steps(r.next_steps.as_ref(), "-");
        if !behavioral_steps.is_empty() {
            lines.push("## Suggested next".into());
            lines.extend(behavioral_steps);
            lines.push("".into());
        }
        lines.push("— Behavioral walkthrough, not a fault hunt. Phrase it as a symptom (e.g. \"X failing\") for an incident investigation.".into());
        return lines.join("\n");
    }
    lines.push(format!("Confidence: {}", to_fixed(r.confidence, 2)));
    if let Some(caveat) = runtime_source_caveat(r) {
        lines.push(format!("  ↳ {caveat}"));
    }
    lines.push("".into());

    lines.push("## Summary".into());
    lines.push(r.summary.clone());
    lines.push("".into());

    if let Some(explain) = explain_low_confidence(r) {
        lines.push("## Why confidence is not higher".into());
        for reason in explain {
            lines.push(format!("  - {reason}"));
        }
        lines.push("".into());
    }

    lines.push("## Similar past incidents".into());
    let similar = similar_incidents(r);
    if similar.is_empty() {
        lines.push("(none on record)".into());
    } else {
        for s in &similar {
            lines.push(format!(
                "- {} (overlap {}%) — shared: {}",
                s.title,
                to_fixed(s.overlap * 100.0, 0),
                s.shared_tags.join(", ")
            ));
            if let Some(summary) = s.summary.as_deref().filter(|s| !s.is_empty()) {
                lines.push(format!("    {}", truncate_summary(summary)));
            }
        }
        lines.push("Context only — past incidents inform, but never override, the current evidence.".into());
    }
    lines.push("".into());

    lines.push("## Seed(s)".into());
    if r.seeds.is_empty() {
        lines.push("(none)".into());
    } else {
        for s in &r.seeds {
            let sig = s.signature.as_deref().filter(|x| !x.is_empty()).map(|x| format!(" — {x}")).unwrap_or_default();
            lines.push(format!("- {} ({}){sig}", s.name, format_symbol_location(&s.file_path, s.start_line, s.end_line)));
        }
    }
    lines.push("".into());

    lines.push("## Findings".into());
    if r.findings.is_empty() {
        lines.push("(none)".into());
    } else {
        for f in &r.findings {
            lines.push(format!("- [{}] {}", to_fixed(f.confidence, 2), f.title));
            if let Some(d) = f.detail.as_deref().filter(|d| !d.is_empty()) {
                lines.push(format!("    {d}"));
            }
            if !f.evidence_ids.is_empty() {
                lines.push(format!("    evidence: {}", f.evidence_ids.iter().map(|i| short_id(i)).collect::<Vec<_>>().join(", ")));
            }
        }
    }
    lines.push("".into());

    lines.push("## Timeline".into());
    if r.timeline.events.is_empty() {
        lines.push("(none)".into());
    } else {
        for ev in &r.timeline.events {
            lines.push(format!("  {}. [{}] {}", ev.order, ev.at.as_deref().unwrap_or("structural"), ev.title));
        }
    }
    lines.push("".into());

    lines.push("## Boundary crossings".into());
    if r.timeline.boundary_crossings.is_empty() {
        lines.push("(none)".into());
    } else {
        for bc in &r.timeline.boundary_crossings {
            lines.push(format!(
                "  {}: {} -> {}",
                bc.queue_name,
                bc.producer.as_deref().unwrap_or("?"),
                bc.worker.as_deref().unwrap_or("?")
            ));
        }
    }
    lines.push("".into());

    lines.push("## Correlation".into());

    lines.push("### Cause chains".into());
    if r.correlation.chains.is_empty() {
        lines.push("  (none)".into());
    } else {
        for chain in &r.correlation.chains {
            lines.push(format!("  [{}] {} — {}", to_fixed(chain.strength, 2), chain.title, chain.rationale));
        }
    }

    lines.push("### Related evidence groups".into());
    if r.correlation.groups.is_empty() {
        lines.push("  (none)".into());
    } else {
        for group in &r.correlation.groups {
            lines.push(format!("  {} ({} items)", group.reason, group.evidence_ids.len()));
        }
    }

    lines.push("### Missing evidence".into());
    if r.correlation.missing.is_empty() {
        lines.push("  none".into());
    } else {
        for m in &r.correlation.missing {
            lines.push(format!("  - {}", m.note));
        }
    }
    lines.push("".into());

    let queue_ids = queue_evidence_ids(&r.evidence);

    lines.push("## Suspected causes (ranked)".into());
    if r.suspected_causes.is_empty() {
        lines.push("(none)".into());
    } else {
        for (i, c) in r.suspected_causes.iter().enumerate() {
            let queue_tag = if c.source_evidence_ids.iter().any(|id| queue_ids.contains(id.as_str())) { " [↑ queue]" } else { "" };
            lines.push(format!("{}. [{} / {}] {}{queue_tag}", i + 1, to_fixed(c.final_score, 2), c.band.as_str(), c.title));
            if !c.source_evidence_ids.is_empty() {
                lines.push(format!(
                    "    evidence: {}",
                    c.source_evidence_ids.iter().map(|i| short_id(i)).collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }
    lines.push("".into());

    lines.push("## Hypotheses".into());
    let all_unconfirmed = !r.hypotheses.is_empty() && r.hypotheses.iter().all(|h| h.verdict == crate::validate::Verdict::Unconfirmed);
    if all_unconfirmed {
        lines.push("_All hypotheses below are unconfirmed placeholders — runtime evidence is required to validate them._".into());
    }
    if r.hypotheses.is_empty() {
        lines.push("(none)".into());
    } else {
        for h in &r.hypotheses {
            lines.push(format!(
                "  [{}] [{} (was {})] {}: {}",
                h.verdict.as_str(),
                to_fixed(h.confidence, 2),
                to_fixed(h.prior_confidence, 2),
                h.category,
                h.statement
            ));
            lines.push(format!("      {}", h.rationale));
            if !h.missing_evidence.is_empty() {
                lines.push(format!("      · missing: {}", h.missing_evidence.join("; ")));
            }
        }
    }
    lines.push("".into());

    if let Some(chains) = r.cause_chains.as_ref().filter(|c| !c.is_empty()) {
        lines.push("## Cause chains".into());
        for chain in chains {
            lines.push(format!("  [{}] {}: {}", to_fixed(chain.confidence, 2), chain.category, chain.summary));
            for (i, step) in chain.steps.iter().enumerate() {
                let prefix = if i == chain.steps.len() - 1 { "    └─" } else { "    ├─" };
                let ev_cite = if step.evidence_ids.is_empty() {
                    String::new()
                } else {
                    format!(" (evidence: {})", step.evidence_ids.iter().map(|i| short_id(i)).collect::<Vec<_>>().join(", "))
                };
                lines.push(format!("{prefix} [{}] {}{ev_cite}", role_name(step.role), step.label));
            }
        }
        lines.push("".into());
    }

    lines.push("## Evidence gaps (what we don't know)".into());
    if r.gap_analysis.gaps.is_empty() {
        lines.push("(no major evidence gaps)".into());
    } else {
        for gap in &r.gap_analysis.gaps {
            lines.push(format!(
                "  - {}: {}  → next: {}  (−{} conf)",
                gap.dimension,
                gap.why,
                gap.next_source,
                to_fixed(gap.confidence_impact, 2)
            ));
        }
        lines.push("".into());
        lines.push("Blind spots:".into());
        for bs in &r.gap_analysis.blind_spots {
            lines.push(format!("  - {bs}"));
        }
        lines.push("".into());
        lines.push(format!(
            "Confidence ceiling: {} (current confidence is capped at this until the gaps are filled).",
            number_string(r.gap_analysis.confidence_ceiling)
        ));
    }
    lines.push("".into());

    lines.push("## Evidence".into());
    if r.evidence.is_empty() {
        lines.push("(none)".into());
    } else {
        for e in &r.evidence {
            lines.push(format!("- {} [{}/{}] {}", short_id(&e.id), provider_kind_name(e.source), evidence_kind_name(e.kind), e.title));
        }
    }
    lines.push("".into());

    let queue_groups = group_queue_evidence(&r.evidence);
    let queue_gap = r.gap_analysis.gaps.iter().find(|g| g.dimension == "queue runtime state");
    if !queue_groups.is_empty() || queue_gap.is_some() {
        lines.push("## Queue runtime".into());
        if queue_groups.is_empty() {
            lines.push(format!("  ({})", queue_gap.map(|g| g.why.as_str()).unwrap_or("")));
        } else {
            for (name, evs) in &queue_groups {
                lines.push(format!("  {name}"));
                for e in evs {
                    let detail = if is_queue_summary(e) { fmt_queue_counts(e) } else { strip_queue_name(&e.title, name) };
                    lines.push(format!("    [{}] {detail}", to_fixed(e.relevance, 2)));
                }
            }
        }
        lines.push("".into());
    }

    if let Some(rc) = recent_changes(r).filter(|rc| !rc.commits.is_empty()) {
        let until = rc.window.until.as_deref().filter(|u| !u.is_empty()).map(|u| format!("..{u}")).unwrap_or_else(|| "..HEAD".into());
        let plus = if rc.truncated { "+" } else { "" };
        lines.push("## Recent changes".into());
        lines.push(format!("  Window: {}{until}", rc.window.since));
        lines.push(format!("  Commits: {}{plus}", rc.commits.len()));
        for c in rc.commits.iter().take(10) {
            lines.push(format!("  {} {}", c.short_sha, c.subject));
        }
        if !rc.file_stats.is_empty() {
            lines.push(format!("  Files: {}{plus}", rc.changed_files.len()));
            for f in rc.file_stats.iter().take(8) {
                lines.push(format!("    +{} -{} {}", f.insertions, f.deletions, f.path));
            }
        }
        if rc.truncated {
            if let Some(reason) = rc.truncated_reason.as_deref().filter(|s| !s.is_empty()) {
                lines.push(format!("  (truncated: {reason})"));
            }
        }
        lines.push("".into());
    }

    lines.push("## Next actions".into());
    if r.next_actions.is_empty() {
        lines.push("(none)".into());
    } else {
        for a in &r.next_actions {
            lines.push(format!("- {a}"));
        }
    }

    let suggested = render_route_steps(r.next_steps.as_ref(), "-");
    if !suggested.is_empty() {
        lines.push("".into());
        lines.push("## Suggested next".into());
        lines.extend(suggested);
    }

    lines.join("\n")
}

/// Stable JSON serialization of the full report.
pub fn report_to_json(r: &InvestigationReport) -> String {
    horus_core::json::to_js_json_pretty(r).unwrap_or_default()
}

/// A concise, shareable Markdown report — the deterministic output contract for
/// `horus investigate` (HOR-9): the at-a-glance brief with the six required sections.
pub fn report_to_markdown(r: &InvestigationReport) -> String {
    let mut out: Vec<String> = vec![];

    out.push(format!("# Investigation Report — {}", r.input.hint));
    out.push("".into());
    let md_caveat = runtime_source_caveat(r).map(|c| format!(" _({c})_")).unwrap_or_default();
    out.push(format!("**Confidence:** {}{md_caveat}", to_fixed(r.confidence, 2)));
    if let Some(service) = r.input.service.as_deref().filter(|s| !s.is_empty()) {
        out.push(format!("**Service:** {service}"));
    }
    if let Some(since) = r.input.since.as_deref().filter(|s| !s.is_empty()) {
        out.push(format!("**Since:** {since}"));
    }
    out.push("".into());
    out.push("## Summary".into());
    out.push(r.summary.clone());
    out.push("".into());

    if let Some(explain) = explain_low_confidence(r) {
        out.push("## Why confidence is not higher".into());
        for reason in explain {
            out.push(format!("- {reason}"));
        }
        out.push("".into());
    }

    out.push("## Similar past incidents".into());
    let similar = similar_incidents(r);
    if similar.is_empty() {
        out.push("(none on record)".into());
    } else {
        for s in &similar {
            out.push(format!(
                "- {} (overlap {}%) — shared: {}",
                s.title,
                to_fixed(s.overlap * 100.0, 0),
                s.shared_tags.join(", ")
            ));
            if let Some(summary) = s.summary.as_deref().filter(|s| !s.is_empty()) {
                out.push(format!("  _{}_", truncate_summary(summary)));
            }
        }
        out.push("_Context only — past incidents inform, but never override, the current evidence._".into());
    }
    out.push("".into());

    let md_queue_ids = queue_evidence_ids(&r.evidence);

    out.push("## Suspected causes".into());
    if r.suspected_causes.is_empty() {
        out.push("_none_".into());
    } else {
        for (i, c) in r.suspected_causes.iter().enumerate() {
            let queue_tag = if c.source_evidence_ids.iter().any(|id| md_queue_ids.contains(id.as_str())) { " `[↑ queue]`" } else { "" };
            out.push(format!("{}. **({}, {})**{queue_tag} {}", i + 1, to_fixed(c.final_score, 2), c.band.as_str(), c.title));
        }
    }
    out.push("".into());

    out.push("## Hypotheses".into());
    let md_all_unconfirmed = !r.hypotheses.is_empty() && r.hypotheses.iter().all(|h| h.verdict == crate::validate::Verdict::Unconfirmed);
    if md_all_unconfirmed {
        out.push("_All hypotheses below are unconfirmed placeholders — runtime evidence is required to validate them._".into());
    }
    if r.hypotheses.is_empty() {
        out.push("_none_".into());
    } else {
        for h in &r.hypotheses {
            out.push(format!(
                "- `{}` **{}** (was {}) — {}: {}",
                h.verdict.as_str(),
                to_fixed(h.confidence, 2),
                to_fixed(h.prior_confidence, 2),
                h.category,
                h.statement
            ));
        }
    }
    out.push("".into());

    out.push("## Evidence gaps (what we don't know)".into());
    if r.gap_analysis.gaps.is_empty() {
        out.push("_(no major evidence gaps)_".into());
    } else {
        for gap in &r.gap_analysis.gaps {
            out.push(format!(
                "- **{}**: {}  → _next: {}_ (−{} conf)",
                gap.dimension,
                gap.why,
                gap.next_source,
                to_fixed(gap.confidence_impact, 2)
            ));
        }
        out.push("".into());
        out.push("**Blind spots:**".into());
        for bs in &r.gap_analysis.blind_spots {
            out.push(format!("- {bs}"));
        }
        out.push("".into());
        out.push(format!(
            "_Confidence ceiling: **{}** — current confidence is capped at this until the gaps are filled._",
            number_string(r.gap_analysis.confidence_ceiling)
        ));
    }
    out.push("".into());

    out.push("## Timeline".into());
    if r.timeline.events.is_empty() {
        out.push("_none_".into());
    } else {
        for ev in &r.timeline.events {
            out.push(format!("{}. `{}` {}", ev.order, ev.at.as_deref().unwrap_or("structural"), ev.title));
        }
    }
    out.push("".into());

    out.push(format!("## Evidence ({})", r.evidence.len()));
    if r.evidence.is_empty() {
        out.push("_none_".into());
    } else {
        for e in &r.evidence {
            out.push(format!("- `{}` [{}/{}] {}", short_id(&e.id), provider_kind_name(e.source), evidence_kind_name(e.kind), e.title));
        }
    }
    out.push("".into());

    let md_queue_groups = group_queue_evidence(&r.evidence);
    let md_queue_gap = r.gap_analysis.gaps.iter().find(|g| g.dimension == "queue runtime state");
    if !md_queue_groups.is_empty() || md_queue_gap.is_some() {
        out.push("## Queue runtime".into());
        if md_queue_groups.is_empty() {
            out.push(format!("_{}_", md_queue_gap.map(|g| g.why.as_str()).unwrap_or("")));
        } else {
            for (name, evs) in &md_queue_groups {
                out.push(format!("**{name}**"));
                for e in evs {
                    let detail = if is_queue_summary(e) { fmt_queue_counts(e) } else { strip_queue_name(&e.title, name) };
                    out.push(format!("- `{}` {detail}", to_fixed(e.relevance, 2)));
                }
            }
        }
        out.push("".into());
    }

    out.push("## Next actions".into());
    if r.next_actions.is_empty() {
        out.push("_none_".into());
    } else {
        for a in &r.next_actions {
            out.push(format!("- [ ] {a}"));
        }
    }
    out.push("".into());
    let md_suggested = render_route_steps(r.next_steps.as_ref(), "- [ ]");
    if !md_suggested.is_empty() {
        out.push("## Suggested next".into());
        out.extend(md_suggested);
        out.push("".into());
    }
    out.push("---".into());
    out.push("_Generated by Horus — deterministic report, no AI._".into());

    out.join("\n")
}
