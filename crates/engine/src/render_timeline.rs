//! Human-facing renderers for a ChangeTimeline. Pure, deterministic, no I/O.

use crate::changes::ChangeImpactReport;
use crate::deploy_timeline::ChangeTimeline;
use crate::render_changes::change_impact_to_compact_object;
use crate::render_what_changed::{compact_repo_state, working_tree_line};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

const COMMIT_CAP: usize = 25;

fn change_impact(t: &ChangeTimeline) -> Option<ChangeImpactReport> {
    t.change_impact.clone()
}

// Caps for the compact (default) JSON projection — `timeline --json` produced ~2.6 MB raw.
const JSON_COMMIT_CAP: usize = 25;
const JSON_TOP_FILE_CAP: usize = 15;

/// Sectioned text report for terminal output.
pub fn render_change_timeline(t: &ChangeTimeline) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push("# Change Timeline".into());
    lines.push("".into());

    lines.push("## Summary".into());
    // Show the effective window so users understand why counts may differ from what-changed/changes.
    let since_label = t.window.since.as_deref().unwrap_or("(all history)");
    let until_label = t.window.until.as_deref().unwrap_or("HEAD");
    lines.push(format!("Range: {since_label} → {until_label}"));
    lines.push(t.summary.clone());
    lines.push("".into());

    lines.push(format!("> {}", t.note));
    lines.push("".into());

    // Working tree — uncommitted changes are a change source `git log` can't see.
    if let Some(s) = t.repo_state.as_ref().filter(|s| s.dirty) {
        lines.push(working_tree_line(s));
        lines.push("".into());
    }

    lines.push("## Commits".into());
    if t.commits.is_empty() {
        lines.push("  (none in window)".into());
    } else {
        let shown = &t.commits[..t.commits.len().min(COMMIT_CAP)];
        for c in shown {
            lines.push(format!("  {} {}  {}  ({} file(s))", c.short_sha, c.date_iso, c.subject, c.files.len()));
        }
        let remaining = t.commits.len() - shown.len();
        if remaining > 0 {
            lines.push(format!("  +{remaining} more"));
        }
    }

    if let Some(ci) = change_impact(t) {
        lines.push("".into());
        lines.push("## Change impact".into());
        // Show the exact git refs so users can cross-reference with horus changes <base> <compare>.
        lines.push(format!("Git range: {}..{}", ci.base, ci.compare));
        lines.push(ci.summary.clone());
        for f in &ci.affected_flows {
            lines.push(format!("  - {}", f.flow_name));
        }
    }

    lines.join("\n")
}

/// Stable JSON serialization — compact by default; `full` restores the raw timeline.
pub fn change_timeline_to_json(t: &ChangeTimeline, full: bool) -> String {
    if full {
        return horus_core::json::to_js_json_pretty(t).unwrap_or_default();
    }

    let commits: Vec<Value> = t
        .commits
        .iter()
        .take(JSON_COMMIT_CAP)
        .map(|c| {
            json!({
                "shortSha": c.short_sha,
                "dateIso": c.date_iso,
                "author": c.author,
                "subject": c.subject,
                "fileCount": c.files.len(),
            })
        })
        .collect();

    // Top changed files across the WHOLE window (not just the shown commits).
    let mut file_counts: IndexMap<&str, i64> = IndexMap::new();
    for c in &t.commits {
        for f in &c.files {
            *file_counts.entry(f.as_str()).or_insert(0) += 1;
        }
    }
    let mut ranked: Vec<(&str, i64)> = file_counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    let top_changed_files: Vec<Value> =
        ranked.iter().take(JSON_TOP_FILE_CAP).map(|(file, commits)| json!({ "file": file, "commits": commits })).collect();

    let truncated_count = t.commits.len() - commits.len();
    let mut out = Map::new();
    out.insert("window".into(), json!(t.window));
    out.insert("summary".into(), json!(t.summary));
    out.insert("note".into(), json!(t.note));
    out.insert("repoState".into(), compact_repo_state(t.repo_state.as_ref()));
    if let Some(si) = t.source_index.as_ref() {
        out.insert("sourceIndex".into(), json!(si));
    }
    out.insert("commitCount".into(), json!(t.commits.len()));
    // Commits are newest-first (git log order) — expose the window edges directly.
    out.insert("firstCommitAt".into(), json!(t.commits.last().map(|c| c.date_iso.clone())));
    out.insert("lastCommitAt".into(), json!(t.commits.first().map(|c| c.date_iso.clone())));
    out.insert("commits".into(), Value::Array(commits));
    out.insert("topChangedFiles".into(), Value::Array(top_changed_files));
    out.insert(
        "changeImpact".into(),
        change_impact(t).as_ref().map(change_impact_to_compact_object).unwrap_or(Value::Null),
    );
    if truncated_count > 0 {
        out.insert("truncated".into(), json!(true));
        out.insert("truncatedCount".into(), json!(truncated_count));
        out.insert("hint".into(), json!("re-run with --full for the complete structure"));
    }
    horus_core::json::to_js_json_pretty(&Value::Object(out)).unwrap_or_default()
}
