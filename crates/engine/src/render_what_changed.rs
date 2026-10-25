//! HOR-30 — Render helpers for WhatChangedReport.

use crate::code_provider::RepoState;
use crate::render_changes::{change_impact_to_compact_object, head};
use crate::what_changed::WhatChangedReport;
use serde_json::{json, Map, Value};

// Cap for per-commit file lists in the compact (default) JSON projection.
const JSON_COMMIT_FILE_CAP: usize = 10;

pub fn render_what_changed(r: &WhatChangedReport) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push("# What changed".into());
    lines.push("".into());
    // Show the effective window so users can understand why counts may differ from horus timeline.
    let since_label = r.window.since.as_deref().unwrap_or("(all history)");
    let until_label = r.window.until.as_deref().unwrap_or("HEAD");
    lines.push(format!("Range: {since_label} → {until_label}"));
    lines.push(r.summary.clone());
    lines.push("".into());
    lines.push(format!("> {}", r.note));

    // Git truth FIRST — what the diff actually says, independent of the source index.
    if let Some(g) = &r.git_truth {
        lines.push("".into());
        lines.push(format!(
            "## Git truth: {} file(s) changed, +{}/-{} ({}..{})",
            g.file_count, g.insertions, g.deletions, g.base, g.compare
        ));
        lines.push(format!(
            "  runtime {} · test {} · docs {} · config {}",
            g.buckets.runtime, g.buckets.test, g.buckets.docs, g.buckets.config
        ));
        for f in g.files.iter().take(10) {
            lines.push(format!("  {} {}", f.status, f.path));
        }
        if g.file_count > 10 {
            lines.push(format!("  +{} more", g.file_count - 10));
        }
    }

    // Working tree — uncommitted changes are a change source commit history can't see.
    if let Some(s) = r.repo_state.as_ref().filter(|s| s.dirty) {
        lines.push("".into());
        lines.push(working_tree_line(s));
    }

    if !r.top_commits.is_empty() {
        lines.push("".into());
        lines.push("## Top commits".into());
        for c in &r.top_commits {
            lines.push(format!("  {}  {}  {}", c.short_sha, c.date_iso, c.subject));
        }
    }

    if !r.contributors.is_empty() {
        lines.push("".into());
        lines.push(format!(
            "## Top contributors: {}",
            r.contributors.iter().map(|c| format!("{} ×{}", c.author, c.commits)).collect::<Vec<_>>().join(", ")
        ));
    }

    lines.push("".into());
    if r.queue_topology.touched {
        lines.push(format!(
            "## Queue topology: touched — {}",
            r.queue_topology.files.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
        ));
    } else {
        lines.push("## Queue topology: no queue/worker files changed".into());
    }

    // Structural impact — the source-index view, reported separately from git truth.
    if let Some(ci) = &r.change_impact {
        lines.push("".into());
        lines.push(format!(
            "## Structural impact (source index): {} added / {} modified / {} removed symbols · {} execution flow(s) affected",
            ci.added.len(),
            ci.modified.len(),
            ci.removed.len(),
            ci.affected_flows.len()
        ));
        for f in &ci.affected_flows {
            lines.push(format!("  - {}", f.flow_name));
        }
        if let Some(related) = ci.related_incidents.as_ref().filter(|r| !r.is_empty()) {
            lines.push("".into());
            lines.push("## Past incidents in this code".into());
            for i in related {
                lines.push(format!("  - {} {} ({})", head(&i.created_at, 10), head(&i.hint, 100), i.investigation_id));
            }
        }
    }

    lines.join("\n")
}

pub(crate) fn working_tree_line(s: &RepoState) -> String {
    format!(
        "## Working tree (uncommitted): {} staged, {} unstaged, {} untracked (+{}/-{} vs HEAD)",
        s.staged_count, s.unstaged_count, s.untracked_count, s.insertions, s.deletions
    )
}

/// Compact repo state: counts stay exact, file lists slim to 10 entries each.
pub(crate) fn compact_repo_state(s: Option<&RepoState>) -> Value {
    match s {
        None => Value::Null,
        Some(s) => json!({
            "headSha": s.head_sha,
            "branch": s.branch,
            "dirty": s.dirty,
            "stagedCount": s.staged_count,
            "unstagedCount": s.unstaged_count,
            "untrackedCount": s.untracked_count,
            "insertions": s.insertions,
            "deletions": s.deletions,
            "staged": s.staged.iter().take(10).collect::<Vec<_>>(),
            "unstaged": s.unstaged.iter().take(10).collect::<Vec<_>>(),
            "untracked": s.untracked.iter().take(10).collect::<Vec<_>>(),
        }),
    }
}

/// Stable JSON serialization — compact by default; `full` restores the raw report.
pub fn what_changed_to_json(r: &WhatChangedReport, full: bool) -> String {
    if full {
        return horus_core::json::to_js_json_pretty(r).unwrap_or_default();
    }

    let mut omitted_files = 0usize;
    let top_commits: Vec<Value> = r
        .top_commits
        .iter()
        .map(|c| {
            omitted_files += c.files.len().saturating_sub(JSON_COMMIT_FILE_CAP);
            json!({
                "shortSha": c.short_sha,
                "dateIso": c.date_iso,
                "author": c.author,
                "subject": c.subject,
                "fileCount": c.files.len(),
                "files": c.files.iter().take(JSON_COMMIT_FILE_CAP).collect::<Vec<_>>(),
            })
        })
        .collect();

    let git_truth = match &r.git_truth {
        None => Value::Null,
        Some(g) => {
            let mut v = serde_json::to_value(g).unwrap_or(Value::Null);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("files".into(), json!(g.files.iter().take(25).collect::<Vec<_>>()));
            }
            v
        }
    };

    let mut out = Map::new();
    out.insert("window".into(), json!(r.window));
    out.insert("summary".into(), json!(r.summary));
    out.insert("note".into(), json!(r.note));
    out.insert("commitCount".into(), json!(r.commit_count));
    out.insert("gitTruth".into(), git_truth);
    out.insert("repoState".into(), compact_repo_state(r.repo_state.as_ref()));
    out.insert("topCommits".into(), Value::Array(top_commits));
    out.insert("contributors".into(), json!(r.contributors));
    out.insert("queueTopology".into(), json!(r.queue_topology));
    out.insert(
        "changeImpact".into(),
        r.change_impact.as_ref().map(change_impact_to_compact_object).unwrap_or(Value::Null),
    );
    if omitted_files > 0 {
        out.insert("truncated".into(), json!(true));
        out.insert("truncatedCount".into(), json!(omitted_files));
        out.insert("hint".into(), json!("re-run with --full for the complete structure"));
    }
    horus_core::json::to_js_json_pretty(&Value::Object(out)).unwrap_or_default()
}
