//! HOR-22 — Deployment / change-timeline reconstruction.
//! Treats git history as EVIDENCE, not conclusions.
//!
//! Git I/O comes from `code_provider` (ported-from @horus/connectors git/provider.ts);
//! the pure assembly lives in [`assemble_change_timeline`].

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::changes::{change_impact, ChangeImpactInput, ChangeImpactReport};
use crate::code_provider::{collect_repo_state, git_log, CodeProvider, GitCommit, GitLogOptions, RepoState};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceIndexFreshness {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_indexed_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChangeTimelineInput {
    pub repo_path: String,
    pub since: Option<String>,
    pub until: Option<String>,
    pub service: Option<String>,
    /// `.horus/source/meta.json` freshness, injected by the CLI when available.
    pub source_index: Option<SourceIndexFreshness>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeWindow {
    pub since: Option<String>,
    pub until: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeTimeline {
    pub window: ChangeWindow,
    pub commits: Vec<GitCommit>,
    /// Always serialized (`null` when the impact diff failed or no commits).
    pub change_impact: Option<ChangeImpactReport>,
    /// Null when the repo state could not be read.
    pub repo_state: Option<RepoState>,
    pub source_index: Option<SourceIndexFreshness>,
    pub summary: String,
    pub note: String,
}

/// `commits.filter(c => c.files.some(f => f.includes(service)))` (case-insensitive).
pub fn filter_commits_by_service(commits: Vec<GitCommit>, service: Option<&str>) -> Vec<GitCommit> {
    let Some(service) = service else { return commits };
    let needle = service.to_lowercase();
    commits.into_iter().filter(|c| c.files.iter().any(|f| f.to_lowercase().contains(&needle))).collect()
}

/// The `(base, compare)` refs the TS code diffs for change impact: `oldest^..newest`.
pub fn impact_range(commits: &[GitCommit]) -> Option<(String, String)> {
    let oldest = commits.last()?;
    let newest = commits.first()?;
    Some((format!("{}^", oldest.sha), newest.sha.clone()))
}

/// Assemble the timeline from already-collected inputs (`commits` must already be
/// service-filtered via [`filter_commits_by_service`]).
pub fn assemble_change_timeline(
    input: &ChangeTimelineInput,
    commits: Vec<GitCommit>,
    impact: Option<ChangeImpactReport>,
    repo_state: Option<RepoState>,
) -> ChangeTimeline {
    let service = input.service.as_deref();

    // Strip trailing period from impact.summary before embedding — we add our own.
    let impact_part = match impact.as_ref().map(|i| i.summary.as_str()) {
        Some(s) => format!("; {}", s.strip_suffix('.').unwrap_or(s)),
        None => String::new(),
    };

    let dirty_part = match &repo_state {
        Some(rs) if rs.dirty => format!(
            "; working tree has uncommitted changes ({} staged, {} unstaged, {} untracked)",
            rs.staged_count, rs.unstaged_count, rs.untracked_count
        ),
        _ => String::new(),
    };

    let summary = format!(
        "{} commit(s){} in window{}{impact_part}{dirty_part}.",
        commits.len(),
        service.map(|s| format!(" touching {s}")).unwrap_or_default(),
        input.since.as_deref().map(|s| format!(" since {s}")).unwrap_or_default()
    );

    let note = if commits.is_empty() && repo_state.as_ref().is_some_and(|rs| rs.dirty) {
        "No commits in the window, but the working tree carries uncommitted changes — they are reported as a working-tree change source above, not in commit history."
    } else {
        "Changes are evidence, not conclusions — a change in this window is not automatically the cause."
    };

    ChangeTimeline {
        window: ChangeWindow { since: input.since.clone(), until: input.until.clone(), service: service.map(str::to_string) },
        commits,
        change_impact: impact,
        repo_state,
        source_index: input.source_index.clone(),
        summary,
        note: note.into(),
    }
}

/// HOR-22 entry point: git log (service-filtered) + change impact over the window +
/// working-tree state, assembled into a [`ChangeTimeline`].
pub async fn reconstruct_change_timeline(
    input: ChangeTimelineInput,
    code: &dyn CodeProvider,
) -> Result<ChangeTimeline> {
    let commits = git_log(
        &input.repo_path,
        GitLogOptions { since: input.since.clone(), until: input.until.clone(), max_count: None },
    )
    .await?;
    let commits = filter_commits_by_service(commits, input.service.as_deref());

    let mut impact: Option<ChangeImpactReport> = None;
    if let Some((base, compare)) = impact_range(&commits) {
        impact = change_impact(ChangeImpactInput { base, compare: Some(compare) }, code).await.ok();
    }

    // Repo truth beyond `git log`: best-effort — None (not a fabricated "clean") when unreadable.
    let repo_state = collect_repo_state(&input.repo_path).await;

    Ok(assemble_change_timeline(&input, commits, impact, repo_state))
}
