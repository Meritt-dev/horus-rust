//! HOR-30 — 'what changed' entry point. Composes HOR-22 reconstruction and adds
//! ownership + queue-topology signals for a service + window.

use crate::changes::ChangeImpactReport;
use crate::code_provider::{git_diff_summary, CodeProvider, GitCommit, RepoFileChange, RepoState};
use crate::deploy_timeline::{reconstruct_change_timeline, ChangeTimelineInput};
use horus_core::{bucket_for_change, ChangeBucket};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contributor {
    pub author: String,
    pub commits: i64,
}

/// How many changed files land in each risk bucket.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Buckets {
    pub runtime: i64,
    pub test: i64,
    pub docs: i64,
    pub config: i64,
}

/// The git TRUTH for the window — `git diff --name-status/--shortstat` over the commit range,
/// independent of the source index. Reported FIRST.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitTruth {
    pub base: String,
    pub compare: String,
    pub files: Vec<RepoFileChange>,
    pub file_count: i64,
    pub insertions: i64,
    pub deletions: i64,
    pub buckets: Buckets,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Window {
    pub since: Option<String>,
    pub until: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueTopology {
    pub touched: bool,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhatChangedReport {
    pub window: Window,
    pub commit_count: i64,
    pub top_commits: Vec<GitCommit>,
    /// Git truth first (null when the range is not diffable).
    pub git_truth: Option<GitTruth>,
    /// Repo/working-tree state — dirty worktrees are a change source too.
    pub repo_state: Option<RepoState>,
    pub change_impact: Option<ChangeImpactReport>,
    pub contributors: Vec<Contributor>,
    pub queue_topology: QueueTopology,
    pub summary: String,
    pub note: String,
}

pub struct WhatChangedInput {
    pub repo_path: String,
    pub since: Option<String>,
    pub until: Option<String>,
    pub service: Option<String>,
}

static QUEUE_FILE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.(processor|module)\.ts$").unwrap());

pub async fn what_changed(input: WhatChangedInput, code: &dyn CodeProvider) -> anyhow::Result<WhatChangedReport> {
    let t = reconstruct_change_timeline(
        ChangeTimelineInput {
            repo_path: input.repo_path.clone(),
            since: input.since.clone(),
            until: input.until.clone(),
            service: input.service.clone(),
            source_index: None,
        },
        code,
    )
    .await?;

    // Tally commits by author
    let mut author_map: IndexMap<String, i64> = IndexMap::new();
    for commit in &t.commits {
        *author_map.entry(commit.author.clone()).or_insert(0) += 1;
    }
    let mut contributors: Vec<Contributor> = author_map.into_iter().map(|(author, commits)| Contributor { author, commits }).collect();
    contributors.sort_by(|a, b| b.commits.cmp(&a.commits));
    contributors.truncate(5);

    // Queue topology: collect files matching queue/processor patterns
    let mut queue_file_set: IndexSet<String> = IndexSet::new();
    'outer: for commit in &t.commits {
        for file in &commit.files {
            let lower = file.to_lowercase();
            if QUEUE_FILE_RE.is_match(file) || lower.contains("queue") || lower.contains("processor") {
                queue_file_set.insert(file.clone());
                if queue_file_set.len() >= 20 {
                    break 'outer;
                }
            }
        }
    }
    let queue_files: Vec<String> = queue_file_set.into_iter().take(20).collect();
    let queue_topology = QueueTopology { touched: !queue_files.is_empty(), files: queue_files };

    let top_commits: Vec<GitCommit> = t.commits.iter().take(3).cloned().collect();

    // Git truth for the window: diff the same range the change impact uses
    // (oldest-in-window^ .. newest). Best-effort — undiffable reports as null, never zeros.
    let mut git_truth: Option<GitTruth> = None;
    if let (Some(newest), Some(oldest)) = (t.commits.first(), t.commits.last()) {
        let base = format!("{}^", oldest.sha);
        if let Some(diff) = git_diff_summary(&input.repo_path, &base, &newest.sha).await {
            let mut buckets = Buckets::default();
            for f in &diff.files {
                match bucket_for_change(&f.path) {
                    ChangeBucket::Runtime => buckets.runtime += 1,
                    ChangeBucket::Test => buckets.test += 1,
                    ChangeBucket::Docs => buckets.docs += 1,
                    ChangeBucket::Config => buckets.config += 1,
                }
            }
            git_truth = Some(GitTruth {
                base,
                compare: newest.sha.clone(),
                files: diff.files,
                file_count: diff.file_count,
                insertions: diff.insertions,
                deletions: diff.deletions,
                buckets,
            });
        }
    }

    let git_truth_part = match &git_truth {
        Some(g) => format!(
            "; {} file(s) changed (+{}/-{}, {} runtime)",
            g.file_count, g.insertions, g.deletions, g.buckets.runtime
        ),
        None => String::new(),
    };
    let dirty_part = match t.repo_state.as_ref().filter(|s| s.dirty) {
        Some(s) => format!(
            "; working tree has uncommitted changes ({} modified, {} untracked)",
            s.staged_count + s.unstaged_count,
            s.untracked_count
        ),
        None => String::new(),
    };
    let mut summary = format!("{} commit(s)", t.commits.len());
    if let Some(service) = &input.service {
        summary.push_str(&format!(" touching {service}"));
    }
    if let Some(since) = &input.since {
        summary.push_str(&format!(" since {since}"));
    }
    summary.push_str(&git_truth_part);
    let change_impact: Option<ChangeImpactReport> = t.change_impact.clone();
    if let Some(ci) = &change_impact {
        summary.push_str(&format!(
            "; {} symbols added/{} modified/{} removed",
            ci.added.len(),
            ci.modified.len(),
            ci.removed.len()
        ));
    }
    if let Some(top) = contributors.first() {
        summary.push_str(&format!("; top contributor {} ({})", top.author, top.commits));
    }
    if queue_topology.touched {
        summary.push_str("; queue/worker files changed (topology may have shifted)");
    }
    summary.push_str(&dirty_part);
    summary.push('.');

    let note = if t.commits.is_empty() && t.repo_state.as_ref().is_some_and(|s| s.dirty) {
        "No commits in the window, but the working tree carries uncommitted changes — see the repo state; they are excluded from commit history."
    } else {
        "A change is evidence, not a conclusion — confirm with logs/metrics before blaming a change."
    };

    Ok(WhatChangedReport {
        window: Window { since: input.since, until: input.until, service: input.service },
        commit_count: t.commits.len() as i64,
        top_commits,
        git_truth,
        repo_state: t.repo_state,
        change_impact,
        contributors,
        queue_topology,
        summary,
        note: note.to_string(),
    })
}
