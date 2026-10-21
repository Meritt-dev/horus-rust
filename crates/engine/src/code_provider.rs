//! Connector-facing helpers the engine's command modules consume: the provider contract
//! (re-exported from `horus-connectors`), multi-repo providers, and git helpers.

use anyhow::Result;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

// The provider contract is owned by `horus-connectors` (contract.rs).
pub use horus_connectors::contract::{
    CodeCommunity, CodeOverview, CodeProcess, CodeProcessStep, CodeProvider, CouplingPair, DeadCodeSummary, DiffRange,
    Provider,
};

// ported-from: @horus/connectors RepoProvider
pub struct RepoProvider {
    pub name: String,
    pub path: String,
    pub host_url: String,
    pub code: Box<dyn CodeProvider>,
}

// ── Git types (ported-from: @horus/connectors git/provider.ts) ───────────────

pub use crate::types::{GitCommit, RepoFileChange, RepoState};

// ported-from: @horus/connectors FileContributor
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileContributor {
    pub author: String,
    pub commits: i64,
    pub first_date: String,
    pub last_date: String,
}

// ported-from: @horus/connectors gitDiffSummary result
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffSummary {
    pub files: Vec<RepoFileChange>,
    pub file_count: i64,
    pub insertions: i64,
    pub deletions: i64,
}

pub(crate) async fn git(repo_path: &str, args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ported-from: @horus/connectors parseFileContributors
/// Each line is `name\x1femail\x1fISODATE`; grouped by email so display-name aliases merge.
/// Sorted by commits desc, then lastDate desc.
pub fn parse_file_contributors(stdout: &str) -> Vec<FileContributor> {
    if stdout.trim().is_empty() {
        return vec![];
    }
    struct Tally {
        name: String,
        commits: i64,
        first_date: String,
        last_date: String,
    }
    let mut tally: IndexMap<String, Tally> = IndexMap::new();
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('\u{1f}').collect();
        if parts.len() < 3 {
            continue;
        }
        let name = parts[0].trim();
        let email = parts[1].trim();
        let date = parts[2].trim();
        if name.is_empty() || date.is_empty() {
            continue;
        }
        let key = if email.is_empty() { name } else { email };
        match tally.get_mut(key) {
            None => {
                tally.insert(
                    key.to_string(),
                    Tally { name: name.to_string(), commits: 1, first_date: date.to_string(), last_date: date.to_string() },
                );
            }
            Some(existing) => {
                existing.commits += 1;
                if date < existing.first_date.as_str() {
                    existing.first_date = date.to_string();
                }
                if date > existing.last_date.as_str() {
                    existing.last_date = date.to_string();
                    existing.name = name.to_string();
                }
            }
        }
    }
    let mut result: Vec<FileContributor> = tally
        .into_values()
        .map(|s| FileContributor { author: s.name, commits: s.commits, first_date: s.first_date, last_date: s.last_date })
        .collect();
    result.sort_by(|a, b| b.commits.cmp(&a.commits).then_with(|| b.last_date.cmp(&a.last_date)));
    result
}

// ported-from: @horus/connectors gitFileContributors
/// Per-author contribution stats for one file (`--follow` tracks renames). Empty on error.
pub async fn git_file_contributors(repo_path: &str, file: &str) -> Vec<FileContributor> {
    match git(repo_path, &["log", "--follow", "--format=%an%x1f%ae%x1f%aI", "--", file]).await {
        Ok(stdout) => parse_file_contributors(&stdout),
        Err(_) => vec![],
    }
}

pub(crate) fn parse_name_status(stdout: &str) -> Vec<RepoFileChange> {
    let mut out = vec![];
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split('\t');
        let status = parts.next().unwrap_or("");
        // renames are "R100 old new" — report the new path
        let path = parts.last();
        if let (false, Some(path)) = (status.is_empty(), path) {
            if !path.is_empty() {
                out.push(RepoFileChange { path: path.to_string(), status: status.chars().next().map(String::from).unwrap_or_else(|| status.to_string()) });
            }
        }
    }
    out
}

pub(crate) fn parse_shortstat(stdout: &str) -> (i64, i64) {
    let grab = |suffix: &str| -> i64 {
        let re = regex::Regex::new(&format!(r"(\d+) {suffix}")).unwrap();
        re.captures(stdout).and_then(|c| c[1].parse().ok()).unwrap_or(0)
    };
    (grab("insertion"), grab("deletion"))
}

// ported-from: @horus/connectors gitDiffSummary
/// `git diff --name-status` + `--shortstat` between two refs — the git TRUTH for a
/// change window. `None` when the range is not diffable (never fabricated zeros).
pub async fn git_diff_summary(repo_path: &str, base: &str, compare: &str) -> Option<DiffSummary> {
    let range = format!("{base}..{compare}");
    let name_status_args = ["diff", "--name-status", range.as_str()];
    let shortstat_args = ["diff", "--shortstat", range.as_str()];
    let (name_status, shortstat) = tokio::try_join!(
        git(repo_path, &name_status_args),
        git(repo_path, &shortstat_args),
    )
    .ok()?;
    let files = parse_name_status(&name_status);
    let (insertions, deletions) = parse_shortstat(&shortstat);
    Some(DiffSummary { file_count: files.len() as i64, files, insertions, deletions })
}

// ported-from: @horus/connectors fetchHostRepoPath
/// GET `<hostUrl>/api/host` identity probe; `None` when unreachable or unreported.
pub async fn fetch_host_repo_path(host_url: &str) -> Option<String> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_millis(2500)).build().ok()?;
    let res = client.get(format!("{host_url}/api/host")).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let j: serde_json::Value = res.json().await.ok()?;
    for key in ["repoPath", "repo_path"] {
        if let Some(s) = j.get(key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

// ported-from: @horus/connectors parseGitLog
/// Each commit block starts with a `\x1f`-delimited header line; subsequent non-empty lines
/// (until the next header) are file paths from `--name-only`.
pub fn parse_git_log(stdout: &str) -> Vec<GitCommit> {
    let mut commits: Vec<GitCommit> = vec![];
    if stdout.trim().is_empty() {
        return commits;
    }
    let mut current: Option<GitCommit> = None;
    for line in stdout.split('\n') {
        if line.contains('\u{1f}') {
            if let Some(c) = current.take() {
                commits.push(c);
            }
            let parts: Vec<&str> = line.split('\u{1f}').collect();
            let get = |i: usize| parts.get(i).copied().unwrap_or("").to_string();
            current = Some(GitCommit { sha: get(0), short_sha: get(1), author: get(2), date_iso: get(3), subject: get(4), files: vec![] });
        } else if !line.trim().is_empty() {
            if let Some(c) = current.as_mut() {
                c.files.push(line.trim().to_string());
            }
        }
    }
    if let Some(c) = current {
        commits.push(c);
    }
    commits
}

// ported-from: @horus/connectors resolvesToCommit
/// True when `rev` resolves to a commit in `repo_path` (i.e. it's a git ref, not a date).
pub async fn resolves_to_commit(repo_path: &str, rev: &str) -> bool {
    let spec = format!("{rev}^{{commit}}");
    git(repo_path, &["rev-parse", "--verify", "--quiet", &spec]).await.is_ok()
}

// ported-from: @horus/connectors GitLogOptions
#[derive(Debug, Clone, Default)]
pub struct GitLogOptions {
    pub since: Option<String>,
    pub until: Option<String>,
    pub max_count: Option<usize>,
}

// ported-from: @horus/connectors gitLog
/// Commits in git order (newest first). `since`/`until` accept EITHER a date (git --since
/// semantics) OR a git ref (HOR-354): a ref builds a revision range instead.
pub async fn git_log(repo_path: &str, opts: GitLogOptions) -> Result<Vec<GitCommit>> {
    let mut args: Vec<String> =
        vec!["log".into(), "--no-merges".into(), "--pretty=format:%H\x1f%h\x1f%an\x1f%aI\x1f%s".into(), "--name-only".into()];
    let since_is_ref = match &opts.since {
        Some(s) => resolves_to_commit(repo_path, s).await,
        None => false,
    };
    if since_is_ref {
        let since = opts.since.as_deref().unwrap_or("");
        let end = match &opts.until {
            Some(u) if resolves_to_commit(repo_path, u).await => u.clone(),
            _ => "HEAD".to_string(),
        };
        args.push(format!("{since}..{end}"));
    } else {
        if let Some(s) = &opts.since {
            args.push(format!("--since={s}"));
        }
        if let Some(u) = &opts.until {
            args.push(format!("--until={u}"));
        }
    }
    args.push(format!("--max-count={}", opts.max_count.unwrap_or(200)));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    Ok(parse_git_log(&git(repo_path, &refs).await?))
}

/// Cap for staged/unstaged/untracked file lists — counts stay exact.
const REPO_STATE_FILE_CAP: usize = 100;

// ported-from: @horus/connectors collectRepoState
/// HEAD, branch, and the dirty-worktree truth. `None` when `repo_path` is not a usable git repo.
pub async fn collect_repo_state(repo_path: &str) -> Option<RepoState> {
    let head_sha = git(repo_path, &["rev-parse", "HEAD"]).await.ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let branch =
        git(repo_path, &["rev-parse", "--abbrev-ref", "HEAD"]).await.ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let staged_raw = git(repo_path, &["diff", "--name-status", "--cached"]).await.ok()?;
    let unstaged_raw = git(repo_path, &["diff", "--name-status"]).await.ok()?;
    let untracked_raw = git(repo_path, &["ls-files", "--others", "--exclude-standard"]).await.ok()?;
    let shortstat = git(repo_path, &["diff", "HEAD", "--shortstat"]).await.unwrap_or_default();

    let staged = parse_name_status(&staged_raw);
    let unstaged = parse_name_status(&unstaged_raw);
    let untracked: Vec<String> = untracked_raw.split('\n').map(|l| l.trim()).filter(|l| !l.is_empty()).map(String::from).collect();
    let (insertions, deletions) = parse_shortstat(&shortstat);

    Some(RepoState {
        head_sha,
        branch,
        dirty: !staged.is_empty() || !unstaged.is_empty() || !untracked.is_empty(),
        staged_count: staged.len(),
        unstaged_count: unstaged.len(),
        untracked_count: untracked.len(),
        staged: staged.into_iter().take(REPO_STATE_FILE_CAP).collect(),
        unstaged: unstaged.into_iter().take(REPO_STATE_FILE_CAP).collect(),
        untracked: untracked.into_iter().take(REPO_STATE_FILE_CAP).collect(),
        insertions: insertions.max(0) as u64,
        deletions: deletions.max(0) as u64,
    })
}

// ── DB stand-ins (ported-from: @horus/db) ────────────────────────────────────

// ported-from: @horus/db QueueEdge
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueEdge {
    pub queue_name: String,
    pub producer_symbol: Option<String>,
    pub producer_file: Option<String>,
    pub worker_symbol: Option<String>,
    pub worker_file: Option<String>,
}

impl horus_core::QueueEdgeLike for QueueEdge {
    fn queue_name(&self) -> &str {
        &self.queue_name
    }
    fn producer_symbol(&self) -> Option<&str> {
        self.producer_symbol.as_deref()
    }
    fn producer_file(&self) -> Option<&str> {
        self.producer_file.as_deref()
    }
    fn worker_symbol(&self) -> Option<&str> {
        self.worker_symbol.as_deref()
    }
    fn worker_file(&self) -> Option<&str> {
        self.worker_file.as_deref()
    }
}

// ported-from: @horus/db listInvestigations row (subset the engine reads)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationRow {
    pub id: String,
    pub title: String,
    /// ISO timestamp (already normalised by the caller), or `None`.
    pub created_at: Option<String>,
    /// Raw saved report JSON (only populated by `listInvestigationsWithReports`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<serde_json::Value>,
}
