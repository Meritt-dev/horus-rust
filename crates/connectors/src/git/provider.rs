//! Git history provider (HOR-22). Shells out to `git` — this is intentional and expected
//! for the history connector (the "no CLI shell-out" rule only applies to
//! source-intelligence queries). See architecture.md §2.2.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;

use serde::{Deserialize, Serialize};

const US: char = '\u{1f}'; // unit separator used as the --pretty field delimiter

async fn git(repo_path: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = tokio::process::Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitCommit {
    pub sha: String,
    pub short_sha: String,
    pub author: String,
    pub date_iso: String,
    pub subject: String,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitLogOptions {
    pub since: Option<String>,
    pub until: Option<String>,
    pub max_count: Option<u32>,
}

/// Pure parser for `git log` stdout. Each commit block starts with a line containing the
/// unit separator as the field delimiter; subsequent non-empty lines (up to the next header
/// line or end of input) are file paths from --name-only.
pub fn parse_git_log(stdout: &str) -> Vec<GitCommit> {
    let mut commits = Vec::new();
    if stdout.trim().is_empty() {
        return commits;
    }
    let mut current: Option<GitCommit> = None;
    for line in stdout.split('\n') {
        if line.contains(US) {
            if let Some(c) = current.take() {
                commits.push(c);
            }
            let parts: Vec<&str> = line.split(US).collect();
            let get = |i: usize| parts.get(i).copied().unwrap_or("").to_string();
            current = Some(GitCommit {
                sha: get(0),
                short_sha: get(1),
                author: get(2),
                date_iso: get(3),
                subject: get(4),
                files: vec![],
            });
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

/// True when `rev` resolves to a commit in `repo_path` (i.e. it's a git ref, not a date).
pub async fn resolves_to_commit(repo_path: &Path, rev: &str) -> bool {
    git(repo_path, &["rev-parse", "--verify", "--quiet", &format!("{rev}^{{commit}}")])
        .await
        .is_ok()
}

/// Fetch git log for `repo_path` with optional time-window and commit-count limits.
/// Returns commits in git order (newest first).
pub async fn git_log(repo_path: &Path, opts: &GitLogOptions) -> anyhow::Result<Vec<GitCommit>> {
    let mut args: Vec<String> = vec![
        "log".into(),
        "--no-merges".into(),
        format!("--pretty=format:%H{US}%h{US}%an{US}%aI{US}%s"),
        "--name-only".into(),
    ];
    // `since`/`until` accept EITHER a date (git --since semantics, e.g. "7 days ago") OR a
    // git ref (e.g. HEAD~10). A ref passed to --since is parsed as an invalid date and
    // silently yields zero commits (HOR-354), so when `since` resolves to a commit we build a
    // revision range instead.
    match &opts.since {
        Some(since) if resolves_to_commit(repo_path, since).await => {
            let end = match &opts.until {
                Some(u) if resolves_to_commit(repo_path, u).await => u.as_str(),
                _ => "HEAD",
            };
            args.push(format!("{since}..{end}"));
        }
        _ => {
            if let Some(s) = &opts.since {
                args.push(format!("--since={s}"));
            }
            if let Some(u) = &opts.until {
                args.push(format!("--until={u}"));
            }
        }
    }
    args.push(format!("--max-count={}", opts.max_count.unwrap_or(200)));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    Ok(parse_git_log(&git(repo_path, &refs).await?))
}

/// Returns true when the repo has at least one commit; false on any error.
pub async fn git_repo_has_commits(repo_path: &Path) -> bool {
    git_log(repo_path, &GitLogOptions { max_count: Some(1), ..Default::default() })
        .await
        .map(|c| !c.is_empty())
        .unwrap_or(false)
}

/// A single contributor's summary for a file, derived from git log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileContributor {
    pub author: String,
    pub commits: u64,
    pub first_date: String,
    pub last_date: String,
}

/// Pure parser for `git log --format=%an%x1f%ae%x1f%aI` stdout. Entries are grouped by
/// email so different display-name aliases for the same address are merged. Returns
/// contributors sorted by commits descending, then by last_date descending.
pub fn parse_file_contributors(stdout: &str) -> Vec<FileContributor> {
    if stdout.trim().is_empty() {
        return vec![];
    }
    struct Tally {
        name: String,
        commits: u64,
        first: String,
        last: String,
    }
    // Insertion order kept (JS Map) so equal-ranked entries keep their first-seen order.
    let mut order: Vec<String> = Vec::new();
    let mut tally: HashMap<String, Tally> = HashMap::new();
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(US).collect();
        if parts.len() < 3 {
            continue;
        }
        let (name, email, date) = (parts[0].trim(), parts[1].trim(), parts[2].trim());
        if name.is_empty() || date.is_empty() {
            continue;
        }
        // Group by email to merge alias commits; fall back to name when email is absent.
        let key = if email.is_empty() { name } else { email };
        match tally.get_mut(key) {
            None => {
                order.push(key.to_string());
                tally.insert(
                    key.to_string(),
                    Tally { name: name.to_string(), commits: 1, first: date.to_string(), last: date.to_string() },
                );
            }
            Some(e) => {
                e.commits += 1;
                if date < e.first.as_str() {
                    e.first = date.to_string();
                }
                if date > e.last.as_str() {
                    e.last = date.to_string();
                    e.name = name.to_string(); // use the most recently seen display name
                }
            }
        }
    }
    let mut result: Vec<FileContributor> = order
        .iter()
        .filter_map(|k| tally.get(k))
        .map(|t| FileContributor { author: t.name.clone(), commits: t.commits, first_date: t.first.clone(), last_date: t.last.clone() })
        .collect();
    result.sort_by(|a, b| b.commits.cmp(&a.commits).then_with(|| b.last_date.cmp(&a.last_date)));
    result
}

/// Fetch per-author contribution stats for a single file in a git repo. Uses `--follow` to
/// track renames. Returns an empty vec on any error.
pub async fn git_file_contributors(repo_path: &Path, file: &str) -> Vec<FileContributor> {
    let fmt = format!("--format=%an{US}%ae{US}%aI");
    git(repo_path, &["log", "--follow", &fmt, "--", file])
        .await
        .map(|s| parse_file_contributors(&s))
        .unwrap_or_default()
}

/// One changed file with its git status letter (M/A/D/R…).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoFileChange {
    pub path: String,
    pub status: String,
}

/// Cap for staged/unstaged/untracked file lists — counts stay exact.
const REPO_STATE_FILE_CAP: usize = 100;

/// A truthful snapshot of the repo beyond commit history: staged/unstaged/untracked work
/// that a `git log`-only change report would miss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoState {
    pub head_sha: Option<String>,
    pub branch: Option<String>,
    /// True when anything is staged, unstaged, or untracked.
    pub dirty: bool,
    pub staged: Vec<RepoFileChange>,
    pub unstaged: Vec<RepoFileChange>,
    pub untracked: Vec<String>,
    pub staged_count: usize,
    pub unstaged_count: usize,
    pub untracked_count: usize,
    /// Working-tree insertions/deletions vs HEAD (staged + unstaged combined).
    pub insertions: u64,
    pub deletions: u64,
}

fn parse_name_status(stdout: &str) -> Vec<RepoFileChange> {
    let mut out = Vec::new();
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split('\t');
        let status = parts.next().unwrap_or("");
        let path = parts.last(); // renames are "R100 old new" — report the new path
        if let (false, Some(path)) = (status.is_empty(), path) {
            out.push(RepoFileChange {
                path: path.to_string(),
                status: status.chars().next().map(|c| c.to_string()).unwrap_or_else(|| status.to_string()),
            });
        }
    }
    out
}

fn parse_shortstat(stdout: &str) -> (u64, u64) {
    let grab = |re: &str| {
        regex::Regex::new(re)
            .unwrap()
            .captures(stdout)
            .and_then(|c| c[1].parse::<u64>().ok())
            .unwrap_or(0)
    };
    (grab(r"(\d+) insertion"), grab(r"(\d+) deletion"))
}

/// Collect the repo's current state: HEAD, branch, and the dirty-worktree truth. Returns
/// None when `repo_path` is not a usable git repo — callers treat that as "unknown".
pub async fn collect_repo_state(repo_path: &Path) -> Option<RepoState> {
    let (head, branch, staged_raw, unstaged_raw, untracked_raw, shortstat) = tokio::join!(
        git(repo_path, &["rev-parse", "HEAD"]),
        git(repo_path, &["rev-parse", "--abbrev-ref", "HEAD"]),
        git(repo_path, &["diff", "--name-status", "--cached"]),
        git(repo_path, &["diff", "--name-status"]),
        git(repo_path, &["ls-files", "--others", "--exclude-standard"]),
        git(repo_path, &["diff", "HEAD", "--shortstat"]),
    );
    let non_empty = |r: anyhow::Result<String>| r.ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let (staged_raw, unstaged_raw, untracked_raw) = (staged_raw.ok()?, unstaged_raw.ok()?, untracked_raw.ok()?);
    let staged = parse_name_status(&staged_raw);
    let unstaged = parse_name_status(&unstaged_raw);
    let untracked: Vec<String> = untracked_raw.split('\n').map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
    let (insertions, deletions) = parse_shortstat(&shortstat.unwrap_or_default());
    Some(RepoState {
        head_sha: non_empty(head),
        branch: non_empty(branch),
        dirty: !staged.is_empty() || !unstaged.is_empty() || !untracked.is_empty(),
        staged_count: staged.len(),
        unstaged_count: unstaged.len(),
        untracked_count: untracked.len(),
        staged: staged.into_iter().take(REPO_STATE_FILE_CAP).collect(),
        unstaged: unstaged.into_iter().take(REPO_STATE_FILE_CAP).collect(),
        untracked: untracked.into_iter().take(REPO_STATE_FILE_CAP).collect(),
        insertions,
        deletions,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitDiffSummary {
    pub files: Vec<RepoFileChange>,
    pub file_count: usize,
    pub insertions: u64,
    pub deletions: u64,
}

/// `git diff --name-status` + `--shortstat` between two refs — the git TRUTH for a change
/// window, independent of the source index. Returns None when the range is not diffable.
pub async fn git_diff_summary(repo_path: &Path, base: &str, compare: &str) -> Option<GitDiffSummary> {
    let range = format!("{base}..{compare}");
    let a = ["diff", "--name-status", range.as_str()];
    let b = ["diff", "--shortstat", range.as_str()];
    let (name_status, shortstat) = tokio::join!(git(repo_path, &a), git(repo_path, &b));
    // Full list — consumers bucket over ALL files and cap only at display/serialization time.
    let files = parse_name_status(&name_status.ok()?);
    let (insertions, deletions) = parse_shortstat(&shortstat.ok()?);
    Some(GitDiffSummary { file_count: files.len(), files, insertions, deletions })
}
