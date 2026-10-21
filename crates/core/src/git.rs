//! Local git helpers. Every function shells out to `git` and never panics or errors
//! on git failure — a missing repo or binary degrades to `None`/empty results.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangedFile {
    pub path: String,
    /// Only set when status is `renamed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    pub status: FileStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSummary {
    pub hash: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum LocalChangeResult {
    #[serde(rename = "local-changes")]
    LocalChanges { base_ref: String, changed_files: Vec<ChangedFile>, commits: Vec<CommitSummary> },
    #[serde(rename = "no-git-repo")]
    NoGitRepo { cwd: String },
}

fn cwd_or_current(cwd: Option<&Path>) -> PathBuf {
    cwd.map(Path::to_path_buf).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// stdout of `git <args>` when it exits 0; None otherwise (including a missing binary).
fn git_stdout(args: &[&str], cwd: &Path) -> Option<String> {
    let out = Command::new("git").args(args).current_dir(cwd).stdin(Stdio::null()).stderr(Stdio::piped()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Collect changed files and commits between `base_ref` (default `HEAD~1`) and HEAD.
/// Returns `NoGitRepo` when `cwd` is not inside a git repository. Never fails.
pub fn collect_local_changes(cwd: Option<&Path>, base_ref: Option<&str>) -> LocalChangeResult {
    let cwd = cwd_or_current(cwd);
    let base_ref = base_ref.unwrap_or("HEAD~1").to_string();

    if git_stdout(&["rev-parse", "--git-dir"], &cwd).is_none() {
        return LocalChangeResult::NoGitRepo { cwd: cwd.to_string_lossy().into_owned() };
    }
    let range = format!("{base_ref}..HEAD");
    let changed_files = parse_diff(&git_stdout(&["diff", "--name-status", &range], &cwd).unwrap_or_default());
    let commits = parse_log(&git_stdout(&["log", "--oneline", &range], &cwd).unwrap_or_default());
    LocalChangeResult::LocalChanges { base_ref, changed_files, commits }
}

fn run_git(args: &[&str], cwd: Option<&Path>) -> Option<String> {
    let out = git_stdout(args, &cwd_or_current(cwd))?;
    let out = out.trim();
    (!out.is_empty()).then(|| out.to_string())
}

/// Current HEAD commit SHA, or None outside a git repo.
pub fn get_head_sha(cwd: Option<&Path>) -> Option<String> {
    run_git(&["rev-parse", "HEAD"], cwd)
}

/// Current branch name (or `HEAD` when detached), or None outside a git repo.
pub fn get_current_branch(cwd: Option<&Path>) -> Option<String> {
    run_git(&["rev-parse", "--abbrev-ref", "HEAD"], cwd)
}

/// Whether the working tree has uncommitted changes. None outside a git repo.
pub fn is_working_tree_dirty(cwd: Option<&Path>) -> Option<bool> {
    git_stdout(&["status", "--porcelain"], &cwd_or_current(cwd)).map(|s| !s.trim().is_empty())
}

fn parse_diff(stdout: &str) -> Vec<ChangedFile> {
    let mut files = Vec::new();
    for line in stdout.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        let raw = parts.first().copied().unwrap_or("");
        let part = |i: usize| parts.get(i).map(|s| s.to_string());
        if raw.starts_with('R') {
            files.push(ChangedFile {
                path: part(2).or_else(|| part(1)).unwrap_or_default(),
                old_path: part(1),
                status: FileStatus::Renamed,
            });
        } else if let Some(status) = match raw {
            "A" => Some(FileStatus::Added),
            "D" => Some(FileStatus::Deleted),
            "M" => Some(FileStatus::Modified),
            _ => None,
        } {
            files.push(ChangedFile { path: part(1).unwrap_or_default(), old_path: None, status });
        }
    }
    files
}

fn parse_log(stdout: &str) -> Vec<CommitSummary> {
    stdout
        .split('\n')
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let (hash, message) = line.split_once(' ')?;
            Some(CommitSummary { hash: hash.to_string(), message: message.to_string() })
        })
        .collect()
}
