//! Bounded git change collector for investigation input (HOR-93).
//!
//! Accepts a repo path + a "since" value (duration, ISO date, or commit ref) and returns a
//! bounded summary of commits + per-file diff stats. Hard limits on files, commits, and bytes
//! prevent large repositories from generating unbounded investigation input.

use std::path::Path;
use std::sync::LazyLock;

use horus_connectors::git::provider::{git_log, GitCommit, GitLogOptions};
use indexmap::IndexSet;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::code_provider::git;
use crate::js;

const DEFAULT_MAX_COMMITS: usize = 50;
const DEFAULT_MAX_FILES: usize = 100;
const DEFAULT_MAX_BYTES: usize = 50_000;

/// Default look-back window (in days) used when no explicit `--since` is supplied but a repo
/// path is available (HOR-333).
pub const DEFAULT_CHANGE_WINDOW_DAYS: i64 = 14;

const DAY_MS: f64 = 86_400_000.0;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct GitChangeQuery {
    pub repo_path: String,
    /// Duration ("24 hours ago", "2 days ago"), ISO date, or commit ref/SHA.
    pub since: String,
    pub until: Option<String>,
    pub max_commits: Option<usize>,
    pub max_files: Option<usize>,
    /// Byte cap on the total serialised size of fileStats entries.
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileStat {
    pub path: String,
    pub insertions: i64,
    pub deletions: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeWindow {
    pub since: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundedGitChange {
    pub commits: Vec<GitCommit>,
    pub file_stats: Vec<FileStat>,
    pub changed_files: Vec<String>,
    pub total_insertions: i64,
    pub total_deletions: i64,
    pub window: ChangeWindow,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<String>,
    /// HOR-423: the diff carries NO usable change signal (wrong/absent base, +0/-0 no-op, or
    /// an over-reaching diff). Consumers treat a degenerate window as no change evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degenerate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degenerate_reason: Option<String>,
}

impl BoundedGitChange {
    pub fn is_degenerate(&self) -> bool {
        self.degenerate == Some(true)
    }
}

// HOR-423: a diff "over-reaches" when it reports at least this many files AND dwarfs (by
// OVERREACH_FACTOR×) what the in-window commits actually touched.
const OVERREACH_MIN_FILES: usize = 20;
const OVERREACH_FACTOR: usize = 4;

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

re!(DATE_LIKE, r"(?i)\s|:|ago|yesterday|week|month|year|=");
re!(DURATION, r"(?i)^\d+[smhd]$");
re!(HEX_SHA, r"(?i)^[0-9a-f]{7,40}$");
re!(NAMED_REF, r"^[a-zA-Z0-9_.~^/-]{1,200}$");
re!(ISO_DAY, r"^\d{4}-\d{2}-\d{2}$");

/// True when `s` looks like a git ref (SHA or ref name) rather than a date/duration.
pub fn is_ref_like(s: &str) -> bool {
    let t = s.trim();
    // Reject flag-like strings and range notation embedded in a ref value.
    if t.starts_with('-') || t.contains("..") {
        return false;
    }
    if DATE_LIKE.is_match(t) || DURATION.is_match(t) {
        return false;
    }
    if HEX_SHA.is_match(t) {
        return true;
    }
    NAMED_REF.is_match(t) && !ISO_DAY.is_match(t)
}

re!(FILES_CHANGED, r"^\d+ files? changed");

/// Parse `git diff --stat` output into FileStat[]; the summary line is skipped.
pub fn parse_diff_stat(stdout: &str) -> Vec<FileStat> {
    let mut stats = vec![];
    for line in stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || FILES_CHANGED.is_match(trimmed) {
            continue;
        }
        let Some(pipe_idx) = trimmed.rfind('|') else { continue };
        let path = trimmed[..pipe_idx].trim();
        let rest = trimmed[pipe_idx + 1..].trim();
        if path.is_empty() || rest.contains("Bin") {
            continue;
        }
        let insertions = rest.matches('+').count() as i64;
        let deletions = rest.matches('-').count() as i64;
        stats.push(FileStat { path: path.to_string(), insertions, deletions });
    }
    stats
}

/// An ISO-8601 `since` timestamp `days` before the anchor instant. Pure; None when the
/// anchor cannot be parsed.
pub fn change_window_since_from(anchor_iso: &str, days: i64) -> Option<String> {
    let anchor_ms = js::date_parse(anchor_iso);
    if anchor_ms.is_nan() {
        return None;
    }
    let span = if days > 0 { days } else { DEFAULT_CHANGE_WINDOW_DAYS };
    Some(js::iso_from_ms(anchor_ms - span as f64 * DAY_MS))
}

/// Author date (ISO-8601) of the repo's most recent commit — the deterministic anchor for
/// the auto change window. Never fails; None when the path is not absolute or git fails.
pub async fn latest_commit_date(repo_path: &str) -> Option<String> {
    if !repo_path.starts_with('/') {
        return None;
    }
    let out = git(repo_path, &["log", "-1", "--format=%aI"]).await.ok()?;
    let iso = out.trim();
    if iso.is_empty() { None } else { Some(iso.to_string()) }
}

re!(SHA_LINE, r"(?i)^[0-9a-f]{7,40}$");

/// Commits (full SHAs) that touched a specific LINE RANGE of a file (`git log -L`). None on
/// any git failure so callers fall back to file-level attribution.
pub async fn commits_touching_range(
    repo_path: &str,
    file: &str,
    start_line: i64,
    end_line: i64,
    since_iso: Option<&str>,
) -> Option<Vec<String>> {
    if !repo_path.starts_with('/') || start_line < 1 || end_line < start_line {
        return None;
    }
    let range_arg = format!("-L{start_line},{end_line}:{file}");
    let mut args: Vec<String> =
        ["log", "--format=%H", "--no-patch", "-s"].iter().map(|s| s.to_string()).collect();
    args.push(range_arg);
    // A ref-like `since` is not a valid `--since` value — skip it.
    if let Some(since) = since_iso.filter(|s| !s.is_empty() && !is_ref_like(s)) {
        args.push(format!("--since={since}"));
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let stdout = git(repo_path, &refs).await.ok()?;
    let mut seen: IndexSet<String> = IndexSet::new();
    for line in stdout.split('\n') {
        let sha = line.trim();
        if SHA_LINE.is_match(sha) {
            seen.insert(sha.to_string());
        }
    }
    Some(seen.into_iter().collect())
}

/// Default change-window `since` anchored to the repo's last commit (HOR-333).
pub async fn default_change_window_since(repo_path: &str, days: i64) -> Option<String> {
    let anchor = latest_commit_date(repo_path).await?;
    change_window_since_from(&anchor, days)
}

// ── Config/migration change classification (HOR-332) ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigChangeCategory {
    Migration,
    Config,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigChangeFile {
    pub path: String,
    pub category: ConfigChangeCategory,
}

re!(MIGRATION_DIR_RE, r"(?i)(^|/)(migrations?|alembic|migrate)/");
re!(SCHEMA_FILE_RE, r"(?i)(^|/)schema\.(sql|prisma|rb|graphql|gql)$");
re!(MIGRATION_FILE_RE, r"(?i)\.(migration|migrate)\.[a-z0-9]+$");
re!(ENV_FILE_RE, r"(?i)(^|\.)env($|\.)");
re!(CONFIG_FILE_RE, r"(?i)\.(config|conf)($|\.)");
re!(DATA_FILE_RE, r"(?i)\.(ya?ml|toml|ini)$");

/// Classify a changed path as a config/migration change source. Migration wins over config.
pub fn classify_config_path(path: &str) -> Option<ConfigChangeCategory> {
    let p = path.trim();
    if p.is_empty() {
        return None;
    }
    let base = p.rsplit('/').next().unwrap_or(p);
    if MIGRATION_DIR_RE.is_match(p) || SCHEMA_FILE_RE.is_match(p) || MIGRATION_FILE_RE.is_match(base) {
        return Some(ConfigChangeCategory::Migration);
    }
    if ENV_FILE_RE.is_match(base) || CONFIG_FILE_RE.is_match(base) || DATA_FILE_RE.is_match(base) {
        return Some(ConfigChangeCategory::Config);
    }
    None
}

/// Pick the config/migration files from a changed-files list; de-duplicated, input order kept.
pub fn classify_config_change_files(paths: &[String]) -> Vec<ConfigChangeFile> {
    let mut out = vec![];
    let mut seen: IndexSet<String> = IndexSet::new();
    for raw in paths {
        let path = raw.trim();
        if path.is_empty() || seen.contains(path) {
            continue;
        }
        if let Some(category) = classify_config_path(path) {
            out.push(ConfigChangeFile { path: path.to_string(), category });
            seen.insert(path.to_string());
        }
    }
    out
}

// ── Core function ─────────────────────────────────────────────────────────────

/// Collect bounded git changes. Never fails — errors produce a truncated result with a reason.
pub async fn collect_git_changes(query: &GitChangeQuery) -> BoundedGitChange {
    let max_commits = query.max_commits.unwrap_or(DEFAULT_MAX_COMMITS);
    let max_files = query.max_files.unwrap_or(DEFAULT_MAX_FILES);
    let max_bytes = query.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);

    let empty = |reason: Option<String>| BoundedGitChange {
        commits: vec![],
        file_stats: vec![],
        changed_files: vec![],
        total_insertions: 0,
        total_deletions: 0,
        window: ChangeWindow { since: query.since.clone(), until: query.until.clone() },
        truncated: reason.is_some(),
        truncated_reason: reason,
        degenerate: Some(false),
        degenerate_reason: None,
    };

    // Input validation (security: prevent argv flag smuggling).
    if !query.repo_path.starts_with('/') {
        return empty(Some("repoPath must be an absolute path".into()));
    }
    if let Some(until) = &query.until {
        if is_ref_like(&query.since) && !is_ref_like(until) {
            return empty(Some(format!("invalid until ref: {}", js::slice_chars(until, 60))));
        }
    }

    // 1. Fetch commits.
    let commits_res: anyhow::Result<Vec<GitCommit>> = if is_ref_like(&query.since) {
        let range = format!("{}..{}", query.since, query.until.as_deref().unwrap_or("HEAD"));
        let max = format!("--max-count={max_commits}");
        git(
            &query.repo_path,
            &["log", "--no-merges", "--pretty=format:%H\x1f%h\x1f%an\x1f%aI\x1f%s", "--name-only", &max, &range],
        )
        .await
        .map(|out| parse_ref_range_log(&out))
    } else {
        git_log(
            Path::new(&query.repo_path),
            &GitLogOptions {
                since: Some(query.since.clone()),
                until: query.until.clone(),
                max_count: Some(max_commits as u32),
            },
        )
        .await
    };
    let commits = match commits_res {
        Ok(c) => c,
        Err(err) => return empty(Some(format!("git log failed: {}", js::slice_chars(&err.to_string(), 120)))),
    };
    if commits.is_empty() {
        return empty(None);
    }
    let truncated_commits = commits.len() >= max_commits;

    // 2. Diff stats (HOR-423: diff against the CORRECT base — the supplied ref, or the FIRST
    // PARENT of the oldest in-window commit; a root/shallow boundary fails → degenerate).
    let mut raw_stats: Vec<FileStat> = vec![];
    let mut diff_ok = false;
    if let Some(oldest) = commits.last() {
        let range_base =
            if is_ref_like(&query.since) { query.since.clone() } else { format!("{}^1", oldest.sha) };
        let range = format!("{range_base}..{}", query.until.as_deref().unwrap_or("HEAD"));
        if let Ok(out) = git(&query.repo_path, &["diff", "--stat", &range]).await {
            raw_stats = parse_diff_stat(&out);
            diff_ok = true;
        }
    }

    // 3. File and byte limits.
    let mut file_stats = raw_stats.clone();
    let mut truncated_files = false;
    let mut truncated_bytes = false;
    if file_stats.len() > max_files {
        file_stats.truncate(max_files);
        truncated_files = true;
    }
    let mut byte_count = 0usize;
    let mut bounded = vec![];
    for s in file_stats {
        let entry_size = s.path.encode_utf16().count() + 30; // path + numbers + overhead
        if byte_count + entry_size > max_bytes {
            truncated_bytes = true;
            break;
        }
        byte_count += entry_size;
        bounded.push(s);
    }
    let file_stats = bounded;

    // 4. Totals.
    let total_insertions: i64 = file_stats.iter().map(|s| s.insertions).sum();
    let total_deletions: i64 = file_stats.iter().map(|s| s.deletions).sum();

    // Unique changed files from commits (capped to maxFiles).
    let mut file_set: IndexSet<String> = IndexSet::new();
    'outer: for c in &commits {
        for f in &c.files {
            file_set.insert(f.clone());
            if file_set.len() >= max_files {
                break 'outer;
            }
        }
    }
    let changed_files: Vec<String> = file_set.into_iter().collect();

    let truncated = truncated_commits || truncated_files || truncated_bytes;
    let mut reasons: Vec<String> = vec![];
    if truncated_commits {
        reasons.push(format!("commits capped at {max_commits}"));
    }
    if truncated_files {
        reasons.push(format!("files capped at {max_files}"));
    }
    if truncated_bytes {
        reasons.push(format!("output capped at {max_bytes} bytes"));
    }

    // 5. Degenerate-diff detection (HOR-423).
    let mut degenerate = false;
    let mut degenerate_reason: Option<String> = None;
    let commit_file_union: IndexSet<&str> =
        commits.iter().flat_map(|c| c.files.iter().map(String::as_str)).collect();
    let diff_file_count = raw_stats.len();

    if !diff_ok {
        if !changed_files.is_empty() {
            degenerate = true;
            degenerate_reason = Some("no usable diff base (root commit, shallow clone, or diff failed)".into());
        }
    } else if diff_file_count > 0 && total_insertions + total_deletions == 0 {
        degenerate = true;
        degenerate_reason = Some("+0/-0 no-op diff (pure merge, rename, or mode-only change)".into());
    } else if diff_file_count >= OVERREACH_MIN_FILES
        && !commit_file_union.is_empty()
        && diff_file_count >= commit_file_union.len() * OVERREACH_FACTOR
    {
        degenerate = true;
        degenerate_reason = Some(format!(
            "diff over-reaches base ({diff_file_count} files vs {} touched by in-window commits)",
            commit_file_union.len()
        ));
    }

    BoundedGitChange {
        window: ChangeWindow { since: query.since.clone(), until: query.until.clone() },
        commits,
        file_stats,
        changed_files,
        total_insertions,
        total_deletions,
        truncated,
        truncated_reason: if reasons.is_empty() { None } else { Some(reasons.join("; ")) },
        degenerate: Some(degenerate),
        degenerate_reason,
    }
}

fn parse_ref_range_log(stdout: &str) -> Vec<GitCommit> {
    let mut commits = vec![];
    if stdout.trim().is_empty() {
        return commits;
    }
    let mut current: Option<GitCommit> = None;
    for line in stdout.split('\n') {
        if line.contains('\x1f') {
            if let Some(c) = current.take() {
                commits.push(c);
            }
            let parts: Vec<&str> = line.split('\x1f').collect();
            let at = |i: usize| parts.get(i).copied().unwrap_or("").to_string();
            current = Some(GitCommit {
                sha: at(0),
                short_sha: at(1),
                author: at(2),
                date_iso: at(3),
                subject: at(4),
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
