//! Git remote detection — a discovery aid for `horus cloud link` (HOR-238 §7). Port of
//! `packages/cli/src/lib/cloud/git.ts`. Used only to suggest a repository name; never
//! authoritative.

use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct GitRemote {
    pub remote_url: String,
    /// Bare repo name, e.g. `horus-cli` from `git@github.com:meritt-dev/horus-cli.git`.
    pub repo_name: String,
}

/// Parses the trailing repo name out of an SSH or HTTPS git remote URL.
pub fn parse_repo_name(remote_url: &str) -> String {
    let cleaned = remote_url.trim();
    let cleaned = cleaned.strip_suffix(".git").unwrap_or(cleaned);
    cleaned.split(['/', ':']).filter(|s| !s.is_empty()).last().unwrap_or("").to_string()
}

/// Canonical form of a git remote for equality, so SSH and HTTPS forms of the same repo match:
/// both become `github.com/org/repo` (HOR-307).
pub fn normalize_remote(remote_url: &str) -> String {
    let s = remote_url.trim();
    let mut s = s.strip_suffix(".git").unwrap_or(s).to_string();
    // drop scheme (https://, ssh://)
    if let Some(i) = s.find("://") {
        if i > 0 && s[..i].chars().all(|c| c.is_ascii_alphabetic()) {
            s = s[i + 3..].to_string();
        }
    }
    // drop user@ (git@)
    if let Some(i) = s.find('@') {
        if i > 0 && !s[..i].contains('/') {
            s = s[i + 1..].to_string();
        }
    }
    // scp-style host:path → host/path (first ':' only)
    let s = s.replacen(':', "/", 1);
    s.trim_end_matches('/').to_lowercase()
}

/// True when two remotes point at the same repository (scheme/auth-insensitive).
pub fn remotes_match(a: &str, b: &str) -> bool {
    normalize_remote(a) == normalize_remote(b)
}

/// Infers the cloud `provider` value from a remote host.
pub fn infer_provider(remote_url: &str) -> &'static str {
    let n = normalize_remote(remote_url);
    let host = n.split('/').next().unwrap_or("");
    if host.contains("github") {
        "github"
    } else if host.contains("gitlab") {
        "gitlab"
    } else {
        "other"
    }
}

pub fn detect_git_remote(root: &Path) -> Option<GitRemote> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["remote", "get-url", "origin"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let remote_url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if remote_url.is_empty() {
        return None;
    }
    Some(GitRemote { repo_name: parse_repo_name(&remote_url), remote_url })
}
