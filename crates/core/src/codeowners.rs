//! CODEOWNERS ownership parser.
//!
//! Parses GitHub/GitLab CODEOWNERS-style files and resolves which owners are
//! responsible for a given file path: exact paths, directory prefixes (`src/lib/`),
//! extension globs (`*.ts`) and double-star globs (`**/*.test.ts`).
//! Resolution follows the CODEOWNERS rule: last matching rule wins.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipRule {
    pub pattern: String,
    pub owners: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FileOwnershipResult {
    #[serde(rename = "owned")]
    Owned { file: String, owners: Vec<String>, matched_pattern: String },
    #[serde(rename = "unowned")]
    Unowned { file: String },
}

/// Parse a CODEOWNERS file into an ordered list of rules. Comment and blank lines are ignored.
pub fn parse_codeowners(content: &str) -> Vec<OwnershipRule> {
    let mut rules = Vec::new();
    for raw in content.split('\n') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pattern) = parts.next() else { continue };
        let owners: Vec<String> = parts.map(str::to_string).collect();
        if !owners.is_empty() {
            rules.push(OwnershipRule { pattern: pattern.to_string(), owners });
        }
    }
    rules
}

/// Resolve which owners are responsible for `file`. Last matching rule wins.
pub fn resolve_owner(file: &str, rules: &[OwnershipRule]) -> FileOwnershipResult {
    let matched = rules.iter().rfind(|r| pattern_matches(&r.pattern, file));
    match matched {
        Some(rule) => FileOwnershipResult::Owned {
            file: file.to_string(),
            owners: rule.owners.clone(),
            matched_pattern: rule.pattern.clone(),
        },
        None => FileOwnershipResult::Unowned { file: file.to_string() },
    }
}

fn pattern_matches(pattern: &str, file: &str) -> bool {
    let p = pattern.strip_prefix('/').unwrap_or(pattern);
    if p.ends_with('/') {
        return file.starts_with(p);
    }
    // GitHub CODEOWNERS: patterns without a path separator match at any depth.
    let effective = if p.contains('/') { p.to_string() } else { format!("**/{p}") };
    glob_to_regex(&effective).is_match(file)
}

fn glob_to_regex(pattern: &str) -> Regex {
    let chars: Vec<char> = pattern.chars().collect();
    let mut result = String::from("^");
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '*' && chars.get(i + 1) == Some(&'*') {
            if chars.get(i + 2) == Some(&'/') {
                // **/ → zero or more directories
                result.push_str("(?:.+/)?");
                i += 3;
            } else {
                result.push_str(".*");
                i += 2;
            }
        } else if chars[i] == '*' {
            result.push_str("[^/]*");
            i += 1;
        } else {
            let c = chars[i];
            if ".+^${}()|[]\\".contains(c) {
                result.push('\\');
            }
            result.push(c);
            i += 1;
        }
    }
    result.push('$');
    Regex::new(&result).expect("glob regex")
}

/// Built-in fixture — reusable in replay tests (HOR-69).
pub const FIXTURE_CODEOWNERS: &str = "# Horus project CODEOWNERS fixture (HOR-69)
# Used for deterministic ownership resolution tests.

*.ts                      @horus/core-team
packages/cli/             @horus/cli-team
packages/connectors/      @horus/connectors-team
**/*.test.ts              @horus/qa-team
docs/                     @horus/docs-team
packages/core/src/git.ts  @horus/core-team @horus/devex-team";

/// Pre-parsed rules from FIXTURE_CODEOWNERS.
pub static FIXTURE_CODEOWNERS_RULES: LazyLock<Vec<OwnershipRule>> =
    LazyLock::new(|| parse_codeowners(FIXTURE_CODEOWNERS));
