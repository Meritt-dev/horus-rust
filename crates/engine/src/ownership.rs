//! Ownership estimation from git commit history (HOR-20).
//! Output is probabilistic — always carries confidence + evidence.
//! Confidence is capped at 0.95; this is NEVER an org-chart lookup.

use crate::code_provider::{git_file_contributors, CodeProvider, FileContributor};
use horus_core::Symbol;
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Bot commit identities that must never be surfaced as a maintainer (HOR-369).
static BOT_AUTHOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\[bot\]|^(?:github-actions|dependabot(?:-preview)?|renovate(?:-bot)?|pre-commit-ci|greenkeeper|snyk-bot|mergify|imgbot|whitesource|codecov|semantic-release-bot|allcontributors)\b").unwrap()
});

/// True when a git author name/email belongs to an automated account (HOR-369).
pub fn is_bot_author(author: &str) -> bool {
    BOT_AUTHOR_RE.is_match(author.trim())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipEstimate {
    pub query: String,
    pub symbol: Option<Symbol>,
    pub file: Option<String>,
    pub contributors: Vec<FileContributor>,
    pub likely_maintainer: Option<String>,
    pub maintainer_share: f64,
    pub most_active_recent: Option<String>,
    pub confidence: f64,
    pub evidence: Vec<String>,
    /// Populated when multiple files match a file-path query and the result is ambiguous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<String>>,
    pub note: String,
}

// Extensions treated as file-path queries (not symbol names).
const CODE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "rb", "go", "rs", "java", "kt", "swift", "cs", "cpp", "c", "h",
    "hpp", "cc", "vue", "svelte", "astro", "php", "scala", "clj", "ex", "exs", "hs", "sh", "bash", "zsh", "json",
    "yaml", "yml", "toml", "sql", "graphql", "proto", "html", "css", "scss", "sass", "less", "md", "mdx",
];

fn looks_like_file_path(query: &str) -> bool {
    let base = query.rsplit('/').next().unwrap_or("");
    match base.rfind('.') {
        Some(idx) if idx > 0 => CODE_EXTENSIONS.contains(&base[idx + 1..].to_lowercase().as_str()),
        _ => false,
    }
}

fn empty_estimate(query: &str, symbol: Option<Symbol>, file: Option<String>, contributors: Vec<FileContributor>, evidence: Vec<String>, candidates: Option<Vec<String>>, note: String) -> OwnershipEstimate {
    OwnershipEstimate {
        query: query.to_string(),
        symbol,
        file,
        contributors,
        likely_maintainer: None,
        maintainer_share: 0.0,
        most_active_recent: None,
        confidence: 0.0,
        evidence,
        candidates,
        note,
    }
}

pub struct OwnershipDeps<'a> {
    pub code: &'a dyn CodeProvider,
    pub repo_path: String,
    /// `Some(..)` to reuse an already-resolved seed and skip the source-intelligence search
    /// (`Some(None)` = caller resolved nothing; still searches, matching TS `symbol: null`).
    pub symbol: Option<Option<Symbol>>,
}

/// Estimate who likely owns a component by searching for the closest symbol and
/// examining its file's git commit history.
pub async fn estimate_ownership(query: &str, deps: OwnershipDeps<'_>) -> anyhow::Result<OwnershipEstimate> {
    let mut top: Option<Symbol> = deps.symbol.clone().flatten();
    let needs_search = top.is_none();

    if needs_search {
        if looks_like_file_path(query) {
            // File-path query: search broadly then prefer exact basename / path-suffix matches
            // over whatever fuzzy symbol the provider returns as top-1.
            let query_base = query.rsplit('/').next().unwrap_or(query);
            let broad = deps.code.search_symbols(query, Some(20)).await?;
            let mut by_file: IndexMap<String, Symbol> = IndexMap::new();
            for sym in broad {
                let fp = sym.file_path.clone();
                if fp == query || fp.ends_with(&format!("/{query}")) || fp.rsplit('/').next() == Some(query_base) {
                    by_file.entry(fp).or_insert(sym);
                }
            }
            if by_file.len() == 1 {
                top = by_file.into_values().next();
            } else if by_file.len() > 1 {
                let n = by_file.len();
                return Ok(empty_estimate(
                    query,
                    None,
                    None,
                    vec![],
                    vec![],
                    Some(by_file.into_keys().collect()),
                    format!("Ambiguous: {n} files match \"{query}\". Use a more specific path to disambiguate."),
                ));
            } else {
                // No exact file match — fall back to fuzzy symbol search.
                top = deps.code.search_symbols(query, Some(5)).await?.into_iter().next();
            }
        } else {
            top = deps.code.search_symbols(query, Some(5)).await?.into_iter().next();
        }
    }

    let Some(file) = top.as_ref().map(|s| s.file_path.clone()) else {
        return Ok(empty_estimate(
            query,
            None,
            None,
            vec![],
            vec![],
            None,
            "No source symbol matched the query — cannot estimate ownership.".into(),
        ));
    };

    let contributors = git_file_contributors(&deps.repo_path, &file).await;

    // Bots can dominate a file's commit count yet are never the maintainer — rank only HUMAN
    // contributors (HOR-369). `contributors` (the full list) is still returned for evidence.
    let humans: Vec<&FileContributor> = contributors.iter().filter(|c| !is_bot_author(&c.author)).collect();

    if humans.is_empty() {
        let note = if contributors.is_empty() {
            format!("No commit history found for {file} — cannot estimate ownership.")
        } else {
            format!("Only automated/bot contributors found for {file} — no human maintainer to report.")
        };
        let evidence = if contributors.is_empty() {
            vec![]
        } else {
            vec![format!(
                "all {} contributor(s) are bots: {}",
                contributors.len(),
                contributors.iter().map(|c| c.author.as_str()).collect::<Vec<_>>().join(", ")
            )]
        };
        return Ok(empty_estimate(query, top, Some(file), contributors, evidence, None, note));
    }

    let total: i64 = humans.iter().map(|c| c.commits).sum();
    let lead = humans[0];
    let maintainer_share = if total > 0 { lead.commits as f64 / total as f64 } else { 0.0 };

    // Most active recently = HUMAN contributor with the latest lastDate (stable sort).
    let mut by_recent = humans.clone();
    by_recent.sort_by(|a, b| b.last_date.cmp(&a.last_date));
    let most_active_recent = by_recent.first().map(|c| c.author.clone());

    let confidence = f64::min(0.95, maintainer_share);

    let evidence = vec![
        format!("{} of {total} human commit(s) to {file}", lead.commits),
        format!("last touched {} by {}", lead.last_date, lead.author),
        format!("{} distinct contributor(s)", contributors.len()),
    ];

    Ok(OwnershipEstimate {
        query: query.to_string(),
        symbol: top,
        file: Some(file),
        likely_maintainer: Some(lead.author.clone()),
        contributors,
        maintainer_share,
        most_active_recent,
        confidence,
        evidence,
        candidates: None,
        note: "Estimate from git commit history only — not an org chart or HR data; confirm with the team.".into(),
    })
}
