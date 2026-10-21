//! Onboarding guide: architecture filtered toward an area, ownership, and past incidents.

use crate::architecture::{discover_architecture, ArchitectureDeps, ArchitectureModel};
use crate::code_provider::{CodeProvider, InvestigationRow, QueueEdge};
use crate::memory::derive_tags;
use crate::ownership::{estimate_ownership, OwnershipDeps, OwnershipEstimate};
use crate::types::InvestigationReport;
use horus_core::Symbol;
use indexmap::IndexSet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PastIncident {
    pub id: String,
    pub title: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingGuide {
    pub area: Option<String>,
    pub architecture: ArchitectureModel,
    pub ownership: Option<OwnershipEstimate>,
    pub past_incidents: Vec<PastIncident>,
    pub summary: String,
}

static NON_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9/_.\-]+").unwrap());
static CAMEL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-z0-9])([A-Z])").unwrap());
static ACRONYM_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([A-Z]+)([A-Z][a-z])").unwrap());
static SPLIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\s/_.\-]+").unwrap());

/// Tokenize a string into lowercase alphanumeric words, splitting camelCase/PascalCase.
fn tokenize(text: &str) -> Vec<String> {
    let with_spaces = NON_TOKEN_RE.replace_all(text, " ");
    let with_spaces = CAMEL_RE.replace_all(&with_spaces, "$1 $2");
    let with_spaces = ACRONYM_RE.replace_all(&with_spaces, "$1 $2");
    let lower = with_spaces.to_lowercase();
    let set: IndexSet<String> = SPLIT_RE.split(&lower).filter(|t| !t.is_empty()).map(String::from).collect();
    set.into_iter().collect()
}

/// Generic programming/directory tokens that are not useful for area filtering.
const GENERIC_PATH_TOKENS: &[&str] = &[
    "src", "lib", "app", "test", "tests", "spec", "dist", "node", "modules", "common", "shared", "public", "private",
    "types", "interfaces", "constants", "config", "index", "main", "server", "client", "api", "http", "db", "database",
    "model", "models", "schema", "migration", "seed", "fixture", "mock", "hook", "context", "provider", "factory",
    "middleware", "route", "router", "routes", "service", "services", "controller", "controllers", "resolver",
    "resolvers", "worker", "workers", "helper", "helpers", "util", "utils",
];

/// Build a relevance token set from the area string and resolved symbols. Area tokens are
/// always kept; symbol/path tokens are filtered to avoid generic programming terms.
pub fn build_area_tokens(area: &str, symbols: &[Symbol]) -> IndexSet<String> {
    let mut tokens: IndexSet<String> = tokenize(area).into_iter().collect();
    for sym in symbols {
        for t in tokenize(&sym.name).into_iter().chain(tokenize(&sym.file_path)) {
            if t.chars().count() >= 3 && !GENERIC_PATH_TOKENS.contains(&t.as_str()) {
                tokens.insert(t);
            }
        }
    }
    tokens
}

/// True when text contains at least one area token.
pub fn matches_area(text: &str, tokens: &IndexSet<String>) -> bool {
    let text_tokens: HashSet<String> = tokenize(text).into_iter().collect();
    tokens.iter().any(|t| text_tokens.contains(t))
}

/// Score a symbol by how many area tokens appear in its name/path.
fn area_match_score(symbol: &Symbol, tokens: &IndexSet<String>) -> i64 {
    let name_tokens = tokenize(&symbol.name);
    let path_tokens = tokenize(&symbol.file_path);
    let mut score = 0;
    for t in tokens {
        if name_tokens.contains(t) {
            score += 2;
        }
        if path_tokens.contains(t) {
            score += 1;
        }
    }
    score
}

/// Pick the symbol that best matches the area string from a search result.
pub fn best_area_symbol(area: &str, symbols: &[Symbol]) -> Option<Symbol> {
    let area_only: IndexSet<String> = tokenize(area).into_iter().collect();
    let mut best: Option<&Symbol> = None;
    let mut best_score = -1;
    for sym in symbols {
        let score = area_match_score(sym, &area_only);
        if score > best_score {
            best_score = score;
            best = Some(sym);
        }
    }
    best.cloned()
}

/// Filter architecture components to those whose names overlap with the area tokens.
pub fn filter_architecture(architecture: &ArchitectureModel, tokens: &IndexSet<String>) -> ArchitectureModel {
    ArchitectureModel {
        node_stats: architecture.node_stats.clone(),
        subsystems: architecture.subsystems.iter().filter(|s| matches_area(&s.name, tokens)).cloned().collect(),
        async_boundaries: architecture
            .async_boundaries
            .iter()
            .filter(|b| {
                matches_area(&b.queue_name, tokens)
                    || b.producers.iter().any(|p| matches_area(&p.symbol, tokens))
                    || b.workers.iter().any(|w| matches_area(&w.symbol, tokens))
            })
            .cloned()
            .collect(),
        key_flows: architecture.key_flows.iter().filter(|f| matches_area(f, tokens)).cloned().collect(),
        external_systems: architecture.external_systems.iter().filter(|e| matches_area(&e.name, tokens)).cloned().collect(),
        fragile: architecture.fragile.clone(),
        summary: architecture.summary.clone(),
    }
}

pub struct OnboardingDeps<'a> {
    pub code: &'a dyn CodeProvider,
    pub repo_path: String,
    pub project: Option<String>,
    /// Manifest-derived package names — excluded from external-system detection (N2).
    pub own_packages: Vec<String>,
    /// Pre-fetched `listQueueEdges` rows for the project (the TS reads the db here).
    pub queue_edges: Vec<QueueEdge>,
    /// Pre-fetched `listInvestigations(db, 8)` rows, newest first (no-area path).
    pub recent_investigations: Vec<InvestigationRow>,
    /// Pre-fetched `listInvestigationsWithReports(db, 50)` rows, newest first (area path).
    pub investigations_with_reports: Vec<InvestigationRow>,
}

pub async fn build_onboarding(area: Option<&str>, deps: OnboardingDeps<'_>) -> anyhow::Result<OnboardingGuide> {
    let architecture = discover_architecture(ArchitectureDeps {
        code: deps.code,
        queue_edges: deps.queue_edges,
        project: deps.project.clone(),
        own_packages: deps.own_packages.clone(),
    })
    .await;

    let area = area.map(|a| a.trim().to_string());
    let mut filtered_architecture = architecture.clone();
    let mut past_incidents: Vec<PastIncident> = vec![];
    let mut area_symbol: Option<Symbol> = None;

    match area.as_deref().filter(|a| !a.is_empty()) {
        Some(area) => {
            // Resolve area to candidate symbols once; reuse the token set for every filter.
            let symbols = deps.code.search_symbols(area, Some(20)).await?;
            let tokens = build_area_tokens(area, &symbols);
            area_symbol = best_area_symbol(area, &symbols);
            filtered_architecture = filter_architecture(&architecture, &tokens);

            // Past incidents: prefer reports with tag overlap, fall back to title matching.
            let mut seen_ids: HashSet<&str> = HashSet::new();
            for inv in &deps.investigations_with_reports {
                let Some(report) = &inv.report else { continue };
                if !seen_ids.insert(inv.id.as_str()) {
                    continue;
                }
                let mut relevant = match serde_json::from_value::<InvestigationReport>(report.clone()) {
                    Ok(r) => {
                        let tag_set: HashSet<String> = derive_tags(&r).into_iter().map(|t| t.to_lowercase()).collect();
                        tokens.iter().any(|t| tag_set.contains(&t.to_lowercase()))
                    }
                    Err(_) => false,
                };
                if !relevant {
                    relevant = matches_area(&inv.title, &tokens);
                }
                if relevant {
                    past_incidents.push(PastIncident { id: inv.id.clone(), title: inv.title.clone(), created_at: inv.created_at.clone() });
                }
            }
            past_incidents.truncate(8);
        }
        None => {
            // No area supplied — show the whole-repo view.
            past_incidents = deps
                .recent_investigations
                .iter()
                .take(8)
                .map(|i| PastIncident { id: i.id.clone(), title: i.title.clone(), created_at: i.created_at.clone() })
                .collect();
        }
    }

    let ownership = match area.as_deref().filter(|a| !a.is_empty()) {
        Some(a) => Some(
            estimate_ownership(a, OwnershipDeps { code: deps.code, repo_path: deps.repo_path.clone(), symbol: Some(area_symbol) }).await?,
        ),
        None => None,
    };

    let largest_name = filtered_architecture.subsystems.first().map(|s| s.name.as_str()).unwrap_or("n/a");
    let summary = format!(
        "{}{} subsystems (largest {largest_name}), {} async queue boundaries, {} external systems, {} past investigation(s) on record.{}",
        match &area {
            Some(a) => format!("Onboarding for \"{a}\": "),
            None => "System onboarding: ".to_string(),
        },
        filtered_architecture.subsystems.len(),
        filtered_architecture.async_boundaries.len(),
        filtered_architecture.external_systems.len(),
        past_incidents.len(),
        match &area {
            Some(a) => format!(" Filtered toward \"{a}\"."),
            None => String::new(),
        },
    );

    Ok(OnboardingGuide { area, architecture: filtered_architecture, ownership, past_incidents, summary })
}
