//! Architecture discovery: subsystems, async boundaries, key flows, external systems
//! and fragility metrics derived from the source index + stitched queue edges.

use crate::code_provider::{CodeProvider, QueueEdge};
use crate::js::locale_compare;
use horus_core::{classify_path, filter_queue_edges, PathKind};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subsystem {
    pub name: String,
    pub members: i64,
    /// Test/docs/maintenance-dominated (by name tokens or member paths) — rendered tagged + last.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub testy: Option<bool>,
}

/// Producer/worker symbol + file — file disambiguates same-named producer/worker (HOR-368).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SymFile {
    pub symbol: String,
    pub file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AsyncBoundary {
    pub queue_name: String,
    pub producers: Vec<SymFile>,
    pub workers: Vec<SymFile>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalSystem {
    pub name: String,
    pub files: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeStat {
    pub label: String,
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fragile {
    pub dead_code: i64,
    pub high_coupling_pairs: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchitectureModel {
    pub node_stats: Vec<NodeStat>,
    pub subsystems: Vec<Subsystem>,
    pub async_boundaries: Vec<AsyncBoundary>,
    pub key_flows: Vec<String>,
    pub external_systems: Vec<ExternalSystem>,
    pub fragile: Fragile,
    pub summary: String,
}

const EXTERNAL_MARKERS: &[&str] = &[
    "zoho", "stripe", "prisma", "redis", "bullmq", "twilio", "sendgrid", "clerk", "pusher", "axios",
    "elasticsearch", "prometheus", "mongo", "graphql",
    // Python ecosystem (HOR-356)
    "sqlalchemy", "sqlmodel", "psycopg", "celery", "fastapi", "flask", "django", "kafka", "boto3",
    // Node ORMs/DB drivers (HOR-359)
    "typeorm", "sequelize", "knex", "drizzle-orm", "postgres", "mariadb", "mysql2", "mssql",
    // Python async DB drivers (HOR-379)
    "sqlite", "asyncpg", "aiomysql", "asyncmy", "aiopg", "pymysql",
];

/// Community-name tokens that mark a test/example/docs cluster (de-prioritized in ranking).
const TESTY_TOKENS: &[&str] = &[
    "test", "tests", "spec", "specs", "example", "examples", "sample", "samples", "demo", "demos",
    "docs", "doc", "tutorial", "tutorials", "fixture", "fixtures", "e2e",
];

static TESTY_SPLIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[+\s/_.\-]+").unwrap());

/// True when a Louvain community name is dominated by test/example/docs tokens (HOR-365).
pub fn is_testy_community(name: &str) -> bool {
    TESTY_SPLIT_RE.split(&name.to_lowercase()).any(|t| TESTY_TOKENS.contains(&t))
}

// Repo-maintenance trees that are never "the architecture". Ranking-only signal — deliberately
// NOT part of is_test_or_example_path, which also gates dead-code and external-system detection.
static MAINTENANCE_DIR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(^|/)(scripts?|tools?|tooling|ci|\.github|hack)(/|$)").unwrap());

/// True when most of a community's MEMBERS live under test/example/docs trees. Member node ids
/// are path-shaped (`<kind>:<path>:<name>`), so the file path is extractable without extra requests.
pub fn is_mostly_non_product_members(members: Option<&[String]>) -> bool {
    let Some(members) = members else { return false };
    if members.is_empty() {
        return false;
    }
    let mut non_product = 0usize;
    for id in members {
        let parts: Vec<&str> = id.split(':').collect();
        let path = if parts.len() >= 2 { parts[1] } else { "" };
        if !path.is_empty() && (is_test_or_example_path(path) || MAINTENANCE_DIR_RE.is_match(path)) {
            non_product += 1;
        }
    }
    non_product as f64 / members.len() as f64 > 0.6
}

static LEADING_UNDERSCORE_DOT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[_.]+").unwrap());

/// Normalize a community name on display (HOR-377): strip leading `_`/`.` and collapse "X+x"
/// where both halves are the same case-insensitively ("Sqs+sqs" → "Sqs").
pub fn clean_subsystem_name(name: &str) -> String {
    let mut n = LEADING_UNDERSCORE_DOT_RE.replace(name, "").trim().to_string();
    let parts: Vec<&str> = n.split('+').collect();
    if parts.len() == 2 {
        let (a, b) = (parts[0], parts[1]);
        if !a.is_empty() && !b.is_empty() && a.to_lowercase() == b.to_lowercase() {
            n = a.to_string();
        }
    }
    if n.is_empty() {
        name.to_string()
    } else {
        n
    }
}

/// A file path in a test/example/docs tree or file — excluded from external-system
/// detection (HOR-366). Delegates to the shared classifier.
pub fn is_test_or_example_path(p: &str) -> bool {
    matches!(classify_path(p), PathKind::Test | PathKind::Docs | PathKind::Example)
}

// Word-list / dataset files are full of proper nouns and common words that collide with
// integration markers — excluded from external-system detection only.
static DATA_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|/)(datasets?|seed(?:s|-?data)?|dictionar(?:y|ies)|word-?lists?|locales?|i18n|corpus)(/|$)|(^|/)(first-?names?|last-?names?|sur-?names?|full-?names?|countries|cities|nouns|adjectives|verbs|words|colou?rs|jobs?-?titles?|emojis?)\.[jt]sx?$",
    )
    .unwrap()
});

/// A word-list/dataset file whose string contents falsely match integration markers.
pub fn is_data_file_path(p: &str) -> bool {
    DATA_FILE_RE.is_match(p)
}

fn alnum_only(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

/// True when a marker's matched files are dominated by the repo's OWN plugin/capability for
/// that marker, not an integration WITH it: ≥50% of the matched product files live under a
/// directory segment named after the marker, or ≥2 files and ≥33% (a diffuse but anchored cluster).
pub fn is_own_capability(marker: &str, product_files: &[String]) -> bool {
    if product_files.is_empty() {
        return false;
    }
    let needle = alnum_only(&marker.to_lowercase());
    if needle.is_empty() {
        return false;
    }
    let in_own_dir = product_files
        .iter()
        .filter(|p| {
            let lower = p.replace('\\', "/").to_lowercase();
            let segs: Vec<&str> = lower.split('/').collect();
            segs[..segs.len().saturating_sub(1)].iter().any(|seg| alnum_only(seg).contains(&needle))
        })
        .count();
    let frac = in_own_dir as f64 / product_files.len() as f64;
    frac >= 0.5 || (in_own_dir >= 2 && frac >= 0.33)
}

pub struct ArchitectureDeps<'a> {
    pub code: &'a dyn CodeProvider,
    /// Pre-fetched queue edges for the active project (`listQueueEdges`); the TS reads the db here.
    pub queue_edges: Vec<QueueEdge>,
    /// Active project — scopes queue edges so other projects' queues don't leak in (HOR-207).
    pub project: Option<String>,
    /// Manifest-derived package names of THIS repo — excluded from external-system detection.
    pub own_packages: Vec<String>,
}

/// Every section degrades to its empty default independently — one absent provider method or
/// failed request must not blank the whole architecture view.
pub async fn discover_architecture(deps: ArchitectureDeps<'_>) -> ArchitectureModel {
    // 1. Node label counts
    let node_stats: Vec<NodeStat> = match deps.code.overview().await {
        Ok(Some(o)) => {
            let mut rows: Vec<NodeStat> = o
                .nodes_by_label
                .into_iter()
                .map(|(label, count)| NodeStat { label, count })
                .filter(|s| s.label.to_lowercase() != "embedding")
                .collect();
            rows.sort_by(|a, b| b.count.cmp(&a.count));
            rows
        }
        _ => vec![],
    };

    // 2. Subsystems (Louvain communities)
    let subsystems: Vec<Subsystem> = match deps.code.communities().await {
        Ok(communities) => {
            let mut rows: Vec<Subsystem> = communities
                .unwrap_or_default()
                .into_iter()
                .map(|c| Subsystem {
                    name: clean_subsystem_name(&c.name),
                    members: c.member_count,
                    testy: Some(is_testy_community(&c.name) || is_mostly_non_product_members(c.members.as_deref())),
                })
                .collect();
            // De-prioritize test/example/docs clusters so the real product subsystems lead (HOR-365).
            rows.sort_by(|a, b| {
                let at = a.testy.unwrap_or(false) as u8;
                let bt = b.testy.unwrap_or(false) as u8;
                at.cmp(&bt).then_with(|| b.members.cmp(&a.members))
            });
            rows.truncate(12);
            rows
        }
        Err(_) => vec![],
    };

    // 3. Async boundaries from queue edges — hygiene rules live in horus-core.
    let async_boundaries: Vec<AsyncBoundary> = {
        let edges = filter_queue_edges(deps.queue_edges);
        let mut by_queue: IndexMap<String, (IndexMap<String, SymFile>, IndexMap<String, SymFile>)> = IndexMap::new();
        for edge in edges {
            let entry = by_queue.entry(edge.queue_name.clone()).or_default();
            if let Some(sym) = edge.producer_symbol.as_deref().filter(|s| !s.is_empty()) {
                let file = edge.producer_file.clone();
                entry.0.insert(
                    format!("{sym}\u{0}{}", file.as_deref().unwrap_or("")),
                    SymFile { symbol: sym.to_string(), file },
                );
            }
            if let Some(sym) = edge.worker_symbol.as_deref().filter(|s| !s.is_empty()) {
                let file = edge.worker_file.clone();
                entry.1.insert(
                    format!("{sym}\u{0}{}", file.as_deref().unwrap_or("")),
                    SymFile { symbol: sym.to_string(), file },
                );
            }
        }
        by_queue
            .into_iter()
            .map(|(queue_name, (producers, workers))| AsyncBoundary {
                queue_name,
                producers: producers.into_values().collect(),
                workers: workers.into_values().collect(),
            })
            .collect()
    };

    // 4. Key flows (Process nodes) — ranked by IMPORTANCE: real-path flows lead, longer flows
    //    beat shorter ones, name only breaks ties.
    let key_flows: Vec<String> = match deps.code.processes().await {
        Ok(processes) => {
            struct Ranked {
                name: String,
                steps: i64,
                non_product: bool,
            }
            let mut ranked: Vec<Ranked> = processes
                .unwrap_or_default()
                .into_iter()
                .filter(|p| !p.name.is_empty())
                .map(|p| {
                    let first_step = p.steps.as_ref().and_then(|s| s.first()).map(|s| s.node_id.clone()).unwrap_or_default();
                    let parts: Vec<&str> = first_step.split(':').collect();
                    let path = if parts.len() >= 2 { parts[1] } else { "" };
                    Ranked {
                        steps: p.step_count.or_else(|| p.steps.as_ref().map(|s| s.len() as i64)).unwrap_or(0),
                        non_product: !path.is_empty() && is_test_or_example_path(path),
                        name: p.name,
                    }
                })
                .collect();
            ranked.sort_by(|a, b| {
                a.non_product
                    .cmp(&b.non_product)
                    .then_with(|| b.steps.cmp(&a.steps))
                    .then_with(|| locale_compare(&a.name, &b.name))
            });
            ranked.into_iter().take(20).map(|p| p.name).collect()
        }
        Err(_) => vec![],
    };

    // 5. Fragility metrics
    let dead_code = match deps.code.dead_code().await {
        Ok(r) => r.map(|r| r.total).unwrap_or(0),
        Err(_) => 0,
    };
    let high_coupling_pairs = match deps.code.coupling().await {
        Ok(pairs) => pairs.unwrap_or_default().iter().filter(|p| p.co_changes >= 3).count() as i64,
        Err(_) => 0,
    };

    // 6. External systems — ONE per-token file search for all markers; count only genuine
    //    product source and skip the repo's OWN package(s) (HOR-366, dogfood N2).
    let own_packages: HashSet<String> = deps
        .project
        .iter()
        .chain(deps.own_packages.iter())
        .filter(|x| !x.is_empty())
        .map(|x| x.to_lowercase())
        .collect();
    let external_systems: Vec<ExternalSystem> = {
        let markers: Vec<String> = EXTERNAL_MARKERS
            .iter()
            .filter(|m| !own_packages.contains(&m.to_lowercase()))
            .map(|m| m.to_string())
            .collect();
        match deps.code.files_containing(&markers, Some(500)).await {
            Ok(matches) => {
                let matches = matches.unwrap_or_default();
                let mut rows: Vec<ExternalSystem> = markers
                    .iter()
                    .filter_map(|marker| {
                        let product_files: Vec<String> = matches
                            .get(marker)
                            .map(|v| {
                                v.iter()
                                    .filter(|p| !p.is_empty() && classify_path(p) == PathKind::Product && !is_data_file_path(p))
                                    .cloned()
                                    .collect()
                            })
                            .unwrap_or_default();
                        let files = product_files.len() as i64;
                        if files > 0 && !is_own_capability(marker, &product_files) {
                            Some(ExternalSystem { name: marker.clone(), files })
                        } else {
                            None
                        }
                    })
                    .collect();
                rows.sort_by(|a, b| b.files.cmp(&a.files));
                rows
            }
            Err(_) => vec![],
        }
    };

    // 7. Summary sentence
    let largest_desc = match subsystems.first() {
        Some(s) => format!("{} with {} symbols", s.name, s.members),
        None => "none".to_string(),
    };
    let summary = format!(
        "{} subsystems (largest: {largest_desc}), {} async queue boundaries, {} external systems, {dead_code} unreferenced symbols.",
        subsystems.len(),
        async_boundaries.len(),
        external_systems.len(),
    );

    ArchitectureModel {
        node_stats,
        subsystems,
        async_boundaries,
        key_flows,
        external_systems,
        fragile: Fragile { dead_code, high_coupling_pairs },
        summary,
    }
}
