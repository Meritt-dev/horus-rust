//! Blast-radius analysis: upstream (callees), downstream (callers by depth) and the async
//! queue boundaries a seed crosses.

use crate::code_provider::{CodeProvider, QueueEdge};
use crate::seeds::{parse_named_symbols, rank_seeds, resolve_seed_symbol, ResolutionKind, SeedResolveOptions};
use horus_core::{ImpactDepth, Symbol};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AsyncDependency {
    pub queue_name: String,
    pub counterpart: String,
    pub counterpart_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Low,
    Medium,
    High,
}

impl Criticality {
    pub fn as_str(self) -> &'static str {
        match self {
            Criticality::Low => "low",
            Criticality::Medium => "medium",
            Criticality::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlastRadiusReport {
    pub seed: Symbol,
    /// How the query resolved to the seed (shared resolver semantics — same as explain).
    pub resolution: ResolutionKind,
    /// True when multiple exact matches tied — `alternatives` disclose them.
    pub ambiguous: bool,
    /// Runner-up candidates from the same resolution tier (for disambiguation display).
    pub alternatives: Vec<Symbol>,
    pub upstream: Vec<Symbol>,
    pub downstream: Vec<ImpactDepth>,
    pub async_upstream: Vec<AsyncDependency>,
    pub async_downstream: Vec<AsyncDependency>,
    pub blast_radius: i64,
    pub criticality: Criticality,
    pub summary: String,
    pub note: String,
    /// True when the local database was unavailable, so the async queue-boundary enrichment
    /// was skipped; the source-graph blast radius itself is unaffected.
    pub db_unavailable: bool,
}

pub struct BlastRadiusDeps<'a> {
    pub code: &'a dyn CodeProvider,
    /// Pre-fetched queue edges for the project (`listQueueEdges`); `None` = db unavailable.
    pub queue_edges: Option<Vec<QueueEdge>>,
    pub project: Option<String>,
}

pub async fn analyze_blast_radius(
    query: &str,
    deps: BlastRadiusDeps<'_>,
    depth: Option<usize>,
    include_tests: bool,
) -> anyhow::Result<Option<BlastRadiusReport>> {
    let depth = depth.unwrap_or(3);
    // THE canonical resolver (shared with explain/search/investigate): exact-qualified > exact >
    // fuzzy, product code before tests, deterministic ambiguity. Only a FUZZY result falls back to
    // the HOR-385 prompt-named seed ranking.
    let res = resolve_seed_symbol(deps.code, query, SeedResolveOptions { limit: Some(20), include_tests: Some(include_tests) }).await?;
    let mut top: Option<Symbol> = res.candidates.first().cloned();
    if res.kind == ResolutionKind::Fuzzy {
        let prefer_named = parse_named_symbols(query).into_iter().next();
        top = rank_seeds(&res.candidates, None, None, false, None, prefer_named.as_deref()).into_iter().next().map(|r| r.symbol);
    }
    let Some(top) = top else { return Ok(None) };
    // Alternatives: same-tier runners-up (exact matches only) for disambiguation display.
    let alternatives: Vec<Symbol> = if matches!(res.kind, ResolutionKind::Exact | ResolutionKind::ExactQualified) {
        res.candidates
            .iter()
            .skip(1)
            .filter(|s| s.name.to_lowercase() == top.name.to_lowercase())
            .take(4)
            .cloned()
            .collect()
    } else {
        vec![]
    };

    let (ctx, impact) = tokio::try_join!(
        deps.code.context(&top.id),
        deps.code.impact(&top.id, Some(depth), if include_tests { Some(true) } else { None }),
    )?;

    // upstream = what the seed depends on (callees); downstream = callers by depth
    let upstream: Vec<Symbol> = ctx.callees;
    let downstream: Vec<ImpactDepth> = impact.by_depth;

    // Queue edges are the only db-backed enrichment here — degrade to no async boundaries
    // rather than crash the whole blast-radius report.
    let db_unavailable = deps.queue_edges.is_none();
    let edges = deps.queue_edges.unwrap_or_default();

    // asyncDownstream: seed is the producer -> workers are downstream
    let mut async_downstream_map: IndexMap<String, AsyncDependency> = IndexMap::new();
    for edge in &edges {
        if edge.producer_file.as_deref() == Some(top.file_path.as_str()) || edge.producer_symbol.as_deref() == Some(top.name.as_str()) {
            let counterpart = edge.worker_symbol.clone().unwrap_or_else(|| "unknown-worker".into());
            let key = format!("{}|{counterpart}", edge.queue_name);
            async_downstream_map.entry(key).or_insert_with(|| AsyncDependency {
                queue_name: edge.queue_name.clone(),
                counterpart,
                counterpart_file: edge.worker_file.clone(),
            });
        }
    }
    let async_downstream: Vec<AsyncDependency> = async_downstream_map.into_values().collect();

    // asyncUpstream: seed is the worker -> producers are upstream
    let mut async_upstream_map: IndexMap<String, AsyncDependency> = IndexMap::new();
    for edge in &edges {
        if edge.worker_file.as_deref() == Some(top.file_path.as_str()) || edge.worker_symbol.as_deref() == Some(top.name.as_str()) {
            let counterpart = edge.producer_symbol.clone().unwrap_or_else(|| "unknown-producer".into());
            let key = format!("{}|{counterpart}", edge.queue_name);
            async_upstream_map.entry(key).or_insert_with(|| AsyncDependency {
                queue_name: edge.queue_name.clone(),
                counterpart,
                counterpart_file: edge.producer_file.clone(),
            });
        }
    }
    let async_upstream: Vec<AsyncDependency> = async_upstream_map.into_values().collect();

    let blast_radius = impact.affected + async_downstream.len() as i64;
    let criticality = if blast_radius >= 10 {
        Criticality::High
    } else if blast_radius >= 3 {
        Criticality::Medium
    } else {
        Criticality::Low
    };

    let summary = format!(
        "If {} ({}) fails, ~{blast_radius} symbol(s) are affected downstream{}; it depends on {} symbol(s) upstream{}. Criticality: {}.",
        top.name,
        top.file_path,
        if async_downstream.is_empty() { String::new() } else { format!(" (incl. {} across async queue boundaries)", async_downstream.len()) },
        upstream.len(),
        if async_upstream.is_empty() { String::new() } else { format!(" + {} async producer(s)", async_upstream.len()) },
        criticality.as_str(),
    );

    Ok(Some(BlastRadiusReport {
        seed: top,
        resolution: res.kind,
        ambiguous: res.ambiguous,
        alternatives,
        upstream,
        downstream,
        async_upstream,
        async_downstream,
        blast_radius,
        criticality,
        summary,
        note: "The component reporting an error is often not the cause — inspect the upstream dependencies first.".into(),
        db_unavailable,
    }))
}
