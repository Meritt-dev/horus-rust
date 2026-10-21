//! HOR-15 — Cause Scoring Engine v2.
//!
//! Principled, explainable multi-factor scoring. Every boost/penalty produces a
//! human-readable explanation. Scores map to four confidence bands.

use std::collections::{HashMap, HashSet};

use horus_core::{Evidence, EvidenceKind, EvidencePriority, ProviderKind};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::graph::{implicated_node_ids, max_implication_score, GraphNodeType, InvestigationGraph};
use crate::js;
use crate::types::{provider_kind_name, Intent};

/// Qualitative confidence band for a scored cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CauseBand {
    /// finalScore ≥ 0.85
    HighlyLikely,
    /// finalScore ≥ 0.65
    Likely,
    /// finalScore ≥ 0.40
    Possible,
    /// finalScore < 0.40
    Observation,
}

impl CauseBand {
    pub fn as_str(self) -> &'static str {
        match self {
            CauseBand::HighlyLikely => "highly-likely",
            CauseBand::Likely => "likely",
            CauseBand::Possible => "possible",
            CauseBand::Observation => "observation",
        }
    }
}

/// One factor's contribution to the final score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreExplanation {
    pub factor: String,
    pub delta: f64,
    pub reason: String,
}

/// A fully scored cause candidate, ready for ranking and report inclusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CauseCandidate {
    pub id: String,
    pub title: String,
    pub category: String,
    pub source_evidence_ids: Vec<String>,
    pub affected_node_ids: Vec<String>,
    pub base_score: f64,
    pub final_score: f64,
    /// Alias for finalScore; kept separate for future divergence.
    pub confidence: f64,
    pub band: CauseBand,
    pub explanations: Vec<ScoreExplanation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

/// Caller-supplied input for a cause to be scored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CauseInput {
    pub id: String,
    pub title: String,
    pub category: String,
    pub source_evidence_ids: Vec<String>,
    /// If omitted, derived from the graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_node_ids: Option<Vec<String>>,
    /// Heuristic prior probability (0–1).
    pub base_score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

/// Minimal finding shape accepted by the scorer (structurally `ReportFinding`).
#[derive(Debug, Clone, PartialEq)]
pub struct ScoringFinding {
    pub kind: String,
    pub confidence: f64,
    pub evidence_ids: Vec<String>,
}

/// Investigation request parameters forwarded to the scorer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScoringRequest {
    pub hint: Option<String>,
    pub service: Option<String>,
}

/// Contextual data the scorer uses to compute factor adjustments.
#[derive(Debug, Clone)]
pub struct ScoringContext<'a> {
    pub evidence: &'a [Evidence],
    pub graph: &'a InvestigationGraph,
    pub findings: Option<Vec<ScoringFinding>>,
    /// Provider source ID → reliability score (0–1). When absent, Factor 8 is skipped.
    pub provider_reliability: Option<HashMap<String, f64>>,
    pub request: Option<ScoringRequest>,
    /// Reference ISO timestamp for recency; defaults to now when omitted.
    pub now: Option<String>,
    /// HOR-363: graph node id → number of PRIOR investigations that touched it.
    pub prior_incidents: Option<HashMap<String, i64>>,
    /// HOR-385: `Some(Intent::SourceImpact)` drops the structural penalties.
    pub mode: Option<Intent>,
}

fn priority_weight(p: EvidencePriority) -> f64 {
    match p {
        EvidencePriority::Critical => 1.00,
        EvidencePriority::High => 0.90,
        EvidencePriority::Medium => 0.75,
        EvidencePriority::Low => 0.50,
        EvidencePriority::Info => 0.15,
    }
}

fn is_structural_kind(k: EvidenceKind) -> bool {
    matches!(k, EvidenceKind::Symbol | EvidenceKind::Flow | EvidenceKind::Impact | EvidenceKind::QueueEdge)
}

fn clamp01(n: f64) -> f64 {
    if n.is_nan() {
        return 0.0;
    }
    n.max(0.0).min(1.0)
}

/// Map a 0–1 score to a qualitative confidence band (shared with packet.ts — HOR-384).
pub fn get_band(score: f64) -> CauseBand {
    if score >= 0.85 {
        CauseBand::HighlyLikely
    } else if score >= 0.65 {
        CauseBand::Likely
    } else if score >= 0.40 {
        CauseBand::Possible
    } else {
        CauseBand::Observation
    }
}

/// Factor 1 — Evidence quality (severity × confidence).
fn factor_evidence_quality(items: &[&Evidence], suppress_info_penalty: bool) -> Option<ScoreExplanation> {
    let scored: Vec<&Evidence> =
        items.iter().copied().filter(|ev| ev.priority.is_some_and(|p| p != EvidencePriority::Info)).collect();
    if scored.is_empty() {
        if items.is_empty() {
            return None;
        }
        // HOR-385: all-info is the EXPECTED shape of a purely structural cause.
        if suppress_info_penalty {
            return None;
        }
        return Some(ScoreExplanation {
            factor: "evidence-quality".into(),
            delta: -0.05,
            reason: "All attached evidence has info priority — no anomaly signal present".into(),
        });
    }
    let total = scored.iter().fold(0.0, |sum, ev| {
        let w = ev.priority.map(priority_weight).unwrap_or(0.5);
        sum + w * ev.relevance
    });
    let avg = total / scored.len() as f64;
    let delta = js::round_to(avg - 0.5, 3);
    if delta.abs() < 0.01 {
        return None;
    }
    let sign = if delta > 0.0 { "+" } else { "" };
    Some(ScoreExplanation {
        factor: "evidence-quality".into(),
        delta,
        reason: format!(
            "{} anomaly evidence item(s); priority-weighted quality {} ({}{} vs 0.50 baseline)",
            scored.len(),
            js::to_fixed(avg, 2),
            sign,
            js::to_fixed(delta, 2)
        ),
    })
}

/// Factor 2 — Source diversity (independent corroboration).
fn factor_source_diversity(items: &[&Evidence]) -> Option<ScoreExplanation> {
    let sources: IndexSet<ProviderKind> = items.iter().map(|e| e.source).collect();
    let count = sources.len();
    if count <= 1 {
        return None;
    }
    let delta = if count == 2 { 0.05 } else { 0.10 };
    let mut names: Vec<&str> = sources.iter().map(|s| provider_kind_name(*s)).collect();
    names.sort();
    Some(ScoreExplanation {
        factor: "source-diversity".into(),
        delta,
        reason: format!(
            "Evidence from {count} independent providers ({}) — multi-source corroboration",
            names.join(", ")
        ),
    })
}

/// Factor 3 — Graph proximity (infrastructure implication).
fn factor_graph_proximity(source_evidence_ids: &[String], graph: &InvestigationGraph) -> Option<ScoreExplanation> {
    let score = max_implication_score(graph, source_evidence_ids);
    if score <= 0.0 {
        return None;
    }
    let delta = js::round_to(score * 0.10, 3);
    Some(ScoreExplanation {
        factor: "graph-proximity".into(),
        delta,
        reason: format!(
            "Infrastructure node implication score {} → graph-confirmed path (+{}%)",
            js::to_fixed(score, 2),
            js::to_fixed(delta * 100.0, 0)
        ),
    })
}

/// Factor 4 — Runtime signals (recency + recurrence).
fn factor_runtime_signals(items: &[&Evidence], now: &str) -> Option<ScoreExplanation> {
    let now_ms = js::date_parse(now);
    let mut recency_delta = 0.0;
    let mut recency_reason = "";

    let mut timestamps: Vec<f64> =
        items.iter().filter_map(|e| e.timestamp.as_deref()).map(js::date_parse).collect();
    timestamps.sort_by(|a, b| js::cmp_f64(*b, *a));

    if let Some(&newest_ts) = timestamps.first() {
        let raw_age_ms = now_ms - newest_ts;
        // Future timestamps: within 5 min tolerance → "just now"; further → skip recency.
        // NaN mirrors JS: every comparison is false, so it falls through to the stale arm.
        let age_ms = if raw_age_ms < 0.0 {
            if raw_age_ms >= -300_000.0 { Some(0.0) } else { None }
        } else {
            Some(raw_age_ms)
        };
        if let Some(age_ms) = age_ms {
            if age_ms <= 3_600_000.0 {
                recency_delta = 0.05;
                recency_reason = "Evidence from within the last hour";
            } else if age_ms <= 86_400_000.0 {
                recency_delta = 0.02;
                recency_reason = "Evidence from within the last 24 hours";
            } else if age_ms <= 259_200_000.0 {
                // 24 h – 3 days: neutral
            } else if age_ms <= 604_800_000.0 {
                recency_delta = -0.02;
                recency_reason = "Most recent evidence is 3–7 days old — may predate this incident";
            } else {
                recency_delta = -0.05;
                recency_reason = "Most recent evidence is over 7 days old — likely predates this incident";
            }
        }
    }

    let mut recurrence_delta: f64 = 0.0;
    let mut recurrence_reason = String::new();
    for ev in items.iter().filter(|e| e.kind == EvidenceKind::Log) {
        if ev.is_new == Some(true) {
            recurrence_delta = recurrence_delta.max(0.05);
            recurrence_reason = "New error signature (isNew=true)".into();
        } else if let Some(ratio) = ev.ratio.filter(|r| *r >= 3.0) {
            recurrence_delta = recurrence_delta.max(0.03);
            recurrence_reason = format!("Error spike (ratio {}×)", js::to_fixed(ratio, 1));
        }
    }

    let delta = js::round_to(recency_delta + recurrence_delta, 3);
    if delta.abs() < 0.001 {
        return None;
    }
    let mut parts: Vec<&str> = vec![];
    if !recency_reason.is_empty() {
        parts.push(recency_reason);
    }
    if !recurrence_reason.is_empty() {
        parts.push(&recurrence_reason);
    }
    Some(ScoreExplanation { factor: "runtime-signals".into(), delta, reason: parts.join("; ") })
}

/// Factor 5 — Blast radius (capped at +0.05).
fn factor_blast_radius(metadata: Option<&Map<String, Value>>) -> Option<ScoreExplanation> {
    let affected = metadata?.get("blastRadius")?.as_f64()?;
    if affected <= 0.0 {
        return None;
    }
    let delta = js::round_to((affected / 20.0).min(1.0) * 0.05, 3);
    if delta < 0.005 {
        return None;
    }
    Some(ScoreExplanation {
        factor: "blast-radius".into(),
        delta,
        reason: format!(
            "Blast radius: {} affected symbol(s) — fault propagation risk",
            js::number_string(affected)
        ),
    })
}

/// Factor 6 — Signal strength (structural penalty + anomaly bonus).
fn factor_signal_strength(items: &[&Evidence]) -> Option<ScoreExplanation> {
    let non_structural: Vec<&Evidence> = items.iter().copied().filter(|e| !is_structural_kind(e.kind)).collect();

    if !items.is_empty() && non_structural.is_empty() {
        return Some(ScoreExplanation {
            factor: "signal-strength".into(),
            delta: -0.05,
            reason: "All evidence is structural (topology-only) — no runtime anomaly signal".into(),
        });
    }

    let high_relevance = non_structural.iter().filter(|e| e.relevance >= 0.85).count();
    if high_relevance > 0 {
        return Some(ScoreExplanation {
            factor: "signal-strength".into(),
            delta: 0.03,
            reason: format!("{high_relevance} high-relevance anomaly signal(s) (relevance ≥ 0.85)"),
        });
    }
    None
}

/// Factor 7 — Finding uncertainty: never boosts; penalises causes whose evidence only
/// appears in low-confidence findings.
fn factor_finding_uncertainty(source_evidence_ids: &[String], findings: &[ScoringFinding]) -> Option<ScoreExplanation> {
    if findings.is_empty() {
        return None;
    }
    let id_set: HashSet<&str> = source_evidence_ids.iter().map(String::as_str).collect();
    let relevant: Vec<&ScoringFinding> = findings
        .iter()
        .filter(|f| f.kind != "observation" && f.evidence_ids.iter().any(|eid| id_set.contains(eid.as_str())))
        .collect();
    if relevant.is_empty() {
        return None;
    }
    let max_confidence = relevant.iter().map(|f| f.confidence).fold(f64::NEG_INFINITY, f64::max);
    if max_confidence >= 0.60 {
        return None;
    }
    let delta = js::round_to(-(0.60 - max_confidence) * 0.10, 3);
    if delta == 0.0 {
        return None;
    }
    Some(ScoreExplanation {
        factor: "finding-uncertainty".into(),
        delta,
        reason: format!(
            "Relevant findings have low confidence (max {}) — investigation uncertain about evidence significance",
            js::to_fixed(max_confidence, 2)
        ),
    })
}

/// Factor 8 — Provider reliability.
fn factor_provider_reliability(items: &[&Evidence], reliability: &HashMap<String, f64>) -> Option<ScoreExplanation> {
    if items.is_empty() {
        return None;
    }
    let sources: IndexSet<ProviderKind> = items.iter().map(|e| e.source).collect();
    let scores: Vec<f64> =
        sources.iter().map(|s| reliability.get(provider_kind_name(*s)).copied().unwrap_or(0.65)).collect();
    let avg = scores.iter().fold(0.0, |a, b| a + b) / scores.len() as f64;
    if avg >= 0.80 {
        return Some(ScoreExplanation {
            factor: "provider-reliability".into(),
            delta: 0.03,
            reason: format!("Evidence from high-reliability provider(s) (avg reliability {})", js::to_fixed(avg, 2)),
        });
    }
    if avg < 0.50 {
        return Some(ScoreExplanation {
            factor: "provider-reliability".into(),
            delta: -0.03,
            reason: format!("Evidence from low-reliability provider(s) (avg reliability {})", js::to_fixed(avg, 2)),
        });
    }
    None
}

/// Factor 9 — Request / implicated-path context.
fn factor_request_context(
    source_evidence_ids: &[String],
    graph: &InvestigationGraph,
    request: &ScoringRequest,
) -> Option<ScoreExplanation> {
    let service = request.service.as_deref().filter(|s| !s.is_empty())?;
    let service_node_id = format!("service:{service}");
    let id_set: HashSet<&str> = source_evidence_ids.iter().map(String::as_str).collect();
    let matched = graph.nodes.iter().any(|n| {
        n.id == service_node_id && n.implicated && n.evidence_ids.iter().any(|eid| id_set.contains(eid.as_str()))
    });
    if !matched {
        return None;
    }
    Some(ScoreExplanation {
        factor: "request-context".into(),
        delta: 0.04,
        reason: format!("Cause directly implicates the investigated service ({service})"),
    })
}

/// Factor 10 — Incident memory (bounded to +0.10).
fn factor_incident_history(
    source_evidence_ids: &[String],
    graph: &InvestigationGraph,
    prior_incidents: &HashMap<String, i64>,
) -> Option<ScoreExplanation> {
    if prior_incidents.is_empty() {
        return None;
    }
    let id_set: HashSet<&str> = source_evidence_ids.iter().map(String::as_str).collect();
    let code_nodes = graph.nodes.iter().filter(|n| {
        matches!(n.node_type, GraphNodeType::Symbol | GraphNodeType::File)
            && n.evidence_ids.iter().any(|eid| id_set.contains(eid.as_str()))
    });
    let mut matched: Vec<&str> = vec![];
    let mut total_prior: i64 = 0;
    for n in code_nodes {
        if let Some(&count) = prior_incidents.get(&n.id) {
            if count > 0 {
                matched.push(&n.label);
                total_prior += count;
            }
        }
    }
    if matched.is_empty() {
        return None;
    }
    // +0.04 per distinct matched code node, capped at +0.10.
    let delta = js::round_to((matched.len() as f64 * 0.04).min(0.1), 3);
    let names: Vec<&str> = matched.iter().take(3).copied().collect();
    Some(ScoreExplanation {
        factor: "incident-history".into(),
        delta,
        reason: format!(
            "Implicated code has a prior-incident history ({total_prior} prior investigation(s) on {}{})",
            names.join(", "),
            if matched.len() > 3 { ", …" } else { "" }
        ),
    })
}

/// Score a single cause candidate by applying all ten factors to its baseScore.
pub fn score_cause(input: &CauseInput, ctx: &ScoringContext) -> CauseCandidate {
    let now = ctx.now.clone().unwrap_or_else(js::iso_now);

    let id_set: HashSet<&str> = input.source_evidence_ids.iter().map(String::as_str).collect();
    let attached: Vec<&Evidence> = ctx.evidence.iter().filter(|e| id_set.contains(e.id.as_str())).collect();

    let source_impact = ctx.mode == Some(Intent::SourceImpact);
    let raw_factors = [
        factor_evidence_quality(&attached, source_impact),
        factor_source_diversity(&attached),
        factor_graph_proximity(&input.source_evidence_ids, ctx.graph),
        factor_runtime_signals(&attached, &now),
        factor_blast_radius(input.metadata.as_ref()),
        // HOR-385: drop the structural-only penalty and finding-uncertainty for a source-impact cause.
        if source_impact { None } else { factor_signal_strength(&attached) },
        if source_impact {
            None
        } else {
            factor_finding_uncertainty(&input.source_evidence_ids, ctx.findings.as_deref().unwrap_or(&[]))
        },
        ctx.provider_reliability.as_ref().and_then(|r| factor_provider_reliability(&attached, r)),
        ctx.request.as_ref().and_then(|r| factor_request_context(&input.source_evidence_ids, ctx.graph, r)),
        ctx.prior_incidents.as_ref().and_then(|p| factor_incident_history(&input.source_evidence_ids, ctx.graph, p)),
    ];

    let mut explanations: Vec<ScoreExplanation> = raw_factors.into_iter().flatten().collect();
    let total_delta = explanations.iter().fold(0.0, |sum, e| sum + e.delta);
    let mut raw_score = clamp01(input.base_score + total_delta);

    // Single-source ceiling: `highly-likely` requires multi-source confirmation.
    let distinct_sources = attached.iter().map(|e| e.source).collect::<HashSet<_>>().len();
    if distinct_sources <= 1 && raw_score > 0.84 {
        let ceiling_delta = js::round_to(0.84 - raw_score, 3);
        explanations.push(ScoreExplanation {
            factor: "single-source-ceiling".into(),
            delta: ceiling_delta,
            reason: "Highly-likely requires multi-source corroboration — capped at 0.84 (single provider)".into(),
        });
        raw_score = 0.84;
    }

    let final_score = raw_score;
    let band = get_band(final_score);

    let derived_node_ids = input
        .affected_node_ids
        .clone()
        .unwrap_or_else(|| implicated_node_ids(ctx.graph, &input.source_evidence_ids));

    CauseCandidate {
        id: input.id.clone(),
        title: input.title.clone(),
        category: input.category.clone(),
        source_evidence_ids: input.source_evidence_ids.clone(),
        affected_node_ids: derived_node_ids,
        base_score: input.base_score,
        final_score,
        confidence: final_score,
        band,
        explanations,
        metadata: input.metadata.clone(),
    }
}

/// Score and rank a set of cause inputs: at most `limit` candidates in descending
/// finalScore order, with a deterministic id-based tiebreaker.
pub fn rank_causes(inputs: &[CauseInput], ctx: &ScoringContext, limit: usize) -> Vec<CauseCandidate> {
    let mut scored: Vec<CauseCandidate> = inputs.iter().map(|i| score_cause(i, ctx)).collect();
    scored.sort_by(|a, b| match js::cmp_f64(b.final_score, a.final_score) {
        std::cmp::Ordering::Equal => js::locale_compare(&a.id, &b.id),
        o => o,
    });
    scored.truncate(limit);
    scored
}

/// Result of [`select_headline_cause`].
#[derive(Debug, Clone, PartialEq)]
pub struct HeadlineSelection {
    /// Highest-finalScore cause overall.
    pub top_cause: Option<CauseCandidate>,
    /// Highest-finalScore cause that clears ≥0.2 AND is seed-linked.
    pub top_linked_cause: Option<CauseCandidate>,
    /// The linked one if any; else the top cause iff it clears ≥0.2.
    pub headline_cause: Option<CauseCandidate>,
    pub headline_linked: bool,
}

/// SCORE-BASED headline selection (HOR-402, reorder-safe). Ties keep the FIRST
/// occurrence (strict `>`). The optional reranker may only reorder the eligible
/// set — never promote a gated-out cause and never influence `top_cause`.
pub fn select_headline_cause(
    ranked_causes: &[CauseCandidate],
    is_linked_to_seed: &dyn Fn(&[String]) -> bool,
    rerank: Option<&dyn Fn(&[CauseCandidate]) -> Vec<CauseCandidate>>,
) -> HeadlineSelection {
    let mut top_cause: Option<&CauseCandidate> = None;
    for c in ranked_causes {
        if top_cause.is_none_or(|t| c.final_score > t.final_score) {
            top_cause = Some(c);
        }
    }

    let pick_eligible = |set: &[&CauseCandidate]| -> Option<CauseCandidate> {
        if set.is_empty() {
            return None;
        }
        if let Some(rerank) = rerank {
            let owned: Vec<CauseCandidate> = set.iter().map(|c| (*c).clone()).collect();
            if let Some(top) = rerank(&owned).into_iter().find(|c| set.iter().any(|s| s.id == c.id)) {
                return Some(top);
            }
        }
        let mut best = set[0];
        for c in set {
            if c.final_score > best.final_score {
                best = c;
            }
        }
        Some(best.clone())
    };

    let linked_eligible: Vec<&CauseCandidate> = ranked_causes
        .iter()
        .filter(|c| c.final_score >= 0.2 && is_linked_to_seed(&c.source_evidence_ids))
        .collect();
    let all_eligible: Vec<&CauseCandidate> = ranked_causes.iter().filter(|c| c.final_score >= 0.2).collect();

    let top_linked_cause = pick_eligible(&linked_eligible);
    let headline_cause = top_linked_cause.clone().or_else(|| pick_eligible(&all_eligible));
    let headline_linked = headline_cause.as_ref().is_some_and(|h| is_linked_to_seed(&h.source_evidence_ids));
    HeadlineSelection { top_cause: top_cause.cloned(), top_linked_cause, headline_cause, headline_linked }
}
