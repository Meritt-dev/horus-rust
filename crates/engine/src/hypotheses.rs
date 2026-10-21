//! HOR-24 — Deterministic competing-hypothesis generation.
//!
//! A fixed set of competing hypotheses so the investigation never anchors on a
//! single explanation. Always emitted (even unsupported), with missing evidence
//! listed. Pure apart from the UUID generator.

use horus_core::{Evidence, EvidenceKind};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::correlate::CorrelationResult;
use crate::graph::{implicated_evidence_ids_by_node_type, GraphNodeType, InvestigationGraph};
use crate::js;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hypothesis {
    pub id: String,
    pub category: String,
    pub statement: String,
    /// 0–1 prior confidence derived deterministically from available evidence.
    pub confidence: f64,
    pub supporting_evidence_ids: Vec<String>,
    pub contradicting_evidence_ids: Vec<String>,
    pub missing_evidence: Vec<String>,
}

/// Context supplied by the engine. See the TS docstrings for the per-field tickets.
#[derive(Debug, Clone, Default)]
pub struct HypothesisContext<'a> {
    /// Human-readable label for the seed symbol (e.g. "OrderService").
    pub seed_label: String,
    /// Distinct queue names that appear in the implicated queue-edge evidence.
    pub queues: Vec<String>,
    /// Metric evidence IDs with latency-spike or error-rate-change anomalies (HOR-40).
    pub latency_metric_ev_ids: Option<Vec<String>>,
    /// Per-queue runtime signal evidence IDs (HOR-45); insertion-ordered.
    pub queue_backlog_ev_ids_by_queue: Option<IndexMap<String, Vec<String>>>,
    pub queue_starvation_ev_ids_by_queue: Option<IndexMap<String, Vec<String>>>,
    pub queue_metric_ev_ids_by_queue: Option<IndexMap<String, Vec<String>>>,
    pub since_provided: Option<bool>,
    /// HOR-385: source-impact mode emits no runtime hypotheses.
    pub suppress_runtime_hypotheses: Option<bool>,
    /// HOR-406: `None` ⇒ treated as relevant.
    pub recent_change_relevant: Option<bool>,
    /// HOR-451: files-touched count of the most-focused seed-touching commit.
    pub seed_change_focus: Option<Option<i64>>,
    pub seed_change_broad: Option<bool>,
    pub vague_perf_guess: Option<bool>,
    pub graph: Option<&'a InvestigationGraph>,
    /// HOR-435 lever #2/#4.
    pub per_dimension_duration_ev_ids: Option<Vec<String>>,
    /// HOR-435 lever #3/#4.
    pub bimodal_metric_ev_ids: Option<Vec<String>>,
    /// HOR-438.
    pub per_segment_queue_structure_ev_ids: Option<Vec<String>>,
    /// HOR-435 lever #4.
    pub benign_variance_applicable: Option<bool>,
    /// HOR-435 lever #1: alert-text-suggested categories (annotation only, never a prior).
    pub alert_suggested_categories: Option<Vec<String>>,
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn dedup(ids: impl IntoIterator<Item = String>) -> Vec<String> {
    ids.into_iter().collect::<IndexSet<String>>().into_iter().collect()
}

/// `${ctx.seedChangeFocus}` — JS prints `null`/`undefined` literally.
fn focus_string(focus: Option<Option<i64>>) -> String {
    match focus {
        Some(Some(n)) => n.to_string(),
        Some(None) => "null".into(),
        None => "undefined".into(),
    }
}

/// Generate the full competing set of hypotheses, sorted by confidence descending (stable).
pub fn generate_hypotheses(
    evidence: &[Evidence],
    _correlation: &CorrelationResult,
    ctx: &HypothesisContext,
) -> Vec<Hypothesis> {
    // Per-commit timeline detail (`perCommit`) is excluded: the AGGREGATE change-range
    // evidence is the change signal.
    let commit_evs: Vec<&Evidence> = evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Commit && e.payload.get("perCommit") != Some(&Value::Bool(true)))
        .collect();
    let has_commit = !commit_evs.is_empty();
    let queues = &ctx.queues;

    // HOR-410: only name queue-runtime tooling when the repo actually has queue topology.
    let has_queue_topology = !queues.is_empty();

    // Log spikes (ratio >= 2.0): consistent with retry amplification.
    let log_spike_ev_ids: Vec<String> = evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Log && e.ratio.is_some_and(|r| r >= 2.0))
        .map(|e| e.id.clone())
        .collect();

    // DB / application-state evidence: infra-level issues rather than pure code bugs.
    let state_ev_ids: Vec<String> =
        evidence.iter().filter(|e| e.kind == EvidenceKind::State).map(|e| e.id.clone()).collect();

    let all_queue_backlog_ev_ids: Vec<String> =
        ctx.queue_backlog_ev_ids_by_queue.iter().flat_map(|m| m.values()).flatten().cloned().collect();
    let all_queue_starvation_ev_ids: Vec<String> =
        ctx.queue_starvation_ev_ids_by_queue.iter().flat_map(|m| m.values()).flatten().cloned().collect();

    // Graph-derived signals: evidence attached to implicated collection nodes.
    let graph_implicated_collection_ev_ids: Vec<String> = ctx
        .graph
        .map(|g| implicated_evidence_ids_by_node_type(g, GraphNodeType::Collection))
        .unwrap_or_default();

    let mut hyps: Vec<Hypothesis> = vec![];

    // HOR-385: source-impact mode emits none of the runtime/incident framings.
    if ctx.suppress_runtime_hypotheses == Some(true) {
        return hyps;
    }

    // a. deployment-regression — always emitted (HOR-406 / HOR-451 relevance gating).
    let has_relevant_commit = has_commit && ctx.recent_change_relevant != Some(false);
    let broad_change = has_relevant_commit && ctx.seed_change_broad == Some(true);
    let vague_guess = has_relevant_commit && !broad_change && ctx.vague_perf_guess == Some(true);
    let regression_statement = if broad_change {
        format!(
            "A broad recent change ({} files) touched {}'s file, but breadth alone is weak evidence — not clearly linked to the symptom.",
            focus_string(ctx.seed_change_focus),
            ctx.seed_label
        )
    } else if vague_guess {
        format!(
            "A recent change touching {} might relate to the performance symptom — unconfirmed structural guess (no metrics evidence, low-confidence seed).",
            ctx.seed_label
        )
    } else if has_commit && !has_relevant_commit {
        format!(
            "Changes shipped in the window but none touched {} — a deployment regression of the seed is unlikely.",
            ctx.seed_label
        )
    } else {
        format!("A recent change/deployment touching {} introduced the fault.", ctx.seed_label)
    };
    hyps.push(Hypothesis {
        id: new_id(),
        category: "deployment-regression".into(),
        statement: regression_statement,
        confidence: if broad_change {
            0.25
        } else if vague_guess {
            0.3
        } else if has_relevant_commit {
            0.5
        } else {
            0.15
        },
        supporting_evidence_ids: if has_relevant_commit && !broad_change && !vague_guess {
            commit_evs.iter().map(|e| e.id.clone()).collect()
        } else {
            vec![]
        },
        contradicting_evidence_ids: vec![],
        missing_evidence: if broad_change {
            vec!["Runtime evidence (logs/metrics) linking the broad change to the symptom — diff the change directly to narrow it".into()]
        } else if vague_guess {
            vec!["Metrics evidence for the performance symptom — without it the change link stays an unconfirmed structural guess".into()]
        } else if has_relevant_commit {
            vec![]
        } else if has_commit {
            vec![format!(
                "No in-window commit touched {} — diff the actual change range or check upstream deps/data/config",
                ctx.seed_label
            )]
        } else if ctx.since_provided == Some(true) {
            vec!["No git changes found in the specified range — verify the ref is accessible or use HEAD~N for exact commit ranges".into()]
        } else {
            vec!["A change/deployment range — re-run with --since <ref> to diff what shipped".into()]
        },
    });

    // b+c. Per-queue hypotheses — one pair (queue-backlog + worker-slowdown) per queue.
    for queue_name in queues {
        let backlog_ev_ids: Vec<String> = ctx
            .queue_backlog_ev_ids_by_queue
            .as_ref()
            .and_then(|m| m.get(queue_name))
            .cloned()
            .unwrap_or_default();
        hyps.push(Hypothesis {
            id: new_id(),
            category: "queue-backlog".into(),
            statement: format!("A backlog on {queue_name} — producers enqueue faster than the worker drains."),
            confidence: if backlog_ev_ids.is_empty() { 0.35 } else { 0.7 },
            missing_evidence: if backlog_ev_ids.is_empty() {
                vec!["Live queue depth + failed/delayed counts (`horus queues`)".into()]
            } else {
                vec![]
            },
            supporting_evidence_ids: backlog_ev_ids,
            contradicting_evidence_ids: vec![],
        });

        let metric_ev_ids: Vec<String> = ctx
            .queue_metric_ev_ids_by_queue
            .as_ref()
            .and_then(|m| m.get(queue_name))
            .cloned()
            .unwrap_or_default();
        let starvation_ev_ids: Vec<String> = ctx
            .queue_starvation_ev_ids_by_queue
            .as_ref()
            .and_then(|m| m.get(queue_name))
            .cloned()
            .unwrap_or_default();
        let slowdown_ev_ids: Vec<String> = metric_ev_ids.into_iter().chain(starvation_ev_ids).collect();
        hyps.push(Hypothesis {
            id: new_id(),
            category: "worker-slowdown".into(),
            statement: format!("The worker(s) consuming {queue_name} are processing slowly or stalling."),
            confidence: if slowdown_ev_ids.is_empty() { 0.3 } else { 0.55 },
            missing_evidence: if slowdown_ev_ids.is_empty() {
                vec!["Worker latency/throughput metrics (Grafana — `horus metrics`)".into()]
            } else {
                vec![]
            },
            supporting_evidence_ids: slowdown_ev_ids,
            contradicting_evidence_ids: vec![],
        });
    }

    // d. external-api-latency — always emitted (direct metric support only).
    let latency_metric_ev_ids: Vec<String> = ctx.latency_metric_ev_ids.clone().unwrap_or_default();
    hyps.push(Hypothesis {
        id: new_id(),
        category: "external-api-latency".into(),
        statement: "An upstream/external API the implicated code calls is slow or returning errors.".into(),
        confidence: if latency_metric_ev_ids.is_empty() { 0.2 } else { 0.55 },
        missing_evidence: if latency_metric_ev_ids.is_empty() {
            vec!["Request latency metrics + error logs (`horus metrics` / `horus logs`)".into()]
        } else {
            vec![]
        },
        supporting_evidence_ids: latency_metric_ev_ids,
        contradicting_evidence_ids: vec![],
    });

    // e. retry-storm — always emitted. Contradiction: queue starvation.
    let retry_storm_support = dedup(log_spike_ev_ids.iter().chain(all_queue_backlog_ev_ids.iter()).cloned());
    hyps.push(Hypothesis {
        id: new_id(),
        category: "retry-storm".into(),
        statement: "A retry storm is amplifying load on the failing path.".into(),
        confidence: if retry_storm_support.is_empty() { 0.15 } else { 0.35 },
        missing_evidence: if !retry_storm_support.is_empty() {
            vec![]
        } else if has_queue_topology {
            vec!["Retry/error logs + queue retry statistics (`horus logs` / `horus queues`)".into()]
        } else {
            vec!["Retry/error logs (`horus logs`)".into()]
        },
        supporting_evidence_ids: retry_storm_support,
        contradicting_evidence_ids: all_queue_starvation_ev_ids.clone(),
    });

    // f. infrastructure — always emitted.
    let infra_support = dedup(
        state_ev_ids
            .iter()
            .chain(all_queue_starvation_ev_ids.iter())
            .chain(ctx.latency_metric_ev_ids.iter().flatten())
            .chain(graph_implicated_collection_ev_ids.iter())
            .cloned(),
    );
    hyps.push(Hypothesis {
        id: new_id(),
        category: "infrastructure".into(),
        statement: "An infrastructure issue (database, cache, or network) is degrading processing.".into(),
        confidence: if infra_support.is_empty() { 0.15 } else { 0.35 },
        missing_evidence: if infra_support.is_empty() {
            vec!["Infrastructure metrics + datastore/cache state (`horus metrics`)".into()]
        } else {
            vec![]
        },
        supporting_evidence_ids: infra_support,
        contradicting_evidence_ids: vec![],
    });

    // g. benign-variance (HOR-435 lever #4): low prior, rises only with real evidence.
    let benign_support = dedup(
        ctx.per_dimension_duration_ev_ids
            .iter()
            .flatten()
            .chain(ctx.bimodal_metric_ev_ids.iter().flatten())
            .chain(ctx.per_segment_queue_structure_ev_ids.iter().flatten())
            .cloned(),
    );
    // A segmented metric distribution cannot explain away directly relevant runtime errors.
    let direct_failures: Vec<String> = evidence
        .iter()
        .filter(|e| {
            e.kind == EvidenceKind::Log
                && e.payload.get("relevanceClass").and_then(Value::as_str) == Some("direct")
                && matches!(
                    e.payload.get("level").and_then(Value::as_str).unwrap_or(""),
                    "error" | "fatal" | "critical"
                )
        })
        .map(|e| e.id.clone())
        .collect();
    if !benign_support.is_empty() || ctx.benign_variance_applicable == Some(true) {
        hyps.push(Hypothesis {
            id: new_id(),
            category: "benign-variance".into(),
            statement: "The anomaly may reflect expected per-segment/per-region variance (or a skewed average), not a failure.".into(),
            confidence: 0.1,
            missing_evidence: if benign_support.is_empty() {
                vec!["Per-segment duration breakdown (region/market/tenant) or a bimodal metric distribution (`horus logs` / `horus metrics`)".into()]
            } else {
                vec![]
            },
            supporting_evidence_ids: benign_support,
            contradicting_evidence_ids: direct_failures,
        });
    }

    // HOR-435 lever #1: alert text is CONTEXT-ONLY — annotate, never raise a prior.
    if let Some(suggested) = ctx.alert_suggested_categories.as_ref().filter(|s| !s.is_empty()) {
        for h in &mut hyps {
            if suggested.contains(&h.category) && h.supporting_evidence_ids.is_empty() {
                h.missing_evidence.push(
                    "Suggested by the alert/hint text — confidence requires independent evidence, not the alert wording itself".into(),
                );
            }
        }
    }

    hyps.sort_by(|a, b| js::cmp_f64(b.confidence, a.confidence));
    hyps
}
