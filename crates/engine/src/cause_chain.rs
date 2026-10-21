//! HOR-196 — Deterministic cause-chain construction.
//!
//! Ordered causal chains (trigger → propagation → symptom [→ impact]) from
//! validated hypotheses and the evidence graph. Pure and synchronous.

use std::sync::LazyLock;

use horus_core::{Evidence, EvidenceKind};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::graph::{GraphNodeType, InvestigationGraph};
use crate::js;
use crate::validate::{ValidatedHypothesis, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CauseChainStepRole {
    Trigger,
    Propagation,
    Symptom,
    Impact,
}

impl CauseChainStepRole {
    pub fn as_str(self) -> &'static str {
        match self {
            CauseChainStepRole::Trigger => "trigger",
            CauseChainStepRole::Propagation => "propagation",
            CauseChainStepRole::Symptom => "symptom",
            CauseChainStepRole::Impact => "impact",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CauseChainStep {
    pub role: CauseChainStepRole,
    pub label: String,
    pub evidence_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CauseChain {
    pub hypothesis_id: String,
    pub category: String,
    /// Adjusted confidence from the validated hypothesis.
    pub confidence: f64,
    pub steps: Vec<CauseChainStep>,
    /// One-line causal narrative summarising the full chain.
    pub summary: String,
}

type EvidenceByKind<'a> = IndexMap<EvidenceKind, Vec<&'a Evidence>>;

fn group_by_kind<'a>(ids: &[String], ev_by_id: &IndexMap<&str, &'a Evidence>) -> EvidenceByKind<'a> {
    let mut map: EvidenceByKind<'a> = IndexMap::new();
    for id in ids {
        if let Some(ev) = ev_by_id.get(id.as_str()) {
            map.entry(ev.kind).or_default().push(ev);
        }
    }
    map
}

fn of<'a>(by_kind: &'a EvidenceByKind<'a>, kind: EvidenceKind) -> &'a [&'a Evidence] {
    by_kind.get(&kind).map(Vec::as_slice).unwrap_or(&[])
}

fn ids(evs: &[&Evidence]) -> Vec<String> {
    evs.iter().map(|e| e.id.clone()).collect()
}

fn first_implicated_node(graph: &InvestigationGraph, node_type: GraphNodeType) -> Option<String> {
    graph.nodes.iter().find(|n| n.node_type == node_type && n.implicated).map(|n| n.id.clone())
}

fn first_node_of_type(graph: &InvestigationGraph, node_type: GraphNodeType) -> Option<String> {
    graph.nodes.iter().find(|n| n.node_type == node_type).map(|n| n.id.clone())
}

fn queue_node_id(graph: &InvestigationGraph, queue_name: Option<&str>) -> Option<String> {
    match queue_name {
        Some(q) => {
            let id = format!("queue:{q}");
            graph.nodes.iter().find(|n| n.id == id).map(|n| n.id.clone())
        }
        None => first_implicated_node(graph, GraphNodeType::Queue),
    }
}

fn finish(hyp: &ValidatedHypothesis, steps: Vec<CauseChainStep>, summary: String) -> CauseChain {
    CauseChain {
        hypothesis_id: hyp.id.clone(),
        category: hyp.category.clone(),
        confidence: hyp.confidence,
        steps,
        summary,
    }
}

/// `${payload.affected ?? '?'}` for a JSON value.
fn affected_string(ev: &Evidence) -> String {
    match ev.payload.get("affected") {
        None | Some(Value::Null) => "?".into(),
        Some(Value::Number(n)) => n.as_f64().map(js::number_string).unwrap_or_else(|| n.to_string()),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn chain_for_deployment_regression(
    hyp: &ValidatedHypothesis,
    by_kind: &EvidenceByKind,
    graph: &InvestigationGraph,
    seed_label: &str,
) -> CauseChain {
    let commit_evs = of(by_kind, EvidenceKind::Commit);
    let symbol_evs = of(by_kind, EvidenceKind::Symbol);
    let log_evs = of(by_kind, EvidenceKind::Log);
    let metric_evs = of(by_kind, EvidenceKind::Metric);
    let impact_evs = of(by_kind, EvidenceKind::Impact);

    let runtime_ev_ids: Vec<String> = ids(log_evs).into_iter().chain(ids(metric_evs)).collect();
    let mut steps = vec![];

    steps.push(CauseChainStep {
        role: CauseChainStepRole::Trigger,
        label: match commit_evs.first() {
            Some(c) => format!("Recent change: {}", c.title),
            None => "Recent change (commit range not captured)".into(),
        },
        evidence_ids: ids(commit_evs),
        graph_node_id: first_node_of_type(graph, GraphNodeType::Deployment),
    });

    steps.push(CauseChainStep {
        role: CauseChainStepRole::Propagation,
        label: format!(
            "Affected code path: {seed_label}{}",
            match impact_evs.first() {
                Some(i) => format!(" ({} downstream symbol(s))", affected_string(i)),
                None => String::new(),
            }
        ),
        evidence_ids: ids(symbol_evs).into_iter().chain(ids(impact_evs)).collect(),
        graph_node_id: first_node_of_type(graph, GraphNodeType::Symbol),
    });

    if !runtime_ev_ids.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Symptom,
            label: if !log_evs.is_empty() {
                format!("Runtime error signatures observed ({} signature(s))", log_evs.len())
            } else {
                format!("Metric anomalies observed ({} signal(s))", metric_evs.len())
            },
            evidence_ids: runtime_ev_ids.clone(),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Service),
        });
    }

    let non_empty: Vec<CauseChainStep> = steps
        .into_iter()
        .filter(|s| !s.evidence_ids.is_empty() || s.role == CauseChainStepRole::Trigger)
        .collect();
    let summary = format!(
        "Change to {seed_label} → affected code path{}",
        if !runtime_ev_ids.is_empty() { " → runtime symptoms observed" } else { "" }
    );
    finish(hyp, non_empty, summary)
}

fn chain_for_queue_backlog(
    hyp: &ValidatedHypothesis,
    by_kind: &EvidenceByKind,
    graph: &InvestigationGraph,
    queue_name: Option<&str>,
) -> CauseChain {
    let queue_edge_evs = of(by_kind, EvidenceKind::QueueEdge);
    let queue_state_evs = of(by_kind, EvidenceKind::QueueState);
    let log_evs = of(by_kind, EvidenceKind::Log);
    let metric_evs = of(by_kind, EvidenceKind::Metric);

    let queue_node = queue_node_id(graph, queue_name);
    let mut steps = vec![];

    steps.push(CauseChainStep {
        role: CauseChainStepRole::Trigger,
        label: match queue_name {
            Some(q) => format!("Producer enqueuing to \"{q}\" faster than consumer drains"),
            None => "Producer enqueuing faster than consumer drains".into(),
        },
        evidence_ids: ids(queue_edge_evs),
        graph_node_id: queue_node.clone(),
    });

    if !queue_state_evs.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Propagation,
            label: format!("Queue depth growing{}", queue_name.map(|q| format!(" on \"{q}\"")).unwrap_or_default()),
            evidence_ids: ids(queue_state_evs),
            graph_node_id: queue_node.clone(),
        });
    }

    let symptom_ev_ids: Vec<String> = ids(log_evs).into_iter().chain(ids(metric_evs)).collect();
    if !symptom_ev_ids.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Symptom,
            label: "Worker throughput degraded — downstream delays observable".into(),
            evidence_ids: symptom_ev_ids.clone(),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Worker)
                .or_else(|| first_implicated_node(graph, GraphNodeType::Service)),
        });
    }

    let summary = format!(
        "{} backed up — producers outpacing consumers{}",
        queue_name.map(|q| format!("\"{q}\" queue")).unwrap_or_else(|| "Queue".into()),
        if !symptom_ev_ids.is_empty() { " → downstream delays" } else { "" }
    );
    finish(hyp, steps, summary)
}

fn chain_for_worker_slowdown(
    hyp: &ValidatedHypothesis,
    by_kind: &EvidenceByKind,
    graph: &InvestigationGraph,
    queue_name: Option<&str>,
) -> CauseChain {
    let queue_state_evs = of(by_kind, EvidenceKind::QueueState);
    let metric_evs = of(by_kind, EvidenceKind::Metric);
    let log_evs = of(by_kind, EvidenceKind::Log);

    let worker_node = first_implicated_node(graph, GraphNodeType::Worker);
    let queue_node = queue_node_id(graph, queue_name);
    let mut steps = vec![];

    let stalled: Vec<&Evidence> = queue_state_evs
        .iter()
        .copied()
        .filter(|e| {
            e.payload.get("isPaused") == Some(&Value::Bool(true))
                || e.payload.get("active").and_then(Value::as_f64) == Some(0.0)
        })
        .collect();
    let trigger_ev_ids: Vec<String> = ids(&stalled).into_iter().chain(ids(metric_evs)).collect();

    steps.push(CauseChainStep {
        role: CauseChainStepRole::Trigger,
        label: match queue_name {
            Some(q) => format!("Workers consuming \"{q}\" stalled or processing slowly"),
            None => "Workers stalled or processing slowly".into(),
        },
        evidence_ids: if trigger_ev_ids.is_empty() { ids(queue_state_evs) } else { trigger_ev_ids },
        graph_node_id: worker_node,
    });

    if !queue_state_evs.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Propagation,
            label: format!(
                "Queue depth accumulating{}",
                queue_name.map(|q| format!(" on \"{q}\"")).unwrap_or_default()
            ),
            evidence_ids: ids(queue_state_evs),
            graph_node_id: queue_node,
        });
    }

    if !log_evs.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Symptom,
            label: "Downstream latency and error signatures observed".into(),
            evidence_ids: ids(log_evs),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Service),
        });
    }

    let summary = format!(
        "Worker stall on {} → queue depth growing{}",
        queue_name.map(|q| format!("\"{q}\"")).unwrap_or_else(|| "queue".into()),
        if !log_evs.is_empty() { " → downstream errors" } else { "" }
    );
    finish(hyp, steps, summary)
}

fn chain_for_external_api_latency(
    hyp: &ValidatedHypothesis,
    by_kind: &EvidenceByKind,
    graph: &InvestigationGraph,
) -> CauseChain {
    let metric_evs = of(by_kind, EvidenceKind::Metric);
    let log_evs = of(by_kind, EvidenceKind::Log);
    let queue_state_evs = of(by_kind, EvidenceKind::QueueState);
    let mut steps = vec![];

    steps.push(CauseChainStep {
        role: CauseChainStepRole::Trigger,
        label: format!("External or upstream dependency latency spike ({} metric signal(s))", metric_evs.len()),
        evidence_ids: ids(metric_evs),
        graph_node_id: first_implicated_node(graph, GraphNodeType::Service),
    });

    if !log_evs.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Propagation,
            label: "Calls to upstream timing out or returning errors".into(),
            evidence_ids: ids(log_evs),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Service),
        });
    }

    if !queue_state_evs.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Symptom,
            label: "Queue backlog accumulating from stalled downstream workers".into(),
            evidence_ids: ids(queue_state_evs),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Queue),
        });
    }

    let summary = format!(
        "External API latency spike{}{}",
        if !log_evs.is_empty() { " → timeout errors propagating" } else { "" },
        if !queue_state_evs.is_empty() { " → queue backlog" } else { "" }
    );
    finish(hyp, steps, summary)
}

fn chain_for_infrastructure(
    hyp: &ValidatedHypothesis,
    by_kind: &EvidenceByKind,
    graph: &InvestigationGraph,
) -> CauseChain {
    let state_evs = of(by_kind, EvidenceKind::State);
    let queue_state_evs = of(by_kind, EvidenceKind::QueueState);
    let log_evs = of(by_kind, EvidenceKind::Log);
    let metric_evs = of(by_kind, EvidenceKind::Metric);

    let trigger_ev_ids: Vec<String> = ids(state_evs).into_iter().chain(ids(metric_evs)).collect();
    let propagation_ev_ids = ids(queue_state_evs);
    let symptom_ev_ids = ids(log_evs);
    let mut steps = vec![];

    steps.push(CauseChainStep {
        role: CauseChainStepRole::Trigger,
        label: "Infrastructure component degraded (database, network, or cache)".into(),
        evidence_ids: if trigger_ev_ids.is_empty() { ids(queue_state_evs) } else { trigger_ev_ids },
        graph_node_id: first_implicated_node(graph, GraphNodeType::Collection)
            .or_else(|| first_implicated_node(graph, GraphNodeType::Database))
            .or_else(|| first_implicated_node(graph, GraphNodeType::Queue)),
    });

    if !propagation_ev_ids.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Propagation,
            label: "Dependent services / workers lost access to the degraded component".into(),
            evidence_ids: propagation_ev_ids,
            graph_node_id: first_implicated_node(graph, GraphNodeType::Worker)
                .or_else(|| first_implicated_node(graph, GraphNodeType::Service)),
        });
    }

    if !symptom_ev_ids.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Symptom,
            label: "Processing failures and error signatures observed".into(),
            evidence_ids: symptom_ev_ids.clone(),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Service),
        });
    }

    let summary = format!(
        "Infrastructure degradation → services/workers affected{}",
        if !symptom_ev_ids.is_empty() { " → processing failures" } else { "" }
    );
    finish(hyp, steps, summary)
}

fn chain_for_retry_storm(
    hyp: &ValidatedHypothesis,
    by_kind: &EvidenceByKind,
    graph: &InvestigationGraph,
) -> CauseChain {
    let log_evs = of(by_kind, EvidenceKind::Log);
    let queue_state_evs = of(by_kind, EvidenceKind::QueueState);
    let metric_evs = of(by_kind, EvidenceKind::Metric);
    let mut steps = vec![];

    steps.push(CauseChainStep {
        role: CauseChainStepRole::Trigger,
        label: format!(
            "Initial failure with automatic retry enabled ({} log signature(s) spiking)",
            log_evs.len()
        ),
        evidence_ids: ids(log_evs),
        graph_node_id: first_implicated_node(graph, GraphNodeType::Service),
    });

    if !queue_state_evs.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Propagation,
            label: "Retry amplification growing queue depth and error volume".into(),
            evidence_ids: ids(queue_state_evs),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Queue),
        });
    }

    if !metric_evs.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Symptom,
            label: "Cascading load visible in metric anomalies".into(),
            evidence_ids: ids(metric_evs),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Service),
        });
    }

    let summary = format!(
        "Initial failure + retry → amplified load{}",
        if !metric_evs.is_empty() { " → cascading metric anomalies" } else { "" }
    );
    finish(hyp, steps, summary)
}

fn chain_generic(hyp: &ValidatedHypothesis, by_kind: &EvidenceByKind, graph: &InvestigationGraph) -> CauseChain {
    // Fallback: group all supporting evidence into trigger + symptom.
    let log_or_metric: Vec<&Evidence> =
        of(by_kind, EvidenceKind::Log).iter().chain(of(by_kind, EvidenceKind::Metric).iter()).copied().collect();

    let mut steps = vec![CauseChainStep {
        role: CauseChainStepRole::Trigger,
        label: hyp.statement.clone(),
        evidence_ids: hyp.supporting_evidence_ids.clone(),
        graph_node_id: first_implicated_node(graph, GraphNodeType::Service)
            .or_else(|| first_implicated_node(graph, GraphNodeType::Queue)),
    }];

    if !log_or_metric.is_empty() {
        steps.push(CauseChainStep {
            role: CauseChainStepRole::Symptom,
            label: "Observable symptoms in logs / metrics".into(),
            evidence_ids: ids(&log_or_metric),
            graph_node_id: first_implicated_node(graph, GraphNodeType::Service),
        });
    }

    finish(hyp, steps, hyp.statement.clone())
}

static ON_QUEUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u:\b)on ([a-zA-Z0-9_-]+)").unwrap());
static CONSUMING_QUEUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"consuming ([a-zA-Z0-9_-]+)").unwrap());

/// Extract the queue name from a hypothesis statement like
/// "A backlog on payments — producers enqueue faster than the worker drains."
fn extract_queue_name(statement: &str) -> Option<String> {
    ON_QUEUE
        .captures(statement)
        .or_else(|| CONSUMING_QUEUE.captures(statement))
        .and_then(|m| m.get(1))
        .map(|g| g.as_str().to_string())
}

/// Build causal chains for all `supported` and `weakened` hypotheses.
pub fn build_cause_chains(
    hypotheses: &[ValidatedHypothesis],
    evidence: &[Evidence],
    graph: &InvestigationGraph,
    seed_label: &str,
) -> Vec<CauseChain> {
    let ev_by_id: IndexMap<&str, &Evidence> = evidence.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut chains = vec![];

    for hyp in hypotheses {
        if hyp.verdict != Verdict::Supported && hyp.verdict != Verdict::Weakened {
            continue;
        }
        let by_kind = group_by_kind(&hyp.supporting_evidence_ids, &ev_by_id);

        let chain = match hyp.category.as_str() {
            "deployment-regression" => chain_for_deployment_regression(hyp, &by_kind, graph, seed_label),
            "queue-backlog" => {
                let q = extract_queue_name(&hyp.statement);
                chain_for_queue_backlog(hyp, &by_kind, graph, q.as_deref())
            }
            "worker-slowdown" => {
                let q = extract_queue_name(&hyp.statement);
                chain_for_worker_slowdown(hyp, &by_kind, graph, q.as_deref())
            }
            "external-api-latency" => chain_for_external_api_latency(hyp, &by_kind, graph),
            "infrastructure" => chain_for_infrastructure(hyp, &by_kind, graph),
            "retry-storm" => chain_for_retry_storm(hyp, &by_kind, graph),
            _ => chain_generic(hyp, &by_kind, graph),
        };
        chains.push(chain);
    }
    chains
}
