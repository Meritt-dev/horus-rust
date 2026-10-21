//! HOR-14 — Deterministic evidence correlation engine.
//!
//! Organises Evidence[] into groups, cause chains, and a missing-evidence
//! checklist so the AI only has to explain — not discover — the facts. Pure.

use std::sync::LazyLock;

use horus_core::{Evidence, EvidenceKind};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::js;
use crate::types::evidence_kind_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupDimension {
    Symbol,
    File,
    Queue,
    Commit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceGroup {
    pub key: String,
    pub dimension: GroupDimension,
    pub reason: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationChain {
    pub id: String,
    pub title: String,
    pub evidence_ids: Vec<String>,
    /// 0–1 deterministic strength derived from member relevance.
    pub strength: f64,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissingEvidence {
    pub kind: String,
    pub note: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub groups: Vec<EvidenceGroup>,
    pub chains: Vec<CorrelationChain>,
    pub missing: Vec<MissingEvidence>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CorrelateOptions {
    /// HOR-406: whether the most-recent in-window change is RELEVANT to the seed.
    /// `None` ⇒ treated as relevant (legacy).
    pub recent_change_relevant: Option<bool>,
    /// HOR-410: whether the repo has any queue topology. `None` ⇒ treated as present.
    pub has_queue_topology: Option<bool>,
}

fn clamp01(n: f64) -> f64 {
    if n.is_nan() {
        return 0.0;
    }
    n.clamp(0.0, 1.0)
}

static QUEUE_EDGE_TITLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"Queue\s+"[^"]*":\s*(.+?)\s*->\s*(.+)$"#).unwrap());

/// Parse producer and worker names from `Queue "orders": OrderService -> OrderProcessor`.
pub(crate) fn parse_queue_edge_title(title: &str) -> (Option<String>, Option<String>) {
    let Some(m) = QUEUE_EDGE_TITLE.captures(title) else { return (None, None) };
    let pick = |i: usize| m.get(i).map(|g| g.as_str().trim().to_string()).filter(|s| !s.is_empty());
    (pick(1), pick(2))
}

static NON_ALNUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9]").unwrap());

/// Generate a stable, short synthetic id for a cause chain.
fn chain_id(index: usize, key: &str) -> String {
    let cleaned = NON_ALNUM.replace_all(key, "_");
    format!("chain_{index}_{}", js::slice_chars(&cleaned, 24))
}

fn build_groups(evidence: &[Evidence]) -> Vec<EvidenceGroup> {
    let mut symbol_map: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut file_map: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut queue_map: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut commit_group: Vec<String> = vec![];

    for ev in evidence {
        let links = &ev.links;
        if let Some(symbol_id) = links.symbol_id.as_deref().filter(|s| !s.is_empty()) {
            symbol_map.entry(symbol_id.to_string()).or_default().push(ev.id.clone());
        }
        if let Some(file) = links.file.as_deref().filter(|s| !s.is_empty()) {
            file_map.entry(file.to_string()).or_default().push(ev.id.clone());
        }
        if let Some(queue_name) = links.queue_name.as_deref().filter(|s| !s.is_empty()) {
            queue_map.entry(queue_name.to_string()).or_default().push(ev.id.clone());
        }
        if ev.kind == EvidenceKind::Commit || links.commit.as_deref().is_some_and(|c| !c.is_empty()) {
            commit_group.push(ev.id.clone());
        }
    }

    let mut raw: Vec<EvidenceGroup> = vec![];
    for (key, ids) in symbol_map {
        if ids.len() >= 2 {
            raw.push(EvidenceGroup {
                reason: format!("Share symbol {key}"),
                key,
                dimension: GroupDimension::Symbol,
                evidence_ids: ids,
            });
        }
    }
    for (key, ids) in file_map {
        if ids.len() >= 2 {
            raw.push(EvidenceGroup {
                reason: format!("Share file {key}"),
                key,
                dimension: GroupDimension::File,
                evidence_ids: ids,
            });
        }
    }
    for (key, ids) in queue_map {
        if ids.len() >= 2 {
            raw.push(EvidenceGroup {
                reason: format!("Share queue {key}"),
                key,
                dimension: GroupDimension::Queue,
                evidence_ids: ids,
            });
        }
    }
    if commit_group.len() >= 2 {
        raw.push(EvidenceGroup {
            key: "commit".into(),
            dimension: GroupDimension::Commit,
            reason: "Share commit change presence".into(),
            evidence_ids: commit_group,
        });
    }

    // Most evidence first, ties broken alphabetically by key (code-unit order).
    raw.sort_by(|a, b| b.evidence_ids.len().cmp(&a.evidence_ids.len()).then_with(|| a.key.cmp(&b.key)));
    raw
}

fn build_chains(evidence: &[Evidence], recent_change_relevant: bool) -> Vec<CorrelationChain> {
    let queue_edges: Vec<&Evidence> = evidence.iter().filter(|e| e.kind == EvidenceKind::QueueEdge).collect();
    let commit_evs: Vec<&Evidence> = evidence.iter().filter(|e| e.kind == EvidenceKind::Commit).collect();
    let symbol_evs: Vec<&Evidence> = evidence.iter().filter(|e| e.kind == EvidenceKind::Symbol).collect();

    let relevance_by_id: IndexMap<&str, f64> = evidence.iter().map(|e| (e.id.as_str(), e.relevance)).collect();
    let avg_relevance = |ids: &[String]| -> f64 {
        if ids.is_empty() {
            return 0.0;
        }
        let sum = ids.iter().fold(0.0, |s, id| s + relevance_by_id.get(id.as_str()).copied().unwrap_or(0.0));
        sum / ids.len() as f64
    };

    let mut chains: Vec<CorrelationChain> = vec![];

    if !queue_edges.is_empty() {
        for edge in queue_edges {
            let queue_name = edge.links.queue_name.clone().unwrap_or_else(|| "?".into());

            // Derive producer/worker from payload first, fall back to title parse.
            let mut producer: Option<String> = None;
            let mut worker: Option<String> = None;
            if let Value::Object(p) = &edge.payload {
                if let Some(s) = p.get("producerSymbol").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    producer = Some(s.to_string());
                }
                if let Some(s) = p.get("workerSymbol").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    worker = Some(s.to_string());
                }
            }
            if producer.is_none() || worker.is_none() {
                let (tp, tw) = parse_queue_edge_title(&edge.title);
                if producer.is_none() {
                    producer = Some(tp.unwrap_or_else(|| "unknown-producer".into()));
                }
                if worker.is_none() {
                    worker = Some(tw.unwrap_or_else(|| "unknown-worker".into()));
                }
            }
            let producer = producer.unwrap_or_default();
            let worker = worker.unwrap_or_default();

            let title = format!("Queue {queue_name} path: {producer} -> {worker}");

            let mut member_ids: Vec<String> = vec![edge.id.clone()];
            for c in &commit_evs {
                if !member_ids.contains(&c.id) {
                    member_ids.push(c.id.clone());
                }
            }
            if let Some(seed_ev) = symbol_evs.first() {
                if !member_ids.contains(&seed_ev.id) {
                    member_ids.push(seed_ev.id.clone());
                }
            }

            // HOR-406: only claim "a recent change is present" when it is RELEVANT to the seed.
            let has_relevant_commit = !commit_evs.is_empty() && recent_change_relevant;
            let rationale = if has_relevant_commit {
                "A recent change is present and the implicated symbol sits on this queue boundary"
            } else {
                "The implicated symbol sits on this queue boundary"
            };

            let base = avg_relevance(&member_ids);
            // +0.1 per extra linked evidence beyond the first.
            let strength = clamp01(base + 0.1 * (member_ids.len().saturating_sub(1)) as f64);

            chains.push(CorrelationChain {
                id: chain_id(chains.len(), &queue_name),
                title,
                evidence_ids: member_ids,
                strength,
                rationale: rationale.into(),
            });
        }
    } else if let (Some(first_commit), Some(first_symbol)) = (commit_evs.first(), symbol_evs.first()) {
        // HOR-406: suppress the recent-change chain when the change is NOT relevant to the seed.
        if recent_change_relevant {
            let member_ids = vec![first_commit.id.clone(), first_symbol.id.clone()];
            let base = avg_relevance(&member_ids);
            let strength = clamp01(base + 0.1 * (member_ids.len() - 1) as f64);
            chains.push(CorrelationChain {
                id: chain_id(0, "recent_change"),
                title: "Recent change to the implicated code".into(),
                evidence_ids: member_ids,
                strength,
                rationale: "A recent change to the implicated symbol may have introduced the regression".into(),
            });
        }
    }

    chains.sort_by(|a, b| js::cmp_f64(b.strength, a.strength));
    chains
}

// HOR-410: missing-evidence notes are stack-neutral — they name the `horus` command.
fn missing_note(kind: EvidenceKind) -> String {
    match kind {
        EvidenceKind::Log => "No error logs collected for this investigation — run `horus logs \"<hint>\"`".into(),
        EvidenceKind::Metric => "No metrics collected — run `horus metrics \"<hint>\"`".into(),
        EvidenceKind::QueueState => "No live queue depth/failure data — run `horus queues --live`".into(),
        EvidenceKind::RedisKey => "No cache/state evidence collected".into(),
        other => format!("No {} evidence yet", evidence_kind_name(other)),
    }
}

const RUNTIME_KINDS: [EvidenceKind; 4] =
    [EvidenceKind::Log, EvidenceKind::Metric, EvidenceKind::QueueState, EvidenceKind::RedisKey];

fn build_missing(evidence: &[Evidence], has_queue_topology: bool) -> Vec<MissingEvidence> {
    let mut missing = vec![];
    for kind in RUNTIME_KINDS {
        // Suppress the queue-state note on repos with no queue topology (HOR-410).
        if kind == EvidenceKind::QueueState && !has_queue_topology {
            continue;
        }
        if !evidence.iter().any(|e| e.kind == kind) {
            missing.push(MissingEvidence { kind: evidence_kind_name(kind).into(), note: missing_note(kind) });
        }
    }
    missing
}

pub fn correlate(evidence: &[Evidence], opts: Option<&CorrelateOptions>) -> CorrelationResult {
    // HOR-406: default to relevant when the caller does not supply a verdict.
    let recent_change_relevant = opts.and_then(|o| o.recent_change_relevant) != Some(false);
    let has_queue_topology = opts.and_then(|o| o.has_queue_topology) != Some(false);
    CorrelationResult {
        groups: build_groups(evidence),
        chains: build_chains(evidence, recent_change_relevant),
        missing: build_missing(evidence, has_queue_topology),
    }
}
