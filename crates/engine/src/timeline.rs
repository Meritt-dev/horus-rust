//! HOR-7 — Deterministic timeline reconstruction layer.
//! Input: Evidence[]. Output: ordered TimelineEvents + queue boundary crossings.

use horus_core::{Evidence, EvidenceKind};
use serde::{Deserialize, Serialize};

use crate::correlate::parse_queue_edge_title;
use crate::js;
use crate::types::evidence_kind_name;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub order: i64,
    /// Always serialized (`null` when untimed).
    pub at: Option<String>,
    pub kind: String,
    pub title: String,
    pub evidence_ids: Vec<String>,
    pub boundary_crossing: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryCrossing {
    pub queue_name: String,
    pub producer: Option<String>,
    pub worker: Option<String>,
    pub evidence_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    pub events: Vec<TimelineEvent>,
    pub boundary_crossings: Vec<BoundaryCrossing>,
}

/// Priority for untimed evidence kinds; lower = earlier in the untimed block.
fn untimed_priority(kind: EvidenceKind) -> i32 {
    match kind {
        EvidenceKind::Symbol => 0,
        EvidenceKind::Flow => 1,
        EvidenceKind::QueueEdge => 2,
        EvidenceKind::Impact => 3,
        _ => 4,
    }
}

/// Guard Date.parse against NaN.
fn safe_parse(ts: &str) -> f64 {
    let n = js::date_parse(ts);
    if n.is_nan() { 0.0 } else { n }
}

pub fn build_timeline(evidence: &[Evidence]) -> Timeline {
    let mut timed: Vec<&Evidence> = vec![];
    let mut untimed: Vec<&Evidence> = vec![];
    for e in evidence {
        match e.timestamp.as_deref() {
            Some(ts) if !ts.is_empty() => timed.push(e),
            _ => untimed.push(e),
        }
    }

    // Stable sorts preserve input order for ties.
    timed.sort_by(|a, b| {
        js::cmp_f64(safe_parse(a.timestamp.as_deref().unwrap_or("")), safe_parse(b.timestamp.as_deref().unwrap_or("")))
    });
    untimed.sort_by_key(|e| untimed_priority(e.kind));

    let events: Vec<TimelineEvent> = timed
        .iter()
        .chain(untimed.iter())
        .enumerate()
        .map(|(i, e)| TimelineEvent {
            order: i as i64 + 1,
            at: e.timestamp.clone(),
            kind: evidence_kind_name(e.kind).into(),
            title: e.title.clone(),
            evidence_ids: vec![e.id.clone()],
            boundary_crossing: e.kind == EvidenceKind::QueueEdge,
        })
        .collect();

    let boundary_crossings: Vec<BoundaryCrossing> = evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::QueueEdge)
        .map(|e| {
            let (producer, worker) = parse_queue_edge_title(&e.title);
            BoundaryCrossing {
                queue_name: e.links.queue_name.clone().unwrap_or_default(),
                producer,
                worker,
                evidence_id: e.id.clone(),
            }
        })
        .collect();

    Timeline { events, boundary_crossings }
}
