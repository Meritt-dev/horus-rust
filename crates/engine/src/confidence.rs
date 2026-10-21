//! Weighted evidence confidence calculation (HOR-45). Pure.

use std::collections::HashSet;

use horus_core::{Evidence, EvidenceKind, ProviderKind};
use indexmap::IndexMap;

fn is_runtime_kind(k: EvidenceKind) -> bool {
    matches!(
        k,
        EvidenceKind::Log
            | EvidenceKind::Metric
            | EvidenceKind::Commit
            | EvidenceKind::QueueState
            | EvidenceKind::RedisKey
            | EvidenceKind::State
    )
}

// Runtime sources carry direct live observations — up to 2.0 each before the cap.
const MAX_RUNTIME_CONTRIBUTION: f64 = 2.0;
// Structural sources provide supporting context, not live confirmation.
const MAX_STRUCTURAL_CONTRIBUTION: f64 = 0.6;
// Ambient runtime evidence (runtime kind but not linked to the seed — HOR-156/158).
const MAX_AMBIENT_RUNTIME_CONTRIBUTION: f64 = 0.6;
// 3 independent high-quality runtime sources at max contribution → 1.0.
const NORMALIZATION: f64 = 6.0;

fn clamp01(n: f64) -> f64 {
    if n.is_nan() {
        return 0.0;
    }
    n.clamp(0.0, 1.0)
}

/// Compute an evidence-quality confidence value (0–1) for a set of evidence.
///
/// Each item contributes `clamp01(relevance) × (1.5 if runtime, else 0.5)`, grouped
/// by source; runtime sources cap at 2.0, structural (and ambient runtime) at 0.6.
pub fn compute_weighted_evidence_confidence(
    evidence: &[Evidence],
    ambient_evidence_ids: Option<&HashSet<String>>,
) -> f64 {
    let mut runtime_by_source: IndexMap<ProviderKind, f64> = IndexMap::new();
    let mut ambient_by_source: IndexMap<ProviderKind, f64> = IndexMap::new();
    let mut structural_by_source: IndexMap<ProviderKind, f64> = IndexMap::new();

    for e in evidence {
        let r = clamp01(e.relevance);
        if is_runtime_kind(e.kind) {
            if ambient_evidence_ids.is_some_and(|s| s.contains(&e.id)) {
                *ambient_by_source.entry(e.source).or_insert(0.0) += 0.5 * r;
            } else {
                *runtime_by_source.entry(e.source).or_insert(0.0) += 1.5 * r;
            }
        } else {
            *structural_by_source.entry(e.source).or_insert(0.0) += 0.5 * r;
        }
    }

    let runtime_sum = runtime_by_source.values().fold(0.0, |acc, w| acc + w.min(MAX_RUNTIME_CONTRIBUTION));
    let ambient_sum = ambient_by_source.values().fold(0.0, |acc, w| acc + w.min(MAX_AMBIENT_RUNTIME_CONTRIBUTION));
    let structural_sum =
        structural_by_source.values().fold(0.0, |acc, w| acc + w.min(MAX_STRUCTURAL_CONTRIBUTION));

    clamp01((runtime_sum + ambient_sum + structural_sum) / NORMALIZATION)
}
