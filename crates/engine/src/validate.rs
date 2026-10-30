//! HOR-25 — Deterministic hypothesis validation. Pure.

use std::collections::HashSet;

use horus_core::Evidence;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::hypotheses::Hypothesis;
use crate::js;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Supported,
    Unconfirmed,
    Weakened,
    Eliminated,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Supported => "supported",
            Verdict::Unconfirmed => "unconfirmed",
            Verdict::Weakened => "weakened",
            Verdict::Eliminated => "eliminated",
        }
    }
}

/// `Hypothesis` fields (flattened, in TS order) plus the validation outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedHypothesis {
    pub id: String,
    pub category: String,
    pub statement: String,
    pub confidence: f64,
    pub supporting_evidence_ids: Vec<String>,
    pub contradicting_evidence_ids: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub prior_confidence: f64,
    pub verdict: Verdict,
    pub supporting_present: i64,
    pub contradicting_present: i64,
    pub rationale: String,
}

fn clamp01(n: f64) -> f64 {
    if n.is_nan() {
        return 0.0;
    }
    n.clamp(0.0, 1.0)
}

/// Confidence gained from `n` supporting items: +0.15 for the first, each further item
/// worth 60% of the one before (0.15, 0.24, 0.29, 0.33 … never above 0.375). More of the
/// same kind of evidence corroborates less each time, so volume alone can't reach certainty.
fn support_gain(n: i64) -> f64 {
    0.15 * (1.0 - 0.6f64.powi(n.max(0) as i32)) / 0.4
}

/// Validate hypotheses against the available evidence. Sorted by adjusted confidence
/// descending, with 'eliminated' verdicts pushed to the end.
pub fn validate_hypotheses(hyps: &[Hypothesis], evidence: &[Evidence]) -> Vec<ValidatedHypothesis> {
    let present: HashSet<&str> = evidence.iter().map(|e| e.id.as_str()).collect();

    let mut validated: Vec<ValidatedHypothesis> = hyps
        .iter()
        .map(|h| {
            let supporting_present =
                h.supporting_evidence_ids.iter().filter(|id| present.contains(id.as_str())).count() as i64;
            let contradicting_present =
                h.contradicting_evidence_ids.iter().filter(|id| present.contains(id.as_str())).count() as i64;

            let mut confidence =
                clamp01(h.confidence + support_gain(supporting_present) - 0.3 * contradicting_present as f64);

            // Many correlated metric series must not outvote a directly observed failure.
            if h.category == "benign-variance" && contradicting_present > 0 {
                confidence = confidence.min(0.1);
            }

            let verdict = if contradicting_present > 0 && confidence < 0.1 {
                Verdict::Eliminated
            } else if contradicting_present > 0 {
                Verdict::Weakened
            } else if supporting_present > 0 {
                Verdict::Supported
            } else {
                Verdict::Unconfirmed
            };

            let awaiting_clause = match (verdict, h.missing_evidence.first()) {
                (Verdict::Unconfirmed, Some(first)) => format!("; awaiting {first}"),
                _ => String::new(),
            };
            let rationale = format!(
                "{supporting_present} supporting / {contradicting_present} contradicting evidence present{awaiting_clause}."
            );

            ValidatedHypothesis {
                id: h.id.clone(),
                category: h.category.clone(),
                statement: h.statement.clone(),
                confidence,
                supporting_evidence_ids: h.supporting_evidence_ids.clone(),
                contradicting_evidence_ids: h.contradicting_evidence_ids.clone(),
                missing_evidence: h.missing_evidence.clone(),
                prior_confidence: h.confidence,
                verdict,
                supporting_present,
                contradicting_present,
                rationale,
            }
        })
        .collect();

    // HOR-435 lever #5: hypotheses sharing an IDENTICAL, NON-EMPTY set of PRESENT
    // supporting evidence (and no contradiction) are correlated red herrings — cap the cohort.
    const SHARED_EVIDENCE_CEILING: f64 = 0.75;
    let mut by_support: IndexMap<String, Vec<usize>> = IndexMap::new();
    for (i, v) in validated.iter().enumerate() {
        if v.contradicting_present > 0 {
            continue;
        }
        let mut present_support: Vec<&str> = v
            .supporting_evidence_ids
            .iter()
            .map(String::as_str)
            .filter(|id| present.contains(id))
            .collect();
        present_support.sort();
        if present_support.is_empty() {
            continue;
        }
        by_support.entry(present_support.join("|")).or_default().push(i);
    }
    for cohort in by_support.values() {
        if cohort.len() < 2 {
            continue;
        }
        for &i in cohort {
            let v = &mut validated[i];
            if v.confidence > SHARED_EVIDENCE_CEILING {
                v.confidence = SHARED_EVIDENCE_CEILING;
                let base = v.rationale.strip_suffix('.').unwrap_or(&v.rationale).to_string();
                v.rationale = format!(
                    "{base}; capped at {} — shares all supporting evidence with {} other hypothesis(es) and nothing distinguishes them.",
                    js::number_string(SHARED_EVIDENCE_CEILING),
                    cohort.len() - 1
                );
            }
        }
    }

    validated.sort_by(|a, b| {
        let a_elim = (a.verdict == Verdict::Eliminated) as i32;
        let b_elim = (b.verdict == Verdict::Eliminated) as i32;
        a_elim.cmp(&b_elim).then_with(|| js::cmp_f64(b.confidence, a.confidence))
    });
    validated
}
