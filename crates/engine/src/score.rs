//! HOR-27 — Investigation quality scoring. Measures Horus's investigation
//! quality, NOT the engineers being investigated.

use serde::{Deserialize, Serialize};

use crate::js;
use crate::types::InvestigationReport;
use crate::validate::Verdict;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreComponent {
    pub dimension: String,
    pub value: f64,
    pub weight: f64,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityScore {
    pub score: f64,
    pub grade: String,
    pub components: Vec<ScoreComponent>,
    pub summary: String,
}

fn to_grade(score: f64) -> &'static str {
    if score >= 85.0 {
        "A"
    } else if score >= 70.0 {
        "B"
    } else if score >= 55.0 {
        "C"
    } else if score >= 40.0 {
        "D"
    } else {
        "F"
    }
}

pub fn score_investigation(r: &InvestigationReport) -> QualityScore {
    // 1. Evidence support
    let evidence_value = (r.evidence.len() as f64 / 8.0).min(1.0);

    // 2. Hypothesis discrimination
    let total = r.hypotheses.len();
    let resolved = r.hypotheses.iter().filter(|h| h.verdict != Verdict::Unconfirmed).count();
    let discrimination_value = if total > 0 { resolved as f64 / total as f64 } else { 0.0 };

    // 3. Diagnostic calibration (dogfood #5): the report's CALIBRATED confidence, so an
    // honest "no dominant cause" run is not punished and a confident-but-wrong one not rewarded.
    let root_cause_value = r.confidence;

    // 4. Evidence completeness
    let completeness_value = 1.0 - (r.gap_analysis.gaps.len() as f64 / 6.0).min(1.0);

    // 5. Actionability
    let actionability_value = if !r.next_actions.is_empty() { 1.0 } else { 0.0 };

    let components = vec![
        ScoreComponent {
            dimension: "evidence support".into(),
            value: evidence_value,
            weight: 0.2,
            note: "how much evidence was gathered".into(),
        },
        ScoreComponent {
            dimension: "hypothesis discrimination".into(),
            value: discrimination_value,
            weight: 0.25,
            note: "fraction of hypotheses ruled in or out (vs left unconfirmed)".into(),
        },
        ScoreComponent {
            dimension: "diagnostic calibration".into(),
            value: root_cause_value,
            weight: 0.25,
            note: "calibrated confidence in the diagnosis — a seed-linked cause scores high; honest uncertainty is not punished".into(),
        },
        ScoreComponent {
            dimension: "evidence completeness".into(),
            value: completeness_value,
            weight: 0.2,
            note: "share of the needed evidence dimensions that were available".into(),
        },
        ScoreComponent {
            dimension: "actionability".into(),
            value: actionability_value,
            weight: 0.1,
            note: "produced concrete next actions".into(),
        },
    ];

    let score = js::math_round(100.0 * components.iter().fold(0.0, |acc, c| acc + c.value * c.weight));
    let grade = to_grade(score).to_string();

    // The component with the lowest value is the biggest improvement lever.
    let mut lowest = &components[0];
    for c in &components {
        if c.value < lowest.value {
            lowest = c;
        }
    }

    let summary = format!(
        "Quality {}/100 ({}). Biggest lever: {} — {}. Measures Horus's investigation, not engineers.",
        js::int_string(score),
        grade,
        lowest.dimension,
        lowest.note
    );

    QualityScore { score, grade, components, summary }
}
