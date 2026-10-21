//! HOR-204 — Deterministic investigation Q&A.
//!
//! Answers common follow-up questions directly from a persisted InvestigationReport,
//! without re-querying any connector or invoking an LLM. Unrecognised text → `None`.

use std::sync::LazyLock;

use horus_core::Evidence;
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::js;
use crate::types::evidence_kind_name;
use crate::types::InvestigationReport;
use crate::validate::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QAKind {
    Contradicts,
    MissingEvidence,
    Confidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QAAnswer {
    pub question: String,
    pub kind: QAKind,
    /// One-line direct answer.
    pub headline: String,
    /// Supporting detail lines.
    pub details: Vec<String>,
    /// Evidence items that back the answer.
    pub evidence: Vec<Evidence>,
}

static CONTRADICTS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)(contradict|contradicts|argues?\s+against|evidence\s+against|rule\s+out|disprove|refute|weaken)(?-u:\b)").unwrap()
});
static MISSING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)(missing|absent|gaps?|don'?t\s+have|do\s+not\s+have|lack(?:ing)?|what\s+else)(?-u:\b)").unwrap()
});
static CONFIDENCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)(confidence|confident|certainty|sure|why\s+(?:is\s+)?(?:it\s+)?not\s+higher)(?-u:\b)").unwrap()
});

/// Classify free text as one of the supported questions.
pub fn detect_question(text: &str) -> Option<QAKind> {
    let t = text.to_lowercase();
    // Confidence and contradiction are more specific than the broad "missing" verbs.
    if CONFIDENCE_RE.is_match(&t) {
        return Some(QAKind::Confidence);
    }
    if CONTRADICTS_RE.is_match(&t) {
        return Some(QAKind::Contradicts);
    }
    if MISSING_RE.is_match(&t) {
        return Some(QAKind::MissingEvidence);
    }
    None
}

/// Map a topic phrase to known cause/hypothesis categories via the shared topic map.
fn categories_for_topic(text: &str) -> Option<(&'static str, &'static [&'static str])> {
    let t = text.to_lowercase();
    for entry in crate::refine::TOPIC_MAP {
        let (topic, keywords, categories) = (entry.name, entry.keywords, entry.categories);
        if topic == t.trim() {
            return Some((topic, categories));
        }
        if keywords.iter().any(|kw| {
            Regex::new(&format!(r"(?-u:\b){}(?-u:\b)", regex::escape(kw))).map(|re| re.is_match(&t)).unwrap_or(false)
        }) {
            return Some((topic, categories));
        }
    }
    None
}

fn evidence_by_id(report: &InvestigationReport) -> IndexMap<&str, &Evidence> {
    report.evidence.iter().map(|e| (e.id.as_str(), e)).collect()
}

fn unique<'a>(ids: impl Iterator<Item = &'a String>) -> Vec<&'a String> {
    ids.collect::<IndexSet<&String>>().into_iter().collect()
}

fn answer_contradicts(report: &InvestigationReport, question: &str) -> QAAnswer {
    let matched = categories_for_topic(question);
    let by_id = evidence_by_id(report);

    let hyps: Vec<_> = match matched {
        Some((_, categories)) => {
            report.hypotheses.iter().filter(|h| categories.contains(&h.category.as_str())).collect()
        }
        None => vec![],
    };

    if let Some((topic, _)) = matched {
        if hyps.is_empty() {
            let evaluated = unique(report.hypotheses.iter().map(|h| &h.category));
            return QAAnswer {
                question: question.into(),
                kind: QAKind::Contradicts,
                headline: format!("\"{topic}\" was not among the evaluated hypotheses — no evidence supports it."),
                details: if evaluated.is_empty() {
                    vec!["No hypotheses were formed for this investigation.".into()]
                } else {
                    vec![format!(
                        "Hypotheses evaluated: {}.",
                        evaluated.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    )]
                },
                evidence: vec![],
            };
        }
    }

    if hyps.is_empty() {
        // No topic recognized — report contradicting evidence across all hypotheses.
        let ids = unique(report.hypotheses.iter().flat_map(|h| h.contradicting_evidence_ids.iter()));
        let ev: Vec<Evidence> = ids.iter().filter_map(|id| by_id.get(id.as_str())).map(|e| (*e).clone()).collect();
        return QAAnswer {
            question: question.into(),
            kind: QAKind::Contradicts,
            headline: if ev.is_empty() {
                "No contradicting evidence was recorded for any hypothesis.".into()
            } else {
                format!("{} item(s) contradict the leading hypotheses.", ev.len())
            },
            details: if ev.is_empty() {
                vec!["Evidence either supports or is neutral to the hypotheses.".into()]
            } else {
                vec![]
            },
            evidence: ev,
        };
    }

    let ids = unique(hyps.iter().flat_map(|h| h.contradicting_evidence_ids.iter()));
    let ev: Vec<Evidence> = ids.iter().filter_map(|id| by_id.get(id.as_str())).map(|e| (*e).clone()).collect();
    let verdicts = hyps
        .iter()
        .map(|h| h.verdict.as_str())
        .collect::<IndexSet<&str>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    let topic = matched.map(|(t, _)| t).unwrap_or("this");
    let details: Vec<String> = hyps.iter().map(|h| format!("{}: {}", h.category, h.rationale)).collect();
    if ev.is_empty() {
        return QAAnswer {
            question: question.into(),
            kind: QAKind::Contradicts,
            headline: format!("No evidence contradicts \"{topic}\" (verdict: {verdicts})."),
            details,
            evidence: vec![],
        };
    }
    QAAnswer {
        question: question.into(),
        kind: QAKind::Contradicts,
        headline: format!("{} item(s) contradict \"{topic}\" (verdict: {verdicts}).", ev.len()),
        details,
        evidence: ev,
    }
}

fn answer_missing(report: &InvestigationReport, question: &str) -> QAAnswer {
    let gaps = &report.gap_analysis.gaps;
    let blind_spots = &report.gap_analysis.blind_spots;
    let hyp_missing = unique(report.hypotheses.iter().flat_map(|h| h.missing_evidence.iter()));
    if gaps.is_empty() && hyp_missing.is_empty() {
        return QAAnswer {
            question: question.into(),
            kind: QAKind::MissingEvidence,
            headline: "No evidence gaps — all expected dimensions were collected.".into(),
            details: vec![],
            evidence: vec![],
        };
    }
    let mut details: Vec<String> = gaps
        .iter()
        .map(|g| {
            format!(
                "{}: {} → {} (−{}% ceiling)",
                g.dimension,
                g.why,
                g.next_source,
                js::to_fixed(g.confidence_impact * 100.0, 0)
            )
        })
        .collect();
    if !hyp_missing.is_empty() {
        details.push(format!(
            "To confirm hypotheses: {}.",
            hyp_missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("; ")
        ));
    }
    for bs in blind_spots {
        details.push(format!("Blind spot: {bs}"));
    }
    QAAnswer {
        question: question.into(),
        kind: QAKind::MissingEvidence,
        headline: format!("{} evidence gap(s) limit this investigation.", gaps.len()),
        details,
        evidence: vec![],
    }
}

fn answer_confidence(report: &InvestigationReport, question: &str) -> QAAnswer {
    let gaps = &report.gap_analysis.gaps;
    let ceiling_pct = js::int_string(js::math_round(report.gap_analysis.confidence_ceiling * 100.0));
    let actual_pct = js::int_string(js::math_round(report.confidence * 100.0));
    // Limiting factors = gaps ordered by how much each shaves off the ceiling.
    let mut limiting: Vec<_> = gaps.iter().collect();
    limiting.sort_by(|a, b| js::cmp_f64(b.confidence_impact, a.confidence_impact));
    let mut details: Vec<String> = vec![];
    if !limiting.is_empty() {
        details.push(format!("Confidence is capped at {ceiling_pct}% by missing evidence:"));
        for g in &limiting {
            details.push(format!(
                "  • {} (−{}%): {}",
                g.dimension,
                js::to_fixed(g.confidence_impact * 100.0, 0),
                g.why
            ));
        }
    } else {
        details.push("No evidence gaps cap the ceiling.".into());
    }
    let weak: Vec<_> = report
        .hypotheses
        .iter()
        .filter(|h| h.verdict == Verdict::Weakened || h.verdict == Verdict::Unconfirmed)
        .collect();
    if !weak.is_empty() {
        details.push(format!(
            "Unconfirmed/weakened hypotheses: {}.",
            weak.iter().map(|h| format!("{} ({})", h.category, h.verdict.as_str())).collect::<Vec<_>>().join(", ")
        ));
    }
    QAAnswer {
        question: question.into(),
        kind: QAKind::Confidence,
        headline: format!(
            "Confidence is {actual_pct}% (ceiling {ceiling_pct}%). {}",
            if limiting.is_empty() {
                "Limited by hypothesis support, not gaps."
            } else {
                "Missing evidence is the main limiter."
            }
        ),
        details,
        evidence: vec![],
    }
}

/// Answer a follow-up question from the report, or `None` when the text is not a
/// recognized question (the caller then falls back to topic filtering).
pub fn answer_question(report: &InvestigationReport, question: &str) -> Option<QAAnswer> {
    match detect_question(question)? {
        QAKind::Contradicts => Some(answer_contradicts(report, question)),
        QAKind::MissingEvidence => Some(answer_missing(report, question)),
        QAKind::Confidence => Some(answer_confidence(report, question)),
    }
}

/// Render a Q&A answer as a terminal-friendly text block (plain strings — the CLI colors).
pub fn render_qa_answer(a: &QAAnswer) -> String {
    let mut lines: Vec<String> = vec![format!("Q: {}", a.question), String::new(), a.headline.clone()];
    for d in &a.details {
        lines.push(if d.starts_with("  ") { d.clone() } else { format!("  {d}") });
    }
    if !a.evidence.is_empty() {
        lines.push(String::new());
        lines.push("Evidence:".into());
        for e in &a.evidence {
            lines.push(format!("  [{}] ({}) {}", js::slice_chars(&e.id, 8), evidence_kind_name(e.kind), e.title));
        }
    }
    lines.join("\n")
}

/// Render a Q&A answer as JSON (2-space indent, like `JSON.stringify(…, null, 2)`).
pub fn qa_to_json(a: &QAAnswer) -> String {
    let v = json!({
        "question": a.question,
        "kind": a.kind,
        "headline": a.headline,
        "details": a.details,
        "evidence": a.evidence.iter().map(|e| json!({ "id": e.id, "kind": e.kind, "title": e.title })).collect::<Vec<_>>(),
    });
    horus_core::json::to_js_json_pretty(&v).unwrap_or_default()
}
