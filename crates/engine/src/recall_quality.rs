//! Score chronological recall reviews, separately from investigation accuracy and
//! dispositions. TS `assert` failures become `Err`.

use std::collections::{HashMap, HashSet};

use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};

use crate::js;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecallReviewCase {
    pub id: String,
    pub relevant_report_ids: Vec<String>,
    pub rationale: String,
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecallReview {
    pub reviewer: String,
    pub version: String,
    pub cases: Vec<RecallReviewCase>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecallReport {
    pub id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecallMatch {
    pub report_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecallResult {
    pub id: String,
    pub matches: Vec<RecallMatch>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FalseMatch {
    pub id: String,
    pub report_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecallQualityScore {
    pub reviewer: String,
    pub version: String,
    pub labeled: i64,
    pub recurrences: i64,
    pub top_three_hits: i64,
    pub top_three_rate: Option<f64>,
    pub unrelated: i64,
    pub no_matches: i64,
    pub no_match_rate: Option<f64>,
    pub misses: Vec<String>,
    pub false_matches: Vec<FalseMatch>,
    pub passed: bool,
}

pub fn score_recall_quality(
    reports: &[RecallReport],
    results: &[RecallResult],
    review: &RecallReview,
) -> Result<RecallQualityScore> {
    ensure!(!review.reviewer.trim().is_empty(), "assertion failed");
    ensure!(!review.version.trim().is_empty(), "assertion failed");
    ensure!(!review.cases.is_empty() && review.cases.len() <= 1000, "assertion failed");
    let times: HashMap<&str, f64> = reports.iter().map(|r| (r.id.as_str(), js::date_parse(&r.created_at))).collect();
    ensure!(times.len() == reports.len(), "Duplicate source report IDs");
    let recalled: HashMap<&str, &[RecallMatch]> =
        results.iter().map(|r| (r.id.as_str(), &r.matches[..r.matches.len().min(3)])).collect();
    let mut labeled: HashSet<&str> = HashSet::new();
    let (mut recurrences, mut top_three_hits, mut unrelated, mut no_matches) = (0i64, 0i64, 0i64, 0i64);
    let mut misses: Vec<String> = vec![];
    let mut false_matches: Vec<FalseMatch> = vec![];
    for label in &review.cases {
        ensure!(!labeled.contains(label.id.as_str()), "Duplicate/invalid review ID");
        labeled.insert(&label.id);
        ensure!(!label.rationale.trim().is_empty(), "Missing relevance rationale");
        ensure!(
            !label.source_refs.is_empty() && label.source_refs.iter().all(|r| !r.trim().is_empty()),
            "Missing review provenance"
        );
        let unique: HashSet<&str> = label.relevant_report_ids.iter().map(String::as_str).collect();
        ensure!(unique.len() == label.relevant_report_ids.len(), "Duplicate relevant report IDs");
        let at = times.get(label.id.as_str()).copied();
        let matches = recalled.get(label.id.as_str()).copied();
        let (Some(at), Some(matches)) = (at.filter(|a| a.is_finite()), matches) else {
            bail!("Review report unavailable: {}", label.id);
        };
        for id in &label.relevant_report_ids {
            let prior = times.get(id.as_str()).copied();
            ensure!(prior.is_some_and(|p| p.is_finite() && p < at), "Relevant report must be earlier: {id}");
        }
        for m in matches {
            for id in &m.report_ids {
                let prior = times.get(id.as_str()).copied();
                ensure!(prior.is_some_and(|p| p < at), "Recall leaked non-earlier report: {id}");
            }
        }
        let expected = unique;
        if !expected.is_empty() {
            recurrences += 1;
            if matches.iter().any(|m| m.report_ids.iter().any(|id| expected.contains(id.as_str()))) {
                top_three_hits += 1;
            } else {
                misses.push(label.id.clone());
            }
        } else {
            unrelated += 1;
            if matches.is_empty() {
                no_matches += 1;
            }
        }
        for m in matches {
            if !m.report_ids.iter().any(|id| expected.contains(id.as_str())) {
                false_matches.push(FalseMatch { id: label.id.clone(), report_ids: m.report_ids.clone() });
            }
        }
    }
    Ok(RecallQualityScore {
        reviewer: review.reviewer.clone(),
        version: review.version.clone(),
        labeled: labeled.len() as i64,
        recurrences,
        top_three_hits,
        top_three_rate: if recurrences > 0 { Some(top_three_hits as f64 / recurrences as f64) } else { None },
        unrelated,
        no_matches,
        no_match_rate: if unrelated > 0 { Some(no_matches as f64 / unrelated as f64) } else { None },
        misses,
        false_matches,
        passed: recurrences > 0
            && unrelated > 0
            && top_three_hits as f64 >= 0.9 * recurrences as f64
            && no_matches as f64 >= 0.95 * unrelated as f64,
    })
}
