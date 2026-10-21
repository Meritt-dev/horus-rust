//! Baseline accuracy + feature-separation diagnostic (HOR-403).
//!
//! `compute_baseline` is intentionally a thin shell over `summarize_outcome_labels` so the harness's
//! hit-rate can NEVER drift from `horus memory accuracy`: same dedupe, same math. `feature_separation`
//! is a NO-MODEL diagnostic — it only measures how far each cause-scoring factor's delta separates
//! yes-outcome from no-outcome rows, with a simple variance/effect-size estimate. Nothing is trained.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

use horus_db::{summarize_outcome_labels, OutcomeLabel};

use crate::types::{BaselineReport, CorpusRow, FeatureSeparation, FeatureSeparationReport, ProjectBaseline};

/// Compute the baseline hit-rate report over a label set with the SAME math as
/// `summarize_outcome_labels` (so it equals `horus memory accuracy`). `byProject` partitions the labels
/// by `project` and summarizes each slice with the identical function.
pub fn compute_baseline(labels: &[OutcomeLabel]) -> BaselineReport {
    let summary = summarize_outcome_labels(labels);

    // Map keyed by project (None = null), in first-seen order like the JS Map.
    let mut order: Vec<Option<String>> = Vec::new();
    let mut by_project_map: HashMap<Option<String>, Vec<OutcomeLabel>> = HashMap::new();
    for l in labels {
        let key = l.project.clone();
        match by_project_map.get_mut(&key) {
            Some(arr) => arr.push(l.clone()),
            None => {
                order.push(key.clone());
                by_project_map.insert(key, vec![l.clone()]);
            }
        }
    }
    let mut by_project: Vec<ProjectBaseline> = order
        .into_iter()
        .map(|project| {
            let s = summarize_outcome_labels(&by_project_map[&project]);
            ProjectBaseline { project, n: s.evaluated, strict_hit_rate: s.accuracy, weighted_hit_rate: s.weighted_score }
        })
        .collect();
    // Stable: nulls last, then by project name.
    by_project.sort_by(|a, b| match (&a.project, &b.project) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a), Some(b)) => a.cmp(b),
    });

    BaselineReport {
        n: summary.evaluated,
        strict_hit_rate: summary.accuracy,
        weighted_hit_rate: summary.weighted_score,
        class_balance: summary.counts,
        by_source: summary.by_source,
        by_project,
    }
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().fold(0.0, |a, b| a + b) / xs.len() as f64
}

/// Population variance (divide by n) — a simple, deterministic spread estimate.
fn variance(xs: &[f64], m: f64) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().fold(0.0, |a, b| a + (b - m) * (b - m)) / xs.len() as f64
}

/// Feature-separation diagnostic. For each factor seen on any headline cause, gather its delta on the
/// yes-outcome rows vs the no-outcome rows and report mean/variance/separation/effect-size + an
/// overall CV. `confirm` rows are excluded (positive-only → no `no` samples, and circular target).
/// `partly` rows are excluded from the two-group contrast (the diagnostic is strictly yes-vs-no).
///
/// A row that lacks a factor contributes a 0 delta for that factor (the factor did not fire), which
/// is the correct neutral baseline for separation.
pub fn feature_separation(rows: &[CorpusRow]) -> FeatureSeparationReport {
    // Only feedback rows with a headline cause and a yes/no target are usable.
    let usable: Vec<(&CorpusRow, &crate::types::CorpusHeadlineCause)> = rows
        .iter()
        .filter(|r| !r.weak && (r.target == "yes" || r.target == "no"))
        .filter_map(|r| r.headline_cause.as_ref().map(|h| (r, h)))
        .collect();

    // Discover every factor across usable rows (deterministic, sorted).
    let factors: BTreeSet<&str> = usable.iter().flat_map(|(_, h)| h.factors.iter().map(|f| f.factor.as_str())).collect();

    let mut out: Vec<FeatureSeparation> = factors
        .into_iter()
        .map(|factor| {
            let mut yes: Vec<f64> = Vec::new();
            let mut no: Vec<f64> = Vec::new();
            for (r, h) in &usable {
                // factor did not fire on this row → neutral 0
                let delta = h.factors.iter().find(|x| x.factor == factor).map(|f| f.delta).unwrap_or(0.0);
                if r.target == "yes" {
                    yes.push(delta);
                } else {
                    no.push(delta);
                }
            }
            let mean_yes = mean(&yes);
            let mean_no = mean(&no);
            let var_yes = variance(&yes, mean_yes);
            let var_no = variance(&no, mean_no);
            let separation = mean_yes - mean_no;

            // Pooled std across both groups for a Cohen's-d-ish effect size.
            let all: Vec<f64> = yes.iter().chain(no.iter()).copied().collect();
            let overall_mean = mean(&all);
            let pooled_var = variance(&all, overall_mean);
            let pooled_std = pooled_var.sqrt();
            let effect_size = if pooled_std == 0.0 { 0.0 } else { separation / pooled_std };
            let cv = if overall_mean == 0.0 { 0.0 } else { pooled_std / overall_mean.abs() };

            FeatureSeparation {
                factor: factor.to_string(),
                n_yes: yes.len(),
                n_no: no.len(),
                mean_yes,
                mean_no,
                var_yes,
                var_no,
                separation,
                effect_size,
                cv,
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.effect_size.abs().partial_cmp(&a.effect_size.abs()).unwrap_or(Ordering::Equal).then_with(|| a.factor.cmp(&b.factor))
    });

    FeatureSeparationReport { evaluated: usable.len(), factors: out }
}
