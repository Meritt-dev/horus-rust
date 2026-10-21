//! Reranker (HOR-404) — a small, honesty-constrained learned reranker that REORDERS candidate causes
//! using the per-tenant outcome-label corpus.
//!
//! It is a RANKING AID ONLY: it never fabricates evidence, never changes finalScore / confidence /
//! bands / ceilings, and (by `horus train`'s gate) ships OFF until it demonstrably beats the hand-tuned
//! baseline on a DETERMINISTIC holdout. Training is LOCAL and per-tenant — the corpus never leaves the
//! client; the model is a few kilobytes of logistic weights.
//!
//! Everything here is PURE (no DB, no fs, no clock, no RNG): the `horus train` command feeds it the
//! corpus (labels joined to reports) and persists the model JSON; `horus investigate` loads the model
//! and calls [`apply_reranker`] at the reorder-safe seam.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

use horus_engine::score_cause::CauseCandidate;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{js_number, js_numbers, OutcomeResolved};

pub const RERANKER_VERSION: &str = "v1";

/// Minimum distinct labeled investigations (with a derivable correct candidate) before training is
/// even attempted — below this a holdout is degenerate and any "win" is noise. `horus train` refuses
/// under this gate rather than fit on too little data.
pub const MIN_TRAIN_INVESTIGATIONS: usize = 25;

/// Scalar features read directly off a candidate (deterministic order; prefix-free).
const SCALAR_KEYS: [&str; 5] = ["finalScore", "confidence", "baseScore", "evidenceCount", "affectedCount"];

/// The candidate fields the reranker depends on. TS narrows to a `Pick<CauseCandidate, …>`; the Rust
/// port uses the engine's full candidate (the only concrete type the CLI ever hands it).
pub type RankableCause = CauseCandidate;

/// One investigation's candidates + its human verdict, the unit the reranker trains/evaluates on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RerankInvestigation {
    pub investigation_id: String,
    pub target: OutcomeResolved,
    /// Human-attested root cause (feedback only); None when absent or circular (confirm).
    pub confirmed_cause: Option<String>,
    pub candidates: Vec<RankableCause>,
}

/// Honest holdout measurement vs the hand-tuned baseline — the ship/no-ship signal.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RerankerHoldout {
    pub n: usize,
    #[serde(serialize_with = "js_number")]
    pub baseline_hit_rate: f64,
    #[serde(serialize_with = "js_number")]
    pub reranked_hit_rate: f64,
    #[serde(serialize_with = "js_number")]
    pub delta: f64,
}

/// The persisted, honesty-audited model. A few kB of JSON; written to ~/.horus/reranker.json.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RerankerModel {
    #[serde(default)]
    pub version: String,
    /// Feature schema (scalar keys + `f:<factor>` keys) — the exact order weights apply to.
    pub feature_keys: Vec<String>,
    /// Standardization params captured at train time (same length as featureKeys).
    #[serde(serialize_with = "js_numbers")]
    pub mean: Vec<f64>,
    #[serde(serialize_with = "js_numbers")]
    pub std: Vec<f64>,
    /// Learned logistic weights (same length as featureKeys) + bias.
    #[serde(serialize_with = "js_numbers")]
    pub weights: Vec<f64>,
    #[serde(serialize_with = "js_number")]
    pub bias: f64,
    #[serde(default)]
    pub holdout: RerankerHoldout,
    #[serde(default)]
    pub train_examples: usize,
    #[serde(default)]
    pub train_investigations: usize,
}

/// Why training did not produce a model (so `horus train` can report honestly).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RerankTrainSkip {
    pub ok: bool,
    /// `insufficient-corpus` | `no-derivable-labels` | `degenerate-holdout`.
    pub reason: &'static str,
    pub detail: String,
    pub labeled_investigations: usize,
}

/// `({ ok: true } & RerankerModel) | RerankTrainSkip`.
#[derive(Debug, Clone, PartialEq)]
pub enum RerankTrainResult {
    Ok(RerankerModel),
    Skip(RerankTrainSkip),
}

fn skip(reason: &'static str, detail: String, labeled_investigations: usize) -> RerankTrainResult {
    RerankTrainResult::Skip(RerankTrainSkip { ok: false, reason, detail, labeled_investigations })
}

// ── Text matching (confirmedCause ↔ candidate) ───────────────────────────────

fn tokenize(s: &str) -> HashSet<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit())
        .filter(|t| t.len() >= 3)
        .map(str::to_string)
        .collect()
}

/// Does the human-attested `confirmedCause` text refer to this candidate? Token-overlap (Jaccard-ish)
/// between the confirmedCause and the candidate's title+category. Deliberately fuzzy — this only
/// derives TRAINING labels, never a verdict, and the result is validated on a holdout.
pub fn matches_confirmed_cause(confirmed_cause: &str, cause: &RankableCause) -> f64 {
    let a = tokenize(confirmed_cause);
    let b = tokenize(&format!("{} {}", cause.title, cause.category));
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let overlap = a.iter().filter(|t| b.contains(*t)).count();
    overlap as f64 / a.len() as f64 // fraction of the cause's words found among the candidate's
}

// ── Feature extraction ───────────────────────────────────────────────────────

/// The full feature schema for a candidate set: fixed scalars + the sorted union of factor ids.
pub fn collect_feature_keys(investigations: &[RerankInvestigation]) -> Vec<String> {
    let factors: BTreeSet<&str> = investigations
        .iter()
        .flat_map(|inv| inv.candidates.iter())
        .flat_map(|c| c.explanations.iter().map(|e| e.factor.as_str()))
        .collect();
    SCALAR_KEYS.iter().map(|k| k.to_string()).chain(factors.into_iter().map(|f| format!("f:{f}"))).collect()
}

/// Raw (un-standardized) feature vector for one candidate, in `featureKeys` order.
pub fn extract_raw_features(cause: &RankableCause, feature_keys: &[String]) -> Vec<f64> {
    let mut factor_delta: HashMap<&str, f64> = HashMap::new();
    for e in &cause.explanations {
        *factor_delta.entry(e.factor.as_str()).or_insert(0.0) += e.delta;
    }
    feature_keys
        .iter()
        .map(|k| match k.as_str() {
            "finalScore" => cause.final_score,
            "confidence" => cause.confidence,
            "baseScore" => cause.base_score,
            "evidenceCount" => cause.source_evidence_ids.len() as f64,
            "affectedCount" => cause.affected_node_ids.len() as f64,
            // 'f:<factor>'
            other => factor_delta.get(other.get(2..).unwrap_or("")).copied().unwrap_or(0.0),
        })
        .collect()
}

// ── Per-candidate label derivation ───────────────────────────────────────────

/// The headline candidate the baseline points at: max finalScore, tie-broken by id asc.
pub fn baseline_top(candidates: &[RankableCause]) -> Option<&RankableCause> {
    let mut best: Option<&RankableCause> = None;
    for c in candidates {
        if best.is_none_or(|b| c.final_score > b.final_score || (c.final_score == b.final_score && c.id < b.id)) {
            best = Some(c);
        }
    }
    best
}

#[derive(Debug, Clone, PartialEq)]
pub struct LabeledExample<'a> {
    pub cause: &'a RankableCause,
    pub label: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DerivedLabels<'a> {
    pub relevant_id: Option<String>,
    pub examples: Vec<LabeledExample<'a>>,
}

fn label_all<'a>(cands: &'a [RankableCause], relevant: &str) -> Vec<LabeledExample<'a>> {
    cands.iter().map(|c| LabeledExample { cause: c, label: u8::from(c.id == relevant) }).collect()
}

/// Derive per-candidate relevance labels for one investigation, or none when no usable signal exists.
/// Returns the id of the KNOWN-relevant candidate (for top-1 holdout scoring) plus the 0/1 examples.
///
/// Rules (honest — only label what we actually know):
///  - `confirmedCause` present → the best text-matching candidate (above a floor) is relevant=1, the
///    rest 0. This is the cleanest per-candidate signal.
///  - else `target=yes` → the baseline headline was right: headline=1, rest=0.
///  - else `target=no`  → the headline was WRONG: headline=0; the others are UNKNOWN (we don't know
///    which was right) → excluded. (A negative-only row trains "this wasn't it" without guessing.)
///  - else `target=partly` with no cause → ambiguous → no examples.
pub fn derive_labels(inv: &RerankInvestigation) -> DerivedLabels<'_> {
    let cands = &inv.candidates;
    let none = DerivedLabels { relevant_id: None, examples: Vec::new() };
    if cands.is_empty() {
        return none;
    }

    if let Some(confirmed) = inv.confirmed_cause.as_deref().filter(|c| !c.trim().is_empty()) {
        let mut best_id: Option<&str> = None;
        let mut best_score = 0.0;
        for c in cands {
            let m = matches_confirmed_cause(confirmed, c);
            if m > best_score {
                best_score = m;
                best_id = Some(&c.id);
            }
        }
        if let Some(best_id) = best_id.filter(|_| best_score >= 0.34) {
            return DerivedLabels { relevant_id: Some(best_id.to_string()), examples: label_all(cands, best_id) };
        }
        // confirmedCause didn't match any candidate → fall through to verdict-based labeling.
    }

    let Some(top) = baseline_top(cands) else { return none };

    if inv.target == "yes" {
        return DerivedLabels { relevant_id: Some(top.id.clone()), examples: label_all(cands, &top.id) };
    }
    if inv.target == "no" {
        // Only a confirmed negative on the headline; the true cause is unknown → no relevant id.
        return DerivedLabels { relevant_id: None, examples: vec![LabeledExample { cause: top, label: 0 }] };
    }
    none // partly, no cause text → ambiguous
}

// ── Logistic regression (deterministic batch gradient descent) ────────────────

fn sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        return 1.0 / (1.0 + (-z).exp());
    }
    let e = z.exp();
    e / (1.0 + e)
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TrainOptions {
    pub epochs: Option<usize>,
    pub lr: Option<f64>,
    pub l2: Option<f64>,
}

/// Fit logistic weights on standardized features. Deterministic: zero init, fixed schedule.
fn fit_logistic(x: &[Vec<f64>], y: &[u8], opts: TrainOptions) -> (Vec<f64>, f64) {
    let epochs = opts.epochs.unwrap_or(400);
    let lr = opts.lr.unwrap_or(0.1);
    let l2 = opts.l2.unwrap_or(0.001);
    let dim = x.first().map(Vec::len).unwrap_or(0);
    let mut weights = vec![0.0; dim];
    let mut bias = 0.0;
    let n = x.len();
    if n == 0 {
        return (weights, bias);
    }
    let nf = n as f64;
    for _ in 0..epochs {
        let mut grad_w = vec![0.0; dim];
        let mut grad_b = 0.0;
        for (xi, &yi) in x.iter().zip(y) {
            let mut z = bias;
            for j in 0..dim {
                z += weights[j] * xi[j];
            }
            let err = sigmoid(z) - yi as f64;
            for j in 0..dim {
                grad_w[j] += err * xi[j];
            }
            grad_b += err;
        }
        for j in 0..dim {
            weights[j] -= lr * (grad_w[j] / nf + l2 * weights[j]);
        }
        bias -= lr * (grad_b / nf);
    }
    (weights, bias)
}

fn score_vector(weights: &[f64], bias: f64, x: &[f64]) -> f64 {
    let mut z = bias;
    for (w, xj) in weights.iter().zip(x) {
        z += w * xj;
    }
    z
}

// ── Standardization ──────────────────────────────────────────────────────────

fn standardize_params(x: &[Vec<f64>]) -> (Vec<f64>, Vec<f64>) {
    let dim = x.first().map(Vec::len).unwrap_or(0);
    let mut mean = vec![0.0; dim];
    let mut std = vec![0.0; dim];
    if x.is_empty() {
        return (mean, std);
    }
    let n = x.len() as f64;
    for row in x {
        for j in 0..dim {
            mean[j] += row[j];
        }
    }
    for m in mean.iter_mut() {
        *m /= n;
    }
    for row in x {
        for j in 0..dim {
            std[j] += (row[j] - mean[j]).powi(2);
        }
    }
    for s in std.iter_mut() {
        // `Math.sqrt(...) || 1` — guard 0 (and NaN) → 1
        let v = (*s / n).sqrt();
        *s = if v == 0.0 || v.is_nan() { 1.0 } else { v };
    }
    (mean, std)
}

fn apply_standardize(x: &[f64], mean: &[f64], std: &[f64]) -> Vec<f64> {
    x.iter().enumerate().map(|(j, v)| (v - mean[j]) / std[j]).collect()
}

// ── Training + holdout evaluation ────────────────────────────────────────────

/// Top-1 hit rate over a set of investigations, scoring each candidate with `score`.
fn top1_hit_rate(set: &[(&RerankInvestigation, &str)], score: impl Fn(&RankableCause) -> f64) -> f64 {
    if set.is_empty() {
        return 0.0;
    }
    let mut hits = 0usize;
    for (inv, relevant_id) in set {
        let mut best_id: Option<&str> = None;
        let mut best_score = f64::NEG_INFINITY;
        for c in &inv.candidates {
            let s = score(c);
            // Tie-break by id asc to stay deterministic and match baseline_top semantics.
            if s > best_score || (s == best_score && best_id.is_some_and(|b| c.id.as_str() < b)) {
                best_score = s;
                best_id = Some(&c.id);
            }
        }
        if best_id == Some(relevant_id) {
            hits += 1;
        }
    }
    hits as f64 / set.len() as f64
}

/// Train the reranker on the given investigations, holding out the ids in `holdout_ids`. PURE. Returns
/// a model with an honest holdout delta vs the baseline (finalScore order), or a typed skip when the
/// corpus is too small / unlabelable to train or evaluate honestly.
pub fn train_reranker(
    investigations: &[RerankInvestigation],
    holdout_ids: &HashSet<String>,
    opts: TrainOptions,
) -> RerankTrainResult {
    let labeled: Vec<(&RerankInvestigation, DerivedLabels<'_>)> = investigations
        .iter()
        .map(|inv| (inv, derive_labels(inv)))
        .filter(|(_, derived)| !derived.examples.is_empty())
        .collect();

    // Investigations with a KNOWN-correct candidate — the only ones a top-1 holdout can score.
    let scorable: Vec<(&RerankInvestigation, &str)> = labeled
        .iter()
        .filter(|(inv, derived)| derived.relevant_id.is_some() && inv.candidates.len() >= 2)
        .map(|(inv, derived)| (*inv, derived.relevant_id.as_deref().unwrap_or("")))
        .collect();

    if scorable.len() < MIN_TRAIN_INVESTIGATIONS {
        return skip(
            "insufficient-corpus",
            format!(
                "need ≥{MIN_TRAIN_INVESTIGATIONS} labeled investigations with a known-correct candidate; have {}",
                scorable.len()
            ),
            scorable.len(),
        );
    }

    let feature_keys = collect_feature_keys(investigations);

    let train_set: Vec<&(&RerankInvestigation, &str)> =
        scorable.iter().filter(|(inv, _)| !holdout_ids.contains(&inv.investigation_id)).collect();
    let holdout_set: Vec<(&RerankInvestigation, &str)> =
        scorable.iter().filter(|(inv, _)| holdout_ids.contains(&inv.investigation_id)).copied().collect();
    if holdout_set.is_empty() || train_set.is_empty() {
        return skip(
            "degenerate-holdout",
            format!("train/holdout split left {} train / {} holdout", train_set.len(), holdout_set.len()),
            scorable.len(),
        );
    }

    // Build the standardized training matrix from the TRAIN split only (no holdout leakage).
    let mut raw_x: Vec<Vec<f64>> = Vec::new();
    let mut y: Vec<u8> = Vec::new();
    for (inv, _) in &train_set {
        for ex in derive_labels(inv).examples {
            raw_x.push(extract_raw_features(ex.cause, &feature_keys));
            y.push(ex.label);
        }
    }
    if raw_x.is_empty() {
        return skip("no-derivable-labels", "no training examples after split".into(), scorable.len());
    }
    let (mean, std) = standardize_params(&raw_x);
    let x: Vec<Vec<f64>> = raw_x.iter().map(|row| apply_standardize(row, &mean, &std)).collect();
    let (weights, bias) = fit_logistic(&x, &y, opts);

    let model_score =
        |c: &RankableCause| score_vector(&weights, bias, &apply_standardize(&extract_raw_features(c, &feature_keys), &mean, &std));

    let baseline_hit_rate = top1_hit_rate(&holdout_set, |c| c.final_score);
    let reranked_hit_rate = top1_hit_rate(&holdout_set, model_score);

    RerankTrainResult::Ok(RerankerModel {
        version: RERANKER_VERSION.to_string(),
        feature_keys,
        mean,
        std,
        weights,
        bias,
        holdout: RerankerHoldout {
            n: holdout_set.len(),
            baseline_hit_rate,
            reranked_hit_rate,
            delta: reranked_hit_rate - baseline_hit_rate,
        },
        train_examples: raw_x.len(),
        train_investigations: train_set.len(),
    })
}

// ── Inference: reorder only ──────────────────────────────────────────────────

/// Reorder candidates by the model's score, descending. PURE and REORDER-ONLY — it returns a new array
/// and NEVER mutates any candidate's finalScore/confidence/band. Ties (and any candidate the model
/// can't score) preserve the input order, so a no-op model leaves ordering unchanged.
pub fn apply_reranker(model: &RerankerModel, candidates: &[RankableCause]) -> Vec<RankableCause> {
    let mut scored: Vec<(usize, f64)> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let x = apply_standardize(&extract_raw_features(c, &model.feature_keys), &model.mean, &model.std);
            (i, score_vector(&model.weights, model.bias, &x))
        })
        .collect();
    // score desc, stable on original index (a NaN difference is falsy in JS → index order)
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal).then_with(|| a.0.cmp(&b.0)));
    scored.into_iter().map(|(i, _)| candidates[i].clone()).collect()
}

/// Type guard for a persisted model blob (defensive against hand-edited / legacy files).
pub fn is_reranker_model(blob: &Value) -> bool {
    let Some(m) = blob.as_object() else { return false };
    let arr = |k: &str| m.get(k).and_then(Value::as_array);
    match (arr("featureKeys"), arr("weights"), arr("mean"), arr("std"), m.get("bias")) {
        (Some(keys), Some(weights), Some(_), Some(_), Some(bias)) => bias.is_number() && weights.len() == keys.len(),
        _ => false,
    }
}
