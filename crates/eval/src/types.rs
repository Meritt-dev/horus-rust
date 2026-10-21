//! Public types for the read-only accuracy harness (HOR-403).
//!
//! The harness turns the converged outcome-label store (HOR-390) + the joined investigation reports
//! into a stable, evaluable corpus + a baseline accuracy report + a no-model feature-separation
//! diagnostic. It NEVER writes the label store — only `horus feedback` (source=feedback) and
//! `horus memory confirm` (source=confirm) do. Everything here is a read/transform.

use serde::{Deserialize, Serialize, Serializer};

/// `yes` | `partly` | `no` (validated by `horus_db::is_outcome_resolved`).
pub type OutcomeResolved = String;
/// `feedback` | `confirm` (validated by `horus_db::is_outcome_source`).
pub type OutcomeSource = String;

/// Schema version of the emitted corpus — bump when the row shape changes.
pub const CORPUS_VERSION: &str = "v1";

/// `JSON.stringify` prints an integral double as `1`, serde_json as `1.0`; the corpus JSONL must be
/// byte-identical to the TS artifact.
pub fn js_number<S: Serializer>(x: &f64, s: S) -> Result<S::Ok, S::Error> {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 9007199254740992.0 {
        s.serialize_i64(*x as i64)
    } else {
        s.serialize_f64(*x)
    }
}

pub fn js_numbers<S: Serializer>(xs: &[f64], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(xs.len()))?;
    for x in xs {
        seq.serialize_element(&JsNumber(*x))?;
    }
    seq.end()
}

struct JsNumber(f64);
impl Serialize for JsNumber {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        js_number(&self.0, s)
    }
}

/// One factor's contribution on the headline cause, flattened from `ScoreExplanation`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorpusFactor {
    /// Stable factor id, e.g. 'evidence-quality'.
    pub factor: String,
    /// Summed signed delta for this factor on the headline cause.
    #[serde(serialize_with = "js_number")]
    pub delta: f64,
}

/// The headline cause Horus pointed at (highest finalScore, tie-broken by id) projected for eval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusHeadlineCause {
    pub id: String,
    pub category: String,
    #[serde(serialize_with = "js_number")]
    pub final_score: f64,
    #[serde(serialize_with = "js_number")]
    pub confidence: f64,
    pub band: String,
    pub source_evidence_ids: Vec<String>,
    /// Flattened, factor-sorted explanation deltas (deterministic order).
    pub factors: Vec<CorpusFactor>,
}

/// One corpus row = one investigation's CURRENT verdict joined to its report's cause-scoring features.
///
/// The `target` is the human verdict (yes|partly|no). For `confirm` rows the target is positive-only
/// and weak (confirm hard-codes resolved=yes), and `confirmedCause` is deliberately DROPPED to null —
/// confirm's confirmedCause is Horus's own report.summary, so using it as a target is circular.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusRow {
    pub investigation_id: String,
    pub project: Option<String>,
    /// ISO-8601 attestation time of the current verdict.
    pub at: String,
    /// The label verdict — the supervised target.
    pub target: OutcomeResolved,
    pub source: OutcomeSource,
    /// True for source=confirm: positive-only + weak (never a discriminative target).
    pub weak: bool,
    /// Human-attested root cause — feedback only; null for confirm (circular) and when absent.
    pub confirmed_cause: Option<String>,
    /// Report headline summary (Horus's own one-liner).
    pub summary: String,
    /// 0–1 overall investigation confidence from the report.
    #[serde(serialize_with = "js_number")]
    pub report_confidence: f64,
    /// Seed symbol names the hint resolved to (minimal projection).
    pub seeds: Vec<String>,
    /// Number of suspected causes the report ranked.
    pub cause_count: usize,
    /// The headline (top-ranked) cause, or null when the report ranked none.
    pub headline_cause: Option<CorpusHeadlineCause>,
}

/// A row that failed the validate-on-read firewall (bad resolved/source) — counted, excluded.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantinedRow {
    pub investigation_id: Option<String>,
    pub resolved: String,
    pub source: String,
    pub reason: String,
}

/// A current-verdict row that could not be joined to a usable report — counted, excluded.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnjoinableRow {
    pub investigation_id: Option<String>,
    /// `null-investigation` | `missing-report` | `legacy-report`.
    pub reason: &'static str,
}

/// Class balance over the corpus targets (current verdicts that survived to the corpus).
pub type ClassBalance = horus_db::OutcomeCounts;

/// Source segregation count over the corpus rows.
pub type SourceBalance = horus_db::OutcomeBySource;

/// Result of building the corpus from the labels + report resolver (all read-only, pure).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusBuild {
    pub rows: Vec<CorpusRow>,
    /// Distinct investigations carrying a current verdict (before firewall/join drops).
    pub evaluated: usize,
    /// Firewall rejects — bad resolved/source. Counted, excluded from `rows`.
    pub quarantined: Vec<QuarantinedRow>,
    /// Join failures — null investigationId or missing/legacy report. Counted, excluded.
    pub unjoinable: Vec<UnjoinableRow>,
    pub class_balance: ClassBalance,
    pub by_source: SourceBalance,
}

/// Deterministic, byte-stable serialization of a corpus build.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CorpusArtifact {
    /// `corpus-<version>.jsonl` filename.
    pub filename: String,
    /// The JSONL body (one CorpusRow per line, trailing newline), sorted deterministically.
    pub jsonl: String,
    pub manifest: CorpusManifest,
}

/// Sidecar manifest describing a corpus artifact.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusManifest {
    pub version: String,
    /// Set by the writer; not part of the deterministic jsonl.
    pub generated_at: Option<String>,
    pub rows: usize,
    pub evaluated: usize,
    pub quarantined: usize,
    pub unjoinable: usize,
    pub class_balance: ClassBalance,
    pub by_source: SourceBalance,
    pub holdout: HoldoutSplit,
}

/// Deterministic 80/20 holdout split spec — partitions investigationIds by a stable hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HoldoutSplit {
    /// Holdout fraction (0–1); the rule is `hash(investigationId) % 100 < holdoutPct`.
    pub holdout_pct: u32,
    /// investigationIds assigned to training (sorted).
    pub train: Vec<String>,
    /// investigationIds assigned to the held-out eval set (sorted).
    pub holdout: Vec<String>,
}

/// Per-project hit-rate slice, same math as `summarize_outcome_labels`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBaseline {
    pub project: Option<String>,
    pub n: usize,
    #[serde(serialize_with = "js_number")]
    pub strict_hit_rate: f64,
    #[serde(serialize_with = "js_number")]
    pub weighted_hit_rate: f64,
}

/// The baseline accuracy report — Horus's own measured hit-rate over the eval set, computed with the
/// SAME math as `summarize_outcome_labels` so it can never drift from `horus memory accuracy`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineReport {
    /// Distinct investigations with a current verdict.
    pub n: usize,
    /// `yes / n` — strict "did it point at the cause?".
    #[serde(serialize_with = "js_number")]
    pub strict_hit_rate: f64,
    /// `(yes + 0.5·partly) / n` — partial-credit.
    #[serde(serialize_with = "js_number")]
    pub weighted_hit_rate: f64,
    pub class_balance: ClassBalance,
    pub by_source: SourceBalance,
    pub by_project: Vec<ProjectBaseline>,
}

/// One factor's yes-vs-no separation across the corpus — a NO-MODEL diagnostic. We measure how far
/// apart the factor's delta sits between yes-outcome and no-outcome rows, plus a simple
/// variance/effect-size estimate. `confirm` rows are excluded (positive-only → no `no` samples).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureSeparation {
    pub factor: String,
    pub n_yes: usize,
    pub n_no: usize,
    #[serde(serialize_with = "js_number")]
    pub mean_yes: f64,
    #[serde(serialize_with = "js_number")]
    pub mean_no: f64,
    #[serde(serialize_with = "js_number")]
    pub var_yes: f64,
    #[serde(serialize_with = "js_number")]
    pub var_no: f64,
    /// meanYes − meanNo.
    #[serde(serialize_with = "js_number")]
    pub separation: f64,
    /// separation / pooled-std (0 when pooled-std is 0); a Cohen's-d-ish signal-to-noise.
    #[serde(serialize_with = "js_number")]
    pub effect_size: f64,
    /// Coefficient of variation of the factor overall (pooled-std / |overall-mean|).
    #[serde(serialize_with = "js_number")]
    pub cv: f64,
}

/// The feature-separation diagnostic over all factors (sorted by |effectSize| desc, then factor).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeatureSeparationReport {
    /// Rows used (feedback rows with a headline cause and a yes/no target).
    pub evaluated: usize,
    pub factors: Vec<FeatureSeparation>,
}

/// Read-flag slice shared with `horus memory accuracy` (--source/--days/--limit/--repo).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EvalReadOptions {
    pub source: Option<OutcomeSource>,
    /// Inclusive lower bound on `at`.
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<usize>,
}
