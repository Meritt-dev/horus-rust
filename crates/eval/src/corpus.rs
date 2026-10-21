//! Corpus construction (HOR-403) — the read-only transform from outcome labels + joined reports to a
//! stable, evaluable corpus. Pure: it takes already-fetched labels and a report resolver, so it is
//! trivially testable and shares the EXACT current-verdict definition with `horus memory accuracy`.
//!
//! Pipeline (each stage counted, never silently dropped):
//!   1. dedupe to the CURRENT verdict per investigation (shared `dedupe_to_current_verdict`);
//!   2. drop null-investigationId verdicts → `unjoinable` (the label has no report to join);
//!   3. validate-on-read firewall: resolved∈{yes,partly,no} + source∈{feedback,confirm} → else
//!      `quarantine`;
//!   4. join `investigations.report` by investigationId → missing/legacy report → `unjoinable`;
//!   5. project the survivors into `CorpusRow`s (confirm rows flagged weak + confirmedCause dropped).

use std::collections::HashMap;

use horus_db::{dedupe_to_current_verdict, format_ts, is_outcome_resolved, is_outcome_source, OutcomeLabel};
use horus_engine::score_cause::CauseCandidate;
use serde_json::Value;

use crate::types::{
    ClassBalance, CorpusArtifact, CorpusBuild, CorpusFactor, CorpusHeadlineCause, CorpusManifest, CorpusRow,
    HoldoutSplit, QuarantinedRow, SourceBalance, UnjoinableRow, CORPUS_VERSION,
};

/// Resolves an investigation's stored report blob (jsonb) by id, or None when absent.
pub type ReportResolver<'a> = dyn Fn(&str) -> Option<Value> + 'a;

/// A minimally-validated report view: enough to be a corpus row (defensive against legacy blobs).
struct UsableReport {
    summary: String,
    confidence: f64,
    seeds: Vec<String>,
    causes: Vec<CauseCandidate>,
}

/// Validate a stored report blob into a `UsableReport`, or None if it is missing/legacy. "Legacy" =
/// not an object or no `suspectedCauses` array (the field that carries every cause-scoring feature).
/// An empty `suspectedCauses` is VALID (the run ranked nothing) — it joins with headlineCause=null.
fn to_usable_report(blob: &Value) -> Option<UsableReport> {
    let r = blob.as_object()?;
    let causes = r.get("suspectedCauses")?.as_array()?;
    // TS casts the array unchecked; Rust needs typed candidates, so a cause that does not decode
    // as a `CauseCandidate` is treated as legacy (recorded in DIVERGENCES.md).
    let causes: Vec<CauseCandidate> = causes.iter().map(|c| serde_json::from_value(c.clone()).ok()).collect::<Option<_>>()?;
    let seeds = match r.get("seeds").and_then(Value::as_array) {
        Some(seeds) => seeds
            .iter()
            .filter_map(|s| s.as_object().and_then(|o| o.get("name")))
            .map(|name| match name {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .filter(|s| !s.is_empty())
            .collect(),
        None => Vec::new(),
    };
    Some(UsableReport {
        summary: r.get("summary").and_then(Value::as_str).unwrap_or("").to_string(),
        confidence: r.get("confidence").and_then(Value::as_f64).filter(|c| c.is_finite()).unwrap_or(0.0),
        seeds,
        causes,
    })
}

/// Pick the headline cause: the one Horus pointed at — highest `finalScore`, tie-broken by `id` asc
/// for determinism. Returns None when no causes were ranked.
pub fn pick_headline_cause(causes: &[CauseCandidate]) -> Option<&CauseCandidate> {
    let mut best: Option<&CauseCandidate> = None;
    for c in causes {
        if best.is_none_or(|b| c.final_score > b.final_score || (c.final_score == b.final_score && c.id < b.id)) {
            best = Some(c);
        }
    }
    best
}

/// Flatten a cause's explanations into factor→summed-delta, sorted by factor for byte-stability.
fn flatten_factors(cause: &CauseCandidate) -> Vec<CorpusFactor> {
    let mut sums: HashMap<&str, f64> = HashMap::new();
    for e in &cause.explanations {
        *sums.entry(e.factor.as_str()).or_insert(0.0) += e.delta;
    }
    let mut out: Vec<CorpusFactor> =
        sums.into_iter().map(|(factor, delta)| CorpusFactor { factor: factor.to_string(), delta }).collect();
    out.sort_by(|a, b| a.factor.cmp(&b.factor));
    out
}

fn project_headline(cause: &CauseCandidate) -> CorpusHeadlineCause {
    let mut source_evidence_ids = cause.source_evidence_ids.clone();
    source_evidence_ids.sort();
    CorpusHeadlineCause {
        id: cause.id.clone(),
        category: cause.category.clone(),
        final_score: cause.final_score,
        confidence: cause.confidence,
        band: cause.band.as_str().to_string(),
        source_evidence_ids,
        factors: flatten_factors(cause),
    }
}

/// Build the corpus from a label set + a report resolver. READ-ONLY: nothing here writes. The labels
/// are expected pre-filtered (project/source/since/limit) by the caller, exactly as
/// `horus memory accuracy` filters them, so the two read paths stay aligned.
pub fn build_corpus(labels: &[OutcomeLabel], resolve_report: &ReportResolver<'_>) -> CorpusBuild {
    let current = dedupe_to_current_verdict(labels);
    let evaluated = current.len();

    let mut rows: Vec<CorpusRow> = Vec::new();
    let mut quarantined: Vec<QuarantinedRow> = Vec::new();
    let mut unjoinable: Vec<UnjoinableRow> = Vec::new();

    for label in current {
        // (2) A null investigationId carries no report to join — the label has only `project`.
        let Some(investigation_id) = label.investigation_id.clone() else {
            unjoinable.push(UnjoinableRow { investigation_id: None, reason: "null-investigation" });
            continue;
        };
        // (3) Validate-on-read firewall: defense-in-depth against legacy/corrupt rows.
        if !is_outcome_resolved(&label.resolved) || !is_outcome_source(&label.source) {
            quarantined.push(QuarantinedRow {
                investigation_id: Some(investigation_id),
                resolved: label.resolved.clone(),
                source: label.source.clone(),
                reason: if !is_outcome_resolved(&label.resolved) {
                    format!("invalid resolved \"{}\"", label.resolved)
                } else {
                    format!("invalid source \"{}\"", label.source)
                },
            });
            continue;
        }
        // (4) Join the report.
        let Some(blob) = resolve_report(&investigation_id).filter(|b| !b.is_null()) else {
            unjoinable.push(UnjoinableRow { investigation_id: Some(investigation_id), reason: "missing-report" });
            continue;
        };
        let Some(report) = to_usable_report(&blob) else {
            unjoinable.push(UnjoinableRow { investigation_id: Some(investigation_id), reason: "legacy-report" });
            continue;
        };
        // (5) Project to a corpus row. confirm = positive-only/weak; its confirmedCause is circular.
        let is_confirm = label.source == "confirm";
        let headline = pick_headline_cause(&report.causes);
        rows.push(CorpusRow {
            investigation_id,
            project: label.project.clone(),
            at: format_ts(&label.at),
            target: label.resolved.clone(),
            source: label.source.clone(),
            weak: is_confirm,
            confirmed_cause: if is_confirm { None } else { label.confirmed_cause.clone() },
            summary: report.summary,
            report_confidence: report.confidence,
            seeds: report.seeds,
            cause_count: report.causes.len(),
            headline_cause: headline.map(project_headline),
        });
    }

    let mut class_balance = ClassBalance::default();
    let mut by_source = SourceBalance::default();
    for r in &rows {
        match r.target.as_str() {
            "yes" => class_balance.yes += 1,
            "partly" => class_balance.partly += 1,
            "no" => class_balance.no += 1,
            _ => {}
        }
        match r.source.as_str() {
            "feedback" => by_source.feedback += 1,
            "confirm" => by_source.confirm += 1,
            _ => {}
        }
    }

    CorpusBuild { rows, evaluated, quarantined, unjoinable, class_balance, by_source }
}

/// `corpus-<version>.jsonl`.
pub fn corpus_filename(version: Option<&str>) -> String {
    format!("corpus-{}.jsonl", version.unwrap_or(CORPUS_VERSION))
}

/// Sort corpus rows for byte-stable output: by investigationId, then by `at`. Identical inputs always
/// produce an identical ordering (and JSON of a fixed-shape struct is key-stable here).
fn sort_rows(rows: &[CorpusRow]) -> Vec<CorpusRow> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|a, b| a.investigation_id.cmp(&b.investigation_id).then_with(|| a.at.cmp(&b.at)));
    sorted
}

/// Deterministic FNV-1a (32-bit) string hash — used only to bucket investigationIds into the holdout
/// split. No crypto dependency; stable across runs/machines. Hashes UTF-16 code units like the TS
/// `charCodeAt` loop.
fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for unit in s.encode_utf16() {
        h ^= unit as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// Deterministic holdout split spec: `hash(investigationId) % 100 < holdoutPct` → holdout, else
/// train. Stable and reproducible — the same investigation always lands in the same bucket.
pub fn holdout_split<'a>(investigation_ids: impl IntoIterator<Item = &'a str>, holdout_pct: Option<u32>) -> HoldoutSplit {
    let holdout_pct = holdout_pct.unwrap_or(20);
    let mut train: Vec<String> = Vec::new();
    let mut holdout: Vec<String> = Vec::new();
    for id in investigation_ids {
        if fnv1a(id) % 100 < holdout_pct {
            holdout.push(id.to_string());
        } else {
            train.push(id.to_string());
        }
    }
    train.sort();
    holdout.sort();
    HoldoutSplit { holdout_pct, train, holdout }
}

/// Serialize a corpus build into a byte-stable artifact: a sorted JSONL body + a manifest. For
/// identical inputs the `jsonl` is byte-identical (sorted rows, fixed key order). `generatedAt` is
/// left None here so the body and manifest stay deterministic; the writer stamps it.
pub fn serialize_corpus(build: &CorpusBuild, version: Option<&str>) -> CorpusArtifact {
    let version = version.unwrap_or(CORPUS_VERSION);
    let sorted = sort_rows(&build.rows);
    let mut jsonl = sorted
        .iter()
        .map(|r| serde_json::to_string(r).expect("corpus row serializes"))
        .collect::<Vec<_>>()
        .join("\n");
    if !sorted.is_empty() {
        jsonl.push('\n');
    }
    let manifest = CorpusManifest {
        version: version.to_string(),
        generated_at: None,
        rows: sorted.len(),
        evaluated: build.evaluated,
        quarantined: build.quarantined.len(),
        unjoinable: build.unjoinable.len(),
        class_balance: build.class_balance.clone(),
        by_source: build.by_source.clone(),
        holdout: holdout_split(sorted.iter().map(|r| r.investigation_id.as_str()), None),
    };
    CorpusArtifact { filename: corpus_filename(Some(version)), jsonl, manifest }
}
