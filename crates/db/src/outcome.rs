//! Outcome-label / eval store API (HOR-390).
//!
//! A small, queryable store of investigation outcome labels keyed by `investigation_id`. It is
//! the persisted, evaluable record of Horus's own accuracy — the flywheel's eval/training set —
//! and the single sink that `horus feedback` and `horus memory confirm` both write to.
//!
//! Append-only: `record_outcome_label` always inserts a new row, so the dataset keeps every
//! attestation (and corrections to it). Use `get_latest_outcome_label` for the current verdict
//! and `list_outcome_labels` to slice by project, source, verdict and date range.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, params_from_iter, types::Value, Row};
use serde::Serialize;

use crate::client::DbHandle;
use crate::schema::{format_ts, parse_ts, OutcomeLabel};

/// Verdicts an attester can give: did Horus point at the real cause?
pub const OUTCOME_RESOLVED: &[&str] = &["yes", "partly", "no"];
/// The two entry points that converge into the eval store (HOR-390).
pub const OUTCOME_SOURCE: &[&str] = &["feedback", "confirm"];

/// Validation guards — pure so callers (CLI/engine) can reject bad input early.
pub fn is_outcome_resolved(v: &str) -> bool {
    OUTCOME_RESOLVED.contains(&v)
}

pub fn is_outcome_source(v: &str) -> bool {
    OUTCOME_SOURCE.contains(&v)
}

/// The label payload an entry point records. `at` defaults to now; `id` is generated.
#[derive(Debug, Clone, Default)]
pub struct OutcomeLabelInput {
    pub investigation_id: String,
    /// `yes` | `partly` | `no`.
    pub resolved: String,
    /// `feedback` | `confirm`.
    pub source: String,
    pub confirmed_cause: Option<String>,
    pub note: Option<String>,
    /// Denormalized repo/project scope, so accuracy can be sliced per project.
    pub project: Option<String>,
    /// Forward-compat extras as JSON text (e.g. manualEstimateMinutes, horusSeconds).
    pub payload: Option<String>,
    /// Override the attestation time (defaults to the DB clock).
    pub at: Option<DateTime<Utc>>,
}

/// Filter/slice options for querying the eval dataset.
#[derive(Debug, Clone, Default)]
pub struct OutcomeLabelQuery {
    pub investigation_id: Option<String>,
    pub project: Option<String>,
    pub source: Option<String>,
    pub resolved: Option<String>,
    /// Inclusive lower bound on `at`.
    pub since: Option<DateTime<Utc>>,
    /// Inclusive upper bound on `at`.
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
}

const COLUMNS: &str = "id, investigation_id, project, resolved, confirmed_cause, note, source, payload, at";

fn row_to_label(r: &Row<'_>) -> Result<OutcomeLabel> {
    Ok(OutcomeLabel {
        id: r.get(0)?,
        investigation_id: r.get(1)?,
        project: r.get(2)?,
        resolved: r.get(3)?,
        confirmed_cause: r.get(4)?,
        note: r.get(5)?,
        source: r.get(6)?,
        payload: r.get(7)?,
        at: parse_ts(&r.get::<_, String>(8)?)?,
    })
}

/// Persist one outcome label (append-only). Errors on an invalid `resolved`/`source` so a bad
/// value never silently pollutes the eval set. Returns the inserted row.
pub async fn record_outcome_label(db: &DbHandle, input: OutcomeLabelInput) -> Result<OutcomeLabel> {
    if !is_outcome_resolved(&input.resolved) {
        return Err(anyhow!(
            "invalid resolved \"{}\" — expected one of {}",
            input.resolved,
            OUTCOME_RESOLVED.join("|")
        ));
    }
    if !is_outcome_source(&input.source) {
        return Err(anyhow!("invalid source \"{}\" — expected one of {}", input.source, OUTCOME_SOURCE.join("|")));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let at = input.at.map(|t| format_ts(&t));
    db.with_conn(move |c| {
        c.execute(
            "INSERT INTO outcome_label (id, investigation_id, resolved, source, confirmed_cause, note, project, payload, at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, COALESCE(?9, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))",
            params![
                id,
                input.investigation_id,
                input.resolved,
                input.source,
                input.confirmed_cause,
                input.note,
                input.project,
                input.payload,
                at,
            ],
        )?;
        let row = c.query_row(&format!("SELECT {COLUMNS} FROM outcome_label WHERE id = ?1"), params![id], |r| {
            Ok(row_to_label(r))
        })??;
        Ok(row)
    })
    .await
}

/// List outcome labels newest-first, filtered by any combination of investigation, project,
/// source, verdict and date range. With no options it returns the whole dataset (capped by `limit`).
pub async fn list_outcome_labels(db: &DbHandle, opts: OutcomeLabelQuery) -> Result<Vec<OutcomeLabel>> {
    let mut conditions: Vec<String> = Vec::new();
    let mut args: Vec<Value> = Vec::new();
    let mut push = |cond: &str, v: Value| {
        args.push(v);
        conditions.push(format!("{cond} ?{}", args.len()));
    };
    if let Some(v) = opts.investigation_id { push("investigation_id =", Value::Text(v)); }
    if let Some(v) = opts.project { push("project =", Value::Text(v)); }
    if let Some(v) = opts.source { push("source =", Value::Text(v)); }
    if let Some(v) = opts.resolved { push("resolved =", Value::Text(v)); }
    if let Some(v) = opts.since { push("at >=", Value::Text(format_ts(&v))); }
    if let Some(v) = opts.until { push("at <=", Value::Text(format_ts(&v))); }
    let where_clause = if conditions.is_empty() { String::new() } else { format!(" WHERE {}", conditions.join(" AND ")) };
    let limit_clause = match opts.limit {
        Some(n) => {
            args.push(Value::Integer(n));
            format!(" LIMIT ?{}", args.len())
        }
        None => String::new(),
    };
    db.with_conn(move |c| {
        let mut stmt = c.prepare(&format!("SELECT {COLUMNS} FROM outcome_label{where_clause} ORDER BY at DESC{limit_clause}"))?;
        let rows = stmt.query_map(params_from_iter(args), |r| Ok(row_to_label(r)))?;
        rows.map(|r| r?).collect()
    })
    .await
}

/// The current verdict for an investigation: the most recently attested label, or None.
pub async fn get_latest_outcome_label(db: &DbHandle, investigation_id: &str) -> Result<Option<OutcomeLabel>> {
    let investigation_id = investigation_id.to_string();
    db.with_conn(move |c| {
        let mut stmt = c.prepare(&format!(
            "SELECT {COLUMNS} FROM outcome_label WHERE investigation_id = ?1 ORDER BY at DESC LIMIT 1"
        ))?;
        let mut rows = stmt.query(params![investigation_id])?;
        match rows.next()? {
            Some(r) => Ok(Some(row_to_label(r)?)),
            None => Ok(None),
        }
    })
    .await
}

/// Horus's own measured hit-rate over the eval set. Pure (no DB).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeAccuracy {
    /// Distinct investigations that carry at least one verdict.
    pub evaluated: usize,
    /// Total label rows considered (the append-only history can exceed `evaluated`).
    pub attestations: usize,
    /// Counts over the CURRENT verdict (latest label) per investigation.
    pub counts: OutcomeCounts,
    /// Strict hit-rate: `yes / evaluated` (0 when nothing is evaluated).
    pub accuracy: f64,
    /// Partial-credit score: `(yes + 0.5·partly) / evaluated` (0 when nothing is evaluated).
    pub weighted_score: f64,
    /// Which entry point attested the CURRENT verdict, across investigations.
    pub by_source: OutcomeBySource,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct OutcomeCounts {
    pub yes: usize,
    pub partly: usize,
    pub no: usize,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct OutcomeBySource {
    pub feedback: usize,
    pub confirm: usize,
}

/// Collapse an append-only label set to the CURRENT verdict per investigation: the latest `at`,
/// tie-broken by greater `id` for determinism. A null `investigation_id` (legacy/unlinked) is
/// bucketed ALONE (keyed by its row id) so it never collapses with another investigation's verdict.
///
/// Order-independent. This is the single shared definition of "current verdict" — both
/// `summarize_outcome_labels` and the read-only eval harness use it, so they can never diverge.
pub fn dedupe_to_current_verdict(labels: &[OutcomeLabel]) -> Vec<OutcomeLabel> {
    let mut latest: HashMap<String, &OutcomeLabel> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for l in labels {
        let key = l.investigation_id.clone().unwrap_or_else(|| format!("__row_{}", l.id));
        match latest.get(&key) {
            Some(cur) if !(l.at > cur.at || (l.at == cur.at && l.id > cur.id)) => {}
            Some(_) => {
                latest.insert(key, l);
            }
            None => {
                order.push(key.clone());
                latest.insert(key, l);
            }
        }
    }
    // Map insertion order, like the JS Map iteration the TS returns.
    order.into_iter().map(|k| latest[&k].clone()).collect()
}

/// Collapse a set of outcome labels into an accuracy summary, deduped to the CURRENT verdict per
/// investigation so re-attesting never double-counts. `attestations` keeps the raw total.
pub fn summarize_outcome_labels(labels: &[OutcomeLabel]) -> OutcomeAccuracy {
    let latest = dedupe_to_current_verdict(labels);
    let mut counts = OutcomeCounts::default();
    let mut by_source = OutcomeBySource::default();
    for l in &latest {
        match l.resolved.as_str() {
            "yes" => counts.yes += 1,
            "partly" => counts.partly += 1,
            "no" => counts.no += 1,
            _ => {}
        }
        match l.source.as_str() {
            "feedback" => by_source.feedback += 1,
            "confirm" => by_source.confirm += 1,
            _ => {}
        }
    }
    let evaluated = latest.len();
    let denom = evaluated as f64;
    OutcomeAccuracy {
        evaluated,
        attestations: labels.len(),
        accuracy: if evaluated == 0 { 0.0 } else { counts.yes as f64 / denom },
        weighted_score: if evaluated == 0 { 0.0 } else { (counts.yes as f64 + 0.5 * counts.partly as f64) / denom },
        counts,
        by_source,
    }
}
