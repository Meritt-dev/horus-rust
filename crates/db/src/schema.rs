//! Horus database schema — row types for the tables this crate operates on, plus the
//! timestamp conventions every column of the SQLite port shares.
//!
//! Tables (identical names to the Postgres/Drizzle schema): projects, repositories,
//! investigations, evidence, findings, hypotheses, incident_memory, memory_item, memory_link,
//! memory_audit, memory_sync_*, outcome_label, queue_edges, provider_cache, watch_*. The DDL
//! lives in `migrations_bundle.rs`; tables without a Rust operation here are reached through
//! `DbHandle::with_conn` by their owning crate.
//!
//! JSON columns are `String` holding the JSON text exactly as written — saved investigation
//! payloads must round-trip byte-identically, so this crate never re-serialises them.

use anyhow::{anyhow, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use horus_core::QueueEdgeLike;
use serde::Serialize;

/// Format a timestamp the way every `timestamptz` column of the SQLite port stores it:
/// `YYYY-MM-DDTHH:MM:SS.mmmZ` (same shape as SQLite's `strftime('%Y-%m-%dT%H:%M:%fZ')`
/// default and as `Date#toISOString()`), so text ordering equals time ordering.
pub fn format_ts(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse a stored timestamp column.
pub fn parse_ts(text: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| anyhow!("invalid stored timestamp {text:?}: {e}"))
}

/// A single investigation run and its AI narrative (full `investigations` row).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Investigation {
    pub id: String,
    pub title: String,
    /// JSON text of the `InvestigationInput` (the replay payload), verbatim.
    pub incident_input: String,
    pub status: String,
    pub summary: Option<String>,
    /// JSON text, verbatim.
    pub narrative: Option<String>,
    /// JSON text of the persisted `InvestigationReport`, verbatim.
    pub report: Option<String>,
    /// Project label (nullable for back-compat); migration 0011 backfills from `incident_input.repo`.
    pub project: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert shape for `investigations` (what the engine's `persist` writes).
#[derive(Debug, Clone, Default)]
pub struct NewInvestigation {
    /// Omit to let the DB generate a v4 UUID.
    pub id: Option<String>,
    pub title: String,
    /// JSON text, stored verbatim.
    pub incident_input: String,
    /// Defaults to `"open"`.
    pub status: Option<String>,
    pub summary: Option<String>,
    pub narrative: Option<String>,
    pub report: Option<String>,
    pub project: Option<String>,
    /// Defaults to the DB clock.
    pub created_at: Option<DateTime<Utc>>,
}

/// The queue-boundary graph the stitcher synthesizes (full `queue_edges` row).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueEdge {
    pub id: String,
    pub queue_name: String,
    pub producer_symbol: Option<String>,
    pub producer_file: Option<String>,
    pub worker_symbol: Option<String>,
    pub worker_file: Option<String>,
    /// Who synthesized this edge (`stitcher`).
    pub source: String,
    pub project: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert shape for `queue_edges`.
#[derive(Debug, Clone, Default)]
pub struct NewQueueEdge {
    pub queue_name: String,
    pub producer_symbol: Option<String>,
    pub producer_file: Option<String>,
    pub worker_symbol: Option<String>,
    pub worker_file: Option<String>,
    /// Defaults to `"stitcher"`.
    pub source: Option<String>,
    pub project: Option<String>,
}

impl QueueEdgeLike for QueueEdge {
    fn queue_name(&self) -> &str { &self.queue_name }
    fn producer_symbol(&self) -> Option<&str> { self.producer_symbol.as_deref() }
    fn producer_file(&self) -> Option<&str> { self.producer_file.as_deref() }
    fn worker_symbol(&self) -> Option<&str> { self.worker_symbol.as_deref() }
    fn worker_file(&self) -> Option<&str> { self.worker_file.as_deref() }
}

impl QueueEdgeLike for NewQueueEdge {
    fn queue_name(&self) -> &str { &self.queue_name }
    fn producer_symbol(&self) -> Option<&str> { self.producer_symbol.as_deref() }
    fn producer_file(&self) -> Option<&str> { self.producer_file.as_deref() }
    fn worker_symbol(&self) -> Option<&str> { self.worker_symbol.as_deref() }
    fn worker_file(&self) -> Option<&str> { self.worker_file.as_deref() }
}

/// Outcome-label / eval store row (HOR-390). Append-only: one row per attestation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeLabel {
    pub id: String,
    pub investigation_id: Option<String>,
    pub project: Option<String>,
    /// `yes` | `partly` | `no`.
    pub resolved: String,
    pub confirmed_cause: Option<String>,
    pub note: Option<String>,
    /// `feedback` | `confirm`.
    pub source: String,
    /// JSON text, verbatim.
    pub payload: Option<String>,
    pub at: DateTime<Utc>,
}
