//! Shared state-provider contract (HOR-33 / HOR-CONNECTORS). A "state provider"
//! surfaces application STATE anomalies (stale sync records, failed/stuck states)
//! as Evidence — never raw records. MongoDB and Postgres both implement it; the
//! analysis loop is shared via `analyze_state_with` so each provider only supplies a
//! read-only `StateClient`.

use super::analyze::{
    age_hours_of, classify_age, is_anomalous_status, pick_field, Classification, CollectionState, StateAnalysis,
    StatusCount, DATE_FIELDS, DEFAULT_LEGACY_HOURS, STATUS_FIELDS,
};
use super::record_query::StateRecordQuery;
use crate::contract::Provider;
use anyhow::Result;
use async_trait::async_trait;
use horus_core::{Evidence, HealthStatus};

/// `analyzeState(opts)` overrides.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct AnalyzeStateOpts {
    pub stale_hours: Option<f64>,
    pub legacy_hours: Option<f64>,
}

#[async_trait]
pub trait StateProvider: Provider {
    async fn analyze_state(&self, opts: AnalyzeStateOpts) -> Result<StateAnalysis>;
    fn to_evidence(&self, analysis: &StateAnalysis) -> Vec<Evidence>;
    /// List containers (collections/tables) in the configured database.
    /// `None` = not supported by this provider (TS optional method).
    async fn list_collections(&self) -> Result<Option<Vec<String>>> {
        Ok(None)
    }
    /// Bounded, projected, equality-only record reads where supported (`None` otherwise).
    async fn query_records(&self, _query: &StateRecordQuery) -> Result<Option<Vec<Evidence>>> {
        Ok(None)
    }
    /// Close the underlying connection so the process can exit.
    async fn close(&self);
}

/// Read-only datastore access used by `analyze_state_with`. Method names are storage-
/// neutral despite the Mongo lineage: for Postgres, `list_collections` returns tables
/// and `sample_fields` returns column names. There is no write surface here.
/// (`health`/`close` live here too — TS intersects them onto the client type.)
#[async_trait]
pub trait StateClient: Send + Sync {
    /// Container names in the database (collections / tables), for auto-discovery.
    async fn list_collections(&self) -> Result<Vec<String>>;
    /// Record count for a container.
    async fn count(&self, container: &str) -> Result<i64>;
    /// Field/column names for a container (for date/status field detection).
    async fn sample_fields(&self, container: &str) -> Result<Vec<String>>;
    /// ISO timestamp of the newest value of a date field, or None.
    async fn max_date(&self, container: &str, field: &str) -> Result<Option<String>>;
    /// Record counts grouped by a string field (top values).
    async fn group_by(&self, container: &str, field: &str) -> Result<Vec<StatusCount>>;
    async fn health(&self) -> HealthStatus;
    async fn close(&self);
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzeStateWithOpts {
    pub database: String,
    pub collections: Vec<String>,
    pub stale_hours: f64,
    pub legacy_hours: Option<f64>,
}

/// Shared analysis loop: count + date-age + status-bucket each container, classify
/// staleness, and flag anomalous status buckets. A single bad/missing container is
/// skipped, never aborting the whole analysis — but when EVERY container fails the
/// first error is rethrown: a completely-down database must reach the engine as a
/// failure, not as a clean empty analysis. (Auto-discovery already throws on a down
/// DB via list_collections.)
pub async fn analyze_state_with(client: &dyn StateClient, opts: &AnalyzeStateWithOpts, now_ms: i64) -> Result<StateAnalysis> {
    let stale_hours = opts.stale_hours;
    let legacy_hours = opts.legacy_hours.unwrap_or(DEFAULT_LEGACY_HOURS);
    let mut collections: Vec<CollectionState> = Vec::new();
    let mut first_error: Option<anyhow::Error> = None;

    let mut targets = opts.collections.clone();
    let mut auto_discovered = false;
    if targets.is_empty() {
        targets = client.list_collections().await?;
        auto_discovered = true;
    }

    for coll in &targets {
        match inspect(client, coll, stale_hours, legacy_hours, now_ms).await {
            Ok(cs) => collections.push(cs),
            // A single bad/missing container must not abort the whole analysis.
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }

    if !targets.is_empty() && collections.is_empty() {
        if let Some(err) = first_error {
            return Err(err);
        }
    }
    Ok(StateAnalysis {
        database: opts.database.clone(),
        stale_hours,
        legacy_hours,
        collections,
        auto_discovered: Some(auto_discovered),
    })
}

async fn inspect(client: &dyn StateClient, coll: &str, stale_hours: f64, legacy_hours: f64, now_ms: i64) -> Result<CollectionState> {
    let count = client.count(coll).await?;
    let fields = client.sample_fields(coll).await?;
    let mut cs = CollectionState {
        collection: coll.to_string(),
        count,
        classification: Classification::Unknown,
        anomalies: Vec::new(),
        date_field: None,
        last_activity: None,
        age_hours: None,
        is_stale: None,
        status_field: None,
        status_counts: None,
    };

    if let Some(date_field) = pick_field(&fields, DATE_FIELDS) {
        if let Some(last) = client.max_date(coll, &date_field).await? {
            let age = age_hours_of(&last, now_ms);
            cs.date_field = Some(date_field);
            cs.last_activity = Some(last);
            cs.age_hours = Some(age);
            cs.is_stale = Some(age > stale_hours);
        }
    }
    cs.classification = classify_age(cs.age_hours, stale_hours, legacy_hours);

    if let Some(status_field) = pick_field(&fields, STATUS_FIELDS) {
        let counts = client.group_by(coll, &status_field).await?;
        cs.status_field = Some(status_field);
        cs.anomalies = counts.iter().filter(|c| is_anomalous_status(&c.value)).cloned().collect();
        cs.status_counts = Some(counts);
    }

    Ok(cs)
}
