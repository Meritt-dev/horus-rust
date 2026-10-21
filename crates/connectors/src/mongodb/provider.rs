//! MongoDB `StateProvider` (`mongodb/provider.ts`): the shared database provider plus
//! targeted record lookups.

use super::client::MongoStateClient;
use crate::contract::Provider;
use crate::jsutil::now_iso;
use crate::state::analyze::StateAnalysis;
use crate::state::database_provider::{DatabaseStateOpts, DatabaseStateProvider};
use crate::state::provider::{AnalyzeStateOpts, StateProvider};
use crate::state::record_query::{validate_state_record_query, StateRecordQuery};
use anyhow::Result;
use async_trait::async_trait;
use horus_core::{Evidence, EvidenceKind, EvidenceLinks, HealthStatus, ProviderKind, Provenance};
use serde_json::json;
use std::sync::Arc;

pub struct MongoStateProvider {
    inner: DatabaseStateProvider,
    record_client: Arc<MongoStateClient>,
}

impl MongoStateProvider {
    pub fn new(record_client: Arc<MongoStateClient>, opts: DatabaseStateOpts) -> Self {
        Self { inner: DatabaseStateProvider::new("mongodb", record_client.clone(), opts), record_client }
    }
}

#[async_trait]
impl Provider for MongoStateProvider {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::State
    }
    async fn health(&self) -> HealthStatus {
        self.inner.health().await
    }
}

#[async_trait]
impl StateProvider for MongoStateProvider {
    async fn analyze_state(&self, opts: AnalyzeStateOpts) -> Result<StateAnalysis> {
        self.inner.analyze_state(opts).await
    }

    fn to_evidence(&self, analysis: &StateAnalysis) -> Vec<Evidence> {
        self.inner.to_evidence(analysis)
    }

    async fn list_collections(&self) -> Result<Option<Vec<String>>> {
        self.inner.list_collections().await
    }

    async fn query_records(&self, query: &StateRecordQuery) -> Result<Option<Vec<Evidence>>> {
        validate_state_record_query(query)?;
        let records = self.record_client.records(query).await?;
        let collected_at = now_iso();
        Ok(Some(vec![Evidence {
            id: "ev_mongo_records".to_string(),
            source: ProviderKind::State,
            kind: EvidenceKind::State,
            title: format!("Targeted {} lookup: {} record(s)", query.collection, records.len()),
            timestamp: None,
            relevance: 0.0,
            payload: json!({ "collection": query.collection, "records": records }),
            links: EvidenceLinks::default(),
            provenance: Provenance { query: serde_json::to_string(query)?, collected_at },
            priority: None,
            category: None,
            subject: None,
            is_new: None,
            ratio: None,
        }]))
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}
