//! Generic `StateProvider` over any read-only `StateClient` (`database-provider.ts`).

use super::analyze::{state_to_evidence, StateAnalysis, DEFAULT_LEGACY_HOURS};
use super::provider::{analyze_state_with, AnalyzeStateOpts, AnalyzeStateWithOpts, StateClient, StateProvider};
use crate::contract::Provider;
use crate::jsutil::{now_iso, now_ms};
use anyhow::Result;
use async_trait::async_trait;
use horus_core::{Evidence, HealthStatus, ProviderKind};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseStateOpts {
    pub database: String,
    pub collections: Vec<String>,
    pub stale_hours: f64,
}

pub struct DatabaseStateProvider {
    id: String,
    client: Arc<dyn StateClient>,
    opts: DatabaseStateOpts,
}

impl DatabaseStateProvider {
    pub fn new(id: impl Into<String>, client: Arc<dyn StateClient>, opts: DatabaseStateOpts) -> Self {
        Self { id: id.into(), client, opts }
    }
}

#[async_trait]
impl Provider for DatabaseStateProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::State
    }
    async fn health(&self) -> HealthStatus {
        self.client.health().await
    }
}

#[async_trait]
impl StateProvider for DatabaseStateProvider {
    async fn analyze_state(&self, opts: AnalyzeStateOpts) -> Result<StateAnalysis> {
        analyze_state_with(
            self.client.as_ref(),
            &AnalyzeStateWithOpts {
                database: self.opts.database.clone(),
                collections: self.opts.collections.clone(),
                stale_hours: opts.stale_hours.unwrap_or(self.opts.stale_hours),
                legacy_hours: Some(opts.legacy_hours.unwrap_or(DEFAULT_LEGACY_HOURS)),
            },
            now_ms(),
        )
        .await
    }

    fn to_evidence(&self, analysis: &StateAnalysis) -> Vec<Evidence> {
        let prefix = if self.id == "mongodb" { "mongo" } else { self.id.as_str() };
        state_to_evidence(analysis, &format!("{prefix}.analyzeState"), &now_iso(), &[])
    }

    async fn list_collections(&self) -> Result<Option<Vec<String>>> {
        Ok(Some(self.client.list_collections().await?))
    }

    async fn close(&self) {
        self.client.close().await;
    }
}
