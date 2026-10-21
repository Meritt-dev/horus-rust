//! Provider contracts for horus-connectors.
//!
//! `Provider` is the base trait shared by every data-source adapter.
//! `CodeProvider` extends it with all code-graph operations backed by source intelligence.

use anyhow::Result;
use async_trait::async_trait;
use horus_core::{ChangeSet, CypherResult, Flow, HealthStatus, ImpactResult, ProviderKind, Symbol, SymbolContext};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimal interface every provider must satisfy.
#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &str;
    fn kind(&self) -> ProviderKind;
    async fn health(&self) -> HealthStatus;
}

/// `{ base, compare }` refs for `detect_changes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRange {
    pub base: String,
    pub compare: String,
}

/// Aggregate node counts by label (GET /api/overview).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeOverview {
    pub nodes_by_label: indexmap::IndexMap<String, i64>,
}

/// Community cluster (Louvain) with member count; `members` (node ids) lets the engine
/// detect docs/example-dominated clusters by path.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeCommunity {
    pub name: String,
    pub member_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeProcessStep {
    pub node_id: String,
}

/// Discovered execution process (GET /api/processes).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeProcess {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<CodeProcessStep>>,
}

/// Dead-code report — the engine consumes `total` (GET /api/dead-code).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeadCodeSummary {
    pub total: i64,
}

/// Temporal coupling pair — the engine counts `co_changes >= 3` (GET /api/coupling).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CouplingPair {
    pub co_changes: i64,
}

/// Full contract for a code-graph provider (source intelligence).
///
/// The TS optional methods (`classMethods?`, `overview?`, …) are modelled as methods
/// with a default body returning `Ok(None)` ("not supported"); the engine degrades
/// per-section when one is absent.
#[async_trait]
pub trait CodeProvider: Provider {
    async fn search_symbols(&self, query: &str, limit: Option<usize>) -> Result<Vec<Symbol>>;
    async fn context(&self, symbol_id: &str) -> Result<SymbolContext>;
    /// Product-only by default; `include_tests` restores test/docs/example callers.
    async fn impact(&self, symbol_id: &str, depth: Option<usize>, include_tests: Option<bool>) -> Result<ImpactResult>;
    async fn flows_for(&self, symbol_id: &str, include_tests: Option<bool>) -> Result<Vec<Flow>>;
    /// Method symbols of a class, for class-seed walkthroughs (typed /api/class-methods).
    async fn class_methods(&self, _file: &str, _class_name: &str) -> Result<Option<Vec<Symbol>>> {
        Ok(None)
    }
    async fn detect_changes(&self, diff: &DiffRange) -> Result<ChangeSet>;
    async fn cypher(&self, query: &str) -> Result<CypherResult>;

    // Typed read-path methods for architecture discovery (HOR-392 follow-up). The engine's
    // `discoverArchitecture` previously emitted raw Cypher through `cypher()`, which the
    // SQLite console rejects — every query silently failed and `horus architecture` rendered
    // empty on every repo. These are the REST-backed replacements; optional because
    // they're additive, and the engine degrades per-section when one is absent.

    async fn overview(&self) -> Result<Option<CodeOverview>> {
        Ok(None)
    }
    async fn communities(&self) -> Result<Option<Vec<CodeCommunity>>> {
        Ok(None)
    }
    async fn processes(&self) -> Result<Option<Vec<CodeProcess>>> {
        Ok(None)
    }
    async fn dead_code(&self) -> Result<Option<DeadCodeSummary>> {
        Ok(None)
    }
    async fn coupling(&self) -> Result<Option<Vec<CouplingPair>>> {
        Ok(None)
    }
    /// Per-token distinct file paths containing the token (POST /api/content-search filesOnly).
    async fn files_containing(&self, _tokens: &[String], _limit: Option<usize>) -> Result<Option<HashMap<String, Vec<String>>>> {
        Ok(None)
    }
}
