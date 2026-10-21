//! Shopify Admin evidence provider (HOR-CONNECTORS).
//!
//! Shopify admin/business data is application state, so each configured/supplied query
//! becomes one `kind: 'state'` Evidence (or `'log'`/`'metric'` when the query declares it).
//!
//! The provider embeds NO queries. `collect()` runs the GraphQL documents it is HANDED — from
//! the caller at investigation time (`--shopify-query`) or, when none are supplied, the
//! config-declared defaults (`connectors.shopify.queries[]`, used by `horus watch`).
//!
//! Privacy: the title is redacted. priority / category / subject are NOT set here — the
//! normalization layer stamps those.

use async_trait::async_trait;
use horus_core::{
    redact_secrets, Evidence, EvidenceKind, EvidenceLinks, HealthStatus, Provenance, ProviderKind, ShopifyQueryKind,
    ShopifyQuerySpec,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::client::ShopifyAdminClient;
use crate::contract::Provider;
use crate::jsutil::{now_iso, short_ts};

#[derive(Debug, Clone)]
pub struct ShopifyProviderOpts {
    /// Store domain — used for evidence provenance + title.
    pub store: String,
    /// Default queries run when the caller supplies none (e.g. `horus watch`).
    pub queries: Option<Vec<ShopifyQuerySpec>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShopifyRecordError {
    pub message: String,
}

/// The result of running one Shopify query, before it becomes Evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShopifyRecord {
    /// Query label (provenance + title).
    pub name: String,
    /// EvidenceKind the result maps onto.
    pub kind: ShopifyQueryKind,
    /// The GraphQL `data` payload, verbatim.
    pub data: Value,
    /// Base relevance seed from config, before hint-term weighting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relevance: Option<f64>,
    /// GraphQL-level errors, when the query returned any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ShopifyRecordError>>,
    /// The `extensions.cost` block, for rate-budget visibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<Value>,
    /// Collection timestamp (window end).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ShopifyCollectOpts {
    pub from: Option<String>,
    pub to: Option<String>,
    pub hint_terms: Vec<String>,
    pub queries: Option<Vec<ShopifyQuerySpec>>,
    /// Only used by `query_evidence`.
    pub collected_at: Option<String>,
}

/// Map a per-query EvidenceKind onto the ProviderKind (`source`) it belongs to.
fn kind_to_source(kind: ShopifyQueryKind) -> ProviderKind {
    match kind {
        ShopifyQueryKind::State => ProviderKind::State,
        ShopifyQueryKind::Log => ProviderKind::Logs,
        ShopifyQueryKind::Metric => ProviderKind::Metrics,
    }
}

fn kind_to_evidence(kind: ShopifyQueryKind) -> EvidenceKind {
    match kind {
        ShopifyQueryKind::State => EvidenceKind::State,
        ShopifyQueryKind::Log => EvidenceKind::Log,
        ShopifyQueryKind::Metric => EvidenceKind::Metric,
    }
}

pub struct ShopifyProvider {
    client: ShopifyAdminClient,
    opts: ShopifyProviderOpts,
}

impl ShopifyProvider {
    pub fn new(client: ShopifyAdminClient, opts: ShopifyProviderOpts) -> Self {
        Self { client, opts }
    }

    /// Run each supplied (or, as a fallback, config-declared) query verbatim and return one
    /// record per success. The window is injected as `$from`/`$to` for queries that opt in
    /// (`bind_window`). A single failing query is dropped, but when EVERY query fails the
    /// first error is returned — a total outage must reach the engine as a failure.
    pub async fn collect(&self, opts: &ShopifyCollectOpts) -> anyhow::Result<Vec<ShopifyRecord>> {
        let specs: Vec<ShopifyQuerySpec> = match &opts.queries {
            Some(q) if !q.is_empty() => q.clone(),
            _ => self.opts.queries.clone().unwrap_or_default(),
        };
        if specs.is_empty() {
            return Ok(vec![]);
        }
        let to = opts.to.clone().unwrap_or_else(now_iso);
        let from = opts.from.as_deref();
        let to = to.as_str();

        let results = futures::future::join_all(specs.iter().map(|q| async move {
            let vars = bind_window_vars(q, from, Some(to));
            self.client.graphql(&q.query, Some(&vars)).await.map(|result| ShopifyRecord {
                name: q.name.clone(),
                kind: q.kind,
                data: result.data.unwrap_or(Value::Null),
                relevance: q.relevance,
                // GraphQL error text is upstream-controlled and lands in the evidence payload.
                errors: result.errors.filter(|e| !e.is_empty()).map(|errs| {
                    errs.iter().map(|e| ShopifyRecordError { message: redact_secrets(&e.message) }).collect()
                }),
                cost: result.extensions.and_then(|e| e.cost).map(|c| serde_json::to_value(c).unwrap_or(Value::Null)),
                timestamp: Some(to.to_string()),
            })
        }))
        .await;

        let mut first_error = None;
        let mut ok = Vec::new();
        for r in results {
            match r {
                Ok(rec) => ok.push(rec),
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        match (ok.is_empty(), first_error) {
            (true, Some(err)) => Err(err),
            _ => Ok(ok),
        }
    }

    /// Synthesize one Evidence per record. Preserves per-query provenance.
    pub fn to_evidence(&self, records: &[ShopifyRecord], hint_terms: &[String], collected_at: &str) -> Vec<Evidence> {
        records
            .iter()
            .enumerate()
            .map(|(i, rec)| self.record_to_evidence(rec, hint_terms, collected_at, i))
            .collect()
    }

    /// One-shot evidence query: collect + convert. Degrades to [] on any failure so a flaky
    /// Shopify never aborts an investigation.
    pub async fn query_evidence(&self, opts: &ShopifyCollectOpts) -> Vec<Evidence> {
        match self.collect(opts).await {
            Ok(records) => {
                let collected_at = opts.collected_at.clone().unwrap_or_else(now_iso);
                self.to_evidence(&records, &opts.hint_terms, &collected_at)
            }
            Err(_) => vec![],
        }
    }

    fn record_to_evidence(&self, rec: &ShopifyRecord, hint_terms: &[String], collected_at: &str, index: usize) -> Evidence {
        let mut payload = Map::new();
        payload.insert("source".into(), json!("shopify"));
        payload.insert("shop".into(), json!(self.opts.store));
        payload.insert("queryName".into(), json!(rec.name));
        payload.insert("data".into(), rec.data.clone());
        if let Some(c) = &rec.cost {
            payload.insert("cost".into(), c.clone());
        }
        if let Some(e) = &rec.errors {
            payload.insert("errors".into(), json!(e));
        }
        Evidence {
            id: format!("ev_shopify_{index}"),
            source: kind_to_source(rec.kind),
            kind: kind_to_evidence(rec.kind),
            title: build_title(rec, &self.opts.store),
            timestamp: rec.timestamp.clone(),
            relevance: compute_relevance(rec, hint_terms),
            payload: Value::Object(payload),
            links: EvidenceLinks::default(),
            provenance: Provenance {
                query: format!("shopify {} {}", self.opts.store, rec.name),
                collected_at: collected_at.to_string(),
            },
            priority: None,
            category: None,
            subject: None,
            is_new: None,
            ratio: None,
        }
    }
}

#[async_trait]
impl Provider for ShopifyProvider {
    fn id(&self) -> &str {
        "shopify"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::State
    }
    async fn health(&self) -> HealthStatus {
        self.client.health().await
    }
}

/// Merge static query variables with the injected `$from`/`$to` window (opt-in per query).
fn bind_window_vars(q: &ShopifyQuerySpec, from: Option<&str>, to: Option<&str>) -> Map<String, Value> {
    let mut base = q.variables.clone().unwrap_or_default();
    if q.bind_window != Some(true) {
        return base;
    }
    if let Some(f) = from {
        base.insert("from".into(), json!(f));
    }
    if let Some(t) = to {
        base.insert("to".into(), json!(t));
    }
    base
}

/// Build the human one-line title: store, query name, a short result summary (edge/node
/// count or the first GraphQL error), and a short timestamp. Redacted.
pub fn build_title(rec: &ShopifyRecord, store: &str) -> String {
    let ts = rec.timestamp.as_deref().filter(|t| !t.is_empty()).map(|t| format!(" · {}", short_ts(t))).unwrap_or_default();
    redact_secrets(&format!("Shopify {store} {}: {}{ts}", rec.name, summarize(rec))).chars().take(220).collect()
}

/// One-line summary of a query result: "N results", the first error, or "ok".
fn summarize(rec: &ShopifyRecord) -> String {
    if let Some(first) = rec.errors.as_ref().and_then(|e| e.first()) {
        return format!("error: {}", first.message);
    }
    match count_results(&rec.data) {
        Some(count) => format!("{count} result{}", if count == 1 { "" } else { "s" }),
        None => "ok".to_string(),
    }
}

/// Sum the sizes of any top-level GraphQL connections (`edges`/`nodes`), or None if none.
fn count_results(data: &Value) -> Option<usize> {
    let obj = data.as_object()?;
    let mut total = 0;
    let mut found = false;
    for value in obj.values() {
        let Some(conn) = value.as_object() else { continue };
        if let Some(edges) = conn.get("edges").and_then(Value::as_array) {
            total += edges.len();
            found = true;
        } else if let Some(nodes) = conn.get("nodes").and_then(Value::as_array) {
            total += nodes.len();
            found = true;
        }
    }
    found.then_some(total)
}

/// Relevance-weight a record: the config seed (default 0.6) plus a bump when a hint term
/// appears anywhere in the result. Clamped 0.5–0.95.
pub fn compute_relevance(rec: &ShopifyRecord, hint_terms: &[String]) -> f64 {
    let mut score = rec.relevance.unwrap_or(0.6);
    let data = if rec.data.is_null() { json!({}) } else { rec.data.clone() };
    let hay = serde_json::to_string(&data).unwrap_or_default().to_lowercase();
    if hint_terms.iter().filter(|t| t.len() > 2).any(|t| hay.contains(&t.to_lowercase())) {
        score += 0.2;
    }
    score.clamp(0.5, 0.95)
}
