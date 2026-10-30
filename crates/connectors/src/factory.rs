//! ConnectorFactory (`factory.ts`) — wires a `HorusConfig` or a `ResolvedEnvironment`
//! into live provider instances.
//!
//! HOR-34: the primary API is environment-scoped (`code_for_env`, `logs_for_env`,
//! `metrics_for_env`, …). The old global helpers (`code_for_repo`,
//! `logs_provider_from_config`, `metrics_provider_from_config`, `repo_providers`,
//! `create_connectors`, `source_host_url_for_repo`) are kept as thin compat wrappers.
//!
//! TS builders that may throw (ES field-mapping validation, config schema parses, Redis
//! URL parsing) return `Result` here; "not configured" stays `Ok(None)` / `Ok(vec![])`.

use anyhow::{bail, Result};
use horus_core::{
    redis_url_for_db, resolve_environment, EsPreset, HorusConfig, RedisRole, ResolveOptions, ResolvedElasticsearchFields,
    ResolvedEnvironment, ResolvedRedisDatabase, REDIS_QUEUE_ROLES,
};
use std::sync::Arc;

use crate::axiom::{AxiomClient, AxiomClientOpts, AxiomProvider, AxiomProviderOpts};
use crate::bullmq::{BullMQClientOpts, BullMQRedisClient};
use crate::bullmq::BullMQRuntimeProvider;
use crate::cloud_logs::{CloudLogConfig, CloudLogsProvider};
use crate::elasticsearch::{
    ElasticsearchClient, ElasticsearchClientOpts, ElasticsearchFieldMapping, ElasticsearchLogsProvider, ElasticsearchLogsProviderOpts,
    ECS_FIELD_MAPPING, MERITT_FIELD_MAPPING,
};
use crate::firestore::FirestoreStateClient;
use crate::grafana::{GrafanaClient, GrafanaClientOpts, GrafanaMetricsProvider, GrafanaMetricsProviderOpts, MetricsProvider};
use crate::http::HttpRequestOptions;
use crate::lens::{LensClientOpts, LensCloudClient};
use crate::lens::{LensProvider, LensProviderOpts};
use crate::mongodb::{MongoClientOpts, MongoStateClient};
use crate::mongodb::MongoStateProvider;
use crate::postgres::{PostgresClientOpts, PostgresStateClient};
use crate::prometheus::PrometheusMetricsProvider;
use crate::redis::{RedisStateDb, RedisStateRuntimeProvider, RedisStateScan};
use crate::runtime_queue::{KafkaQueueProvider, QueueEvidenceProvider, ServiceBusQueueProvider};
use crate::sentry::{SentryClient, SentryClientOpts, SentryProvider, SentryProviderOpts};
use crate::shopify::{ShopifyAdminClient, ShopifyClientOpts};
use crate::shopify::{ShopifyProvider, ShopifyProviderOpts};
use crate::source::{SourceClientOptions, SourceHttpClient};
use crate::source::{MemoryVectorIndexLike, SourceMemoryVectorIndex, SourceMemoryVectorIndexOptions};
use crate::source::SourceCodeProvider;
#[cfg(feature = "sqlserver")]
use crate::sqlserver::SqlServerStateClient;
use crate::state::{DatabaseStateOpts, DatabaseStateProvider};

fn source_client(host_url: &str) -> SourceHttpClient {
    SourceHttpClient::new(SourceClientOptions::new(host_url))
}

// ---------------------------------------------------------------------------
// Environment-scoped builders (primary API, HOR-34)
// ---------------------------------------------------------------------------

/// A source `CodeProvider` for the resolved environment, or None when no source
/// connector is configured.
pub fn code_for_env(renv: &ResolvedEnvironment) -> Option<SourceCodeProvider> {
    let host_url = renv.repositories.first()?.source_host_url.as_deref().filter(|u| !u.is_empty())?;
    Some(SourceCodeProvider::new(source_client(host_url)))
}

/// A source `CodeProvider` pointed at an explicit host URL (HOR-421: ground on this
/// repo's OWN host when the configured port is occupied by another repo's host).
pub fn code_for_url(host_url: &str) -> SourceCodeProvider {
    SourceCodeProvider::new(source_client(host_url))
}

/// Source-host-backed memory vector index (M2). Host configured → Source index that
/// degrades to `fallback`; host not configured → `fallback` itself (None when absent).
/// Memory vectors are LOCAL-ONLY; this never participates in any cloud-sync path.
pub fn memory_index_for_env(renv: &ResolvedEnvironment, fallback: Option<Arc<dyn MemoryVectorIndexLike>>) -> Option<Arc<dyn MemoryVectorIndexLike>> {
    match renv.repositories.first().and_then(|r| r.source_host_url.as_deref()).filter(|u| !u.is_empty()) {
        None => fallback,
        Some(host_url) => Some(Arc::new(SourceMemoryVectorIndex::new(source_client(host_url), SourceMemoryVectorIndexOptions { fallback }))),
    }
}

fn apply_field_overrides(base: &ElasticsearchFieldMapping, o: &ResolvedElasticsearchFields) -> ElasticsearchFieldMapping {
    let mut m = base.clone();
    if let Some(v) = &o.timestamp {
        m.timestamp_field = v.clone();
    }
    if let Some(v) = &o.level {
        m.level_field = v.clone();
    }
    if let Some(v) = o.level_format {
        m.level_format = v;
    }
    if let Some(v) = &o.service {
        m.service_field = v.clone();
    }
    if let Some(v) = o.service_keyword {
        m.service_keyword = v;
    }
    if let Some(v) = &o.message {
        m.message_field = v.clone();
    }
    if let Some(v) = &o.message_fallback {
        m.message_fallback_field = Some(v.clone());
    }
    if let Some(v) = &o.trace_id {
        m.trace_id_field = Some(v.clone());
    }
    if let Some(v) = &o.request_id {
        m.request_id_field = Some(v.clone());
    }
    if let Some(v) = &o.event_code {
        m.event_code_field = v.clone();
    }
    if let Some(v) = o.event_code_keyword {
        m.event_code_keyword = v;
    }
    if let Some(v) = &o.detail {
        m.detail_fields = v.clone();
    }
    m
}

// Query endpoints run heavy work (ES aggregations that auto-widen to 30d, Grafana
// datasource-proxy queries bounded by the engine's 30s metrics budget). The shared
// HTTP helper's 8s default is sized for point requests — matched to the engine budget.
const QUERY_TIMEOUT_MS: u64 = 30_000;

/// An Elasticsearch `LogsProvider`, or None when ES is not (or incompletely) configured.
/// Errors when the configured field mapping is invalid.
pub fn logs_for_env(renv: &ResolvedEnvironment) -> Result<Option<ElasticsearchLogsProvider>> {
    let Some(es) = renv.connectors.elasticsearch.as_ref().filter(|es| !es.url.is_empty()) else { return Ok(None) };
    let base = if es.preset == EsPreset::Ecs { &*ECS_FIELD_MAPPING } else { &*MERITT_FIELD_MAPPING };
    let field_mapping = match &es.fields {
        Some(f) => apply_field_overrides(base, f),
        None => base.clone(),
    };
    let client = ElasticsearchClient::new(ElasticsearchClientOpts {
        base_url: es.url.clone(),
        username: es.username.clone(),
        password: es.password.clone(),
        http: Some(HttpRequestOptions::with_timeout_ms(QUERY_TIMEOUT_MS)),
    });
    Ok(Some(ElasticsearchLogsProvider::new(client, ElasticsearchLogsProviderOpts { index_pattern: es.index_pattern.clone(), field_mapping: Some(field_mapping) })?))
}

/// A Grafana `MetricsProvider`; falls back to direct Prometheus when Grafana is absent.
pub fn metrics_for_env(renv: &ResolvedEnvironment) -> Result<Option<Box<dyn MetricsProvider>>> {
    let Some(g) = renv.connectors.grafana.as_ref().filter(|g| g.url.as_deref().is_some_and(|u| !u.is_empty())) else {
        return Ok(match &renv.connectors.prometheus {
            Some(p) => Some(Box::new(PrometheusMetricsProvider::new(p.clone())?)),
            None => None,
        });
    };
    let client = GrafanaClient::new(GrafanaClientOpts {
        base_url: g.url.clone().unwrap_or_default(),
        username: g.username.clone(),
        password: g.password.clone(),
        http: Some(HttpRequestOptions::with_timeout_ms(QUERY_TIMEOUT_MS)),
    });
    Ok(Some(Box::new(GrafanaMetricsProvider::new(client, GrafanaMetricsProviderOpts { default_step: 60.0, dashboard_uids: g.dashboards.clone() }))))
}

/// Does `db` carry any of `roles`?
fn db_has_role(db: &ResolvedRedisDatabase, roles: &[RedisRole]) -> bool {
    db.roles.iter().any(|r| roles.contains(r))
}

/// The Redis logical DB that holds BullMQ queues (HOR-201): a DB tagged `bullmq`/`queues`,
/// else the sole configured DB (legacy single-URL config).
pub fn queue_database_for_env(renv: &ResolvedEnvironment) -> Option<&ResolvedRedisDatabase> {
    let dbs = &renv.connectors.redis.as_ref()?.databases;
    dbs.iter().find(|d| db_has_role(d, REDIS_QUEUE_ROLES)).or(if dbs.len() == 1 { dbs.first() } else { None })
}

/// Resolved DBs tagged with any state role — cache/state/locks/rate-limit/session/dedupe.
const STATE_ROLES: &[RedisRole] = &[RedisRole::Cache, RedisRole::State, RedisRole::Locks, RedisRole::RateLimit, RedisRole::Session, RedisRole::Dedupe];

pub fn state_databases_for_env(renv: &ResolvedEnvironment) -> Vec<&ResolvedRedisDatabase> {
    renv.connectors.redis.iter().flat_map(|r| r.databases.iter()).filter(|d| db_has_role(d, STATE_ROLES)).collect()
}

/// A Redis state-evidence provider for the env's state DBs (counts only, never values),
/// or None when none are configured.
pub fn redis_state_for_env(renv: &ResolvedEnvironment) -> Option<RedisStateRuntimeProvider> {
    let base_url = renv.connectors.redis.as_ref()?.url.as_deref().filter(|u| !u.is_empty())?;
    let state_dbs = state_databases_for_env(renv);
    if state_dbs.is_empty() {
        return None;
    }
    Some(RedisStateRuntimeProvider::new(
        state_dbs
            .into_iter()
            .map(|d| RedisStateDb {
                db: d.db,
                name: d.name.clone(),
                roles: d.roles.clone(),
                url: redis_url_for_db(base_url, d.db),
                scan: d.scan.as_ref().map(|s| RedisStateScan { sample_limit: s.sample_limit, patterns: s.patterns.clone() }),
            })
            .collect(),
    ))
}

/// A BullMQ `QueueRuntimeProvider` on the queue DB with its configured prefix, or None.
pub fn queue_for_env(renv: &ResolvedEnvironment) -> Result<Option<BullMQRuntimeProvider>> {
    let Some(url) = renv.connectors.redis.as_ref().and_then(|r| r.url.as_deref()).filter(|u| !u.is_empty()) else { return Ok(None) };
    let Some(queue_db) = queue_database_for_env(renv) else { return Ok(None) };
    let client = BullMQRedisClient::new(BullMQClientOpts { url: redis_url_for_db(url, queue_db.db), prefix: Some(queue_db.bullmq_prefix.clone()) })?;
    Ok(Some(BullMQRuntimeProvider::new(client)))
}

/// A MongoDB `StateProvider` (read-only, allowlisted collections), or None when no URL.
pub fn mongo_for_env(renv: &ResolvedEnvironment) -> Option<MongoStateProvider> {
    let m = renv.connectors.mongodb.as_ref()?;
    let url = m.url.as_deref().filter(|u| !u.is_empty())?;
    if m.database.is_empty() {
        return None;
    }
    let client = MongoStateClient::new(MongoClientOpts { url: url.to_string(), database: m.database.clone(), allowlist: m.collections.clone() });
    Some(MongoStateProvider::new(Arc::new(client), DatabaseStateOpts { database: m.database.clone(), collections: m.collections.clone(), stale_hours: 24.0 }))
}

/// A Postgres `StateProvider` (read-only, allowlisted tables), or None when no URL.
pub fn postgres_for_env(renv: &ResolvedEnvironment) -> Option<DatabaseStateProvider> {
    let p = renv.connectors.postgres.as_ref()?;
    let url = p.url.as_deref().filter(|u| !u.is_empty())?;
    let client = PostgresStateClient::new(PostgresClientOpts { url: url.to_string(), schema: p.schema.clone(), allowlist: p.tables.clone() });
    let database = p.database.clone().or_else(|| p.schema.clone()).unwrap_or_else(|| "postgres".into());
    Some(DatabaseStateProvider::postgres(client, DatabaseStateOpts { database, collections: p.tables.clone(), stale_hours: 24.0 }))
}

/// A Sentry error-evidence provider, or None when token / org / project is missing.
pub fn sentry_for_env(renv: &ResolvedEnvironment) -> Option<SentryProvider> {
    let s = renv.connectors.sentry.as_ref()?;
    let token = s.auth_token.as_deref().filter(|t| !t.is_empty())?;
    if s.org.is_empty() || s.project.is_empty() {
        return None;
    }
    let client = SentryClient::new(SentryClientOpts { auth_token: token.to_string(), org: s.org.clone(), project: s.project.clone(), base_url: s.url.clone(), http: None });
    Some(SentryProvider::new(client, SentryProviderOpts { org: s.org.clone(), project: s.project.clone(), ..Default::default() }))
}

/// An Axiom logs-evidence provider, or None when token / dataset is missing.
pub fn axiom_for_env(renv: &ResolvedEnvironment) -> Option<AxiomProvider> {
    let a = renv.connectors.axiom.as_ref()?;
    let token = a.token.as_deref().filter(|t| !t.is_empty())?;
    if a.dataset.is_empty() {
        return None;
    }
    let client = AxiomClient::new(AxiomClientOpts { token: token.to_string(), dataset: a.dataset.clone(), base_url: a.url.clone(), http: None });
    Some(AxiomProvider::new(client, AxiomProviderOpts { dataset: a.dataset.clone(), ..Default::default() }))
}

/// A Shopify Admin evidence provider whenever AUTH is present (store + secret) — queries
/// may be supplied per-investigation, so missing config `queries` does not disable it.
pub fn shopify_for_env(renv: &ResolvedEnvironment) -> Option<ShopifyProvider> {
    let s = renv.connectors.shopify.as_ref()?;
    let secret = s.secret.as_deref().filter(|t| !t.is_empty())?;
    if s.store.is_empty() {
        return None;
    }
    let client = ShopifyAdminClient::new(ShopifyClientOpts {
        store: s.store.clone(),
        api_version: s.api_version.clone(),
        access_id: s.access_id.clone(),
        secret: secret.to_string(),
        base_url: None,
    });
    Some(ShopifyProvider::new(client, ShopifyProviderOpts { store: s.store.clone(), queries: s.queries.clone() }))
}

/// Lens user-report provider (HOR-470) — the NATIVE Horus Cloud connector, wired from
/// the CLI's cloud auth + the repo's cloud-linked workspace id (no config stanza).
pub fn lens_for_cloud(api_base_url: &str, token: &str, workspace_id: &str) -> LensProvider {
    LensProvider::new(
        LensCloudClient::new(LensClientOpts { api_base_url: api_base_url.to_string(), token: token.to_string(), workspace_id: workspace_id.to_string(), http: None }),
        LensProviderOpts::default(),
    )
}

/// Cloud log providers for every configured `azure-monitor` / `cloudwatch` / `gcp-logging`.
pub fn cloud_logs_for_env(renv: &ResolvedEnvironment) -> Result<Vec<CloudLogsProvider>> {
    let c = &renv.connectors;
    let configs = [
        c.azure_monitor.clone().map(CloudLogConfig::AzureMonitor),
        c.cloudwatch.clone().map(CloudLogConfig::CloudWatch),
        c.gcp_logging.clone().map(CloudLogConfig::GcpLogging),
    ];
    configs.into_iter().flatten().map(CloudLogsProvider::new).collect()
}

/// Firestore / SQL Server state providers (shared database provider).
pub fn additional_state_for_env(renv: &ResolvedEnvironment) -> Result<Vec<DatabaseStateProvider>> {
    let c = &renv.connectors;
    let mut out = Vec::new();
    if let Some(fs) = &c.firestore {
        let opts = DatabaseStateOpts { database: fs.database.clone(), collections: fs.collections.clone(), stale_hours: 24.0 };
        out.push(DatabaseStateProvider::new("firestore", Arc::new(FirestoreStateClient::new(fs.clone())?), opts));
    }
    if let Some(sql) = &c.sqlserver {
        #[cfg(feature = "sqlserver")]
        {
            let opts = DatabaseStateOpts { database: sql.database.clone(), collections: sql.tables.clone(), stale_hours: 24.0 };
            out.push(DatabaseStateProvider::new("sqlserver", Arc::new(SqlServerStateClient::new(sql.clone())?), opts));
        }
        #[cfg(not(feature = "sqlserver"))]
        {
            let _ = sql;
            bail!("sqlserver connector configured but horus-connectors was built without the `sqlserver` feature");
        }
    }
    Ok(out)
}

/// Kafka / Azure Service Bus queue-evidence providers.
pub fn additional_queues_for_env(renv: &ResolvedEnvironment) -> Result<Vec<Box<dyn QueueEvidenceProvider>>> {
    let c = &renv.connectors;
    let mut out: Vec<Box<dyn QueueEvidenceProvider>> = Vec::new();
    if let Some(k) = &c.kafka {
        out.push(Box::new(KafkaQueueProvider::new(k.clone())?));
    }
    if let Some(sb) = &c.azure_service_bus {
        out.push(Box::new(ServiceBusQueueProvider::new(sb.clone())?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Legacy Connectors bundle + compat wrappers (HOR-34)
// ---------------------------------------------------------------------------

pub struct Connectors {
    pub code: SourceCodeProvider,
}

fn resolve_project(config: &HorusConfig, repo_name: Option<&str>) -> Result<ResolvedEnvironment> {
    resolve_environment(config, &ResolveOptions { project: repo_name, ..Default::default() })
}

/// A `CodeProvider` for a project (or the default/single one). Errors when no source
/// connector is configured for the resolved environment.
pub fn code_for_repo(config: &HorusConfig, repo_name: Option<&str>) -> Result<SourceCodeProvider> {
    let renv = resolve_project(config, repo_name)?;
    match code_for_env(&renv) {
        Some(c) => Ok(c),
        None => bail!("No source-intelligence connector configured for project \"{}\" / env \"{}\".", renv.project, renv.env),
    }
}

/// The source-intelligence host URL for a project ("" when none is configured).
pub fn source_host_url_for_repo(config: &HorusConfig, repo_name: Option<&str>) -> Result<String> {
    let renv = resolve_project(config, repo_name)?;
    Ok(renv.repositories.first().and_then(|r| r.source_host_url.clone()).unwrap_or_default())
}

/// Connectors bundle for the default (or single) project/env.
pub fn create_connectors(config: &HorusConfig) -> Result<Connectors> {
    Ok(Connectors { code: code_for_repo(config, None)? })
}

/// A fully-resolved, live-wired descriptor for a single configured repository.
pub struct RepoProvider {
    pub name: String,
    pub path: String,
    pub host_url: String,
    pub code: SourceCodeProvider,
}

/// A `RepoProvider` for every repository of every project. A missing source host yields a
/// stub that reports unreachable on health().
pub fn repo_providers(config: &HorusConfig) -> Result<Vec<RepoProvider>> {
    let mut out = Vec::new();
    for p in &config.projects {
        let renv = resolve_project(config, Some(&p.name))?;
        for r in renv.repositories {
            let host_url = r.source_host_url.unwrap_or_default();
            out.push(RepoProvider { name: r.name, path: r.path, code: SourceCodeProvider::new(source_client(&host_url)), host_url });
        }
    }
    Ok(out)
}

/// Elasticsearch `LogsProvider` for the default project/env (secrets via resolve_environment).
pub fn logs_provider_from_config(config: &HorusConfig) -> Result<Option<ElasticsearchLogsProvider>> {
    logs_for_env(&resolve_environment(config, &ResolveOptions::default())?)
}

/// Metrics provider for the default project/env.
pub fn metrics_provider_from_config(config: &HorusConfig) -> Result<Option<Box<dyn MetricsProvider>>> {
    metrics_for_env(&resolve_environment(config, &ResolveOptions::default())?)
}
