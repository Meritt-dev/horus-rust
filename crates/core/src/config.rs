//! Horus configuration schema. Loaded from `.horus/config.json`, `config/horus.config.{js,ts}`
//! (evaluated with `node`) or a path given to `load_config`. `validate_config` walks the raw
//! value through a zod-equivalent schema (every issue, zod's wording and order); serde then
//! fills defaults (unknown keys are stripped, like `z.object`). A malformed config fails at
//! startup with a clear message rather than deep in the pipeline.
//!
//! HOR-34: Config is project/environment scoped. No connector may run without an
//! explicit project/env scope.

use crate::discovery::{decrypt_connector_secrets, discover_local_config, find_repo_root, read_file_utf8, read_local_secrets};
use crate::runtime_connectors::*;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::sync::Once;

/// Placeholder URL filled into the deprecated `database` block when a config omits it.
/// NEVER connected to — exists only so back-compat consumers of `config.database.url`
/// keep resolving while the block is deprecated.
const DEPRECATED_DB_PLACEHOLDER: &str = "embedded";

// ---------------------------------------------------------------------------
// Repository schema (CODE — belongs to the PROJECT)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositorySource {
    pub host_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryConfig {
    pub name: String,
    pub path: String,
    /// Horus source-intelligence backend host for this repository (`source.hostUrl`, HOR-137).
    /// When absent/unreachable, source context degrades — runtime evidence still works.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<RepositorySource>,
}

// ---------------------------------------------------------------------------
// Connector-level schemas (RUNTIME — belong to the ENVIRONMENT)
// ---------------------------------------------------------------------------

/// Roles a Redis logical DB can play (HOR-201).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedisRole {
    Cache,
    State,
    Locks,
    RateLimit,
    Session,
    Dedupe,
    Bullmq,
    Queues,
}

pub const REDIS_ROLES: &[RedisRole] = &[
    RedisRole::Cache,
    RedisRole::State,
    RedisRole::Locks,
    RedisRole::RateLimit,
    RedisRole::Session,
    RedisRole::Dedupe,
    RedisRole::Bullmq,
    RedisRole::Queues,
];
/// Roles that mark a DB as holding BullMQ queues.
pub const REDIS_QUEUE_ROLES: &[RedisRole] = &[RedisRole::Bullmq, RedisRole::Queues];

impl RedisRole {
    pub fn as_str(self) -> &'static str {
        match self {
            RedisRole::Cache => "cache",
            RedisRole::State => "state",
            RedisRole::Locks => "locks",
            RedisRole::RateLimit => "rate-limit",
            RedisRole::Session => "session",
            RedisRole::Dedupe => "dedupe",
            RedisRole::Bullmq => "bullmq",
            RedisRole::Queues => "queues",
        }
    }
}

/// Parse the logical DB index from a redis URL path (`redis://h:p/1` → 1); defaults to 0.
pub fn redis_db_from_url(url: Option<&str>) -> i64 {
    let Some(url) = url.filter(|u| !u.is_empty()) else { return 0 };
    let Ok(u) = url::Url::parse(url) else { return 0 };
    // `Number.parseInt(seg, 10)`: leading digits only (an optional sign would never be ≥ 0 anyway).
    let seg = u.path().trim_start_matches('/');
    let digits: String = seg.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<i64>().unwrap_or(0)
}

/// Return `url` with its DB-index path set to `db`, for selecting a logical DB.
pub fn redis_url_for_db(url: &str, db: i64) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            u.set_path(&format!("/{db}"));
            u.to_string()
        }
        Err(_) => url.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EsPreset {
    #[default]
    Meritt,
    Ecs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LevelFormat {
    Numeric,
    String,
}

/// Per-field overrides merged on top of the selected preset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElasticsearchFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level_format: Option<LevelFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_keyword: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_fallback: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_code_keyword: Option<bool>,
    /// Fields holding the specific failure text behind a generic message template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<Vec<String>>,
}
pub type ResolvedElasticsearchFields = ElasticsearchFields;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElasticsearchConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_pattern: Option<String>,
    /// Multiple index patterns — joined with ',' when resolving. Takes precedence over indexPattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// Log schema preset: `meritt` (pino-based Meritt shared logger) or `ecs`.
    #[serde(default)]
    pub preset: EsPreset,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<ElasticsearchFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Env var holding the ES base URL. Defaults to "ES_URL".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MongodbConfig {
    pub database: String,
    #[serde(default)]
    pub collections: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Env var holding the MongoDB URL. Defaults to "MONGODB_URL".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostgresConfig {
    /// Schema to introspect (default: "public").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// Allowlisted tables to analyze (empty = auto-discover all base tables).
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Env var holding the Postgres URL. Defaults to "DATABASE_URL".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
}

/// Sentry error-tracking connector: grouped exceptions become ERROR evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentryConfig {
    pub org: String,
    pub project: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Env var holding the auth token. Defaults to "SENTRY_AUTH_TOKEN".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Env var holding the base URL. Defaults to "SENTRY_URL".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
}

/// Axiom logs connector (HOR-429).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AxiomConfig {
    pub dataset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Env var holding the API token. Defaults to "AXIOM_TOKEN".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Env var holding the base URL. Defaults to "AXIOM_URL".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShopifyQueryKind {
    #[default]
    State,
    Log,
    Metric,
}

/// A single Shopify Admin GraphQL query to run as evidence. The `query` text is authored
/// by the operator — never built in connector code. Shared by config, investigation input
/// and the provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShopifyQuerySpec {
    /// Label for provenance + the evidence title.
    pub name: String,
    /// Verbatim Admin GraphQL query document (read-only).
    pub query: String,
    /// Static variables merged under any engine-bound window variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<Map<String, Value>>,
    /// EvidenceKind to map results onto.
    #[serde(default)]
    pub kind: ShopifyQueryKind,
    /// Base relevance seed (0–1) before hint-term weighting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relevance: Option<f64>,
    /// Inject the investigation window as `$from`/`$to` variables when declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_window: Option<bool>,
}

/// Shopify Admin connector. Auth is a read-only Client-Credentials grant: `accessId` is
/// the app `client_id`, `secret` the `client_secret` (encrypted at rest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShopifyConfig {
    /// Store subdomain, e.g. "my-store" (a full domain is also accepted).
    pub store: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_id: Option<String>,
    /// Env var holding the client_id. Defaults to "SHOPIFY_ACCESS_ID".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_id_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Env var holding the client_secret. Defaults to "SHOPIFY_SECRET".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_env: Option<String>,
    /// Default named queries run when no `--shopify-query` is supplied (notably `horus watch`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queries: Option<Vec<ShopifyQuerySpec>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<String>,
    /// Multiple dashboard UIDs to fetch. Takes precedence over `dashboard` when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboards: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Env var holding the Grafana base URL. Defaults to "GRAFANA_URL".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Env var holding the Grafana username. Defaults to "GRAFANA_USER".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Env var holding the Grafana password. Defaults to "GRAFANA_PASSWORD".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
}

fn bull() -> String {
    "bull".into()
}
fn default_true() -> bool {
    true
}
fn sample_limit() -> i64 {
    500
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedisBullmqConfig {
    #[serde(default = "bull")]
    pub prefix: String,
}

/// Sampled-scan settings for cache/state/locks DBs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisScanConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "sample_limit")]
    pub sample_limit: i64,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisDatabaseConfig {
    /// Logical DB index on the server (0–15 by default Redis config).
    pub db: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What this DB holds — drives which collectors/commands use it.
    #[serde(default)]
    pub roles: Vec<RedisRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bullmq: Option<RedisBullmqConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<RedisScanConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Env var holding the Redis URL. Defaults to "REDIS_URL".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
    /// Logical databases on the same Redis server (HOR-201). When omitted, the DB index in
    /// `url` (default 0) is treated as a single configured database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub databases: Option<Vec<RedisDatabaseConfig>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prometheus: Option<PrometheusConfig>,
    #[serde(rename = "azure-service-bus", skip_serializing_if = "Option::is_none")]
    pub azure_service_bus: Option<AzureServiceBusConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kafka: Option<KafkaConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firestore: Option<FirestoreConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlserver: Option<SqlServerConfig>,
    #[serde(rename = "azure-monitor", skip_serializing_if = "Option::is_none")]
    pub azure_monitor: Option<AzureMonitorConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudwatch: Option<CloudWatchConfig>,
    #[serde(rename = "gcp-logging", skip_serializing_if = "Option::is_none")]
    pub gcp_logging: Option<GcpLoggingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elasticsearch: Option<ElasticsearchConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mongodb: Option<MongodbConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres: Option<PostgresConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentry: Option<SentryConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axiom: Option<AxiomConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shopify: Option<ShopifyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grafana: Option<GrafanaConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis: Option<RedisConfig>,
}

fn min_confidence() -> f64 {
    0.6
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyWebhook {
    pub url: String,
    /// HMAC-SHA256 signing secret; when set, payloads carry an `X-Horus-Signature` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

/// Outbound notify sink (HOR-454). CLI/notify-layer only — the deterministic engine never sees this.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyConfig {
    /// Only dispatch when an auto-investigation's confidence is >= this (0..1). Default 0.6.
    #[serde(default = "min_confidence")]
    pub min_confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<NotifyWebhook>,
    /// Also push the headline to Horus Cloud (uses the existing cloud session, if signed in).
    #[serde(default)]
    pub cloud: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentConfig {
    pub name: String,
    #[serde(default = "default_true")]
    pub read_only: bool,
    #[serde(default)]
    pub connectors: ConnectorsConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<NotifyConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    /// Code repositories (with their source-intelligence hosts) — code belongs to the project.
    pub repositories: Vec<RepositoryConfig>,
    /// Runtime environments — runtime systems belong to the environment.
    pub environments: Vec<EnvironmentConfig>,
}

/// DEPRECATED (Batch A8): ignored. Local persistence is embedded; kept for back-compat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}
impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig { url: DEPRECATED_DB_PLACEHOLDER.to_string() }
    }
}

fn reasoning_model() -> String {
    "claude-opus-4-8".into()
}
fn extraction_model() -> String {
    "claude-haiku-4-5".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelsConfig {
    #[serde(default = "reasoning_model")]
    pub reasoning: String,
    #[serde(default = "extraction_model")]
    pub extraction: String,
}
impl Default for ModelsConfig {
    fn default() -> Self {
        ModelsConfig { reasoning: reasoning_model(), extraction: extraction_model() }
    }
}

/// AI providers a user can connect (HOR-206).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiProvider {
    Anthropic,
    Claude,
    Codex,
    Gemini,
    Kimi,
    Cursor,
}
pub const AI_PROVIDERS: &[AiProvider] =
    &[AiProvider::Anthropic, AiProvider::Claude, AiProvider::Codex, AiProvider::Gemini, AiProvider::Kimi, AiProvider::Cursor];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnthropicConfig {
    /// Direct API key (takes priority over apiKeyEnv). Stored redacted in display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Env var holding the key. Defaults to ANTHROPIC_API_KEY.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// AI narrative configuration (HOR-206). Secrets resolve from config first, then env.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<AiProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<AnthropicConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HorusConfig {
    #[serde(default)]
    pub projects: Vec<ProjectConfig>,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub models: ModelsConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai: Option<AiConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedAiSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<AiProvider>,
    /// Resolved Anthropic API key (config value or env fallback), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anthropic_api_key: Option<String>,
    /// Whether the key came from config (vs env) — drives doctor's "configured" wording.
    pub anthropic_key_from_config: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Resolve AI settings: config key first, then the ANTHROPIC_API_KEY env fallback.
pub fn resolve_ai_settings(config: &HorusConfig) -> ResolvedAiSettings {
    let ai = config.ai.as_ref();
    let anthropic = ai.and_then(|a| a.anthropic.as_ref());
    let from_config = anthropic.and_then(|a| a.api_key.clone());
    let key = from_config
        .clone()
        .or_else(|| env(anthropic.and_then(|a| a.api_key_env.as_deref()).unwrap_or("ANTHROPIC_API_KEY")));
    ResolvedAiSettings {
        provider: ai.and_then(|a| a.provider),
        anthropic_api_key: key,
        anthropic_key_from_config: from_config.is_some(),
        model: anthropic.and_then(|a| a.model.clone()),
    }
}

/// Which fields of each connector are SECRETS (HOR-452). These never live in config.json —
/// `horus connect` encrypts them into `.horus/secrets.local.json`. Connection URLs for
/// mongo/postgres/redis are secrets because they embed credentials.
pub const CONNECTOR_SECRET_FIELDS: &[(&str, &[&str])] = &[
    ("prometheus", &["token"]),
    ("kafka", &["username", "password"]),
    ("sqlserver", &["url"]),
    ("elasticsearch", &["username", "password"]),
    ("mongodb", &["url"]),
    ("postgres", &["url"]),
    ("sentry", &["authToken"]),
    ("axiom", &["token"]),
    ("grafana", &["username", "password"]),
    ("redis", &["url"]),
    ("shopify", &["secret"]),
];

/// Secret field names for `connector` (empty when it has none).
pub fn connector_secret_fields(connector: &str) -> &'static [&'static str] {
    CONNECTOR_SECRET_FIELDS.iter().find(|(c, _)| *c == connector).map(|(_, f)| *f).unwrap_or(&[])
}

/// True if `field` is a secret for `connector`.
pub fn is_secret_field(connector: &str, field: &str) -> bool {
    connector_secret_fields(connector).contains(&field)
}

/// Scan a raw local project object for connector secret fields stored as plaintext direct
/// values (the legacy/insecure shape). Returns `env/connector.field` locators.
pub fn find_plaintext_connector_secrets(project: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(envs) = project.get("environments").and_then(Value::as_array) else { return out };
    for env in envs {
        let env_name = env.get("name").and_then(Value::as_str).unwrap_or("(unnamed)");
        let Some(connectors) = env.get("connectors").and_then(Value::as_object) else { continue };
        for (connector, cfg) in connectors {
            if !cfg.is_object() {
                continue;
            }
            for field in connector_secret_fields(connector) {
                if cfg.get(*field).and_then(Value::as_str).is_some_and(|v| !v.is_empty()) {
                    out.push(format!("{env_name}/{connector}.{field}"));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Resolved environment types (runtime, with secrets read from the process env)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedRepository {
    pub name: String,
    pub path: String,
    /// Canonical Horus-owned source-intelligence host URL (HOR-137).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_host_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedElasticsearch {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub index_pattern: String,
    /// All configured index patterns (populated when indexPatterns was used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    pub preset: EsPreset,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<ElasticsearchFields>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedMongodb {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub database: String,
    pub collections: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedPostgres {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    pub tables: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedSentry {
    pub org: String,
    pub project: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedAxiom {
    pub dataset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedShopify {
    pub store: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queries: Option<Vec<ShopifyQuerySpec>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedGrafana {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<String>,
    /// All configured dashboard UIDs (populated when dashboards was used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboards: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedRedisScan {
    pub enabled: bool,
    pub sample_limit: i64,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedRedisDatabase {
    pub db: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub roles: Vec<RedisRole>,
    /// BullMQ key prefix for this DB (default "bull").
    pub bullmq_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<ResolvedRedisScan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedRedis {
    /// Base server URL (auth + host + port). The DB index in the path is captured
    /// per-database in `databases`; consumers pick the DB they need.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Always at least one entry when redis is configured (synthesized from the URL).
    pub databases: Vec<ResolvedRedisDatabase>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedConnectors {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prometheus: Option<PrometheusConfig>,
    #[serde(rename = "azure-service-bus", skip_serializing_if = "Option::is_none")]
    pub azure_service_bus: Option<AzureServiceBusConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kafka: Option<KafkaConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firestore: Option<FirestoreConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlserver: Option<SqlServerConfig>,
    #[serde(rename = "azure-monitor", skip_serializing_if = "Option::is_none")]
    pub azure_monitor: Option<AzureMonitorConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudwatch: Option<CloudWatchConfig>,
    #[serde(rename = "gcp-logging", skip_serializing_if = "Option::is_none")]
    pub gcp_logging: Option<GcpLoggingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elasticsearch: Option<ResolvedElasticsearch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mongodb: Option<ResolvedMongodb>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres: Option<ResolvedPostgres>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentry: Option<ResolvedSentry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axiom: Option<ResolvedAxiom>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shopify: Option<ResolvedShopify>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grafana: Option<ResolvedGrafana>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis: Option<ResolvedRedis>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedEnvironment {
    pub project: String,
    pub env: String,
    pub read_only: bool,
    /// Code repositories for the project (with their source-intelligence hosts).
    pub repositories: Vec<ResolvedRepository>,
    /// Primary repository path (first repo) — convenience for git-based commands.
    pub path: String,
    pub connectors: ResolvedConnectors,
    /// Outbound notify sink for `horus watch` (HOR-454); absent when not configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<NotifyConfig>,
}

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectEnv {
    pub project: String,
    pub env: String,
}

/// Flatten all configured project/env pairs (for help text / matrix display).
pub fn list_environments(config: &HorusConfig) -> Vec<ProjectEnv> {
    config
        .projects
        .iter()
        .flat_map(|p| p.environments.iter().map(move |e| ProjectEnv { project: p.name.clone(), env: e.name.clone() }))
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ResolveOptions<'a> {
    pub project: Option<&'a str>,
    pub env: Option<&'a str>,
    pub cwd: Option<&'a Path>,
}

/// `direct ?? process.env[envName ?? default]`
fn direct_or_env(direct: &Option<String>, env_name: &Option<String>, default: &str) -> Option<String> {
    direct.clone().or_else(|| env(env_name.as_deref().unwrap_or(default)))
}

/// Resolve a concrete environment from the config, reading connector secrets from the
/// process env. Errors when resolution is ambiguous.
///
/// - project: `opts.project` if given; else the single configured project; else infer
///   from the current repo (a project whose repository path is the repo root); else error.
/// - env: `opts.env` if given; else the single env; else the one named "production"; else error.
pub fn resolve_environment(config: &HorusConfig, opts: &ResolveOptions) -> Result<ResolvedEnvironment> {
    let names = |it: &mut dyn Iterator<Item = &str>| it.collect::<Vec<_>>().join(", ");

    // --- pick project ---
    let project: &ProjectConfig = if let Some(wanted) = opts.project {
        config.projects.iter().find(|p| p.name == wanted).ok_or_else(|| {
            let n = names(&mut config.projects.iter().map(|p| p.name.as_str()));
            anyhow!("Unknown project: {wanted} (configured: {})", if n.is_empty() { "none".to_string() } else { n })
        })?
    } else if config.projects.len() == 1 {
        &config.projects[0]
    } else {
        // Infer from the current repo by matching its root against repository paths.
        let cwd = opts.cwd.map(Path::to_path_buf).unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
        let root = find_repo_root(&cwd).unwrap_or_else(|| std::path::absolute(&cwd).unwrap_or(cwd));
        let matches: Vec<&ProjectConfig> = config
            .projects
            .iter()
            .filter(|p| p.repositories.iter().any(|r| std::path::absolute(&r.path).is_ok_and(|rp| rp == root)))
            .collect();
        match matches.as_slice() {
            [one] => one,
            _ => bail!(
                "Multiple projects configured; pass --repo <name> (one of: {}) — or run from inside a project's repository.",
                names(&mut config.projects.iter().map(|p| p.name.as_str()))
            ),
        }
    };

    // --- pick environment ---
    let env_names = || names(&mut project.environments.iter().map(|e| e.name.as_str()));
    let environment: &EnvironmentConfig = if let Some(wanted) = opts.env {
        project
            .environments
            .iter()
            .find(|e| e.name == wanted)
            .ok_or_else(|| anyhow!("Unknown environment: {wanted} in project {} (one of: {})", project.name, env_names()))?
    } else if project.environments.len() == 1 {
        &project.environments[0]
    } else if let Some(prod) = project.environments.iter().find(|e| e.name == "production") {
        prod
    } else if project.environments.is_empty() {
        bail!("Project {} has no environments.", project.name)
    } else {
        bail!("Project {} has multiple environments; pass --env <name> (one of: {})", project.name, env_names())
    };

    // --- resolve repositories ---
    let repositories: Vec<ResolvedRepository> = project
        .repositories
        .iter()
        .map(|r| ResolvedRepository {
            name: r.name.clone(),
            path: r.path.clone(),
            source_host_url: r.source.as_ref().map(|s| s.host_url.clone()).filter(|u| !u.is_empty()),
        })
        .collect();

    // --- resolve connectors (runtime belongs to the environment) ---
    let c = &environment.connectors;
    let mut resolved = ResolvedConnectors {
        prometheus: c.prometheus.clone(),
        azure_service_bus: c.azure_service_bus.clone(),
        kafka: c.kafka.clone(),
        firestore: c.firestore.clone(),
        sqlserver: c.sqlserver.clone(),
        azure_monitor: c.azure_monitor.clone(),
        cloudwatch: c.cloudwatch.clone(),
        gcp_logging: c.gcp_logging.clone(),
        ..Default::default()
    };

    if let Some(es) = &c.elasticsearch {
        resolved.elasticsearch = Some(ResolvedElasticsearch {
            url: direct_or_env(&es.url, &es.url_env, "ES_URL").unwrap_or_default(),
            username: direct_or_env(&es.username, &es.username_env, "ES_USERNAME"),
            password: direct_or_env(&es.password, &es.password_env, "ES_PASSWORD"),
            // indexPatterns (array) takes precedence; falls back to indexPattern string.
            index_pattern: es.index_patterns.as_ref().map(|p| p.join(",")).or_else(|| es.index_pattern.clone()).unwrap_or_default(),
            index_patterns: es.index_patterns.clone(),
            service_name: es.service_name.clone(),
            preset: es.preset,
            fields: es.fields.clone(),
        });
    }
    if let Some(m) = &c.mongodb {
        resolved.mongodb = Some(ResolvedMongodb {
            url: direct_or_env(&m.url, &m.url_env, "MONGODB_URL"),
            database: m.database.clone(),
            collections: m.collections.clone(),
        });
    }
    if let Some(p) = &c.postgres {
        resolved.postgres = Some(ResolvedPostgres {
            url: direct_or_env(&p.url, &p.url_env, "DATABASE_URL"),
            schema: p.schema.clone(),
            database: p.database.clone(),
            tables: p.tables.clone(),
        });
    }
    if let Some(s) = &c.sentry {
        resolved.sentry = Some(ResolvedSentry {
            org: s.org.clone(),
            project: s.project.clone(),
            auth_token: direct_or_env(&s.auth_token, &s.auth_token_env, "SENTRY_AUTH_TOKEN"),
            url: direct_or_env(&s.url, &s.url_env, "SENTRY_URL"),
        });
    }
    if let Some(a) = &c.axiom {
        resolved.axiom = Some(ResolvedAxiom {
            dataset: a.dataset.clone(),
            token: direct_or_env(&a.token, &a.token_env, "AXIOM_TOKEN"),
            url: direct_or_env(&a.url, &a.url_env, "AXIOM_URL"),
        });
    }
    if let Some(sh) = &c.shopify {
        resolved.shopify = Some(ResolvedShopify {
            store: sh.store.clone(),
            api_version: sh.api_version.clone(),
            access_id: direct_or_env(&sh.access_id, &sh.access_id_env, "SHOPIFY_ACCESS_ID"),
            secret: direct_or_env(&sh.secret, &sh.secret_env, "SHOPIFY_SECRET"),
            queries: sh.queries.clone(),
        });
    }
    if let Some(g) = &c.grafana {
        resolved.grafana = Some(ResolvedGrafana {
            url: direct_or_env(&g.url, &g.url_env, "GRAFANA_URL"),
            username: direct_or_env(&g.username, &g.username_env, "GRAFANA_USER"),
            password: direct_or_env(&g.password, &g.password_env, "GRAFANA_PASSWORD"),
            dashboard: g.dashboard.clone(),
            dashboards: g.dashboards.clone(),
        });
    }
    if let Some(r) = &c.redis {
        let url = direct_or_env(&r.url, &r.url_env, "REDIS_URL");
        let databases = match &r.databases {
            Some(dbs) if !dbs.is_empty() => dbs
                .iter()
                .map(|d| ResolvedRedisDatabase {
                    db: d.db,
                    name: d.name.clone(),
                    roles: d.roles.clone(),
                    bullmq_prefix: d.bullmq.as_ref().map(|b| b.prefix.clone()).unwrap_or_else(bull),
                    scan: d.scan.as_ref().map(|s| ResolvedRedisScan {
                        enabled: s.enabled,
                        sample_limit: s.sample_limit,
                        patterns: s.patterns.clone(),
                    }),
                })
                .collect(),
            // Backward compatibility: no `databases` declared — the DB index from the URL
            // (default 0) is a single configured database with no roles assumed.
            _ => vec![ResolvedRedisDatabase {
                db: redis_db_from_url(url.as_deref()),
                name: None,
                roles: vec![],
                bullmq_prefix: bull(),
                scan: None,
            }],
        };
        resolved.redis = Some(ResolvedRedis { url, databases });
    }

    Ok(ResolvedEnvironment {
        project: project.name.clone(),
        env: environment.name.clone(),
        read_only: environment.read_only,
        path: repositories.first().map(|r| r.path.clone()).unwrap_or_default(),
        repositories,
        connectors: resolved,
        notify: environment.notify.clone(),
    })
}

// ---------------------------------------------------------------------------
// Validation (zod constraints) + loading
// ---------------------------------------------------------------------------

const REDIS_ROLE_NAMES: &[&str] = &["cache", "state", "locks", "rate-limit", "session", "dedupe", "bullmq", "queues"];
const AI_PROVIDER_NAMES: &[&str] = &["anthropic", "claude", "codex", "gemini", "kimi", "cursor"];

fn s(checks: Vec<StrCheck>) -> Z {
    Z::Str(checks)
}
fn ostrs() -> Z {
    opt(arr(s(vec![]), None, None))
}
fn obool() -> Z {
    opt(Z::Bool)
}

fn connectors_schema() -> Z {
    let es_fields = obj(vec![
        ("timestamp", ostr()),
        ("level", ostr()),
        ("levelFormat", opt(Z::Enum(&["numeric", "string"]))),
        ("service", ostr()),
        ("serviceKeyword", obool()),
        ("message", ostr()),
        ("messageFallback", ostr()),
        ("traceId", ostr()),
        ("requestId", ostr()),
        ("eventCode", ostr()),
        ("eventCodeKeyword", obool()),
        ("detail", ostrs()),
    ]);
    let elasticsearch = obj(vec![
        ("indexPattern", ostr()),
        ("indexPatterns", ostrs()),
        ("serviceName", ostr()),
        ("preset", opt(Z::Enum(&["meritt", "ecs"]))),
        ("fields", opt(es_fields)),
        ("url", ostr()),
        ("urlEnv", ostr()),
        ("username", ostr()),
        ("usernameEnv", ostr()),
        ("password", ostr()),
        ("passwordEnv", ostr()),
    ]);
    let mongodb = obj(vec![("database", s(vec![])), ("collections", ostrs()), ("url", ostr()), ("urlEnv", ostr())]);
    let postgres = obj(vec![
        ("schema", ostr()),
        ("database", ostr()),
        ("tables", ostrs()),
        ("url", ostr()),
        ("urlEnv", ostr()),
    ]);
    let sentry = obj(vec![
        ("org", s(vec![])),
        ("project", s(vec![])),
        ("authToken", ostr()),
        ("authTokenEnv", ostr()),
        ("url", ostr()),
        ("urlEnv", ostr()),
    ]);
    let axiom = obj(vec![("dataset", s(vec![])), ("token", ostr()), ("tokenEnv", ostr()), ("url", ostr()), ("urlEnv", ostr())]);
    let shopify_query = obj(vec![
        ("name", s(vec![])),
        ("query", s(vec![])),
        ("variables", opt(Z::Record)),
        ("kind", opt(Z::Enum(&["state", "log", "metric"]))),
        ("relevance", opt(Z::Num(vec![NumCheck::Gte(0.0), NumCheck::Lte(1.0)]))),
        ("bindWindow", obool()),
    ]);
    let shopify = obj(vec![
        ("store", s(vec![])),
        ("apiVersion", ostr()),
        ("accessId", ostr()),
        ("accessIdEnv", ostr()),
        ("secret", ostr()),
        ("secretEnv", ostr()),
        ("queries", opt(arr(shopify_query, None, None))),
    ]);
    let grafana = obj(vec![
        ("dashboard", ostr()),
        ("dashboards", ostrs()),
        ("url", ostr()),
        ("urlEnv", ostr()),
        ("username", ostr()),
        ("usernameEnv", ostr()),
        ("password", ostr()),
        ("passwordEnv", ostr()),
    ]);
    let redis_db = obj(vec![
        ("db", Z::Num(vec![NumCheck::Int, NumCheck::Gte(0.0), NumCheck::Lte(15.0)])),
        ("name", ostr()),
        ("roles", opt(arr(Z::Enum(REDIS_ROLE_NAMES), None, None))),
        ("bullmq", opt(obj(vec![("prefix", ostr())]))),
        (
            "scan",
            opt(obj(vec![
                ("enabled", obool()),
                ("sampleLimit", opt(Z::Num(vec![NumCheck::Int, NumCheck::Gt(0.0)]))),
                ("patterns", ostrs()),
            ])),
        ),
    ]);
    let redis = obj(vec![("url", ostr()), ("urlEnv", ostr()), ("databases", opt(arr(redis_db, None, None)))]);
    opt(obj(vec![
        ("prometheus", opt(prometheus_schema())),
        ("azure-service-bus", opt(azure_service_bus_schema())),
        ("kafka", opt(kafka_schema())),
        ("firestore", opt(firestore_schema())),
        ("sqlserver", opt(sqlserver_schema())),
        ("azure-monitor", opt(azure_monitor_schema())),
        ("cloudwatch", opt(cloudwatch_schema())),
        ("gcp-logging", opt(gcp_logging_schema())),
        ("elasticsearch", opt(elasticsearch)),
        ("mongodb", opt(mongodb)),
        ("postgres", opt(postgres)),
        ("sentry", opt(sentry)),
        ("axiom", opt(axiom)),
        ("shopify", opt(shopify)),
        ("grafana", opt(grafana)),
        ("redis", opt(redis)),
    ]))
}

/// `horusConfigSchema`, field for field in TS declaration order (zod reports issues in
/// this order).
fn horus_config_schema() -> Z {
    let min1 = || s(vec![StrCheck::Min(1)]);
    let repository = obj(vec![
        ("name", min1()),
        ("path", min1()),
        ("source", opt(obj(vec![("hostUrl", s(vec![StrCheck::Url]))]))),
    ]);
    let notify = opt(obj(vec![
        ("minConfidence", opt(Z::Num(vec![NumCheck::Gte(0.0), NumCheck::Lte(1.0)]))),
        ("webhook", opt(obj(vec![("url", s(vec![StrCheck::Url])), ("secret", opt(min1()))]))),
        ("cloud", obool()),
    ]));
    let environment =
        obj(vec![("name", min1()), ("readOnly", obool()), ("connectors", connectors_schema()), ("notify", notify)]);
    let project = obj(vec![
        ("name", min1()),
        ("repositories", arr(repository, Some(1), None)),
        ("environments", arr(environment, Some(1), None)),
    ]);
    obj(vec![
        ("projects", opt(arr(project, None, None))),
        ("database", opt(obj(vec![("url", min1())]))),
        ("models", opt(obj(vec![("reasoning", ostr()), ("extraction", ostr())]))),
        (
            "ai",
            opt(obj(vec![
                ("provider", opt(Z::Enum(AI_PROVIDER_NAMES))),
                ("anthropic", opt(obj(vec![("apiKey", ostr()), ("apiKeyEnv", ostr()), ("model", ostr())]))),
            ])),
        ),
    ])
}

/// zod `horusConfigSchema.safeParse(raw)` issues (structural + constraint). Empty = valid.
pub fn validate_config(raw: &Value) -> Vec<ConfigIssue> {
    let mut i = Issues::default();
    zod_walk(&horus_config_schema(), Some(raw), &mut i);
    i.items
}

/// Example value hints shown alongside validation errors (array indices appear as `*`).
const CONFIG_EXAMPLES: &[(&str, &str)] = &[
    ("(root)", "add at least one project"),
    ("projects.*.name", "e.g. name: \"my-api\""),
    ("projects.*.repositories", "e.g. [{ name: \"my-api\", path: \"/path/to/repo\" }]"),
    ("projects.*.repositories.*.name", "e.g. name: \"my-api\""),
    ("projects.*.repositories.*.path", "e.g. path: \"/absolute/path/to/repo\""),
    ("projects.*.repositories.*.source.hostUrl", "e.g. \"http://127.0.0.1:8420\"  (start one with: horus init)"),
    ("projects.*.environments", "e.g. [{ name: \"production\", connectors: {} }]"),
    ("projects.*.environments.*.name", "e.g. name: \"production\""),
    ("projects.*.environments.*.connectors.elasticsearch.indexPattern", "e.g. indexPattern: \"my-api-prod-*\""),
];

static DATABASE_DEPRECATION: Once = Once::new();

/// Warn once that the `database` config block is ignored (local persistence is embedded).
fn warn_database_deprecated() {
    DATABASE_DEPRECATION
        .call_once(|| eprintln!("database config is deprecated — local persistence is embedded; teams use Horus Cloud"));
}

fn invalid_config_error(source: &str, issues: &[ConfigIssue]) -> anyhow::Error {
    let details: Vec<String> = issues
        .iter()
        .map(|i| {
            let hint = CONFIG_EXAMPLES.iter().find(|(k, _)| *k == i.path).map(|(_, e)| format!("\n  → {e}")).unwrap_or_default();
            format!("  • {}: {}{hint}", i.path, i.message)
        })
        .collect();
    anyhow!("Invalid Horus config ({source}):\n{}", details.join("\n"))
}

/// Validate a raw config object, failing with a readable error.
pub fn parse_config(raw: Value, source: &str) -> Result<HorusConfig> {
    if raw.get("database").is_some_and(|d| !d.is_null()) {
        warn_database_deprecated();
    }
    let issues = validate_config(&raw);
    if !issues.is_empty() {
        return Err(invalid_config_error(source, &issues));
    }
    // The schema walk accepted it, so serde only fills defaults; a failure here is a schema drift.
    let config: HorusConfig = serde_json::from_value(raw)
        .map_err(|e| invalid_config_error(source, &[ConfigIssue { path: "(root)".into(), message: e.to_string() }]))?;
    Ok(config)
}

/// Decrypt connector secrets from `.horus/secrets.local.json` and inject them into the raw
/// in-memory `project` so `resolve_environment` sees them as direct values (HOR-452).
/// Only injects into connectors already declared in config. Best-effort.
fn hydrate_connector_secrets(project: &mut Value, root: &Path) {
    let decrypted = decrypt_connector_secrets(root);
    for w in &decrypted.warnings {
        eprintln!("horus: skipped encrypted connector secret ({w})");
    }
    if decrypted.values.is_empty() {
        return;
    }
    let Some(envs) = project.get_mut("environments").and_then(Value::as_array_mut) else { return };
    for env in envs {
        let Some(env_name) = env.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()).map(str::to_string) else { continue };
        let Some(by_connector) = decrypted.values.get(&env_name) else { continue };
        let Some(env_obj) = env.as_object_mut() else { continue };
        for (connector, fields) in by_connector {
            // HOR-454: the notify webhook signing secret lives under the pseudo-connector
            // "notify" → hydrate into env.notify.webhook.secret, never config.json.
            if connector == "notify" {
                if let (Some(webhook), Some(secret)) =
                    (env_obj.get_mut("notify").and_then(|n| n.get_mut("webhook")).and_then(Value::as_object_mut), fields.get("webhookSecret"))
                {
                    webhook.insert("secret".to_string(), Value::String(secret.clone()));
                }
                continue;
            }
            let Some(target) = env_obj.get_mut("connectors").and_then(|c| c.get_mut(connector)).and_then(Value::as_object_mut) else {
                continue; // not declared in config — skip
            };
            for (field, value) in fields {
                target.insert(field.clone(), Value::String(value.clone()));
            }
        }
    }
}

/// Evaluates a config module with the installed `node` and prints its default export as
/// JSON after a sentinel (the module may write to stdout itself). argv[1] is the target.
const NODE_CONFIG_LOADER: &str = r#"
import { pathToFileURL } from 'node:url';
let out;
try {
  const mod = await import(pathToFileURL(process.argv[1]).href);
  out = mod.default ? { config: mod.default } : { missingDefault: true };
} catch (err) {
  out = { error: String(err?.message ?? err) };
}
process.stdout.write('\n__HORUS_CONFIG_JSON__' + JSON.stringify(out));
"#;
const NODE_SENTINEL: &str = "\n__HORUS_CONFIG_JSON__";

/// `import()` (`.js/.mjs/.cjs`) or jiti (anything else, i.e. `.ts`) in TS. The Rust build
/// runs the module under `node` (type stripping for TS) and returns its default export.
fn load_config_module(target: &Path) -> Result<Value> {
    let shown = target.display();
    let native_js = [".js", ".mjs", ".cjs"].iter().any(|e| target.to_string_lossy().ends_with(e));
    let mut cmd = std::process::Command::new("node");
    cmd.arg("--no-warnings");
    if !native_js {
        cmd.arg("--experimental-strip-types");
    }
    cmd.args(["--input-type=module", "-e", NODE_CONFIG_LOADER]).arg(target);
    let out = match cmd.output() {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "Could not load Horus config at {shown}: JS/TS configs are evaluated with Node.js, but `node` was not found on PATH. Install Node.js (≥ 22.6 for .ts) or use .horus/config.json (`horus init`)."
        ),
        Err(e) => bail!("Could not load Horus config at {shown}: failed to run node: {e}"),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let Some(at) = stdout.rfind(NODE_SENTINEL) else {
        let hint = if native_js { "" } else { " (TypeScript configs need Node.js ≥ 22.6)" };
        bail!("Could not load Horus config at {shown}: {}{hint}", stderr.trim());
    };
    // Pass through anything the module itself printed.
    print!("{}", &stdout[..at]);
    eprint!("{stderr}");
    let result: Value = serde_json::from_str(&stdout[at + NODE_SENTINEL.len()..])?;
    if let Some(err) = result.get("error").and_then(Value::as_str) {
        bail!("Could not load Horus config at {shown}: {err}");
    }
    match result.get("config") {
        Some(config) => Ok(config.clone()),
        None => bail!("Horus config at {shown} must have a default export."),
    }
}

/// JS truthiness of a JSON value (`file.project ? … : …`).
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// Load a config file by absolute path — JSON, native JS/ESM, or a TS module.
fn load_config_file(target: &Path) -> Result<HorusConfig> {
    let source = target.to_string_lossy().into_owned();
    if !source.ends_with(".json") {
        return parse_config(load_config_module(target)?, &source);
    }
    // A local `.horus/config.json` wraps a single project. Read untyped, like the TS
    // `JSON.parse(...) as LocalConfigFile` cast: the schema walk reports shape errors.
    let text = read_file_utf8(target)?;
    let mut file: Value = serde_json::from_str(&text).with_context(|| format!("parse {source}"))?;
    let root = target.parent().and_then(Path::parent).map(Path::to_path_buf).unwrap_or_default();
    // Hydrate the API key from `.horus/secrets.local.json` (HOR-212) into the in-memory ai block only.
    let mut ai = file.get("ai").cloned();
    if let Some(api_key) = read_local_secrets(&root).anthropic.and_then(|a| a.api_key).filter(|k| !k.is_empty()) {
        let mut ai_obj = ai.and_then(|v| v.as_object().cloned()).unwrap_or_default();
        let mut anthropic = ai_obj.get("anthropic").and_then(Value::as_object).cloned().unwrap_or_default();
        anthropic.insert("apiKey".to_string(), Value::String(api_key));
        ai_obj.insert("anthropic".to_string(), Value::Object(anthropic));
        ai = Some(Value::Object(ai_obj));
    }
    let mut raw = Map::new();
    let project = file.get_mut("project");
    let has_project = truthy(project.as_deref());
    let projects = match project {
        Some(p) if has_project => {
            // Hydrate encrypted connector secrets (HOR-452). Never written back to disk.
            hydrate_connector_secrets(p, &root);
            json!([p.take()])
        }
        _ => json!([]),
    };
    raw.insert("projects".into(), projects);
    // `database` is deprecated and ignored; only forwarded when the file still sets it so
    // parse_config can emit the one-time deprecation warning.
    if let Some(db) = file.get("database") {
        raw.insert("database".into(), db.clone());
    }
    if let Some(ai) = ai {
        raw.insert("ai".into(), ai);
    }
    parse_config(Value::Object(raw), &source)
}

/// Node `path.resolve`: absolute against cwd, lexically normalised, no symlink resolution.
fn resolve_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in std::env::current_dir().unwrap_or_default().join(p).components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Load and validate the active Horus config. Resolution order:
///   1. an explicit `config_path` (e.g. `--config`)
///   2. a discovered `.horus/config.json` walking up from `cwd` (git-style)
///   3. the `HORUS_CONFIG` environment variable
///   4. `config/horus.config.js` relative to cwd (preferred)
///   5. `config/horus.config.ts` relative to cwd
pub fn load_config(config_path: Option<&Path>, cwd: Option<&Path>) -> Result<HorusConfig> {
    let cwd: PathBuf = cwd.map(Path::to_path_buf).unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let target = if let Some(p) = config_path {
        resolve_path(p)
    } else if let Some(discovered) = discover_local_config(&cwd) {
        discovered
    } else if let Some(p) = env("HORUS_CONFIG").filter(|p| !p.is_empty()) {
        resolve_path(Path::new(&p))
    } else {
        let js_path = cwd.join("config/horus.config.js");
        let ts_path = cwd.join("config/horus.config.ts");
        // No `.horus/config.json`, no $HORUS_CONFIG, no `config/horus.config.*` — this repo
        // isn't set up. Fail with an ACTIONABLE message.
        if !js_path.exists() && !ts_path.exists() {
            bail!(
                "No Horus config found. Run from a configured repo or pass --config <path>. (Looked under {}; run `horus init` to set this repo up.)",
                cwd.display()
            );
        }
        if js_path.exists() { js_path } else { ts_path }
    };
    load_config_file(&target)
}
