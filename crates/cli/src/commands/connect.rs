//! `horus connect <type>` — add or update a runtime connector in the current repo's
//! `.horus/config.json` (HOR-41). Port of `packages/cli/src/commands/connect.ts`.
//!
//! Two modes: flags only (machine-friendly), or interactive (kicks in when key flags are
//! missing). Secrets are split out and AES-256-GCM encrypted into `.horus/secrets.local.json`
//! (HOR-452); config.json only ever carries non-secret fields.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use base64::Engine as _;
use horus_connectors::jsutil::issues_to_error;
use horus_connectors::axiom::{AxiomClient, AxiomClientOpts};
use horus_connectors::cloud_logs::{CloudLogConfig, CloudLogsProvider};
use horus_connectors::elasticsearch::client::{ElasticsearchClient, ElasticsearchClientOpts};
use horus_connectors::grafana::client::{GrafanaClient, GrafanaClientOpts};
use horus_connectors::prometheus::PrometheusMetricsProvider;
use horus_connectors::sentry::{SentryClient, SentryClientOpts, SentryNamedResource};
use horus_connectors::shopify::{ShopifyAdminClient, ShopifyClientOpts};
use horus_connectors::{
    probe_redis_databases, FirestoreStateClient, KafkaQueueProvider, MongoClientOpts, MongoStateClient,
    PostgresClientOpts, PostgresStateClient, ProbeOpts, Provider, RedisDbProbe, RedisScanClient, RedisScanClientOpts,
    ServiceBusQueueProvider, SqlServerStateClient, StateClient,
};
use horus_core::{
    connector_secret_fields, discover_local_config, ensure_master_key, ensure_project_gitignore, find_repo_root,
    local_config_path, local_secrets_path, master_key_status, patch_local_connector, read_local_config,
    redact_error_message, write_connector_secret, Issues, RedisRole, REDIS_ROLES,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::commands::connect_ai::{run_connect_ai, ConnectAiOpts};
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red, yellow};
use crate::lib::tty_selector::{checkbox_search, is_interactive, select_search, ExitPromptError, RawMode, SelectError};

/// A logical Redis DB the user wants to configure, with its roles.
#[derive(Debug, Clone)]
pub struct RedisDatabaseSpec {
    pub db: i64,
    pub name: Option<String>,
    pub roles: Vec<RedisRole>,
}

fn role_str(r: RedisRole) -> String {
    serde_json::to_value(r).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// Parse a `--db` spec like "0:cache,state" or "1:bullmq" into a RedisDatabaseSpec.
pub fn parse_db_spec(spec: &str) -> Result<RedisDatabaseSpec> {
    let mut parts = spec.split(':');
    let db_part = parts.next().unwrap_or("").trim();
    let roles_part = parts.next().unwrap_or("");
    let db = parse_int_prefix(db_part).filter(|d| (0..=15).contains(d)).ok_or_else(|| {
        anyhow!("Invalid --db spec \"{spec}\": DB index must be 0–15 (e.g. 1:bullmq,queues)")
    })?;
    let valid: Vec<String> = REDIS_ROLES.iter().map(|r| role_str(*r)).collect();
    let mut roles = Vec::new();
    for role in roles_part.split(',').map(str::trim).filter(|r| !r.is_empty()) {
        let parsed: Option<RedisRole> = serde_json::from_value(Value::String(role.into())).ok();
        match parsed {
            Some(r) => roles.push(r),
            None => bail!("Invalid role \"{role}\" in --db spec \"{spec}\". Valid roles: {}", valid.join(", ")),
        }
    }
    Ok(RedisDatabaseSpec { db, name: None, roles })
}

/// JS `parseInt(s, 10)`.
fn parse_int_prefix(s: &str) -> Option<i64> {
    let s = s.trim_start();
    let end = s
        .char_indices()
        .find(|(i, c)| !(c.is_ascii_digit() || (*i == 0 && (*c == '-' || *c == '+'))))
        .map_or(s.len(), |(i, _)| i);
    s[..end].parse().ok()
}

#[derive(Debug, Clone, Default)]
pub struct ConnectOpts {
    pub queries: Option<String>,
    pub namespace_id: Option<String>,
    pub queues: Option<String>,
    pub brokers: Option<String>,
    pub topics: Option<String>,
    pub groups: Option<String>,
    pub ssl: Option<bool>,
    pub mechanism: Option<String>,
    pub workspace: Option<String>,
    pub subscription: Option<String>,
    pub region: Option<String>,
    pub log_group: Option<String>,
    pub profile: Option<String>,
    pub filter: Option<String>,
    pub executable: Option<String>,
    pub env: Option<String>,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub index_pattern: Option<String>,
    /// Multiple index patterns selected during interactive discovery.
    pub index_patterns: Option<Vec<String>>,
    pub service: Option<String>,
    pub database: Option<String>,
    pub collections: Option<String>,
    pub schema: Option<String>,
    pub tables: Option<String>,
    pub auth_token: Option<String>,
    pub org: Option<String>,
    pub project: Option<String>,
    pub token: Option<String>,
    pub dataset: Option<String>,
    pub store: Option<String>,
    pub api_version: Option<String>,
    pub access_id: Option<String>,
    pub secret: Option<String>,
    pub dashboard: Option<String>,
    /// Multiple dashboard UIDs selected during interactive discovery.
    pub dashboard_uids: Option<Vec<String>>,
    pub no_test: bool,
    pub provider: Option<String>,
    pub api_key: Option<String>,
    pub ai_model: Option<String>,
    pub db: Vec<String>,
    pub bullmq_prefix: Option<String>,
    /// Force/skip interactive DB scan (redis). None = auto when interactive.
    pub scan_dbs: Option<bool>,
    pub redis_databases: Option<Vec<RedisDatabaseSpec>>,
}

const SUPPORTED: &[&str] = &[
    "prometheus",
    "azure-service-bus",
    "kafka",
    "firestore",
    "sqlserver",
    "azure-monitor",
    "cloudwatch",
    "gcp-logging",
    "elasticsearch",
    "mongodb",
    "postgres",
    "sentry",
    "axiom",
    "shopify",
    "grafana",
    "redis",
];

pub async fn run(args: &ConnectArgs) -> Result<()> {
    let opts = ConnectOpts {
        env: args.env.clone(),
        queries: args.queries.clone(),
        namespace_id: args.namespace_id.clone(),
        queues: args.queues.clone(),
        brokers: args.brokers.clone(),
        topics: args.topics.clone(),
        groups: args.groups.clone(),
        // Commander `--no-ssl`: `ssl` defaults to true.
        ssl: Some(!args.no_ssl),
        mechanism: args.mechanism.clone(),
        workspace: args.workspace.clone(),
        subscription: args.subscription.clone(),
        region: args.region.clone(),
        log_group: args.log_group.clone(),
        profile: args.profile.clone(),
        filter: args.filter.clone(),
        executable: args.executable.clone(),
        url: args.url.clone(),
        username: args.username.clone(),
        password: args.password.clone(),
        index_pattern: args.index_pattern.clone(),
        service: args.service.clone(),
        database: args.database.clone(),
        collections: args.collections.clone(),
        schema: args.schema.clone(),
        tables: args.tables.clone(),
        auth_token: args.auth_token.clone(),
        org: args.org.clone(),
        project: args.sentry_project.clone().or_else(|| args.gcp_project.clone()),
        token: args.token.clone(),
        dataset: args.dataset.clone(),
        store: args.store.clone(),
        api_version: args.api_version.clone(),
        access_id: args.access_id.clone(),
        secret: args.secret.clone(),
        dashboard: args.dashboard.clone(),
        db: args.db.clone(),
        bullmq_prefix: args.bullmq_prefix.clone(),
        // Commander `--no-scan-dbs`: `scanDbs` defaults to true.
        scan_dbs: Some(!args.no_scan_dbs),
        provider: args.provider.clone(),
        api_key: args.api_key.clone(),
        ai_model: args.model.clone(),
        no_test: args.no_test,
        ..Default::default()
    };
    let code = run_connect(&args.r#type, opts).await;
    if code != 0 {
        return Err(SilentExit(code).into());
    }
    Ok(())
}

pub async fn run_connect(kind: &str, opts: ConnectOpts) -> u8 {
    // AI providers are not per-environment connectors — dispatch to the dedicated flow.
    if kind == "ai" {
        return run_connect_ai(ConnectAiOpts {
            provider: opts.provider.clone(),
            api_key: opts.api_key.clone(),
            model: opts.ai_model.clone(),
            no_test: opts.no_test,
        })
        .await;
    }
    if !SUPPORTED.contains(&kind) {
        eprintln!(
            "{}{}",
            red(&format!("Unknown connector type: {kind}")),
            dim(&format!("\n  supported: {}, ai", SUPPORTED.join(", ")))
        );
        return 1;
    }
    match run_connect_inner(kind, opts).await {
        Ok(code) => code,
        Err(err) => {
            if err.downcast_ref::<ExitPromptError>().is_some() {
                eprintln!("{}", red("Cancelled."));
            } else {
                eprintln!("{}", red(&redact_error_message(&err)));
            }
            1
        }
    }
}

async fn run_connect_inner(kind: &str, opts: ConnectOpts) -> Result<u8> {
    let cwd = std::env::current_dir()?;
    let root = find_repo_root(&cwd).unwrap_or_else(|| cwd.clone());
    let config_path = discover_local_config(&cwd).unwrap_or_else(|| local_config_path(&root));

    // Fill in any missing opts interactively.
    let filled = fill_interactive(kind, opts).await?;

    // Safety net: never save a half-configured connector.
    if missing_required(kind, &filled) {
        eprintln!(
            "{}{}",
            red(&format!("Missing required field(s) for {kind} — nothing saved.")),
            dim(&format!(
                "\n  Re-run {} and fill every prompt, or pass them as flags (e.g. --secret for the token).",
                bold(&format!("horus connect {kind}"))
            ))
        );
        return Ok(1);
    }

    let patch = match kind {
        "prometheus" | "azure-service-bus" | "kafka" | "firestore" | "sqlserver" => build_runtime_patch(kind, &filled)?,
        "azure-monitor" | "cloudwatch" | "gcp-logging" => build_cloud_log_patch(kind, &filled)?,
        "elasticsearch" => build_es_patch(&filled)?,
        "mongodb" => build_mongo_patch(&filled)?,
        "postgres" => build_postgres_patch(&filled),
        "sentry" => build_sentry_patch(&filled),
        "axiom" => build_axiom_patch(&filled)?,
        "shopify" => build_shopify_patch(&filled)?,
        "grafana" => build_grafana_patch(&filled),
        _ => build_redis_patch(&filled)?,
    };

    // Probe the connector unless --no-test.
    if !filled.no_test {
        let (ok, detail) = probe(kind, &filled).await;
        if !ok {
            eprintln!(
                "\n{} {detail}{}",
                red(&format!("✗ Could not reach {kind}:")),
                dim("\n  Fix the connection and retry, or pass --no-test to skip.")
            );
            return Ok(1);
        }
        println!("\n{} {kind} reachable {}", green("✓"), dim(&format!("({detail})")));
    }

    // HOR-452: split the patch into SECRETS (encrypted) and non-secret config.
    let env_name = resolve_env_name(&config_path, filled.env.as_deref())?;
    let secret_fields = connector_secret_fields(kind);
    let mut non_secret = Map::new();
    let mut secrets: Vec<(String, String)> = Vec::new();
    for (k, v) in patch {
        match v.as_str() {
            Some(s) if secret_fields.contains(&k.as_str()) && !s.is_empty() => secrets.push((k, s.to_string())),
            _ => {
                non_secret.insert(k, v);
            }
        }
    }

    // Always keep `.horus/` out of Git.
    ensure_project_gitignore(&root);

    if !secrets.is_empty() {
        let key_result = match ensure_master_key() {
            Ok(k) => k,
            Err(e) => {
                eprintln!("{}", red(&redact_error_message(&e)));
                return Ok(1);
            }
        };
        for (field, value) in &secrets {
            write_connector_secret(&root, &env_name, kind, field, value, Some(&key_result.key))?;
        }
        if let Some(w) = &key_result.warning {
            eprintln!("{}", yellow(&format!("\n⚠ {w}")));
        }
    }

    // Always patch — even an empty patch — so the connector block exists for resolution.
    patch_local_connector(&config_path, kind, non_secret, Some(&env_name))?;

    println!("{} {} connector saved → {}", green("✓"), bold(kind), dim(&config_path.display().to_string()));
    if !secrets.is_empty() {
        let n = secrets.len();
        println!(
            "{}",
            dim(&format!(
                "  {n} secret{} encrypted → {}\n  master key: {}",
                if n > 1 { "s" } else { "" },
                local_secrets_path(&root).display(),
                master_key_status().detail
            ))
        );
    }
    print_summary(kind, &filled);
    println!("{}", dim("\n  run: horus investigate \"<hint>\""));
    Ok(0)
}

// ---------------------------------------------------------------------------
// Interactive fill-in
// ---------------------------------------------------------------------------

fn exit_err(e: SelectError) -> Option<anyhow::Error> {
    match e {
        SelectError::Exit(x) => Some(x.into()),
        SelectError::Other(_) => None,
    }
}

async fn fill_interactive(kind: &str, opts: ConnectOpts) -> Result<ConnectOpts> {
    if !missing_required(kind, &opts) {
        return Ok(opts);
    }
    println!("\n{} {}\n", bold(&format!("Connect {kind}")), dim("(press Enter to skip optional fields)"));
    let mut f = opts;
    let opt = |s: String| (!s.is_empty()).then_some(s);

    match kind {
        "prometheus" => {
            f.url = f.url.or_else(|| Some(ask("Prometheus URL", "", true)));
            f.queries = f.queries.or_else(|| Some(ask("Queries JSON ([{title,expr}])", "", true)));
        }
        "azure-service-bus" => {
            f.namespace_id = f.namespace_id.or_else(|| Some(ask("Service Bus namespace ARM ID", "", true)));
            f.queues = f.queues.or_else(|| Some(ask("Queues (comma-separated)", "", true)));
        }
        "kafka" => {
            f.brokers = f.brokers.or_else(|| Some(ask("Brokers (host:port, comma-separated)", "", true)));
            f.topics = f.topics.or_else(|| Some(ask("Topics (comma-separated)", "", true)));
            f.groups = f.groups.or_else(|| Some(ask("Consumer groups (comma-separated)", "", true)));
        }
        "firestore" => {
            f.project = f.project.or_else(|| Some(ask("Google Cloud project ID", "", true)));
            f.collections = f.collections.or_else(|| Some(ask("Collection paths (comma-separated)", "", true)));
        }
        "sqlserver" => {
            f.url = f.url.or_else(|| Some(ask_password("SQL Server connection string", false)));
            f.database = f.database.or_else(|| Some(ask("Database", "", true)));
            f.tables = f.tables.or_else(|| Some(ask("Tables (comma-separated)", "", true)));
        }
        "azure-monitor" => f.workspace = f.workspace.or_else(|| Some(ask("Log Analytics workspace GUID", "", true))),
        "cloudwatch" => {
            f.region = f.region.or_else(|| Some(ask("AWS region", "", true)));
            f.log_group = f.log_group.or_else(|| Some(ask("CloudWatch log group", "", true)));
            if f.profile.is_none() {
                f.profile = opt(ask("Local AWS profile", "", false));
            }
        }
        "gcp-logging" => f.project = f.project.or_else(|| Some(ask("Google Cloud project ID", "", true))),
        "elasticsearch" => {
            f.url = f.url.or_else(|| Some(ask("URL", "https://elastic.example.com", true)));
            if f.username.is_none() {
                f.username = opt(ask("Username", "", false));
            }
            if f.password.is_none() {
                f.password = opt(ask_password("Password", false));
            }
            // Discover available indexes if no index pattern was passed via flag.
            if f.index_pattern.is_none() && f.index_patterns.is_none() {
                let discovered = discover_es_indices(f.url.as_deref(), f.username.as_deref(), f.password.as_deref()).await;
                if !discovered.is_empty() {
                    let selected = ask_index_selection(&discovered)?;
                    if !selected.is_empty() {
                        f.index_patterns = Some(selected);
                    }
                }
                if f.index_patterns.is_none() {
                    f.index_pattern = Some(ask("Index pattern", "logs-*", true));
                }
            }
            if f.service.is_none() {
                f.service = opt(ask("Service name", "", true));
            }
        }
        "mongodb" => {
            f.url = f.url.or_else(|| Some(ask("Connection string", "mongodb://localhost:27017", true)));
            f.database = f.database.or_else(|| Some(ask("Database name", "", true)));
            if f.collections.is_none() {
                f.collections = opt(ask("Collections (comma-separated, or Enter for all)", "", true));
            }
        }
        "postgres" => {
            f.url = f.url.or_else(|| Some(ask("Connection string", "postgres://localhost:5432/postgres", true)));
            if f.schema.is_none() {
                f.schema = opt(ask("Schema", "public", true));
            }
            if f.tables.is_none() {
                f.tables = opt(ask("Tables (comma-separated, or Enter for all)", "", true));
            }
        }
        "sentry" => {
            // Token + base URL first — both are needed to list orgs/projects for the pickers.
            if f.auth_token.is_none() {
                f.auth_token = opt(ask_password("Auth token", false));
            }
            if f.url.is_none() {
                f.url = opt(ask("Base URL (self-hosted)", "https://sentry.io", false));
            }
            let base_url = f.url.clone().unwrap_or_else(|| "https://sentry.io".into());
            if f.org.is_none() {
                if let Some(token) = f.auth_token.clone() {
                    let orgs = sentry_client(&token, "", "", &base_url).list_organizations().await.unwrap_or_default();
                    f.org = pick_sentry_resource("Sentry organization", &orgs)?;
                }
            }
            f.org = f.org.or_else(|| Some(ask("Org slug", "my-org", true)));
            if f.project.is_none() {
                if let (Some(token), Some(org)) = (f.auth_token.clone(), f.org.clone().filter(|o| !o.is_empty())) {
                    let projects = sentry_client(&token, &org, "", &base_url).list_projects().await.unwrap_or_default();
                    f.project = pick_sentry_resource("Sentry project", &projects)?;
                }
            }
            f.project = f.project.or_else(|| Some(ask("Project slug", "my-project", true)));
        }
        "axiom" => {
            if f.token.is_none() {
                f.token = opt(ask_password("Axiom API token", false));
            }
            if f.url.is_none() {
                f.url = Some(ask_axiom_region()?);
            }
            if f.dataset.is_none() {
                let base_url = f.url.clone().unwrap_or_else(|| "https://api.axiom.co".into());
                let mut names: Vec<String> = Vec::new();
                if let Some(token) = &f.token {
                    let client = AxiomClient::new(AxiomClientOpts {
                        token: token.clone(),
                        dataset: String::new(),
                        base_url: Some(base_url),
                        http: None,
                    });
                    names = client.list_datasets().await.into_iter().map(|d| d.name).filter(|n| !n.is_empty()).collect();
                }
                if !names.is_empty() {
                    if let Some(picked) = ask_dataset_selection(&names)? {
                        f.dataset = Some(picked);
                    }
                }
                if f.dataset.is_none() {
                    if names.is_empty() {
                        println!(
                            "{}",
                            yellow("  Couldn't list datasets (check token / network / region) — enter the name manually.")
                        );
                    }
                    f.dataset = Some(ask("Dataset name", "logs", true));
                }
            }
        }
        "shopify" => {
            // Subdomain only — Horus adds `.myshopify.com` internally.
            f.store = f.store.or_else(|| Some(ask("Store name (subdomain only, e.g. acme-store)", "my-store", true)));
            f.api_version = f.api_version.or_else(|| Some(ask("API version", "2025-10", true)));
            if f.secret.is_none() {
                if ask_shopify_auth_method() == "client-credentials" {
                    f.access_id = f.access_id.or_else(|| Some(ask_required_text("Access id (client_id)")));
                    f.secret = opt(ask_password("Client secret", true));
                } else {
                    // Static token: the secret IS the Admin API access token; no access id.
                    f.access_id = None;
                    f.secret = opt(ask_password("Admin API access token (e.g. shpat_…)", true));
                }
            }
        }
        "grafana" => {
            f.url = f.url.or_else(|| Some(ask("URL", "https://grafana.example.com", true)));
            if f.username.is_none() {
                f.username = opt(ask("Username", "", false));
            }
            if f.password.is_none() {
                f.password = opt(ask_password("Password", false));
            }
            if f.dashboard.is_none() && f.dashboard_uids.is_none() {
                let discovered =
                    discover_grafana_dashboards(f.url.as_deref(), f.username.as_deref(), f.password.as_deref()).await;
                if !discovered.is_empty() {
                    let selected = ask_dashboard_selection(&discovered)?;
                    if !selected.is_empty() {
                        f.dashboard_uids = Some(selected.into_iter().map(|d| d.0).collect());
                    }
                }
                if f.dashboard_uids.is_none() {
                    f.dashboard = opt(ask("Default dashboard uid", "", false));
                }
            }
        }
        "redis" => {
            println!(
                "{}",
                dim("  Tip: embed credentials directly in the URL — redis://:password@host:6379\n       or enter the URL and password separately below.")
            );
            f.url = f.url.or_else(|| Some(ask("URL", "redis://localhost:6379", true)));
            // Only prompt for password when the URL doesn't already contain one.
            if !redis_url_has_password(f.url.as_deref()) {
                if let (Some(pw), Some(url)) = (opt(ask_password("Password", false)), f.url.clone()) {
                    f.url = Some(inject_redis_password(&url, &pw));
                }
            }
            // Multi-DB configuration (HOR-201): explicit --db > interactive scan > none.
            if !f.db.is_empty() {
                f.redis_databases = Some(f.db.iter().map(|s| parse_db_spec(s)).collect::<Result<_>>()?);
            } else if f.url.is_some() && f.scan_dbs != Some(false) && is_interactive() && ask_scan_dbs() {
                let prefix = f.bullmq_prefix.clone().unwrap_or_else(|| "bull".into());
                f.redis_databases = Some(discover_and_select_dbs(f.url.as_deref().unwrap_or(""), &prefix).await?);
            }
        }
        _ => {}
    }
    Ok(f)
}

fn blank(v: &Option<String>) -> bool {
    v.as_deref().is_none_or(str::is_empty)
}

fn missing_required(kind: &str, o: &ConnectOpts) -> bool {
    match kind {
        "prometheus" => blank(&o.url) || blank(&o.queries),
        "azure-service-bus" => blank(&o.namespace_id) || blank(&o.queues),
        "kafka" => blank(&o.brokers) || blank(&o.topics) || blank(&o.groups),
        "firestore" => blank(&o.project) || blank(&o.collections),
        "sqlserver" => blank(&o.url) || blank(&o.database) || blank(&o.tables),
        "azure-monitor" => blank(&o.workspace),
        "cloudwatch" => blank(&o.region) || blank(&o.log_group),
        "gcp-logging" => blank(&o.project),
        "elasticsearch" => blank(&o.url) || (blank(&o.index_pattern) && o.index_patterns.as_ref().is_none_or(Vec::is_empty)),
        "mongodb" => blank(&o.url) || blank(&o.database),
        "postgres" | "grafana" | "redis" => blank(&o.url),
        "sentry" => blank(&o.org) || blank(&o.project) || blank(&o.auth_token),
        "axiom" => blank(&o.dataset) || blank(&o.token),
        // accessId is optional (blank ⇒ static token).
        "shopify" => blank(&o.store) || blank(&o.secret),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Readline helpers
// ---------------------------------------------------------------------------

/// Plain line prompt. Empty input yields `placeholder` when required, else `""`.
pub fn ask(label: &str, placeholder: &str, required: bool) -> String {
    let hint = if placeholder.is_empty() { String::new() } else { dim(&format!(" ({placeholder})")) };
    let suffix = if required { String::new() } else { dim(" [optional]") };
    print!("  {label}{suffix}{hint}: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    // EOF (closed/piped stdin): the TS readline `line` event never fires and the process
    // simply drains and exits 0 — mirror that instead of continuing with an empty answer.
    if matches!(std::io::stdin().lock().read_line(&mut line), Ok(0)) {
        std::process::exit(0);
    }
    let v = line.trim();
    if !v.is_empty() {
        v.to_string()
    } else if required {
        placeholder.to_string()
    } else {
        String::new()
    }
}

/// Masked secret prompt (raw mode, `•` per char). Non-TTY falls back to a plain line read.
pub fn ask_password(label: &str, required: bool) -> String {
    if !std::io::stdin().is_terminal() {
        return ask(label, "", false);
    }
    let suffix = if required { String::new() } else { dim(" [optional]") };
    print!("  {label}{suffix}: ");
    let _ = std::io::stdout().flush();
    let raw = RawMode::enter();
    let mut value = String::new();
    loop {
        let Some(chunk) = crate::lib::tty_selector::read_key() else { break };
        match chunk.as_str() {
            "\r" | "\n" => {
                // A required secret can't be skipped — re-prompt on an empty Enter.
                if required && value.is_empty() {
                    print!("\r\n{}\r\n  {label}: ", yellow("  Required — please enter a value."));
                    let _ = std::io::stdout().flush();
                    continue;
                }
                break;
            }
            "\x03" => {
                drop(raw);
                std::process::exit(1);
            }
            "\x7F" | "\x08" => {
                if value.pop().is_some() {
                    print!("\x08 \x08");
                }
            }
            other => {
                value.push_str(other);
                print!("•");
            }
        }
        let _ = std::io::stdout().flush();
    }
    drop(raw);
    println!();
    value
}

/// Prompt for a REQUIRED free-text value, re-prompting until something is entered.
fn ask_required_text(label: &str) -> String {
    loop {
        let v = ask(label, "", false);
        if !v.is_empty() {
            return v;
        }
        println!("{}", yellow("  Required — please enter a value."));
    }
}

/// Which Shopify auth model to configure (static Admin API token vs Client-Credentials app).
fn ask_shopify_auth_method() -> &'static str {
    println!("  {}", bold("Auth method"));
    println!("    {} Static Admin API access token   {}", bold("1)"), dim("— a Custom App shpat_… token"));
    println!("    {} Client-Credentials app          {}", bold("2)"), dim("— client id + secret, exchanged for a token"));
    loop {
        match ask("Choose", "1", true).as_str() {
            "1" => return "static",
            "2" => return "client-credentials",
            _ => println!("{}", yellow("  Enter 1 or 2.")),
        }
    }
}

// ---------------------------------------------------------------------------
// Patch builders
// ---------------------------------------------------------------------------

fn split_list(v: &str) -> Vec<String> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

fn build_es_patch(o: &ConnectOpts) -> Result<Map<String, Value>> {
    let patterns = o.index_patterns.as_ref().filter(|p| !p.is_empty());
    if non_empty(&o.index_pattern).is_none() && patterns.is_none() {
        bail!("Index pattern is required for elasticsearch");
    }
    let mut p = Map::new();
    // indexPatterns (array) takes precedence over the legacy indexPattern string.
    match patterns {
        Some(list) => p.insert("indexPatterns".into(), json!(list)),
        None => p.insert("indexPattern".into(), json!(o.index_pattern)),
    };
    for (k, v) in [("url", &o.url), ("username", &o.username), ("password", &o.password), ("serviceName", &o.service)] {
        if let Some(v) = non_empty(v) {
            p.insert(k.into(), json!(v));
        }
    }
    Ok(p)
}

fn build_mongo_patch(o: &ConnectOpts) -> Result<Map<String, Value>> {
    let Some(db) = non_empty(&o.database) else { bail!("Database name is required for mongodb") };
    let mut p = Map::new();
    p.insert("database".into(), json!(db));
    if let Some(v) = non_empty(&o.url) {
        p.insert("url".into(), json!(v));
    }
    if let Some(v) = non_empty(&o.collections) {
        p.insert("collections".into(), json!(split_list(v)));
    }
    Ok(p)
}

fn build_postgres_patch(o: &ConnectOpts) -> Map<String, Value> {
    let mut p = Map::new();
    if let Some(v) = non_empty(&o.url) {
        p.insert("url".into(), json!(v));
    }
    if let Some(v) = non_empty(&o.schema) {
        p.insert("schema".into(), json!(v));
    }
    if let Some(v) = non_empty(&o.tables) {
        p.insert("tables".into(), json!(split_list(v)));
    }
    p
}

fn build_sentry_patch(o: &ConnectOpts) -> Map<String, Value> {
    let mut p = Map::new();
    for (k, v) in [("org", &o.org), ("project", &o.project), ("authToken", &o.auth_token)] {
        if let Some(v) = non_empty(v) {
            p.insert(k.into(), json!(v));
        }
    }
    // Only persist a non-default base URL (self-hosted Sentry).
    if let Some(u) = non_empty(&o.url).filter(|u| strip_one_slash(u) != "https://sentry.io") {
        p.insert("url".into(), json!(u));
    }
    p
}

fn strip_one_slash(u: &str) -> &str {
    u.strip_suffix('/').unwrap_or(u)
}

fn build_axiom_patch(o: &ConnectOpts) -> Result<Map<String, Value>> {
    let Some(ds) = non_empty(&o.dataset) else { bail!("Dataset is required for axiom") };
    let mut p = Map::new();
    p.insert("dataset".into(), json!(ds));
    if let Some(v) = non_empty(&o.token) {
        p.insert("token".into(), json!(v));
    }
    // Only persist a non-default base URL (EU region / self-hosted).
    if let Some(u) = non_empty(&o.url).filter(|u| strip_one_slash(u) != "https://api.axiom.co") {
        p.insert("url".into(), json!(u));
    }
    Ok(p)
}

fn build_shopify_patch(o: &ConnectOpts) -> Result<Map<String, Value>> {
    let Some(store) = non_empty(&o.store) else { bail!("Store is required for shopify") };
    let mut p = Map::new();
    p.insert("store".into(), json!(store));
    // `secret` is routed to encrypted storage by CONNECTOR_SECRET_FIELDS.shopify.
    for (k, v) in [("apiVersion", &o.api_version), ("accessId", &o.access_id), ("secret", &o.secret)] {
        if let Some(v) = non_empty(v) {
            p.insert(k.into(), json!(v));
        }
    }
    Ok(p)
}

fn build_grafana_patch(o: &ConnectOpts) -> Map<String, Value> {
    let mut p = Map::new();
    for (k, v) in [("url", &o.url), ("username", &o.username), ("password", &o.password)] {
        if let Some(v) = non_empty(v) {
            p.insert(k.into(), json!(v));
        }
    }
    // dashboardUids (array) takes precedence over the legacy dashboard string.
    match (o.dashboard_uids.as_ref().filter(|d| !d.is_empty()), non_empty(&o.dashboard)) {
        (Some(uids), _) => {
            p.insert("dashboards".into(), json!(uids));
        }
        (None, Some(d)) => {
            p.insert("dashboard".into(), json!(d));
        }
        _ => {}
    }
    p
}

fn build_redis_patch(o: &ConnectOpts) -> Result<Map<String, Value>> {
    let mut p = Map::new();
    if let Some(v) = non_empty(&o.url) {
        p.insert("url".into(), json!(v));
    }
    let dbs = match &o.redis_databases {
        Some(d) => d.clone(),
        None => o.db.iter().map(|s| parse_db_spec(s)).collect::<Result<_>>()?,
    };
    if !dbs.is_empty() {
        let prefix = o.bullmq_prefix.clone().unwrap_or_else(|| "bull".into());
        let list: Vec<Value> = dbs
            .iter()
            .map(|d| {
                let is_queue = d.roles.iter().any(|r| matches!(r, RedisRole::Bullmq | RedisRole::Queues));
                let mut m = Map::new();
                m.insert("db".into(), json!(d.db));
                if let Some(n) = d.name.as_deref().filter(|n| !n.is_empty()) {
                    m.insert("name".into(), json!(n));
                }
                m.insert("roles".into(), json!(d.roles.iter().map(|r| role_str(*r)).collect::<Vec<_>>()));
                if is_queue {
                    m.insert("bullmq".into(), json!({ "prefix": prefix }));
                }
                Value::Object(m)
            })
            .collect();
        p.insert("databases".into(), Value::Array(list));
    }
    Ok(p)
}

/// Interactive: ask whether to scan DBs 0–15.
fn ask_scan_dbs() -> bool {
    let a = ask("Scan Redis DBs 0-15 to detect queues vs cache?", "yes", false).to_lowercase();
    a.is_empty() || a == "y" || a == "yes"
}

/// One-line summary of a DB probe.
fn describe_probe(p: &RedisDbProbe) -> String {
    if !p.reachable {
        return format!("unreachable ({})", p.detail.as_deref().unwrap_or("error"));
    }
    if p.key_count == 0 {
        return "empty".into();
    }
    if !p.bullmq_queues.is_empty() {
        let sample = p.bullmq_queues.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        return format!(
            "{} BullMQ queue(s) · prefix {} · {sample}",
            p.bullmq_queues.len(),
            p.bullmq_prefix.as_deref().unwrap_or("")
        );
    }
    let examples = p.prefixes.iter().take(3).map(|x| format!("{}:*", x.prefix)).collect::<Vec<_>>().join(", ");
    let roles = p.suggested_roles.iter().map(|r| role_str(*r)).collect::<Vec<_>>().join("/");
    format!("{} keys · {roles}{}", p.key_count, if examples.is_empty() { String::new() } else { format!(" · {examples}") })
}

/// Interactive: probe DBs 0–15, show findings, let the user pick which to save.
async fn discover_and_select_dbs(url: &str, bullmq_prefix: &str) -> Result<Vec<RedisDatabaseSpec>> {
    println!("{}", dim("\n  Scanning DBs 0-15 (read-only, sampled)…"));
    let probes =
        probe_redis_databases(url, ProbeOpts { bullmq_prefix: Some(bullmq_prefix.into()), ..Default::default() }).await?;
    let non_empty: Vec<&RedisDbProbe> = probes.iter().filter(|p| p.reachable && p.key_count > 0).collect();
    if non_empty.is_empty() {
        println!("{}", dim("  No populated DBs found."));
        return Ok(vec![]);
    }
    for p in &non_empty {
        println!("  {} {}", bold(&format!("DB {}", p.db)), dim(&format!("· {}", describe_probe(p))));
    }
    let labels: Vec<String> = non_empty
        .iter()
        .map(|p| {
            let roles = p.suggested_roles.iter().map(|r| role_str(*r)).collect::<Vec<_>>().join("/");
            let roles = if roles.is_empty() { "unrolled".to_string() } else { roles };
            format!("DB {} — {roles} ({})", p.db, describe_probe(p))
        })
        .collect();
    let selected = match checkbox_search("Select DBs to save", &labels, Some(12)) {
        Ok(s) => s,
        Err(e) => match exit_err(e) {
            Some(err) => return Err(err),
            None => labels.clone(), // non-interactive fallback: save all detected
        },
    };
    Ok(selected
        .iter()
        .filter_map(|label| labels.iter().position(|l| l == label).map(|i| non_empty[i]))
        .map(|p| RedisDatabaseSpec {
            db: p.db,
            name: Some(if p.suggested_roles.contains(&RedisRole::Bullmq) { "queues" } else { "cache" }.into()),
            roles: p.suggested_roles.clone(),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Live probe
// ---------------------------------------------------------------------------

fn sentry_client(token: &str, org: &str, project: &str, base_url: &str) -> SentryClient {
    SentryClient::new(SentryClientOpts {
        auth_token: token.into(),
        org: org.into(),
        project: project.into(),
        base_url: Some(base_url.into()),
        ..Default::default()
    })
}

/// Deserialize a JSON patch into a typed config (zod `parse` equivalent: strips unknown keys,
/// applies defaults) and serialize it back, preserving the struct's field order.
fn reparse<T: DeserializeOwned + Serialize>(v: Value) -> Result<(T, Map<String, Value>)> {
    let typed: T = serde_json::from_value(v)?;
    let back = match horus_core::json::to_js_value(&typed)? {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    Ok((typed, back))
}

fn drop_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).collect()),
        other => other,
    }
}

fn runtime_raw(o: &ConnectOpts) -> Result<Value> {
    let list = |v: &Option<String>| v.as_deref().map(split_list);
    let queries: Option<Value> = match &o.queries {
        Some(q) => Some(serde_json::from_str(q)?),
        None => None,
    };
    Ok(drop_nulls(json!({
        "url": o.url, "token": o.token, "queries": queries, "namespaceId": o.namespace_id,
        "queues": list(&o.queues), "brokers": list(&o.brokers), "topics": list(&o.topics), "groups": list(&o.groups),
        "ssl": o.ssl, "username": o.username, "password": o.password, "mechanism": o.mechanism, "project": o.project,
        "database": o.database, "collections": list(&o.collections), "tables": list(&o.tables), "schema": o.schema,
        "executable": o.executable,
    })))
}

fn build_runtime_patch(kind: &str, o: &ConnectOpts) -> Result<Map<String, Value>> {
    let raw = runtime_raw(o)?;
    let mut issues = Issues::default();
    let patch = match kind {
        "prometheus" => {
            let (c, m) = reparse::<horus_core::PrometheusConfig>(raw)?;
            horus_core::validate_prometheus(&mut issues, &c);
            m
        }
        "azure-service-bus" => {
            let (c, m) = reparse::<horus_core::AzureServiceBusConfig>(raw)?;
            horus_core::validate_azure_service_bus(&mut issues, &c);
            m
        }
        "kafka" => {
            let (c, m) = reparse::<horus_core::KafkaConfig>(raw)?;
            horus_core::validate_kafka(&mut issues, &c);
            m
        }
        "firestore" => {
            let (c, m) = reparse::<horus_core::FirestoreConfig>(raw)?;
            horus_core::validate_firestore(&mut issues, &c);
            m
        }
        _ => {
            let (c, m) = reparse::<horus_core::SqlServerConfig>(raw)?;
            horus_core::validate_sqlserver(&mut issues, &c);
            m
        }
    };
    issues_to_error(&issues)?;
    Ok(patch)
}

fn cloud_log_config(kind: &str, o: &ConnectOpts) -> Result<(CloudLogConfig, Map<String, Value>)> {
    let raw = drop_nulls(json!({
        "workspace": o.workspace, "subscription": o.subscription,
        "tables": o.tables.as_deref().map(|t| t.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>()),
        "region": o.region, "logGroup": o.log_group, "profile": o.profile, "project": o.project,
        "filter": o.filter, "executable": o.executable,
    }));
    let mut issues = Issues::default();
    let out = match kind {
        "azure-monitor" => {
            let (c, m) = reparse::<horus_core::AzureMonitorConfig>(raw)?;
            horus_core::validate_azure_monitor(&mut issues, &c);
            (CloudLogConfig::AzureMonitor(c), m)
        }
        "cloudwatch" => {
            let (c, m) = reparse::<horus_core::CloudWatchConfig>(raw)?;
            horus_core::validate_cloudwatch(&mut issues, &c);
            (CloudLogConfig::CloudWatch(c), m)
        }
        _ => {
            let (c, m) = reparse::<horus_core::GcpLoggingConfig>(raw)?;
            horus_core::validate_gcp_logging(&mut issues, &c);
            (CloudLogConfig::GcpLogging(c), m)
        }
    };
    issues_to_error(&issues)?;
    Ok(out)
}

fn build_cloud_log_patch(kind: &str, o: &ConnectOpts) -> Result<Map<String, Value>> {
    Ok(cloud_log_config(kind, o)?.1)
}

async fn probe(kind: &str, o: &ConnectOpts) -> (bool, String) {
    match probe_inner(kind, o).await {
        Ok(r) => r,
        Err(e) => (false, e.to_string()),
    }
}

async fn probe_inner(kind: &str, o: &ConnectOpts) -> Result<(bool, String)> {
    let h = |h: horus_core::HealthStatus| (h.ok, h.detail);
    Ok(match kind {
        "prometheus" => {
            let c: horus_core::PrometheusConfig = serde_json::from_value(Value::Object(build_runtime_patch(kind, o)?))?;
            h(PrometheusMetricsProvider::new(c)?.health().await)
        }
        "azure-service-bus" => {
            let c: horus_core::AzureServiceBusConfig = serde_json::from_value(Value::Object(build_runtime_patch(kind, o)?))?;
            h(ServiceBusQueueProvider::new(c)?.health().await)
        }
        "kafka" => {
            let c: horus_core::KafkaConfig = serde_json::from_value(Value::Object(build_runtime_patch(kind, o)?))?;
            h(KafkaQueueProvider::new(c)?.health().await)
        }
        "firestore" => {
            let c: horus_core::FirestoreConfig = serde_json::from_value(Value::Object(build_runtime_patch(kind, o)?))?;
            let client = FirestoreStateClient::new(c)?;
            let r = client.health().await;
            client.close().await;
            h(r)
        }
        "sqlserver" => {
            let c: horus_core::SqlServerConfig = serde_json::from_value(Value::Object(build_runtime_patch(kind, o)?))?;
            let client = SqlServerStateClient::new(c)?;
            let r = client.health().await;
            client.close().await;
            h(r)
        }
        "azure-monitor" | "cloudwatch" | "gcp-logging" => h(CloudLogsProvider::new(cloud_log_config(kind, o)?.0)?.health().await),
        "elasticsearch" => {
            let Some(url) = non_empty(&o.url) else { return Ok((true, "skipped (no URL)".into())) };
            let client = ElasticsearchClient::new(ElasticsearchClientOpts {
                base_url: url.into(),
                username: o.username.clone(),
                password: o.password.clone(),
                http: None,
            });
            match tokio::time::timeout(Duration::from_secs(8), client.health()).await {
                Ok(r) => h(r),
                Err(_) => (false, "timed out after 8s".into()),
            }
        }
        "mongodb" => {
            let (Some(url), Some(db)) = (non_empty(&o.url), non_empty(&o.database)) else {
                return Ok((true, "skipped (no URL)".into()));
            };
            let client = MongoStateClient::new(MongoClientOpts {
                url: url.into(),
                database: db.into(),
                allowlist: o.collections.as_deref().map(split_list).unwrap_or_default(),
            });
            let r = client.health().await;
            client.close().await;
            h(r)
        }
        "postgres" => {
            let Some(url) = non_empty(&o.url) else { return Ok((true, "skipped (no URL)".into())) };
            let client = PostgresStateClient::new(PostgresClientOpts {
                url: url.into(),
                schema: o.schema.clone(),
                allowlist: o.tables.as_deref().map(split_list).unwrap_or_default(),
            });
            let r = client.health().await;
            client.close().await;
            h(r)
        }
        "sentry" => {
            let (Some(t), Some(org), Some(p)) = (non_empty(&o.auth_token), non_empty(&o.org), non_empty(&o.project)) else {
                return Ok((true, "skipped (missing org/project/token)".into()));
            };
            let client = SentryClient::new(SentryClientOpts {
                auth_token: t.into(),
                org: org.into(),
                project: p.into(),
                base_url: non_empty(&o.url).map(str::to_string),
                ..Default::default()
            });
            h(client.health().await)
        }
        "axiom" => {
            let (Some(t), Some(ds)) = (non_empty(&o.token), non_empty(&o.dataset)) else {
                return Ok((true, "skipped (missing dataset/token)".into()));
            };
            let client = AxiomClient::new(AxiomClientOpts {
                token: t.into(),
                dataset: ds.into(),
                base_url: non_empty(&o.url).map(str::to_string),
                http: None,
            });
            h(client.health().await)
        }
        "shopify" => {
            let (Some(store), Some(secret)) = (non_empty(&o.store), non_empty(&o.secret)) else {
                return Ok((true, "skipped (missing store/secret)".into()));
            };
            // Auth liveness — runs the Client-Credentials grant; embeds no GraphQL query.
            let client = ShopifyAdminClient::new(ShopifyClientOpts {
                store: store.into(),
                secret: secret.into(),
                access_id: non_empty(&o.access_id).map(str::to_string),
                api_version: non_empty(&o.api_version).map(str::to_string),
                base_url: None,
            });
            h(client.health().await)
        }
        "grafana" => {
            let Some(url) = non_empty(&o.url) else { return Ok((true, "skipped (no URL)".into())) };
            let mut req = reqwest::Client::new()
                .get(format!("{}/api/health", strip_one_slash(url)))
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(5));
            if let (Some(u), Some(p)) = (non_empty(&o.username), non_empty(&o.password)) {
                let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
                req = req.header("Authorization", format!("Basic {encoded}"));
            }
            let res = req.send().await?;
            if res.status().is_success() {
                (true, "Grafana API reachable".into())
            } else {
                (false, format!("HTTP {}", res.status().as_u16()))
            }
        }
        _ => {
            let Some(url) = non_empty(&o.url) else { return Ok((true, "skipped (no URL)".into())) };
            // Real PING (exercises AUTH), not just a TCP open.
            let client = RedisScanClient::new(RedisScanClientOpts { url: url.into(), db: None })?;
            let r = client.health().await;
            client.close().await;
            let parsed = url::Url::parse(url)?;
            let host = parsed.host_str().unwrap_or("").to_string();
            let port = parsed.port().map_or("6379".to_string(), |p| p.to_string());
            if r.ok {
                (true, format!("PING ok at {host}:{port}"))
            } else {
                let d = r.detail.to_lowercase();
                let auth_failed = d.contains("wrongpass") || d.contains("noauth") || d.contains("invalid password");
                (false, if auth_failed { format!("auth failed ({})", r.detail) } else { r.detail })
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn dots(s: &str) -> String {
    "•".repeat(s.chars().count().min(8))
}

fn print_summary(kind: &str, o: &ConnectOpts) {
    let mut lines: Vec<String> = Vec::new();
    if let Some(u) = non_empty(&o.url) {
        let shown = if connector_secret_fields(kind).contains(&"url") {
            "[encrypted connection string]".to_string()
        } else {
            redact_url(u)
        };
        lines.push(format!("  url:            {shown}"));
    }
    if let Some(v) = non_empty(&o.username) {
        lines.push(format!("  username:       {v}"));
    }
    if let Some(v) = non_empty(&o.password) {
        lines.push(format!("  password:       {}", dots(v)));
    }
    match o.index_patterns.as_ref().filter(|p| !p.is_empty()) {
        Some(p) => lines.push(format!("  index-patterns: {}", p.join(", "))),
        None => {
            if let Some(v) = non_empty(&o.index_pattern) {
                lines.push(format!("  index-pattern:  {v}"));
            }
        }
    }
    for (label, v) in [
        ("service:        ", &o.service),
        ("database:       ", &o.database),
        ("collections:    ", &o.collections),
        ("org:            ", &o.org),
        ("project:        ", &o.project),
        ("dataset:        ", &o.dataset),
        ("store:          ", &o.store),
        ("api-version:    ", &o.api_version),
        ("access-id:      ", &o.access_id),
    ] {
        if let Some(v) = non_empty(v) {
            lines.push(format!("  {label}{v}"));
        }
    }
    for (label, v) in [("secret:         ", &o.secret), ("auth-token:     ", &o.auth_token), ("token:          ", &o.token)] {
        if let Some(v) = non_empty(v) {
            lines.push(format!("  {label}{}", dots(v)));
        }
    }
    match o.dashboard_uids.as_ref().filter(|d| !d.is_empty()) {
        Some(d) => lines.push(format!("  dashboards:     {}", d.join(", "))),
        None => {
            if let Some(v) = non_empty(&o.dashboard) {
                lines.push(format!("  dashboard:      {v}"));
            }
        }
    }
    if !lines.is_empty() {
        println!("{}", dim(&lines.join("\n")));
    }
}

/// Resolve the target environment the same way `patch_local_connector` does: `--env` if given
/// (validated), else the first environment in the config.
fn resolve_env_name(config_path: &Path, requested: Option<&str>) -> Result<String> {
    let file = read_local_config(config_path)?;
    let names: Vec<String> = file
        .project
        .get("environments")
        .and_then(Value::as_array)
        .map(|envs| envs.iter().map(|e| e.get("name").and_then(Value::as_str).unwrap_or("").to_string()).collect())
        .unwrap_or_default();
    if let Some(r) = requested.filter(|r| !r.is_empty()) {
        if !names.iter().any(|n| n == r) {
            bail!("Environment \"{r}\" not found in config.");
        }
        return Ok(r.to_string());
    }
    names.into_iter().next().filter(|n| !n.is_empty()).ok_or_else(|| anyhow!("No environments found in config."))
}

// ---------------------------------------------------------------------------
// Discovery helpers
// ---------------------------------------------------------------------------

async fn discover_es_indices(url: Option<&str>, username: Option<&str>, password: Option<&str>) -> Vec<String> {
    let Some(url) = url.filter(|u| !u.is_empty()) else { return vec![] };
    let client = ElasticsearchClient::new(ElasticsearchClientOpts {
        base_url: url.into(),
        username: username.map(str::to_string),
        password: password.map(str::to_string),
        http: None,
    });
    tokio::time::timeout(Duration::from_secs(8), client.list_indices()).await.unwrap_or_default()
}

fn is_number_list(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == ',' || c.is_whitespace())
}

fn numbered_picks<'a, T>(input: &str, shown: &'a [T]) -> Vec<&'a T> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| parse_int_prefix(s).map(|n| n - 1))
        .filter(|i| *i >= 0 && (*i as usize) < shown.len())
        .map(|i| &shown[i as usize])
        .collect()
}

const MAX_DISPLAY: usize = 25;

/// Pick discovered Elasticsearch indexes (checkbox on a TTY; numbered list otherwise). Empty =
/// skipped → caller prompts for a pattern.
pub fn ask_index_selection(indices: &[String]) -> Result<Vec<String>> {
    if is_interactive() {
        match checkbox_search("Select index patterns to use", indices, Some(12)) {
            Ok(v) => return Ok(v),
            Err(e) => {
                if let Some(err) = exit_err(e) {
                    return Err(err);
                }
            }
        }
    }
    let shown = &indices[..indices.len().min(MAX_DISPLAY)];
    println!("\n  Available Elasticsearch indexes/data streams:");
    for (i, name) in shown.iter().enumerate() {
        println!("  {} {name}", dim(&format!("[{}]", i + 1)));
    }
    if indices.len() > MAX_DISPLAY {
        println!(
            "{}",
            dim(&format!("  … and {} more (type a pattern manually to match all)", indices.len() - MAX_DISPLAY))
        );
    }
    let input = ask("  Select index patterns to use (e.g. 1,2 or Enter to type pattern manually)", "", false);
    if input.is_empty() {
        return Ok(vec![]);
    }
    if is_number_list(&input) {
        let picks: Vec<String> = numbered_picks(&input, shown).into_iter().cloned().collect();
        if !picks.is_empty() {
            return Ok(picks);
        }
    }
    // Non-numeric input: a manually-typed pattern.
    Ok(vec![input])
}

/// `(uid, title, folderTitle)`.
type Dashboard = (String, String, Option<String>);

async fn discover_grafana_dashboards(url: Option<&str>, username: Option<&str>, password: Option<&str>) -> Vec<Dashboard> {
    let Some(url) = url.filter(|u| !u.is_empty()) else { return vec![] };
    let client = GrafanaClient::new(GrafanaClientOpts {
        base_url: url.into(),
        username: username.map(str::to_string),
        password: password.map(str::to_string),
        http: None,
    });
    match tokio::time::timeout(Duration::from_secs(8), client.search_dashboards(None)).await {
        Ok(Ok(list)) => list.into_iter().map(|d| (d.uid, d.title, d.folder_title)).collect(),
        _ => vec![],
    }
}

pub fn ask_dashboard_selection(dashboards: &[Dashboard]) -> Result<Vec<Dashboard>> {
    if is_interactive() {
        let titles: Vec<String> = dashboards.iter().map(|d| d.1.clone()).collect();
        match checkbox_search("Select dashboards to use", &titles, Some(12)) {
            Ok(sel) => return Ok(dashboards.iter().filter(|d| sel.contains(&d.1)).cloned().collect()),
            Err(e) => {
                if let Some(err) = exit_err(e) {
                    return Err(err);
                }
            }
        }
    }
    let shown = &dashboards[..dashboards.len().min(MAX_DISPLAY)];
    println!("\n  Available Grafana dashboards:");
    for (i, d) in shown.iter().enumerate() {
        let folder = d.2.as_deref().filter(|f| !f.is_empty()).map(|f| dim(&format!(" ({f})"))).unwrap_or_default();
        println!("  {} {}{folder}", dim(&format!("[{}]", i + 1)), d.1);
    }
    if dashboards.len() > MAX_DISPLAY {
        println!("{}", dim(&format!("  … and {} more", dashboards.len() - MAX_DISPLAY)));
    }
    let input = ask("  Select dashboards to use (e.g. 1,2 or Enter to type uid manually)", "", false);
    if input.is_empty() || !is_number_list(&input) {
        return Ok(vec![]);
    }
    Ok(numbered_picks(&input, shown).into_iter().cloned().collect())
}

/// Single-select the Axiom server / region (US / EU / Custom URL). Non-interactive ⇒ US.
pub fn ask_axiom_region() -> Result<String> {
    const US: &str = "US — api.axiom.co";
    const EU: &str = "EU — api.eu.axiom.co";
    const CUSTOM: &str = "Custom URL…";
    const US_URL: &str = "https://api.axiom.co";
    const EU_URL: &str = "https://api.eu.axiom.co";
    if !is_interactive() {
        return Ok(US_URL.into());
    }
    let choices = [US.to_string(), EU.to_string(), CUSTOM.to_string()];
    let choice = match select_search("Axiom server / region", &choices, Some(3)) {
        Ok(c) => c,
        Err(e) => {
            return match exit_err(e) {
                Some(err) => Err(err),
                None => Ok(US_URL.into()),
            }
        }
    };
    Ok(match choice.as_str() {
        EU => EU_URL.into(),
        CUSTOM => {
            let v = ask("Custom Axiom base URL", US_URL, true);
            if v.is_empty() {
                US_URL.into()
            } else {
                v
            }
        }
        _ => US_URL.into(),
    })
}

/// Pick exactly ONE discovered Axiom dataset; None = skipped (caller prompts manually).
pub fn ask_dataset_selection(names: &[String]) -> Result<Option<String>> {
    if names.is_empty() {
        return Ok(None);
    }
    if is_interactive() {
        match select_search("Select an Axiom dataset", names, Some(12)) {
            Ok(v) => return Ok(Some(v)),
            Err(e) => {
                if let Some(err) = exit_err(e) {
                    return Err(err);
                }
            }
        }
    }
    let shown = &names[..names.len().min(MAX_DISPLAY)];
    println!("\n  Available Axiom datasets:");
    for (i, n) in shown.iter().enumerate() {
        println!("  {} {n}", dim(&format!("[{}]", i + 1)));
    }
    if names.len() > MAX_DISPLAY {
        println!("{}", dim(&format!("  … and {} more", names.len() - MAX_DISPLAY)));
    }
    let input = ask("  Select a dataset (e.g. 1 or Enter to type a name manually)", "", false);
    if input.is_empty() {
        return Ok(None);
    }
    if input.chars().all(|c| c.is_ascii_digit()) {
        if let Some(i) = input.parse::<usize>().ok().and_then(|n| n.checked_sub(1)).filter(|i| *i < shown.len()) {
            return Ok(Some(shown[i].clone()));
        }
    }
    Ok(Some(input))
}

/// Discover-then-select a Sentry org or project; returns the SLUG, or None when the list is
/// empty or the user skips (caller then prompts for the slug manually).
pub fn pick_sentry_resource(label: &str, resources: &[SentryNamedResource]) -> Result<Option<String>> {
    let lower = label.to_lowercase();
    if resources.is_empty() {
        println!(
            "{}",
            yellow(&format!("  Couldn't list {lower}s (check token / org / network) — enter the slug manually."))
        );
        return Ok(None);
    }
    let choice_for =
        |r: &SentryNamedResource| if !r.name.is_empty() && r.name != r.slug { format!("{} ({})", r.name, r.slug) } else { r.slug.clone() };
    let slug_from_choice = |choice: &str| -> String {
        let slug = choice
            .trim_end()
            .strip_suffix(')')
            .and_then(|s| s.rfind('(').map(|i| s[i + 1..].to_string()))
            .filter(|s| !s.contains(')') && !s.is_empty())
            .unwrap_or_else(|| choice.to_string());
        if resources.iter().any(|r| r.slug == slug) {
            slug
        } else {
            choice.to_string()
        }
    };
    if is_interactive() {
        let choices: Vec<String> = resources.iter().map(choice_for).collect();
        match select_search(&format!("Select a {lower}"), &choices, Some(12)) {
            Ok(p) => return Ok(Some(slug_from_choice(&p))),
            Err(e) => {
                if let Some(err) = exit_err(e) {
                    return Err(err);
                }
            }
        }
    }
    let shown = &resources[..resources.len().min(MAX_DISPLAY)];
    println!("\n  Available {lower}s:");
    for (i, r) in shown.iter().enumerate() {
        println!("  {} {}", dim(&format!("[{}]", i + 1)), choice_for(r));
    }
    if resources.len() > MAX_DISPLAY {
        println!("{}", dim(&format!("  … and {} more", resources.len() - MAX_DISPLAY)));
    }
    let input = ask(&format!("  Select a {lower} (e.g. 1, or Enter to type the slug manually)"), "", false);
    if input.is_empty() {
        return Ok(None);
    }
    if input.chars().all(|c| c.is_ascii_digit()) {
        if let Some(i) = input.parse::<usize>().ok().and_then(|n| n.checked_sub(1)).filter(|i| *i < shown.len()) {
            return Ok(Some(shown[i].slug.clone()));
        }
    }
    Ok(Some(input))
}

// ---------------------------------------------------------------------------
// Redis credential helpers
// ---------------------------------------------------------------------------

fn redis_url_has_password(raw: Option<&str>) -> bool {
    raw.and_then(|r| url::Url::parse(r).ok()).is_some_and(|u| u.password().is_some_and(|p| !p.is_empty()))
}

/// JS `encodeURIComponent`.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Inject a password into a Redis URL that has no credentials (`redis://:password@host:port/db`).
fn inject_redis_password(raw: &str, password: &str) -> String {
    let enc = encode_uri_component(password);
    match url::Url::parse(raw) {
        Ok(mut u) => {
            let _ = u.set_password(Some(&enc));
            u.to_string()
        }
        Err(_) => {
            // Not parseable — naive splice after the scheme.
            for scheme in ["rediss://", "redis://"] {
                if let Some(rest) = raw.strip_prefix(scheme).filter(|r| !r.is_empty()) {
                    return format!("{scheme}:{enc}@{rest}");
                }
            }
            raw.to_string()
        }
    }
}

/// Redact `user:pass@` from a URL before displaying it.
fn redact_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            if !u.username().is_empty() || u.password().is_some() {
                let user = if u.username().is_empty() { "" } else { "***" };
                let pass = u.password().filter(|p| !p.is_empty()).map(|_| "***");
                let _ = u.set_username(user);
                let _ = u.set_password(pass);
            }
            u.to_string()
        }
        Err(_) => raw.to_string(),
    }
}
