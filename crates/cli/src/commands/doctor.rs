//! Port of `packages/cli/src/commands/doctor.ts`.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use horus_core::json::to_js_json_pretty;
use horus_core::{
    discover_local_config, find_plaintext_connector_secrets, find_repo_root, is_horus_gitignored, load_config,
    read_local_config, ConnectorsConfig, HORUS_VERSION,
};
use horus_db::check_embedded_db;
use serde::Serialize;
use serde_json::Value;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red, yellow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub label: String,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

fn check(label: &str, status: CheckStatus, detail: String, next: Option<&str>) -> DoctorCheck {
    DoctorCheck { label: label.into(), status, detail, next: next.map(str::to_string) }
}

#[derive(Debug, Serialize)]
pub struct DoctorOutput {
    pub version: String,
    /// True when no check has status 'fail'. Warn-level issues are advisory, not blocking.
    pub ready: bool,
    pub checks: Vec<DoctorCheck>,
    pub summary: Summary,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
}

// ---------------------------------------------------------------------------
// Connector readiness registry (HOR-437)
//
// One entry per connector kind, in the SAME order as the TS `CONNECTOR_CHECKS` object (which
// is also the output order). TS enforces exhaustiveness over `keyof ConnectorsConfig` with a
// mapped type; here `connector_check` matches on every `ConnectorsConfig` field by name, so a
// new connector field is a compile error in `configured_check` until its readiness check exists.
// ---------------------------------------------------------------------------

/// `(key, label, absentNext)` — the "not configured" hint per connector.
const CONNECTOR_KEYS: &[(&str, &str, &str)] = &[
    ("prometheus", "prometheus", "horus connect prometheus"),
    ("azure-service-bus", "azure-service-bus", "horus connect azure-service-bus"),
    ("kafka", "kafka", "horus connect kafka"),
    ("firestore", "firestore", "horus connect firestore"),
    ("sqlserver", "SQL Server", "horus connect sqlserver"),
    ("azure-monitor", "Azure Monitor", "horus connect azure-monitor"),
    ("cloudwatch", "CloudWatch Logs", "horus connect cloudwatch"),
    ("gcp-logging", "Google Cloud Logging", "horus connect gcp-logging"),
    (
        "elasticsearch",
        "Elasticsearch",
        "add connectors.elasticsearch to an environment in your Horus config for runtime log evidence",
    ),
    ("grafana", "Grafana", "add connectors.grafana to an environment for metric evidence"),
    ("mongodb", "MongoDB", "add connectors.mongodb to an environment for database state evidence"),
    ("postgres", "Postgres", "add connectors.postgres to an environment for database state evidence"),
    ("sentry", "Sentry", "add connectors.sentry to an environment for error-tracking evidence"),
    ("axiom", "Axiom", "add connectors.axiom to an environment for structured log evidence"),
    ("shopify", "Shopify", "add connectors.shopify to an environment for Shopify Admin state evidence"),
    ("redis", "Redis", "add connectors.redis to an environment for queue state evidence"),
];

/// JS truthiness for an optional string: present and non-empty.
fn truthy(v: &Option<String>) -> bool {
    v.as_deref().is_some_and(|s| !s.is_empty())
}

/// `direct || process.env[envName ?? default]`
fn secret_set(direct: &Option<String>, env_name: &Option<String>, default: &str) -> bool {
    truthy(direct) || truthy(&std::env::var(env_name.as_deref().unwrap_or(default)).ok())
}

fn configured_note(label: &str, ctx: &str) -> DoctorCheck {
    check(label, CheckStatus::Pass, format!("{ctx} — configured; run horus status to verify read access"), None)
}

/// The readiness check for `key` in one environment, or None when that connector is absent.
fn configured_check(key: &str, c: &ConnectorsConfig, ctx: &str) -> Option<DoctorCheck> {
    use CheckStatus::*;
    let pending = "[runtime ingestion pending]";
    Some(match key {
        "prometheus" => configured_note("prometheus", ctx).into_option(c.prometheus.is_some())?,
        "azure-service-bus" => configured_note("azure-service-bus", ctx).into_option(c.azure_service_bus.is_some())?,
        "kafka" => configured_note("kafka", ctx).into_option(c.kafka.is_some())?,
        "firestore" => configured_note("firestore", ctx).into_option(c.firestore.is_some())?,
        "sqlserver" => {
            let s = c.sqlserver.as_ref()?;
            let ok = truthy(&s.url);
            check(
                "SQL Server",
                if ok { Pass } else { Warn },
                format!(
                    "{ctx} — {}",
                    if ok { "configured; run horus status to verify read access" } else { "connection string unavailable" }
                ),
                None,
            )
        }
        "azure-monitor" => {
            let a = c.azure_monitor.as_ref()?;
            check("Azure Monitor", Pass, format!("{ctx} — {}; local vendor login required, run horus status", a.workspace), None)
        }
        "cloudwatch" => {
            let a = c.cloudwatch.as_ref()?;
            check("CloudWatch Logs", Pass, format!("{ctx} — {}; local vendor login required, run horus status", a.log_group), None)
        }
        "gcp-logging" => {
            let a = c.gcp_logging.as_ref()?;
            check("Google Cloud Logging", Pass, format!("{ctx} — {}; local vendor login required, run horus status", a.project), None)
        }
        "elasticsearch" => {
            let es = c.elasticsearch.as_ref()?;
            if !truthy(&es.index_pattern) {
                check("Elasticsearch", Warn, format!("{ctx} — indexPattern not set"), Some("set indexPattern in connectors.elasticsearch"))
            } else {
                check("Elasticsearch", Pass, format!("{ctx} — {} {pending}", es.index_pattern.as_deref().unwrap_or("")), None)
            }
        }
        "grafana" => {
            let g = c.grafana.as_ref()?;
            if !truthy(&g.url) {
                check("Grafana", Warn, format!("{ctx} — URL not set"), Some("set grafana.url or grafana.urlEnv in your Horus config"))
            } else {
                let dash = g.dashboard.as_deref().filter(|d| !d.is_empty()).map(|d| format!(" ({d})")).unwrap_or_default();
                check("Grafana", Pass, format!("{ctx} — URL configured{dash} {pending}"), None)
            }
        }
        "mongodb" => {
            let m = c.mongodb.as_ref()?;
            if !truthy(&m.url) {
                check("MongoDB", Warn, format!("{ctx} — URL not set"), Some("set mongodb.url or mongodb.urlEnv in your Horus config"))
            } else {
                check("MongoDB", Pass, format!("{ctx} — {} {pending}", m.database), None)
            }
        }
        "postgres" => {
            let p = c.postgres.as_ref()?;
            if !truthy(&p.url) {
                check("Postgres", Warn, format!("{ctx} — URL not set"), Some("set postgres.url or postgres.urlEnv in your Horus config"))
            } else {
                let name = p.database.as_deref().or(p.schema.as_deref()).unwrap_or("postgres");
                check("Postgres", Pass, format!("{ctx} — {name} {pending}"), None)
            }
        }
        "sentry" => {
            let s = c.sentry.as_ref()?;
            if !secret_set(&s.auth_token, &s.auth_token_env, "SENTRY_AUTH_TOKEN") {
                check(
                    "Sentry",
                    Warn,
                    format!("{ctx} — auth token not set"),
                    Some("set sentry.authToken or sentry.authTokenEnv (default SENTRY_AUTH_TOKEN) in your Horus config"),
                )
            } else {
                check("Sentry", Pass, format!("{ctx} — {}/{} {pending}", s.org, s.project), None)
            }
        }
        // Axiom (structured logs) — HOR-437: previously omitted from doctor entirely.
        "axiom" => {
            let a = c.axiom.as_ref()?;
            if !secret_set(&a.token, &a.token_env, "AXIOM_TOKEN") {
                check(
                    "Axiom",
                    Warn,
                    format!("{ctx} — API token not set"),
                    Some("set axiom.token or axiom.tokenEnv (default AXIOM_TOKEN) in your Horus config"),
                )
            } else {
                check("Axiom", Pass, format!("{ctx} — {} {pending}", a.dataset), None)
            }
        }
        "shopify" => {
            let s = c.shopify.as_ref()?;
            if !secret_set(&s.secret, &s.secret_env, "SHOPIFY_SECRET") {
                check(
                    "Shopify",
                    Warn,
                    format!("{ctx} — client secret not set"),
                    Some("set shopify.secret or shopify.secretEnv (default SHOPIFY_SECRET), or run horus connect shopify"),
                )
            } else {
                let n = s.queries.as_ref().map_or(0, Vec::len);
                let note = if n > 0 {
                    format!(" ({n} default quer{})", if n == 1 { "y" } else { "ies" })
                } else {
                    " (no default queries — supply --shopify-query at investigate time)".to_string()
                };
                check("Shopify", Pass, format!("{ctx} — {}{note} {pending}", s.store), None)
            }
        }
        "redis" => {
            let r = c.redis.as_ref()?;
            if !truthy(&r.url) {
                check("Redis", Warn, format!("{ctx} — URL not set"), Some("set redis.url or redis.urlEnv in your Horus config"))
            } else {
                check("Redis", Pass, format!("{ctx} — URL configured {pending}"), None)
            }
        }
        _ => unreachable!("connector key {key} missing from doctor registry"),
    })
}

trait IntoOption: Sized {
    fn into_option(self, present: bool) -> Option<Self> {
        present.then_some(self)
    }
}
impl IntoOption for DoctorCheck {}

fn mark(status: CheckStatus) -> String {
    match status {
        CheckStatus::Pass => green("✓"),
        CheckStatus::Warn => yellow("~"),
        CheckStatus::Fail => red("✗"),
    }
}

/// First `project.repositories[].source.hostUrl` that is set.
fn source_host_url(project: &Value) -> Option<&str> {
    project
        .get("repositories")?
        .as_array()?
        .iter()
        .filter_map(|r| r.get("source")?.get("hostUrl")?.as_str())
        .find(|s| !s.is_empty())
}

pub async fn run(args: &DoctorArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let mut checks: Vec<DoctorCheck> = Vec::new();
    use CheckStatus::*;

    checks.push(check("CLI version", Pass, format!("horus {HORUS_VERSION}"), None));

    let repo_root = find_repo_root(&cwd);
    match &repo_root {
        Some(root) => checks.push(check("Git root", Pass, root.display().to_string(), None)),
        None => checks.push(check(
            "Git root",
            Warn,
            "not in a git repository".into(),
            Some("run horus doctor from inside a git repository"),
        )),
    }

    let config_path = discover_local_config(&cwd);
    match &config_path {
        Some(path) => {
            checks.push(check("Local config", Pass, path.display().to_string(), None));
            match read_local_config(path) {
                Ok(file) => match source_host_url(&file.project) {
                    Some(host_url) => checks.push(check("Source-intelligence host", Pass, host_url.into(), None)),
                    None => checks.push(check(
                        "Source-intelligence host",
                        Warn,
                        "not configured".into(),
                        Some("run `horus init` to analyze this repo and start a host"),
                    )),
                },
                Err(_) => checks.push(check(
                    "Source-intelligence host",
                    Warn,
                    "could not read local config".into(),
                    Some("run `horus init` to recreate .horus/config.json for this repo"),
                )),
            }
        }
        None => {
            checks.push(check(
                "Local config",
                Warn,
                ".horus/config.json not found".into(),
                Some("run `horus init` to create one for this repo"),
            ));
            checks.push(check(
                "Source-intelligence host",
                Warn,
                "not configured (no local config)".into(),
                Some("run `horus init` to set up source intelligence"),
            ));
        }
    }

    // Secrets hygiene (HOR-452): `.horus/` must be gitignored, and config.json must not carry
    // plaintext connector credentials.
    if let Some(root) = &repo_root {
        if !is_horus_gitignored(root) {
            checks.push(check(
                "Secrets gitignore",
                Warn,
                ".horus/ is NOT gitignored — credentials could be committed".into(),
                Some("run `horus secrets migrate` (also hardens .gitignore), or add `.horus/` to .gitignore"),
            ));
        } else {
            checks.push(check("Secrets gitignore", Pass, ".horus/ is gitignored".into(), None));
        }
    }
    if let Some(path) = &config_path {
        // Config unreadable → already flagged by the Local config check above.
        if let Ok(file) = read_local_config(path) {
            let plaintext = find_plaintext_connector_secrets(&file.project);
            if !plaintext.is_empty() {
                checks.push(check(
                    "Secret storage",
                    Warn,
                    format!("{} plaintext credential(s) in config.json: {}", plaintext.len(), plaintext.join(", ")),
                    Some("run `horus secrets migrate` to encrypt them and strip config.json"),
                ));
            } else {
                checks.push(check("Secret storage", Pass, "no plaintext credentials in config.json".into(), None));
            }
        }
    }

    // Database check — the embedded local database. No user-run Postgres and DATABASE_URL is
    // ignored; the only failure mode is a build without local persistence (display-only).
    {
        let db = check_embedded_db().await;
        if !db.reachable {
            checks.push(check("Database", Warn, db.reachable_detail, Some("install via npm or Homebrew for local persistence")));
        } else {
            checks.push(check("Database", Pass, db.reachable_detail, None));
        }
    }

    // Runtime connector checks — driven off the connector registry (HOR-437). Every configured
    // connector in every environment gets a readiness line; any connector never configured gets
    // a single "not configured" hint. No loadable global config → skip silently.
    if let Ok(global_config) = load_config(args.config.as_deref().map(Path::new), Some(&cwd)) {
        let mut configured: HashSet<&str> = HashSet::new();
        for project in &global_config.projects {
            for env in &project.environments {
                let ctx = format!("{}/{}", project.name, env.name);
                for (key, _, _) in CONNECTOR_KEYS {
                    if let Some(c) = configured_check(key, &env.connectors, &ctx) {
                        configured.insert(key);
                        checks.push(c);
                    }
                }
            }
        }
        for (key, label, absent_next) in CONNECTOR_KEYS {
            if configured.contains(key) {
                continue;
            }
            checks.push(check(label, Warn, "not configured".into(), Some(absent_next)));
        }
    }

    let has_failure = checks.iter().any(|c| c.status == Fail);

    if args.json {
        let count = |s: CheckStatus| checks.iter().filter(|c| c.status == s).count();
        let summary = Summary { pass: count(Pass), warn: count(Warn), fail: count(Fail) };
        let output = DoctorOutput { version: HORUS_VERSION.into(), ready: !has_failure, checks, summary };
        println!("{}", to_js_json_pretty(&output)?);
        return if has_failure { Err(SilentExit(1).into()) } else { Ok(()) };
    }

    println!("{}", bold("\nHorus readiness check\n"));
    for c in &checks {
        println!("  {} {}  {}", mark(c.status), bold(&format!("{:<26}", c.label)), dim(&c.detail));
        if let Some(next) = &c.next {
            println!("    {}", dim(&format!("→ {next}")));
        }
    }
    println!();
    println!("{}", dim("  Hit a bug or a missing capability? Report it:  horus report"));
    println!();

    if has_failure {
        return Err(SilentExit(1).into());
    }
    Ok(())
}
