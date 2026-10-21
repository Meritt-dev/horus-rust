//! Port of `packages/cli/src/commands/status.ts` — per-environment connector health matrix.
//! `--json` emits ONE compact, always-parseable object on stdout (agent contract).

use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use horus_connectors::{
    additional_queues_for_env, additional_state_for_env, axiom_for_env, check_source_compatibility, cloud_logs_for_env,
    logs_for_env, metrics_for_env, mongo_for_env, postgres_for_env, redis_server_status, sentry_for_env, shopify_for_env,
    Provider, StateProvider,
};
use horus_connectors::prometheus::PrometheusMetricsProvider;
use horus_connectors::source::{SourceClientOptions, SourceHttpClient};
use horus_core::json::to_js_json_pretty;
use horus_core::{
    list_environments, load_config, resolve_environment, HorusConfig, ResolveOptions, ResolvedEnvironment, HORUS_VERSION,
    PINNED_SOURCE_VERSION,
};
use horus_db::check_embedded_db;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red, yellow};

/// `true`/`false`/`pending` — the TS `boolean | 'pending'`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ok3 {
    Yes,
    No,
    Pending,
}

impl From<bool> for Ok3 {
    fn from(b: bool) -> Self {
        if b { Ok3::Yes } else { Ok3::No }
    }
}

fn mark(ok: Ok3) -> String {
    match ok {
        Ok3::Pending => yellow("○"),
        Ok3::Yes => green("●"),
        Ok3::No => red("●"),
    }
}

fn state(ok: Ok3) -> &'static str {
    match ok {
        Ok3::Pending => "pending",
        Ok3::Yes => "ok",
        Ok3::No => "fail",
    }
}

/// Collects human lines (text mode) or structured checks (`--json`), never both — stdout must
/// stay valid JSON under `--json`.
struct Sink {
    json: Option<Vec<Value>>,
}

impl Sink {
    fn log(&self, line: &str) {
        if self.json.is_none() {
            println!("{line}");
        }
    }
    fn record(&mut self, name: &str, repo: Option<&str>, ok: Ok3, detail: &str, databases: Option<Vec<Value>>) {
        let Some(out) = self.json.as_mut() else { return };
        let mut o = Map::new();
        o.insert("name".into(), json!(name));
        if let Some(r) = repo {
            o.insert("repo".into(), json!(r));
        }
        o.insert("state".into(), json!(state(ok)));
        o.insert("detail".into(), json!(detail));
        if let Some(d) = databases {
            o.insert("databases".into(), Value::Array(d));
        }
        out.push(Value::Object(o));
    }
}

static AUTH_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)WRONGPASS|NOAUTH").unwrap());
static CREDS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"//:?[^@]*@").unwrap());

/// Mask credentials in a Redis URL for safe display.
fn redact_redis_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            if u.password().is_some() {
                let _ = u.set_password(Some("***"));
            }
            if !u.username().is_empty() {
                let _ = u.set_username("***");
            }
            u.to_string()
        }
        Err(_) => CREDS_RE.replace(raw, "//:***@").into_owned(),
    }
}

/// `host:port` for a Redis URL — never includes credentials.
fn redis_server_label(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => format!("{}:{}", u.host_str().unwrap_or(""), u.port().map(|p| p.to_string()).unwrap_or_else(|| "6379".into())),
        Err(_) => redact_redis_url(raw),
    }
}

/// Health for one resolved environment. Returns true when healthy.
async fn check_env(renv: &ResolvedEnvironment, sink: &mut Sink) -> Result<bool> {
    let mut all_ok = true;

    // Additional runtime providers (cloud logs, extra state stores, Kafka/Service Bus).
    let mut extra: Vec<(String, horus_core::HealthStatus)> = Vec::new();
    for p in cloud_logs_for_env(renv)? {
        extra.push((p.id().to_string(), p.health().await));
    }
    for p in additional_state_for_env(renv)? {
        let h = p.health().await;
        p.close().await;
        extra.push((p.id().to_string(), h));
    }
    for p in additional_queues_for_env(renv)? {
        extra.push((p.id().to_string(), p.health().await));
    }
    for (id, h) in extra {
        if !h.ok {
            all_ok = false;
        }
        sink.record(&id, None, h.ok.into(), &h.detail, None);
        sink.log(&format!("  {} {id}: {}", mark(h.ok.into()), h.detail));
    }

    if let Some(p) = &renv.connectors.prometheus {
        let h = PrometheusMetricsProvider::new(p.clone())?.health().await;
        if !h.ok {
            all_ok = false;
        }
        sink.record("prometheus", None, h.ok.into(), &h.detail, None);
        sink.log(&format!("  {} prometheus: {}", mark(h.ok.into()), h.detail));
    }

    sink.log(&format!(
        "  {} / {}{}",
        bold(&renv.project),
        bold(&renv.env),
        if renv.read_only { dim("  (read-only)") } else { String::new() }
    ));

    // Source intelligence — belongs to the project's repositories.
    let src_row = |ok: Ok3, detail: &str| format!("    {} {}          {}", mark(ok), bold("Source"), dim(detail));
    if renv.repositories.is_empty() {
        sink.log(&src_row(Ok3::Pending, "no repositories configured"));
        sink.record("source", None, Ok3::Pending, "no repositories configured", None);
    }
    for repo in &renv.repositories {
        let Some(host) = repo.source_host_url.as_deref().filter(|u| !u.is_empty()) else {
            sink.log(&src_row(Ok3::Pending, &format!("{}: not configured", repo.name)));
            sink.record("source", Some(&repo.name), Ok3::Pending, "not configured", None);
            continue;
        };
        let source = SourceHttpClient::new(SourceClientOptions::new(host));
        let (health, compat) = tokio::join!(source.health(), check_source_compatibility(&source));
        // TS `client.version()` never throws (null on any failure).
        let (version, matches) = match &compat {
            Ok(c) => (c.version.clone(), c.matches),
            Err(_) => (None, false),
        };
        let version_part = match version {
            None => "version unknown".to_string(),
            Some(v) if matches => format!("v{v} (pinned ✓)"),
            Some(v) => format!("v{v} (pinned {PINNED_SOURCE_VERSION} — MISMATCH)"),
        };
        let detail = if health.ok {
            format!("{} · responded {} · {version_part} at {host}", repo.name, health.status)
        } else {
            format!("{} · unreachable at {host}", repo.name)
        };
        sink.log(&src_row(health.ok.into(), &detail));
        sink.record("source", Some(&repo.name), health.ok.into(), &detail, None);
        if !health.ok {
            all_ok = false;
        }
    }

    // Each fixed row: (ok, detail, padded label). The padding differs per state exactly as in
    // the TS template literals, so it is spelled out at each call site.
    let line = |ok: Ok3, label: &str, pad: &str, detail: &str| format!("    {} {}{pad}{}", mark(ok), bold(label), dim(detail));

    // Elasticsearch
    match &renv.connectors.elasticsearch {
        Some(es) => {
            let idx = es.index_patterns.as_ref().map(|p| p.join(", ")).unwrap_or_else(|| es.index_pattern.clone());
            match logs_for_env(renv)? {
                Some(logs) => {
                    let h = logs.health().await;
                    let detail = if h.ok { format!("reachable · index {idx}") } else { format!("unreachable · index {idx}") };
                    sink.log(&line(h.ok.into(), "Elasticsearch", "   ", &detail));
                    sink.record("elasticsearch", None, h.ok.into(), &detail, None);
                    if !h.ok {
                        all_ok = false;
                    }
                }
                None => {
                    let detail = format!("configured (index {idx}) but ES_URL not set");
                    sink.log(&line(Ok3::No, "Elasticsearch", "   ", &detail));
                    sink.record("elasticsearch", None, Ok3::No, &detail, None);
                }
            }
        }
        None => {
            sink.log(&line(Ok3::Pending, "Elasticsearch", "   ", "not configured"));
            sink.record("elasticsearch", None, Ok3::Pending, "not configured", None);
        }
    }

    // Grafana
    match &renv.connectors.grafana {
        Some(g) => match metrics_for_env(renv)? {
            Some(metrics) => {
                let h = metrics.health().await;
                let dash = g.dashboards.as_ref().map(|d| d.join(", ")).or_else(|| g.dashboard.clone());
                let suffix = dash.filter(|d| !d.is_empty()).map(|d| format!(" · dashboards: {d}")).unwrap_or_default();
                let detail = if h.ok { format!("reachable{suffix}") } else { format!("unreachable{suffix}") };
                sink.log(&line(h.ok.into(), "Grafana", "         ", &detail));
                sink.record("grafana", None, h.ok.into(), &detail, None);
                if !h.ok {
                    all_ok = false;
                }
            }
            None => {
                let detail = "configured but GRAFANA_URL not set";
                sink.log(&line(Ok3::Pending, "Grafana", "         ", detail));
                sink.record("grafana", None, Ok3::Pending, detail, None);
            }
        },
        None => {
            sink.log(&line(Ok3::Pending, "Grafana", "         ", "not configured"));
            sink.record("grafana", None, Ok3::Pending, "not configured", None);
        }
    }

    // MongoDB
    match &renv.connectors.mongodb {
        Some(m) => match mongo_for_env(renv) {
            Some(mongo) => {
                let probe = async {
                    let h = mongo.health().await;
                    if !h.ok {
                        return Ok::<_, anyhow::Error>((false, format!("unreachable · db {}", m.database)));
                    }
                    let allowlist =
                        if m.collections.is_empty() { "allowlist: all".to_string() } else { format!("allowlist: {}", m.collections.len()) };
                    let discovered = mongo
                        .list_collections()
                        .await?
                        .map(|c| format!(" · discovered: {} collection(s)", c.len()))
                        .unwrap_or_default();
                    Ok((true, format!("reachable · db {} · {allowlist}{discovered}", m.database)))
                };
                let res = probe.await;
                mongo.close().await;
                let (ok, detail) = res?;
                // TS pads the failing row one space shorter than the passing one.
                sink.log(&line(ok.into(), "MongoDB", if ok { "         " } else { "        " }, &detail));
                sink.record("mongodb", None, ok.into(), &detail, None);
                if !ok {
                    all_ok = false;
                }
            }
            None => {
                let detail = format!("configured (db {}) but Mongo URL not set", m.database);
                sink.log(&line(Ok3::No, "MongoDB", "        ", &detail));
                sink.record("mongodb", None, Ok3::No, &detail, None);
            }
        },
        None => {
            sink.log(&line(Ok3::Pending, "MongoDB", "         ", "not configured"));
            sink.record("mongodb", None, Ok3::Pending, "not configured", None);
        }
    }

    // Postgres (state)
    match &renv.connectors.postgres {
        Some(pc) => {
            let db_name = pc.database.clone().or_else(|| pc.schema.clone()).unwrap_or_else(|| "postgres".into());
            match postgres_for_env(renv) {
                Some(pg) => {
                    let probe = async {
                        let h = pg.health().await;
                        if !h.ok {
                            return Ok::<_, anyhow::Error>((false, format!("unreachable · db {db_name}")));
                        }
                        let allowlist =
                            if pc.tables.is_empty() { "allowlist: all".to_string() } else { format!("allowlist: {}", pc.tables.len()) };
                        let discovered = pg
                            .list_collections()
                            .await?
                            .map(|c| format!(" · discovered: {} table(s)", c.len()))
                            .unwrap_or_default();
                        Ok((true, format!("reachable · db {db_name} · {allowlist}{discovered}")))
                    };
                    let res = probe.await;
                    pg.close().await;
                    let (ok, detail) = res?;
                    sink.log(&line(ok.into(), "Postgres", if ok { "        " } else { "       " }, &detail));
                    sink.record("postgres", None, ok.into(), &detail, None);
                    if !ok {
                        all_ok = false;
                    }
                }
                None => {
                    let detail = format!("configured (db {db_name}) but Postgres URL not set");
                    sink.log(&line(Ok3::No, "Postgres", "       ", &detail));
                    sink.record("postgres", None, Ok3::No, &detail, None);
                }
            }
        }
        None => {
            sink.log(&line(Ok3::Pending, "Postgres", "        ", "not configured"));
            sink.record("postgres", None, Ok3::Pending, "not configured", None);
        }
    }

    // Sentry / Axiom / Shopify — simple reachability probes with the same row shape.
    async fn probe(p: Option<&dyn Provider>) -> Option<bool> {
        match p {
            Some(p) => Some(p.health().await.ok),
            None => None,
        }
    }
    let sentry = sentry_for_env(renv);
    let axiom = axiom_for_env(renv);
    let shopify = shopify_for_env(renv);
    let simple: [(&str, &str, Option<String>, Option<&dyn Provider>, &str, [&str; 2]); 3] = [
        (
            "sentry",
            "Sentry",
            renv.connectors.sentry.as_ref().map(|s| format!("{}/{}", s.org, s.project)),
            sentry.as_ref().map(|p| p as &dyn Provider),
            "auth token not set",
            ["          ", "         "],
        ),
        (
            "axiom",
            "Axiom",
            renv.connectors.axiom.as_ref().map(|a| if a.dataset.is_empty() { "(no dataset)".into() } else { a.dataset.clone() }),
            axiom.as_ref().map(|p| p as &dyn Provider),
            "API token not set",
            ["           ", "          "],
        ),
        (
            "shopify",
            "Shopify",
            renv.connectors.shopify.as_ref().map(|s| if s.store.is_empty() { "(no store)".into() } else { s.store.clone() }),
            shopify.as_ref().map(|p| p as &dyn Provider),
            "client secret not set",
            ["         ", "        "],
        ),
    ];
    for (name, label, cfg_label, provider, missing, [pad_ok, pad_fail]) in simple {
        match cfg_label {
            None => {
                sink.log(&line(Ok3::Pending, label, pad_ok, "not configured"));
                sink.record(name, None, Ok3::Pending, "not configured", None);
            }
            Some(lbl) => match probe(provider).await {
                Some(true) => {
                    let detail = format!("reachable · {lbl}");
                    sink.log(&line(Ok3::Yes, label, pad_ok, &detail));
                    sink.record(name, None, Ok3::Yes, &detail, None);
                }
                Some(false) => {
                    let detail = format!("unreachable · {lbl}");
                    sink.log(&line(Ok3::No, label, pad_fail, &detail));
                    sink.record(name, None, Ok3::No, &detail, None);
                    all_ok = false;
                }
                None => {
                    let detail = format!("configured ({lbl}) but {missing}");
                    sink.log(&line(Ok3::No, label, pad_fail, &detail));
                    sink.record(name, None, Ok3::No, &detail, None);
                }
            },
        }
    }

    // Redis — server line plus a per-logical-DB breakdown (HOR-201).
    match renv.connectors.redis.as_ref().and_then(|r| r.url.as_deref()).filter(|u| !u.is_empty()) {
        Some(url) => {
            let server = redis_server_label(url);
            match redis_server_status(renv).await? {
                None => {
                    let detail = format!("configured · {server}");
                    sink.log(&line(Ok3::Pending, "Redis", "           ", &detail));
                    sink.record("redis", None, Ok3::Pending, &detail, None);
                }
                Some(status) if !status.reachable => {
                    let detail = format!("{} · {server}", if status.auth_failed { "auth failed" } else { "unreachable" });
                    sink.log(&line(Ok3::No, "Redis", "           ", &detail));
                    sink.record("redis", None, Ok3::No, &detail, None);
                    all_ok = false;
                }
                Some(status) => {
                    let detail = format!("reachable · {server}");
                    sink.log(&line(Ok3::Yes, "Redis", "           ", &detail));
                    let mut databases = Vec::new();
                    for d in &status.databases {
                        let roles: Vec<&str> = d.roles.iter().map(|r| r.as_str()).collect();
                        let role_label = if roles.is_empty() { "unrolled".to_string() } else { roles.join("/") };
                        let name = d.name.as_ref().map(|n| format!(" {n}")).unwrap_or_default();
                        let ddetail = if !d.reachable {
                            if AUTH_RE.is_match(d.detail.as_deref().unwrap_or("")) { "auth failed".to_string() } else { "unreachable".to_string() }
                        } else if let Some(q) = d.queue_count {
                            format!("{q} queue(s), prefix {}", d.bullmq_prefix.as_deref().unwrap_or("undefined"))
                        } else {
                            format!("{} key(s)", d.key_count.unwrap_or(0))
                        };
                        sink.log(&format!(
                            "      {} {}{name} {}",
                            mark(d.reachable.into()),
                            bold(&format!("DB {}", d.db)),
                            dim(&format!("{role_label} · {ddetail}"))
                        ));
                        let mut o = Map::new();
                        o.insert("db".into(), json!(d.db));
                        if let Some(n) = &d.name {
                            o.insert("name".into(), json!(n));
                        }
                        o.insert("roles".into(), json!(roles));
                        o.insert("reachable".into(), json!(d.reachable));
                        if let Some(q) = d.queue_count {
                            o.insert("queueCount".into(), json!(q));
                        }
                        if let Some(k) = d.key_count {
                            o.insert("keyCount".into(), json!(k));
                        }
                        databases.push(Value::Object(o));
                    }
                    sink.record("redis", None, Ok3::Yes, &detail, Some(databases));
                }
            }
        }
        None => {
            sink.log(&line(Ok3::Pending, "Redis", "           ", "not configured"));
            sink.record("redis", None, Ok3::Pending, "not configured", None);
        }
    }

    sink.log("");
    Ok(all_ok)
}

fn print_json(v: &Value) {
    println!("{}", to_js_json_pretty(v).unwrap_or_default());
}

fn env_json(renv: &ResolvedEnvironment, healthy: bool, checks: Vec<Value>) -> Value {
    let mut o = Map::new();
    o.insert("project".into(), json!(renv.project));
    o.insert("env".into(), json!(renv.env));
    if renv.read_only {
        o.insert("readOnly".into(), json!(true));
    }
    o.insert("healthy".into(), json!(healthy));
    o.insert("checks".into(), Value::Array(checks));
    Value::Object(o)
}

pub async fn run(args: &StatusArgs) -> Result<()> {
    let json_mode = args.json;

    if !json_mode {
        println!("{}", bold(&format!("\nHorus {HORUS_VERSION}")));
        println!("{}", dim(&format!("pinned backend: {PINNED_SOURCE_VERSION} · transport: HTTP/MCP only\n")));
    }

    let (config, config_detail): (Option<HorusConfig>, String) = match load_config(args.config.as_deref().map(Path::new), None) {
        Ok(c) => (Some(c), "loaded & valid".into()),
        Err(e) => (None, format!("{e:#}")),
    };

    // Compact JSON contract: key order version, pinnedSource, config, environments, healthy,
    // then `database` (assigned after the literal in TS, so it serializes last).
    let mut out = Map::new();
    out.insert("version".into(), json!(HORUS_VERSION));
    out.insert("pinnedSource".into(), json!(PINNED_SOURCE_VERSION));
    out.insert("config".into(), json!({ "ok": config.is_some(), "detail": config_detail }));
    out.insert("environments".into(), json!([]));
    out.insert("healthy".into(), json!(true));
    let push_env = |out: &mut Map<String, Value>, v: Value| {
        if let Some(Value::Array(a)) = out.get_mut("environments") {
            a.push(v);
        }
    };

    if !json_mode {
        println!("  {} {}  {}", mark(config.is_some().into()), bold("Config"), dim(&config_detail));
    }

    let Some(config) = config else {
        if json_mode {
            out.insert("healthy".into(), json!(false));
            print_json(&Value::Object(out));
        } else {
            println!();
        }
        return Err(SilentExit(1).into());
    };

    // --- Embedded local database (always shown, not project-scoped) ---
    let h = check_embedded_db().await;
    if json_mode {
        out.insert(
            "database".into(),
            json!({ "reachable": h.reachable, "schemaReady": h.schema_ready, "detail": h.reachable_detail, "schemaDetail": h.schema_detail }),
        );
    } else {
        println!("  {} {}  {}", mark(h.reachable.into()), bold("Database"), dim(&h.reachable_detail));
        println!();
    }

    // --- Project / environment matrix ---
    let env_list = list_environments(&config);
    if env_list.is_empty() {
        if json_mode {
            print_json(&Value::Object(out));
        } else {
            println!("{}", dim("  No projects configured.\n"));
        }
        return Ok(());
    }

    if let Some(env) = args.env.as_deref() {
        // Focused: single env.
        let renv = match resolve_environment(&config, &ResolveOptions { env: Some(env), ..Default::default() }) {
            Ok(r) => r,
            Err(e) => {
                if json_mode {
                    out.insert("healthy".into(), json!(false));
                    push_env(&mut out, json!({ "project": "", "env": env, "healthy": false, "error": format!("{e:#}") }));
                    print_json(&Value::Object(out));
                } else {
                    eprintln!("{}", red(&format!("{e:#}")));
                }
                return Err(SilentExit(1).into());
            }
        };
        let mut sink = Sink { json: json_mode.then(Vec::new) };
        let ok = check_env(&renv, &mut sink).await?;
        if let Some(checks) = sink.json {
            push_env(&mut out, env_json(&renv, ok, checks));
            out.insert("healthy".into(), json!(ok));
            print_json(&Value::Object(out));
        }
        return if ok { Ok(()) } else { Err(SilentExit(1).into()) };
    }

    // Matrix: all environments.
    let mut all_healthy = true;
    for pe in &env_list {
        let renv = match resolve_environment(&config, &ResolveOptions { project: Some(&pe.project), env: Some(&pe.env), cwd: None }) {
            Ok(r) => r,
            Err(e) => {
                if json_mode {
                    push_env(&mut out, json!({ "project": pe.project, "env": pe.env, "healthy": false, "error": format!("{e:#}") }));
                } else {
                    eprintln!("{}", red(&format!("  {}/{}: {e:#}", pe.project, pe.env)));
                }
                all_healthy = false;
                continue;
            }
        };
        let mut sink = Sink { json: json_mode.then(Vec::new) };
        let ok = check_env(&renv, &mut sink).await?;
        if let Some(checks) = sink.json {
            push_env(&mut out, env_json(&renv, ok, checks));
        }
        if !ok {
            all_healthy = false;
        }
    }

    if json_mode {
        out.insert("healthy".into(), json!(all_healthy));
        print_json(&Value::Object(out));
    }
    // Unreachable providers are warnings in matrix mode; only a bad config exits non-zero.
    Ok(())
}
