//! Durable unattended watcher: supervisor loop, per-job worker, status and operational notices.
//! Port of `packages/cli/src/lib/watch-service.ts`.
//!
//! The supervisor (`horus service run`) polls each enabled project's alert source, accepts
//! events into the durable queue, and runs ONE job at a time in a bounded worker subprocess
//! (`horus service worker --job`). The worker checkpoints each stage (engine → ai → upload →
//! notify → complete → done) so a crash or retry never repeats finished inference.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use chrono::{SecondsFormat, Utc};
use futures::FutureExt;
use horus_connectors::elasticsearch::{LogLevel, LogQuery, LogRecord, LogsProvider};
use horus_connectors::sentry::SentryIssue;
use horus_connectors::{logs_for_env, sentry_for_env};
use horus_core::{load_config, redact_error_message, resolve_environment, NotifyConfig, NotifyWebhook, ResolveOptions};
use horus_db::{acquire_db_lock, create_local_db, get_investigation, local_db_path, DbHandle};
use horus_engine::types::{
    AICitation, Diagnosis, FixPr, FixPrStatus, InvestigationReport, StoredAIJudgment, Unattended, UnattendedStatus,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::lib::claude_investigation::{interpret_incident, run_process, IncidentResult, RunOptions, IPC_PREFIX};
use crate::lib::cloud::api::{CloudError, NotifyInvestigationInput, ServiceNoticeInput};
use crate::lib::cloud::investigation_sync::{upload_investigation_to_cloud, UploadOpts};
use crate::lib::cloud::memory_sync::{memory_sync_context, sync_linked_memory, MemorySyncContext, MemorySyncOptions};
use crate::lib::investigation_runner::{
    build_investigation_context, dispose_investigation_context, run_one_investigation_with, BuildContextOptions,
    InvestigationContext, RunInvestigationInput,
};
use crate::lib::incident_followups::{check_key, collect_incident_check, incident_window_check, FollowupContext};
use crate::lib::incident_repair::{repair_eligible, repair_incident, FixPrConfig, RepairOptions};
use crate::lib::notify_sink::{dispatch_notify, notification_cause, AiNotice, DispatchReport, NoPush};
use crate::lib::watch_store::{
    accept_events, accept_events_with_state, digest, is_iso_datetime, jobs, parse_ms, read_watch_state,
    redact_value, save_job, save_job_conn, write_watch_state, CloudClaim, IncidentEvent, JobNotice, WatchJobData,
};
use crate::lib::worker_activity::{
    activity_event, activity_path, claude_activity_args, read_activity, worker_run_logs, RunLogResult, WorkerActivity,
};

// ── Config ──────────────────────────────────────────────────────────────────

fn default_interval() -> i64 {
    60
}
fn default_deadline() -> i64 {
    300
}
fn default_web_url() -> String {
    "https://cloud.horus.sh".into()
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchProject {
    pub root: String,
    pub config: String,
    pub project: String,
    pub environment: String,
    /// `sentry` | `elasticsearch` | `pagerduty` | `auto`.
    pub source: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// `off` | `configured`.
    pub notifications: String,
    #[serde(default)]
    pub idempotent_destination: bool,
    /// Runtime identity scoped to this project/environment; PagerDuty display names are not log services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_service: Option<String>,
    /// Presence explicitly authorizes draft PR publication in this repository only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_pr: Option<FixPrConfig>,
}

/// `serviceConfigSchema` (strict).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub claude: String,
    pub runtime: String,
    pub entry: String,
    #[serde(default)]
    pub runtime_args: Vec<String>,
    #[serde(default = "default_interval")]
    pub interval_seconds: i64,
    #[serde(default = "default_deadline")]
    pub deadline_seconds: i64,
    /// Pilot caps are selected during activation; no invented permanent daily allowance.
    pub daily_investigations: i64,
    pub daily_model_calls: i64,
    #[serde(default = "default_web_url")]
    pub cloud_web_url: String,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    pub projects: Vec<WatchProject>,
}

impl ServiceConfig {
    fn validate(&self) -> Result<()> {
        let abs = |p: &str| Path::new(p).is_absolute();
        if !abs(&self.claude) || !abs(&self.runtime) || !abs(&self.entry) {
            bail!("Absolute path required");
        }
        if !(10..=3600).contains(&self.interval_seconds) || !(10..=1800).contains(&self.deadline_seconds) {
            bail!("Invalid service interval/deadline");
        }
        if self.daily_investigations <= 0 || self.daily_model_calls <= 0 {
            bail!("Daily limits must be positive");
        }
        if url::Url::parse(&self.cloud_web_url).is_err() {
            bail!("Invalid cloudWebUrl");
        }
        if self.projects.is_empty() || self.projects.len() > 50 {
            bail!("Projects must contain 1 to 50 entries");
        }
        for p in &self.projects {
            if !abs(&p.root) || !abs(&p.config) {
                bail!("Absolute path required");
            }
            if p.project.is_empty() || p.environment.is_empty() {
                bail!("Project and environment are required");
            }
            if !["sentry", "elasticsearch", "pagerduty", "auto"].contains(&p.source.as_str())
                || !["off", "configured"].contains(&p.notifications.as_str())
            {
                bail!("Invalid project source/notifications");
            }
            if p.runtime_service.as_deref().is_some_and(|s| !(1..=200).contains(&s.chars().count())) {
                bail!("Invalid runtimeService");
            }
            if let Some(f) = &p.fix_pr {
                f.validate()?;
            }
        }
        Ok(())
    }

    /// Worker argv: `[...runtimeArgs, entry, ...rest]`. A native Rust binary has no script
    /// entry: when `entry` IS the runtime it is omitted (DIVERGENCES.md).
    pub fn command_args(&self, rest: &[&str]) -> Vec<String> {
        let mut args = self.runtime_args.clone();
        if self.entry != self.runtime {
            args.push(self.entry.clone());
        }
        args.extend(rest.iter().map(|s| s.to_string()));
        args
    }
}

pub fn service_home() -> PathBuf {
    let base = std::env::var("HORUS_SERVICE_DIR")
        .or_else(|_| std::env::var("HORUS_HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_default().join(".horus"));
    base.join("service")
}

pub fn route_key(p: &WatchProject) -> String {
    digest(&[&p.root, &p.project, &p.environment])
}

pub fn read_service_config(path: &Path) -> Result<ServiceConfig> {
    let config: ServiceConfig = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    config.validate()?;
    let mut routes: Vec<String> = config.projects.iter().map(route_key).collect();
    routes.sort();
    routes.dedup();
    if routes.len() != config.projects.len() {
        bail!("Duplicate project/environment routes");
    }
    Ok(config)
}

async fn with_db() -> Result<DbHandle> {
    create_local_db(None).await
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn today() -> String {
    now_iso()[..10].to_string()
}

fn ensure_private_dir(dir: &Path) {
    let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
}

fn redact_err(e: &dyn std::fmt::Display) -> String {
    redact_error_message(e)
}

fn log(message: &str) {
    let home = service_home();
    ensure_private_dir(&home);
    let file = home.join("service.log");
    // Omit oversized diagnostics before regex redaction; cutting a credential mid-value could
    // expose it, and unbounded redaction can stall the supervisor.
    let safe = if message.len() > 8192 {
        "[truncated] Diagnostic exceeded 8192 characters".to_string()
    } else {
        redact_err(&message)
    };
    let line = format!("{} {safe}\n", now_iso());
    if std::fs::metadata(&file).is_ok_and(|m| m.len() + line.len() as u64 > 1_000_000) {
        let _ = std::fs::rename(&file, home.join("service.log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&file) {
        let _ = f.write_all(line.as_bytes());
    }
}

pub fn record_service_failure(error: &anyhow::Error) {
    let _ = finish_supervisor("fatal", None);
    log(&format!("Supervisor stopped: {error}"));
}

// ── status.json + supervisor history ─────────────────────────────────────────

fn status_path() -> PathBuf {
    service_home().join("status.json")
}

fn read_status() -> Map<String, Value> {
    let file = status_path();
    if std::fs::metadata(&file).map_or(true, |m| m.len() > 1_000_000) {
        return Map::new();
    }
    match std::fs::read_to_string(&file).ok().and_then(|r| serde_json::from_str::<Value>(&r).ok()) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

fn write_status(status: &Value) -> Result<()> {
    let home = service_home();
    ensure_private_dir(&home);
    let tmp = home.join("status.tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(horus_core::json::to_js_json(status)?.as_bytes())?;
    std::fs::rename(tmp, home.join("status.json"))?;
    Ok(())
}

/// `exitSchema` (strict).
fn valid_exit(v: &Value) -> bool {
    let Some(o) = v.as_object() else { return false };
    o.keys().all(|k| ["at", "reason", "signal"].contains(&k.as_str()))
        && o.get("at").and_then(Value::as_str).is_some_and(is_iso_datetime)
        && o.get("reason").and_then(Value::as_str).is_some_and(|r| ["signal", "completed", "fatal", "unrecorded"].contains(&r))
        && o.get("signal").map_or(true, |s| s.as_str().is_some_and(|s| ["SIGTERM", "SIGINT"].contains(&s)))
}

/// `supervisorSchema.safeParse` — the parsed object, or None.
fn parse_supervisor(v: Option<&Value>) -> Option<Map<String, Value>> {
    static SHA: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").unwrap());
    let o = v?.as_object()?;
    let ok = o.keys().all(|k| ["startedAt", "runtimeSha256", "restartCount", "previousExit", "currentExit"].contains(&k.as_str()))
        && o.get("startedAt").and_then(Value::as_str).is_some_and(is_iso_datetime)
        && o.get("runtimeSha256").map_or(true, |s| s.as_str().is_some_and(|s| SHA.is_match(s)))
        && o.get("restartCount").and_then(Value::as_f64).is_some_and(|n| n.fract() == 0.0 && (0.0..=1_000_000.0).contains(&n))
        && o.get("previousExit").is_some_and(|p| p.is_null() || valid_exit(p))
        && o.get("currentExit").map_or(true, valid_exit);
    ok.then(|| o.clone())
}

pub fn summarize_service_sync(status: Option<&Value>) -> Option<Value> {
    let s = status?.as_object()?;
    let mut out = Map::new();
    for k in ["state", "eligible", "synced", "pending", "excluded", "failed", "lastPull", "lastPush", "oldestPending"] {
        if let Some(v) = s.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    out.insert("conflictsTotal".into(), json!(s.get("conflicts").and_then(Value::as_array).map_or(0, Vec::len)));
    if let Some(e) = s.get("error").and_then(Value::as_str).filter(|e| !e.is_empty()) {
        out.insert("error".into(), json!(redact_err(&e).chars().take(200).collect::<String>()));
    }
    Some(Value::Object(out))
}

/// Status is a bounded projection; complete results and history remain in the DB.
pub fn summarize_service_jobs(list: &[WatchJobData]) -> Map<String, Value> {
    let skip = list.len().saturating_sub(20);
    let jobs: Vec<Value> = list[skip..]
        .iter()
        .map(|job| {
            let mut m = Map::new();
            m.insert("id".into(), json!(job.id));
            m.insert("reportId".into(), json!(job.report_id));
            m.insert("createdAt".into(), json!(job.created_at));
            m.insert("stage".into(), json!(job.stage));
            m.insert("status".into(), json!(job.status));
            if let Some(e) = job.error.as_deref().filter(|e| !e.is_empty()) {
                m.insert("error".into(), json!(redact_err(&e).chars().take(200).collect::<String>()));
            }
            Value::Object(m)
        })
        .collect();
    let mut out = Map::new();
    out.insert("jobsTotal".into(), json!(list.len()));
    out.insert("jobs".into(), Value::Array(jobs));
    out
}

/// Existing status.json owns supervisor history; children only read its projection.
pub fn supervisor_metadata() -> Option<Value> {
    let mut parsed = parse_supervisor(read_status().get("supervisor"))?;
    parsed.shift_remove("currentExit");
    Some(Value::Object(parsed))
}

pub fn begin_supervisor(entry: &str) -> Result<()> {
    let mut prior = read_status();
    let previous = parse_supervisor(prior.get("supervisor"));
    // Missing identity must not prevent diagnostics for a bad entry.
    let runtime_sha256 = std::fs::read(entry)
        .ok()
        .map(|b| Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect::<String>());
    let at = now_iso();
    let previous_at = prior
        .get("at")
        .and_then(Value::as_str)
        .and_then(parse_ms)
        .and_then(chrono::DateTime::<Utc>::from_timestamp_millis)
        .map_or_else(|| at.clone(), |t| t.to_rfc3339_opts(SecondsFormat::Millis, true));
    let mut sup = Map::new();
    sup.insert("startedAt".into(), json!(at));
    if let Some(sha) = runtime_sha256 {
        sup.insert("runtimeSha256".into(), json!(sha));
    }
    let restart = previous.as_ref().map_or(0.0, |p| (p["restartCount"].as_f64().unwrap_or(0.0) + 1.0).min(1_000_000.0));
    sup.insert("restartCount".into(), json!(restart as i64));
    sup.insert(
        "previousExit".into(),
        match &previous {
            Some(p) => p.get("currentExit").cloned().unwrap_or_else(|| json!({ "at": previous_at, "reason": "unrecorded" })),
            None => Value::Null,
        },
    );
    prior.insert("at".into(), json!(at));
    prior.insert("pid".into(), json!(std::process::id()));
    prior.insert("activeJob".into(), Value::Null);
    prior.insert("supervisor".into(), Value::Object(sup));
    write_status(&Value::Object(prior))
}

fn finish_supervisor(reason: &str, signal: Option<&str>) -> Result<()> {
    let mut prior = read_status();
    let Some(mut parsed) = parse_supervisor(prior.get("supervisor")) else { return Ok(()) };
    if prior.get("pid").and_then(Value::as_u64) != Some(u64::from(std::process::id())) {
        return Ok(());
    }
    let mut exit = Map::new();
    exit.insert("at".into(), json!(now_iso()));
    exit.insert("reason".into(), json!(reason));
    if let Some(s) = signal {
        exit.insert("signal".into(), json!(s));
    }
    parsed.insert("currentExit".into(), Value::Object(exit));
    prior.insert("at".into(), json!(now_iso()));
    prior.insert("supervisor".into(), Value::Object(parsed));
    write_status(&Value::Object(prior))
}

/// Slack uses Cloud's app; retain explicit generic HTTP receivers for compatibility.
pub fn service_webhook(notify: Option<&NotifyConfig>) -> Result<Option<NotifyWebhook>> {
    let Some(webhook) = notify.and_then(|n| n.webhook.clone()) else { return Ok(None) };
    let host = url::Url::parse(&webhook.url)?.host_str().unwrap_or("").to_lowercase();
    Ok((!["hooks.slack.com", "hooks.slack-gov.com"].contains(&host.as_str())).then_some(webhook))
}

/// Retry-After from a CloudError anywhere in the chain (0 otherwise).
fn retry_after_ms(e: &anyhow::Error) -> i64 {
    match e.downcast_ref::<CloudError>() {
        Some(CloudError::Http { retry_after_ms: Some(ms), .. }) => *ms as i64,
        _ => 0,
    }
}

fn deadline_in(ms: u64) -> Option<Instant> {
    Some(Instant::now() + Duration::from_millis(ms))
}

fn workspace_id(c: &MemorySyncContext) -> String {
    c.config.workspace.as_ref().map(|w| w.id.clone()).unwrap_or_default()
}

fn project_id(c: &MemorySyncContext) -> String {
    c.config.project.as_ref().map(|p| p.id.clone()).unwrap_or_default()
}

/// Delivery is a checkpoint on the existing job; it never retries engine/AI work.
pub async fn deliver_operational_notice(db: &DbHandle, p: &WatchProject, job: &mut WatchJobData) -> Result<()> {
    let Some(notice) = job.notice.clone() else { return Ok(()) };
    if notice.state == "done" || notice.retry_at > now_ms() {
        return Ok(());
    }
    let attempt: Result<()> = async {
        let Some(cloud) = memory_sync_context(Path::new(&p.root), &p.project, deadline_in(5000)) else {
            bail!("Cloud sign-in/link required to deliver the worker notice");
        };
        if read_watch_state::<String>(db, &format!("scope:{}", job.route)).await?.as_deref() != Some(cloud.scope.as_str()) {
            bail!("Watcher account/project scope mismatch; worker notice retained locally");
        }
        let result = cloud
            .client
            .notify_service_notice(
                &project_id(&cloud),
                &ServiceNoticeInput {
                    kind: notice.kind.clone(),
                    environment: p.environment.clone(),
                    job_id: job.id.clone(),
                    day: notice.day.clone(),
                    hint: notice.hint.clone(),
                    cause: notice.cause.clone(),
                },
            )
            .await?;
        if !["off", "delivered"].contains(&result.state.as_str()) {
            bail!("{}", result.error.unwrap_or_else(|| "Invalid worker notice response".into()));
        }
        Ok(())
    }
    .await;
    let n = job.notice.as_mut().expect("notice");
    match attempt {
        Ok(()) => {
            n.state = "done".into();
            n.error = None;
        }
        Err(e) => {
            n.error = Some(redact_err(&e).chars().take(2000).collect());
            n.retry_at = now_ms() + 60_000.max(retry_after_ms(&e));
        }
    }
    save_job(db, job).await
}

fn validated(event: Value) -> Result<IncidentEvent> {
    let e: IncidentEvent = serde_json::from_value(event)?;
    e.validate()?;
    Ok(e)
}

/// JS `String(n)` for a JSON number.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => horus_core::json::to_js_json(other).unwrap_or_default(),
    }
}

pub fn sentry_event(issue: &SentryIssue, environment: &str) -> Result<IncidentEvent> {
    let Some(last_seen) = &issue.last_seen else { bail!("Sentry issue has no occurrence time") };
    let resolved = issue.status.as_deref() == Some("resolved");
    let mut m = Map::new();
    m.insert("source".into(), json!("sentry"));
    m.insert(
        "eventId".into(),
        json!(format!(
            "{}:{last_seen}:{}:{}",
            issue.id,
            js_string(&json!(issue.count)),
            issue.status.as_deref().unwrap_or("undefined")
        )),
    );
    m.insert("incidentId".into(), json!(issue.id));
    m.insert("fingerprint".into(), json!(issue.title));
    m.insert(
        "occurredAt".into(),
        json!(if resolved { issue.last_status_change.clone().unwrap_or_else(now_iso) } else { last_seen.clone() }),
    );
    m.insert("hint".into(), json!(issue.title));
    m.insert("environment".into(), json!(environment));
    if let Some(u) = &issue.permalink {
        m.insert("sourceUrl".into(), json!(u));
    }
    m.insert("severity".into(), json!(issue.level.as_deref().unwrap_or("error")));
    m.insert("state".into(), json!(if resolved { "resolved" } else { "active" }));
    if let Some(ep) = issue.last_status_change.as_ref().or(issue.first_seen.as_ref()) {
        m.insert("episode".into(), json!(ep));
    }
    validated(Value::Object(m))
}

pub fn elastic_event(record: &LogRecord, environment: &str) -> Result<IncidentEvent> {
    static CODE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_.-]{1,128}$").unwrap());
    static CRITICAL: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)exhaust|fatal").unwrap());
    let empty = Map::new();
    let c = record.context.as_ref().unwrap_or(&empty);
    let field = |keys: &[&str]| keys.iter().filter_map(|k| c.get(*k)).find(|v| v.is_string() || v.is_number()).cloned();
    let object = |v: Option<&Value>| v.and_then(Value::as_object).cloned().unwrap_or_default();
    let code = |v: Option<&Value>| v.and_then(Value::as_str).filter(|s| CODE.is_match(s)).map(str::to_string);
    let details = object(object(c.get("data")).get("details"));
    let error_code = code(details.get("code")).or_else(|| code(field(&["errorCode", "error_code"]).as_ref()));
    let reason = code(details.get("reason"));
    let status = c.get("status").and_then(Value::as_f64).filter(|n| n.fract() == 0.0 && (100.0..=599.0).contains(n)).map(|n| n as i64);
    let request_id = record.request_id.clone().or_else(|| code(object(c.get("headers")).get("x-request-id")));
    let order_id = field(&["orderId", "order_id", "orderNumber", "order_number"]).map(|v| js_string(&v));
    let workflow = field(&["workflow", "workflowName", "workflow_name", "operation"]).map(|v| js_string(&v));
    let message_digest = || digest(&record.message);
    let event_id = match &record.document_id {
        Some(id) => format!("{}:{id}", record.index),
        None => digest(&json!([record.index, record.timestamp, record.event_code, record.message, c])),
    };
    let incident_id = order_id
        .clone()
        .or_else(|| record.trace_id.clone())
        .or_else(|| request_id.clone())
        .or_else(|| record.event_code.clone())
        .unwrap_or_else(message_digest);
    let mut fp = vec![record.event_code.clone().unwrap_or_else(message_digest)];
    fp.extend(error_code.clone());
    fp.extend(reason.clone());
    fp.extend(status.map(|s| s.to_string()));
    let tag = if error_code.is_some() || reason.is_some() || status.is_some() {
        let mut parts: Vec<String> = status.map(|s| format!("HTTP {s}")).into_iter().collect();
        parts.extend(error_code.clone().filter(|s| !s.is_empty()));
        parts.extend(reason.clone().filter(|s| !s.is_empty()));
        format!(" [{}]", parts.join("; "))
    } else {
        String::new()
    };
    let hint: String = format!("{} {}{tag}", record.event_code.as_deref().unwrap_or(""), record.message)
        .trim()
        .chars()
        .take(2000)
        .collect();
    let level = js_string(&serde_json::to_value(record.level)?);
    let mut m = Map::new();
    m.insert("source".into(), json!("elasticsearch"));
    m.insert("eventId".into(), json!(event_id));
    m.insert("incidentId".into(), json!(incident_id));
    m.insert("fingerprint".into(), json!(fp.join(":")));
    m.insert("occurredAt".into(), json!(record.timestamp));
    m.insert("hint".into(), json!(hint));
    m.insert("environment".into(), json!(environment));
    if let Some(s) = &record.service {
        m.insert("service".into(), json!(s));
    }
    m.insert("severity".into(), json!(if CRITICAL.is_match(&record.message) { "critical".to_string() } else { level }));
    m.insert("state".into(), json!("active"));
    let opt = |m: &mut Map<String, Value>, k: &str, v: Option<String>| {
        if let Some(v) = v {
            m.insert(k.into(), json!(v));
        }
    };
    opt(&mut m, "orderId", order_id);
    opt(&mut m, "workflow", workflow);
    opt(
        &mut m,
        "correlationId",
        field(&["correlationId", "correlation_id"]).map(|v| js_string(&v)).or_else(|| record.trace_id.clone()).or(request_id),
    );
    opt(&mut m, "eventCode", record.event_code.clone());
    opt(&mut m, "errorCode", error_code);
    opt(&mut m, "operation", field(&["operation"]).map(|v| js_string(&v)));
    validated(Value::Object(m))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Budget {
    investigations: i64,
    model_calls: i64,
}

fn exhausted(usage: Option<&Budget>, limits: &ServiceConfig) -> bool {
    usage.is_some_and(|u| u.investigations >= limits.daily_investigations || u.model_calls >= limits.daily_model_calls)
}

fn heartbeat_body(ctx: &MemorySyncContext, p: &WatchProject, worker_id: &str, state: &str) -> Map<String, Value> {
    let mut b = Map::new();
    b.insert("projectId".into(), json!(project_id(ctx)));
    b.insert("environment".into(), json!(p.environment));
    b.insert("workerId".into(), json!(worker_id));
    b.insert("state".into(), json!(state));
    b
}

fn with_supervisor(mut b: Map<String, Value>) -> Value {
    if let Some(s) = supervisor_metadata() {
        b.insert("supervisor".into(), s);
    }
    Value::Object(b)
}

pub async fn poll_project(p: &WatchProject, worker_id: &str, limits: &ServiceConfig) -> Result<()> {
    let route = route_key(p);
    let root = Path::new(&p.root);
    let config = load_config(Some(Path::new(&p.config)), Some(root))?;
    let env = resolve_environment(
        &config,
        &ResolveOptions { project: Some(&p.project), env: Some(&p.environment), cwd: Some(root) },
    )?;
    if !same_path(&env.path, &p.root) {
        bail!("Configured project root mismatch");
    }
    // CloudClient starts its bounded timeout per request, after local DB work.
    let Some(ctx) = memory_sync_context(root, &p.project, None) else {
        bail!("Sign-in required and Cloud project link required for unattended reports");
    };
    let db = with_db().await?;
    let result = poll_project_inner(p, worker_id, limits, &route, &env, &ctx, &db).await;
    db.end().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn poll_project_inner(
    p: &WatchProject,
    worker_id: &str,
    limits: &ServiceConfig,
    route: &str,
    env: &horus_core::ResolvedEnvironment,
    ctx: &MemorySyncContext,
    db: &DbHandle,
) -> Result<()> {
    let scope_key = format!("scope:{route}");
    if let Some(saved) = read_watch_state::<String>(db, &scope_key).await? {
        if saved != ctx.scope {
            bail!("Cloud account or project changed; drain or explicitly migrate this watcher profile");
        }
    }
    write_watch_state(db, &scope_key, json!(ctx.scope)).await?;
    let usage = read_watch_state::<Budget>(db, &format!("budget:{}", today())).await?;
    let state = if exhausted(usage.as_ref(), limits) { "budget-exhausted" } else { "idle" };
    if let Err(e) = ctx.client.worker_heartbeat(&workspace_id(ctx), &with_supervisor(heartbeat_body(ctx, p, worker_id, state))).await {
        if p.source == "pagerduty" {
            return Err(e.into());
        }
        log(&format!("Cloud offline; local detection continues: {}", redact_err(&e)));
    }
    let active = jobs(db, Some(route)).await?;
    if active.iter().filter(|j| !["done", "cancelled"].contains(&j.status.as_str())).count() >= 500 {
        bail!("Queue cap 500 reached; cursor retained, backlog deferred");
    }
    if p.source == "pagerduty" {
        let sources = ctx.client.list_alert_sources(&workspace_id(ctx)).await?;
        let failing = sources.iter().find(|s| {
            s.provider == "pagerduty"
                && s.enabled
                && s.project_id.as_deref() == Some(project_id(ctx).as_str())
                && s.environment.as_deref() == Some(p.environment.as_str())
                && s.last_error.clone().flatten().is_some_and(|e| !e.is_empty())
        });
        let ingress_error =
            failing.map(|f| anyhow!("PagerDuty ingress degraded: {}", f.last_error.clone().flatten().unwrap_or_default()));
        // Claim only what this single executor can start now. Other requests remain durable in Cloud.
        if active.iter().any(|j| !["done", "cancelled", "terminal-failed"].contains(&j.status.as_str())) {
            return ingress_error.map_or(Ok(()), Err);
        }
        let requests = ctx.client.list_alert_requests(&workspace_id(ctx), &project_id(ctx), &p.environment).await?;
        if ingress_error.is_none() {
            write_watch_state(
                db,
                &format!("health:{route}"),
                json!({ "lastSuccess": now_iso(), "failures": 0, "cloudPending": requests.len() }),
            )
            .await?;
        }
        let Some(request) = requests.first() else { return ingress_error.map_or(Ok(()), Err) };
        if request.environment != p.environment || request.project_id != project_id(ctx) {
            bail!("Cloud event route mismatch");
        }
        let claim = ctx
            .client
            .alert_request(
                &workspace_id(ctx),
                &request.id,
                "claim",
                &json!({ "projectId": project_id(ctx), "environment": p.environment, "workerId": worker_id }),
            )
            .await?;
        let mut payload = claim.payload.clone().unwrap_or_else(|| request.payload.clone());
        let resolved = payload.get("state").and_then(Value::as_str) == Some("resolved");
        payload.insert("hint".into(), json!(claim.hint.clone().unwrap_or_else(|| request.hint.clone())));
        payload.insert("state".into(), json!(if resolved { "resolved" } else { "active" }));
        let event = validated(Value::Object(payload))?;
        if event.environment != p.environment {
            bail!("Cloud event route mismatch");
        }
        accept_events(
            db,
            route,
            vec![event],
            None,
            Some(CloudClaim {
                request_id: request.id.clone(),
                report_id: claim.local_report_id.clone(),
                claim_token: claim.claim_token.clone(),
                worker_id: worker_id.to_string(),
            }),
        )
        .await?;
        // Queue draining is independent of failed ingress enrichment.
        return ingress_error.map_or(Ok(()), Err);
    }
    let source = if p.source == "auto" {
        if env.connectors.sentry.is_some() { "sentry" } else { "elasticsearch" }
    } else {
        p.source.as_str()
    };
    let cursor = read_watch_state::<String>(db, &format!("cursor:{route}")).await?;
    let cursor_ms = cursor.as_deref().and_then(parse_ms);
    let now = now_ms();
    let start = cursor_ms.map_or(now - 86_400_000, |c| c - 120_000);
    // Source windows advance durably with overlap; long offline gaps remain visible while catching up.
    let mut end = now.min(cursor_ms.unwrap_or(start) + 3_600_000);
    let iso = |ms: i64| {
        chrono::DateTime::<Utc>::from_timestamp_millis(ms).unwrap_or_default().to_rfc3339_opts(SecondsFormat::Millis, true)
    };
    if source == "sentry" {
        let Some(sentry) = sentry_for_env(env) else { bail!("Sentry unconfigured or credentials missing") };
        let key = format!("page:{route}");
        let page_state = read_watch_state::<Value>(db, &key).await?;
        let ps = |k: &str| page_state.as_ref().and_then(|v| v.get(k)).and_then(Value::as_str).map(str::to_string);
        let from = ps("from").unwrap_or_else(|| iso(start));
        let to = ps("to").unwrap_or_else(|| iso(end));
        let page = sentry.watch_issues(&from, &to, &p.environment, ps("cursor").as_deref()).await?;
        let mut events = page.issues.iter().map(|i| sentry_event(i, &p.environment)).collect::<Result<Vec<_>>>()?;
        // lastSeen does not change when an issue is resolved. Reconcile known open issues separately.
        let unresolved: Vec<&WatchJobData> =
            active.iter().filter(|j| j.event.source == "sentry" && j.resolved_at.is_none()).collect();
        let offset = read_watch_state::<i64>(db, &format!("reconcile:{route}")).await?.unwrap_or(0).max(0) as usize;
        let ids: Vec<String> = unresolved.iter().skip(offset).take(5).map(|j| j.event.incident_id.clone()).collect();
        let updates = futures::future::try_join_all(ids.iter().map(|id| sentry.watch_issue(id))).await?;
        for issue in &updates {
            events.push(sentry_event(issue, &p.environment)?);
        }
        let next = if offset + 5 >= unresolved.len() { 0 } else { offset + 5 };
        write_watch_state(db, &format!("reconcile:{route}"), json!(next)).await?;
        let page_value = match &page.next_cursor {
            Some(c) => json!({ "from": from, "to": to, "cursor": c }),
            None => Value::Null,
        };
        let commit_cursor = if page.next_cursor.is_some() { None } else { Some(to.clone()) };
        accept_events_with_state(db, route, events, commit_cursor, key, page_value).await?;
    } else {
        let Some(logs) = logs_for_env(env)? else { bail!("Elasticsearch unconfigured or credentials missing") };
        let service = env.connectors.elasticsearch.as_ref().and_then(|e| e.service_name.clone());
        let records = loop {
            let records = logs
                .search_logs(&LogQuery {
                    from: Some(iso(start)),
                    to: Some(iso(end)),
                    level: Some(LogLevel::Error),
                    service: service.clone(),
                    limit: Some(1000),
                    ..Default::default()
                })
                .await?;
            if records.len() < 1000 {
                break records;
            }
            if end - start <= 1000 || cursor_ms.is_some_and(|c| end <= c) {
                bail!("Elasticsearch window exceeds 1000 events/second; cursor retained, refine service filter");
            }
            end = (start + end).div_euclid(2);
        };
        let events = records.iter().map(|r| elastic_event(r, &p.environment)).collect::<Result<Vec<_>>>()?;
        accept_events(db, route, events, Some(iso(end)), None).await?;
    }
    let gap = match cursor_ms {
        Some(c) if now - c > 86_400_000 => {
            json!("Offline over 24h: upstream retention must be verified; catch-up may be incomplete")
        }
        _ => Value::Null,
    };
    write_watch_state(
        db,
        &format!("health:{route}"),
        json!({
            "lastSuccess": now_iso(),
            "failures": 0,
            "backlogPolicy": "Previous 24h, ten immediate bootstrap jobs; remaining work stays queued",
            "gap": gap,
        }),
    )
    .await
}

// ── Worker ─────────────────────────────────────────────────────────────────

/// Shared abort state: the token plus the reason the first `stop` recorded.
#[derive(Clone)]
struct Abort {
    token: CancellationToken,
    reason: Arc<Mutex<Option<String>>>,
}

impl Abort {
    fn new() -> Self {
        Self { token: CancellationToken::new(), reason: Arc::new(Mutex::new(None)) }
    }
    fn stop(&self, reason: &str) {
        let mut r = self.reason.lock().expect("abort reason");
        if r.is_none() {
            *r = Some(reason.to_string());
        }
        self.token.cancel();
    }
    fn aborted(&self) -> bool {
        self.token.is_cancelled()
    }
    fn throw_if_aborted(&self) -> Result<()> {
        if self.aborted() {
            bail!("{}", self.reason.lock().expect("abort reason").clone().unwrap_or_else(|| "Cancelled".into()));
        }
        Ok(())
    }
}

/// Supervisor-bound progress line (replaces Node `process.send`).
fn send_progress(job: &WatchJobData) {
    if std::env::var("HORUS_WORKER_IPC").as_deref() == Ok("1") {
        let msg = json!({ "jobId": job.id, "stage": job.stage });
        println!("{IPC_PREFIX}{}", horus_core::json::to_js_json(&msg).unwrap_or_default());
        let _ = std::io::stdout().flush();
    }
}

fn add_activity(job: &mut WatchJobData, kind: &str, action: &str) {
    let mut list = job.activity.take().unwrap_or_default();
    if let Ok(ev) = activity_event(&job.id, kind, action) {
        list.push(ev);
    }
    let skip = list.len().saturating_sub(100);
    job.activity = Some(list.split_off(skip));
}

fn collect_activity(job: &mut WatchJobData, hook_file: Option<&Path>) {
    let Some(file) = hook_file else { return };
    let mut events: indexmap::IndexMap<String, WorkerActivity> =
        job.activity.take().unwrap_or_default().into_iter().map(|e| (e.id.clone(), e)).collect();
    for e in read_activity(file, &job.id) {
        events.insert(e.id.clone(), e);
    }
    let mut list: Vec<WorkerActivity> = events.into_values().collect();
    list.sort_by(|a, b| a.at.cmp(&b.at));
    let skip = list.len().saturating_sub(100);
    job.activity = Some(list.split_off(skip));
}

fn active_job_value(job: &WatchJobData) -> Value {
    let mut m = Map::new();
    m.insert("jobId".into(), json!(job.id));
    m.insert("reportId".into(), json!(job.report_id));
    if let Some(c) = &job.cloud_report_id {
        m.insert("cloudReportId".into(), json!(c));
    }
    m.insert("stage".into(), json!(job.stage));
    Value::Object(m)
}

/// Best-effort activity heartbeat; never fails or retries the investigation.
async fn publish_activity(p: &WatchProject, cloud_scope: &str, job: &WatchJobData, local_worker_id: &str) {
    let Some(telemetry) = memory_sync_context(Path::new(&p.root), &p.project, deadline_in(3000)) else { return };
    if telemetry.scope != cloud_scope {
        return;
    }
    let worker = job.cloud_request.as_ref().map_or(local_worker_id.to_string(), |r| r.worker_id.clone());
    let done = job.status == "done";
    let mut body = heartbeat_body(&telemetry, p, &worker, if done { "idle" } else { "running" });
    body.insert("activeJob".into(), if done { Value::Null } else { active_job_value(job) });
    body.insert("activity".into(), json!(job.activity.clone().unwrap_or_default()));
    let _ = telemetry.client.worker_heartbeat(&workspace_id(&telemetry), &with_supervisor(body)).await;
}

/// The worker's job as the TS interval timers see it: TS timers mutate the shared `job` object;
/// here the 25s heartbeat / 2s activity tasks own a mirror that the stage driver syncs on every
/// checkpoint (activities are merged by id in both directions).
struct Live {
    job: WatchJobData,
    hook: Option<PathBuf>,
}

type SharedLive = Arc<Mutex<Live>>;

/// Union two activity lists by id, ordered by `at`, last 100 (the TS `collectActivity` shape).
fn merge_activity(a: Option<Vec<WorkerActivity>>, b: Option<Vec<WorkerActivity>>) -> Option<Vec<WorkerActivity>> {
    if a.is_none() && b.is_none() {
        return None;
    }
    let mut events: indexmap::IndexMap<String, WorkerActivity> = indexmap::IndexMap::new();
    for e in a.unwrap_or_default().into_iter().chain(b.unwrap_or_default()) {
        events.insert(e.id.clone(), e);
    }
    let mut list: Vec<WorkerActivity> = events.into_values().collect();
    list.sort_by(|x, y| x.at.cmp(&y.at));
    let skip = list.len().saturating_sub(100);
    Some(list.split_off(skip))
}

/// Pull the timers' activity into `job`, then publish `job` (+ hook path) to the mirror.
fn sync_live(live: &SharedLive, job: &mut WatchJobData, hook: Option<&Path>) {
    let mut l = live.lock().expect("live job");
    job.activity = merge_activity(job.activity.take(), l.job.activity.take());
    l.job = job.clone();
    l.hook = hook.map(Path::to_path_buf);
}

/// Single-flight `publishActivity` over the mirror (TS reuses the in-flight promise; a tick that
/// finds one in flight is skipped — the next tick publishes the newer state).
async fn publish_live(live: &SharedLive, inflight: &tokio::sync::Mutex<()>, p: &WatchProject, scope: &str, worker: &str) {
    let Ok(_guard) = inflight.try_lock() else { return };
    let snapshot = {
        let mut l = live.lock().expect("live job");
        let hook = l.hook.clone();
        collect_activity(&mut l.job, hook.as_deref());
        l.job.clone()
    };
    publish_activity(p, scope, &snapshot, worker).await;
}

struct WorkerTimers {
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    activity: Option<tokio::task::JoinHandle<()>>,
}

impl WorkerTimers {
    fn stop_activity(&mut self) {
        if let Some(t) = self.activity.take() {
            t.abort();
        }
    }
}

impl Drop for WorkerTimers {
    fn drop(&mut self) {
        if let Some(t) = self.heartbeat.take() {
            t.abort();
        }
        self.stop_activity();
    }
}

/// `setInterval(beat, 25_000)` + `setInterval(publishActivity, 2000)`. A failed claim heartbeat
/// stops the job (TS `beat().catch(stop)`).
fn start_worker_timers(
    live: &SharedLive,
    inflight: &Arc<tokio::sync::Mutex<()>>,
    cloud: &MemorySyncContext,
    p: &WatchProject,
    worker: &str,
    abort: &Abort,
) -> WorkerTimers {
    let tick = |ms: u64| {
        let mut i = tokio::time::interval(Duration::from_millis(ms));
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    };
    let heartbeat = {
        let (live, inflight, cloud, p, worker, abort) =
            (live.clone(), inflight.clone(), cloud.clone(), p.clone(), worker.to_string(), abort.clone());
        tokio::spawn(async move {
            let mut every = tick(25_000);
            every.tick().await; // first tick is immediate; TS fires after 25s
            loop {
                every.tick().await;
                let job = live.lock().expect("live job").job.clone();
                if let Some(r) = &job.cloud_request {
                    if let Err(e) = cloud.client.alert_request(&workspace_id(&cloud), &r.id, "heartbeat", &claim_body(&cloud, &p, &job)).await {
                        abort.stop(&e.to_string());
                        return;
                    }
                }
                publish_live(&live, &inflight, &p, &cloud.scope, &worker).await;
            }
        })
    };
    let activity = {
        let (live, inflight, p, scope, worker) = (live.clone(), inflight.clone(), p.clone(), cloud.scope.clone(), worker.to_string());
        tokio::spawn(async move {
            let mut every = tick(2000);
            every.tick().await;
            loop {
                every.tick().await;
                publish_live(&live, &inflight, &p, &scope, &worker).await;
            }
        })
    };
    WorkerTimers { heartbeat: Some(heartbeat), activity: Some(activity) }
}

fn claim_body(cloud: &MemorySyncContext, p: &WatchProject, job: &WatchJobData) -> Value {
    let mut b = Map::new();
    b.insert("projectId".into(), json!(project_id(cloud)));
    b.insert("environment".into(), json!(p.environment));
    if let Some(r) = &job.cloud_request {
        b.insert("id".into(), json!(r.id));
        b.insert("claimToken".into(), json!(r.claim_token));
        b.insert("workerId".into(), json!(r.worker_id));
    }
    Value::Object(b)
}

/// Persist the report and job together.
async fn persist_report(db: &DbHandle, report: &InvestigationReport, job: &WatchJobData) -> Result<()> {
    let (raw, job, id) = (horus_core::json::to_js_json(report)?, job.clone(), job.report_id.clone());
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        tx.execute("UPDATE investigations SET report = ?1 WHERE id = ?2", rusqlite::params![raw, id])?;
        save_job_conn(&tx, &job)?;
        tx.commit()?;
        Ok(())
    })
    .await
}

pub async fn run_service_worker(settings: &Path, job_id: &str) -> Result<()> {
    let config = read_service_config(settings)?;
    for (k, v) in &config.environment {
        std::env::set_var(k, v);
    }
    std::env::remove_var("ANTHROPIC_API_KEY");
    std::env::remove_var("ANTHROPIC_AUTH_TOKEN");
    let abort = Abort::new();
    // Signals and the deadline abort; a hung abort path is cut off with exit 124 after 2s.
    let stopper = {
        let abort = abort.clone();
        let deadline_s = config.deadline_seconds as u64;
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).ok();
            let mut int = signal(SignalKind::interrupt()).ok();
            let reason = tokio::select! {
                _ = async { if let Some(t) = term.as_mut() { t.recv().await; } else { std::future::pending::<()>().await } } => "Worker interrupted by signal",
                _ = async { if let Some(i) = int.as_mut() { i.recv().await; } else { std::future::pending::<()>().await } } => "Worker interrupted by signal",
                _ = tokio::time::sleep(Duration::from_secs(deadline_s)) => "Investigation deadline exceeded",
            };
            abort.stop(reason);
            tokio::time::sleep(Duration::from_secs(2)).await;
            std::process::exit(124);
        })
    };
    // A supervised worker owns its detached group. Supervisor death (reparenting) stops the group
    // immediately so no orphan can outlive the supervisor deadline (Node: IPC `disconnect`).
    let watchdog = (std::env::var("HORUS_WORKER_IPC").as_deref() == Ok("1")).then(|| {
        let parent = std::os::unix::process::parent_id();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if std::os::unix::process::parent_id() != parent {
                    let _ = std::process::Command::new("kill")
                        .args(["-KILL", &format!("-{}", std::process::id())])
                        .status();
                }
            }
        })
    });
    let deadline = now_ms() + config.deadline_seconds * 1000;
    let result = run_worker_job(&config, settings, job_id, &abort, deadline).await;
    stopper.abort();
    if let Some(w) = watchdog {
        w.abort();
    }
    result
}

async fn run_worker_job(config: &ServiceConfig, _settings: &Path, job_id: &str, abort: &Abort, deadline: i64) -> Result<()> {
    // Short-lived handles until the investigation context (which owns the single-writer DB
    // lock for the rest of the run) exists — the TS `withDb` / `context.dbHandle` split.
    let mut hook_file: Option<PathBuf> = None;
    let (found, worker) = {
        let db = with_db().await?;
        let found = jobs(&db, None).await.map(|j| j.into_iter().find(|j| j.id == job_id));
        let worker = read_watch_state::<String>(&db, "worker:id").await;
        db.end().await;
        (found?, worker?)
    };
    let Some(mut job) = found else { bail!("Unknown watcher job") };
    let previous_attempts = job.attempts.clone();
    let local_worker_id = worker.unwrap_or_else(|| format!("local-{}", std::os::unix::process::parent_id()));
    let mut context: Option<InvestigationContext> = None;
    let outcome = worker_stages(config, &mut context, &mut job, abort, deadline, &mut hook_file, &local_worker_id).await;
    let result = match outcome {
        Ok(()) => Ok(()),
        Err(error) => match &context {
            Some(ctx) => handle_worker_error(config, &ctx.db, &mut job, &previous_attempts, &local_worker_id, error).await,
            None => {
                let db = with_db().await?;
                let r = handle_worker_error(config, &db, &mut job, &previous_attempts, &local_worker_id, error).await;
                db.end().await;
                r
            }
        },
    };
    if let Some(f) = &hook_file {
        let _ = std::fs::remove_file(f);
    }
    if let Some(ctx) = context {
        dispose_investigation_context(ctx).await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn worker_stages(
    config: &ServiceConfig,
    context: &mut Option<InvestigationContext>,
    job: &mut WatchJobData,
    abort: &Abort,
    deadline: i64,
    hook_file: &mut Option<PathBuf>,
    local_worker_id: &str,
) -> Result<()> {
    let Some(p) = config.projects.iter().find(|p| route_key(p) == job.route && p.enabled).cloned() else {
        bail!("Job project disabled or missing");
    };
    let root = PathBuf::from(&p.root);
    let loaded = load_config(Some(Path::new(&p.config)), Some(&root))?;
    let env = resolve_environment(
        &loaded,
        &ResolveOptions { project: Some(&p.project), env: Some(&p.environment), cwd: Some(&root) },
    )?;
    let worker_deadline = Instant::now() + Duration::from_millis((deadline - now_ms()).max(1) as u64);
    let Some(cloud) = memory_sync_context(&root, &p.project, Some(worker_deadline)) else {
        bail!("Sign in and link Cloud before running this job");
    };
    let stored_scope = {
        let db = with_db().await?;
        let s = read_watch_state::<String>(&db, &format!("scope:{}", job.route)).await;
        db.end().await;
        s?
    };
    if stored_scope.as_deref() != Some(cloud.scope.as_str()) {
        bail!("Watcher account/project scope mismatch");
    }
    let ws = workspace_id(&cloud);
    if job.cloud_request.is_some() && job.stage != "complete" {
        let req_id = job.cloud_request.as_ref().map(|r| r.id.clone()).unwrap_or_default();
        let beat = cloud.client.alert_request(&ws, &req_id, "heartbeat", &claim_body(&cloud, &p, job)).await;
        if beat.is_err() {
            let worker = job.cloud_request.as_ref().map(|r| r.worker_id.clone()).unwrap_or_default();
            let claim = cloud
                .client
                .alert_request(&ws, &req_id, "claim", &json!({ "projectId": project_id(&cloud), "environment": p.environment, "workerId": worker }))
                .await?;
            if let Some(r) = job.cloud_request.as_mut() {
                r.claim_token = claim.claim_token;
            }
            let db = with_db().await?;
            let saved = save_job(&db, job).await;
            db.end().await;
            saved?;
        } else {
            publish_activity(&p, &cloud.scope, job, local_worker_id).await;
        }
    }
    let live: SharedLive = Arc::new(Mutex::new(Live { job: job.clone(), hook: None }));
    let inflight = Arc::new(tokio::sync::Mutex::new(()));
    let mut timers = start_worker_timers(&live, &inflight, &cloud, &p, local_worker_id, abort);
    let stage_activity = job.stage.clone();
    add_activity(job, "stage", &stage_activity);
    sync_live(&live, job, hook_file.as_deref());
    publish_live(&live, &inflight, &p, &cloud.scope, local_worker_id).await;

    // No source host auto-start or re-index in the unattended path.
    let service = p.runtime_service.clone().or_else(|| env.connectors.elasticsearch.as_ref().and_then(|e| e.service_name.clone()));
    let ctx = context.insert(
        build_investigation_context(
            env.clone(),
            BuildContextOptions { database_url: "", unattended: true, service: service.clone(), log: Some(&|l: &str| log(l)) },
        )
        .await?,
    );
    let ctx: &InvestigationContext = ctx;
    let db = &ctx.db;
    let followups = FollowupContext::for_env(&env, service.clone())?;
    job.status = "running".into();
    job.started_at.get_or_insert_with(now_iso);
    job.pid = Some(i64::from(std::process::id()));
    save_job(db, job).await?;
    let day = today();
    let budget_key = format!("budget:{day}");
    let mut budget = read_watch_state::<Budget>(db, &budget_key).await?.unwrap_or_default();
    let remaining = move || (deadline - now_ms()).max(1) as u64;

    macro_rules! save {
        () => {{
            abort.throw_if_aborted()?;
            sync_live(&live, job, hook_file.as_deref());
            collect_activity(job, hook_file.as_deref());
            let last_stage = job
                .activity
                .as_deref()
                .unwrap_or_default()
                .iter()
                .rev()
                .find(|a| a.kind == "stage" && !["recall", "collect"].contains(&a.action.as_str()))
                .map(|a| a.action.clone());
            if last_stage.as_deref() != Some(job.stage.as_str()) {
                let s = job.stage.clone();
                add_activity(job, "stage", &s);
            }
            save_job(db, job).await?;
            sync_live(&live, job, hook_file.as_deref());
            publish_live(&live, &inflight, &p, &cloud.scope, local_worker_id).await;
            if let Some(r) = job.cloud_request.clone() {
                let _ = cloud.client.alert_request(&ws, &r.id, "heartbeat", &claim_body(&cloud, &p, job)).await;
            }
            send_progress(job);
        }};
    }

    let saved = get_investigation(db, &job.report_id).await?;
    let mut report: Option<InvestigationReport> =
        saved.and_then(|r| r.report).map(|raw| serde_json::from_str(&raw)).transpose()?;
    if job.stage == "engine" {
        if report.is_none() {
            if budget.investigations >= config.daily_investigations {
                bail!("DAILY_BUDGET: investigations exhausted; deferred until UTC tomorrow");
            }
            budget.investigations += 1;
            write_watch_state(db, &budget_key, serde_json::to_value(&budget)?).await?;
            *job.attempts.entry("engine".into()).or_insert(0) += 1;
            save!();
            // `onActivity`: record on the live mirror and publish immediately (TS
            // `addActivity('stage', action); void publishActivity()`); merged into `job` below.
            let on_activity = {
                let (live, inflight, p, scope, worker) =
                    (live.clone(), inflight.clone(), p.clone(), cloud.scope.clone(), local_worker_id.to_string());
                move |action: &str| {
                    add_activity(&mut live.lock().expect("live job").job, "stage", action);
                    let (live, inflight, p, scope, worker) = (live.clone(), inflight.clone(), p.clone(), scope.clone(), worker.clone());
                    tokio::spawn(async move { publish_live(&live, &inflight, &p, &scope, &worker).await });
                }
            };
            let incident = serde_json::from_value(serde_json::to_value(&job.event)?)?;
            let run_service = if job.event.source == "pagerduty" {
                p.runtime_service.clone().or_else(|| env.connectors.elasticsearch.as_ref().and_then(|e| e.service_name.clone()))
            } else {
                job.event.service.clone()
            };
            let ran = run_one_investigation_with(
                RunInvestigationInput {
                    report_id: Some(job.report_id.clone()),
                    hint: job.event.hint.clone(),
                    incident: Some(incident),
                    service: run_service,
                    ..Default::default()
                },
                ctx,
                Some((config.deadline_seconds * 1000 + 60_000) as u64),
                Some(&on_activity),
            )
            .await;
            sync_live(&live, job, hook_file.as_deref());
            let produced = ran?;
            if produced.persisted != Some(true) {
                bail!("Engine report was not durably saved");
            }
            report = Some(produced);
        }
        job.stage = "ai".into();
        save!();
    }
    if job.stage != "complete" {
        let Some(mut rep) = report.take() else { bail!("Saved engine report is missing") };
        if job.stage == "ai" {
            if job.initial_evidence_collected != Some(true) {
                add_activity(job, "stage", "collect");
                let ev = collect_incident_check(&incident_window_check(&job.event), &followups, &job.event).await?;
                rep.evidence.retain(|e| e.id != ev.id);
                rep.evidence.push(ev);
                job.initial_evidence_collected = Some(true);
                persist_report(db, &rep, job).await?;
            }
            loop {
                if job.ai.is_none() && job.attempts_for("ai") < 3 {
                    if budget.model_calls >= config.daily_model_calls {
                        bail!("DAILY_BUDGET: model calls exhausted; deferred until UTC tomorrow");
                    }
                    budget.model_calls += 1;
                    write_watch_state(db, &budget_key, serde_json::to_value(&budget)?).await?;
                    *job.attempts.entry("ai".into()).or_insert(0) += 1;
                    save!();
                    let session_id = uuid::Uuid::new_v4().to_string();
                    let mut activity_args = Vec::new();
                    match activity_path(&service_home(), &session_id) {
                        Ok(path) => {
                            let created = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path);
                            let args = claude_activity_args(&config.runtime, &config.runtime_args, &config.entry, &session_id, &job.id);
                            match (created, args) {
                                (Ok(_), Ok(a)) => {
                                    *hook_file = Some(path);
                                    activity_args = a;
                                }
                                _ => *hook_file = None,
                            }
                        }
                        Err(_) => *hook_file = None,
                    }
                    let event = job.current_event().clone();
                    let attempt = interpret_incident(
                        &config.claude,
                        &root,
                        &event,
                        &rep,
                        remaining(),
                        Some(&abort.token),
                        true, // Keep Claude/tools in the worker group so supervisor cleanup survives SIGKILL.
                        &activity_args,
                    )
                    .await;
                    let outcome: Result<()> = match attempt {
                        Ok(r) => {
                            job.ai = Some(crate::lib::watch_store::AiRecord { session_id: r.session_id, model: r.model, result: r.result });
                            job.ai_failure = None;
                            // Persist inference before report annotation: recovery reuses the validated result.
                            async {
                                save!();
                                anyhow::Ok(())
                            }
                            .await
                        }
                        Err(e) => {
                            job.ai_failure = Some(redact_err(&e));
                            if job.attempts_for("ai") < 3 { Err(e) } else { Ok(()) }
                        }
                    };
                    collect_activity(job, hook_file.as_deref());
                    if let Some(f) = hook_file.take() {
                        let _ = std::fs::remove_file(f);
                    }
                    outcome?;
                }
                let Some(ai) = &job.ai else { break };
                let interpreted = IncidentResult::parse(&ai.result)?;
                let mut seen: Vec<String> = rep.evidence.iter().map(|e| e.id.clone()).collect();
                let requested: Vec<_> = interpreted
                    .checks
                    .iter()
                    .filter(|c| {
                        let id = format!("ev_followup_{}", check_key(c));
                        if seen.contains(&id) {
                            return false;
                        }
                        seen.push(id);
                        true
                    })
                    .cloned()
                    .collect();
                if requested.is_empty() || job.ai_round.unwrap_or(0) >= 2 {
                    break;
                }
                add_activity(job, "stage", "collect");
                for check in &requested {
                    abort.throw_if_aborted()?;
                    rep.evidence.push(collect_incident_check(check, &followups, &job.event).await?);
                }
                job.ai_round = Some(job.ai_round.unwrap_or(0) + 1);
                rep.followup_rounds = job.ai_round;
                job.ai = None;
                job.attempts.insert("ai".into(), 0);
                persist_report(db, &rep, job).await?;
            }
            rep.unattended = Some(match &job.ai {
                Some(ai) => Unattended {
                    model: ai.model.clone(),
                    session_id: Some(ai.session_id.clone()),
                    status: UnattendedStatus::Completed,
                    error: None,
                    engine_only: None,
                },
                None => Unattended {
                    model: crate::lib::claude_investigation::CLAUDE_MODEL.into(),
                    session_id: None,
                    status: UnattendedStatus::Failed,
                    error: job.ai_failure.clone(),
                    engine_only: Some(true),
                },
            });
            if let Some(ai) = &job.ai {
                let result = IncidentResult::parse(&ai.result)?;
                rep.diagnosis = Some(if result.diagnosis == "supported" { Diagnosis::Supported } else { Diagnosis::Unresolved });
                rep.ai_judgment = Some(StoredAIJudgment {
                    what: result.summary.clone(),
                    why: format!("{}. {}", result.likely_cause.as_deref().unwrap_or("Cause uncertain"), result.uncertainty),
                    where_next: result.next_checks.clone(),
                    citations: result.evidence_ids.iter().map(|id| AICitation { evidence_id: id.clone(), rationale: None }).collect(),
                    confidence: result.confidence,
                    mentioned_services: None,
                    hypothesis_judgments: None,
                    root_cause_assessment: None,
                    provider: "local Claude Code / claude-opus-5-5".into(),
                    generated_at: now_iso(),
                });
            }
            rep.diagnosis.get_or_insert(Diagnosis::Unresolved);
            persist_report(db, &rep, job).await?;
            if rep.fix_pr.is_none() {
                let result = job.ai.as_ref().map(|a| IncidentResult::parse(&a.result)).transpose()?;
                match (&p.fix_pr, &result) {
                    (Some(fix_cfg), Some(result)) if repair_eligible(&rep, result) => {
                        job.repair_attempts = Some(job.repair_attempts.unwrap_or(0) + 1);
                        save!();
                        // Leave time for diagnosis upload and notification even if coding stalls.
                        let repair_ms = 120_000i64.min(remaining() as i64 - 30_000);
                        let repair_deadline = now_ms() + repair_ms.max(1);
                        let repair_token = abort.token.child_token();
                        let timer = {
                            let t = repair_token.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(repair_ms.max(1) as u64)).await;
                                t.cancel();
                            })
                        };
                        let attempt = if repair_ms < 1000 {
                            Err(anyhow!("Insufficient repair time; diagnosis delivery takes priority"))
                        } else {
                            let budget_cell = Arc::new(Mutex::new(budget.clone()));
                            let (db2, key2, cap) = (db.clone(), budget_key.clone(), config.daily_model_calls);
                            let bc = budget_cell.clone();
                            let mut reserve = move || {
                                let (db2, key2, bc) = (db2.clone(), key2.clone(), bc.clone());
                                async move {
                                    let snapshot = {
                                        let mut b = bc.lock().expect("budget");
                                        if b.model_calls >= cap {
                                            bail!("DAILY_BUDGET: model calls exhausted; draft PR blocked");
                                        }
                                        b.model_calls += 1;
                                        b.clone()
                                    };
                                    write_watch_state(&db2, &key2, serde_json::to_value(&snapshot)?).await
                                }
                                .boxed()
                            };
                            let db3 = db.clone();
                            let checkpoint = move |j: WatchJobData| {
                                let db3 = db3.clone();
                                async move { save_job(&db3, &j).await }.boxed()
                            };
                            let remaining_repair = move || (repair_deadline - now_ms()).max(1) as u64;
                            let r = repair_incident(
                                RepairOptions {
                                    root: &root,
                                    home: &service_home(),
                                    claude: &config.claude,
                                    config: fix_cfg,
                                    report: &rep,
                                    cancel: &repair_token,
                                    remaining: &remaining_repair,
                                    reserve_model_call: &mut reserve,
                                    checkpoint: &checkpoint,
                                },
                                job,
                            )
                            .await;
                            r
                        };
                        let repair_aborted = repair_token.is_cancelled();
                        timer.abort();
                        match attempt {
                            Ok(pr) => rep.fix_pr = Some(pr),
                            Err(e) => {
                                if abort.aborted() {
                                    return Err(e);
                                }
                                let message = redact_err(&e);
                                if job.repair_attempts.unwrap_or(0) < 3 && !repair_aborted && repair_ms >= 1000 && !message.contains("DAILY_BUDGET") {
                                    return Err(e);
                                }
                                rep.fix_pr = Some(FixPr {
                                    status: FixPrStatus::Blocked,
                                    branch: None,
                                    url: None,
                                    summary: format!("Draft PR could not be prepared: {}", message.chars().take(2000).collect::<String>()),
                                });
                            }
                        }
                    }
                    _ => {
                        rep.fix_pr = Some(FixPr {
                            status: FixPrStatus::Skipped,
                            branch: None,
                            url: None,
                            summary: if p.fix_pr.is_some() {
                                "No supported code fix with current targeted evidence".into()
                            } else {
                                "Draft PR publication is not configured for this route".into()
                            },
                        });
                    }
                }
                persist_report(db, &rep, job).await?;
            }
            job.stage = "upload".into();
            save!();
        }
        if job.stage == "upload" {
            job.analysis_ended_at.get_or_insert_with(now_iso);
            *job.attempts.entry("upload".into()).or_insert(0) += 1;
            save!();
            let refs = upload_investigation_to_cloud(
                &cloud.client,
                &cloud.config,
                &serde_json::to_value(&rep)?,
                UploadOpts {
                    db: Some(db),
                    run_timing: Some((job.started_at.clone().unwrap_or_default(), job.analysis_ended_at.clone().unwrap_or_default())),
                    run_activity: Some(job.activity.as_deref().unwrap_or_default()),
                },
            )
            .await?;
            job.cloud_report_id = Some(refs.investigation_id.clone());
            job.cloud_agent_run_id = refs.agent_run_id.clone();
            let slug = |r: &Option<crate::lib::cloud::context_store::Ref>| r.as_ref().map(|r| r.slug.clone()).unwrap_or_default();
            let parts = [slug(&cloud.config.organization), slug(&cloud.config.workspace), slug(&cloud.config.project), "investigations".into(), refs.investigation_id];
            job.cloud_url = Some(format!(
                "{}/{}",
                config.cloud_web_url.trim_end_matches('/'),
                parts.iter().map(|s| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>().replace('+', "%20")).collect::<Vec<_>>().join("/")
            ));
            let sync = sync_linked_memory(db, &root, &p.project, MemorySyncOptions::default()).await?;
            if sync.state != "Synced" {
                bail!("Memory {}: {}", sync.state, sync.error.clone().unwrap_or_else(|| format!("{} pending", sync.pending)));
            }
            job.stage = "notify".into();
            save!();
        }
        if job.stage == "notify" {
            let Some(cloud_url) = job.cloud_url.clone() else { bail!("Cloud report link missing; notification deferred") };
            if job.notified != Some(true) {
                *job.attempts.entry("notify".into()).or_insert(0) += 1;
                let webhook = if p.notifications == "configured" { service_webhook(env.notify.as_ref())? } else { None };
                // Legacy direct webhook safety remains independent of Cloud's durable receipt.
                if webhook.is_some() && job.notification_key.is_some() && !p.idempotent_destination {
                    bail!("DELIVERY_UNKNOWN: inspect destination before service retry --delivery-checked");
                }
                if job.notification_key.is_none() {
                    let ev = job.current_event();
                    job.notification_key = Some(format!(
                        "{}:{}",
                        job.id,
                        digest(&json!([job.cloud_report_id, ev.severity, ev.event_id, job.ai_failure]))
                    ));
                }
                save!();
                let ai = job.ai.as_ref().map(|a| IncidentResult::parse(&a.result)).transpose()?;
                let notice = ai.as_ref().map(|r| AiNotice {
                    likely_cause: r.likely_cause.as_deref(),
                    evidence_ids: &r.evidence_ids,
                    uncertainty: &r.uncertainty,
                    next_checks: &r.next_checks,
                });
                let cause: String = notification_cause(&rep, notice.as_ref(), job.ai_failure.is_some()).chars().take(4000).collect();
                let ev = job.current_event().clone();
                let service_tag = rep.input.service.as_deref().filter(|s| !s.is_empty()).map(|s| format!(" / {s}")).unwrap_or_default();
                let hint_raw = format!("{}/{}{service_tag} [{}]: {}", p.project, p.environment, ev.severity, ev.hint);
                let hint: String = js_string(&redact_value(json!(hint_raw))).chars().take(1000).collect();
                let confidence = ai.as_ref().map_or(rep.confidence, |r| r.confidence);
                let key = job.notification_key.clone().unwrap_or_default();
                // Cloud owns the Slack app and project channel. This explicit checkpoint, after
                // upload, cannot notify from historical sync or repeat engine/AI work.
                let delivered = cloud
                    .client
                    .notify_investigation(
                        &project_id(&cloud),
                        job.cloud_report_id.as_deref().unwrap_or_default(),
                        &NotifyInvestigationInput { notification_key: key.clone(), hint: hint.clone(), cause: cause.clone(), confidence },
                    )
                    .await?;
                if !["off", "delivered"].contains(&delivered.state.as_str()) {
                    bail!("Cloud notification failed: {}", delivered.error.unwrap_or_else(|| "invalid delivery response".into()));
                }
                if let Some(webhook) = webhook {
                    let n = NotifyConfig {
                        min_confidence: 0.0,
                        webhook: Some(webhook),
                        cloud: env.notify.as_ref().is_some_and(|n| n.cloud),
                    };
                    let results = dispatch_notify(
                        DispatchReport { id: rep.id.clone(), confidence, hint, cause, notification_key: Some(key), report_url: Some(cloud_url) },
                        Some(&n),
                        Some(5000u64.min(remaining())),
                        None::<NoPush>,
                    )
                    .await;
                    let failed: Vec<String> = results.iter().filter(|r| !r.ok).map(|r| r.detail.clone()).collect();
                    if !failed.is_empty() {
                        bail!("Notification failed: {}", failed.join("; "));
                    }
                }
                job.notified = Some(true);
            }
            job.stage = "complete".into();
            save!();
        }
        report = Some(rep);
    }
    if job.stage == "complete" {
        let judgment: Option<RunLogResult> =
            report.as_ref().and_then(|r| r.ai_judgment.as_ref()).and_then(|j| serde_json::to_value(j).ok()).and_then(|v| serde_json::from_value(v).ok());
        let run_logs_body = |job: &WatchJobData| -> Result<crate::lib::cloud::api::AgentRunBody> {
            let logs = worker_run_logs(job.activity.as_deref().unwrap_or_default(), judgment.as_ref());
            Ok(crate::lib::cloud::api::AgentRunBody { logs_format: Some(logs.logs_format), logs: Some(logs.logs), ..Default::default() })
        };
        // Retry delivery of the saved timeline, never inference, if Cloud is unavailable.
        if let (Some(run), Some(inv)) = (job.cloud_agent_run_id.clone(), job.cloud_report_id.clone()) {
            cloud.client.update_agent_run(&project_id(&cloud), &inv, &run, &run_logs_body(job)?).await?;
        }
        if let Some(req) = job.cloud_request.clone() {
            let complete_body = |job: &WatchJobData| {
                let mut b = claim_body(&cloud, &p, job);
                if let Some(obj) = b.as_object_mut() {
                    if let Some(c) = &job.cloud_report_id {
                        obj.insert("investigationId".into(), json!(c));
                    }
                    obj.insert("eventId".into(), json!(job.current_event().event_id));
                }
                b
            };
            if cloud.client.alert_request(&ws, &req.id, "complete", &complete_body(job)).await.is_err() {
                let claim = cloud
                    .client
                    .alert_request(&ws, &req.id, "claim", &json!({ "projectId": project_id(&cloud), "environment": p.environment, "workerId": req.worker_id }))
                    .await?;
                if let Some(r) = job.cloud_request.as_mut() {
                    r.claim_token = claim.claim_token;
                }
                save!();
                cloud.client.alert_request(&ws, &req.id, "complete", &complete_body(job)).await?;
            }
        }
        job.stage = "done".into();
        job.status = "done".into();
        job.error = None;
        job.pid = None;
        save!();
        // TS: clearInterval(activityTimer); await activitySend; await publishActivity().
        timers.stop_activity();
        let _ = inflight.lock().await;
        sync_live(&live, job, hook_file.as_deref());
        publish_live(&live, &inflight, &p, &cloud.scope, local_worker_id).await;
        if let (Some(run), Some(inv)) = (job.cloud_agent_run_id.clone(), job.cloud_report_id.clone()) {
            // The durable pre-completion timeline is already saved; completion remains authoritative.
            if let Ok(body) = run_logs_body(job) {
                let _ = cloud.client.update_agent_run(&project_id(&cloud), &inv, &run, &body).await;
            }
        }
    }
    Ok(())
}

async fn handle_worker_error(
    config: &ServiceConfig,
    db: &DbHandle,
    job: &mut WatchJobData,
    previous_attempts: &indexmap::IndexMap<String, i64>,
    local_worker_id: &str,
    error: anyhow::Error,
) -> Result<()> {
    let stage = job.stage.clone();
    add_activity(job, "error", &stage);
    let message = redact_err(&error);
    job.error = Some(message.clone());
    job.pid = None;
    let budget = message.contains("DAILY_BUDGET");
    if !budget && job.attempts_for(&stage) == previous_attempts.get(&stage).copied().unwrap_or(0) {
        *job.attempts.entry(stage.clone()).or_insert(0) += 1;
    }
    job.status = if !budget && (job.attempts_for(&stage) >= 5 || message.contains("DELIVERY_UNKNOWN")) {
        "terminal-failed"
    } else {
        "retry-wait"
    }
    .into();
    job.next_attempt_at = if budget {
        let tomorrow = (Utc::now() + chrono::Duration::days(1)).date_naive();
        tomorrow.and_hms_opt(0, 0, 0).expect("midnight").and_utc().timestamp_millis()
    } else {
        let backoff = 3_600_000i64.min(30_000i64.saturating_mul(2i64.saturating_pow(job.attempts_for(&stage).clamp(0, 30) as u32)));
        now_ms() + retry_after_ms(&error).max(backoff)
    };
    save_job(db, job).await?;
    let p = config.projects.iter().find(|p| route_key(p) == job.route).cloned();
    if let Some(p) = &p {
        if let Some(cloud) = memory_sync_context(Path::new(&p.root), &p.project, deadline_in(5000)) {
            if let (true, Some(req)) = (job.status == "terminal-failed", job.cloud_request.clone()) {
                let body = json!({
                    "id": req.id, "claimToken": req.claim_token, "workerId": req.worker_id,
                    "projectId": project_id(&cloud), "environment": p.environment,
                    "error": message.chars().take(2000).collect::<String>(), "terminal": true,
                });
                let _ = cloud.client.alert_request(&workspace_id(&cloud), &req.id, "fail", &body).await;
            }
            let worker = job.cloud_request.as_ref().map_or(local_worker_id.to_string(), |r| r.worker_id.clone());
            let mut b = heartbeat_body(&cloud, p, &worker, if budget { "budget-exhausted" } else { "degraded" });
            b.insert("activeJob".into(), active_job_value(job));
            b.insert("activity".into(), json!(job.activity.clone().unwrap_or_default()));
            let _ = cloud.client.worker_heartbeat(&workspace_id(&cloud), &with_supervisor(b)).await;
        }
        if budget || job.status == "terminal-failed" {
            let kind = if budget { "budget" } else { "terminal" };
            let day = today();
            let stale = job.notice.as_ref().map_or(true, |n| n.kind != kind || (budget && n.day != day));
            if stale {
                let hint_raw = format!(
                    "{}/{}: {}",
                    p.project,
                    p.environment,
                    if budget { "Daily budget reached" } else { "Investigation needs attention" }
                );
                let cause_raw = format!(
                    "{message}. Inspect horus service status{}",
                    if budget { "; work remains queued until UTC tomorrow".to_string() } else { format!("; retry job {} after fixing the cause", job.id) }
                );
                job.notice = Some(JobNotice {
                    kind: kind.into(),
                    day,
                    hint: js_string(&redact_value(json!(hint_raw))).chars().take(1000).collect(),
                    cause: js_string(&redact_value(json!(cause_raw))).chars().take(4000).collect(),
                    state: "pending".into(),
                    retry_at: 0,
                    error: None,
                });
                save_job(db, job).await?;
            }
            deliver_operational_notice(db, p, job).await?;
        }
    }
    log(&format!("{} {}: {message}", job.id, job.stage));
    Ok(())
}

// ── Supervisor ─────────────────────────────────────────────────────────────

fn stamp(job: &WatchJobData, p: &WatchProject) {
    let mut prior = read_status();
    prior.insert("at".into(), json!(now_iso()));
    prior.insert("pid".into(), json!(std::process::id()));
    match read_status().get("supervisor") {
        Some(s) => prior.insert("supervisor".into(), s.clone()),
        None => prior.shift_remove("supervisor"),
    };
    prior.insert(
        "activeJob".into(),
        json!({ "id": job.id, "project": p.project, "environment": p.environment, "stage": job.stage }),
    );
    let _ = write_status(&Value::Object(prior));
}

pub async fn run_watch_service(settings: &Path, once: bool) -> Result<()> {
    let mut config = read_service_config(settings)?;
    for (k, v) in &config.environment {
        std::env::set_var(k, v);
    }
    let home = service_home();
    ensure_private_dir(&home);
    let _lock = acquire_db_lock(&home.join("worker"), Duration::from_millis(100))?;
    let token = CancellationToken::new();
    let stopped_by: Arc<Mutex<Option<&'static str>>> = Arc::new(Mutex::new(None));
    let signals = {
        let (token, stopped_by) = (token.clone(), stopped_by.clone());
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else { return };
            let which = tokio::select! { _ = term.recv() => "SIGTERM", _ = int.recv() => "SIGINT" };
            *stopped_by.lock().expect("signal") = Some(which);
            token.cancel();
        })
    };
    let result = supervise(&mut config, settings, once, &token, &home).await;
    signals.abort();
    let signal = *stopped_by.lock().expect("signal");
    let (reason, sig) = match (&result, signal) {
        (Err(_), _) => ("fatal", None),
        (Ok(()), Some(s)) => ("signal", Some(s)),
        (Ok(()), None) => ("completed", None),
    };
    if let Err(e) = finish_supervisor(reason, sig) {
        eprintln!("Could not save supervisor exit: {}", redact_err(&e));
    }
    result
}

async fn supervise(config: &mut ServiceConfig, settings: &Path, once: bool, token: &CancellationToken, home: &Path) -> Result<()> {
    begin_supervisor(&config.entry)?;
    let worker_id = {
        let db = with_db().await?;
        let id = read_watch_state::<String>(&db, "worker:id").await?.unwrap_or_else(|| format!("local-{}", uuid::Uuid::new_v4()));
        write_watch_state(&db, "worker:id", json!(id)).await?;
        db.end().await;
        id
    };
    loop {
        *config = read_service_config(settings)?;
        for p in config.projects.clone().into_iter().filter(|p| p.enabled) {
            if token.is_cancelled() {
                break;
            }
            let route = route_key(&p);
            let health_key = format!("health:{route}");
            let polled: Result<()> = async {
                let db = with_db().await?;
                let health = read_watch_state::<Value>(&db, &health_key).await;
                let usage = read_watch_state::<Budget>(&db, &format!("budget:{}", today())).await;
                let scope = read_watch_state::<String>(&db, &format!("scope:{route}")).await;
                db.end().await;
                let health = health?;
                let retry_at = health.as_ref().and_then(|h| h.get("retryAt")).and_then(Value::as_i64).filter(|r| *r != 0);
                if retry_at.map_or(true, |r| r <= now_ms()) {
                    return poll_project(&p, &worker_id, config).await;
                }
                // Source backoff must not make a live worker appear offline in Cloud.
                let (scope, usage) = (scope?, usage?);
                if let Some(cloud) = memory_sync_context(Path::new(&p.root), &p.project, deadline_in(5000)) {
                    if scope.as_deref() == Some(cloud.scope.as_str()) {
                        let failures = health.as_ref().and_then(|h| h.get("failures")).and_then(Value::as_i64).unwrap_or(0);
                        let state = if exhausted(usage.as_ref(), config) {
                            "budget-exhausted"
                        } else if failures >= 3 {
                            "degraded"
                        } else {
                            "idle"
                        };
                        if let Err(e) = cloud.client.worker_heartbeat(&workspace_id(&cloud), &with_supervisor(heartbeat_body(&cloud, &p, &worker_id, state))).await {
                            log(&format!("Cloud heartbeat: {}", redact_err(&e)));
                        }
                    }
                }
                Ok(())
            }
            .await;
            if let Err(error) = polled {
                let db = with_db().await?;
                let health = read_watch_state::<Value>(&db, &health_key).await?;
                let mut h = health.and_then(|v| v.as_object().cloned()).unwrap_or_default();
                let failures = h.get("failures").and_then(Value::as_i64).unwrap_or(0) + 1;
                h.insert("failures".into(), json!(failures));
                h.insert("error".into(), json!(redact_err(&error)));
                let backoff = 3_600_000i64.min(10_000 * 2i64.pow(failures.min(8) as u32));
                h.insert("retryAt".into(), json!(now_ms() + retry_after_ms(&error).max(backoff)));
                write_watch_state(&db, &health_key, Value::Object(h)).await?;
                db.end().await;
                log(&format!("{}/{} source: {}", p.project, p.environment, redact_err(&error)));
            }
            {
                let db = with_db().await?;
                match sync_linked_memory(&db, Path::new(&p.root), &p.project, MemorySyncOptions::default()).await {
                    Ok(sync) => write_watch_state(&db, &format!("sync:{route}"), serde_json::to_value(&sync)?).await?,
                    Err(e) => log(&format!("{} memory: {}", p.project, redact_err(&e))),
                }
                db.end().await;
            }
            let db = with_db().await?;
            let pending = jobs(&db, Some(&route)).await?;
            // Retry one due notice per route independently of deferred/terminal analysis.
            if let Some(mut notice_job) =
                pending.iter().find(|j| j.notice.as_ref().is_some_and(|n| n.state == "pending" && n.retry_at <= now_ms())).cloned()
            {
                deliver_operational_notice(&db, &p, &mut notice_job).await?;
            }
            db.end().await;
            let Some(mut job) = pending
                .into_iter()
                .find(|j| !["done", "cancelled", "terminal-failed"].contains(&j.status.as_str()) && j.next_attempt_at <= now_ms())
            else {
                continue;
            };
            if let Some(pid) = job.pid {
                if crate::lib::host_reaper::is_pid_alive(pid) {
                    log(&format!("{}: prior worker still alive; waiting", job.id));
                    continue;
                }
            }
            stamp(&job, &p);
            let started = job.clone();
            let settings_s = settings.to_string_lossy().to_string();
            let args = config.command_args(&["service", "worker", "--settings", &settings_s, "--job", &job.id]);
            // `setInterval(stamp, 25_000)`: the timer and progress messages share the job.
            let stamped = Arc::new(Mutex::new(job.clone()));
            let status_timer = {
                let (stamped, p) = (stamped.clone(), p.clone());
                tokio::spawn(async move {
                    let mut every = tokio::time::interval(Duration::from_millis(25_000));
                    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    every.tick().await;
                    loop {
                        every.tick().await;
                        let j = stamped.lock().expect("stamped job").clone();
                        stamp(&j, &p);
                    }
                })
            };
            let job_id = job.id.clone();
            let mut on_message = |message: Value| {
                let stage = message.get("stage").and_then(Value::as_str).unwrap_or("");
                if message.get("jobId").and_then(Value::as_str) != Some(job_id.as_str())
                    || !["engine", "ai", "upload", "notify", "complete", "done"].contains(&stage)
                {
                    return;
                }
                let mut j = stamped.lock().expect("stamped job");
                j.stage = stage.to_string();
                stamp(&j, &p);
            };
            let ran = run_process(
                &config.runtime,
                &args,
                RunOptions {
                    cwd: Path::new(&p.root),
                    input: None,
                    timeout_ms: ((config.deadline_seconds + 5) * 1000) as u64,
                    cancel: Some(token),
                    env: None,
                    inherit_process_group: false,
                    on_message: Some(&mut on_message),
                },
            )
            .await;
            status_timer.abort();
            job.stage = stamped.lock().expect("stamped job").stage.clone();
            if let Err(error) = ran {
                let db = with_db().await?;
                if let Some(mut current) = jobs(&db, Some(&route)).await?.into_iter().find(|j| j.id == started.id) {
                    if current.status != "done" {
                        current.pid = None;
                        current.error = Some(redact_err(&error));
                        // The child journals a stage attempt before work; only count an unrecorded crash here.
                        let st = current.stage.clone();
                        if current.attempts_for(&st) == started.attempts_for(&st) {
                            *current.attempts.entry(st.clone()).or_insert(0) += 1;
                        }
                        current.status = if current.attempts_for(&st) >= 5 { "terminal-failed" } else { "retry-wait" }.into();
                        current.next_attempt_at = now_ms() + 60_000;
                        save_job(&db, &current).await?;
                    }
                }
                db.end().await;
            }
        }
        let db = with_db().await?;
        let mut snapshot = Map::new();
        if let Some(b) = read_watch_state::<Value>(&db, &format!("budget:{}", today())).await? {
            snapshot.insert("budget".into(), b);
        }
        snapshot.insert("activeJob".into(), Value::Null);
        snapshot.insert("at".into(), json!(now_iso()));
        snapshot.insert("pid".into(), json!(std::process::id()));
        if let Some(s) = read_status().get("supervisor") {
            snapshot.insert("supervisor".into(), s.clone());
        }
        snapshot.insert("database".into(), json!(local_db_path().to_string_lossy()));
        let mut projects = Vec::new();
        for p in &config.projects {
            let rk = route_key(p);
            let mut m = Map::new();
            m.insert("project".into(), json!(p.project));
            m.insert("environment".into(), json!(p.environment));
            m.insert("enabled".into(), json!(p.enabled));
            if let Some(h) = read_watch_state::<Value>(&db, &format!("health:{rk}")).await? {
                m.insert("health".into(), h);
            }
            if let Some(s) = summarize_service_sync(read_watch_state::<Value>(&db, &format!("sync:{rk}")).await?.as_ref()) {
                m.insert("sync".into(), s);
            }
            m.extend(summarize_service_jobs(&jobs(&db, Some(&rk)).await?));
            projects.push(Value::Object(m));
        }
        snapshot.insert("projects".into(), Value::Array(projects));
        db.end().await;
        write_status(&redact_value(Value::Object(snapshot)))?;
        if once || token.is_cancelled() {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.interval_seconds as u64)) => {}
            _ = token.cancelled() => {}
        }
        if token.is_cancelled() {
            break;
        }
    }
    let _ = home;
    Ok(())
}

/// `resolve(a) === resolve(b)` for the project-root identity check.
pub fn same_path(a: &str, b: &str) -> bool {
    use std::path::Component;
    let norm = |p: &str| {
        let mut out = PathBuf::new();
        for c in std::env::current_dir().unwrap_or_default().join(p).components() {
            match c {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other),
            }
        }
        out
    };
    norm(a) == norm(b)
}
