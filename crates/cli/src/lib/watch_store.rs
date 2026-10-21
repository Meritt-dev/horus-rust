//! Durable watch queue: incident events, jobs and source cursors. Port of
//! `packages/cli/src/lib/watch-store.ts`. Tables `watch_state` / `watch_job` / `watch_event`
//! (migration 0014) hold JSON text; `watch_state.value` wraps the payload as `{ "data": … }`
//! like the TS jsonb column.

use std::sync::LazyLock;

use anyhow::{anyhow, bail, Result};
use chrono::Utc;
use horus_db::{format_ts, DbHandle};
use indexmap::IndexMap;
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::lib::worker_activity::WorkerActivity;

/// `redactCloudValue` applied to a typed value (round-trips through JSON).
pub fn redact<T: Serialize + DeserializeOwned>(v: &T) -> Result<T> {
    let value = serde_json::to_value(v)?;
    Ok(serde_json::from_value(redact_value(value))?)
}

/// `redactCloudValue` on a JSON value.
pub fn redact_value(v: Value) -> Value {
    crate::lib::cloud::investigation_sync::redact_cloud_value(&v)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentEvent {
    /// `sentry` | `elasticsearch` | `pagerduty`.
    pub source: String,
    pub event_id: String,
    pub incident_id: String,
    pub fingerprint: String,
    pub occurred_at: String,
    pub hint: String,
    pub environment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// `active` | `resolved`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub investigation_required: Option<bool>,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

/// zod `datetime({ offset: true })`: ISO-8601 with `Z` or a numeric offset.
pub fn is_iso_datetime(s: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$").unwrap()
    });
    RE.is_match(s)
}

/// JS `Date.parse` for the ISO forms the schemas admit (ms; None on NaN).
pub fn parse_ms(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .or_else(|| chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M%:z").ok())
        .or_else(|| chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z").ok())
        .map(|t| t.timestamp_millis())
}

impl IncidentEvent {
    /// `incidentEventSchema.parse`: bounds, enums, datetime and url checks.
    pub fn validate(&self) -> Result<()> {
        let len = |s: &str| s.chars().count();
        if !["sentry", "elasticsearch", "pagerduty"].contains(&self.source.as_str()) {
            bail!("Invalid incident source");
        }
        if !["active", "resolved"].contains(&self.state.as_str()) {
            bail!("Invalid incident state");
        }
        for (name, v, max) in [
            ("eventId", &self.event_id, 512),
            ("incidentId", &self.incident_id, 512),
            ("fingerprint", &self.fingerprint, 1024),
            ("hint", &self.hint, 2000),
        ] {
            if len(v) < 1 || len(v) > max {
                bail!("Invalid incident {name}");
            }
        }
        if self.environment.is_empty() {
            bail!("Invalid incident environment");
        }
        if !is_iso_datetime(&self.occurred_at) {
            bail!("Invalid incident occurredAt");
        }
        if self.source_url.as_deref().is_some_and(|u| url::Url::parse(u).is_err()) {
            bail!("Invalid incident sourceUrl");
        }
        if self.event_code.as_deref().is_some_and(|c| len(c) > 255) {
            bail!("Invalid incident eventCode");
        }
        Ok(())
    }

    /// Correlation family: order workflow, explicit correlation, else source incident fingerprint.
    pub fn family(&self) -> String {
        match (&self.order_id, &self.correlation_id) {
            (Some(order), _) => format!("{}:{order}", self.workflow.as_deref().unwrap_or("workflow")),
            (None, Some(c)) => c.clone(),
            _ => format!("{}:{}:{}", self.source, self.incident_id, self.fingerprint),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudRequestRef {
    pub id: String,
    pub claim_token: String,
    pub worker_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiRecord {
    pub session_id: String,
    pub model: String,
    pub result: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairCheckpoint {
    pub base_sha: String,
    pub worktree: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobNotice {
    /// `budget` | `terminal`.
    pub kind: String,
    pub day: String,
    pub hint: String,
    pub cause: String,
    /// `pending` | `done`.
    pub state: String,
    pub retry_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One durable watch job. `stage`: engine|ai|upload|notify|complete|done; `status`:
/// pending|running|retry-wait|terminal-failed|done|cancelled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchJobData {
    pub id: String,
    pub route: String,
    pub event: IncidentEvent,
    pub report_id: String,
    pub created_at: String,
    pub stage: String,
    pub attempts: IndexMap<String, i64>,
    pub next_attempt_at: i64,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_report_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_agent_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_request: Option<CloudRequestRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai: Option<AiRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_round: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_evidence_collected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair: Option<RepairCheckpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_attempts: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<JobNotice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_event: Option<IncidentEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<Vec<WorkerActivity>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_ended_at: Option<String>,
}

impl WatchJobData {
    pub fn attempts_for(&self, stage: &str) -> i64 {
        self.attempts.get(stage).copied().unwrap_or(0)
    }
    /// The newest event of this job's episode.
    pub fn current_event(&self) -> &IncidentEvent {
        self.latest_event.as_ref().unwrap_or(&self.event)
    }
}

/// sha256 hex of the JSON encoding.
pub fn digest<T: Serialize + ?Sized>(v: &T) -> String {
    let s = horus_core::json::to_js_json(v).unwrap_or_default();
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn now_iso() -> String {
    format_ts(&Utc::now())
}

// ── Sync helpers on a connection (usable inside a transaction) ─────────────

pub fn read_watch_state_conn<T: DeserializeOwned>(c: &Connection, key: &str) -> Result<Option<T>> {
    let raw: Option<String> =
        c.query_row("SELECT value FROM watch_state WHERE key = ?1", params![key], |r| r.get(0)).optional()?;
    let Some(raw) = raw else { return Ok(None) };
    let v: Value = serde_json::from_str(&raw)?;
    match v.get("data") {
        None | Some(Value::Null) => Ok(None),
        Some(d) => Ok(Some(serde_json::from_value(d.clone())?)),
    }
}

pub fn write_watch_state_conn<T: Serialize + ?Sized>(c: &Connection, key: &str, value: &T) -> Result<()> {
    let wrapped = serde_json::json!({ "data": serde_json::to_value(value)? });
    c.execute(
        "INSERT INTO watch_state (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, horus_core::json::to_js_json(&wrapped)?],
    )?;
    Ok(())
}

/// All jobs (optionally one route), oldest first.
pub fn jobs_conn(c: &Connection, route: Option<&str>) -> Result<Vec<WatchJobData>> {
    let mut stmt = c.prepare(match route {
        Some(_) => "SELECT data FROM watch_job WHERE route = ?1",
        None => "SELECT data FROM watch_job",
    })?;
    let rows: Vec<String> = match route {
        Some(r) => stmt.query_map(params![r], |row| row.get(0))?.collect::<Result<_, _>>()?,
        None => stmt.query_map([], |row| row.get(0))?.collect::<Result<_, _>>()?,
    };
    let mut out: Vec<WatchJobData> = rows.iter().map(|r| serde_json::from_str(r)).collect::<Result<_, _>>()?;
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(out)
}

pub fn save_job_conn(c: &Connection, job: &WatchJobData) -> Result<()> {
    let data = horus_core::json::to_js_json(&redact(job)?)?;
    c.execute("UPDATE watch_job SET data = ?1, updated_at = ?2 WHERE id = ?3", params![data, now_iso(), job.id])?;
    Ok(())
}

// ── Async wrappers (TS surface) ─────────────────────────────────────────────

pub async fn read_watch_state<T: DeserializeOwned + Send + 'static>(db: &DbHandle, key: &str) -> Result<Option<T>> {
    let key = key.to_string();
    db.with_conn(move |c| read_watch_state_conn(c, &key)).await
}

pub async fn write_watch_state(db: &DbHandle, key: &str, value: Value) -> Result<()> {
    let key = key.to_string();
    db.with_conn(move |c| write_watch_state_conn(c, &key, &value)).await
}

pub async fn jobs(db: &DbHandle, route: Option<&str>) -> Result<Vec<WatchJobData>> {
    let route = route.map(str::to_string);
    db.with_conn(move |c| jobs_conn(c, route.as_deref())).await
}

pub async fn save_job(db: &DbHandle, job: &WatchJobData) -> Result<()> {
    let job = job.clone();
    db.with_conn(move |c| save_job_conn(c, &job)).await
}

/// Cloud claim attached to a batch of accepted events.
#[derive(Debug, Clone)]
pub struct CloudClaim {
    pub request_id: String,
    pub report_id: String,
    pub claim_token: String,
    pub worker_id: String,
}

impl CloudClaim {
    fn as_ref(&self) -> CloudRequestRef {
        CloudRequestRef { id: self.request_id.clone(), claim_token: self.claim_token.clone(), worker_id: self.worker_id.clone() }
    }
}

/// Event acceptance and the source cursor commit together. No permanent in-memory seen set.
pub async fn accept_events(
    db: &DbHandle,
    route: &str,
    events: Vec<IncidentEvent>,
    cursor: Option<String>,
    cloud: Option<CloudClaim>,
) -> Result<()> {
    let route = route.to_string();
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        accept_events_conn(&tx, &route, events, cursor.as_deref(), cloud.as_ref())?;
        tx.commit()?;
        Ok(())
    })
    .await
}

/// `acceptEvents` plus one extra `watch_state` write, committed in the same transaction (the
/// Sentry page cursor advances only with the events it produced).
pub async fn accept_events_with_state(
    db: &DbHandle,
    route: &str,
    events: Vec<IncidentEvent>,
    cursor: Option<String>,
    state_key: String,
    state_value: Value,
) -> Result<()> {
    let route = route.to_string();
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        accept_events_conn(&tx, &route, events, cursor.as_deref(), None)?;
        write_watch_state_conn(&tx, &state_key, &state_value)?;
        tx.commit()?;
        Ok(())
    })
    .await
}

fn accept_events_conn(
    c: &Connection,
    route: &str,
    mut events: Vec<IncidentEvent>,
    cursor: Option<&str>,
    cloud: Option<&CloudClaim>,
) -> Result<()> {
    events.sort_by(|a, b| a.occurred_at.cmp(&b.occurred_at));
    for raw in events {
        raw.validate()?;
        let event = redact(&raw)?;
        let stored_event_id = match cloud {
            Some(cl) => format!("{}:{}", cl.request_id, event.event_id),
            None => event.event_id.clone(),
        };
        let seen: Option<String> = c
            .query_row(
                "SELECT job_id FROM watch_event WHERE route = ?1 AND event_id = ?2",
                params![route, stored_event_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(job_id) = seen {
            if let Some(cl) = cloud {
                let raw_job: String =
                    c.query_row("SELECT data FROM watch_job WHERE id = ?1", params![job_id], |r| r.get(0))?;
                let mut job: WatchJobData = serde_json::from_str(&raw_job)?;
                job.cloud_request = Some(cl.as_ref());
                if job.status == "done" {
                    job.stage = "complete".into();
                    job.status = "pending".into();
                }
                save_job_conn(c, &job)?;
            }
            continue;
        }
        let family = event.family();
        let prior = jobs_conn(c, Some(route))?
            .into_iter()
            .filter(|j| match cloud {
                Some(cl) => j.id == cl.request_id || j.cloud_request.as_ref().is_some_and(|r| r.id == cl.request_id),
                None => j.event.family() == family,
            })
            .last();
        let occurred = parse_ms(&event.occurred_at);
        let is_later = match &prior {
            None => true,
            Some(p) => match (occurred, parse_ms(&p.current_event().occurred_at)) {
                (Some(a), Some(b)) => a >= b,
                _ => false, // NaN comparison
            },
        };
        // Explicit resolution or a native new episode reopens; ES has no resolve, so a quiet hour
        // is an explicit episode boundary.
        let recurrence = prior.as_ref().is_some_and(|p| {
            is_later
                && event.state == "active"
                && ((p.resolved_at.is_some() && (event.episode.is_none() || event.episode != p.event.episode))
                    || (event.episode.is_some() && event.episode != p.event.episode)
                    || (event.source == "elasticsearch"
                        && matches!((occurred, parse_ms(&p.current_event().occurred_at)), (Some(a), Some(b)) if a - b > 3_600_000)))
        });
        let mut job = match prior {
            Some(p) if !recurrence => p,
            _ => {
                let id = cloud.map_or_else(|| uuid::Uuid::new_v4().to_string(), |cl| cl.request_id.clone());
                let resolved = event.state == "resolved";
                let job = WatchJobData {
                    id: id.clone(),
                    route: route.to_string(),
                    event: event.clone(),
                    report_id: cloud.map_or_else(|| uuid::Uuid::new_v4().to_string(), |cl| cl.report_id.clone()),
                    created_at: now_iso(),
                    stage: "engine".into(),
                    attempts: IndexMap::new(),
                    next_attempt_at: 0,
                    status: if resolved && event.investigation_required != Some(true) { "cancelled" } else { "pending" }.into(),
                    resolved_at: resolved.then(|| event.occurred_at.clone()),
                    ..empty_job()
                };
                let episode = match cloud {
                    Some(cl) => digest(&[&cl.request_id]),
                    None => digest(&[&family, event.episode.as_ref().unwrap_or(&event.event_id)]),
                };
                c.execute(
                    "INSERT INTO watch_job (id, route, episode, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![id, route, episode, horus_core::json::to_js_json(&job)?, now_iso()],
                )?;
                insert_and_continue(c, route, &stored_event_id, job, cloud)?;
                continue;
            }
        };
        if is_later {
            let reopen = |job: &mut WatchJobData| {
                job.stage = "engine".into();
                job.status = "pending".into();
                job.next_attempt_at = 0;
            };
            let closed = |job: &WatchJobData| ["cancelled", "done"].contains(&job.status.as_str());
            if event.investigation_required == Some(true) && job.attempts_for("engine") == 0 && closed(&job) {
                reopen(&mut job);
            }
            let previous_severity = job.current_event().severity.clone();
            job.latest_event = Some(event.clone());
            if event.state == "resolved" {
                job.resolved_at = Some(event.occurred_at.clone());
            } else {
                // A resolved-only episode has no report; its first active event still needs the engine.
                if job.resolved_at.is_some() && job.attempts_for("engine") == 0 && closed(&job) {
                    reopen(&mut job);
                }
                job.resolved_at = None;
            }
            // Severity changes re-deliver the saved incident without re-running inference.
            if event.severity != previous_severity && job.status == "done" {
                job.stage = "notify".into();
                job.status = "pending".into();
                job.notified = Some(false);
                // The prior delivery was acknowledged; this update gets its own retry checkpoint.
                job.notification_key = None;
                job.attempts.insert("notify".into(), 0);
                job.next_attempt_at = 0;
            }
        }
        insert_and_continue(c, route, &stored_event_id, job, cloud)?;
    }
    if let Some(cursor) = cursor.filter(|c| !c.is_empty()) {
        write_watch_state_conn(c, &format!("cursor:{route}"), cursor)?;
    }
    Ok(())
}

/// Shared tail of one accepted event: attach the cloud claim, save, record the event id.
fn insert_and_continue(
    c: &Connection,
    route: &str,
    stored_event_id: &str,
    mut job: WatchJobData,
    cloud: Option<&CloudClaim>,
) -> Result<()> {
    if let Some(cl) = cloud {
        job.cloud_request = Some(cl.as_ref());
        if job.status == "done" || job.status == "cancelled" {
            job.stage = "complete".into();
            job.status = "pending".into();
        }
    }
    save_job_conn(c, &job)?;
    c.execute(
        "INSERT INTO watch_event (route, event_id, job_id) VALUES (?1, ?2, ?3)",
        params![route, stored_event_id, job.id],
    )
    .map_err(|e| anyhow!("watch event insert: {e}"))?;
    Ok(())
}

fn empty_job() -> WatchJobData {
    WatchJobData {
        id: String::new(),
        route: String::new(),
        event: IncidentEvent {
            source: String::new(),
            event_id: String::new(),
            incident_id: String::new(),
            fingerprint: String::new(),
            occurred_at: String::new(),
            hint: String::new(),
            environment: String::new(),
            service: None,
            source_url: None,
            state: String::new(),
            investigation_required: None,
            severity: String::new(),
            episode: None,
            order_id: None,
            workflow: None,
            correlation_id: None,
            error_code: None,
            event_code: None,
            operation: None,
        },
        report_id: String::new(),
        created_at: String::new(),
        stage: String::new(),
        attempts: IndexMap::new(),
        next_attempt_at: 0,
        status: String::new(),
        error: None,
        pid: None,
        resolved_at: None,
        cloud_report_id: None,
        cloud_agent_run_id: None,
        cloud_url: None,
        cloud_request: None,
        ai: None,
        ai_failure: None,
        ai_round: None,
        initial_evidence_collected: None,
        repair: None,
        repair_attempts: None,
        notified: None,
        notification_key: None,
        notice: None,
        latest_event: None,
        activity: None,
        started_at: None,
        analysis_ended_at: None,
    }
}
