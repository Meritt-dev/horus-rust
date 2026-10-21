//! Durable replication of the existing memory store; no background work survives CLI exit.
//! Port of `packages/cli/src/lib/cloud/memory-sync.ts`.
//!
//! drizzle queries become raw SQL over the embedded SQLite store. The Postgres
//! `set_config('horus.sync_pull','1', true)` transaction flag is the `__horus_settings` row the
//! sync triggers check (see migration 0013); it is set and cleared inside each transaction.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use horus_core::redact_error_message;
use horus_db::{format_ts, parse_ts, DbHandle};
use horus_engine::auto_investigation_memory::create_investigation_memory;
use horus_engine::memory::{create_local_memory_store, store_incident_memory, LocalMemoryStoreOpts, LocalStore};
use horus_engine::memory_db::SqliteMemoryStorage;
use horus_engine::memory_recall::read_incident_disposition;
use horus_engine::memory_store::{
    AuditActor, AuditActorKind, AuditCtx, LocalMemoryStore, MemoryAudit, MemoryItem, MemoryLink, MemoryStatus, MemoryStore, NewMemoryItem,
};
use horus_engine::migrate_report::migrate_report;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use serde_json::{Map, Value};

use super::api::{CloudClient, MemoryItemRecord, MemoryListQuery, TeamMemoryListQuery};
use super::auth_store::read_auth;
use super::context_store::{read_cloud_config, CloudConfig};
use super::investigation_sync::{fetch_investigation_report_from_cloud, redact_cloud_value, upload_investigation_to_cloud, UploadOpts};
use super::memory_history::{hydrate_memory_history, memory_history_pages};
use super::memory_store::{to_audit_sync_input, to_link_sync_input, to_sync_input};

#[derive(Debug, Clone, Serialize)]
pub struct MemorySyncConflictRow {
    #[serde(rename = "memoryId")]
    pub memory_id: String,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    pub detail: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemorySyncBackfill {
    pub eligible: usize,
    pub indexed: usize,
    pub pending: usize,
    pub excluded: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed: Option<usize>,
}

/// Field order = the TS `status()` object literal (JSON key order).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySyncStatus {
    /// `Synced` | `Pending sync` | `Sign-in required` | `Local only`.
    pub state: String,
    pub eligible: usize,
    pub synced: usize,
    pub pending: usize,
    pub excluded: usize,
    pub failed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backfill: Option<MemorySyncBackfill>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_pull: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_push: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_pending: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<Vec<MemorySyncConflictRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl MemorySyncStatus {
    fn bare(state: &str) -> Self {
        Self {
            state: state.into(),
            eligible: 0,
            synced: 0,
            pending: 0,
            excluded: 0,
            failed: 0,
            backfill: None,
            last_pull: None,
            last_push: None,
            oldest_pending: None,
            conflicts: None,
            error: None,
        }
    }
}

#[derive(Clone)]
pub struct MemorySyncContext {
    pub client: CloudClient,
    pub config: CloudConfig,
    pub scope: String,
    pub repo: String,
    pub user_id: String,
}

impl MemorySyncContext {
    fn project_id(&self) -> &str {
        self.config.project.as_ref().map(|p| p.id.as_str()).unwrap_or_default()
    }
    fn org_id(&self) -> Option<String> {
        self.config.organization.as_ref().map(|o| o.id.clone())
    }
    fn workspace_id(&self) -> Option<String> {
        self.config.workspace.as_ref().map(|w| w.id.clone())
    }
}

/// The sync context for a cloud-linked, logged-in repo, or None. `deadline` is the TS
/// `AbortSignal`: every cloud request is capped at it.
pub fn memory_sync_context(root: &Path, repo: &str, deadline: Option<Instant>) -> Option<MemorySyncContext> {
    let config = read_cloud_config(root)?;
    let auth = read_auth()?;
    let project = config.project.as_ref()?;
    if config.context != "cloud" {
        return None;
    }
    let mut client = CloudClient::new(&auth.api_base_url, Some(&auth.token));
    if let Some(d) = deadline {
        client = client.with_deadline(d);
    }
    let scope = horus_core::json::to_js_json(&serde_json::json!([
        auth.api_base_url.strip_suffix('/').unwrap_or(&auth.api_base_url),
        config.organization.as_ref().map(|o| o.id.clone()),
        config.workspace.as_ref().map(|w| w.id.clone()),
        project.id,
        auth.account.user_id,
    ]))
    .ok()?;
    Some(MemorySyncContext { client, repo: repo.to_string(), user_id: auth.account.user_id.clone(), scope, config })
}

// ── SQL helpers ─────────────────────────────────────────────────────────────

const ITEM_COLS: &str = "id, kind, claim, scope, source, evidence, confidence, status, created_at, last_verified_at, \
    last_verified_hash, org_id, workspace_id, repo, user_id, visibility, sync_scope, sync_generation, origin, cloud_id, \
    author_name, pulled_at, payload, signature, tags";

fn json_col(s: Option<String>) -> Option<Value> {
    s.and_then(|s| serde_json::from_str(&s).ok())
}

fn opt_ts(s: Option<String>) -> Result<Option<DateTime<Utc>>> {
    s.map(|s| parse_ts(&s)).transpose()
}

fn row_item(r: &Row<'_>) -> Result<MemoryItem> {
    Ok(MemoryItem {
        id: r.get("id")?,
        kind: r.get("kind")?,
        claim: r.get("claim")?,
        scope: r.get("scope")?,
        source: r.get("source")?,
        evidence: json_col(r.get("evidence")?).unwrap_or(Value::Array(vec![])),
        confidence: r.get("confidence")?,
        status: r.get("status")?,
        created_at: parse_ts(&r.get::<_, String>("created_at")?)?,
        last_verified_at: opt_ts(r.get("last_verified_at")?)?,
        last_verified_hash: r.get("last_verified_hash")?,
        org_id: r.get("org_id")?,
        workspace_id: r.get("workspace_id")?,
        repo: r.get("repo")?,
        user_id: r.get("user_id")?,
        visibility: r.get("visibility")?,
        sync_scope: r.get("sync_scope")?,
        sync_generation: r.get("sync_generation")?,
        origin: r.get("origin")?,
        cloud_id: r.get("cloud_id")?,
        author_name: r.get("author_name")?,
        pulled_at: opt_ts(r.get("pulled_at")?)?,
        payload: json_col(r.get("payload")?),
        signature: r.get("signature")?,
        tags: json_col(r.get("tags")?).and_then(|v| serde_json::from_value(v).ok()),
    })
}

fn row_link(r: &Row<'_>) -> Result<MemoryLink> {
    Ok(MemoryLink {
        id: r.get("id")?,
        from_memory_id: r.get("from_memory_id")?,
        rel: r.get("rel")?,
        to_kind: r.get("to_kind")?,
        to_ref: r.get("to_ref")?,
        to_file_path: r.get("to_file_path")?,
        created_at: parse_ts(&r.get::<_, String>("created_at")?)?,
    })
}

fn row_audit(r: &Row<'_>) -> Result<MemoryAudit> {
    Ok(MemoryAudit {
        id: r.get("id")?,
        memory_id: r.get("memory_id")?,
        action: r.get("action")?,
        actor: json_col(r.get("actor")?).unwrap_or(Value::Null),
        from_status: r.get("from_status")?,
        to_status: r.get("to_status")?,
        note: r.get("note")?,
        detail: json_col(r.get("detail")?),
        at: parse_ts(&r.get::<_, String>("at")?)?,
    })
}

fn query<T>(c: &Connection, sql: &str, args: &[&dyn rusqlite::ToSql], map: fn(&Row<'_>) -> Result<T>) -> Result<Vec<T>> {
    let mut stmt = c.prepare(sql)?;
    let mut rows = stmt.query(args)?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(map(r)?);
    }
    Ok(out)
}

fn items_where(c: &Connection, clause: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<MemoryItem>> {
    query(c, &format!("SELECT {ITEM_COLS} FROM memory_item WHERE {clause}"), args, row_item)
}

fn all_links(c: &Connection) -> Result<Vec<MemoryLink>> {
    query(c, "SELECT id, from_memory_id, rel, to_kind, to_ref, to_file_path, created_at FROM memory_link", &[], row_link)
}

fn set_sync_pull(c: &Connection, on: bool) -> Result<()> {
    if on {
        c.execute("INSERT OR REPLACE INTO \"__horus_settings\" (key, value) VALUES ('horus.sync_pull', '1')", [])?;
    } else {
        c.execute("DELETE FROM \"__horus_settings\" WHERE key = 'horus.sync_pull'", [])?;
    }
    Ok(())
}

fn now_ts() -> String {
    format_ts(&Utc::now())
}

fn iso(d: &DateTime<Utc>) -> String {
    d.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// `new Date(s).toISOString()` for the ISO strings the cloud returns.
fn date_iso(s: &str) -> Result<String> {
    let t = DateTime::parse_from_rfc3339(s).map_err(|_| anyhow!("Invalid time value"))?;
    Ok(iso(&t.with_timezone(&Utc)))
}

fn js(v: &impl Serialize) -> Result<String> {
    Ok(horus_core::json::to_js_json(v)?)
}

#[derive(Debug, Clone)]
struct StateRow {
    cursor: String,
    team_cursor: String,
    last_pull: Option<String>,
    last_push: Option<String>,
    error: Option<String>,
}

async fn read_state(db: &DbHandle, scope: &str) -> Result<Option<StateRow>> {
    let scope = scope.to_string();
    db.with_conn(move |c| {
        Ok(c.query_row(
            "SELECT cursor, team_cursor, last_pull, last_push, error FROM memory_sync_state WHERE scope = ?1",
            params![scope],
            |r| Ok(StateRow { cursor: r.get(0)?, team_cursor: r.get(1)?, last_pull: r.get(2)?, last_push: r.get(3)?, error: r.get(4)? }),
        )
        .optional()?)
    })
    .await
}

#[derive(Debug, Clone)]
struct OutboxRow {
    id: String,
    memory_id: String,
    generation: i64,
    request: Value,
    attempts: i64,
    next_attempt_at: String,
    error: Option<String>,
    conflict: Option<Value>,
    created_at: String,
}

fn row_outbox(r: &Row<'_>) -> Result<OutboxRow> {
    Ok(OutboxRow {
        id: r.get("id")?,
        memory_id: r.get("memory_id")?,
        generation: r.get("generation")?,
        request: json_col(r.get("request")?).unwrap_or(Value::Null),
        attempts: r.get("attempts")?,
        next_attempt_at: r.get("next_attempt_at")?,
        error: r.get("error")?,
        conflict: json_col(r.get("conflict")?),
        created_at: r.get("created_at")?,
    })
}

const OUTBOX_COLS: &str = "id, memory_id, generation, request, attempts, next_attempt_at, error, conflict, created_at";

async fn outbox_where(db: &DbHandle, clause: &'static str, a: String, b: Option<String>) -> Result<Vec<OutboxRow>> {
    db.with_conn(move |c| match &b {
        Some(b) => query(c, &format!("SELECT {OUTBOX_COLS} FROM memory_sync_outbox WHERE {clause}"), &[&a, b], row_outbox),
        None => query(c, &format!("SELECT {OUTBOX_COLS} FROM memory_sync_outbox WHERE {clause}"), &[&a], row_outbox),
    })
    .await
}

async fn replica(db: &DbHandle, scope: &str, memory_id: &str) -> Result<Option<(String, i64)>> {
    let (scope, memory_id) = (scope.to_string(), memory_id.to_string());
    db.with_conn(move |c| {
        Ok(c.query_row(
            "SELECT revision, generation FROM memory_sync_replica WHERE scope = ?1 AND memory_id = ?2",
            params![scope, memory_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
    })
    .await
}

fn payload_of(item: &MemoryItem) -> Map<String, Value> {
    item.payload.as_ref().and_then(Value::as_object).cloned().unwrap_or_default()
}

fn covered_reports(memories: &[MemoryItem], links: &[MemoryLink]) -> HashSet<String> {
    let mut covered: HashSet<String> = links.iter().filter(|l| l.to_kind == "incident").map(|l| l.to_ref.clone()).collect();
    for item in memories {
        let p = payload_of(item);
        if let Some(id) = p.get("investigationId").and_then(Value::as_str) {
            covered.insert(id.to_string());
        }
        if let Some(ids) = p.get("investigationIds").and_then(Value::as_array) {
            for id in ids {
                covered.insert(match id {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                });
            }
        }
    }
    covered
}

fn can_backfill(report: &Value) -> bool {
    report.pointer("/input/hint").and_then(Value::as_str).is_some_and(|h| !h.is_empty())
        && report.get("hypotheses").is_some_and(Value::is_array)
}

const ELIGIBLE_SQL: &str = "coalesce(json_type(report, '$.hypotheses') = 'array' \
    AND json_extract(report, '$.input.hint') <> '', 0)";

/// Read eligibility cheaply; isolate unreadable payloads without losing the rest of the history.
async fn report_history(db: &DbHandle, repo: &str) -> Result<(Vec<(String, bool)>, Vec<String>)> {
    let repo = repo.to_string();
    db.with_conn(move |c| {
        fn read(c: &Connection, repo: &str, ids: Option<Vec<String>>, rows: &mut Vec<(String, bool)>, failed: &mut Vec<String>) -> Result<()> {
            if ids.as_ref().is_some_and(Vec::is_empty) {
                return Ok(());
            }
            let attempt = || -> Result<Vec<(String, bool)>> {
                let mut sql = format!("SELECT id, {ELIGIBLE_SQL} FROM investigations WHERE project = ?1");
                let mut args: Vec<String> = vec![repo.to_string()];
                if let Some(ids) = &ids {
                    sql += &format!(" AND id IN ({})", (0..ids.len()).map(|i| format!("?{}", i + 2)).collect::<Vec<_>>().join(","));
                    args.extend(ids.iter().cloned());
                }
                let mut stmt = c.prepare(&sql)?;
                let out = stmt
                    .query_map(rusqlite::params_from_iter(args), |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(out)
            };
            match attempt() {
                Ok(batch) => {
                    // A damaged index can expose a metadata row that cannot be fetched by its key.
                    if let Some(ids) = &ids {
                        let found: HashSet<&str> = batch.iter().map(|(id, _)| id.as_str()).collect();
                        failed.extend(ids.iter().filter(|id| !found.contains(id.as_str())).cloned());
                    }
                    rows.extend(batch);
                }
                Err(_) => {
                    let ids = match ids {
                        Some(ids) => ids,
                        None => {
                            let mut stmt = c.prepare("SELECT id FROM investigations WHERE project = ?1")?;
                            let ids = stmt.query_map(params![repo], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                            ids
                        }
                    };
                    if ids.len() <= 1 {
                        failed.extend(ids);
                        return Ok(());
                    }
                    let mid = ids.len().div_ceil(2);
                    read(c, repo, Some(ids[..mid].to_vec()), rows, failed)?;
                    read(c, repo, Some(ids[mid..].to_vec()), rows, failed)?;
                }
            }
            Ok(())
        }
        let (mut rows, mut failed) = (Vec::new(), Vec::new());
        read(c, &repo, None, &mut rows, &mut failed)?;
        Ok((rows, failed))
    })
    .await
}

/// Only named scalar/incident fields leave the device. Unknown payload keys are excluded.
pub fn memory_record(item: &MemoryItem) -> Map<String, Value> {
    let payload = payload_of(item);
    let mut record = Map::new();
    record.insert("confidence".into(), serde_json::json!(item.confidence));
    record.insert("signature".into(), item.signature.clone().map_or(Value::Null, Value::String));
    let evidence: Vec<Value> = item
        .evidence
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| {
                    let picked: Map<String, Value> = ["kind", "ref", "shortId", "capturedAt"]
                        .iter()
                        .filter_map(|k| e.get(*k).filter(|v| v.is_string()).map(|v| (k.to_string(), v.clone())))
                        .collect();
                    Value::Object(picked)
                })
                .collect()
        })
        .unwrap_or_default();
    record.insert("evidence".into(), Value::Array(evidence));
    record.insert("tags".into(), item.tags.as_ref().map_or(Value::Null, |t| serde_json::json!(t)));
    record.insert("clientCreatedAt".into(), Value::String(iso(&item.created_at)));
    record.insert("lastVerifiedAt".into(), item.last_verified_at.as_ref().map_or(Value::Null, |d| Value::String(iso(d))));
    record.insert("lastVerifiedHash".into(), item.last_verified_hash.clone().map_or(Value::Null, Value::String));
    for key in ["hint", "topHypothesis", "lastSeenAt", "investigationId"] {
        if let Some(v) = payload.get(key).filter(|v| v.is_string()) {
            record.insert(key.into(), v.clone());
        }
    }
    if let Some(v) = payload.get("recurrenceCount").filter(|v| v.is_number()) {
        record.insert("recurrenceCount".into(), v.clone());
    }
    if let Some(ids) = payload.get("investigationIds").and_then(Value::as_array) {
        record.insert("investigationIds".into(), Value::Array(ids.iter().filter(|v| v.is_string()).cloned().collect()));
    }
    if let Some(refs) = payload.get("reportRefs").and_then(Value::as_object) {
        record.insert(
            "reportRefs".into(),
            Value::Object(refs.iter().filter(|(_, v)| v.is_string()).map(|(k, v)| (k.clone(), v.clone())).collect()),
        );
    }
    if let Some(outcome) = read_incident_disposition(payload.get("outcome")) {
        if let Ok(v) = horus_core::json::to_js_value(&outcome) {
            record.insert("outcome".into(), v);
        }
    }
    record
}

async fn status(db: &DbHandle, ctx: &MemorySyncContext) -> Result<MemorySyncStatus> {
    let state = read_state(db, &ctx.scope).await?;
    let repo = ctx.repo.clone();
    let (rows, links) = db
        .with_conn(move |c| Ok((items_where(c, "repo = ?1", &[&repo])?, all_links(c)?)))
        .await?;
    // Status needs eligibility, not megabytes of historical evidence on every refresh.
    let (reports, unreadable) = report_history(db, &ctx.repo).await?;
    let covered = covered_reports(&rows, &links);
    let eligible_reports: Vec<&(String, bool)> = reports.iter().filter(|(_, e)| *e).collect();
    let indexed = eligible_reports.iter().filter(|(id, _)| covered.contains(id)).count();
    let backfill = MemorySyncBackfill {
        eligible: eligible_reports.len(),
        indexed,
        pending: eligible_reports.len() - indexed,
        excluded: reports.len() - eligible_reports.len(),
        failed: (!unreadable.is_empty()).then_some(unreadable.len()),
    };
    let scope = ctx.scope.clone();
    let ack: HashMap<String, i64> = db
        .with_conn(move |c| {
            let mut stmt = c.prepare("SELECT memory_id, generation FROM memory_sync_replica WHERE scope = ?1")?;
            let rows = stmt.query_map(params![scope], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows.into_iter().collect())
        })
        .await?;
    let eligible: Vec<&MemoryItem> = rows
        .iter()
        .filter(|r| r.origin != "cloud" && (r.sync_scope.as_deref() == Some(ctx.scope.as_str()) || r.sync_scope.is_none()))
        .collect();
    let pending: Vec<&&MemoryItem> = eligible.iter().filter(|r| ack.get(&r.id) != Some(&r.sync_generation)).collect();
    let outbox = outbox_where(db, "scope = ?1", ctx.scope.clone(), None).await?;

    let state_error = state.as_ref().and_then(|s| s.error.clone());
    let state_label = if state_error.as_deref().is_some_and(|e| e.starts_with("Sign-in required")) {
        "Sign-in required"
    } else if !pending.is_empty() || backfill.pending > 0 || !unreadable.is_empty() || state_error.as_deref().is_some_and(|e| !e.is_empty()) {
        "Pending sync"
    } else {
        "Synced"
    };
    let mut outbox_created: Vec<String> = outbox.iter().map(|r| r.created_at.clone()).collect();
    outbox_created.sort();
    let mut pending_created: Vec<String> = pending.iter().map(|r| iso(&r.created_at)).collect();
    pending_created.sort();
    let error = state_error
        .or_else(|| outbox.iter().find_map(|r| r.error.clone().filter(|e| !e.is_empty())))
        .or_else(|| {
            (!unreadable.is_empty())
                .then(|| format!("Unreadable saved reports ({}): {}", unreadable.len(), unreadable.join(", ")))
        });
    Ok(MemorySyncStatus {
        state: state_label.into(),
        eligible: eligible.len(),
        synced: eligible.len() - pending.len(),
        pending: pending.len(),
        excluded: rows.len() - eligible.len(),
        failed: outbox.iter().filter(|r| r.error.as_deref().is_some_and(|e| !e.is_empty()) || r.conflict.is_some()).count()
            + unreadable.len(),
        backfill: Some(backfill),
        last_pull: state.as_ref().and_then(|s| s.last_pull.clone()),
        last_push: state.as_ref().and_then(|s| s.last_push.clone()),
        oldest_pending: outbox_created.into_iter().next().or_else(|| pending_created.into_iter().next()),
        conflicts: Some(
            outbox
                .iter()
                .filter_map(|r| {
                    Some(MemorySyncConflictRow { memory_id: r.memory_id.clone(), operation_id: r.id.clone(), detail: r.conflict.clone()? })
                })
                .collect(),
        ),
        error,
    })
}

fn str_field<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(Value::as_str)
}

async fn apply_remote(db: &DbHandle, ctx: &MemorySyncContext, row: MemoryItemRecord, advance_pull: bool) -> Result<()> {
    let revision = row.revision.clone().filter(|r| !r.is_empty());
    if revision.is_none()
        || row.project_id.as_deref() != Some(ctx.project_id())
        || Some(row.organization_id.clone()) != ctx.org_id()
        || Some(row.workspace_id.clone()) != ctx.workspace_id()
        || (row.visibility == "private" && row.created_by_user_id.as_deref() != Some(ctx.user_id.as_str()))
    {
        bail!("Cloud memory scope or revision mismatch");
    }
    let revision = revision.unwrap_or_default();
    let ctx = ctx.clone();
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        set_sync_pull(&tx, true)?;
        let finish = |tx: &Connection| -> Result<()> {
            tx.execute("DELETE FROM memory_sync_pull_page WHERE scope = ?1", params![ctx.scope])?;
            if advance_pull {
                tx.execute(
                    "UPDATE memory_sync_state SET pull_progress = NULL, cursor = ?1, last_pull = ?2, error = NULL WHERE scope = ?3",
                    params![revision, now_ts(), ctx.scope],
                )?;
            } else {
                tx.execute("UPDATE memory_sync_state SET pull_progress = NULL WHERE scope = ?1", params![ctx.scope])?;
            }
            set_sync_pull(tx, false)
        };
        let local = items_where(&tx, "id = ?1", &[&row.client_id])?.into_iter().next();
        let replica: Option<i64> = tx
            .query_row(
                "SELECT generation FROM memory_sync_replica WHERE scope = ?1 AND memory_id = ?2",
                params![ctx.scope, row.client_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(l) = &local {
            if l.sync_scope.as_deref().is_some_and(|s| !s.is_empty() && s != ctx.scope) {
                bail!("Memory id belongs to another synchronization scope");
            }
            if replica != Some(l.sync_generation) {
                // Adopt legacy mirror revisions without discarding richer local history.
                if replica.is_none() {
                    tx.execute(
                        "INSERT INTO memory_sync_replica (scope, memory_id, revision, generation) VALUES (?1, ?2, ?3, 0)",
                        params![ctx.scope, l.id, revision],
                    )?;
                }
                // A remote tombstone suppresses recall immediately; the competing correction stays local.
                if row.status == "forgotten" {
                    tx.execute("UPDATE memory_item SET status = 'forgotten' WHERE id = ?1", params![l.id])?;
                }
                finish(&tx)?;
                tx.commit()?;
                return Ok(());
            }
        }
        let record = row.record.clone().unwrap_or_default();
        let own = row.created_by_user_id.as_deref() == Some(ctx.user_id.as_str());
        let created_at = date_iso(str_field(&record, "clientCreatedAt").unwrap_or(&row.created_at))?;
        let last_verified_at = str_field(&record, "lastVerifiedAt").map(date_iso).transpose()?;
        let sync_generation = local.as_ref().map_or(1, |l| l.sync_generation);
        let tags = record.get("tags").filter(|t| t.is_array()).map(js).transpose()?;
        let evidence = js(record.get("evidence").unwrap_or(&Value::Array(vec![])))?;
        tx.execute(
            "INSERT INTO memory_item (id, kind, claim, scope, source, status, visibility, confidence, created_at, \
             last_verified_at, last_verified_hash, signature, tags, repo, org_id, workspace_id, user_id, origin, sync_scope, \
             sync_generation, cloud_id, pulled_at, payload, evidence) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24) \
             ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, claim = excluded.claim, scope = excluded.scope, \
             source = excluded.source, status = excluded.status, visibility = excluded.visibility, \
             confidence = excluded.confidence, created_at = excluded.created_at, last_verified_at = excluded.last_verified_at, \
             last_verified_hash = excluded.last_verified_hash, signature = excluded.signature, tags = excluded.tags, \
             repo = excluded.repo, org_id = excluded.org_id, workspace_id = excluded.workspace_id, user_id = excluded.user_id, \
             origin = excluded.origin, sync_scope = excluded.sync_scope, sync_generation = excluded.sync_generation, \
             cloud_id = excluded.cloud_id, pulled_at = excluded.pulled_at, payload = excluded.payload, evidence = excluded.evidence",
            rusqlite::params![
                row.client_id,
                row.kind,
                row.claim,
                row.scope,
                row.source,
                row.status,
                row.visibility,
                record.get("confidence").and_then(Value::as_f64).unwrap_or(0.0),
                created_at,
                last_verified_at,
                str_field(&record, "lastVerifiedHash"),
                str_field(&record, "signature"),
                tags,
                ctx.repo,
                row.organization_id,
                row.workspace_id,
                row.created_by_user_id,
                if own { "local" } else { "cloud" },
                ctx.scope,
                sync_generation,
                row.id,
                now_ts(),
                js(&record)?,
                evidence,
            ],
        )?;
        tx.execute("DELETE FROM memory_link WHERE from_memory_id = ?1", params![row.client_id])?;
        for link in row.links.as_deref().unwrap_or_default() {
            tx.execute(
                "INSERT INTO memory_link (id, from_memory_id, rel, to_kind, to_ref, to_file_path, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT DO NOTHING",
                params![
                    link.link.idempotency_key,
                    row.client_id,
                    link.link.rel,
                    link.link.to_kind,
                    link.link.to_ref,
                    link.link.to_file_path,
                    date_iso(&link.created_at)?
                ],
            )?;
        }
        for audit in row.audit.as_deref().unwrap_or_default() {
            let detail = audit.detail.clone().unwrap_or_default();
            tx.execute(
                "INSERT INTO memory_audit (id, memory_id, action, actor, at, from_status, to_status, note, detail) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT DO NOTHING",
                params![
                    audit.client_audit_id,
                    row.client_id,
                    audit.action,
                    js(&audit.actor)?,
                    date_iso(&audit.at)?,
                    str_field(&detail, "fromStatus"),
                    str_field(&detail, "toStatus"),
                    str_field(&detail, "note"),
                    audit.detail.as_ref().map(js).transpose()?,
                ],
            )?;
        }
        for label in record.get("accuracyFeedback").and_then(Value::as_array).cloned().unwrap_or_default() {
            insert_feedback_label(&tx, &label, &ctx.repo, None)?;
        }
        tx.execute(
            "INSERT INTO memory_sync_replica (scope, memory_id, revision, generation) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(scope, memory_id) DO UPDATE SET revision = excluded.revision, generation = excluded.generation",
            params![ctx.scope, row.client_id, revision, sync_generation],
        )?;
        finish(&tx)?;
        tx.commit()?;
        Ok(())
    })
    .await
}

/// JS `String(v)` for the label fields carried in `accuracyFeedback`.
fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "null".into(),
        Some(other) => other.to_string(),
    }
}

/// Insert one synced outcome label when its investigation exists locally for `repo`
/// (`only_investigation` pins it to a known id instead of looking it up).
fn insert_feedback_label(tx: &Connection, label: &Value, repo: &str, only_investigation: Option<&str>) -> Result<()> {
    let investigation_id = js_string(label.get("investigationId"));
    let report_id = match only_investigation {
        Some(id) => Some(id.to_string()),
        None => tx
            .query_row(
                "SELECT id FROM investigations WHERE id = ?1 AND project = ?2",
                params![investigation_id, repo],
                |r| r.get::<_, String>(0),
            )
            .optional()?,
    };
    let Some(report_id) = report_id else { return Ok(()) };
    tx.execute(
        "INSERT INTO outcome_label (id, investigation_id, project, resolved, source, at, note, confirmed_cause) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT DO NOTHING",
        params![
            js_string(label.get("id")),
            report_id,
            repo,
            js_string(label.get("resolved")),
            js_string(label.get("source")),
            date_iso(&js_string(label.get("at")))?,
            label.get("note").and_then(Value::as_str),
            label.get("confirmedCause").and_then(Value::as_str),
        ],
    )?;
    Ok(())
}

fn local_store(db: &DbHandle) -> LocalStore {
    create_local_memory_store(Arc::new(SqliteMemoryStorage::new(db.clone())), LocalMemoryStoreOpts::default())
}

fn system_audit(note: &str) -> AuditCtx {
    AuditCtx { actor: AuditActor::system(), note: Some(note.into()) }
}

async fn pull_team_memory(db: &DbHandle, ctx: &MemorySyncContext, deadline: Instant) -> Result<()> {
    let state = read_state(db, &ctx.scope).await?.ok_or_else(|| anyhow!("memory sync state missing"))?;
    let mut cursor = state.team_cursor;
    let store = local_store(db);
    while Instant::now() < deadline {
        let page = ctx
            .client
            .list_team_memory_since(
                ctx.project_id(),
                &TeamMemoryListQuery { since: cursor.clone(), limit: Some(25), include_deleted: true, search: None },
            )
            .await?;
        for item in page.items {
            if Instant::now() >= deadline {
                return Ok(());
            }
            if Some(item.organization_id.clone()) != ctx.org_id() || Some(item.workspace_id.clone()) != ctx.workspace_id() {
                bail!("Shared memory scope mismatch");
            }
            // Workspace promotion is unchanged; investigation startup only imports this project's records.
            if item.source_project_id.as_deref() == Some(ctx.project_id()) {
                let existing = store.get(&item.origin_client_id).await?;
                let cached_ok = match &existing {
                    None => true,
                    Some(e) => e.origin == "cloud" && e.sync_scope.as_deref().is_none_or(|s| s.is_empty() || s == ctx.scope),
                };
                if cached_ok {
                    store
                        .upsert_cached(
                            NewMemoryItem {
                                id: item.origin_client_id.clone(),
                                repo: ctx.repo.clone(),
                                kind: item.kind.clone(),
                                claim: item.claim.clone(),
                                scope: item.scope.clone(),
                                source: item.source.clone(),
                                status: Some(if item.deleted_at.as_deref().is_some_and(|d| !d.is_empty()) {
                                    "forgotten".into()
                                } else {
                                    item.status.clone()
                                }),
                                confidence: item.confidence.unwrap_or(0.0),
                                visibility: Some("team".into()),
                                evidence: Some(Value::Array(vec![])),
                                cloud_id: Some(item.id.clone()),
                                org_id: Some(item.organization_id.clone()),
                                workspace_id: Some(item.workspace_id.clone()),
                                sync_scope: Some(ctx.scope.clone()),
                                author_name: item.author_name.clone(),
                                created_at: Some(parse_ts(&date_iso(&item.promoted_at)?)?),
                                ..Default::default()
                            },
                            &system_audit("Automatic team memory refresh"),
                        )
                        .await?;
                }
            }
            cursor = item.seq.clone();
            let (scope, c2) = (ctx.scope.clone(), cursor.clone());
            db.with_conn(move |c| {
                c.execute("UPDATE memory_sync_state SET team_cursor = ?1 WHERE scope = ?2", params![c2, scope])?;
                Ok(())
            })
            .await?;
        }
        if !page.has_more {
            return Ok(());
        }
    }
    Ok(())
}

/// Resolve a restored local report id through its authorized Cloud mapping, never a dangling stub.
pub async fn restore_memory_report(db: &DbHandle, ctx: &MemorySyncContext, local_id: &str) -> Result<Option<Value>> {
    let existing = horus_db::get_investigation(db, local_id).await?;
    let cached: Option<Value> = existing
        .as_ref()
        .filter(|e| e.project.as_deref() == Some(ctx.repo.as_str()))
        .and_then(|e| e.report.as_deref())
        .and_then(|r| serde_json::from_str(r).ok())
        .filter(|v: &Value| !v.is_null());
    let replica_scope: Option<Value> = existing
        .as_ref()
        .and_then(|e| serde_json::from_str::<Value>(&e.incident_input).ok())
        .and_then(|i| i.get("_horusCloudScope").cloned());
    if existing.is_some() && (cached.is_none() || replica_scope.as_ref().is_some_and(|s| s.as_str() != Some(ctx.scope.as_str()))) {
        return Ok(None);
    }
    // Locally authored reports remain authoritative; only imported copies refresh.
    if cached.is_some() && replica_scope.is_none() {
        return Ok(cached);
    }
    let (scope, repo) = (ctx.scope.clone(), ctx.repo.clone());
    let memories = db.with_conn(move |c| items_where(c, "sync_scope = ?1 AND repo = ?2", &[&scope, &repo])).await?;
    let cloud_id = memories.iter().find_map(|item| {
        payload_of(item).get("reportRefs")?.get(local_id)?.as_str().map(str::to_string)
    });
    let Some(cloud_id) = cloud_id else { return Ok(cached) };
    let report = match fetch_investigation_report_from_cloud(&ctx.client, &ctx.config, &cloud_id).await {
        Ok(r) => r,
        Err(e) => {
            if cached.is_some() {
                return Ok(cached);
            }
            return Err(e);
        }
    };
    let Some(report) = report else { return Ok(cached) };
    let hint = report.pointer("/input/hint").and_then(Value::as_str).unwrap_or_default().to_string();
    if hint.is_empty() || !report.get("evidence").is_some_and(Value::is_array) || !report.get("hypotheses").is_some_and(Value::is_array) {
        return Ok(cached);
    }
    let mut restored = report.clone();
    restored["id"] = Value::String(local_id.into());
    let mut input = report.get("input").and_then(Value::as_object).cloned().unwrap_or_default();
    input.insert("repo".into(), Value::String(ctx.repo.clone()));
    restored["input"] = Value::Object(input.clone());
    restored["persisted"] = Value::Bool(true);
    input.insert("_horusCloudScope".into(), Value::String(ctx.scope.clone()));

    let created_at = report.get("createdAt").and_then(Value::as_str).filter(|s| !s.is_empty()).map(date_iso).transpose()?;
    let summary = report.get("summary").and_then(Value::as_str).map(str::to_string);
    let (id, repo, report_json, input_json) = (local_id.to_string(), ctx.repo.clone(), js(&restored)?, js(&input)?);
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        let now = now_ts();
        tx.execute(
            "INSERT INTO investigations (id, title, incident_input, project, created_at, status, summary, report) \
             VALUES (?1, ?2, ?3, ?4, COALESCE(?5, ?6), 'completed', ?7, ?8) \
             ON CONFLICT(id) DO UPDATE SET title = excluded.title, incident_input = excluded.incident_input, \
             report = excluded.report, summary = excluded.summary, updated_at = ?6",
            params![id, hint, input_json, repo, created_at, now, summary, report_json],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await?;
    if existing.is_none() {
        if let Ok(typed) = migrate_report(restored.clone()) {
            store_incident_memory(&SqliteMemoryStorage::new(db.clone()), Some(local_id), &typed).await;
        }
    }
    let feedback: Vec<Value> = memories
        .iter()
        .flat_map(|item| payload_of(item).get("accuracyFeedback").and_then(Value::as_array).cloned().unwrap_or_default())
        .filter(|l| l.get("investigationId").and_then(Value::as_str) == Some(local_id))
        .collect();
    for label in feedback {
        let (repo, id) = (ctx.repo.clone(), local_id.to_string());
        db.with_conn(move |c| {
            let tx = c.unchecked_transaction()?;
            set_sync_pull(&tx, true)?;
            insert_feedback_label(&tx, &label, &repo, Some(&id))?;
            set_sync_pull(&tx, false)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    }
    Ok(Some(restored))
}

/// Rebuild missing rich entries from saved reports, preserving original dates and inferred findings.
async fn backfill(db: &DbHandle, ctx: &MemorySyncContext, deadline: Instant) -> Result<()> {
    let store = local_store(db);
    let (reports, _) = report_history(db, &ctx.repo).await?;
    let repo = ctx.repo.clone();
    let (memories, links) = db.with_conn(move |c| Ok((items_where(c, "repo = ?1", &[&repo])?, all_links(c)?))).await?;
    let covered = covered_reports(&memories, &links);
    for (id, eligible) in reports {
        if Instant::now() >= deadline {
            break;
        }
        if !eligible || covered.contains(&id) {
            continue;
        }
        let Some(row) = horus_db::get_investigation(db, &id).await? else { continue };
        if row.project.as_deref() != Some(ctx.repo.as_str()) {
            continue;
        }
        let Some(mut report) = row.report.as_deref().and_then(|r| serde_json::from_str::<Value>(r).ok()) else { continue };
        if !can_backfill(&report) {
            continue;
        }
        if let Some(input) = report.get_mut("input").and_then(Value::as_object_mut) {
            input.insert("repo".into(), Value::String(ctx.repo.clone()));
        }
        let typed = migrate_report(report)?;
        let item = create_investigation_memory(
            &store,
            Some(&row.id),
            &typed,
            &system_audit("Imported from saved investigation; outcome unconfirmed"),
        )
        .await?;
        if let Some(item) = item {
            let created = format_ts(&row.created_at);
            db.with_conn(move |c| {
                c.execute("UPDATE memory_item SET created_at = ?1 WHERE id = ?2", params![created, item.id])?;
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct MemorySyncOptions {
    pub limit: Option<usize>,
    pub pull_only: bool,
    /// Default true.
    pub backfill: Option<bool>,
    pub deadline: Option<Instant>,
    pub resolve: Option<String>,
    /// `local` | `cloud`.
    pub choice: Option<String>,
    pub restore: Option<String>,
    pub startup: bool,
}

async fn resolve_conflict(db: &DbHandle, ctx: &MemorySyncContext, id: &str, choice: &str) -> Result<()> {
    let op = outbox_where(db, "scope = ?1 AND memory_id = ?2", ctx.scope.clone(), Some(id.into())).await?.into_iter().next();
    let Some(op) = op.filter(|o| o.conflict.is_some()) else { bail!("No unresolved conflict for this memory") };
    let mut cursor = "0".to_string();
    let remote = loop {
        let page = ctx
            .client
            .list_memory_items(
                ctx.project_id(),
                &MemoryListQuery { after_revision: Some(cursor.clone()), include_history: Some(false), limit: Some(100), ..Default::default() },
            )
            .await?;
        let found = page.items.into_iter().find(|i| i.client_id == id);
        if found.is_some() || page.has_more != Some(true) || page.next_revision.is_none() {
            break found;
        }
        cursor = page.next_revision.unwrap_or_default();
    };
    let Some(remote) = remote.filter(|r| r.revision.as_deref().is_some_and(|r| !r.is_empty())) else {
        bail!("Cannot resolve a conflict without the current server revision");
    };
    let id_s = id.to_string();
    let local = db.with_conn(move |c| items_where(c, "id = ?1", &[&id_s])).await?.into_iter().next();
    let Some(local) = local.filter(|l| l.sync_scope.as_deref() == Some(ctx.scope.as_str())) else { bail!("Memory scope mismatch") };
    if choice == "local" && remote.status == "forgotten" && local.status != "forgotten" {
        bail!("Remote memory was forgotten; accept Cloud and use --restore explicitly");
    }
    let revision = remote.revision.clone().unwrap_or_default();
    let cloud_choice = if choice == "cloud" {
        Some(hydrate_memory_history(db, ctx, remote, Instant::now() + Duration::from_millis(15_000)).await?)
    } else {
        None
    };
    let (op_id, scope, id_s) = (op.id.clone(), ctx.scope.clone(), id.to_string());
    let generation = if choice == "cloud" { local.sync_generation } else { 0 };
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        tx.execute("DELETE FROM memory_sync_outbox WHERE id = ?1", params![op_id])?;
        tx.execute(
            "UPDATE memory_sync_replica SET revision = ?1, generation = ?2 WHERE scope = ?3 AND memory_id = ?4",
            params![revision, generation, scope, id_s],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await?;
    if let Some(cc) = cloud_choice {
        apply_remote(db, ctx, cc, false).await?;
    }
    let (id_s, user, op_id) = (id.to_string(), ctx.user_id.clone(), op.id.clone());
    let choice = choice.to_string();
    db.with_conn(move |c| {
        c.execute(
            "INSERT INTO memory_audit (id, memory_id, action, actor, note) VALUES (?1, ?2, 'resolve-conflict', ?3, ?4)",
            params![
                uuid::Uuid::new_v4().to_string(),
                id_s,
                js(&serde_json::json!({ "kind": "user", "id": user }))?,
                format!("Explicitly selected {choice} after operation {op_id}; rejected correction retained in Cloud operation history"),
            ],
        )?;
        Ok(())
    })
    .await
}

fn sync_error_message(e: &anyhow::Error) -> String {
    if super::api::cloud_status(e) == Some(401) {
        "Sign-in required: run horus login".into()
    } else {
        redact_error_message(e)
    }
}

/// Pull first, then freeze each dirty snapshot before sending it. Retry preserves the exact operation.
pub async fn synchronize_memory(db: &DbHandle, ctx: &MemorySyncContext, opts: &MemorySyncOptions) -> Result<MemorySyncStatus> {
    let deadline = opts.deadline.unwrap_or_else(|| Instant::now() + Duration::from_millis(15_000));
    let (scope, repo) = (ctx.scope.clone(), ctx.repo.clone());
    db.with_conn(move |c| {
        c.execute("INSERT INTO memory_sync_state (scope, repo) VALUES (?1, ?2) ON CONFLICT DO NOTHING", params![scope, repo])?;
        Ok(())
    })
    .await?;
    if let Err(error) = synchronize_inner(db, ctx, opts, deadline).await {
        let message = sync_error_message(&error);
        let scope = ctx.scope.clone();
        db.with_conn(move |c| {
            c.execute("UPDATE memory_sync_state SET error = ?1 WHERE scope = ?2", params![message, scope])?;
            Ok(())
        })
        .await?;
    }
    status(db, ctx).await
}

/// `Some(Status)` when the pull-only path returns early.
async fn synchronize_inner(db: &DbHandle, ctx: &MemorySyncContext, opts: &MemorySyncOptions, deadline: Instant) -> Result<()> {
    let mut cursor = read_state(db, &ctx.scope).await?.map(|s| s.cursor).unwrap_or_else(|| "0".into());
    while Instant::now() < deadline {
        let page = ctx
            .client
            .list_memory_items(
                ctx.project_id(),
                &MemoryListQuery { after_revision: Some(cursor.clone()), include_history: Some(false), limit: Some(25), ..Default::default() },
            )
            .await?;
        if page.next_revision.is_none() {
            bail!("Cloud does not support durable memory sync; upgrade Cloud first");
        }
        let mut applied = cursor.clone();
        let mut failed = None;
        for row in page.items {
            if Instant::now() >= deadline {
                break;
            }
            let rev = row.revision.clone().unwrap_or_default();
            let step = async {
                let hydrated = hydrate_memory_history(db, ctx, row, deadline).await?;
                apply_remote(db, ctx, hydrated, true).await
            };
            if let Err(e) = step.await {
                failed = Some(e);
                break;
            }
            applied = rev;
        }
        // TS only advances the cursor after the whole page, so a bounded pull (1.8s at startup)
        // that times out mid-page re-fetches the same page forever on a store that is far behind.
        // Persist the rows already applied before surfacing the error (DIVERGENCES.md).
        let (scope, a) = (ctx.scope.clone(), applied.clone());
        db.with_conn(move |c| {
            c.execute(
                "UPDATE memory_sync_state SET cursor = ?1, last_pull = ?2, error = NULL WHERE scope = ?3",
                params![a, now_ts(), scope],
            )?;
            Ok(())
        })
        .await?;
        if let Some(e) = failed {
            return Err(e);
        }
        if page.has_more != Some(true) {
            break;
        }
        cursor = applied;
    }
    pull_team_memory(db, ctx, deadline).await?;
    if opts.pull_only {
        return Ok(());
    }
    if let Some(id) = &opts.resolve {
        let Some(choice) = &opts.choice else { bail!("--resolve requires --choice local|cloud") };
        resolve_conflict(db, ctx, id, choice).await?;
    }
    if let Some(id) = &opts.restore {
        let store = local_store(db);
        let local = store.get(id).await?;
        if !local.is_some_and(|l| l.sync_scope.as_deref() == Some(ctx.scope.as_str()) && l.status == "forgotten") {
            bail!("Restore requires a forgotten memory in this Cloud scope");
        }
        store
            .set_status(
                id,
                MemoryStatus::Fresh,
                &AuditCtx { actor: AuditActor { kind: AuditActorKind::User, id: Some(ctx.user_id.clone()), name: None }, note: Some("Explicit restore".into()) },
            )
            .await?;
    }
    if opts.backfill != Some(false) && Instant::now() < deadline {
        backfill(db, ctx, deadline).await?;
    }
    push(db, ctx, opts, deadline).await
}

async fn push(db: &DbHandle, ctx: &MemorySyncContext, opts: &MemorySyncOptions, deadline: Instant) -> Result<()> {
    let (scope, repo) = (ctx.scope.clone(), ctx.repo.clone());
    let rows = db
        .with_conn(move |c| {
            items_where(
                c,
                "repo = ?1 AND origin = 'local' AND (sync_scope = ?2 OR sync_scope IS NULL) AND NOT EXISTS \
                 (SELECT 1 FROM memory_sync_replica r WHERE r.scope = ?2 AND r.memory_id = memory_item.id \
                 AND r.generation = memory_item.sync_generation)",
                &[&repo, &scope],
            )
        })
        .await?;
    let take = opts.limit.unwrap_or(rows.len());
    for item in rows.into_iter().take(take) {
        if Instant::now() >= deadline {
            break;
        }
        let payload = payload_of(&item);
        if let Some(refs) = payload.get("reportRefs").and_then(Value::as_object) {
            for id in refs.keys() {
                if Instant::now() >= deadline {
                    break;
                }
                restore_memory_report(db, ctx, id).await?;
            }
        }
        let mut op = outbox_where(db, "scope = ?1 AND memory_id = ?2", ctx.scope.clone(), Some(item.id.clone())).await?.into_iter().next();
        if op.is_none() {
            let rep = replica(db, &ctx.scope, &item.id).await?;
            if rep.as_ref().map(|r| r.1) == Some(item.sync_generation) {
                continue;
            }
            op = Some(freeze_operation(db, ctx, opts, &item, rep.map(|r| r.0)).await?);
        }
        let Some(op) = op else { continue };
        let next_at = parse_ts(&op.next_attempt_at).map(|t| t.timestamp_millis()).unwrap_or(0);
        if op.conflict.is_some() || next_at > Utc::now().timestamp_millis() {
            continue;
        }
        if let Err(error) = send_operation(db, ctx, &item, &op, deadline).await {
            let message = sync_error_message(&error);
            let backoff = 60_000i64.min(1000 * 2i64.pow(op.attempts.clamp(0, 6) as u32));
            let next = format_ts(&(Utc::now() + chrono::Duration::milliseconds(backoff)));
            let (id, m2) = (op.id.clone(), message.clone());
            db.with_conn(move |c| {
                c.execute(
                    "UPDATE memory_sync_outbox SET attempts = attempts + 1, error = ?1, next_attempt_at = ?2 WHERE id = ?3",
                    params![m2, next, id],
                )?;
                Ok(())
            })
            .await?;
            bail!("{message}");
        }
    }
    Ok(())
}

/// Upload referenced reports, then freeze the redacted sync request into the outbox.
async fn freeze_operation(
    db: &DbHandle,
    ctx: &MemorySyncContext,
    opts: &MemorySyncOptions,
    item: &MemoryItem,
    replica_revision: Option<String>,
) -> Result<OutboxRow> {
    let forgotten = item.status == "forgotten";
    let mut record = if forgotten { Map::new() } else { memory_record(item) };
    let mut report_refs: Map<String, Value> = record.get("reportRefs").and_then(Value::as_object).cloned().unwrap_or_default();
    let item_id = item.id.clone();
    let links = db
        .with_conn(move |c| {
            query(
                c,
                "SELECT id, from_memory_id, rel, to_kind, to_ref, to_file_path, created_at FROM memory_link WHERE from_memory_id = ?1",
                &[&item_id],
                row_link,
            )
        })
        .await?;
    // Upload references before publishing memory; retries use existing stable report keys.
    for link in links.iter().filter(|l| l.to_kind == "incident" && !forgotten) {
        if report_refs.contains_key(&link.to_ref) {
            continue;
        }
        let Some(saved) = horus_db::get_investigation(db, &link.to_ref).await? else { continue };
        let Some(report) = saved.report.as_deref().filter(|_| saved.project.as_deref() == Some(ctx.repo.as_str())) else { continue };
        let mut report: Value = serde_json::from_str(report)?;
        if let Some(o) = report.as_object_mut() {
            o.insert("createdAt".into(), Value::String(iso(&saved.created_at)));
        }
        let result = upload_investigation_to_cloud(&ctx.client, &ctx.config, &report, UploadOpts { db: Some(db), ..Default::default() }).await?;
        report_refs.insert(link.to_ref.clone(), Value::String(result.investigation_id));
        // A recurring memory can link many reports; retain each completed upload across deadlines.
        let mut new_payload = payload_of(item);
        new_payload.insert("reportRefs".into(), Value::Object(report_refs.clone()));
        let (pj, scope, org, ws, user, id) =
            (js(&new_payload)?, ctx.scope.clone(), ctx.org_id(), ctx.workspace_id(), ctx.user_id.clone(), item.id.clone());
        db.with_conn(move |c| {
            let tx = c.unchecked_transaction()?;
            set_sync_pull(&tx, true)?;
            tx.execute(
                "UPDATE memory_item SET payload = ?1, sync_scope = ?2, org_id = ?3, workspace_id = ?4, user_id = ?5 WHERE id = ?6",
                params![pj, scope, org, ws, user, id],
            )?;
            set_sync_pull(&tx, false)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    }
    record.insert("reportRefs".into(), Value::Object(report_refs));
    let report_ids: Vec<String> = links.iter().filter(|l| l.to_kind == "incident" && !forgotten).map(|l| l.to_ref.clone()).collect();
    let labels = if report_ids.is_empty() {
        vec![]
    } else {
        let ids = report_ids.clone();
        db.with_conn(move |c| {
            let sql = format!(
                "SELECT id, investigation_id, resolved, source, at, confirmed_cause, note FROM outcome_label WHERE investigation_id IN ({})",
                (1..=ids.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(",")
            );
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(ids), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?
    };
    let feedback: Vec<Value> = labels
        .into_iter()
        .map(|(id, investigation_id, resolved, source, at, confirmed_cause, note)| {
            serde_json::json!({
                "id": id, "investigationId": investigation_id, "resolved": resolved, "source": source,
                "at": parse_ts(&at).map(|t| iso(&t)).unwrap_or(at), "confirmedCause": confirmed_cause, "note": note,
            })
        })
        .collect();
    record.insert("accuracyFeedback".into(), Value::Array(feedback));
    let item_id = item.id.clone();
    let audit = db
        .with_conn(move |c| {
            query(
                c,
                "SELECT id, memory_id, action, actor, from_status, to_status, note, detail, at FROM memory_audit WHERE memory_id = ?1",
                &[&item_id],
                row_audit,
            )
        })
        .await?;
    let id = uuid::Uuid::new_v4().to_string();
    let mut operation = serde_json::json!({ "id": id, "baseRevision": replica_revision.unwrap_or_else(|| "0".into()) });
    if opts.restore.as_deref() == Some(item.id.as_str()) {
        operation["restore"] = Value::Bool(true);
    }
    let mut sync_item = horus_core::json::to_js_value(&to_sync_input(item)?)?;
    sync_item["evidence"] = record.get("evidence").cloned().unwrap_or(Value::Null);
    if forgotten {
        sync_item["claim"] = Value::String("[Forgotten memory]".into());
        sync_item["evidence"] = Value::Array(vec![]);
    }
    sync_item["record"] = Value::Object(record);
    let audit_rows: Vec<&MemoryAudit> = if forgotten {
        audit.iter().filter(|a| a.action == "forget").last().into_iter().collect()
    } else {
        audit.iter().collect()
    };
    let request = serde_json::json!({
        "operation": operation,
        "items": [sync_item],
        "links": if forgotten { vec![] } else { links.iter().map(to_link_sync_input).collect::<Result<Vec<_>>>()? },
        "audit": audit_rows.into_iter().map(to_audit_sync_input).collect::<Vec<_>>(),
    });
    let request_json = js(&redact_cloud_value(&request))?;
    let (scope, org, ws, user, item_id, generation, id2) =
        (ctx.scope.clone(), ctx.org_id(), ctx.workspace_id(), ctx.user_id.clone(), item.id.clone(), item.sync_generation, id.clone());
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        set_sync_pull(&tx, true)?;
        tx.execute(
            "UPDATE memory_item SET sync_scope = ?1, org_id = ?2, workspace_id = ?3, user_id = ?4 WHERE id = ?5",
            params![scope, org, ws, user, item_id],
        )?;
        tx.execute(
            "INSERT INTO memory_sync_outbox (id, scope, memory_id, generation, request) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id2, scope, item_id, generation, request_json],
        )?;
        set_sync_pull(&tx, false)?;
        tx.commit()?;
        Ok(())
    })
    .await?;
    outbox_where(db, "id = ?1", id, None).await?.into_iter().next().ok_or_else(|| anyhow!("outbox row vanished"))
}

/// Send one frozen operation (page by page); acknowledge the generation on a final receipt.
async fn send_operation(db: &DbHandle, ctx: &MemorySyncContext, item: &MemoryItem, op: &OutboxRow, deadline: Instant) -> Result<()> {
    // Derive the same page IDs/content on every retry. A final receipt is the only ack of generation.
    let mut snapshot = op.request.clone();
    let history_next_page = snapshot
        .as_object_mut()
        .and_then(|o| o.shift_remove("historyNextPage"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let pages = memory_history_pages(&snapshot)?;
    let mut result = None;
    for (i, page) in pages.iter().enumerate().skip(history_next_page) {
        if Instant::now() >= deadline {
            break;
        }
        let r = ctx.client.sync_memory_items(ctx.project_id(), page).await.map_err(anyhow::Error::from)?;
        if r.conflict.is_some() {
            result = Some(r);
            break;
        }
        let history = page.get("history");
        let page_no = history.and_then(|h| h.get("page")).and_then(Value::as_u64);
        let pages_n = history.and_then(|h| h.get("pages")).and_then(Value::as_u64);
        let page_op = page.pointer("/operation/id").and_then(Value::as_str);
        if let (Some(p), Some(n)) = (page_no, pages_n) {
            if p + 1 < n && (r.operation_id.as_deref() != page_op || r.staged != Some(true)) {
                bail!("Cloud does not support bounded memory history; upgrade Cloud before retrying");
            }
        }
        if r.staged == Some(true) {
            let mut staged = snapshot.clone();
            staged["historyNextPage"] = serde_json::json!(i + 1);
            let (json, id) = (js(&staged)?, op.id.clone());
            db.with_conn(move |c| {
                c.execute("UPDATE memory_sync_outbox SET request = ?1 WHERE id = ?2", params![json, id])?;
                Ok(())
            })
            .await?;
        }
        result = Some(r);
    }
    let Some(result) = result.filter(|r| r.staged != Some(true)) else { return Ok(()) };
    if let Some(conflict) = &result.conflict {
        let (cj, reason, id) = (js(conflict)?, conflict.reason.clone(), op.id.clone());
        db.with_conn(move |c| {
            c.execute("UPDATE memory_sync_outbox SET conflict = ?1, error = ?2 WHERE id = ?3", params![cj, reason, id])?;
            Ok(())
        })
        .await?;
        return Ok(());
    }
    let Some(revision) = result.revision.clone().filter(|r| !r.is_empty() && result.operation_id.as_deref() == Some(op.id.as_str()))
    else {
        bail!("Cloud did not acknowledge the durable operation");
    };
    let (scope, memory_id, generation, op_id) = (ctx.scope.clone(), item.id.clone(), op.generation, op.id.clone());
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO memory_sync_replica (scope, memory_id, revision, generation) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(scope, memory_id) DO UPDATE SET revision = excluded.revision, generation = excluded.generation",
            params![scope, memory_id, revision, generation],
        )?;
        tx.execute("DELETE FROM memory_sync_outbox WHERE id = ?1", params![op_id])?;
        tx.execute("UPDATE memory_sync_state SET last_push = ?1, error = NULL WHERE scope = ?2", params![now_ts(), scope])?;
        tx.commit()?;
        Ok(())
    })
    .await
}

/// Sync the repo's linked memory within a bounded budget (1.8s at startup — pull only — else 15s).
pub async fn sync_linked_memory(db: &DbHandle, root: &Path, repo: &str, opts: MemorySyncOptions) -> Result<MemorySyncStatus> {
    let budget = Duration::from_millis(if opts.startup { 1800 } else { 15_000 });
    let deadline = Instant::now() + budget;
    let Some(ctx) = memory_sync_context(root, repo, Some(deadline)) else {
        let linked = read_cloud_config(root).is_some_and(|c| c.context == "cloud");
        return Ok(MemorySyncStatus::bare(if linked { "Sign-in required" } else { "Local only" }));
    };
    let pull_only = opts.startup;
    synchronize_memory(db, &ctx, &MemorySyncOptions { pull_only, deadline: Some(deadline), ..opts }).await
}

