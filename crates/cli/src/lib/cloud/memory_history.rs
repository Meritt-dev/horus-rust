//! Bounded pages of one frozen snapshot; Cloud publishes only the final page. Port of
//! `packages/cli/src/lib/cloud/memory-history.ts`.

use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use horus_db::DbHandle;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::api::{MemoryAuditSyncInput, MemoryHistoryQuery, MemoryItemRecord, MemoryLinkRecord};
use super::memory_sync::MemorySyncContext;

const ROWS: usize = 500;
const BYTES: usize = 1024 * 1024;

fn byte_len(v: &Value) -> usize {
    horus_core::json::to_js_json(v).map(|s| s.len()).unwrap_or(usize::MAX)
}

fn rec_mut(target: &mut Value) -> &mut Map<String, Value> {
    if !target["items"][0]["record"].is_object() {
        target["items"][0]["record"] = Value::Object(Map::new());
    }
    target["items"][0]["record"].as_object_mut().expect("record object")
}

fn arr_len(v: Option<&Value>) -> usize {
    v.and_then(Value::as_array).map_or(0, Vec::len)
}

/// Split one sync request into bounded history pages. A previously valid request is kept
/// byte-for-byte (its operation may already have a receipt whose response was lost); only
/// oversized snapshots split.
pub fn memory_history_pages(request: &Value) -> Result<Vec<Value>> {
    let item = request.get("items").and_then(|i| i.get(0));
    let (Some(item), Some(operation)) = (item, request.get("operation")) else {
        bail!("History requires one revisioned memory");
    };
    let mut record: Map<String, Value> = item.get("record").and_then(Value::as_object).cloned().unwrap_or_default();
    let report_refs = record.shift_remove("reportRefs").unwrap_or_else(|| Value::Object(Map::new()));
    let accuracy = record.shift_remove("accuracyFeedback").unwrap_or_else(|| Value::Array(vec![]));
    let evidence = record.shift_remove("evidence").unwrap_or_else(|| Value::Array(vec![]));

    if arr_len(request.get("links")) <= 2000
        && arr_len(request.get("audit")) <= 2000
        && arr_len(Some(&accuracy)) <= 2000
        && arr_len(Some(&evidence)) <= 2000
        && byte_len(request) <= 6 * 1024 * 1024
    {
        return Ok(vec![request.clone()]);
    }

    let mut base = request.clone();
    {
        let mut base_item = item.as_object().cloned().unwrap_or_default();
        base_item.shift_remove("evidence"); // `evidence: undefined` drops the key
        base_item.insert("record".into(), Value::Object(record));
        base["items"] = Value::Array(vec![Value::Object(base_item)]);
        base["links"] = Value::Array(vec![]);
        base["audit"] = Value::Array(vec![]);
    }

    let append = |target: &mut Value, field: &str, value: &Value| match field {
        "links" | "audit" => target[field].as_array_mut().expect("array").push(value.clone()),
        "reportRefs" => {
            let (k, r) = (value[0].as_str().unwrap_or_default().to_string(), value[1].clone());
            let rec = rec_mut(target);
            rec.entry("reportRefs").or_insert_with(|| Value::Object(Map::new())).as_object_mut().map(|m| m.insert(k, r));
        }
        _ => {
            let rec = rec_mut(target);
            if let Some(a) = rec.entry(field).or_insert_with(|| Value::Array(vec![])).as_array_mut() {
                a.push(value.clone());
            }
        }
    };
    let count = |target: &Value, field: &str| -> usize {
        match field {
            "links" | "audit" => arr_len(target.get(field)),
            "reportRefs" => target["items"][0]["record"]["reportRefs"].as_object().map_or(0, Map::len),
            _ => arr_len(target["items"][0]["record"].get(field)),
        }
    };

    let mut pages: Vec<Value> = Vec::new();
    let mut page = base.clone();
    let mut add = |field: &str, values: Vec<Value>| -> Result<()> {
        for value in values {
            let mut candidate = page.clone();
            append(&mut candidate, field, &value);
            if count(&candidate, field) > ROWS || byte_len(&candidate) > BYTES {
                pages.push(std::mem::replace(&mut page, base.clone()));
                append(&mut page, field, &value);
                if byte_len(&page) > BYTES {
                    bail!("Memory field exceeds bounded sync page size");
                }
            } else {
                page = candidate;
            }
        }
        Ok(())
    };
    let list = |v: Option<&Value>| v.and_then(Value::as_array).cloned().unwrap_or_default();
    add("links", list(request.get("links")))?;
    add("audit", list(request.get("audit")))?;
    let refs: Vec<Value> = report_refs
        .as_object()
        .map(|m| m.iter().map(|(k, v)| Value::Array(vec![Value::String(k.clone()), v.clone()])).collect())
        .unwrap_or_default();
    add("reportRefs", refs)?;
    add("accuracyFeedback", list(Some(&accuracy)))?;
    add("evidence", list(Some(&evidence)))?;
    pages.push(page);

    if pages.len() == 1 {
        return Ok(vec![request.clone()]); // Retain the existing wire contract for small records.
    }
    if pages.len() > 4096 {
        bail!("Memory history exceeds 4096 sync pages");
    }
    let op_id = operation.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
    let base_rev = operation.get("baseRevision").and_then(Value::as_str).unwrap_or_default().to_string();
    let n = pages.len();
    Ok(pages
        .into_iter()
        .enumerate()
        .map(|(i, mut body)| {
            let mut op = operation.as_object().cloned().unwrap_or_default();
            op.insert("baseRevision".into(), Value::String(format!("history:{base_rev}")));
            op.insert("id".into(), Value::String(if i == n - 1 { op_id.clone() } else { format!("{op_id}/history/{i}") }));
            body["operation"] = Value::Object(op);
            body["history"] = serde_json::json!({ "operationId": op_id, "page": i, "pages": n });
            body
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullProgress {
    memory_id: String,
    revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit_cursor: Option<String>,
    link_page: i64,
    audit_page: i64,
    links_done: bool,
    audit_done: bool,
}

async fn reset_pages(db: &DbHandle, scope: &str, progress: Option<String>) -> Result<()> {
    let scope = scope.to_string();
    db.with_conn(move |c| {
        let tx = c.unchecked_transaction()?;
        tx.execute("DELETE FROM memory_sync_pull_page WHERE scope = ?1", params![scope])?;
        tx.execute("UPDATE memory_sync_state SET pull_progress = ?1 WHERE scope = ?2", params![progress, scope])?;
        tx.commit()?;
        Ok(())
    })
    .await
}

/// Download a history-paged record's links/audit page by page. Every downloaded page and its
/// cursor commit together, so a deadline never discards progress.
pub async fn hydrate_memory_history(
    db: &DbHandle,
    ctx: &MemorySyncContext,
    row: MemoryItemRecord,
    deadline: Instant,
) -> Result<MemoryItemRecord> {
    if row.history_paged != Some(true) {
        return Ok(row);
    }
    let revision = row.revision.clone().ok_or_else(|| anyhow!("Cloud memory scope or revision mismatch"))?;
    let scope = ctx.scope.clone();
    let saved: Option<PullProgress> = {
        let scope = scope.clone();
        db.with_conn(move |c| {
            let raw: Option<Option<String>> = c
                .query_row("SELECT pull_progress FROM memory_sync_state WHERE scope = ?1", params![scope], |r| r.get(0))
                .optional()?;
            Ok(raw.flatten().and_then(|s| serde_json::from_str(&s).ok()))
        })
        .await?
    };
    let mut progress = match saved {
        Some(p) if p.memory_id == row.id && p.revision == revision => p,
        _ => {
            let fresh = PullProgress {
                memory_id: row.id.clone(),
                revision: revision.clone(),
                link_cursor: None,
                audit_cursor: None,
                link_page: 0,
                audit_page: 0,
                links_done: false,
                audit_done: false,
            };
            reset_pages(db, &scope, Some(horus_core::json::to_js_json(&fresh)?)).await?;
            fresh
        }
    };
    let project_id = ctx.config.project.as_ref().map(|p| p.id.clone()).unwrap_or_default();

    let result: Result<()> = async {
        for stream in ["links", "audit"] {
            loop {
                let done = if stream == "links" { progress.links_done } else { progress.audit_done };
                if done {
                    break;
                }
                if Instant::now() >= deadline {
                    bail!("Memory history pull paused; resume from saved page");
                }
                let cursor = if stream == "links" { progress.link_cursor.clone() } else { progress.audit_cursor.clone() };
                let query = MemoryHistoryQuery { memory_item_id: row.id.clone(), expected_revision: revision.clone(), cursor };
                let (rows, next_cursor) = if stream == "links" {
                    let p = ctx.client.list_memory_links(&project_id, &query).await?;
                    (p.links, p.next_cursor)
                } else {
                    let p = ctx.client.list_memory_audit(&project_id, &query).await?;
                    (p.audit, p.next_cursor)
                };
                let mut next = progress.clone();
                let page_no;
                if stream == "links" {
                    page_no = progress.link_page;
                    next.links_done = next_cursor.is_none();
                    next.link_cursor = next_cursor;
                    next.link_page += 1;
                } else {
                    page_no = progress.audit_page;
                    next.audit_done = next_cursor.is_none();
                    next.audit_cursor = next_cursor;
                    next.audit_page += 1;
                }
                let (scope, memory_id, rev) = (scope.clone(), row.id.clone(), revision.clone());
                let rows_json = horus_core::json::to_js_json(&rows)?;
                let next_json = horus_core::json::to_js_json(&next)?;
                db.with_conn(move |c| {
                    let tx = c.unchecked_transaction()?;
                    tx.execute(
                        "INSERT INTO memory_sync_pull_page (scope, memory_id, revision, stream, page, rows) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![scope, memory_id, rev, stream, page_no, rows_json],
                    )?;
                    tx.execute("UPDATE memory_sync_state SET pull_progress = ?1 WHERE scope = ?2", params![next_json, scope])?;
                    tx.commit()?;
                    Ok(())
                })
                .await?;
                progress = next;
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        if super::api::cloud_status(&e) == Some(409) {
            reset_pages(db, &scope, None).await?;
        }
        return Err(e);
    }

    let (scope2, memory_id, rev) = (scope.clone(), row.id.clone(), revision.clone());
    let pages: Vec<(String, String)> = db
        .with_conn(move |c| {
            let mut stmt = c.prepare(
                "SELECT stream, rows FROM memory_sync_pull_page WHERE scope = ?1 AND memory_id = ?2 AND revision = ?3 ORDER BY page ASC",
            )?;
            let rows = stmt.query_map(params![scope2, memory_id, rev], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await?;
    let flat = |stream: &str| -> Vec<Value> {
        pages
            .iter()
            .filter(|(s, _)| s == stream)
            .flat_map(|(_, rows)| serde_json::from_str::<Vec<Value>>(rows).unwrap_or_default())
            .collect()
    };
    let links: Vec<MemoryLinkRecord> = flat("links").into_iter().filter_map(|v| serde_json::from_value(v).ok()).collect();
    let audit: Vec<MemoryAuditSyncInput> = flat("audit").into_iter().filter_map(|v| serde_json::from_value(v).ok()).collect();
    Ok(MemoryItemRecord { links: Some(links), audit: Some(audit), ..row })
}
