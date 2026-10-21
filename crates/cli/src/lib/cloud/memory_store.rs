//! Port of `packages/cli/src/lib/cloud/memory-store.ts` — PARTIAL: the three wire mappers
//! (`to_sync_input`, `to_link_sync_input`, `to_audit_sync_input`) that `memory_sync` uses.
//! `createCloudMemoryStore` / `dualWriteMemoryStore` have no non-test caller in the TS CLI and
//! are not ported (see DIVERGENCES.md).
//!
//! PRIVACY CHOKE POINT: the mappers are positive allowlists — `payload` (where an embedding could
//! hide) never reaches the wire, and confirmed-outcome is clamped to `private`.

use anyhow::{bail, Result};
use horus_engine::memory_store::{MemoryAudit, MemoryItem, MemoryLink};
use serde_json::{Map, Value};

use super::api::{MemoryAuditSyncInput, MemoryItemSyncInput, MemoryLinkSyncInput};

/// confirmed-outcome can never be 'team' (spec §5.2) — clamp before anything leaves the device.
fn clamp_visibility(kind: &str, source: &str, v: &str) -> String {
    if kind == "confirmed-outcome" || source == "confirmed-outcome" {
        return "private".into();
    }
    if v.is_empty() { "private".into() } else { v.into() }
}

fn iso(d: &chrono::DateTime<chrono::Utc>) -> String {
    d.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Map a CLI memory item → the cloud sync wire shape (no `payload`, ever).
pub fn to_sync_input(item: &MemoryItem) -> Result<MemoryItemSyncInput> {
    let client_id = item.id.trim().to_string();
    if client_id.is_empty() {
        bail!("cloud memory sync requires a client item id");
    }
    Ok(MemoryItemSyncInput {
        record: None,
        client_id,
        kind: Some(item.kind.clone()),
        claim: Some(item.claim.clone()),
        scope: Some(item.scope.clone()),
        source: Some(item.source.clone()),
        status: Some(if item.status.is_empty() { "fresh".into() } else { item.status.clone() }),
        confidence: Some(item.confidence),
        visibility: Some(clamp_visibility(&item.kind, &item.source, &item.visibility)),
        evidence: Some(item.evidence.clone()),
        last_verified_at: Some(item.last_verified_at.as_ref().map(iso)),
        last_verified_hash: Some(item.last_verified_hash.clone()),
        client_created_at: Some(Some(iso(&item.created_at))),
    })
}

/// Map a CLI link → the cloud link wire shape. A blank id is rejected (cannot dedupe on re-sync).
pub fn to_link_sync_input(link: &MemoryLink) -> Result<MemoryLinkSyncInput> {
    let idempotency_key = link.id.trim().to_string();
    if idempotency_key.is_empty() {
        bail!("cloud memory sync requires a client link id");
    }
    Ok(MemoryLinkSyncInput {
        idempotency_key,
        from_client_id: link.from_memory_id.clone(),
        rel: link.rel.clone(),
        to_kind: link.to_kind.clone(),
        to_ref: link.to_ref.clone(),
        // The cloud schema omits (not nulls) an absent file path.
        to_file_path: link.to_file_path.clone().filter(|p| !p.is_empty()),
    })
}

fn pick(obj: Option<&Value>, keys: &[&str]) -> Map<String, Value> {
    obj.and_then(Value::as_object)
        .map(|o| o.iter().filter(|(k, _)| keys.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

/// Map a CLI audit row → the cloud audit wire shape; optional fields omitted when absent (the
/// cloud zod `.optional()` rejects null). `at` is coerced to RFC3339.
pub fn to_audit_sync_input(row: &MemoryAudit) -> MemoryAuditSyncInput {
    let some = |s: &Option<String>| s.clone().filter(|s| !s.is_empty());
    MemoryAuditSyncInput {
        detail: row.detail.as_ref().filter(|d| !d.is_null()).map(|d| {
            pick(Some(d), &["detection", "rel", "toKind", "toRef", "recurrenceCount", "investigationId"])
        }),
        client_audit_id: row.id.clone(),
        memory_client_id: row.memory_id.clone(),
        action: row.action.clone(),
        actor: pick(Some(&row.actor), &["kind", "id", "name"]),
        from_status: some(&row.from_status),
        to_status: some(&row.to_status),
        note: some(&row.note),
        at: iso(&row.at),
    }
}
