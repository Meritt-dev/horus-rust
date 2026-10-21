//! Telemetry transport (HOR-324 Phase 1b): drain the local spool to the cloud ingest endpoint.
//! Port of `packages/cli/src/lib/telemetry/transport.ts`. Best-effort + time-boxed; the spool is
//! cleared only after every batch is accepted. Anonymous: posts to public `POST /v1/telemetry`.

use std::time::Duration;

use serde_json::{json, Value};

use super::consent::resolve_consent;
use super::spool::{clear_spool, read_spooled_events};
use crate::lib::cloud::api::DEFAULT_API_BASE_URL;
use crate::lib::cloud::auth_store::read_auth;

const CHUNK: usize = 100;
const DEFAULT_TIMEOUT_MS: u64 = 1500;

/// Where to send telemetry: explicit override → logged-in base → default.
pub fn telemetry_base_url() -> String {
    std::env::var("HORUS_TELEMETRY_URL")
        .ok()
        .or_else(|| std::env::var("HORUS_API_BASE_URL").ok())
        .or_else(|| read_auth().map(|a| a.api_base_url))
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

async fn post(url: &str, body: &Value) -> bool {
    // Same switch as cloud writes (lib/cloud/api.rs); events stay spooled.
    if !crate::lib::cloud::api::cloud_writes_enabled() {
        return false;
    }
    let Ok(body) = horus_core::json::to_js_json(body) else { return false };
    match reqwest::Client::new().post(url).header("content-type", "application/json").body(body).send().await {
        Ok(res) => res.status().is_success(),
        Err(_) => false,
    }
}

/// Flush spooled events. No-op when telemetry is disabled or the spool is empty. Never fails.
/// One overall deadline covers every batch (TS: one AbortController for the whole flush).
pub async fn flush_telemetry(timeout_ms: Option<u64>) {
    if !resolve_consent(None).tier_a {
        return;
    }
    let events = read_spooled_events();
    if events.is_empty() {
        return;
    }
    let url = format!("{}/v1/telemetry", telemetry_base_url().trim_end_matches('/'));
    let all_ok = tokio::time::timeout(Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)), async {
        for chunk in events.chunks(CHUNK) {
            if !post(&url, &json!({ "events": chunk })).await {
                return false; // server rejected — keep the spool, retry next run
            }
        }
        true
    })
    .await;
    if all_ok == Ok(true) {
        clear_spool();
    }
}

/// Best-effort server-side deletion of all events for an install (HOR-327). Runs regardless of
/// consent — a deletion request is always honored. Never fails.
pub async fn delete_remote_telemetry(install_id: &str, timeout_ms: Option<u64>) {
    if install_id.is_empty() {
        return;
    }
    let url = format!("{}/v1/telemetry/delete", telemetry_base_url().trim_end_matches('/'));
    let _ = tokio::time::timeout(
        Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
        post(&url, &json!({ "installId": install_id })),
    )
    .await;
}
