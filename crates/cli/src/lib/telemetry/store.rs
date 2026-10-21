//! Persistent telemetry state: `~/.horus/telemetry.json` (HOR-323). Port of
//! `packages/cli/src/lib/telemetry/store.ts`.
//!
//! Holds a stable random `installId` (no PII, no fingerprint) and the two-tier consent decision
//! (Tier A = anonymous usage metadata, Tier B = redacted content). Written 0600. Pure storage:
//! env overrides live in `consent.rs`.

use std::os::unix::fs::PermissionsExt;

use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::paths::telemetry_path;
use crate::lib::cloud::paths::horus_home;

pub const TELEMETRY_SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TierAState {
    /// Anonymous usage metadata. Default on (with notice + easy opt-out).
    pub enabled: bool,
    /// ISO timestamp the one-time first-run notice was displayed, or null.
    pub notice_shown_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TierBState {
    /// Redacted input/output content. Default off — explicit opt-in only.
    pub enabled: bool,
    /// ISO timestamp content sharing was turned on, or null.
    pub enabled_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryState {
    pub schema_version: i64,
    /// Random v4 UUID, generated once, user-resettable. Not a fingerprint.
    pub install_id: String,
    pub tier_a: TierAState,
    pub tier_b: TierBState,
    pub created_at: String,
    pub updated_at: String,
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// A fresh state with collection defaults: Tier A on, Tier B off.
pub fn default_telemetry_state(install_id: Option<String>) -> TelemetryState {
    let now = now_iso();
    TelemetryState {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        install_id: install_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        tier_a: TierAState { enabled: true, notice_shown_at: None },
        tier_b: TierBState { enabled: false, enabled_at: None },
        created_at: now.clone(),
        updated_at: now,
    }
}

/// Coerce an unknown parsed blob into a valid state, or None if unusable.
fn coerce(raw: &Value) -> Option<TelemetryState> {
    let r = raw.as_object()?;
    let install_id = r.get("installId")?.as_str().filter(|s| !s.is_empty())?.to_string();
    let empty = Value::Object(Default::default());
    let tier_a = r.get("tierA").filter(|v| !v.is_null()).unwrap_or(&empty);
    let tier_b = r.get("tierB").filter(|v| !v.is_null()).unwrap_or(&empty);
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let b = |v: &Value, k: &str| v.get(k).and_then(Value::as_bool);
    Some(TelemetryState {
        // ponytail: JS keeps a fractional schemaVersion; we truncate — the file only ever holds 1.
        schema_version: r.get("schemaVersion").and_then(Value::as_f64).map_or(TELEMETRY_SCHEMA_VERSION, |n| n as i64),
        install_id,
        tier_a: TierAState { enabled: b(tier_a, "enabled").unwrap_or(true), notice_shown_at: s(tier_a, "noticeShownAt") },
        tier_b: TierBState { enabled: b(tier_b, "enabled").unwrap_or(false), enabled_at: s(tier_b, "enabledAt") },
        created_at: s(raw, "createdAt").unwrap_or_else(now_iso),
        updated_at: s(raw, "updatedAt").unwrap_or_else(now_iso),
    })
}

/// Read state from disk. None when missing or unreadable/corrupt.
pub fn read_telemetry_state() -> Option<TelemetryState> {
    let raw = std::fs::read_to_string(telemetry_path()).ok()?;
    coerce(&serde_json::from_str(&raw).ok()?)
}

/// Persist state with 0600 perms via temp-file + rename, so a crash or a concurrent run never
/// observes a half-written file (which would re-init and churn the installId).
pub fn write_telemetry_state(state: &TelemetryState) -> Result<()> {
    std::fs::create_dir_all(horus_home())?;
    let p = telemetry_path();
    let tmp = p.with_file_name(format!("{}.{}.tmp", super::paths::TELEMETRY_FILE, std::process::id()));
    std::fs::write(&tmp, horus_core::json::to_js_json_pretty(state)? + "\n")?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if let Err(e) = std::fs::rename(&tmp, &p) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Read existing state, or create+persist a fresh one (generating an installId).
pub fn load_or_init_telemetry_state() -> Result<TelemetryState> {
    if let Some(existing) = read_telemetry_state() {
        return Ok(existing);
    }
    let created = default_telemetry_state(None);
    write_telemetry_state(&created)?;
    Ok(created)
}

/// Load, mutate, bump `updatedAt`, and persist in one step.
pub fn update_telemetry_state(mutate: impl FnOnce(&mut TelemetryState)) -> Result<TelemetryState> {
    let mut state = load_or_init_telemetry_state()?;
    mutate(&mut state);
    state.updated_at = now_iso();
    write_telemetry_state(&state)?;
    Ok(state)
}

/// Delete the local telemetry file entirely (used by `horus telemetry delete`).
pub fn delete_telemetry_state() {
    let _ = std::fs::remove_file(telemetry_path());
}
