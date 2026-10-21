//! Telemetry client (HOR-324): the one entry point command code calls to record a usage event.
//! Port of `packages/cli/src/lib/telemetry/client.ts`. `track()` is fire-and-forget: resolves
//! consent, stamps the base context, spools. Never fails or blocks.

use std::sync::LazyLock;

use chrono::{SecondsFormat, Utc};
use horus_core::HORUS_VERSION;
use serde_json::{Map, Value};

use super::consent::resolve_consent;
use super::events::{tier_for_event_type, TELEMETRY_EVENT_SCHEMA_VERSION};
use super::spool::spool_event;
use super::store::read_telemetry_state;

/// One id per process so events from a single invocation correlate without persisting anything.
static SESSION_ID: LazyLock<String> = LazyLock::new(|| uuid::Uuid::new_v4().to_string());

/// Node `os.platform()`.
pub fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

/// Node `os.arch()`.
pub fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "ia32",
        other => other,
    }
}

/// Record a usage event. `input` is the event minus its base context: an object whose first key
/// is `type`. No-ops when that tier is disabled, no install identity exists yet, or on error.
pub fn track(input: Value) {
    let Value::Object(input) = input else { return };
    let Some(state) = read_telemetry_state() else { return }; // bootstrapped by the first-run notice
    let Some(kind) = input.get("type").and_then(Value::as_str) else { return };
    let tier = tier_for_event_type(kind);
    // Gate on the resolved decision (honors DO_NOT_TRACK / HORUS_TELEMETRY / CI).
    let decision = resolve_consent(Some(Some(&state)));
    if if tier == "A" { !decision.tier_a } else { !decision.tier_b } {
        return;
    }
    let mut event = Map::new();
    event.insert("schemaVersion".into(), TELEMETRY_EVENT_SCHEMA_VERSION.into());
    event.insert("tier".into(), tier.into());
    event.insert("ts".into(), Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true).into());
    event.insert("installId".into(), state.install_id.into());
    event.insert("sessionId".into(), SESSION_ID.as_str().into());
    event.insert("cliVersion".into(), HORUS_VERSION.into());
    event.insert("os".into(), node_platform().into());
    event.insert("arch".into(), node_arch().into());
    event.extend(input);
    spool_event(&Value::Object(event));
}
