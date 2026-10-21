//! Passive update notifier (HOR-383). Port of `packages/cli/src/lib/update-notifier.ts`.
//!
//! On a normal command run, print a one-line hint to STDERR when the CLI is behind the latest
//! release. Decided from a ~24h-cached result so it NEVER blocks on the network; the cache is
//! refreshed in the background for the next run. Suppressed for CI / non-TTY / `--json` /
//! `HORUS_NO_UPDATE_CHECK`.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use horus_core::HORUS_VERSION;
use serde_json::{json, Value};

use crate::commands::update::{is_newer, releases_api};
use crate::lib::format::dim;

const CHECK_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS: u64 = 2500;

fn cache_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".horus").join("update-check.json")
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateCache {
    pub last_check_ms: i64,
    pub latest: String,
}

/// Explicit opt-out, CI, non-interactive stderr, or JSON output.
pub fn is_suppressed() -> bool {
    std::env::var_os("HORUS_NO_UPDATE_CHECK").is_some_and(|v| !v.is_empty())
        || std::env::var_os("CI").is_some_and(|v| !v.is_empty())
        || !std::io::stderr().is_terminal()
        || std::env::args().any(|a| a == "--json")
}

/// The one-line dim hint shown when the CLI is behind the latest release.
pub fn format_hint(latest: &str, current: &str) -> String {
    format!("{}\n", dim(&format!("  A newer Horus is available: {latest} (you're on {current}). Run `horus update`.")))
}

fn read_cache(path: &Path) -> Option<UpdateCache> {
    let j: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    Some(UpdateCache { latest: j.get("latest")?.as_str()?.to_string(), last_check_ms: j.get("lastCheckMs")?.as_f64()? as i64 })
}

fn write_cache(path: &Path, cache: &UpdateCache) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = horus_core::json::to_js_json(&json!({ "lastCheckMs": cache.last_check_ms, "latest": cache.latest })) {
        let _ = std::fs::write(path, s + "\n");
    }
}

/// Pure decision: which hint (if any) to print, and is a background refresh due?
pub fn decide_notification(cache: Option<&UpdateCache>, current: &str, now_ms: i64) -> (Option<String>, bool) {
    let hint = cache
        .filter(|c| !c.latest.is_empty())
        // An unparseable current version (e.g. `dev`) stays silent.
        .filter(|c| is_newer(&c.latest, current).unwrap_or(false))
        .map(|c| format_hint(&c.latest, current));
    let refresh_due = cache.is_none_or(|c| now_ms - c.last_check_ms > CHECK_INTERVAL_MS);
    (hint, refresh_due)
}

async fn refresh(path: PathBuf, now_ms: i64) {
    let res = reqwest::Client::new()
        .get(releases_api())
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", format!("horus/{HORUS_VERSION}"))
        .timeout(Duration::from_millis(FETCH_TIMEOUT_MS))
        .send()
        .await;
    let Ok(res) = res else { return };
    if !res.status().is_success() {
        return;
    }
    let Ok(body) = res.json::<Value>().await else { return };
    let latest = body.get("tag_name").and_then(Value::as_str).map(|t| t.strip_prefix('v').unwrap_or(t).to_string());
    if let Some(latest) = latest.filter(|l| !l.is_empty()) {
        write_cache(&path, &UpdateCache { last_check_ms: now_ms, latest });
    }
}

/// Print a cached update hint (non-blocking) and kick off a background refresh when stale.
/// Safe on every command (TS skips `update`, `service`, `watch`); never blocks or fails.
pub fn maybe_notify_update() {
    if is_suppressed() {
        return;
    }
    let path = cache_path();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let cache = read_cache(&path);
    let (hint, refresh_due) = decide_notification(cache.as_ref(), HORUS_VERSION, now_ms);
    if let Some(h) = hint {
        eprint!("{h}");
    }
    if refresh_due {
        // Throttle eagerly (synchronously) so a fast-exiting command doesn't re-hit the API
        // every run, then fire-and-forget the fetch (it may not finish before exit, like TS).
        write_cache(&path, &UpdateCache { last_check_ms: now_ms, latest: cache.map(|c| c.latest).unwrap_or_default() });
        tokio::spawn(refresh(path, now_ms));
    }
}
