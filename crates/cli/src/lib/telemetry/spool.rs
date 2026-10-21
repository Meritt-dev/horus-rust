//! Offline event spool: `~/.horus/telemetry-queue/events.jsonl` (HOR-324). Port of
//! `packages/cli/src/lib/telemetry/spool.ts`. Bounded (stop appending at MAX_SPOOL_BYTES);
//! nothing here ever fails.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use serde_json::Value;

use super::paths::telemetry_queue_dir;

pub const SPOOL_FILE: &str = "events.jsonl";
pub const MAX_SPOOL_BYTES: u64 = 256 * 1024;

fn spool_file_path() -> PathBuf {
    telemetry_queue_dir().join(SPOOL_FILE)
}

/// Append one event to the spool, honoring the size cap. Never fails.
pub fn spool_event(event: &Value) {
    // HORUS_RUST_CLOUD_WRITE=0 also keeps telemetry local (the spool is shared with the TS CLI).
    if !crate::lib::cloud::api::cloud_writes_enabled() {
        return;
    }
    let _ = (|| -> anyhow::Result<()> {
        std::fs::create_dir_all(telemetry_queue_dir())?;
        let file = spool_file_path();
        let size = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
        if size >= MAX_SPOOL_BYTES {
            return Ok(()); // bounded — drop rather than grow
        }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(file)?;
        writeln!(f, "{}", horus_core::json::to_js_json(event)?)?;
        Ok(())
    })();
}

/// Read and parse all spooled events, skipping corrupt lines.
pub fn read_spooled_events() -> Vec<Value> {
    std::fs::read_to_string(spool_file_path())
        .map(|raw| {
            raw.split('\n')
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Drop the spool file (successful flush, or `telemetry delete`).
pub fn clear_spool() {
    let _ = std::fs::remove_file(spool_file_path());
}
