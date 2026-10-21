//! Filesystem locations for Horus usage-telemetry state (HOR-323). Port of
//! `packages/cli/src/lib/telemetry/paths.ts`. Global (`~/.horus`, `HORUS_HOME` override), never
//! repo-scoped: install identity and consent belong to the machine/user.

use std::path::PathBuf;

use crate::lib::cloud::paths::horus_home;

pub const TELEMETRY_FILE: &str = "telemetry.json";
pub const TELEMETRY_QUEUE_DIR: &str = "telemetry-queue";

/// Consent + install-identity file: `~/.horus/telemetry.json`.
pub fn telemetry_path() -> PathBuf {
    horus_home().join(TELEMETRY_FILE)
}

/// Offline spool directory for not-yet-uploaded events: `~/.horus/telemetry-queue/`.
pub fn telemetry_queue_dir() -> PathBuf {
    horus_home().join(TELEMETRY_QUEUE_DIR)
}
