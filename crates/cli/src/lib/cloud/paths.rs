//! Filesystem locations for Horus Cloud CLI state. Port of `packages/cli/src/lib/cloud/paths.ts`.
//!
//! Two stores, deliberately separated:
//!   - Repo context  → `<repo>/.horus/cloud.json`  — IDs + slugs only, safe to commit.
//!   - Auth token    → `~/.horus/auth.json`         — the secret, NEVER in the repo.

use std::path::{Path, PathBuf};

use horus_core::HORUS_DIR;

pub const CLOUD_CONFIG_FILE: &str = "cloud.json";
pub const AUTH_FILE: &str = "auth.json";

/// Repo-level cloud context file: `<root>/.horus/cloud.json`.
pub fn cloud_config_path(root: &Path) -> PathBuf {
    root.join(HORUS_DIR).join(CLOUD_CONFIG_FILE)
}

/// Global Horus home (`~/.horus`), overridable via `HORUS_HOME`.
pub fn horus_home() -> PathBuf {
    match std::env::var_os("HORUS_HOME") {
        Some(h) => PathBuf::from(h),
        None => dirs::home_dir().unwrap_or_default().join(HORUS_DIR),
    }
}

/// Global auth file holding the CLI token: `~/.horus/auth.json`.
pub fn auth_path() -> PathBuf {
    horus_home().join(AUTH_FILE)
}
