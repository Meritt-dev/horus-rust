//! Auth token store: `~/.horus/auth.json`. Port of `packages/cli/src/lib/cloud/auth-store.ts`.
//! The token is the only secret the CLI holds; it never goes into the repo `.horus/` config.

use std::os::unix::fs::PermissionsExt;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::paths::{auth_path, horus_home};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudAccount {
    pub user_id: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthState {
    pub api_base_url: String,
    pub token: String,
    pub account: CloudAccount,
}

pub fn read_auth() -> Option<AuthState> {
    let raw = std::fs::read_to_string(auth_path()).ok()?;
    let parsed: AuthState = serde_json::from_str(&raw).ok()?;
    if parsed.token.is_empty() || parsed.api_base_url.is_empty() {
        return None;
    }
    Some(parsed)
}

pub fn write_auth(state: &AuthState) -> Result<()> {
    std::fs::create_dir_all(horus_home())?;
    let p = auth_path();
    std::fs::write(&p, serde_json::to_string_pretty(state)? + "\n")?;
    // Tighten perms even if the file pre-existed with a looser mode (best-effort).
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn clear_auth() {
    let _ = std::fs::remove_file(auth_path());
}
