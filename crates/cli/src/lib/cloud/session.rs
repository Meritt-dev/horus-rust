//! Shared resolution helpers for cloud commands: API base URL, repo root, and the authenticated
//! client. Port of `packages/cli/src/lib/cloud/session.ts`.

use std::path::{Path, PathBuf};

use horus_core::find_repo_root;

use super::api::{CloudClient, DEFAULT_API_BASE_URL};
use super::auth_store::{read_auth, AuthState};

pub fn resolve_api_base_url(explicit: Option<&str>) -> String {
    explicit
        .map(str::to_string)
        .or_else(|| std::env::var("HORUS_CLOUD_API_URL").ok())
        .or_else(|| read_auth().map(|a| a.api_base_url))
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

pub fn repo_root_or_cwd(cwd: Option<&Path>) -> PathBuf {
    let cwd = cwd.map(Path::to_path_buf).unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    find_repo_root(&cwd).unwrap_or(cwd)
}

pub struct AuthedSession {
    pub client: CloudClient,
    pub auth: AuthState,
}

/// The authed client, or None when not logged in.
pub fn authed_client() -> Option<AuthedSession> {
    let auth = read_auth()?;
    Some(AuthedSession { client: CloudClient::new(&auth.api_base_url, Some(&auth.token)), auth })
}
