//! Cloud-database guardrail (HOR-298).
//!
//! Horus's local state lives in the embedded database; the Horus Cloud Postgres is the shared
//! team source of truth. The CLI must reach Cloud ONLY through the `/v1` REST API — never by
//! opening a direct connection to the Cloud database. The remaining place a raw Postgres URL
//! is accepted is the one-time `horus db import --from <url>` cutover, so this guard makes the
//! boundary un-bypassable there. See `docs/cloud-vs-cli-databases.md`.

/// Known Horus Cloud database markers (its database name and Postgres port).
const CLOUD_DB_NAME: &str = "horus_cloud";
const CLOUD_DB_PORT: &str = "5434";

#[derive(Debug, thiserror::Error)]
#[error("Refusing to connect: the URL points at the Horus Cloud database ({reason}). Cloud is reached through the /v1 REST API, never a direct DB connection. Import from your own local Postgres instead (do not point --from at the Cloud database / HORUS_CLOUD_DATABASE_URL). See docs/cloud-vs-cli-databases.md.")]
pub struct CloudDatabaseUrlError {
    pub reason: String,
}

fn normalize_url(url: &str) -> &str {
    url.trim().trim_end_matches('/')
}

/// Why a URL looks like the Horus Cloud database, or `None` if it looks local.
/// Pure + side-effect free except for reading `HORUS_CLOUD_DATABASE_URL` from env.
pub fn cloud_database_url_reason(url: &str) -> Option<String> {
    if url.is_empty() {
        return None;
    }
    // Strongest signal: exact match to the configured Cloud DB URL.
    if let Ok(cloud_env) = std::env::var("HORUS_CLOUD_DATABASE_URL") {
        if !cloud_env.is_empty() && normalize_url(url) == normalize_url(&cloud_env) {
            return Some("matches HORUS_CLOUD_DATABASE_URL".into());
        }
    }
    // Structured check via the URL parser; fall back to substring matching for connection
    // strings the parser can't handle.
    match url::Url::parse(url) {
        Ok(u) => {
            let db_name = u.path().trim_start_matches('/');
            if db_name == CLOUD_DB_NAME {
                return Some(format!("database name \"{CLOUD_DB_NAME}\""));
            }
            if u.port().map(|p| p.to_string()).as_deref() == Some(CLOUD_DB_PORT) {
                return Some(format!("Cloud port {CLOUD_DB_PORT}"));
            }
            None
        }
        Err(_) => {
            // `/horus_cloud(\b|$)`
            let needle = format!("/{CLOUD_DB_NAME}");
            let name_hit = url.match_indices(&needle).any(|(i, m)| {
                url[i + m.len()..].chars().next().map_or(true, |c| !(c.is_alphanumeric() || c == '_'))
            });
            if name_hit {
                return Some(format!("database name \"{CLOUD_DB_NAME}\""));
            }
            if url.contains(&format!(":{CLOUD_DB_PORT}")) {
                return Some(format!("Cloud port {CLOUD_DB_PORT}"));
            }
            None
        }
    }
}

/// True if `url` appears to point at the Horus Cloud database.
pub fn looks_like_cloud_database_url(url: &str) -> bool {
    cloud_database_url_reason(url).is_some()
}

/// Error if `url` points at the Horus Cloud database. Call at every point that opens a
/// non-embedded database connection so the boundary can't be crossed silently.
pub fn assert_local_database_url(url: &str) -> Result<(), CloudDatabaseUrlError> {
    match cloud_database_url_reason(url) {
        Some(reason) => Err(CloudDatabaseUrlError { reason }),
        None => Ok(()),
    }
}
