//! Embedded-database probe for `horus status` / `doctor` / `readiness`.

use serde::Serialize;

use crate::client::{is_db_unavailable, local_db_path, open_db};

/// The tables the embedded migrations create (used for the schema-count detail).
pub const EXPECTED_TABLES: &[&str] = &[
    "projects",
    "repositories",
    "investigations",
    "evidence",
    "findings",
    "hypotheses",
    "incident_memory",
    "memory_item",
    "memory_link",
    "memory_audit",
    "outcome_label",
    "queue_edges",
    "provider_cache",
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbHealth {
    /// The embedded database opened and accepted a query.
    pub reachable: bool,
    /// Schema is present (embedded migrations applied — always true once reachable).
    pub schema_ready: bool,
    pub reachable_detail: String,
    pub schema_detail: String,
}

/// Probe the embedded local database. Opening it applies the embedded migrations, so a
/// reachable db is always schema-ready. Never fails — problems are reported as `false` with a
/// human detail.
pub async fn check_embedded_db() -> DbHealth {
    let path = local_db_path();
    let probe = async {
        let handle = open_db().await?;
        // Touch the db so a display-only handle surfaces here.
        let touched = handle.with_conn(|c| Ok(c.query_row("select 1", [], |r| r.get::<_, i64>(0))?)).await;
        handle.end().await;
        touched.map(|_| ())
    };
    match probe.await {
        Ok(()) => DbHealth {
            reachable: true,
            schema_ready: true,
            reachable_detail: format!("embedded ({})", path.display()),
            schema_detail: format!("{} tables present", EXPECTED_TABLES.len()),
        },
        Err(err) if is_db_unavailable(&err) => DbHealth {
            reachable: false,
            schema_ready: false,
            reachable_detail: "embedded database unavailable — this build ships no local persistence".into(),
            schema_detail: "install via npm or Homebrew for local persistence".into(),
        },
        Err(err) => DbHealth {
            reachable: false,
            schema_ready: false,
            reachable_detail: format!("embedded database error — {err}"),
            schema_detail: String::new(),
        },
    }
}
