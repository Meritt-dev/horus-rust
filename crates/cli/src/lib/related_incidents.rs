//! Port of `packages/cli/src/lib/related-incidents.ts`.

use horus_core::{HorusConfig, ModifiedSymbol, Symbol};
use horus_db::{list_investigations_with_reports, open_db};
use horus_engine::changes::{incidents_touching_changes, RelatedIncident};

use crate::lib::engine_code::resolve_env;

/// Past incidents whose code a change touches, read from this project's saved investigations.
/// Best-effort: any config or store failure returns [] so change reports never fail on it.
pub async fn related_incidents_for(
    config: &HorusConfig,
    modified: &[ModifiedSymbol],
    removed: &[Symbol],
    project: Option<&str>,
) -> Vec<RelatedIncident> {
    if modified.is_empty() && removed.is_empty() {
        return vec![];
    }
    let scope = match project {
        Some(p) => p.to_string(),
        None => match resolve_env(config, None) {
            Ok(renv) => renv.project,
            Err(_) => return vec![],
        },
    };
    let Ok(db) = open_db().await else { return vec![] };
    let saved = list_investigations_with_reports(&db, 500, Some(&scope)).await;
    db.end().await;
    saved.map(|rows| incidents_touching_changes(modified, removed, &rows)).unwrap_or_default()
}
