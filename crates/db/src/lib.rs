//! `@horus/db` port: the embedded local database (SQLite at `~/.horus/horus-rust.db`),
//! its migrations, writer lock, and the investigation / outcome-label / queue-edge operations.

pub mod client;
pub mod guard;
pub mod health;
pub mod investigations;
pub mod migrations_bundle;
pub mod outcome;
pub mod queue;
pub mod schema;

pub use client::{
    acquire_db_lock, create_local_db, import_from_postgres, import_tables, is_db_unavailable, local_db_path, open_db, DbError, DbHandle,
    DbLock, DB_BUSY_PREFIX, DB_UNAVAILABLE_PREFIX, IMPORT_TABLES, LOCAL_DB_FILE, MIGRATE_TABLES,
};
pub use guard::{assert_local_database_url, cloud_database_url_reason, looks_like_cloud_database_url, CloudDatabaseUrlError};
pub use health::{check_embedded_db, DbHealth, EXPECTED_TABLES};
pub use investigations::{
    get_investigation, get_last_investigation_id, list_investigations, list_investigations_with_reports,
    save_investigation, save_investigation_bundle, update_investigation_report, InvestigationSummary,
    InvestigationWithReport, NewEvidenceRow, NewFindingRow, NewHypothesisRow,
};
pub use migrations_bundle::{EmbeddedMigration, EMBEDDED_MIGRATIONS};
pub use outcome::{
    dedupe_to_current_verdict, get_latest_outcome_label, is_outcome_resolved, is_outcome_source, list_outcome_labels,
    record_outcome_label, summarize_outcome_labels, OutcomeAccuracy, OutcomeBySource, OutcomeCounts,
    OutcomeLabelInput, OutcomeLabelQuery, OUTCOME_RESOLVED, OUTCOME_SOURCE,
};
pub use queue::{list_queue_edges, replace_queue_edges};
pub use schema::{format_ts, parse_ts, Investigation, NewInvestigation, NewQueueEdge, OutcomeLabel, QueueEdge};
