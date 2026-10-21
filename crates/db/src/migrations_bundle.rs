//! Embedded migrations — the SQLite translation of `packages/db/drizzle/*.sql`.
//!
//! Same tags as the TS bundle so `__horus_migrations` bookkeeping reads the same, applied
//! idempotently by `create_local_db()` (see `client.rs`). Type mapping (see DIVERGENCES.md):
//! uuid → TEXT (v4 default expression), jsonb → TEXT holding JSON, timestamptz → TEXT
//! ISO-8601 (`YYYY-MM-DDTHH:MM:SS.mmmZ`), serial → INTEGER PRIMARY KEY AUTOINCREMENT,
//! arrays → TEXT holding a JSON array, boolean → INTEGER 0/1. Table and column names are
//! identical to Postgres. Postgres `ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY` has no SQLite
//! form, so each FK is folded into the `CREATE TABLE` / `ADD COLUMN` of the same migration.

/// One drizzle migration tag and its SQLite statements.
pub struct EmbeddedMigration {
    /// Drizzle migration tag, e.g. "0000_redundant_kabuki".
    pub tag: &'static str,
    /// Individual SQL statements, each run via `execute_batch`.
    pub statements: &'static [&'static str],
}

/// SQLite default expression producing a lowercase RFC-4122 v4 UUID (replaces `gen_random_uuid()`).
pub const UUID_DEFAULT: &str = "(lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)), 2) || '-' || substr('89ab', abs(random()) % 4 + 1, 1) || substr(hex(randomblob(2)), 2) || '-' || hex(randomblob(6))))";

/// SQLite default expression producing the ISO-8601 UTC timestamp Horus stores (replaces `now()`).
pub const NOW_DEFAULT: &str = "(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))";

/// `WHEN` guard shared by the memory-sync triggers: the Postgres session setting
/// `horus.sync_pull` becomes a row in `__horus_settings` (single-writer DB, so DB-scoped is fine).
const NOT_SYNC_PULL: &str =
    "COALESCE((SELECT value FROM \"__horus_settings\" WHERE key = 'horus.sync_pull'), '') <> '1'";

pub const EMBEDDED_MIGRATIONS: &[EmbeddedMigration] = &[
    EmbeddedMigration {
        tag: "0000_redundant_kabuki",
        statements: &[
            r#"CREATE TABLE "evidence" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"investigation_id" TEXT NOT NULL REFERENCES "investigations"("id") ON DELETE CASCADE,
	"source" TEXT NOT NULL,
	"kind" TEXT NOT NULL,
	"title" TEXT NOT NULL,
	"timestamp" TEXT,
	"relevance" REAL DEFAULT 0 NOT NULL,
	"payload" TEXT,
	"links" TEXT,
	"provenance" TEXT,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE TABLE "hypotheses" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"investigation_id" TEXT NOT NULL REFERENCES "investigations"("id") ON DELETE CASCADE,
	"rank" INTEGER NOT NULL,
	"statement" TEXT NOT NULL,
	"score" REAL DEFAULT 0 NOT NULL,
	"supporting_evidence" TEXT,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE TABLE "investigations" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"title" TEXT NOT NULL,
	"incident_input" TEXT NOT NULL,
	"status" TEXT DEFAULT 'open' NOT NULL,
	"summary" TEXT,
	"narrative" TEXT,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL,
	"updated_at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE TABLE "provider_cache" (
	"provider" TEXT NOT NULL,
	"cache_key" TEXT NOT NULL,
	"payload" TEXT,
	"expires_at" TEXT,
	"updated_at" TEXT DEFAULT __NOW__ NOT NULL,
	CONSTRAINT "provider_cache_provider_cache_key_pk" PRIMARY KEY("provider","cache_key")
);"#,
            r#"CREATE TABLE "queue_edges" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"queue_name" TEXT NOT NULL,
	"producer_symbol" TEXT,
	"producer_file" TEXT,
	"worker_symbol" TEXT,
	"worker_file" TEXT,
	"source" TEXT DEFAULT 'stitcher' NOT NULL,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL,
	"updated_at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE TABLE "repositories" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"name" TEXT NOT NULL,
	"path" TEXT NOT NULL,
	"last_indexed_at" TEXT,
	"source_status" TEXT,
	"stale" INTEGER DEFAULT 1 NOT NULL,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL,
	"updated_at" TEXT DEFAULT __NOW__ NOT NULL,
	CONSTRAINT "repositories_name_unique" UNIQUE("name")
);"#,
            r#"CREATE INDEX "evidence_investigation_idx" ON "evidence" ("investigation_id");"#,
            r#"CREATE INDEX "hypotheses_investigation_idx" ON "hypotheses" ("investigation_id");"#,
            r#"CREATE INDEX "queue_edges_queue_name_idx" ON "queue_edges" ("queue_name");"#,
        ],
    },
    EmbeddedMigration {
        tag: "0001_flaky_lester",
        statements: &[
            r#"CREATE TABLE "findings" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"investigation_id" TEXT NOT NULL REFERENCES "investigations"("id") ON DELETE CASCADE,
	"kind" TEXT NOT NULL,
	"title" TEXT NOT NULL,
	"detail" TEXT,
	"confidence" REAL DEFAULT 0 NOT NULL,
	"evidence_ids" TEXT,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE TABLE "incident_memory" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"investigation_id" TEXT REFERENCES "investigations"("id") ON DELETE SET NULL,
	"title" TEXT NOT NULL,
	"summary" TEXT,
	"signature" TEXT,
	"tags" TEXT,
	"payload" TEXT,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE TABLE "projects" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"name" TEXT NOT NULL,
	"description" TEXT,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL,
	"updated_at" TEXT DEFAULT __NOW__ NOT NULL,
	CONSTRAINT "projects_name_unique" UNIQUE("name")
);"#,
            r#"ALTER TABLE "repositories" ADD COLUMN "project_id" TEXT REFERENCES "projects"("id") ON DELETE SET NULL;"#,
            r#"CREATE INDEX "findings_investigation_idx" ON "findings" ("investigation_id");"#,
            r#"CREATE INDEX "incident_memory_signature_idx" ON "incident_memory" ("signature");"#,
        ],
    },
    EmbeddedMigration {
        tag: "0002_reflective_the_enforcers",
        statements: &[r#"ALTER TABLE "hypotheses" ADD COLUMN "verdict" TEXT;"#],
    },
    EmbeddedMigration {
        tag: "0003_past_chat",
        statements: &[r#"ALTER TABLE "investigations" ADD COLUMN "report" TEXT;"#],
    },
    EmbeddedMigration {
        tag: "0004_queue_edges_project",
        statements: &[
            r#"ALTER TABLE "queue_edges" ADD COLUMN "project" TEXT;"#,
            r#"CREATE INDEX "queue_edges_source_project_idx" ON "queue_edges" ("source","project");"#,
        ],
    },
    EmbeddedMigration {
        tag: "0005_incident_memory_project",
        statements: &[
            r#"ALTER TABLE "incident_memory" ADD COLUMN "project" TEXT;"#,
            r#"UPDATE "incident_memory"
SET "project" = (
  SELECT json_extract(i.incident_input, '$.repo')
  FROM "investigations" i
  WHERE i.id = "incident_memory".investigation_id
    AND json_extract(i.incident_input, '$.repo') IS NOT NULL
)
WHERE investigation_id IS NOT NULL AND project IS NULL;"#,
            r#"CREATE INDEX "incident_memory_project_idx" ON "incident_memory" ("project");"#,
        ],
    },
    // No-op in TS too: the source-intelligence metadata column already exists as "source_status".
    EmbeddedMigration { tag: "0006_source_intelligence_metadata", statements: &[] },
    EmbeddedMigration {
        tag: "0007_memory_item",
        statements: &[
            r#"CREATE TABLE "memory_item" (
	"id" TEXT PRIMARY KEY NOT NULL,
	"kind" TEXT NOT NULL,
	"claim" TEXT NOT NULL,
	"scope" TEXT NOT NULL,
	"source" TEXT NOT NULL,
	"evidence" TEXT DEFAULT '[]' NOT NULL,
	"confidence" REAL NOT NULL,
	"status" TEXT DEFAULT 'fresh' NOT NULL,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL,
	"last_verified_at" TEXT,
	"last_verified_hash" TEXT,
	"org_id" TEXT,
	"workspace_id" TEXT,
	"repo" TEXT NOT NULL,
	"user_id" TEXT,
	"visibility" TEXT DEFAULT 'private' NOT NULL,
	"payload" TEXT
);"#,
            r#"CREATE TABLE "memory_link" (
	"id" TEXT PRIMARY KEY NOT NULL,
	"from_memory_id" TEXT NOT NULL REFERENCES "memory_item"("id") ON DELETE CASCADE,
	"rel" TEXT NOT NULL,
	"to_kind" TEXT NOT NULL,
	"to_ref" TEXT NOT NULL,
	"to_file_path" TEXT,
	"created_at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE TABLE "memory_audit" (
	"id" TEXT PRIMARY KEY NOT NULL,
	"memory_id" TEXT NOT NULL REFERENCES "memory_item"("id") ON DELETE CASCADE,
	"action" TEXT NOT NULL,
	"actor" TEXT NOT NULL,
	"from_status" TEXT,
	"to_status" TEXT,
	"note" TEXT,
	"at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE INDEX "memory_item_repo_idx" ON "memory_item" ("repo");"#,
            r#"CREATE INDEX "memory_item_scope_idx" ON "memory_item" ("scope");"#,
            r#"CREATE INDEX "memory_item_status_idx" ON "memory_item" ("status");"#,
            r#"CREATE INDEX "memory_item_tenancy_idx" ON "memory_item" ("org_id","workspace_id","repo","user_id");"#,
            r#"CREATE INDEX "memory_link_from_idx" ON "memory_link" ("from_memory_id");"#,
            r#"CREATE INDEX "memory_link_to_idx" ON "memory_link" ("to_kind","to_ref");"#,
            r#"CREATE INDEX "memory_audit_memory_idx" ON "memory_audit" ("memory_id");"#,
        ],
    },
    EmbeddedMigration {
        tag: "0008_outcome_label",
        statements: &[
            r#"CREATE TABLE "outcome_label" (
	"id" TEXT PRIMARY KEY NOT NULL DEFAULT __UUID__,
	"investigation_id" TEXT REFERENCES "investigations"("id") ON DELETE CASCADE,
	"project" TEXT,
	"resolved" TEXT NOT NULL,
	"confirmed_cause" TEXT,
	"note" TEXT,
	"source" TEXT NOT NULL,
	"payload" TEXT,
	"at" TEXT DEFAULT __NOW__ NOT NULL
);"#,
            r#"CREATE INDEX "outcome_label_investigation_idx" ON "outcome_label" ("investigation_id");"#,
            r#"CREATE INDEX "outcome_label_project_idx" ON "outcome_label" ("project");"#,
            r#"CREATE INDEX "outcome_label_at_idx" ON "outcome_label" ("at");"#,
        ],
    },
    EmbeddedMigration {
        tag: "0009_memory_audit_detail",
        statements: &[r#"ALTER TABLE "memory_audit" ADD COLUMN "detail" TEXT;"#],
    },
    EmbeddedMigration {
        tag: "0010_memory_item_signature_tags",
        statements: &[
            r#"ALTER TABLE "memory_item" ADD COLUMN "signature" TEXT;"#,
            r#"ALTER TABLE "memory_item" ADD COLUMN "tags" TEXT;"#,
            r#"CREATE INDEX IF NOT EXISTS "memory_item_signature_idx" ON "memory_item" ("signature");"#,
        ],
    },
    EmbeddedMigration {
        tag: "0011_investigations_project",
        statements: &[
            r#"ALTER TABLE "investigations" ADD COLUMN "project" TEXT;"#,
            r#"UPDATE "investigations" SET "project" = json_extract(incident_input, '$.repo')
WHERE "project" IS NULL AND json_extract(incident_input, '$.repo') IS NOT NULL;"#,
            r#"CREATE INDEX "investigations_project_created_idx" ON "investigations" ("project","created_at");"#,
        ],
    },
    EmbeddedMigration {
        tag: "0012_memory_item_origin",
        statements: &[
            r#"ALTER TABLE "memory_item" ADD COLUMN "origin" TEXT DEFAULT 'local' NOT NULL;"#,
            r#"ALTER TABLE "memory_item" ADD COLUMN "cloud_id" TEXT;"#,
            r#"ALTER TABLE "memory_item" ADD COLUMN "author_name" TEXT;"#,
            r#"ALTER TABLE "memory_item" ADD COLUMN "pulled_at" TEXT;"#,
            r#"CREATE INDEX IF NOT EXISTS "memory_item_origin_idx" ON "memory_item" ("repo","origin");"#,
        ],
    },
    EmbeddedMigration {
        tag: "0013_memory_sync",
        statements: &[
            "ALTER TABLE memory_item ADD COLUMN sync_scope TEXT;",
            "ALTER TABLE memory_item ADD COLUMN sync_generation INTEGER NOT NULL DEFAULT 1;",
            r#"CREATE TABLE memory_sync_state (
 scope TEXT PRIMARY KEY, repo TEXT NOT NULL, cursor TEXT NOT NULL DEFAULT '0', team_cursor TEXT NOT NULL DEFAULT '0',
 last_pull TEXT, last_push TEXT, error TEXT
);"#,
            r#"CREATE TABLE memory_sync_replica (
 scope TEXT NOT NULL REFERENCES memory_sync_state(scope),
 memory_id TEXT NOT NULL REFERENCES memory_item(id) ON DELETE CASCADE,
 revision TEXT NOT NULL DEFAULT '0', generation INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(scope, memory_id)
);"#,
            r#"CREATE TABLE memory_sync_outbox (
 id TEXT PRIMARY KEY, scope TEXT NOT NULL REFERENCES memory_sync_state(scope),
 memory_id TEXT NOT NULL REFERENCES memory_item(id) ON DELETE CASCADE,
 generation INTEGER NOT NULL, request TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL DEFAULT __NOW__,
 error TEXT, conflict TEXT, created_at TEXT NOT NULL DEFAULT __NOW__,
 UNIQUE(scope, memory_id)
);"#,
            // Replaces Postgres `current_setting('horus.sync_pull')`: set key 'horus.sync_pull' to '1'
            // while hydrating a pull so the triggers below leave sync_generation alone.
            r#"CREATE TABLE IF NOT EXISTS "__horus_settings" (key TEXT PRIMARY KEY, value TEXT NOT NULL);"#,
            // BEFORE UPDATE … NEW.sync_generation := OLD.sync_generation + 1. SQLite cannot edit NEW,
            // so an AFTER trigger rewrites the row; it does not re-fire itself (recursive_triggers off).
            r#"CREATE TRIGGER memory_changed AFTER UPDATE ON memory_item FOR EACH ROW
WHEN __NOT_SYNC_PULL__
BEGIN
 UPDATE memory_item SET sync_generation = OLD.sync_generation + 1 WHERE id = NEW.id;
END;"#,
            r#"CREATE TRIGGER memory_link_changed_insert AFTER INSERT ON memory_link FOR EACH ROW
WHEN __NOT_SYNC_PULL__
BEGIN UPDATE memory_item SET sync_generation = sync_generation + 1 WHERE id = NEW.from_memory_id; END;"#,
            r#"CREATE TRIGGER memory_link_changed_update AFTER UPDATE ON memory_link FOR EACH ROW
WHEN __NOT_SYNC_PULL__
BEGIN UPDATE memory_item SET sync_generation = sync_generation + 1 WHERE id = NEW.from_memory_id; END;"#,
            r#"CREATE TRIGGER memory_link_changed_delete AFTER DELETE ON memory_link FOR EACH ROW
WHEN __NOT_SYNC_PULL__
BEGIN UPDATE memory_item SET sync_generation = sync_generation + 1 WHERE id = OLD.from_memory_id; END;"#,
            r#"CREATE TRIGGER memory_audit_changed AFTER INSERT ON memory_audit FOR EACH ROW
WHEN __NOT_SYNC_PULL__
BEGIN UPDATE memory_item SET sync_generation = sync_generation + 1 WHERE id = NEW.memory_id; END;"#,
            r#"CREATE TRIGGER memory_feedback_changed AFTER INSERT ON outcome_label FOR EACH ROW
WHEN __NOT_SYNC_PULL__
BEGIN
 UPDATE memory_item SET sync_generation = sync_generation + 1
 WHERE id IN (SELECT from_memory_id FROM memory_link WHERE to_kind = 'incident' AND to_ref = NEW.investigation_id);
END;"#,
        ],
    },
    EmbeddedMigration {
        tag: "0014_watch_jobs",
        statements: &[
            "CREATE TABLE IF NOT EXISTS watch_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            "CREATE TABLE IF NOT EXISTS watch_job (id TEXT PRIMARY KEY, route TEXT NOT NULL, episode TEXT NOT NULL, data TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT __NOW__, UNIQUE(route,episode));",
            "CREATE TABLE IF NOT EXISTS watch_event (route TEXT NOT NULL, event_id TEXT NOT NULL, job_id TEXT NOT NULL REFERENCES watch_job(id), PRIMARY KEY(route,event_id));",
        ],
    },
    EmbeddedMigration {
        tag: "0015_memory_pull_pages",
        statements: &[
            "ALTER TABLE memory_sync_state ADD COLUMN pull_progress TEXT;",
            r#"CREATE TABLE memory_sync_pull_page (
 scope TEXT NOT NULL REFERENCES memory_sync_state(scope) ON DELETE CASCADE,
 memory_id TEXT NOT NULL, revision TEXT NOT NULL, stream TEXT NOT NULL,
 page INTEGER NOT NULL, rows TEXT NOT NULL,
 PRIMARY KEY(scope, memory_id, revision, stream, page)
);"#,
        ],
    },
];

/// Expand the `__UUID__` / `__NOW__` / `__NOT_SYNC_PULL__` placeholders of one statement.
pub fn render_statement(statement: &str) -> String {
    statement
        .replace("__UUID__", UUID_DEFAULT)
        .replace("__NOW__", NOW_DEFAULT)
        .replace("__NOT_SYNC_PULL__", NOT_SYNC_PULL)
}
