//! Open/close the embedded local database, apply migrations, serialise writers.
//!
//! Horus persists ONLY to an embedded, file-backed database — the single local persistence
//! tier (teams that need shared state use Horus Cloud's REST API). TS embeds pglite at
//! `~/.horus/horus.db`; this port embeds SQLite at `~/.horus/horus-rust.db` in the same
//! directory (`HORUS_DB_DIR` overrides it the same way). The TS `horus.db` is never touched.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rusqlite::Connection;

use crate::migrations_bundle::{render_statement, EMBEDDED_MIGRATIONS};

/// File name of the embedded SQLite database (sibling of the TS `horus.db`).
pub const LOCAL_DB_FILE: &str = "horus-rust.db";

/// Default location for the embedded local database (override with HORUS_DB_DIR).
pub fn local_db_path() -> PathBuf {
    let dir = match std::env::var("HORUS_DB_DIR") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".horus"),
    };
    dir.join(LOCAL_DB_FILE)
}

/// Stable prefix on every error raised by the display-only fallback handle. Commands match on
/// this — via `is_db_unavailable` — to degrade gracefully instead of crashing.
pub const DB_UNAVAILABLE_PREFIX: &str = "HORUS_DB_UNAVAILABLE";

/// Prefix on lock-contention errors (another live process owns the database).
pub const DB_BUSY_PREFIX: &str = "HORUS_DB_BUSY";

/// Errors the TS code branches on by message prefix.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("{DB_UNAVAILABLE_PREFIX}: the embedded local database is not available ({0}). Results are display-only.")]
    Unavailable(String),
    #[error("{DB_BUSY_PREFIX}: {0}")]
    Busy(String),
}

/// True when an error originated from the display-only fallback handle (or from failing to open
/// the embedded database). A command that only uses the db for optional enrichment catches THIS
/// to skip the db-backed part and complete; any other error is a genuine fault and propagates.
pub fn is_db_unavailable(err: &anyhow::Error) -> bool {
    err.chain().any(|e| e.to_string().starts_with(DB_UNAVAILABLE_PREFIX))
}

struct Inner {
    path: PathBuf,
    conn: Mutex<Option<Connection>>,
    lock: Mutex<Option<DbLock>>,
}

/// A closeable handle around the active database. Cheap to clone; `end()` releases the
/// connection and the writer lock once on shutdown. An *unavailable* handle (see
/// `DbHandle::unavailable`) does no persistence: every `with_conn` fails with
/// `HORUS_DB_UNAVAILABLE` so persistence helpers that already swallow DB errors degrade to
/// display-only rather than crashing the command, and `end()` is a no-op.
#[derive(Clone)]
pub struct DbHandle {
    inner: Option<Arc<Inner>>,
}

impl std::fmt::Debug for DbHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Some(i) => f.debug_struct("DbHandle").field("path", &i.path).finish(),
            None => f.write_str("DbHandle(unavailable)"),
        }
    }
}

impl DbHandle {
    /// The display-only fallback handle (TS `unavailableDbHandle`).
    pub fn unavailable() -> Self {
        DbHandle { inner: None }
    }

    /// False for the display-only fallback handle.
    pub fn is_available(&self) -> bool {
        self.inner.is_some()
    }

    /// Path of the open database file (None for the fallback handle).
    pub fn path(&self) -> Option<&Path> {
        self.inner.as_ref().map(|i| i.path.as_path())
    }

    /// Run `f` against the connection on a blocking thread. This is the general query surface
    /// (the TS `HorusDb` drizzle handle); the typed helpers in this crate are built on it.
    pub async fn with_conn<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    {
        let inner = self
            .inner
            .clone()
            .ok_or_else(|| anyhow!(DbError::Unavailable("embedded database could not be opened".into())))?;
        tokio::task::spawn_blocking(move || {
            let guard = inner.conn.lock().map_err(|_| anyhow!("database mutex poisoned"))?;
            let conn = guard.as_ref().ok_or_else(|| anyhow!("database handle already closed"))?;
            f(conn)
        })
        .await
        .context("database task panicked")?
    }

    /// Release the underlying resources. Call once on shutdown; later calls are no-ops.
    pub async fn end(&self) {
        let Some(inner) = self.inner.clone() else { return };
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut c) = inner.conn.lock() {
                c.take();
            }
            if let Ok(mut l) = inner.lock.lock() {
                l.take();
            }
        })
        .await;
    }
}

/// Open Horus's local database — ALWAYS the embedded, file-backed SQLite database (default
/// `~/.horus/horus-rust.db`, overridable via `HORUS_DB_DIR`). `DATABASE_URL` is ignored.
///
/// Only a database that cannot be opened at all yields the display-only fallback handle.
/// Migration failures and writer-lock contention propagate; none may silently disable persistence.
pub async fn open_db() -> Result<DbHandle> {
    match create_local_db(None).await {
        Ok(h) => Ok(h),
        Err(e) if is_db_unavailable(&e) => Ok(DbHandle::unavailable()),
        Err(e) => Err(e),
    }
}

/// Create a handle bound to the embedded database at `path` (default `local_db_path()`).
/// Migrations are embedded and applied idempotently on first use, so the file is created and
/// brought to schema on demand. Holds the single-writer lock until `end()`.
pub async fn create_local_db(path: Option<PathBuf>) -> Result<DbHandle> {
    let data_path = path.unwrap_or_else(local_db_path);
    tokio::task::spawn_blocking(move || create_local_db_blocking(data_path))
        .await
        .context("database open task panicked")?
}

fn create_local_db_blocking(data_path: PathBuf) -> Result<DbHandle> {
    if let Some(parent) = data_path.parent() {
        // best-effort; SQLite surfaces a clear error if the path is unusable.
        let _ = fs::create_dir_all(parent);
    }
    // Serialise concurrent CLI runs (single-writer file DB): overlapping investigations could
    // otherwise race a write, lose it, and still print an `ask <id>` hint that won't resolve.
    let lock = acquire_db_lock(&data_path, Duration::from_millis(5000))?;
    let conn = Connection::open(&data_path)
        .map_err(|e| anyhow!(DbError::Unavailable(format!("{}: {e}", data_path.display()))))?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")?;
    apply_embedded_migrations(&conn)?;
    Ok(DbHandle {
        inner: Some(Arc::new(Inner {
            path: data_path,
            conn: Mutex::new(Some(conn)),
            lock: Mutex::new(Some(lock)),
        })),
    })
}

/// Apply the embedded migrations idempotently. Tracks applied tags in `__horus_migrations` so
/// re-opening an existing DB is a no-op and a partially-applied DB resumes where it left off.
fn apply_embedded_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS \"__horus_migrations\" (\
           \"tag\" TEXT PRIMARY KEY,\
           \"applied_at\" TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))\
         );",
    )?;
    let done: Vec<String> = conn
        .prepare("SELECT tag FROM \"__horus_migrations\";")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for migration in EMBEDDED_MIGRATIONS {
        if done.iter().any(|t| t == migration.tag) {
            continue;
        }
        // Each migration is its own transaction: either the whole tag applies or none of it,
        // so the recorded tag always reflects a fully-applied migration.
        let tx = conn.unchecked_transaction()?;
        for statement in migration.statements {
            tx.execute_batch(&render_statement(statement))
                .with_context(|| format!("migration {} failed", migration.tag))?;
        }
        tx.execute("INSERT INTO \"__horus_migrations\" (tag) VALUES (?1);", [migration.tag])?;
        tx.commit()?;
    }
    Ok(())
}

/// Ownership of the single-writer lock; released on drop (or explicitly via `release`).
pub struct DbLock {
    lock_path: PathBuf,
    entry: PathBuf,
    owner: String,
}

impl DbLock {
    /// Release the lock now (equivalent to dropping it).
    pub fn release(self) {}
}

impl Drop for DbLock {
    fn drop(&mut self) {
        let mine = fs::read_to_string(&self.lock_path).map(|v| v == self.owner).unwrap_or(false);
        if mine {
            let _ = remove(&self.lock_path);
        }
        let _ = remove(&self.entry);
    }
}

fn remove(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// `process.kill(pid, 0)`: alive unless the kernel says no such process. Permission/unknown
/// errors fail closed (propagate).
#[cfg(unix)]
fn alive(pid: i64) -> Result<bool> {
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    let pid = i32::try_from(pid).map_err(|_| anyhow!("pid out of range: {pid}"))?;
    if unsafe { kill(pid, 0) } == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    const ESRCH: i32 = 3;
    if err.raw_os_error() == Some(ESRCH) {
        Ok(false)
    } else {
        Err(err.into())
    }
}

#[cfg(not(unix))]
fn alive(_pid: i64) -> Result<bool> {
    // ponytail: no cheap liveness probe off unix; assume alive (never reap a possibly-live owner).
    Ok(true)
}

fn create_private(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Leading `pid` token of a marker file (`Number(value.split(' ')[0])` with integer/positive checks).
fn marker_pid(value: &str) -> Option<i64> {
    let pid: i64 = value.split(' ').next()?.trim().parse().ok()?;
    (pid > 0).then_some(pid)
}

fn busy(msg: String) -> anyhow::Error {
    anyhow!(DbError::Busy(msg))
}

/// Exclusive process ownership of the database at `data_path`; live participants never expire,
/// even when suspended. A bakery ticket serialises stale-file recovery. Each attempt has a
/// unique name, so removing a dead participant can never remove a replacement participant.
/// Ownership records are published only after writing them completely.
///
/// Files: `<db>.lock` (owner marker, hard-linked into place), `<db>.lock.owners/<pid>-<uuid>`
/// (participants + bakery tickets), `<db>.lock.reap` (serialises stale-marker cleanup).
pub fn acquire_db_lock(data_path: &Path, timeout: Duration) -> Result<DbLock> {
    let lock_path = PathBuf::from(format!("{}.lock", data_path.display()));
    let participants = PathBuf::from(format!("{}.owners", lock_path.display()));
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&participants)?;
    }
    let pid = std::process::id() as i64;
    let id = format!("{pid}-{}", uuid::Uuid::new_v4());
    let entry = participants.join(&id);
    let temporary = PathBuf::from(format!("{}.tmp", entry.display()));
    let owner = format!("{pid} {id}");
    let deadline = Instant::now() + timeout;

    let publish = |ticket: u128| -> Result<()> {
        use io::Write;
        let mut f = create_private(&temporary)?;
        write!(f, "{pid} {ticket}")?;
        drop(f);
        fs::rename(&temporary, &entry)?;
        Ok(())
    };
    let scan = || -> Result<Vec<(String, u128)>> {
        let mut rows = Vec::new();
        for dirent in fs::read_dir(&participants)? {
            let name = dirent?.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                continue; // Never a published participant.
            }
            let path = participants.join(&name);
            let value = match fs::read_to_string(&path) {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let parsed = value.split_once(' ').and_then(|(p, t)| {
                let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
                (digits(p) && digits(t)).then(|| (p.parse::<i64>().ok(), t.parse::<u128>().ok()))
            });
            let Some((Some(owner_pid), Some(ticket))) = parsed else {
                return Err(busy(format!("invalid ownership record {}", path.display())));
            };
            if owner_pid <= 0 {
                return Err(busy(format!("invalid ownership record {}", path.display())));
            }
            if !alive(owner_pid)? {
                remove(&path)?;
                continue;
            }
            rows.push((name, ticket));
        }
        Ok(rows)
    };
    let pause = || -> Result<()> {
        if Instant::now() >= deadline {
            return Err(busy(format!(
                "another process owns {}; retry after it exits. Never remove a live owner's lock.",
                lock_path.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(50));
        Ok(())
    };

    let attempt = || -> Result<DbLock> {
        publish(0)?; // Choosing: contenders must wait until the ticket is visible.
        let ticket = scan()?.into_iter().map(|(_, t)| t).max().unwrap_or(0) + 1;
        publish(ticket)?;
        while scan()?.iter().any(|(other, t)| {
            other != &id && (*t == 0 || *t < ticket || (*t == ticket && other < &id))
        }) {
            pause()?;
        }
        // Bridge to old versions' cleanup guard. Anonymous legacy markers cannot be proved
        // dead; require stopping old commands before manually clearing them.
        {
            use io::Write;
            let mut f = create_private(&temporary)?;
            f.write_all(owner.as_bytes())?;
        }
        let reaper = PathBuf::from(format!("{}.reap", lock_path.display()));
        loop {
            match fs::hard_link(&temporary, &reaper) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let value = match fs::read_to_string(&reaper) {
                        Ok(v) => v,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e.into()),
                    };
                    let Some(other_pid) = marker_pid(&value) else {
                        return Err(busy(format!(
                            "anonymous legacy marker {}; stop all older Horus commands before clearing it",
                            reaper.display()
                        )));
                    };
                    if alive(other_pid)? {
                        pause()?;
                        continue;
                    }
                    remove(&reaper)?; // New reapers are serialised by the bakery; names can't be replaced here.
                }
                Err(e) => return Err(e.into()),
            }
        }
        let publish_lock = || -> Result<()> {
            while lock_path.exists() {
                let value = match fs::read_to_string(&lock_path) {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                let Some(other_pid) = marker_pid(&value) else {
                    return Err(busy(format!(
                        "anonymous legacy marker {}; stop all older Horus commands before clearing it",
                        lock_path.display()
                    )));
                };
                if alive(other_pid)? {
                    pause()?;
                    continue;
                }
                remove(&lock_path)?;
            }
            fs::hard_link(&temporary, &lock_path)?; // Atomic publication: never an empty .lock.
            Ok(())
        };
        let published = publish_lock();
        remove(&reaper)?;
        published?;
        remove(&temporary)?;
        Ok(DbLock { lock_path: lock_path.clone(), entry: entry.clone(), owner: owner.clone() })
    };

    let result = attempt();
    let _ = remove(&temporary);
    if result.is_err() {
        let _ = remove(&entry);
    }
    result
}

// ---------------------------------------------------------------------------
// One-time import from a legacy user-run Postgres (`importFromPostgres`)
// ---------------------------------------------------------------------------

pub use pg_import::{import_from_postgres, IMPORT_TABLES};

mod pg_import {
    use super::DbHandle;
    use crate::guard::assert_local_database_url;
    use anyhow::Result;
    use rusqlite::types::Value as SqlValue;
    use serde_json::Value;
    use std::sync::Arc;
    use tokio_postgres::types::{Kind, Type};

    /// Tables copied by [`import_from_postgres`], in FK-safe order (parents before children):
    /// an investigation and its evidence/findings/hypotheses (the cause scores), the incident
    /// and outcome-label records keyed off it, then the authored memory items and their
    /// link/audit rows. Registry (`projects`/`repositories`) and derived caches
    /// (`queue_edges`/`provider_cache`) are intentionally excluded — they are rebuilt locally.
    pub const IMPORT_TABLES: &[&str] = &[
        "investigations",
        "evidence",
        "findings",
        "hypotheses",
        "incident_memory",
        "outcome_label",
        "memory_item",
        "memory_link",
        "memory_audit",
    ];

    /// Rows inserted per batch — keeps a large export from exceeding the bind-parameter limit.
    const IMPORT_CHUNK: usize = 500;

    /// postgres-js `sslmode` handling: absent/`disable` → plain TCP; `require`/`prefer`/`allow`
    /// → TLS without certificate verification; anything else (`verify-full`, …) → verified TLS.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Ssl {
        Off,
        NoVerify,
        Verify,
    }

    fn split_ssl(url: &str) -> (String, Ssl) {
        let Ok(mut u) = url::Url::parse(url) else { return (url.to_string(), Ssl::Off) };
        let mut mode = Ssl::Off;
        let kept: Vec<(String, String)> = u
            .query_pairs()
            .filter_map(|(k, v)| {
                if k == "sslmode" || k == "ssl" {
                    mode = match v.as_ref() {
                        "disable" | "false" => Ssl::Off,
                        "require" | "prefer" | "allow" => Ssl::NoVerify,
                        _ => Ssl::Verify,
                    };
                    None
                } else {
                    Some((k.into_owned(), v.into_owned()))
                }
            })
            .collect();
        if kept.is_empty() {
            u.set_query(None);
        } else {
            u.query_pairs_mut().clear().extend_pairs(kept);
        }
        (u.to_string(), mode)
    }

    #[derive(Debug)]
    struct NoVerify;

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    async fn connect(source_url: &str) -> Result<tokio_postgres::Client> {
        let (url, ssl) = split_ssl(source_url);
        let mut config: tokio_postgres::Config = url.parse()?;
        let client = if ssl == Ssl::Off {
            config.ssl_mode(tokio_postgres::config::SslMode::Disable);
            let (client, conn) = config.connect(tokio_postgres::NoTls).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
        } else {
            let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?;
            let tls = if ssl == Ssl::NoVerify {
                // `prefer`/`allow` may fall back to plain TCP, as postgres-js does.
                config.ssl_mode(tokio_postgres::config::SslMode::Prefer);
                builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_no_client_auth()
            } else {
                config.ssl_mode(tokio_postgres::config::SslMode::Require);
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder.with_root_certificates(roots).with_no_client_auth()
            };
            let (client, conn) = config.connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls)).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
        };
        Ok(client)
    }

    /// One source cell (as `row_to_json` rendered it) converted to the embedded store's
    /// representation: timestamps → `YYYY-MM-DDTHH:MM:SS.mmmZ`, json/jsonb/arrays → JSON text,
    /// booleans → 0/1 — the type mapping documented in `migrations_bundle.rs`.
    fn to_sqlite(ty: &Type, v: Value) -> SqlValue {
        match v {
            Value::Null => SqlValue::Null,
            Value::Bool(b) => SqlValue::Integer(b as i64),
            Value::Number(n) => match n.as_i64() {
                Some(i) => SqlValue::Integer(i),
                None => SqlValue::Real(n.as_f64().unwrap_or(0.0)),
            },
            Value::String(s) if matches!(*ty, Type::TIMESTAMPTZ | Type::TIMESTAMP | Type::DATE) => {
                SqlValue::Text(normalize_ts(&s).unwrap_or(s))
            }
            v if *ty == Type::JSON || *ty == Type::JSONB || matches!(ty.kind(), Kind::Array(_)) => {
                SqlValue::Text(serde_json::to_string(&v).unwrap_or_default())
            }
            Value::String(s) => SqlValue::Text(s),
            other => SqlValue::Text(other.to_string()),
        }
    }

    /// `row_to_json` timestamps (`2024-05-01T10:00:00.123456+00:00`, or no offset for
    /// `timestamp`) → the millisecond UTC form every Horus timestamp column holds.
    fn normalize_ts(s: &str) -> Option<String> {
        use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, Utc};
        let utc: DateTime<Utc> = if let Ok(d) = DateTime::parse_from_rfc3339(s) {
            d.with_timezone(&Utc)
        } else if let Ok(d) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%#z") {
            d.with_timezone(&Utc)
        } else if let Ok(d) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
            d.and_utc()
        } else {
            NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?.and_hms_opt(0, 0, 0)?.and_utc()
        };
        Some(utc.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    /// Read every row of `table` (the embedded schema's columns, which are the TS drizzle
    /// schema's) from the source. Any failure — missing table/column on an older schema, or
    /// an unreachable source — means "nothing to copy", exactly as the TS `catch { continue }`.
    async fn read_table(source: &tokio_postgres::Client, table: &str, columns: &[String]) -> Option<Vec<Vec<SqlValue>>> {
        let cols = columns.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
        let select = format!("SELECT {cols} FROM \"{table}\"");
        let types: Vec<Type> = source.prepare(&select).await.ok()?.columns().iter().map(|c| c.type_().clone()).collect();
        let rows = source.query(&format!("SELECT row_to_json(t)::text FROM ({select}) t"), &[]).await.ok()?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let text: String = row.try_get(0).ok()?;
            let mut obj = match serde_json::from_str::<Value>(&text).ok()? {
                Value::Object(m) => m,
                _ => return None,
            };
            out.push(columns.iter().zip(&types).map(|(c, ty)| to_sqlite(ty, obj.remove(c).unwrap_or(Value::Null))).collect());
        }
        Some(out)
    }

    /// One-time import of a legacy user-run Postgres into the embedded database. Copies the
    /// investigation, cause-score, incident-memory and outcome tables (see [`IMPORT_TABLES`])
    /// from `source_url` into `db`, upserting by primary key so it is fully idempotent
    /// (re-running refreshes rather than duplicates). The source is only ever SELECTed from
    /// and is closed before returning; `db` is the caller's already-open embedded handle.
    ///
    /// Returns the number of source rows processed per table, in [`IMPORT_TABLES`] order.
    pub async fn import_from_postgres(source_url: &str, db: &DbHandle) -> Result<Vec<(String, usize)>> {
        // Guardrail (HOR-298): never open a direct connection to the Horus Cloud database —
        // cloud state is reached through the /v1 REST API, so importing from it is refused.
        assert_local_database_url(source_url)?;
        // postgres-js connects lazily, so a connection failure surfaces per table query.
        let source = connect(source_url).await.ok();
        let mut counts: Vec<(String, usize)> = Vec::new();
        for &table in IMPORT_TABLES {
            counts.push((table.to_string(), 0));
            let Some(source) = source.as_ref() else { continue };
            let t = table.to_string();
            let columns: Vec<String> = db
                .with_conn(move |c| {
                    let mut stmt = c.prepare(&format!("PRAGMA table_info(\"{t}\")"))?;
                    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(cols)
                })
                .await?;
            let Some(rows) = read_table(source, table, &columns).await else { continue };
            if rows.is_empty() {
                continue;
            }
            let n = rows.len();
            let t = table.to_string();
            db.with_conn(move |c| {
                let col_list = columns.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
                let set = columns
                    .iter()
                    .filter(|c| c.as_str() != "id")
                    .map(|c| format!("\"{c}\" = excluded.\"{c}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                let placeholder = format!("({})", vec!["?"; columns.len()].join(", "));
                for batch in rows.chunks(IMPORT_CHUNK) {
                    let values = vec![placeholder.as_str(); batch.len()].join(", ");
                    let sql = format!("INSERT INTO \"{t}\" ({col_list}) VALUES {values} ON CONFLICT(\"id\") DO UPDATE SET {set}");
                    c.execute(&sql, rusqlite::params_from_iter(batch.iter().flatten()))?;
                }
                Ok(())
            })
            .await?;
            if let Some(last) = counts.last_mut() {
                last.1 = n;
            }
        }
        Ok(counts)
    }
}
