//! `horus db import` — one-time cutover from a legacy user-run Postgres into the embedded local
//! database. Port of `packages/cli/src/commands/db.ts`.
//!
//! Copies a team's existing investigation history, cause scores, incident memory and outcome
//! labels forward (`horus_db::import_from_postgres`) so the old Postgres can be decommissioned.
//! `--from` defaults to $DATABASE_URL when set.
//!
//! Rust-only: `horus db migrate-from-ts` copies a TS user's PGlite store (`~/.horus/horus.db`)
//! into the SQLite store, by serving a throwaway COPY of it over the Postgres wire protocol
//! (`@electric-sql/pglite-socket` via npx) and running the same importer over every table.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::Result;
use horus_db::{
    acquire_db_lock, import_from_postgres, import_tables, local_db_path, open_db, CloudDatabaseUrlError, MIGRATE_TABLES,
};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red};

/// Mask any credentials in a Postgres URL before printing it (keep the user, hide the secret).
fn redact_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            if u.password().is_some() {
                let _ = u.set_password(Some("***"));
            }
            u.to_string()
        }
        Err(_) => regex::Regex::new(r"//[^@/]*@").unwrap().replace(raw, "//***@").into_owned(),
    }
}

pub async fn run(args: &DbArgs) -> Result<()> {
    match &args.command {
        DbCommand::Import(a) => run_db_import(a.from.clone()).await,
        DbCommand::MigrateFromTs(a) => run_migrate_from_ts(a.from.as_deref()).await,
    }
}

/// PGlite build the TS CLI ships (horus `@electric-sql/pglite` 0.5.3) and the socket server
/// release that pairs with it. The data directory format follows the PGlite release.
const PGLITE: &str = "@electric-sql/pglite@0.5.3";
const PGLITE_SOCKET: &str = "@electric-sql/pglite-socket@0.2.6";

/// The TS store: `horus.db` beside this CLI's `horus-rust.db` (both honour HORUS_DB_DIR).
fn default_ts_db() -> PathBuf {
    local_db_path().parent().unwrap_or(Path::new(".")).join("horus.db")
}

/// Stops the PGlite server and deletes the temporary copy, however the migration ends.
struct Scratch {
    dir: PathBuf,
    server: Option<std::process::Child>,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(child) = self.server.as_mut() {
            // npx runs the server as a grandchild: signal the whole process group.
            let _ = Command::new("kill").arg("-TERM").arg(format!("-{}", child.id())).status();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fail(msg: &str, hint: &str) -> anyhow::Error {
    eprintln!("{}", red(msg));
    if !hint.is_empty() {
        eprintln!("{}", dim(&format!("  {hint}")));
    }
    SilentExit(1).into()
}

pub async fn run_migrate_from_ts(from: Option<&str>) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let ts_db = from.map(PathBuf::from).unwrap_or_else(default_ts_db);
    if !ts_db.join("PG_VERSION").is_file() {
        return Err(fail(&format!("No TS Horus database at {}.", ts_db.display()), "Pass --from <dir> if it lives elsewhere."));
    }
    let npx_ok = Command::new("npx").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status();
    if !matches!(npx_ok, Ok(s) if s.success()) {
        return Err(fail(
            "Node.js (npx) is required to read the TS database, and it was not found on PATH.",
            "Install Node.js 18+ (https://nodejs.org), then re-run `horus db migrate-from-ts`.",
        ));
    }

    // Copy under the TS single-writer lock: refuses while a live TS process owns it, and keeps
    // TS from writing mid-copy. The original is only ever read.
    let scratch_dir = std::env::temp_dir().join(format!("horus-migrate-{}", std::process::id()));
    let copy = scratch_dir.join("horus.db");
    let mut scratch = Scratch { dir: scratch_dir.clone(), server: None };
    {
        let lock = match acquire_db_lock(&ts_db, Duration::from_secs(2)) {
            Ok(l) => l,
            Err(_) => {
                return Err(fail(
                    &format!("A running TS Horus process is using {}.", ts_db.display()),
                    "Stop it (exit running `horus` commands; `horus service stop` for the watch service), then retry.",
                ))
            }
        };
        std::fs::create_dir_all(&scratch_dir)?;
        let copied = Command::new("cp").arg("-Rp").arg(&ts_db).arg(&copy).status();
        lock.release();
        if !matches!(copied, Ok(s) if s.success()) {
            return Err(fail(&format!("Could not copy {} to {}.", ts_db.display(), copy.display()), ""));
        }
    }

    let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    println!("{}", dim(&format!("Serving a copy of {} with PGlite (npx {PGLITE_SOCKET})…", ts_db.display())));
    let log = std::fs::File::create(scratch_dir.join("server.log"))?;
    let child = Command::new("npx")
        .args(["-y", "-p", PGLITE, "-p", PGLITE_SOCKET, "pglite-server"])
        .arg(format!("--db={}", copy.display()))
        .arg(format!("--port={port}"))
        .arg("--host=127.0.0.1")
        .current_dir(&scratch_dir)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()?;
    scratch.server = Some(child);

    // First run downloads the packages, so allow a while for the server to listen.
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        let exited = scratch.server.as_mut().and_then(|c| c.try_wait().ok().flatten()).is_some();
        if exited || Instant::now() >= deadline {
            let out = std::fs::read_to_string(scratch_dir.join("server.log")).unwrap_or_default();
            let tail: Vec<&str> = out.lines().rev().take(5).collect();
            return Err(fail(
                "The PGlite server for the TS database did not start.",
                &tail.into_iter().rev().collect::<Vec<_>>().join("\n  "),
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let db = open_db().await?;
    println!("{}", dim(&format!("Importing into {}…", local_db_path().display())));
    let url = format!("postgres://postgres@127.0.0.1:{port}/postgres");
    let result = import_tables(&url, &db, MIGRATE_TABLES, true).await;
    db.end().await;
    drop(scratch);
    let counts = result.map_err(|e| fail(&format!("Migration failed: {e}"), "The TS database was not modified; re-running is safe."))?;
    let total: usize = counts.iter().map(|(_, n, d)| n - d).sum();
    let dropped: usize = counts.iter().map(|(_, _, d)| d).sum();
    for (table, n, d) in &counts {
        let note = if *d > 0 { dim(&format!("  ({d} orphaned row(s) without their parent skipped)")) } else { String::new() };
        println!("  {}  {table}{note}", bold(&format!("{:>6}", n - d)));
    }
    println!("{}", green(&format!("✓ Migrated {total} row(s) from the TS database. Re-running refreshes; it never duplicates.")));
    if dropped > 0 {
        println!("{}", dim(&format!("  {dropped} source row(s) pointed at records that no longer exist and were left behind.")));
    }
    Ok(())
}

/// One dim stderr line offering the migration while this store has no investigations and a TS
/// store sits beside it. Never for `db` commands, `--json`, CI or a non-TTY stderr.
pub fn maybe_hint_migrate_from_ts(path: &[String], argv: &[String]) {
    if path.first().map(String::as_str) == Some("db")
        || argv.iter().any(|a| a == "--json")
        || std::env::var_os("CI").is_some()
        || !std::io::stderr().is_terminal()
        || !default_ts_db().join("PG_VERSION").is_file()
    {
        return;
    }
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let has_history = rusqlite::Connection::open_with_flags(local_db_path(), flags)
        .and_then(|c| c.query_row("SELECT EXISTS(SELECT 1 FROM investigations)", [], |r| r.get::<_, bool>(0)))
        .unwrap_or(false);
    if !has_history {
        eprintln!("{}", dim("Found TS Horus history in ~/.horus/horus.db — run `horus db migrate-from-ts` to bring it over."));
    }
}

pub async fn run_db_import(from: Option<String>) -> Result<()> {
    let from = from.or_else(|| std::env::var("DATABASE_URL").ok());
    let Some(from) = from.filter(|f| !f.trim().is_empty()) else {
        eprintln!(
            "{}{}",
            red("No source database to import from."),
            dim("  Pass --from <postgres-url> (or set DATABASE_URL).")
        );
        return Err(SilentExit(1).into());
    };

    let db = open_db().await?;
    println!("{}", dim(&format!("Importing from {} into the embedded database ({})…", redact_url(&from), local_db_path().display())));
    let result = import_from_postgres(&from, &db).await;
    db.end().await;
    match result {
        Ok(counts) => {
            let total: usize = counts.iter().map(|(_, n)| n).sum();
            for (table, n) in &counts {
                println!("  {}  {table}", bold(&format!("{n:>6}")));
            }
            println!("{}", green(&format!("✓ Imported {total} row(s) from Postgres into the embedded database.")));
            if total == 0 {
                println!("{}", dim("  (nothing to copy — the source had no investigation/memory rows)"));
            }
        }
        Err(err) => {
            if let Some(cloud) = err.downcast_ref::<CloudDatabaseUrlError>() {
                eprintln!("{}", red(&cloud.to_string()));
            } else {
                // Connection/read failures (unreachable host, bad credentials, missing db) exit non-zero.
                eprintln!("{}", red(&format!("Import failed: {err}")));
            }
            return Err(SilentExit(1).into());
        }
    }
    Ok(())
}
