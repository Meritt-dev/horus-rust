//! `horus db import` — one-time cutover from a legacy user-run Postgres into the embedded local
//! database. Port of `packages/cli/src/commands/db.ts`.
//!
//! Copies a team's existing investigation history, cause scores, incident memory and outcome
//! labels forward (`horus_db::import_from_postgres`) so the old Postgres can be decommissioned.
//! `--from` defaults to $DATABASE_URL when set.

use anyhow::Result;
use horus_db::{import_from_postgres, local_db_path, open_db, CloudDatabaseUrlError};

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
