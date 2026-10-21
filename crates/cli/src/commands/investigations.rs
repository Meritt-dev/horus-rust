//! `horus investigations` — list saved investigation IDs.
//! Port of `packages/cli/src/commands/investigations.ts`.
//!
//! The LOCAL audit store is the primary source: its ids are what `horus replay`, `horus ask`,
//! and `horus postmortem` accept. When the repo is cloud-linked, team investigations that don't
//! exist locally are appended as clearly-marked `[cloud]` extras (browsable at cloud.horus.sh,
//! not locally replayable).

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};
use horus_core::{load_config, resolve_environment, ResolveOptions};
use horus_db::{list_investigations, open_db};
use serde::Serialize;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::cloud::api::InvestigationRecord;
use crate::lib::cloud::context_store::{is_cloud_active, read_cloud_config};
use crate::lib::cloud::investigation_sync::list_cloud_investigations;
use crate::lib::cloud::session::{authed_client, repo_root_or_cwd};
use crate::lib::format::{dim, format_date_time, red};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    id: String,
    created_at: String,
    title: Option<String>,
    cloud: bool,
}

#[derive(Serialize)]
struct Output {
    investigations: Vec<Item>,
    count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
}

/// The CLI pushes investigations with `idempotencyKey = "<localReportId>:investigation"`,
/// so the local (replayable) id is recoverable from a cloud row it originated from.
fn local_id_from_cloud_row(row: &InvestigationRecord) -> Option<&str> {
    let key = row.idempotency_key.as_deref()?;
    let local = key.strip_suffix(":investigation")?;
    if local.is_empty() {
        return None;
    }
    Some(local)
}

fn print_row(id: &str, created_at: &DateTime<Utc>, title: Option<&str>, marker: Option<&str>) {
    let ts = format_date_time(created_at);
    let title = title.unwrap_or("");
    let t = if title.chars().count() > 60 {
        format!("{}...", title.chars().take(57).collect::<String>())
    } else {
        title.to_string()
    };
    let marker = marker.map(|m| format!("  {}", dim(m))).unwrap_or_default();
    println!("{id}  {ts}  {t}{marker}");
}

fn iso(d: &DateTime<Utc>) -> String {
    d.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub async fn run(args: &InvestigationsArgs) -> Result<()> {
    let json = args.json;
    let repo_root = repo_root_or_cwd(None);
    let cloud_cfg = read_cloud_config(&repo_root);
    let cloud_linked = is_cloud_active(cloud_cfg.as_ref());

    // 1. Local rows — the replayable source of truth, scoped to THIS project: the shared DB
    // holds every project's investigations and an unscoped list leaked other projects'
    // incident titles into this repo (dogfood N1).
    let project = load_config(args.config.as_deref().map(Path::new), None)
        .ok()
        .and_then(|c| resolve_environment(&c, &ResolveOptions::default()).ok())
        .map(|r| r.project);
    let mut local_rows = Vec::new();
    let mut local_error: Option<String> = None;
    match open_db().await {
        Ok(db) => {
            let listed = list_investigations(&db, i64::from(args.limit.unwrap_or(20)), project.as_deref()).await;
            db.end().await;
            match listed {
                Ok(rows) => local_rows = rows,
                Err(e) => local_error = Some(e.to_string()),
            }
        }
        Err(e) => local_error = Some(e.to_string()),
    }
    if let (Some(err), false) = (&local_error, cloud_linked) {
        // stdout must stay VALID JSON under --json (agents parse it); the human message still
        // goes to stderr in both modes.
        if json {
            let out = serde_json::json!({ "error": err, "investigations": [], "count": 0 });
            println!("{}", horus_core::json::to_js_json_pretty(&out)?);
        }
        eprintln!("{}", red(err));
        return Err(SilentExit(1).into());
    }

    let mut items: Vec<Item> = local_rows
        .iter()
        .map(|r| Item { id: r.id.clone(), created_at: iso(&r.created_at), title: Some(r.title.clone()), cloud: false })
        .collect();

    let local_ids: HashSet<&str> = local_rows.iter().map(|r| r.id.as_str()).collect();
    if !json {
        for row in &local_rows {
            print_row(&row.id, &row.created_at, Some(&row.title), None);
        }
    }

    // 2. Cloud-linked: append team investigations that don't exist locally.
    let mut cloud_only = 0;
    let mut cloud_note: Option<String> = None;
    if cloud_linked {
        match authed_client() {
            None => cloud_note = Some("cloud-linked — run `horus login` to include team investigations".into()),
            Some(session) => {
                let listed = list_cloud_investigations(&session.client, cloud_cfg.as_ref().unwrap()).await;
                match listed.and_then(|rows| {
                    rows.into_iter()
                        .map(|row| {
                            let created = DateTime::parse_from_rfc3339(&row.created_at)
                                .map(|t| t.with_timezone(&Utc))
                                .map_err(|e| anyhow::anyhow!("invalid createdAt {:?}: {e}", row.created_at))?;
                            Ok((row, created))
                        })
                        .collect::<Result<Vec<_>>>()
                }) {
                    Ok(rows) => {
                        for (row, created) in rows {
                            if local_id_from_cloud_row(&row).is_some_and(|id| local_ids.contains(id)) {
                                continue; // already listed locally
                            }
                            cloud_only += 1;
                            if !json {
                                print_row(&row.id, &created, Some(&row.title), Some("[cloud]"));
                            }
                            items.push(Item { id: row.id, created_at: iso(&created), title: Some(row.title), cloud: true });
                        }
                        if cloud_only > 0 {
                            cloud_note = Some(
                                "[cloud] entries live in Horus Cloud (cloud.horus.sh) — not locally replayable".into(),
                            );
                        }
                    }
                    Err(_) => cloud_note = Some("cloud list unavailable — showing local investigations only".into()),
                }
            }
        }
    }

    if json {
        let mut notes = Vec::new();
        if let Some(err) = &local_error {
            notes.push(format!("local audit store unavailable — replay needs it ({err})"));
        }
        if let Some(n) = &cloud_note {
            notes.push(n.clone());
        }
        let count = items.len();
        println!("{}", horus_core::json::to_js_json_pretty(&Output { investigations: items, count, notes })?);
        return Ok(());
    }

    if local_rows.is_empty() && cloud_only == 0 && local_error.is_none() {
        println!("No investigations yet. Run: horus investigate \"<hint>\"");
    } else if !local_rows.is_empty() {
        println!("{}", dim("Replay locally: horus replay <id>  ·  postmortem: horus postmortem <id>"));
    }
    if let Some(err) = &local_error {
        println!("{}", dim(&format!("local audit store unavailable — replay needs it ({err})")));
    }
    if let Some(n) = &cloud_note {
        println!("{}", dim(n));
    }
    Ok(())
}
