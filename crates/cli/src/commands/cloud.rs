//! `horus cloud link` / `unlink` / `status` / `sync` (HOR-226, per HOR-225). Port of
//! `packages/cli/src/commands/cloud.ts`.
//!
//! Links the current repo to a cloud project so investigations are stored in Horus Cloud. Git
//! remote detection is a discovery aid only (HOR-238 §7); `.horus/cloud.json` is authoritative
//! and carries no secrets.

use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::Result;
use horus_core::{load_config, resolve_environment, ResolveOptions};
use horus_db::{list_investigations_with_reports, open_db};
use serde_json::Value;

use crate::cli::*;
use crate::commands::context::{cloud_binding, exit, pick_context_target, report_cloud_error, resolve_triple, sync_meta_lines, ResolvedTriple};
use crate::lib::cloud::api::{CloudClient, ContextResponse, CreateProjectBody};
use crate::lib::cloud::context_store::{clear_cloud_config, is_cloud_active, read_cloud_config, write_cloud_config, Ref};
use crate::lib::cloud::git::{detect_git_remote, infer_provider, parse_repo_name, remotes_match, GitRemote};
use crate::lib::cloud::investigation_sync::{upload_investigation_to_cloud, UploadOpts};
use crate::lib::cloud::memory_sync::{sync_linked_memory, MemorySyncOptions};
use crate::lib::cloud::session::{authed_client, repo_root_or_cwd};
use crate::lib::format::{bold, dim, green, red, yellow};

/// JS `s.slice(0, n)` (UTF-16 code units).
fn js_slice(s: &str, n: usize) -> String {
    String::from_utf16_lossy(&s.encode_utf16().take(n).collect::<Vec<_>>())
}

fn slug(r: &Option<Ref>) -> String {
    r.as_ref().map_or_else(|| "undefined".to_string(), |r| r.slug.clone())
}

/// Readline `question`: print the prompt, read one line (None on EOF).
fn question(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_string()),
    }
}

pub async fn run_cloud_link(target: Option<&str>, yes: bool) -> Result<u8> {
    let root = repo_root_or_cwd(None);
    let Some(session) = authed_client() else {
        eprintln!("{}", red(&format!("Not logged in. Run {} first.", bold("horus login"))));
        return Ok(1);
    };
    let ctx = match session.client.context().await {
        Ok(c) => c,
        Err(err) => return Ok(report_cloud_error(&err.into())),
    };
    let remote = detect_git_remote(&root);
    if let Some(r) = &remote {
        println!("{}", dim(&format!("Detected git remote: {}", r.remote_url)));
    }

    // Resolve the target: 1. explicit arg  2. existing binding  3. auto-match by git remote
    // 4. pick from accessible projects  5. create-from-repo.
    let mut resolved: Option<ResolvedTriple> = None;
    let mut target = target.filter(|t| !t.is_empty()).map(str::to_string);
    if target.is_none() {
        if let Some(existing) = read_cloud_config(&root).filter(|c| is_cloud_active(Some(c))) {
            if let (Some(o), Some(w), Some(p)) = (&existing.organization, &existing.workspace, &existing.project) {
                target = Some(format!("{}/{}/{}", o.slug, w.slug, p.slug));
            }
        }
    }
    if target.is_none() {
        if let Some(r) = &remote {
            let matched = ctx
                .projects
                .iter()
                .find(|p| p.remote_url.as_deref().is_some_and(|u| !u.is_empty() && remotes_match(u, &r.remote_url)));
            if let Some(m) = matched {
                let ws = ctx.workspaces.iter().find(|w| w.id == m.workspace_id);
                let org = ctx.organizations.iter().find(|o| o.id == m.organization_id);
                if let (Some(ws), Some(org)) = (ws, org) {
                    let t = format!("{}/{}/{}", org.slug, ws.slug, m.slug);
                    println!("{}", dim(&format!("Matched existing project by remote: {}", bold(&t))));
                    target = Some(t);
                }
            }
        }
    }
    if target.is_none() && !yes && !ctx.projects.is_empty() {
        if let Some(picked) = pick_context_target(&ctx, false, Some("Link this repo to which cloud project?"))? {
            if picked != "local" {
                target = Some(picked);
            }
        }
    }
    if target.is_none() {
        match create_project_from_repo(&session.client, &ctx, remote.as_ref(), yes).await {
            Created::Aborted => return Ok(1),
            Created::None => {
                eprintln!(
                    "{}\n  Run {} in a TTY to pick or create one, pass a target ({}), or create a project at {}.",
                    red("No project to link."),
                    bold("horus cloud link"),
                    bold("horus cloud link <org/workspace/project>"),
                    bold("https://cloud.horus.sh")
                );
                return Ok(1);
            }
            Created::Triple(t) => resolved = Some(t),
        }
    }
    let resolved = match resolved {
        Some(r) => r,
        None => {
            let t = target.unwrap_or_default();
            match resolve_triple(&ctx, &t) {
                Some(r) => r,
                None => {
                    eprintln!(
                        "{}\n  Run {} to see available projects.",
                        red(&format!("You don't have access to {}.", bold(&t))),
                        bold("horus context list")
                    );
                    return Ok(1);
                }
            }
        }
    };
    let label = format!("{}/{}/{}", resolved.organization.slug, resolved.workspace.slug, resolved.project.slug);
    // A project IS the repository/codebase (HOR-280); store the triple only (HOR-278).
    write_cloud_config(&root, &cloud_binding(resolved))?;
    println!("{} Linked. Context for this repo is now {} {}.", green("✓"), bold(&label), dim("(cloud)"));
    println!(
        "{}",
        dim(&format!("  Investigations here save to Horus Cloud. {} to switch back.", bold("horus context use local")))
    );
    let memory: Result<String> = async {
        let cfg = load_config(None, Some(&root))?;
        let local = resolve_environment(&cfg, &ResolveOptions { cwd: Some(&root), ..Default::default() })?;
        let db = open_db().await?;
        let state = sync_linked_memory(&db, &root, &local.project, MemorySyncOptions::default()).await;
        db.end().await;
        let state = state?;
        Ok(format!(
            "Memory: {}; {} pending{}",
            state.state,
            state.pending,
            state.error.as_deref().filter(|e| !e.is_empty()).map(|e| format!(" — {e}")).unwrap_or_default()
        ))
    }
    .await;
    match memory {
        Ok(line) => println!("{line}"),
        Err(e) => eprintln!("Memory restoration pending: {e}"),
    }
    Ok(0)
}

pub fn run_cloud_unlink() -> Result<u8> {
    let root = repo_root_or_cwd(None);
    if !read_cloud_config(&root).is_some_and(|c| c.context == "cloud") {
        println!("{}", dim("This repo isn't linked to a cloud project."));
        return Ok(0);
    }
    clear_cloud_config(&root);
    println!("{} Unlinked. This repo is back to {} mode.", green("✓"), bold("local"));
    Ok(0)
}

pub async fn run_cloud_status() -> Result<u8> {
    let root = repo_root_or_cwd(None);
    let cfg = read_cloud_config(&root);
    let session = authed_client();
    let Some(cfg) = cfg.filter(|c| is_cloud_active(Some(c))) else {
        println!("{}  local", bold("Context:"));
        println!("{}  local Postgres (~/.horus)", bold("Storage:"));
        println!(
            "{}",
            dim(&format!(
                "Tip:      {} then {} to share investigations with your team.",
                bold("horus login"),
                bold("horus cloud link")
            ))
        );
        return Ok(0);
    };
    let project_ref = cfg.project.clone().unwrap_or(Ref { id: String::new(), slug: String::new() });
    let triple = format!("{}/{}/{}", slug(&cfg.organization), slug(&cfg.workspace), project_ref.slug);
    println!("{}     {triple}   {}", bold("Context:"), dim("(cloud)"));

    // Enrich with the project's name + sync metadata when logged in + online; else slug-only.
    let mut project_line = project_ref.slug.clone();
    let mut meta_lines: Vec<String> = Vec::new();
    let mut account = dim("not logged in");
    if let Some(session) = session {
        account = session.auth.account.email.clone();
        if let Ok(ctx) = session.client.context().await {
            let project = ctx.projects.iter().find(|p| p.id == project_ref.id);
            if let Some(project) = project {
                let ws = ctx.workspaces.iter().find(|w| w.id == project.workspace_id);
                let org = ctx.organizations.iter().find(|o| o.id == project.organization_id);
                if let (Some(ws), Some(org)) = (ws, org) {
                    project_line = format!("{}  ·  workspace {}  ·  org {}", project.name, ws.name, org.name);
                    meta_lines = sync_meta_lines(project);
                }
            }
        }
    }
    println!("{}     {project_line}", bold("Project:"));
    for line in meta_lines {
        println!("{line}");
    }
    println!("{}     {account}", bold("Account:"));
    Ok(0)
}

/// `horus cloud sync` (HOR-240) — upload existing LOCAL investigation history (with a stored
/// report) to the linked cloud project through the API. Retries are safe (report-id-derived
/// idempotency keys). Local data is never modified.
pub async fn run_cloud_sync(args: &CloudSyncArgs) -> Result<u8> {
    let root = repo_root_or_cwd(None);
    let Some(cfg) = read_cloud_config(&root).filter(|c| is_cloud_active(Some(c))) else {
        eprintln!("{} Run {} first.", red("This repo isn't linked to a cloud project."), bold("horus cloud link"));
        return Ok(1);
    };
    let Some(session) = authed_client() else {
        eprintln!("{}", red(&format!("Not logged in. Run {} first.", bold("horus login"))));
        return Ok(1);
    };
    // Push ONLY this project's investigations (dogfood N1).
    let project = load_config(args.config.as_deref().map(Path::new), None)
        .ok()
        .and_then(|c| resolve_environment(&c, &ResolveOptions::default()).ok())
        .map(|r| r.project);
    let db = open_db().await?;
    let result = sync_inner(args, &cfg, &session.client, &db, project.as_deref()).await;
    db.end().await;
    result
}

async fn sync_inner(
    args: &CloudSyncArgs,
    cfg: &crate::lib::cloud::context_store::CloudConfig,
    client: &CloudClient,
    db: &horus_db::DbHandle,
    project: Option<&str>,
) -> Result<u8> {
    let rows = list_investigations_with_reports(db, i64::from(args.limit.unwrap_or(1000)), project).await?;
    let mut uploadable: Vec<(String, String, Value)> = Vec::new();
    let mut skipped_no_report = 0;
    for row in rows {
        match row.report.as_deref().and_then(|r| serde_json::from_str::<Value>(r).ok()).filter(Value::is_object) {
            Some(report) => uploadable.push((row.id, row.title, report)),
            None => skipped_no_report += 1,
        }
    }
    let target = format!("{}/{}/{}", slug(&cfg.organization), slug(&cfg.workspace), slug(&cfg.project));
    if uploadable.is_empty() {
        let skipped = if skipped_no_report > 0 { format!(" ({skipped_no_report} without a report skipped)") } else { String::new() };
        println!("{}", dim(&format!("No local investigations with reports to upload.{skipped}")));
        return Ok(0);
    }
    // Preview what will be uploaded (HOR-240: show before migrating).
    println!("{}", bold(&format!("Will upload {} investigation(s) to {target} {}:", uploadable.len(), dim("(cloud)"))));
    for (id, title, _) in uploadable.iter().take(20) {
        let t = if title.is_empty() { "untitled" } else { title.as_str() };
        println!("  {}  {}", dim(&js_slice(id, 8)), js_slice(t, 70));
    }
    if uploadable.len() > 20 {
        println!("{}", dim(&format!("  …and {} more", uploadable.len() - 20)));
    }
    if skipped_no_report > 0 {
        println!("{}", dim(&format!("  ({skipped_no_report} local investigation(s) without a report will be skipped)")));
    }
    if args.dry_run {
        println!("{}", dim("Dry run — nothing uploaded. Re-run without --dry-run to upload."));
        return Ok(0);
    }
    // Confirm unless --yes. Non-interactive without --yes is a safe stop.
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            eprintln!("{}", yellow(&format!("Re-run with {} to upload, or {} to preview only.", bold("--yes"), bold("--dry-run"))));
            return Ok(1);
        }
        let answer = question(&format!("Upload {} investigation(s) to {target}? (y/N) ", uploadable.len()))
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        if answer != "y" && answer != "yes" {
            println!("{}", dim("Aborted. Nothing uploaded."));
            return Ok(0);
        }
    }
    let (mut created, mut failed) = (0, 0);
    for (id, _, report) in &uploadable {
        match upload_investigation_to_cloud(client, cfg, report, UploadOpts { db: Some(db), ..Default::default() }).await {
            Ok(refs) => {
                created += 1;
                println!("{} {} → {}", green("✓"), dim(&js_slice(id, 8)), refs.investigation_id);
            }
            Err(err) => {
                failed += 1;
                eprintln!("{} {} {err}", red("✗"), dim(&js_slice(id, 8)));
            }
        }
    }
    println!();
    println!(
        "{} {}, {skipped_no_report} skipped, {}.",
        bold("Sync complete:"),
        green(&format!("{created} uploaded")),
        if failed > 0 { red(&format!("{failed} failed")) } else { "0 failed".into() }
    );
    println!("{}", dim("Local data was not modified. Re-running is safe — duplicates are deduped by idempotency key."));
    Ok(if failed > 0 { 1 } else { 0 })
}

enum Created {
    Triple(ResolvedTriple),
    None,
    Aborted,
}

/// Interactive create-from-repo (HOR-307): choose an org + workspace (or create one) and name the
/// project (defaulting to the repo name), then create it with the repo's remote so a future
/// `cloud link` auto-matches.
async fn create_project_from_repo(client: &CloudClient, ctx: &ContextResponse, remote: Option<&GitRemote>, yes: bool) -> Created {
    if !std::io::stdin().is_terminal() && !yes {
        return Created::None;
    }
    if ctx.organizations.is_empty() {
        eprintln!(
            "{}\n  Create one at {} first.",
            red("You're not a member of any organization yet."),
            bold("https://cloud.horus.sh")
        );
        return Created::None;
    }
    let ask = |q: &str, def: Option<&str>| -> String {
        if let (true, Some(d)) = (yes, def) {
            return d.to_string();
        }
        let prompt = match def {
            Some(d) if !d.is_empty() => format!("{q} ({d}): "),
            _ => format!("{q}: "),
        };
        let a = question(&prompt).unwrap_or_default().trim().to_string();
        if a.is_empty() { def.unwrap_or("").to_string() } else { a }
    };
    let run = async {
        // Org — auto-select when there's only one.
        let mut org = &ctx.organizations[0];
        if ctx.organizations.len() > 1 {
            println!("Organizations:");
            for (i, o) in ctx.organizations.iter().enumerate() {
                println!("  {}) {}", i + 1, o.slug);
            }
            let idx = ask("Org number", Some("1")).parse::<f64>().map(|n| n - 1.0).unwrap_or(f64::NAN);
            if idx >= 0.0 && idx.fract() == 0.0 {
                org = ctx.organizations.get(idx as usize).unwrap_or(org);
            }
        }
        let org_workspaces: Vec<_> = ctx.workspaces.iter().filter(|w| w.organization_id == org.id).collect();
        let repo_name = remote.map(|r| parse_repo_name(&r.remote_url)).unwrap_or_default();
        let ws_default = if repo_name.is_empty() { "default".to_string() } else { repo_name.clone() };
        let create_ws = |name: String| async move {
            let ws = client.create_workspace(&org.id, &name).await?;
            println!("{}", dim(&format!("Created workspace {}.", bold(&ws.slug))));
            Ok::<Ref, anyhow::Error>(Ref { id: ws.id, slug: ws.slug })
        };
        let workspace = if org_workspaces.is_empty() {
            create_ws(ask("New workspace name", Some(&ws_default))).await?
        } else {
            println!("Workspaces in {}:", bold(&org.slug));
            for (i, w) in org_workspaces.iter().enumerate() {
                println!("  {}) {}", i + 1, w.slug);
            }
            println!("  {}) + create a new workspace", org_workspaces.len() + 1);
            let pick = ask("Workspace number", Some("1")).parse::<f64>().unwrap_or(f64::NAN);
            if pick == (org_workspaces.len() + 1) as f64 {
                create_ws(ask("New workspace name", Some(&ws_default))).await?
            } else {
                let chosen = (pick >= 1.0 && pick.fract() == 0.0)
                    .then(|| org_workspaces.get(pick as usize - 1))
                    .flatten()
                    .unwrap_or(&org_workspaces[0]);
                Ref { id: chosen.id.clone(), slug: chosen.slug.clone() }
            }
        };
        // Project — default the name to the repo name.
        let proj_default = if repo_name.is_empty() { "project".to_string() } else { repo_name };
        let name = ask("Project name", Some(&proj_default));
        let project = client
            .create_project(
                &org.id,
                &workspace.id,
                &CreateProjectBody {
                    name,
                    slug: None,
                    remote_url: remote.map(|r| r.remote_url.clone()),
                    provider: remote.map(|r| infer_provider(&r.remote_url).to_string()),
                },
            )
            .await?;
        println!("{}", dim(&format!("Created project {}.", bold(&project.slug))));
        Ok::<ResolvedTriple, anyhow::Error>(ResolvedTriple {
            organization: Ref { id: org.id.clone(), slug: org.slug.clone() },
            workspace,
            project: Ref { id: project.id, slug: project.slug },
        })
    };
    match run.await {
        Ok(t) => Created::Triple(t),
        Err(err) => {
            report_cloud_error(&err);
            Created::Aborted
        }
    }
}

pub async fn run(args: &CloudArgs) -> Result<()> {
    let code = match &args.command {
        CloudCommand::Link(a) => run_cloud_link(a.target.as_deref(), a.yes).await?,
        CloudCommand::Unlink => run_cloud_unlink()?,
        CloudCommand::Status => run_cloud_status().await?,
        CloudCommand::Sync(a) => run_cloud_sync(a).await?,
    };
    exit(code)
}
