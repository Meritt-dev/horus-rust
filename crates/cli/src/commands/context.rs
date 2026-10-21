//! `horus context list` / `use` / `show` (HOR-226, per HOR-225). Port of
//! `packages/cli/src/commands/context.ts`.
//!
//! A "context" is where this repo's investigations are stored: `local` (default) or a cloud
//! `org/workspace/project`. The user selects a context — never a DB URL.

use anyhow::Result;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::cloud::api::{CloudError, ContextProject, ContextResponse};
use crate::lib::cloud::context_store::{is_cloud_active, read_cloud_config, write_cloud_config, CloudConfig, Ref};
use crate::lib::cloud::session::{authed_client, repo_root_or_cwd};
use crate::lib::format::{bold, dim, green, red, yellow};
use crate::lib::tty_selector::{is_interactive, select_search, SelectError};

pub struct ResolvedTriple {
    pub organization: Ref,
    pub workspace: Ref,
    pub project: Ref,
}

/// The `local` sentinel offered as the first pick in the context selector.
const LOCAL_CHOICE: &str = "local  ·  ~/.horus local Postgres";

/// Map an exit code to the command result (non-zero → silent exit; the message is printed).
pub fn exit(code: u8) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(SilentExit(code).into())
    }
}

/// Interactively pick an `org/workspace/project` triple (or `local`) from the accessible cloud
/// context. None when nothing is pickable / non-interactive (the caller requires an explicit
/// target). A cancelled prompt propagates as an error. Shared by `context use` and `cloud link`.
pub fn pick_context_target(ctx: &ContextResponse, include_local: bool, message: Option<&str>) -> Result<Option<String>> {
    let mut labels: Vec<String> = Vec::new();
    let mut target_by_label: Vec<(String, String)> = Vec::new();
    if include_local {
        labels.push(LOCAL_CHOICE.into());
        target_by_label.push((LOCAL_CHOICE.into(), "local".into()));
    }
    for project in &ctx.projects {
        let Some(triple) = triple_label(ctx, &project.id) else { continue };
        // Show the human project name alongside the slug triple; return the triple.
        let label = if !project.name.is_empty() && project.name != project.slug {
            format!("{triple}  ({})", project.name)
        } else {
            triple.clone()
        };
        if !target_by_label.iter().any(|(l, _)| *l == label) {
            target_by_label.push((label.clone(), triple));
        }
        labels.push(label);
    }
    if target_by_label.is_empty() || (include_local && target_by_label.len() == 1) {
        // Nothing to pick beyond `local` — let the caller handle the empty case.
        return Ok((include_local && target_by_label.len() == 1).then(|| "local".into()));
    }
    if !is_interactive() {
        return Ok(None);
    }
    match select_search(message.unwrap_or("Select a context for this repo"), &labels, Some(12)) {
        Ok(picked) => Ok(target_by_label.into_iter().find(|(l, _)| *l == picked).map(|(_, t)| t)),
        Err(SelectError::Exit(e)) => Err(e.into()),
        Err(SelectError::Other(_)) => Ok(None),
    }
}

/// Resolves `org/workspace/project` slugs against the user's accessible context.
pub fn resolve_triple(ctx: &ContextResponse, target: &str) -> Option<ResolvedTriple> {
    let parts: Vec<&str> = target.split('/').collect();
    let [org_slug, ws_slug, proj_slug] = parts[..] else { return None };
    let organization = ctx.organizations.iter().find(|o| o.slug == org_slug)?;
    let workspace = ctx.workspaces.iter().find(|w| w.slug == ws_slug && w.organization_id == organization.id)?;
    let project = ctx.projects.iter().find(|p| p.slug == proj_slug && p.workspace_id == workspace.id)?;
    Some(ResolvedTriple {
        organization: Ref { id: organization.id.clone(), slug: organization.slug.clone() },
        workspace: Ref { id: workspace.id.clone(), slug: workspace.slug.clone() },
        project: Ref { id: project.id.clone(), slug: project.slug.clone() },
    })
}

fn triple_label(ctx: &ContextResponse, project_id: &str) -> Option<String> {
    let project = ctx.projects.iter().find(|p| p.id == project_id)?;
    let ws = ctx.workspaces.iter().find(|w| w.id == project.workspace_id)?;
    let org = ctx.organizations.iter().find(|o| o.id == project.organization_id)?;
    Some(format!("{}/{}/{}", org.slug, ws.slug, project.slug))
}

/// A cloud config binding exactly the resolved org/workspace/project triple.
pub fn cloud_binding(resolved: ResolvedTriple) -> CloudConfig {
    CloudConfig {
        context: "cloud".into(),
        organization: Some(resolved.organization),
        workspace: Some(resolved.workspace),
        project: Some(resolved.project),
        repository: None,
        extra: Default::default(),
    }
}

pub async fn run_context_list() -> Result<u8> {
    let root = repo_root_or_cwd(None);
    let cfg = read_cloud_config(&root);
    let session = authed_client();
    let active_cloud = is_cloud_active(cfg.as_ref());

    println!("  {} STORAGE", bold(&format!("{:<44}", "CONTEXT")));
    let mark = |active: bool| if active { green("*") } else { " ".into() };
    println!("{} {:<44} {}", mark(!active_cloud), "local", dim("~/.horus local Postgres"));

    let Some(session) = session else {
        println!();
        println!("{}", dim(&format!("Run {} to see cloud contexts you can use.", bold("horus login"))));
        return Ok(0);
    };
    match session.client.context().await {
        Ok(ctx) => {
            for project in &ctx.projects {
                let Some(label) = triple_label(&ctx, &project.id) else { continue };
                let active = active_cloud && cfg.as_ref().and_then(|c| c.project.as_ref()).map(|p| &p.id) == Some(&project.id);
                println!("{} {:<44} {}", mark(active), label, dim("Horus Cloud"));
            }
            println!();
            println!("{}", dim("(* = active for this repo)"));
            Ok(0)
        }
        Err(err) => Ok(report_cloud_error(&err.into())),
    }
}

pub async fn run_context_use(target: Option<&str>) -> Result<u8> {
    let root = repo_root_or_cwd(None);
    let mut target = target.map(str::to_string);

    // No target → pick from the accessible cloud contexts (plus `local`). Requires login + a TTY.
    if target.as_deref().is_none_or(str::is_empty) {
        let Some(session) = authed_client() else {
            eprintln!(
                "{} Run {} first, or pass a target: {}.",
                red("Not logged in."),
                bold("horus login"),
                bold("horus context use local")
            );
            return Ok(1);
        };
        let ctx = match session.client.context().await {
            Ok(c) => c,
            Err(err) => return Ok(report_cloud_error(&err.into())),
        };
        let Some(picked) = pick_context_target(&ctx, true, None)? else {
            eprintln!(
                "{}\n  Pass a target explicitly: {} or {}.\n  Run {} to see what you can use.",
                red("No context selected."),
                bold("horus context use local"),
                bold("horus context use <org>/<workspace>/<project>"),
                bold("horus context list")
            );
            return Ok(1);
        };
        target = Some(picked);
    }
    let target = target.unwrap_or_default();

    if target == "local" {
        let mut cfg = read_cloud_config(&root).unwrap_or(CloudConfig {
            context: "local".into(),
            organization: None,
            workspace: None,
            project: None,
            repository: None,
            extra: Default::default(),
        });
        cfg.context = "local".into();
        write_cloud_config(&root, &cfg)?;
        println!("{} Context for this repo is now {}. {}", green("✓"), bold("local"), dim("(local data preserved)"));
        return Ok(0);
    }

    let Some(session) = authed_client() else {
        eprintln!("{}", red(&format!("Not logged in. Run {} first.", bold("horus login"))));
        return Ok(1);
    };
    let ctx = match session.client.context().await {
        Ok(c) => c,
        Err(err) => return Ok(report_cloud_error(&err.into())),
    };
    let Some(resolved) = resolve_triple(&ctx, &target) else {
        eprintln!(
            "{}\n  Ask an org admin for an invite, or run {} to see available projects.",
            red(&format!("You don't have access to {}.", bold(&target))),
            bold("horus context list")
        );
        return Ok(1);
    };
    // A project IS the repository/codebase (HOR-280); store the triple only (HOR-278).
    write_cloud_config(&root, &cloud_binding(resolved))?;
    println!("{} Context for this repo is now {} {}.", green("✓"), bold(&target), dim("(cloud)"));
    Ok(0)
}

/// `"just now"`, `"5m ago"`, `"3h ago"`, `"2d ago"`, or None for a missing/invalid date.
pub fn format_relative_time(iso: Option<&str>) -> Option<String> {
    let iso = iso.filter(|s| !s.is_empty())?;
    let then = chrono::DateTime::parse_from_rfc3339(iso).ok()?.timestamp_millis();
    let secs = ((chrono::Utc::now().timestamp_millis() - then) as f64 / 1000.0).round().max(0.0);
    if secs < 60.0 {
        return Some("just now".into());
    }
    let mins = (secs / 60.0).round();
    if mins < 60.0 {
        return Some(format!("{mins}m ago"));
    }
    let hours = (mins / 60.0).round();
    if hours < 24.0 {
        return Some(format!("{hours}h ago"));
    }
    Some(format!("{}d ago", (hours / 24.0).round()))
}

/// Sync-metadata lines for a cloud project, shared by `context show` + `cloud status`.
pub fn sync_meta_lines(project: &ContextProject) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(p) = project.provider.as_deref().filter(|p| !p.is_empty() && *p != "other") {
        lines.push(format!("{}    {p}", bold("Provider:")));
    }
    if let Some(r) = project.remote_url.as_deref().filter(|s| !s.is_empty()) {
        lines.push(format!("{}      {r}", bold("Remote:")));
    }
    if let Some(b) = project.default_branch.as_deref().filter(|s| !s.is_empty()) {
        lines.push(format!("{}      {b}", bold("Branch:")));
    }
    let synced = format_relative_time(project.last_synced_at.as_deref()).unwrap_or_else(|| dim("never"));
    lines.push(format!("{}   {synced}", bold("Last sync:")));
    lines
}

/// `horus context show` (HOR-278): the active context and, for a cloud context, the project's
/// sync metadata. Re-resolves the stored project against the live context (stale config must
/// never imply access).
pub async fn run_context_show() -> Result<u8> {
    let root = repo_root_or_cwd(None);
    let cfg = read_cloud_config(&root);
    let Some(cfg) = cfg.filter(|c| is_cloud_active(Some(c))) else {
        println!("{}    local", bold("Context:"));
        println!("{}    local Postgres {}", bold("Storage:"), dim("(~/.horus)"));
        println!(
            "{}",
            dim(&format!(
                "Tip:        {} then {} to use a cloud project.",
                bold("horus login"),
                bold("horus context use <org>/<workspace>/<project>")
            ))
        );
        return Ok(0);
    };
    let project_ref = cfg.project.clone().unwrap_or(Ref { id: String::new(), slug: String::new() });
    let slug = |r: &Option<Ref>| r.as_ref().map_or("undefined".to_string(), |r| r.slug.clone());
    let triple = format!("{}/{}/{}", slug(&cfg.organization), slug(&cfg.workspace), project_ref.slug);
    println!("{}    {triple}   {}", bold("Context:"), dim("(cloud)"));

    let Some(session) = authed_client() else {
        println!("{}    {}", bold("Account:"), dim("not logged in"));
        println!("{}", dim(&format!("Showing cached context. Run {} for live project + sync details.", bold("horus login"))));
        return Ok(0);
    };
    let ctx = match session.client.context().await {
        Ok(c) => c,
        Err(err) => {
            // Offline: the cached triple is still useful; the server stays the auth boundary.
            println!("{}    {}", bold("Account:"), session.auth.account.email);
            if err.is_offline() {
                println!("{}", dim("Offline — showing cached context; sync details unavailable."));
                return Ok(0);
            }
            return Ok(report_cloud_error(&err.into()));
        }
    };
    let Some(project) = ctx.projects.iter().find(|p| p.id == project_ref.id) else {
        // Stored ID resolves to nothing the caller can access → stale/lost-access config.
        println!("{}    {}", bold("Account:"), session.auth.account.email);
        eprintln!(
            "{}\n  Your access may have changed or the project was removed.\n  Run {} to see available projects, then {}.",
            yellow("This repo's stored project is no longer in your accessible context."),
            bold("horus context list"),
            bold("horus context use <org>/<workspace>/<project>")
        );
        return Ok(1);
    };
    let ws = ctx.workspaces.iter().find(|w| w.id == project.workspace_id);
    let org = ctx.organizations.iter().find(|o| o.id == project.organization_id);
    let suffix = match (ws, org) {
        (Some(ws), Some(org)) => format!("  ·  workspace {}  ·  org {}", ws.name, org.name),
        _ => String::new(),
    };
    println!("{}    {}{suffix}", bold("Project:"), project.name);
    for line in sync_meta_lines(project) {
        println!("{line}");
    }
    println!("{}    {}", bold("Account:"), session.auth.account.email);
    println!("{}    {triple} {}", bold("Sync to:"), dim("(horus cloud sync)"));
    Ok(0)
}

/// Print a cloud failure the way every cloud command does; returns the exit code (always 1).
pub fn report_cloud_error(err: &anyhow::Error) -> u8 {
    match err.downcast_ref::<CloudError>() {
        Some(CloudError::Offline(m)) => eprintln!("{}", red(m)),
        Some(CloudError::Http { status: 401, .. }) => eprintln!(
            "{} Run {} to continue. {}",
            red("Your session expired."),
            bold("horus login"),
            dim("(local mode still works)")
        ),
        _ => eprintln!("{}", red(&format!("Cloud request failed: {err}"))),
    }
    1
}

pub async fn run(args: &ContextArgs) -> Result<()> {
    let code = match &args.command {
        ContextCommand::List => run_context_list().await?,
        ContextCommand::Use { target } => run_context_use(target.as_deref()).await?,
        ContextCommand::Show => run_context_show().await?,
    };
    exit(code)
}
