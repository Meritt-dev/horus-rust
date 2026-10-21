//! `horus hosts` — list running source-intelligence hosts across all registered projects
//! (HOR-41), and surface/reap ORPHANED hosts that no registered repo owns (HOR-364).
//! Port of `packages/cli/src/commands/hosts.ts`.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use horus_core::read_registry;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red, yellow};
use crate::lib::host_reaper::{
    count_distinct_live_hosts, is_live_registered_host, is_pid_alive, list_running_source_hosts, reap_pid,
    select_orphans, RegisteredHostState,
};
use horus_connectors::source::lifecycle::{
    fetch_host_repo_path, is_host_healthy, read_source_host_pid, read_source_host_url, read_spawned_host,
};

struct HostRow {
    state: RegisteredHostState,
    root: String,
    live: bool,
}

pub async fn run(args: &HostsArgs) -> Result<()> {
    let registry = read_registry();
    let projects: Vec<(&String, &horus_core::RegistryEntry)> = registry.projects.iter().collect();

    // ── Registered hosts ────────────────────────────────────────────────────
    // Each entry is reconciled against the LIVE process behind it — an HTTP health probe plus,
    // as a fallback, a pid-liveness check — so stale registry entries don't masquerade as
    // running hosts (HOR-389).
    let mut rows: Vec<HostRow> = futures::future::join_all(projects.iter().map(|(name, entry)| async move {
        let root = Path::new(&entry.root);
        let host_url = read_source_host_url(root);
        let rec = read_source_host_pid(root);
        let pid = rec.as_ref().map(|r| r.pid).or_else(|| read_spawned_host(root).map(|s| s.pid));
        let port = host_url.as_deref().and_then(extract_port).or_else(|| rec.as_ref().and_then(|r| r.port));
        let healthy = match &host_url {
            Some(u) => is_host_healthy(u).await,
            None => false,
        };
        // Identity check (dogfood finding 5): the default port is shared across repos,
        // so "something healthy on the port" is NOT "this repo's host is running".
        let mut serves_repo = None;
        if let (true, Some(u)) = (healthy, &host_url) {
            serves_repo = fetch_host_repo_path(u).await.map(|served| resolve_path(&served) == resolve_path(&entry.root));
        }
        let pid_alive = pid.map(is_pid_alive);
        let state = RegisteredHostState { name: name.to_string(), host_url, pid, port, healthy, pid_alive, serves_repo };
        let live = is_live_registered_host(&state);
        HostRow { state, root: entry.root.clone(), live }
    }))
    .await;
    rows.sort_by(|a, b| b.live.cmp(&a.live).then_with(|| a.state.name.cmp(&b.state.name)));

    println!();
    let mut printed_any = false;
    for row in &rows {
        if row.state.host_url.is_none() {
            continue;
        }
        printed_any = true;
        let status = if row.live {
            green("● running")
        } else if row.state.healthy && row.state.serves_repo == Some(false) {
            yellow("● foreign — port serves another repo")
        } else {
            red("● stopped")
        };
        let port = row.state.port.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
        println!(
            "  {status}  {} port {:<6} {}",
            bold(&format!("{:<24}", row.state.name)),
            port,
            dim(&row.root)
        );
    }
    let no_host: Vec<&HostRow> = rows.iter().filter(|r| r.state.host_url.is_none()).collect();
    for row in &no_host {
        println!("  {}   {}", dim("○ no host"), dim(&row.state.name));
    }
    if printed_any || !no_host.is_empty() {
        println!();
    }

    // ── Orphan detection + reap (HOR-364) ────────────────────────────────────
    // A running `horus-source host` whose pid no registered repo records (crashed/restarted
    // host, unregistered repo, or a duplicate on an already-claimed port) is an orphan.
    let mut claimed_pids = HashSet::new();
    for (_, entry) in &projects {
        let root = Path::new(&entry.root);
        if let Some(hp) = read_source_host_pid(root) {
            claimed_pids.insert(hp.pid);
        }
        if let Some(sp) = read_spawned_host(root).filter(|s| s.pid != 0) {
            claimed_pids.insert(sp.pid);
        }
    }
    let orphans = select_orphans(list_running_source_hosts().await, &claimed_pids);

    let mut reap_failed = 0;
    if !orphans.is_empty() {
        println!(
            "{}",
            yellow(&format!("  ⚠ {} orphaned source host(s) — no registered repo owns them:", orphans.len()))
        );
        for o in &orphans {
            println!("{}", dim(&format!("      pid {}  port {}", o.pid, o.port)));
        }
        if args.reap {
            let mut reaped = 0;
            for o in &orphans {
                if reap_pid(o.pid, None, None, None).await {
                    reaped += 1;
                    println!("  {} reaped pid {} {}", green("✓"), o.pid, dim(&format!("(port {})", o.port)));
                } else {
                    reap_failed += 1;
                    println!("{}", red(&format!("  ✗ could not stop pid {} (port {})", o.pid, o.port)));
                }
            }
            println!("{}", dim(&format!("  Reaped {reaped}/{} orphan(s).", orphans.len())));
        } else {
            println!("{}", dim("  Run `horus hosts --reap` to stop them."));
        }
        println!();
    }

    if projects.is_empty() && orphans.is_empty() {
        println!("{}", dim("No registered projects. Run `horus init` in a repo first."));
        return Ok(());
    }
    if !printed_any && orphans.is_empty() {
        println!("{}", dim("No source-intelligence hosts found. Run `horus init` to start one."));
        return Ok(());
    }

    // Count DISTINCT live processes, not registry rows — many entries can resolve to one process
    // (e.g. a shared port), which is what produced the inflated "40 hosts running" (HOR-389).
    let states: Vec<RegisteredHostState> = rows.iter().map(|r| r.state.clone()).collect();
    let running = count_distinct_live_hosts(&states);
    let orphan_note = if orphans.is_empty() { String::new() } else { format!(" · {} orphan(s)", orphans.len()) };
    println!(
        "{}",
        dim(&format!(
            "{running} running{orphan_note} · horus hosts --reap to clear orphans · horus stop --all to stop everything"
        ))
    );
    if reap_failed > 0 {
        return Err(SilentExit(1).into());
    }
    Ok(())
}

/// Node `path.resolve`: absolute against cwd, `.`/`..` folded lexically, no symlink resolution.
fn resolve_path(p: &str) -> std::path::PathBuf {
    use std::path::Component;
    let abs = std::env::current_dir().unwrap_or_default().join(p);
    let mut out = std::path::PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn extract_port(host_url: &str) -> Option<i64> {
    url::Url::parse(host_url).ok()?.port().map(i64::from)
}
