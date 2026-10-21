//! `horus stop` — stop the source-intelligence host(s) spawned by Horus for the current repo
//! (HOR-41). Port of `packages/cli/src/commands/stop.ts`.
//!
//! Safety model:
//!  1. Read `.horus/spawned-host.json` (written by `start_host` at spawn time).
//!  2. Verify the PID is genuinely THIS repo's `horus-source host` — argv matches
//!     `horus-source host --port <port>`, OR (port-fallback, HOR-409) it is a host whose
//!     identity the backend's own `source/host.json` corroborates on pid + bound port + repo.
//!  3. Guard against PID reuse: compare `ps etime` against the recorded startedAt (±60 s).
//!  4. Only then SIGTERM (escalating to SIGKILL, HOR-364).
//!  5. Remove the spawned-host record on success.
//!
//! No fallback to an unowned lsof-discovered PID — we never signal a process we cannot prove
//! Horus spawned.

use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::Result;
use horus_connectors::source::lifecycle::{
    is_host_healthy, read_source_host_pid, read_source_host_url, read_spawned_host,
};
use horus_core::{find_repo_root, read_registry, HORUS_DIR};
use regex::Regex;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red};

const SPAWNED_HOST_FILE: &str = "spawned-host.json";
/// Tolerated drift between recorded start time and measured elapsed time (seconds).
const START_TIME_TOLERANCE_S: i64 = 60;
/// How long to wait after SIGTERM / SIGKILL for the process to exit, and the poll interval.
const STOP_WAIT_MS: u64 = 5_000;
const STOP_KILL_WAIT_MS: u64 = 3_000;
const STOP_POLL_MS: u64 = 200;

pub async fn run(args: &StopArgs) -> Result<()> {
    let code = run_stop(args.all).await;
    if code != 0 {
        return Err(SilentExit(code).into());
    }
    Ok(())
}

pub async fn run_stop(all: bool) -> u8 {
    if all {
        return stop_all().await;
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    let root = find_repo_root(&cwd).unwrap_or(cwd);
    let Some(host_url) = read_source_host_url(&root) else {
        println!("{}", dim("No source-intelligence host found for this repo (.horus/source/host.json absent)."));
        return 0;
    };
    stop_host(&root.to_string_lossy(), &host_url).await
}

async fn stop_host(root: &str, host_url: &str) -> u8 {
    let root_path = Path::new(root);
    let Some(port) = extract_port(host_url) else {
        eprintln!("{}", red(&format!("Cannot determine port from host URL: {host_url}")));
        return 1;
    };

    if !is_host_healthy(host_url).await {
        // A failing /api/health does NOT prove the process is gone: a host can crash mid-index
        // yet keep its port + store lock. Only declare "already stopped" when we own no
        // still-running process; otherwise terminate the stuck host (identity still verified).
        let owned = read_spawned_host(root_path);
        let wrapper_alive = match &owned {
            Some(o) => get_process_info(o.pid).await.is_some(),
            None => false,
        };
        if !wrapper_alive {
            // The wrapper is gone, but the detached real server (source/host.json) can outlive
            // it and keep the port held. Stop it before concluding the host is down.
            let res = stop_backend_server_pid(root, port).await;
            if res == BackendStop::Failed {
                return 1;
            }
            if res != BackendStop::Stopped {
                println!("{}", dim(&format!("Host {host_url} is already stopped.")));
            }
            cleanup_spawned_record(root_path);
            return 0;
        }
        println!(
            "{}",
            dim(&format!(
                "Host {host_url} is unreachable but pid {} is still running — terminating a stuck host.",
                owned.as_ref().map_or(0, |o| o.pid)
            ))
        );
    }

    let Some(spawned) = read_spawned_host(root_path) else {
        eprintln!(
            "{}",
            red(&format!(
                "No ownership record found (.horus/{SPAWNED_HOST_FILE} absent). Horus will not stop a host it did not spawn."
            ))
        );
        return 1;
    };

    // --- validate record structure before using any value from it ---
    if let Some(err) = validate_spawned_record(spawned.pid, spawned.port, &spawned.root, &spawned.started_at) {
        eprintln!("{}", red(&format!("Ownership record is malformed: {err}. Aborting for safety.")));
        return 1;
    }
    if spawned.port != port {
        eprintln!(
            "{}",
            red(&format!(
                "Ownership record port ({}) does not match host URL port ({port}). Record may be stale.",
                spawned.port
            ))
        );
        return 1;
    }
    if spawned.root != root {
        eprintln!(
            "{}",
            red(&format!(
                "Ownership record root ({}) does not match resolved root ({root}). Record may be stale.",
                spawned.root
            ))
        );
        return 1;
    }

    // --- verify process identity ---
    let Some(info) = get_process_info(spawned.pid).await else {
        // The wrapper exited between the health check and here — the detached backend may
        // still be alive, so try it before reporting success.
        let res = stop_backend_server_pid(root, port).await;
        if res == BackendStop::Failed {
            return 1;
        }
        if res != BackendStop::Stopped {
            println!("{}", dim(&format!("Process pid {} is no longer running — already stopped.", spawned.pid)));
        }
        cleanup_spawned_record(root_path);
        return 0;
    };

    if !is_own_host_process(spawned.pid, port, root, &info.args) {
        let got: String = info.args.chars().take(120).collect();
        eprintln!(
            "{}",
            red(&format!(
                "Pid {} args do not match \"horus-source host --port {port}\". Got: \"{got}\". Aborting for safety.",
                spawned.pid
            ))
        );
        return 1;
    }

    // Elapsed-time check: guard against PID reuse. validate_spawned_record guarantees a valid
    // past startedAt.
    let start_ms = parse_date_ms(&spawned.started_at).unwrap_or(0);
    let recorded_age_s = ((chrono::Utc::now().timestamp_millis() - start_ms) as f64 / 1000.0).round() as i64;
    let Some(etime) = info.etime_seconds else {
        eprintln!("{}", red(&format!("Could not read elapsed time for pid {}. Aborting for safety.", spawned.pid)));
        return 1;
    };
    if (etime - recorded_age_s).abs() > START_TIME_TOLERANCE_S {
        eprintln!(
            "{}",
            red(&format!(
                "Pid {} age mismatch: record says ~{recorded_age_s}s, process reports {etime}s elapsed. Possible PID reuse — aborting for safety.",
                spawned.pid
            ))
        );
        return 1;
    }

    // SIGTERM, then escalate to SIGKILL — a host that ignores SIGTERM must not keep the port.
    match terminate_pid(spawned.pid).await {
        Err(e) => {
            eprintln!("{}", red(&format!("Failed to signal pid {}: {e}", spawned.pid)));
            return 1;
        }
        Ok(false) => {
            eprintln!(
                "{}",
                red(&format!("Host pid {} did not exit even after SIGKILL — could not reclaim the port.", spawned.pid))
            );
            return 1;
        }
        Ok(true) => {}
    }
    println!(
        "{} Stopped source-intelligence host {} for {root}",
        green("✓"),
        dim(&format!("(pid {}, port {port})", spawned.pid))
    );

    // The detached backend server can be a separate, still-listening pid — reap it too.
    if stop_backend_server_pid(root, port).await == BackendStop::Failed {
        return 1;
    }
    cleanup_spawned_record(root_path);
    0
}

/// `horus-source host --port <port>` argv matcher: optional path prefix, ordered tokens, and
/// the port followed by whitespace/EOL (so 8420 ≠ 84200). The TS `(?=\s|$)` lookahead is a
/// consuming group here (no lookahead in `regex`); only `is_match` is used, so equivalent.
fn host_argv_regex(port: i64) -> Regex {
    Regex::new(&format!(r"(?:^|\s)(?:\S*/)?horus-source\s+host\s+--port(?:=|\s+){port}(?:\s|$)")).unwrap()
}

static HOST_ARGV_ANY_PORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)(?:\S*/)?horus-source\s+host\s+--port(?:=|\s+)\d+(?:\s|$)").unwrap());

/// Node `path.resolve` (lexical).
fn resolve_path(p: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for c in std::env::current_dir().unwrap_or_default().join(p).components() {
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

/// Is `pid` (argv `args`) THIS repo's source host on the resolved (bound) `port`? Fast path:
/// exact argv. Port-fallback path (HOR-409): any-port host argv AND the backend's own record
/// corroborates this pid serving THIS repo on `port`.
fn is_own_host_process(pid: i64, port: i64, root: &str, args: &str) -> bool {
    if host_argv_regex(port).is_match(args) {
        return true;
    }
    if !HOST_ARGV_ANY_PORT.is_match(args) {
        return false;
    }
    match read_source_host_pid(Path::new(root)) {
        Some(rec) => {
            rec.pid == pid
                && rec.port == Some(port)
                && !rec.repo_path.is_empty()
                && resolve_path(&rec.repo_path) == resolve_path(root)
        }
        None => false,
    }
}

/// Remove the spawn-wrapper ownership record. Best-effort; a missing file is benign.
fn cleanup_spawned_record(root: &Path) {
    let _ = std::fs::remove_file(root.join(HORUS_DIR).join(SPAWNED_HOST_FILE));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendStop {
    Stopped,
    Failed,
    None,
}

/// Stop the detached backend server recorded in `.horus/source/host.json`, if still alive and
/// provably ours (argv + record port/repo match).
async fn stop_backend_server_pid(root: &str, port: i64) -> BackendStop {
    let Some(rec) = read_source_host_pid(Path::new(root)) else { return BackendStop::None };
    // Only act when the backend's own record agrees on port and repo.
    if rec.port.is_some_and(|p| p != port) {
        return BackendStop::None;
    }
    if !rec.repo_path.is_empty() && rec.repo_path != root {
        return BackendStop::None;
    }
    let Some(info) = get_process_info(rec.pid).await else { return BackendStop::None };

    if !is_own_host_process(rec.pid, port, root, &info.args) {
        // Alive but NOT our host — the pid was reused after our host exited. Don't signal it
        // and don't count it as a failure (HOR-378).
        println!(
            "{}",
            dim(&format!(
                "Host pid {} is now an unrelated process (stale source/host.json / PID reuse) — host already gone.",
                rec.pid
            ))
        );
        return BackendStop::None;
    }

    match terminate_pid(rec.pid).await {
        Err(e) => {
            eprintln!("{}", red(&format!("Failed to signal pid {}: {e}", rec.pid)));
            BackendStop::Failed
        }
        Ok(false) => {
            eprintln!(
                "{}",
                red(&format!("Host pid {} did not exit even after SIGKILL — could not reclaim the port.", rec.pid))
            );
            BackendStop::Failed
        }
        Ok(true) => {
            println!(
                "{} Stopped source-intelligence host {} for {root}",
                green("✓"),
                dim(&format!("(pid {}, port {port})", rec.pid))
            );
            BackendStop::Stopped
        }
    }
}

async fn stop_all() -> u8 {
    let registry = read_registry();
    if registry.projects.is_empty() {
        println!("{}", dim("No registered projects."));
        return 0;
    }
    let (mut stopped, mut failed) = (0, 0);
    for (name, entry) in &registry.projects {
        let root = Path::new(&entry.root);
        let Some(host_url) = read_source_host_url(root) else { continue };
        // Something to stop if healthy OR we still hold a record (wrapper or backend).
        let healthy = is_host_healthy(&host_url).await;
        if !healthy && read_spawned_host(root).is_none() && read_source_host_pid(root).is_none() {
            continue;
        }
        println!("  Stopping {} {}", bold(name), dim(&format!("({host_url})")));
        if stop_host(&entry.root, &host_url).await == 0 {
            stopped += 1;
        } else {
            failed += 1;
        }
    }
    if stopped == 0 && failed == 0 {
        println!("{}", dim("No running source-intelligence hosts found."));
    } else {
        let failed_note = if failed > 0 { red(&format!(", {failed} failed")) } else { String::new() };
        println!("\nStopped {stopped} host(s){failed_note}.");
    }
    u8::from(failed > 0)
}

/// Structural validation of the spawned-host record; Some(error) when invalid.
fn validate_spawned_record(pid: i64, port: i64, root: &str, started_at: &str) -> Option<String> {
    if pid <= 0 {
        return Some(format!("invalid pid {pid}"));
    }
    if port <= 0 || port > 65535 {
        return Some(format!("invalid port {port}"));
    }
    if root.is_empty() {
        return Some("root is empty or not a string".into());
    }
    if started_at.is_empty() {
        return Some("startedAt is missing or not a string".into());
    }
    let Some(ts) = parse_date_ms(started_at) else {
        return Some(format!("startedAt is not a valid date: \"{started_at}\""));
    };
    if ts > chrono::Utc::now().timestamp_millis() {
        return Some(format!("startedAt is in the future: \"{started_at}\""));
    }
    None
}

fn parse_date_ms(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|t| t.timestamp_millis())
}

/// SIGTERM, wait, escalate to SIGKILL. Ok(true) once the process is gone; Err only on an
/// unexpected (non-ESRCH) signal error.
async fn terminate_pid(pid: i64) -> Result<bool, String> {
    for (signal, wait_ms) in [("-TERM", STOP_WAIT_MS), ("-KILL", STOP_KILL_WAIT_MS)] {
        match Command::new("kill").args([signal, &pid.to_string()]).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                if err.contains("No such process") {
                    return Ok(true); // already gone
                }
                return Err(err);
            }
            Err(e) => return Err(e.to_string()),
        }
        let deadline = Instant::now() + Duration::from_millis(wait_ms);
        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(STOP_POLL_MS)).await;
            if get_process_info(pid).await.is_none() {
                return Ok(true);
            }
        }
    }
    Ok(get_process_info(pid).await.is_none())
}

struct ProcessInfo {
    args: String,
    /// None when `etime` could not be read/parsed (TS NaN) — callers abort for safety.
    etime_seconds: Option<i64>,
}

async fn ps_field(pid: i64, field: &str) -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_millis(3000),
        tokio::process::Command::new("ps").args(["-p", &pid.to_string(), "-o", field]).output(),
    )
    .await
    .ok()?
    .ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// argv + elapsed time for a PID; None ONLY when the process does not exist (no argv).
/// Uses `etime` (portable), not `etimes` (Linux-only — errors on macOS).
async fn get_process_info(pid: i64) -> Option<ProcessInfo> {
    let args = ps_field(pid, "args=").await.filter(|a| !a.is_empty())?;
    let etime_seconds = ps_field(pid, "etime=").await.and_then(|e| parse_etime_seconds(&e));
    Some(ProcessInfo { args, etime_seconds })
}

static ETIME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$").unwrap());

/// Parse a ps `etime` field (`[[dd-]hh:]mm:ss`) to seconds.
fn parse_etime_seconds(etime: &str) -> Option<i64> {
    let m = ETIME.captures(etime)?;
    let n = |i: usize| m.get(i).map_or(Some(0), |g| g.as_str().parse::<i64>().ok());
    Some(n(1)? * 86400 + n(2)? * 3600 + n(3)? * 60 + n(4)?)
}

fn extract_port(host_url: &str) -> Option<i64> {
    url::Url::parse(host_url).ok()?.port().map(i64::from)
}
