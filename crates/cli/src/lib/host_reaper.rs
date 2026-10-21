//! HOR-364 — orphaned source-host reaper. Port of `packages/cli/src/lib/host-reaper.ts`.
//!
//! `horus hosts` only knows about REGISTERED projects. A `horus-source host --port N` process
//! whose owning record is gone — repo unregistered, host crashed/restarted, or a DUPLICATE
//! bound near a port another host already claims — is invisible to it, yet still holds memory +
//! a store lock. This finds such orphans by scanning for `horus-source host` processes whose
//! pid isn't recorded by any registered repo, and reaps them. Only processes whose argv
//! unmistakably matches a Horus source host are ever considered — we never signal an unrelated
//! process.

use std::collections::HashSet;
use std::process::Command;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningHost {
    pub pid: i64,
    pub port: i64,
}

/// Matches a `horus-source host --port <N>` argv (optional path prefix), capturing the port.
/// (The TS `(?=\s|$)` lookahead is a consuming `(?:\s|$)` here — only the first match is used.)
static HOST_ARGV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)(?:\S*/)?horus-source\s+host\s+--port(?:=|\s+)(\d+)(?:\s|$)").unwrap()
});

/// Parse `ps -axww -o pid=,args=` output into the running source-host processes. Pure.
pub fn parse_source_hosts(ps_stdout: &str) -> Vec<RunningHost> {
    let mut hosts = Vec::new();
    for line in ps_stdout.split('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(sp) = trimmed.find(' ') else { continue };
        let Ok(pid) = trimmed[..sp].parse::<i64>() else { continue };
        if pid <= 0 {
            continue;
        }
        let Some(m) = HOST_ARGV.captures(&trimmed[sp + 1..]) else { continue };
        let Ok(port) = m[1].parse::<i64>() else { continue };
        hosts.push(RunningHost { pid, port });
    }
    hosts
}

/// Pure: a running host whose pid is not claimed by any registered repo is an orphan.
/// Matching on pid (not port) catches a duplicate bound to a port another host already owns.
pub fn select_orphans(running: Vec<RunningHost>, claimed_pids: &HashSet<i64>) -> Vec<RunningHost> {
    running.into_iter().filter(|h| !claimed_pids.contains(&h.pid)).collect()
}

/// Discover running source-host processes via `ps` (best-effort; empty on any error).
pub async fn list_running_source_hosts() -> Vec<RunningHost> {
    let out = tokio::time::timeout(
        Duration::from_millis(5000),
        tokio::process::Command::new("ps").args(["-axww", "-o", "pid=,args="]).output(),
    )
    .await;
    match out {
        Ok(Ok(o)) if o.status.success() => parse_source_hosts(&String::from_utf8_lossy(&o.stdout)),
        _ => Vec::new(),
    }
}

/// Is `pid` alive? Signal 0 via `kill -0` (no `libc` dependency in the workspace).
/// EPERM means it exists but we can't signal it → treat as alive.
pub fn is_pid_alive(pid: i64) -> bool {
    match Command::new("kill").args(["-0", &pid.to_string()]).output() {
        Ok(o) => o.status.success() || String::from_utf8_lossy(&o.stderr).contains("not permitted"),
        Err(_) => false,
    }
}

/// A registered host as `horus hosts` sees it: a registry entry plus what we actually probed
/// about the process behind it.
#[derive(Debug, Clone)]
pub struct RegisteredHostState {
    pub name: String,
    pub host_url: Option<String>,
    pub pid: Option<i64>,
    pub port: Option<i64>,
    /// HTTP `/api/health` result.
    pub healthy: bool,
    /// Signal-0 liveness of the recorded pid (None when no pid is recorded).
    pub pid_alive: Option<bool>,
    /// Does the live host at `host_url` actually serve THIS entry's repo? None = identity
    /// unknown (host down, or an older backend) — treated as matching for back-compat.
    pub serves_repo: Option<bool>,
}

/// Is this registered host backed by a LIVE process? (HOR-389)
///
/// Authoritative signal is the HTTP health check — but a healthy port is NOT enough: the host
/// must serve this entry's repo, or be unable to report identity. Fallback: no host URL to
/// probe but a recorded pid that is still alive.
pub fn is_live_registered_host(h: &RegisteredHostState) -> bool {
    if h.healthy {
        return h.serves_repo != Some(false);
    }
    h.host_url.is_none() && h.pid_alive == Some(true)
}

/// Count DISTINCT live source-host PROCESSES among registered hosts (HOR-389): several registry
/// entries can resolve to the SAME process, so dedupe by pid, else port, else name.
pub fn count_distinct_live_hosts(hosts: &[RegisteredHostState]) -> usize {
    let mut seen = HashSet::new();
    for h in hosts {
        if !is_live_registered_host(h) {
            continue;
        }
        let key = match (h.pid, h.port) {
            (Some(pid), _) => format!("pid:{pid}"),
            (None, Some(port)) => format!("port:{port}"),
            _ => format!("name:{}", h.name),
        };
        seen.insert(key);
    }
    seen.len()
}

/// SIGTERM then escalate to SIGKILL; resolves true once the pid is gone.
pub async fn reap_pid(pid: i64, term_ms: Option<u64>, kill_ms: Option<u64>, poll_ms: Option<u64>) -> bool {
    let poll = Duration::from_millis(poll_ms.unwrap_or(200));
    for (signal, wait) in [("-TERM", term_ms.unwrap_or(4000)), ("-KILL", kill_ms.unwrap_or(3000))] {
        if let Ok(o) = Command::new("kill").args([signal, &pid.to_string()]).output() {
            if !o.status.success() && String::from_utf8_lossy(&o.stderr).contains("No such process") {
                return true; // already gone
            }
        }
        let deadline = Instant::now() + Duration::from_millis(wait);
        while Instant::now() < deadline {
            tokio::time::sleep(poll).await;
            if !is_pid_alive(pid) {
                return true;
            }
        }
    }
    !is_pid_alive(pid)
}
