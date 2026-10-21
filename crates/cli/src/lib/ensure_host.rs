//! HOR-319 (Bug 2) — self-heal a down source-intelligence host. Port of
//! `packages/cli/src/lib/ensure-host.ts`.
//!
//! `horus investigate` used to exit 1 the moment `code.health()` failed. Instead we try to
//! restart a previously-indexed host at its configured port before giving up. This composes
//! the canonical host-lifecycle primitives owned by HOR-SOURCE (`horus_connectors::source`) —
//! it does NOT reimplement host management, and never performs first-time analysis.

use std::path::Path;

use horus_connectors::source::lifecycle::{
    assert_source_version_pinned, fetch_host_repo_path, find_free_port, is_analyzed, is_host_healthy,
    read_source_host_url, reconcile_spawned_host, remove_spawned_host_record, source_available, start_host,
    wait_for_host,
};

use crate::lib::format::{dim, green, red, yellow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureHostReason {
    SourceUnavailable,
    VersionMismatch,
    NotAnalyzed,
    BadUrl,
    NoFreePort,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureHostResult {
    pub ok: bool,
    /// The healthy host URL when ok.
    pub host_url: Option<String>,
    /// Why a self-heal attempt could not proceed, when not ok.
    pub reason: Option<EnsureHostReason>,
}

impl EnsureHostResult {
    fn ok(url: String) -> Self {
        Self { ok: true, host_url: Some(url), reason: None }
    }
    fn fail(reason: EnsureHostReason) -> Self {
        Self { ok: false, host_url: None, reason: Some(reason) }
    }
}

/// Parse the TCP port from a host URL (e.g. `http://127.0.0.1:8420` → 8420).
pub fn parse_host_port(host_url: &str) -> Option<u16> {
    url::Url::parse(host_url).ok()?.port()
}

/// Human-readable next step for why a self-heal attempt could not proceed.
pub fn ensure_host_reason_hint(reason: Option<EnsureHostReason>) -> &'static str {
    match reason {
        Some(EnsureHostReason::SourceUnavailable) => {
            "horus-source is not installed — install it: curl -fsSL https://horus.sh/install.sh | bash"
        }
        Some(EnsureHostReason::VersionMismatch) => {
            "the installed horus-source backend does not match the version Horus is pinned to — reinstall the pinned version (run `horus status` to see it)"
        }
        Some(EnsureHostReason::NotAnalyzed) => "this repo has not been indexed yet — run: horus init",
        Some(EnsureHostReason::BadUrl) => "the configured source host URL is not a valid URL",
        Some(EnsureHostReason::NoFreePort) => {
            "no free localhost port was available to start this repo’s own source host"
        }
        _ => "the host did not become healthy — run: horus init",
    }
}

/// Identity verdict for a source host relative to a target repo (HOR-421).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRepoVerdict {
    /// The host reports it serves THIS repo.
    Match,
    /// The host serves a DIFFERENT repo — grounding on it would investigate foreign code.
    Foreign,
    /// The host could not report its identity (unreachable / older backend).
    Unknown,
}

/// Node `path.resolve`: absolute + lexically normalised, no symlink resolution.
fn resolve(p: &str) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
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

/// HOR-421: does the source host at `host_url` serve `root`? `Unknown` is treated
/// conservatively by callers — not assumed a match, but never reclassified as foreign (which
/// could trigger a second host colliding on the same repo's single-writer store lock).
pub async fn verify_host_serves_repo(host_url: &str, root: &Path) -> HostRepoVerdict {
    match fetch_host_repo_path(host_url).await {
        None => HostRepoVerdict::Unknown,
        Some(served) if resolve(&served) == resolve(&root.to_string_lossy()) => HostRepoVerdict::Match,
        Some(_) => HostRepoVerdict::Foreign,
    }
}

/// Shared guard rails before spawning: backend installed, version pinned, repo analyzed.
async fn spawn_guard(root: &Path) -> Option<EnsureHostReason> {
    if !source_available().await {
        return Some(EnsureHostReason::SourceUnavailable);
    }
    if assert_source_version_pinned().await.is_err() {
        return Some(EnsureHostReason::VersionMismatch);
    }
    if !is_analyzed(root) {
        return Some(EnsureHostReason::NotAnalyzed);
    }
    None
}

/// HOR-421: resolve a host VERIFIED to serve `root` — never a foreign one — by reusing the
/// repo's own recorded host when healthy + matching, else spawning this repo's own host on a
/// FREE port (never the configured port, which a foreign host is occupying).
pub async fn ensure_own_source_host(root: &Path, timeout_ms: Option<u64>) -> EnsureHostResult {
    // 1) The repo's own recorded host, if it is up and genuinely serving this repo.
    if let Some(own) = read_source_host_url(root) {
        if is_host_healthy(&own).await && verify_host_serves_repo(&own, root).await == HostRepoVerdict::Match {
            return EnsureHostResult::ok(own);
        }
    }
    if let Some(reason) = spawn_guard(root).await {
        return EnsureHostResult::fail(reason);
    }
    // 2) Spawn on a free port.
    let Ok(port) = find_free_port(None, None).await else {
        return EnsureHostResult::fail(EnsureHostReason::NoFreePort);
    };
    let host_url = format!("http://127.0.0.1:{port}");
    let _ = start_host(root, port);
    if wait_for_host(&host_url, Some(timeout_ms.unwrap_or(20_000))).await {
        // Defensive: never return a host whose identity doesn't match what we just spawned.
        if verify_host_serves_repo(&host_url, root).await == HostRepoVerdict::Foreign {
            remove_spawned_host_record(root);
            return EnsureHostResult::fail(EnsureHostReason::Unhealthy);
        }
        reconcile_spawned_host(root, i64::from(port));
        return EnsureHostResult::ok(host_url);
    }
    remove_spawned_host_record(root);
    EnsureHostResult::fail(EnsureHostReason::Unhealthy)
}

/// HOR-319 + HOR-421: the single host-selection entry point for grounding an investigation.
/// Self-heals a down configured host, then VERIFIES it serves `root`; a foreign host is
/// rejected and this repo's OWN host is started on a free port instead — so the returned URL
/// may differ from `configured_url`. On failure the caller degrades to runtime-only.
pub async fn resolve_source_host_url(
    root: &Path,
    configured_url: &str,
    timeout_ms: Option<u64>,
    log: &dyn Fn(&str),
) -> EnsureHostResult {
    let healthy_url = if is_host_healthy(configured_url).await {
        Some(configured_url.to_string())
    } else {
        log(&yellow(&format!(
            "Source-intelligence host unreachable ({configured_url}) — attempting to start it…"
        )));
        let healed = ensure_source_host(root, configured_url, timeout_ms).await;
        match healed.host_url.filter(|_| healed.ok) {
            Some(url) => {
                log(&green(&format!("Source-intelligence host is up at {url}.")));
                Some(url)
            }
            None => {
                log(&dim(&format!("  {}", ensure_host_reason_hint(healed.reason))));
                None
            }
        }
    };
    let Some(healthy_url) = healthy_url else {
        return EnsureHostResult::fail(EnsureHostReason::Unhealthy);
    };

    // HOR-421 contamination guard: never ground on a host serving a DIFFERENT repo.
    if verify_host_serves_repo(&healthy_url, root).await != HostRepoVerdict::Foreign {
        return EnsureHostResult::ok(healthy_url);
    }
    log(&red(&format!(
        "Source-intelligence host at {healthy_url} is serving a DIFFERENT repository — refusing to ground this investigation on foreign code."
    )));
    let own = ensure_own_source_host(root, timeout_ms).await;
    if own.ok && own.host_url.is_some() {
        log(&green(&format!(
            "Started this repo's own source-intelligence host at {}.",
            own.host_url.as_deref().unwrap_or_default()
        )));
        return own;
    }
    log(&dim(&format!("  {}", ensure_host_reason_hint(own.reason))));
    EnsureHostResult::fail(own.reason.unwrap_or(EnsureHostReason::Unhealthy))
}

/// Make the host at `host_url` healthy, restarting it at the SAME port if it is down, so an
/// existing CodeProvider pointed at `host_url` keeps working. Only restarts an already-analyzed
/// repo; never triggers first-time analysis.
pub async fn ensure_source_host(root: &Path, host_url: &str, timeout_ms: Option<u64>) -> EnsureHostResult {
    // Maybe it recovered between the caller's health check and now.
    if is_host_healthy(host_url).await {
        return EnsureHostResult::ok(host_url.to_string());
    }
    // Never restart a drifted backend — mirror `horus init`'s guard so self-heal can't smuggle one in.
    if let Some(reason) = spawn_guard(root).await {
        return EnsureHostResult::fail(reason);
    }
    let Some(port) = parse_host_port(host_url) else {
        return EnsureHostResult::fail(EnsureHostReason::BadUrl);
    };
    let _ = start_host(root, port);
    if wait_for_host(host_url, Some(timeout_ms.unwrap_or(20_000))).await {
        // Point the ownership record at the backend's real server pid + bound port (HOR-409).
        reconcile_spawned_host(root, i64::from(port));
        return EnsureHostResult::ok(host_url.to_string());
    }
    // Never became healthy — drop the ownership record so `horus stop` doesn't chase a dead PID.
    remove_spawned_host_record(root);
    EnsureHostResult::fail(EnsureHostReason::Unhealthy)
}
