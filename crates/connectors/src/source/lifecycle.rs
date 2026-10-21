//! Source-intelligence process lifecycle (HOR-37) — analyze a repo and host its graph.
//!
//! This shells out to the `horus-source` CLI for LIFECYCLE only (analyze / host), which is
//! explicitly allowed (like the git connector). The "no CLI shell-out" rule applies to
//! QUERIES — those still go over HTTP via `SourceHttpClient`.
//!
//! Files read/written here (`.horus/source/host.json`, `.horus/source/meta.json`,
//! `.horus/spawned-host.json`, `.horus/source-host.log`) are shared with the TS CLI and
//! must keep the same names, formats and key order.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use horus_core::{redact_secrets, PINNED_SOURCE_VERSION, SOURCE_PIN_ENFORCED};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const SOURCE_BINARY: &str = "horus-source";

/// Run `horus-source --version` with a 5s cap; `Some(stdout)` on exit 0.
async fn run_version() -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(SOURCE_BINARY)
            .arg("--version")
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Resolve the source-intelligence binary, or None if it is not on PATH.
pub async fn resolve_source_bin() -> Option<&'static str> {
    run_version().await.map(|_| SOURCE_BINARY)
}

/// Is the `horus-source` binary on PATH?
pub async fn source_available() -> bool {
    resolve_source_bin().await.is_some()
}

/// Resolve the active source-intelligence binary name, or None if not installed.
pub async fn get_active_source_bin() -> Option<&'static str> {
    resolve_source_bin().await
}

/// Return the installed `horus-source` version string (e.g. "1.0.1"), or None if the
/// binary is not on PATH or the version cannot be parsed.
pub async fn get_source_version() -> Option<String> {
    let stdout = run_version().await?;
    let re = regex::Regex::new(r"(\d+\.\d+\.\d+)").unwrap();
    re.captures(stdout.trim()).map(|c| c[1].to_string())
}

/// Raised when the installed `horus-source` backend does not match `PINNED_SOURCE_VERSION`.
/// Carries both versions so callers can render an actionable, copy-pasteable remediation.
#[derive(Debug, thiserror::Error)]
#[error("horus-source {installed} is installed but Horus is pinned to {pinned}. A drifted backend builds a graph this CLI cannot map and can corrupt the index (e.g. duplicate-primary-key failures during \"Running initial index\").\n  Fix it — run `horus update` to install the backend bundled with this CLI.")]
pub struct SourceVersionMismatchError {
    pub installed: String,
    pub pinned: String,
}

/// Assert the installed backend matches the pinned version BEFORE we let it analyze a repo
/// or host its graph (architecture.md §1, risk R4). A version that cannot be read/parsed is
/// allowed through (treated as "unknown") — we only block on a *known* mismatch.
pub async fn assert_source_version_pinned() -> Result<(), SourceVersionMismatchError> {
    if !SOURCE_PIN_ENFORCED {
        return Ok(()); // unbundled dev run — no meaningful pin
    }
    if let Some(installed) = get_source_version().await {
        if installed != PINNED_SOURCE_VERSION {
            return Err(SourceVersionMismatchError { installed, pinned: PINNED_SOURCE_VERSION.to_string() });
        }
    }
    Ok(())
}

/// Has the repo been analyzed? Checks `.horus/source/`.
pub fn is_analyzed(root: &Path) -> bool {
    root.join(".horus").join("source").exists()
}

/// Active source-storage backend the CLI expects on disk. Mirrors horus-source's
/// `factory.DEFAULT_BACKEND` (SQLite since HOR-392), overridable for parity with the backend
/// env switch. Used to detect a legacy/mismatched store on the 2.0 upgrade path (HOR-433).
fn current_store_backend() -> String {
    std::env::var("HORUS_SOURCE_STORAGE_BACKEND")
        .unwrap_or_else(|_| "sqlite".to_string())
        .trim()
        .to_lowercase()
}

#[derive(Debug, Clone, Default)]
struct SourceMetaStats {
    symbols: Option<i64>,
    embeddings: Option<i64>,
}

#[derive(Debug, Clone, Default)]
struct SourceMeta {
    store_backend: Option<String>,
    embeddings_complete: Option<bool>,
    structural_complete: Option<bool>,
    /// Analysis-capability stamp (D6) — the traversal capabilities the host had when it wrote this index.
    capability_version: Option<f64>,
    stats: Option<SourceMetaStats>,
}

/// Read `.horus/source/meta.json`, or None when absent/unreadable.
fn read_source_meta(root: &Path) -> Option<SourceMeta> {
    let raw = fs::read_to_string(root.join(".horus").join("source").join("meta.json")).ok()?;
    let j: Value = serde_json::from_str(&raw).ok()?;
    let j = j.as_object()?;
    let stats = j.get("stats").and_then(Value::as_object).map(|s| SourceMetaStats {
        symbols: s.get("symbols").and_then(Value::as_i64),
        embeddings: s.get("embeddings").and_then(Value::as_i64),
    });
    Some(SourceMeta {
        store_backend: j.get("store_backend").and_then(Value::as_str).map(|s| s.to_lowercase()),
        embeddings_complete: j.get("embeddings_complete").and_then(Value::as_bool),
        structural_complete: j.get("structural_complete").and_then(Value::as_bool),
        capability_version: j.get("capability_version").and_then(Value::as_f64),
        stats,
    })
}

/// Whether the on-disk index is structurally complete but its embeddings are still warming
/// (B1.4 degraded mode). Read from the DURABLE meta — `structural_complete: true` with
/// `embeddings_complete: false` — not the host's transient `indexing` runtime flag, which
/// briefly reads false between the structural phase finishing and the embedding phase
/// starting (that race made the "warming up" notice flaky on large repos, dogfood 0.21.3).
pub fn index_embeddings_pending(root: &Path) -> bool {
    match read_source_meta(root) {
        Some(m) => m.structural_complete == Some(true) && m.embeddings_complete == Some(false),
        None => false,
    }
}

/// Whether the on-disk index was built by a host below the current analysis capability
/// (D6). An index with no stamp at all (pre-D6 host) is treated as capability 0 → stale.
/// Returns false when there is no index/meta so callers only nudge on a real, out-of-date index.
pub fn index_capability_stale(root: &Path, expected: u32) -> bool {
    match read_source_meta(root) {
        Some(m) => m.capability_version.unwrap_or(0.0) < expected as f64,
        None => false,
    }
}

/// Whether the index has usable semantic vectors (mirror of freshness.semanticSearchReady).
fn meta_has_embeddings(meta: &SourceMeta) -> bool {
    if meta.embeddings_complete == Some(false) {
        return false;
    }
    let embeddings = meta.stats.as_ref().and_then(|s| s.embeddings).unwrap_or(0);
    let symbols = meta.stats.as_ref().and_then(|s| s.symbols).unwrap_or(0);
    !(symbols > 0 && embeddings == 0)
}

/// Whether an existing on-disk index is stale/legacy/incompatible and must be RE-analyzed
/// rather than reused (HOR-433). Returns a human-readable reason, or None when the index is
/// healthy and reusable.
///
/// Intentionally CONSERVATIVE: only a genuinely broken/legacy store triggers a re-analyze:
///   - a legacy `.horus/source/kuzu` store while the active backend is SQLite,
///   - a meta `store_backend` stamp that differs from the active backend,
///   - an index that serves no semantic vectors (symbols present but 0 embeddings, or an
///     explicit `embeddings_complete: false`) WITHOUT a structural-complete marker.
/// An absent `store_backend` stamp alone is NOT treated as stale.
pub fn index_needs_reanalyze(root: &Path) -> Option<String> {
    if !is_analyzed(root) {
        return None; // "not analyzed" is handled by callers, not "stale"
    }
    let current = current_store_backend();

    // (a) Legacy KùzuDB store present while we expect SQLite: the active store is empty/wrong.
    if current != "kuzu" && root.join(".horus").join("source").join("kuzu").exists() {
        return Some("legacy KùzuDB store present".to_string());
    }

    let meta = read_source_meta(root)?; // unreadable meta — don't blindly force a re-index

    // (b) Store-backend stamp mismatch (a stamped index written by a different backend).
    if let Some(sb) = meta.store_backend.as_deref().filter(|s| !s.is_empty()) {
        if sb != current {
            return Some(format!("store backend changed ({sb} -> {current})"));
        }
    }

    // (c) The index serves no semantic vectors.
    if !meta_has_embeddings(&meta) {
        // Carve-out (B1.1): a STRUCTURAL-COMPLETE index with embeddings still pending is NOT
        // stale — the host resumes embeddings in the background (search degrades to FTS-only).
        if meta.structural_complete == Some(true) {
            return None;
        }
        return Some("index has no semantic embeddings (symbols present but 0 vectors)".to_string());
    }
    None
}

/// Base analyze timeout: 15 min covers the structural phase of most repos (B1.3).
const BASE_ANALYZE_TIMEOUT_MS: u64 = 900_000;
/// Hard ceiling so a runaway analyze can never hang `horus init` indefinitely.
const MAX_ANALYZE_TIMEOUT_MS: u64 = 3_600_000;
/// Repos up to this file count use the base cap; larger ones scale linearly.
const ANALYZE_BASELINE_FILES: u64 = 5_000;
/// Linear headroom per file above the baseline, for very large monorepos.
const ANALYZE_TIMEOUT_PER_FILE_MS: u64 = 15;

/// Directories excluded from the pre-walk file count (vendored / generated / VCS).
const ANALYZE_COUNT_SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", ".horus", "dist", "build", "out", "target", "vendor", ".venv", "venv",
    "__pycache__", ".next", ".turbo", "coverage", ".cache",
];

/// Cheap, bounded pre-walk that counts source files under `root` to size the analyze
/// timeout. Skips vendored/generated/VCS dirs and dot-dirs, and bails at `limit`.
/// Best-effort — unreadable dirs are skipped.
pub fn count_repo_files(root: &Path, limit: Option<u64>) -> u64 {
    let limit = limit.unwrap_or(200_000);
    let skip: HashSet<&str> = ANALYZE_COUNT_SKIP_DIRS.iter().copied().collect();
    let mut count = 0u64;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let name = e.file_name();
            let name = name.to_string_lossy();
            if ft.is_dir() {
                if skip.contains(name.as_ref()) || name.starts_with('.') {
                    continue;
                }
                stack.push(e.path());
            } else if ft.is_file() {
                count += 1;
                if count >= limit {
                    return count;
                }
            }
        }
    }
    count
}

/// Resolve the wall-clock timeout (ms) for `horus-source analyze` on `root`.
///
/// Priority: an explicit `HORUS_ANALYZE_TIMEOUT_MS` env override (positive integer) wins;
/// otherwise the base cap is scaled up by a cheap file-count pre-walk for large monorepos
/// and clamped to `MAX_ANALYZE_TIMEOUT_MS`.
pub fn resolve_analyze_timeout_ms(root: &Path) -> u64 {
    if let Ok(raw) = std::env::var("HORUS_ANALYZE_TIMEOUT_MS") {
        if !raw.trim().is_empty() {
            if let Ok(n) = raw.trim().parse::<f64>() {
                if n.is_finite() && n > 0.0 {
                    return n.floor() as u64;
                }
            }
        }
    }
    let files = count_repo_files(root, None);
    if files <= ANALYZE_BASELINE_FILES {
        return BASE_ANALYZE_TIMEOUT_MS;
    }
    let scaled = BASE_ANALYZE_TIMEOUT_MS + (files - ANALYZE_BASELINE_FILES) * ANALYZE_TIMEOUT_PER_FILE_MS;
    scaled.min(MAX_ANALYZE_TIMEOUT_MS)
}

pub const SOURCE_NOT_FOUND_MESSAGE: &str =
    "horus-source not found on PATH. Install it: curl -fsSL https://horus.sh/install.sh | bash";

/// Run `horus-source analyze . --defer-embeddings` in the repo. Errors carry the REAL cause
/// (HOR-381): the timeout, or horus-source's own (redacted) stderr tail.
pub async fn analyze_repo(root: &Path) -> anyhow::Result<()> {
    let bin = resolve_source_bin().await.ok_or_else(|| anyhow::anyhow!(SOURCE_NOT_FOUND_MESSAGE))?;
    let timeout_ms = resolve_analyze_timeout_ms(root);
    // --defer-embeddings: return the moment the STRUCTURAL index is built (search / explain /
    // blast-radius work now); the host resumes embeddings in the background (B1.1).
    let mut child = tokio::process::Command::new(bin)
        .args(["analyze", ".", "--defer-embeddings"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stderr_pipe = child.stderr.take();
    let stdout_pipe = child.stdout.take();
    let drain = async {
        use tokio::io::AsyncReadExt;
        let mut err = Vec::new();
        let mut out = Vec::new();
        if let Some(mut p) = stderr_pipe {
            let _ = p.read_to_end(&mut err).await;
        }
        if let Some(mut p) = stdout_pipe {
            let _ = p.read_to_end(&mut out).await;
        }
        err
    };
    let (status, stderr) = match tokio::time::timeout(Duration::from_millis(timeout_ms), async {
        let (stderr, status) = tokio::join!(drain, child.wait());
        (status, stderr)
    })
    .await
    {
        Ok((status, stderr)) => (Some(status?), stderr),
        Err(_) => {
            let _ = child.kill().await;
            (None, Vec::new())
        }
    };
    // stderr can print env-derived URLs (credential-bearing connection strings) — redact
    // BEFORE capping so a conn string straddling the cut can't lose its scheme prefix and
    // escape the pattern. It also carries the B1.3 liveness lines (phase / files / elapsed).
    let redacted = redact_secrets(String::from_utf8_lossy(&stderr).trim());
    let tail: String = {
        let chars: Vec<char> = redacted.chars().collect();
        chars[chars.len().saturating_sub(800)..].iter().collect()
    };
    match status {
        Some(s) if s.success() => Ok(()),
        None => {
            let secs = (timeout_ms as f64 / 1000.0).round() as u64;
            anyhow::bail!(
                "horus-source analyze timed out after {secs}s while building the structural index (large repo). Raise the cap with HORUS_ANALYZE_TIMEOUT_MS.{}",
                if tail.is_empty() { String::new() } else { format!(" — last output: {tail}") }
            )
        }
        Some(_) => {
            if tail.is_empty() {
                anyhow::bail!("horus-source analyze failed")
            }
            anyhow::bail!("horus-source analyze failed: {tail}")
        }
    }
}

fn host_json_path(root: &Path) -> PathBuf {
    root.join(".horus").join("source").join("host.json")
}

/// Return the host URL for the source-intelligence backend serving `root`, or None.
/// Reads `.horus/source/host.json` — the canonical path written by horus-source. The backend
/// runs at most ONE host per repo, so this is the source of truth for "is this repo already
/// being hosted, and where".
pub fn read_source_host_url(root: &Path) -> Option<String> {
    let raw = fs::read_to_string(host_json_path(root)).ok()?;
    let j: Value = serde_json::from_str(&raw).ok()?;
    j.get("host_url")?.as_str().map(str::to_string)
}

/// The backend's own record of the host process it is running for `root`, from
/// `.horus/source/host.json`. The `pid` here is the ACTUAL listening server — which can differ
/// from, and outlive, the spawn-wrapper pid Horus records in `spawned-host.json`.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceHostRecord {
    pub pid: i64,
    /// Port the backend reports it is serving on, or None if absent/invalid (TS: NaN).
    pub port: Option<i64>,
    /// Repo the backend reports it is hosting, or '' if absent.
    pub repo_path: String,
}

pub fn read_source_host_pid(root: &Path) -> Option<SourceHostRecord> {
    let raw = fs::read_to_string(host_json_path(root)).ok()?;
    let j: Value = serde_json::from_str(&raw).ok()?;
    let pid = j.get("pid")?.as_i64().filter(|p| *p > 0)?;
    Some(SourceHostRecord {
        pid,
        port: j.get("port").and_then(Value::as_i64),
        repo_path: j.get("repo_path").and_then(Value::as_str).unwrap_or("").to_string(),
    })
}

fn probe_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(2500))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Is a source-intelligence host reachable + healthy at this base URL?
pub async fn is_host_healthy(host_url: &str) -> bool {
    match probe_client().get(format!("{host_url}/api/health")).send().await {
        Ok(res) => res.status().is_success(),
        Err(_) => false,
    }
}

/// Fetch the repo path a host at `host_url` reports it is serving (`GET /api/host`), or
/// None when the host is unreachable, unhealthy, or cannot report its identity.
///
/// HOR-421: the default host URL is `:8420` for every repo, so a host serving a DIFFERENT
/// repo can occupy the configured port. Callers VERIFY identity before grounding on it. The
/// wire field is `repoPath`; `repo_path` is also accepted to match the on-disk host.json shape.
pub async fn fetch_host_repo_path(host_url: &str) -> Option<String> {
    let res = probe_client().get(format!("{host_url}/api/host")).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let j: Value = res.json().await.ok()?;
    for key in ["repoPath", "repo_path"] {
        if let Some(s) = j.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
    }
    None
}

/// Find a free localhost TCP port in [start, end].
pub async fn find_free_port(start: Option<u16>, end: Option<u16>) -> anyhow::Result<u16> {
    let (start, end) = (start.unwrap_or(8420), end.unwrap_or(8520));
    for port in start..=end {
        if tokio::net::TcpListener::bind(("127.0.0.1", port)).await.is_ok() {
            return Ok(port);
        }
    }
    anyhow::bail!("No free port available in {start}-{end}")
}

/// Ownership record Horus writes when it spawns a host (`.horus/spawned-host.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpawnedHostRecord {
    pub pid: i64,
    pub port: i64,
    pub root: String,
    pub started_at: String,
    /// Unknown keys are preserved on rewrite (TS spreads the parsed record).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

const SPAWNED_HOST_FILE: &str = "spawned-host.json";

fn spawned_path(root: &Path) -> PathBuf {
    root.join(".horus").join(SPAWNED_HOST_FILE)
}

fn write_spawned(root: &Path, record: &SpawnedHostRecord) -> std::io::Result<()> {
    fs::write(spawned_path(root), serde_json::to_string_pretty(record)? + "\n")
}

/// Read the PID record Horus wrote when it spawned a source-intelligence host for `root`.
pub fn read_spawned_host(root: &Path) -> Option<SpawnedHostRecord> {
    let raw = fs::read_to_string(spawned_path(root)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Spawn `horus-source host --port <port>` as a detached background host in `root`, logging
/// to `.horus/source-host.log`. Records the PID in `.horus/spawned-host.json` for safe
/// teardown. Returns immediately — poll `wait_for_host`.
pub fn start_host(root: &Path, port: u16) -> std::io::Result<()> {
    fs::create_dir_all(root.join(".horus"))?;
    let log = fs::OpenOptions::new().create(true).append(true).open(root.join(".horus").join("source-host.log"))?;
    let log_err = log.try_clone()?;
    let mut cmd = Command::new(SOURCE_BINARY);
    cmd.args(["host", "--port", &port.to_string()])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // detached: survives this CLI process exiting
    }
    match cmd.spawn() {
        Ok(child) => {
            let record = SpawnedHostRecord {
                pid: child.id() as i64,
                port: port as i64,
                root: root.to_string_lossy().into_owned(),
                started_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                extra: Default::default(),
            };
            write_spawned(root, &record)?;
            drop(child); // never waited on — like `child.unref()`
            Ok(())
        }
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                eprintln!("\n{SOURCE_NOT_FOUND_MESSAGE}");
            }
            Err(err)
        }
    }
}

/// Remove the spawned-host record for `root`, if it exists.
pub fn remove_spawned_host_record(root: &Path) {
    let _ = fs::remove_file(spawned_path(root)); // not present — nothing to clean up
}

/// `kill -<sig> pid` via the system `kill` so no libc dependency is needed. Returns true
/// when the signal was delivered (process exists and we may signal it).
fn signal(pid: i64, sig: &str) -> bool {
    Command::new("kill")
        .args([sig, &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Kill the host process(es) for `root` and remove the spawn record (HOR-372). Reaps BOTH
/// the spawn-wrapper pid (spawned-host.json) AND the detached backend server pid
/// (source/host.json) — the latter actually holds the single-writer lock and can outlive the
/// wrapper. SIGTERM then SIGKILL, waiting briefly so the lock is RELEASED before a retry
/// re-opens the same store. Best-effort.
pub async fn kill_spawned_host(root: &Path) {
    let mut pids: Vec<i64> = Vec::new();
    if let Some(s) = read_spawned_host(root).filter(|s| s.pid > 0) {
        pids.push(s.pid);
    }
    if let Some(b) = read_source_host_pid(root) {
        if !pids.contains(&b.pid) {
            pids.push(b.pid);
        }
    }
    for pid in pids {
        for sig in ["-TERM", "-KILL"] {
            if !signal(pid, sig) {
                break; // already gone / not permitted — stop escalating this pid
            }
            let mut dead = false;
            for _ in 0..15 {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if !signal(pid, "-0") {
                    dead = true;
                    break;
                }
            }
            if dead {
                break;
            }
        }
    }
    remove_spawned_host_record(root);
}

/// Reconcile the ownership record (`spawned-host.json`) with the host the backend ACTUALLY
/// brought up: its real server pid AND the port it really bound (HOR-409). Under contention
/// the backend can fall back to a DIFFERENT free port; keeping the requested port would make a
/// scoped `horus stop` refuse to stop a host it really did spawn. Only refines an existing
/// record. `actual_port` is the fallback when the backend record omits a usable port.
/// Best-effort: never fails.
pub fn reconcile_spawned_host(root: &Path, actual_port: i64) {
    let Some(spawned) = read_spawned_host(root) else { return };
    let backend = read_source_host_pid(root);
    let pid = backend.as_ref().map(|b| b.pid).filter(|p| *p > 0).unwrap_or(spawned.pid);
    let port = backend.as_ref().and_then(|b| b.port).filter(|p| *p > 0).unwrap_or(actual_port);
    if spawned.pid == pid && spawned.port == port {
        return;
    }
    let updated = SpawnedHostRecord { pid, port, ..spawned };
    let _ = write_spawned(root, &updated); // reconciliation is an optimisation
}

/// `path.resolve`: absolute + `.`/`..` normalised, no symlink resolution.
fn resolve_path(p: &str) -> PathBuf {
    let abs = if Path::new(p).is_absolute() {
        PathBuf::from(p)
    } else {
        std::env::current_dir().map(|c| c.join(p)).unwrap_or_else(|_| PathBuf::from(p))
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Wait until a source-intelligence host that VERIFIABLY serves `root` is healthy, and return
/// its URL — or None on timeout.
///
/// HOR-409 defense-in-depth: a freshly-spawned host can fall back to a DIFFERENT port than
/// requested (the requested port may be a FOREIGN repo's host). We resolve to the port the
/// backend ACTUALLY bound (`source/host.json`) and NEVER return a host that reports a
/// different repo. A host that cannot report its identity (older backend → None) is accepted.
pub async fn wait_for_own_host(root: &Path, requested_url: &str, timeout_ms: Option<u64>) -> Option<String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.unwrap_or(45_000));
    let root_resolved = resolve_path(&root.to_string_lossy());
    let serves_this_repo = |url: &str| {
        let root_resolved = root_resolved.clone();
        let url = url.to_string();
        async move {
            let served = fetch_host_repo_path(&url).await;
            // None = host can't report its repo (older backend / transient) → accept conservatively;
            // a healthy FOREIGN host reports a different path → reject.
            served.is_none_or(|s| resolve_path(&s) == root_resolved)
        }
    };
    while Instant::now() < deadline {
        // Prefer the port the backend actually bound (host.json); fall back to the requested URL.
        let mut candidates: Vec<String> = Vec::new();
        if let Some(recorded) = read_source_host_url(root) {
            candidates.push(recorded);
        }
        if !candidates.iter().any(|c| c == requested_url) {
            candidates.push(requested_url.to_string());
        }
        for url in candidates {
            if is_host_healthy(&url).await && serves_this_repo(&url).await {
                return Some(url);
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    None
}

/// Poll a host's health until it responds or the timeout elapses.
pub async fn wait_for_host(host_url: &str, timeout_ms: Option<u64>) -> bool {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.unwrap_or(45_000));
    while Instant::now() < deadline {
        if is_host_healthy(host_url).await {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}
