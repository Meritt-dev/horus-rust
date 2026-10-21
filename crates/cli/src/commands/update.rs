//! `horus update` — self-update to the latest GitHub release. Port of
//! `packages/cli/src/commands/update.ts`: download + checksum-verify the release binary, swap
//! it in place (with rollback), refresh the bundled backend wheel, keep the source backend
//! pinned (HOR-350), and kick a non-blocking structural reindex when the local index is
//! capability-stale (D6).
//!
//! Rust-only: the install channel decides HOW to update (see DIVERGENCES.md). npm and Homebrew
//! installs upgrade through their package manager; only standalone installs (shell installer,
//! cargo-binstall, a copied binary) self-replace, from the dist release archive.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};
use horus_connectors::source::lifecycle::{
    get_source_version, index_capability_stale, is_analyzed, is_host_healthy, read_source_host_url,
};
use horus_core::{EXPECTED_INDEX_CAPABILITY, HORUS_VERSION, PINNED_SOURCE_VERSION};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::bundled_backend::install_bundled_backend;
use crate::lib::cloud::session::repo_root_or_cwd;
use crate::lib::format::{bold, cyan, dim, green, red, yellow};

/// Release repo, from the workspace `repository` (Cargo.toml), e.g. `Meritt-dev/horus-rust`.
fn release_repo() -> &'static str {
    env!("CARGO_PKG_REPOSITORY").trim_start_matches("https://github.com/").trim_end_matches('/')
}

pub fn releases_api() -> String {
    format!("https://api.github.com/repos/{}/releases/latest", release_repo())
}

fn installer_hint() -> String {
    format!(
        "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/{}/releases/latest/download/horus-cli-installer.sh | sh",
        release_repo()
    )
}

/// The executable's file name inside the release archives (`horus`).
const BIN: &str = env!("CARGO_BIN_NAME");

/// The dist target this binary was built for; names its release archive. Linux always maps to
/// the static musl build, which also replaces a gnu build.
const TARGET: &str = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
    "aarch64-apple-darwin"
} else if cfg!(target_os = "macos") {
    "x86_64-apple-darwin"
} else if cfg!(target_arch = "aarch64") {
    "aarch64-unknown-linux-musl"
} else {
    "x86_64-unknown-linux-musl"
};

/// How this binary was installed, from its resolved path.
#[derive(Debug, PartialEq)]
enum Channel {
    /// `<prefix>/lib/node_modules/<launcher>-<os>-<cpu>/bin/horus`: (npm prefix, launcher name).
    NpmGlobal(PathBuf, String),
    /// Under some other `node_modules` (a project dependency): launcher name.
    NpmLocal(String),
    /// `<prefix>/Cellar/<formula>/<version>/bin/<exe>`: (formula, the stable `<prefix>/opt/<formula>/bin/<exe>`).
    Homebrew(String, PathBuf),
    Standalone,
}

fn detect_channel(exe: &Path) -> Channel {
    let s = exe.to_string_lossy();
    if let Some((prefix, rest)) = s.split_once("/Cellar/") {
        let formula = rest.split('/').next().unwrap_or(BIN).to_string();
        let exe_name = exe.file_name().map(|n| n.to_os_string()).unwrap_or_else(|| BIN.into());
        let opt_bin = Path::new(prefix).join("opt").join(&formula).join("bin").join(exe_name);
        return Channel::Homebrew(formula, opt_bin);
    }
    if s.contains("/node_modules/") {
        // The platform package's name minus its `-<os>-<cpu>` suffix is the launcher package.
        let name = exe
            .parent()
            .and_then(Path::parent)
            .and_then(|d| std::fs::read_to_string(d.join("package.json")).ok())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|j| j.get("name")?.as_str().map(str::to_string));
        if let Some(name) = name {
            let mut launcher = name.rsplitn(3, '-').nth(2).unwrap_or(&name).to_string();
            // Pre-0.24 side-by-side builds shipped as `<scope>/horus-rs`; it's `<scope>/horus` now.
            if let Some(scope) = launcher.strip_suffix("/horus-rs") {
                launcher = format!("{scope}/horus");
            }
            return match s.split_once("/lib/node_modules/") {
                Some((prefix, _)) => Channel::NpmGlobal(PathBuf::from(prefix), launcher),
                None => Channel::NpmLocal(launcher),
            };
        }
    }
    Channel::Standalone
}

/// The package-manager command `horus update` would run for this install, for the update notice.
pub fn package_manager_hint() -> Option<String> {
    let exe = std::env::current_exe().and_then(|p| p.canonicalize()).ok()?;
    match detect_channel(&exe) {
        Channel::NpmGlobal(_, launcher) | Channel::NpmLocal(launcher) => Some(format!("npm i -g {launcher}@latest")),
        Channel::Homebrew(formula, _) if formula == "horus-rs" => Some("brew install meritt-dev/tap/horus".into()),
        Channel::Homebrew(formula, _) => Some(format!("brew upgrade {formula}")),
        Channel::Standalone => None,
    }
}

/// npm/Homebrew: upgrade through the package manager, then run the NEW binary's `horus update`
/// so it pins the backend to its own wheel and refreshes the index (this process has the old pin).
fn update_via_package_manager(channel: &Channel) -> u8 {
    let (mut cmd, new_exe) = match channel {
        Channel::NpmGlobal(prefix, launcher) => {
            let mut c = Command::new("npm");
            c.args(["install", "-g", "--prefix"]).arg(prefix).arg(format!("{launcher}@latest"));
            (c, std::env::current_exe().and_then(|p| p.canonicalize()).ok())
        }
        // Pre-0.24 side-by-side formula: the binary is the `horus` formula now.
        Channel::Homebrew(formula, opt_bin) if formula == "horus-rs" => {
            let mut c = Command::new("brew");
            c.args(["install", "meritt-dev/tap/horus"]);
            // <prefix>/opt/horus-rs/bin/horus-rs → <prefix>/opt/horus/bin/horus
            (c, opt_bin.ancestors().nth(3).map(|opt| opt.join("horus").join("bin").join(BIN)))
        }
        Channel::Homebrew(formula, opt_bin) => {
            let mut c = Command::new("brew");
            c.args(["upgrade", formula]);
            (c, Some(opt_bin.clone()))
        }
        Channel::NpmLocal(launcher) => {
            out(&format!("  {} Horus is a project dependency here; update it in that project:", yellow("!")));
            out(&format!("    {}", dim(&format!("npm install {launcher}@latest"))));
            return 1;
        }
        Channel::Standalone => unreachable!(),
    };
    out(&format!("\n  Running {}", dim(&format!("{cmd:?}").replace('"', ""))));
    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => {
            out(&format!("  {} Package manager exited with {s}.", red("✗")));
            return 1;
        }
        Err(e) => {
            out(&format!("  {} Could not run the package manager: {e}", red("✗")));
            return 1;
        }
    }
    let Some(new_exe) = new_exe else { return 0 };
    match Command::new(&new_exe).arg("update").status() {
        Ok(s) if s.success() => 0,
        _ => 1,
    }
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

fn out(line: &str) {
    println!("{line}");
}

/// Keep the source backend in lockstep with the CLI (HOR-350). After a binary swap this
/// process still carries the OLD pin, so callers pass the new release version plus a wheel
/// CONFIRMED to be that version; the sibling wheel is only trusted for this binary's own pin.
async fn ensure_backend_pinned(target_version: &str, confirmed_wheel: Option<&Path>) {
    let installed = get_source_version().await;
    if installed.as_deref() == Some(target_version) {
        out(&format!("  {} Source backend already on pinned {target_version}.", green("✓")));
        return;
    }
    if target_version != PINNED_SOURCE_VERSION && confirmed_wheel.is_none() {
        out(&format!("  {} Backend wheel for {target_version} wasn't downloaded — skipping backend install.", yellow("!")));
        out(&format!("    {}", dim("Re-run `horus update`, or: curl -fsSL https://horus.sh/install.sh | bash")));
        return;
    }
    let label = installed.map(|i| format!("Upgrading source backend {i} → {target_version} (bundled wheel)…"));
    install_bundled_backend(&|l| out(l), label.as_deref(), Some(target_version), confirmed_wheel).await;
}

/// `[major, minor, patch]` from `v1.2.3…`.
pub fn parse_version(v: &str) -> Result<[u64; 3]> {
    let s = v.strip_prefix('v').unwrap_or(v);
    let mut parts = s.splitn(3, '.');
    let mut nums = [0u64; 3];
    for n in nums.iter_mut() {
        let p = parts.next().ok_or_else(|| anyhow!("Cannot parse version: {v}"))?;
        let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return Err(anyhow!("Cannot parse version: {v}"));
        }
        *n = digits.parse()?;
    }
    Ok(nums)
}

pub fn is_newer(candidate: &str, current: &str) -> Result<bool> {
    Ok(parse_version(candidate)? > parse_version(current)?)
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(format!("horus/{HORUS_VERSION}"))
        .build()
        .unwrap_or_default()
}

async fn fetch_latest_release() -> Result<GitHubRelease> {
    let res = http().get(releases_api()).header("Accept", "application/vnd.github.v3+json").send().await?;
    if !res.status().is_success() {
        return Err(anyhow!("GitHub API responded {}", res.status().as_u16()));
    }
    Ok(res.json().await?)
}

/// Detached `horus init --reindex` re-invoking THIS (just-updated) binary so it outlives us.
fn default_spawn_reindex(root: &Path) {
    use std::os::unix::process::CommandExt;
    let Ok(exe) = std::env::current_exe() else { return };
    let _ = std::process::Command::new(exe)
        .args(["init", "--reindex"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn();
}

/// D6: when a local index's capability stamp is below the CLI's expectation, fire a
/// NON-BLOCKING structural-only reindex: POST `/api/reindex` on a running watch host, else a
/// detached `horus init --reindex`. Fully best-effort; never fails the update.
pub async fn maybe_background_reindex(cwd: Option<&Path>) -> &'static str {
    let root = repo_root_or_cwd(cwd);
    if !is_analyzed(&root) || !index_capability_stale(&root, EXPECTED_INDEX_CAPABILITY) {
        return "skipped";
    }
    if let Some(host) = read_source_host_url(&root) {
        if is_host_healthy(&host).await {
            let posted = reqwest::Client::new()
                .post(format!("{host}/api/reindex"))
                .header("Content-Type", "application/json")
                .body(r#"{"structural_only":true}"#)
                .send()
                .await;
            if matches!(posted, Ok(r) if r.status().is_success()) {
                out(&dim("  refreshing source index in the background…"));
                return "posted";
            }
            // Non-watch host (400) or transient error — fall through to a detached reindex.
        }
    }
    default_spawn_reindex(&root);
    out(&dim("  refreshing source index in the background…"));
    "spawned"
}

pub async fn run(args: &UpdateArgs) -> Result<()> {
    let code = run_update(args.check, args.force).await;
    if code != 0 {
        return Err(SilentExit(code).into());
    }
    Ok(())
}

async fn download(url: &str) -> Result<reqwest::Response> {
    Ok(http().get(url).send().await?)
}

pub async fn run_update(check: bool, force: bool) -> u8 {
    let current = HORUS_VERSION;
    out(&format!("\n{}\n", bold("Horus update")));
    out(&format!("  Current version: {}", cyan(current)));

    let release = match fetch_latest_release().await {
        Ok(r) => r,
        Err(e) => {
            out(&format!("  {} Could not reach GitHub: {e}", red("✗")));
            return 1;
        }
    };
    let latest = release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name).to_string();
    out(&format!("  Latest version:  {}", cyan(&latest)));

    // TS throws out of the command on an unparseable version (e.g. `dev`).
    let newer = match is_newer(&latest, current) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{}", red(&e.to_string()));
            return 1;
        }
    };

    if check {
        if newer {
            out(&format!("\n  {} {} is available.", yellow("→"), bold(&latest)));
            out(&format!("    Run {} to upgrade.", bold("horus update")));
        } else {
            out(&format!("\n  {} Already on the latest version.", green("✓")));
        }
        return 0;
    }

    if !newer && !force {
        out(&format!("\n  {} Already on the latest version.", green("✓")));
        // Even when the CLI is current, the backend can have drifted — keep it pinned.
        ensure_backend_pinned(PINNED_SOURCE_VERSION, None).await;
        return 0;
    }

    // The running executable (TS: realpath of argv[1]).
    let binary_path: PathBuf = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(e) => {
            out(&format!("  {} Cannot determine binary path: {e}", red("✗")));
            return 1;
        }
    };
    let channel = detect_channel(&binary_path);
    if channel != Channel::Standalone {
        return update_via_package_manager(&channel);
    }

    let tag = release.tag_name.clone();
    let asset_name = format!("horus-cli-{TARGET}.tar.gz");
    let checksum_name = format!("{asset_name}.sha256");
    let find = |n: &str| release.assets.iter().find(|a| a.name == n);

    let Some(archive_asset) = find(&asset_name) else {
        out(&format!("  {} Release {tag} has no archive named '{asset_name}'.", red("✗")));
        out(&format!("    Fallback: {}", dim(&installer_hint())));
        return 1;
    };

    out(&format!("\n  Downloading {asset_name}..."));
    let archive_buf = match download(&archive_asset.browser_download_url).await {
        Ok(r) if r.status().is_success() => match r.bytes().await {
            Ok(b) => b,
            Err(e) => {
                out(&format!("  {} Download failed: {e}", red("✗")));
                return 1;
            }
        },
        Ok(r) => {
            out(&format!("  {} Download failed: {}", red("✗"), r.status().as_u16()));
            return 1;
        }
        Err(e) => {
            out(&format!("  {} Download failed: {e}", red("✗")));
            return 1;
        }
    };

    if let Some(cs) = find(&checksum_name) {
        if let Ok(r) = download(&cs.browser_download_url).await {
            if r.status().is_success() {
                let text = r.text().await.unwrap_or_default();
                let expected = text.split_whitespace().next().unwrap_or("").to_string();
                let actual = hex::encode(Sha256::digest(&archive_buf));
                if expected != actual {
                    out(&format!("  {} Checksum mismatch — download may be corrupt.", red("✗")));
                    out(&format!("    Expected: {expected}"));
                    out(&format!("    Got:      {actual}"));
                    return 1;
                }
                out(&format!("  {} Checksum verified.", green("✓")));
            }
        }
    }

    // Unpack with the system tar: horus-cli-<target>/{horus-rs, horus_source.whl}.
    let unpack = std::env::temp_dir().join(format!("horus-update-{tag}-{}", std::process::id()));
    let bundle = unpack.join(format!("horus-cli-{TARGET}"));
    let unpacked = std::fs::create_dir_all(&unpack)
        .and_then(|_| std::fs::write(unpack.join(&asset_name), &archive_buf))
        .and_then(|_| Command::new("tar").arg("-xzf").arg(unpack.join(&asset_name)).arg("-C").arg(&unpack).status())
        .map(|s| s.success() && bundle.join(BIN).is_file());
    if !matches!(unpacked, Ok(true)) {
        let _ = std::fs::remove_dir_all(&unpack);
        out(&format!("  {} Could not unpack {asset_name}.", red("✗")));
        return 1;
    }
    let tmp_path = bundle.join(BIN);

    let backup_path = PathBuf::from(format!("{}.bak", binary_path.display()));
    if let Err(e) = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755)) {
        let _ = std::fs::remove_dir_all(&unpack);
        out(&format!("  {} Could not write to temp dir: {e}", red("✗")));
        return 1;
    }

    let swapped = (|| -> std::io::Result<()> {
        std::fs::rename(&binary_path, &backup_path)?;
        // rename(2) fails across filesystems (tmp vs bin dir); fall back to copy.
        let placed = std::fs::rename(&tmp_path, &binary_path).or_else(|_| std::fs::copy(&tmp_path, &binary_path).map(|_| ()));
        if let Err(e) = placed.and_then(|_| std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755))) {
            // Rollback: restore backup.
            let _ = std::fs::rename(&backup_path, &binary_path);
            return Err(e);
        }
        let _ = std::fs::remove_file(&backup_path);
        Ok(())
    })();
    if let Err(e) = swapped {
        let _ = std::fs::remove_dir_all(&unpack);
        out(&format!("  {} Could not replace binary at {}: {e}", red("✗"), binary_path.display()));
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            out("\n  Reinstall with the installer instead:");
            out(&format!("    {}", dim(&installer_hint())));
        }
        return 1;
    }

    out(&format!("  {} Updated: {} → {}", green("✓"), bold(current), bold(&latest)));
    out(&format!("  {}", dim(&binary_path.display().to_string())));

    // Refresh the bundled backend wheel from the same archive (one bundle, one version).
    let sibling_wheel = binary_path.parent().unwrap_or(Path::new(".")).join("horus_source.whl");
    let refreshed: Result<PathBuf> = (|| {
        // Write-then-rename so a crash can never leave a TORN wheel trusted by co-location.
        let tmp = PathBuf::from(format!("{}.tmp-{}", sibling_wheel.display(), std::process::id()));
        std::fs::copy(bundle.join("horus_source.whl"), &tmp)?;
        std::fs::rename(&tmp, &sibling_wheel)?;
        Ok(sibling_wheel.clone())
    })();
    let _ = std::fs::remove_dir_all(&unpack);
    let refreshed_wheel = match refreshed {
        Ok(p) => {
            out(&format!("  {} Bundled backend wheel refreshed.", green("✓")));
            Some(p)
        }
        Err(_) => {
            // The OLD sibling wheel must not survive next to the NEW binary.
            if sibling_wheel.exists() {
                if std::fs::remove_file(&sibling_wheel).is_ok() {
                    out(&format!("  {} Backend wheel refresh failed — removed the stale bundled wheel.", yellow("!")));
                } else {
                    out(&format!("  {} Backend wheel refresh failed and the stale wheel could not be removed.", yellow("!")));
                }
            }
            None
        }
    };

    // pglite assets are not refreshed: the Rust build persists to SQLite (see DIVERGENCES).

    // Bring the backend to the release we just installed — not this process's stale pin.
    ensure_backend_pinned(&latest, refreshed_wheel.as_deref()).await;

    maybe_background_reindex(None).await;
    0
}
