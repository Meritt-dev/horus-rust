//! The source-intelligence backend ships INSIDE the horus bundle as a Python wheel. Port of
//! `packages/cli/src/lib/bundled-backend.ts`: `horus init` / `horus update` install it from
//! `horus_source.whl` next to the executable via `uv tool install`.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use horus_core::PINNED_SOURCE_VERSION;
use regex::bytes::Regex;

use crate::lib::format::{dim, green, yellow};

/// The wheel bundled next to the CLI executable, or None when absent. (TS: next to
/// `dist/index.cjs`; the Rust binary is the bundle entry point.) The executable path is
/// resolved first (Homebrew's `bin/horus-rs` is a symlink into the Cellar), and the Homebrew
/// formula (named like the binary) installs the wheel to `<keg>/share/horus-rs/` rather than
/// beside the binary.
pub fn resolve_bundled_wheel() -> Option<PathBuf> {
    let dir = std::env::current_exe().ok()?.canonicalize().ok()?.parent()?.to_path_buf();
    let pkgshare = format!("../share/{}/horus_source.whl", env!("CARGO_BIN_NAME"));
    [dir.join("horus_source.whl"), dir.join(pkgshare)]
        .into_iter()
        .find(|w| w.exists())
}

static DIST_INFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"horus_source-([0-9][A-Za-z0-9.+!-]*?)\.dist-info/").unwrap());

/// The wheel's ACTUAL package version from its `*.dist-info/` member name (zip member paths are
/// stored verbatim, so a byte scan is reliable). None for a torn/corrupt/non-wheel file. This
/// makes the bundled install trust-free: a stale sibling wheel is refused, never installed
/// under a version it isn't.
pub fn read_wheel_dist_version(wheel_path: &Path) -> Option<String> {
    let raw = std::fs::read(wheel_path).ok()?;
    let m = DIST_INFO.captures(&raw)?;
    Some(String::from_utf8_lossy(&m[1]).into_owned())
}

/// Install the backend from the bundled wheel. Best-effort: failures print the installer
/// fallback and return false. The wheel's dist-info version must equal `version` (default:
/// the compiled-in pin; a self-update passes the freshly-downloaded release's version).
pub async fn install_bundled_backend(
    write: &dyn Fn(&str),
    label: Option<&str>,
    version: Option<&str>,
    wheel_path: Option<&Path>,
) -> bool {
    let version = version.unwrap_or(PINNED_SOURCE_VERSION);
    let wheel = match wheel_path.map(Path::to_path_buf).or_else(resolve_bundled_wheel) {
        Some(w) => w,
        None => {
            write(&format!(
                "  {}",
                dim("Bundled backend wheel not found — install via: curl -fsSL https://horus.sh/install.sh | bash")
            ));
            return false;
        }
    };
    let Some(actual) = read_wheel_dist_version(&wheel) else {
        write(&format!("  {} Bundled backend wheel is unreadable/corrupt — skipping install.", yellow("!")));
        write(&format!("    {}", dim("Re-run the installer: curl -fsSL https://horus.sh/install.sh | bash")));
        return false;
    };
    if actual != version {
        write(&format!(
            "  {} Bundled backend wheel is {actual} but {version} is required — refusing the stale wheel.",
            yellow("!")
        ));
        write(&format!("    {}", dim("Re-run `horus update`, or: curl -fsSL https://horus.sh/install.sh | bash")));
        return false;
    }
    let default_label = format!("Installing source backend {version} from the bundle…");
    write(&format!("  {}", label.unwrap_or(&default_label)));

    // uv/pip REQUIRE a PEP 427 wheel filename, so stage a canonically-named copy first.
    let staging = std::env::temp_dir().join(format!("horus-wheel-{}-{}", std::process::id(), chrono::Utc::now().timestamp_millis()));
    let ok = async {
        std::fs::create_dir_all(&staging).ok()?;
        let canonical = staging.join(format!("horus_source-{version}-py3-none-any.whl"));
        std::fs::copy(&wheel, &canonical).ok()?;
        let out = tokio::time::timeout(
            Duration::from_millis(300_000),
            tokio::process::Command::new("uv").args(["tool", "install", "--force"]).arg(&canonical).output(),
        )
        .await
        .ok()?
        .ok()?;
        out.status.success().then_some(())
    }
    .await
    .is_some();
    let _ = std::fs::remove_dir_all(&staging);
    if ok {
        write(&format!("  {} Source backend on {version} (bundled).", green("✓")));
        true
    } else {
        write(&format!("  {} Couldn't install the bundled source backend (is uv installed?).", yellow("!")));
        write(&format!("    {}", dim("Re-run the installer: curl -fsSL https://horus.sh/install.sh | bash")));
        false
    }
}
