//! Prerequisite check for `horus init` (HOR-37, HOR-84): the Horus source-intelligence
//! backend. Port of `packages/cli/src/commands/init-prereqs.ts`. Advisory only — prints a
//! status line and guides fixes, never gates init's exit code.

use horus_connectors::source::lifecycle::get_source_version;
use horus_core::{PINNED_SOURCE_VERSION, SOURCE_PIN_ENFORCED};

use crate::lib::format::{dim, green, red, yellow};

#[derive(Debug, Clone, Copy, Default)]
pub struct PrereqStatus {
    /// horus-source binary responded with a version.
    pub backend_present: bool,
    /// Version matches the pin (false when absent or drifted).
    pub backend_version_ok: bool,
}

pub async fn check_prerequisites() -> PrereqStatus {
    let mut status = PrereqStatus::default();
    match get_source_version().await {
        None => {
            println!("  {} Horus source-intelligence backend not found", red("●"));
            println!(
                "{}",
                dim("      install it (Python 3.11+ required):\n        curl -fsSL https://horus.sh/install.sh | bash\n      ensure ~/.local/bin is on your PATH")
            );
        }
        Some(v) if SOURCE_PIN_ENFORCED && v != PINNED_SOURCE_VERSION => {
            status.backend_present = true;
            println!(
                "  {} Horus source-intelligence backend version mismatch{}",
                yellow("●"),
                dim(&format!(" (installed: {v}, required: {PINNED_SOURCE_VERSION})"))
            );
            println!("{}", dim("      update it:\n        horus update"));
        }
        Some(v) => {
            status.backend_present = true;
            status.backend_version_ok = true;
            println!("  {} Horus source-intelligence backend {}", green("●"), dim(&format!("({v})")));
        }
    }
    status
}
