//! One-time first-run telemetry disclosure (HOR-323). Port of
//! `packages/cli/src/lib/telemetry/notice.ts`. Printed once per install to stderr, only when
//! stderr is a TTY; must never fail or block.

use std::io::IsTerminal;

use super::consent::{is_ci, resolve_consent};
use super::store::{load_or_init_telemetry_state, now_iso, update_telemetry_state};
use crate::lib::format::{bold, color_enabled, cyan, dim};

pub const PRIVACY_URL: &str = "https://horus.sh/privacy";

/// argv tokens for which the banner is suppressed (meta/control commands).
const SUPPRESS_FIRST_TOKEN: &[&str] = &["telemetry", "help"];
const SUPPRESS_FLAGS: &[&str] = &["-V", "--version", "-h", "--help"];

fn should_suppress_for(argv: &[String]) -> bool {
    let args = argv.get(1..).unwrap_or_default();
    if args.is_empty() {
        return true; // bare `horus` prints help; don't precede it
    }
    if args.iter().any(|a| SUPPRESS_FLAGS.contains(&a.as_str())) {
        return true;
    }
    args.iter().find(|a| !a.starts_with('-')).is_some_and(|t| SUPPRESS_FIRST_TOKEN.contains(&t.as_str()))
}

fn underline(s: &str) -> String {
    if color_enabled() {
        format!("\x1b[4m{s}\x1b[24m")
    } else {
        s.to_string()
    }
}

fn banner() -> String {
    [
        String::new(),
        cyan(&bold("Horus collects anonymous usage data to improve the tool.")),
        dim("  • On by default: command names, timings, success/failure, and where the"),
        dim("    engine ran out of evidence. No file contents, queries, or secrets."),
        dim("  • Off by default: your investigation inputs/outputs (opt in to help train"),
        format!("    {}  {} {}", dim("Horus)"), dim("— run"), bold("horus telemetry enable-content")),
        dim("  • If you use Horus Cloud, linked investigations sync to your workspace."),
        String::new(),
        format!(
            "  {} {}  {}  {}  {}  {}",
            dim("Opt out anytime:"),
            bold("horus telemetry disable"),
            dim("·"),
            bold("HORUS_TELEMETRY=0"),
            dim("·"),
            bold("DO_NOT_TRACK=1")
        ),
        format!("  {} {}", dim("Details:"), underline(PRIVACY_URL)),
        String::new(),
    ]
    .join("\n")
}

/// Show the disclosure once and ensure an install identity + saved preference exist. Safe to
/// call unconditionally at the top of every run. `argv` is the full process argv (TS
/// `process.argv` minus the node binary — index 0 is the program).
pub fn maybe_show_first_run_notice(argv: &[String]) {
    // Respect a hard env opt-out: don't create files or print anything.
    if resolve_consent(None).forced_off || is_ci() {
        return;
    }
    let Ok(state) = load_or_init_telemetry_state() else { return };
    if state.tier_a.notice_shown_at.is_some() || should_suppress_for(argv) {
        return;
    }
    // TTY check on stderr — our write target — so piped stdout / `--json` is never affected.
    if !std::io::stderr().is_terminal() {
        return;
    }
    eprintln!("{}", banner());
    let _ = update_telemetry_state(|s| s.tier_a.notice_shown_at = Some(now_iso()));
}
