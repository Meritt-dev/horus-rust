//! `horus telemetry` — the control surface for usage telemetry (HOR-323).
//! Port of `packages/cli/src/commands/telemetry.ts`.
//!
//! All state lives in `~/.horus/telemetry.json`; env overrides (DO_NOT_TRACK / HORUS_TELEMETRY /
//! CI) are surfaced by `status` so users can see why the effective decision may differ.

use anyhow::Result;

use crate::cli::*;
use crate::lib::format::{bold, dim, green, yellow};
use crate::lib::telemetry::consent::{resolve_consent, ConsentSource};
use crate::lib::telemetry::notice::PRIVACY_URL;
use crate::lib::telemetry::paths::telemetry_path;
use crate::lib::telemetry::spool::clear_spool;
use crate::lib::telemetry::store::{delete_telemetry_state, now_iso, read_telemetry_state, update_telemetry_state};
use crate::lib::telemetry::transport::delete_remote_telemetry;

fn on_off(enabled: bool) -> String {
    if enabled {
        green("on")
    } else {
        dim("off")
    }
}

fn warn_if_env_overrides() {
    let decision = resolve_consent(None);
    if decision.forced_off {
        println!(
            "{}",
            yellow(&format!("\nNote: telemetry is currently forced off by your environment ({}).", decision.reason))
        );
        println!("{}", dim("Your saved preference will apply once that override is removed."));
    } else if decision.source == ConsentSource::Ci {
        println!("{}", yellow("\nNote: CI environment detected — telemetry stays off here regardless."));
    }
}

pub async fn run(args: &TelemetryArgs) -> Result<()> {
    match args.command {
        TelemetryCommand::Status => status(),
        TelemetryCommand::Enable => {
            update_telemetry_state(|s| {
                s.tier_a.enabled = true;
                s.tier_a.notice_shown_at.get_or_insert_with(now_iso);
            })?;
            println!("{}", green("Anonymous usage metadata (Tier A) is now ON. Thank you!"));
            warn_if_env_overrides();
        }
        TelemetryCommand::Disable => {
            update_telemetry_state(|s| {
                s.tier_a.enabled = false;
                // Disabling metadata also disables the content tier (it's a superset).
                s.tier_b.enabled = false;
                s.tier_a.notice_shown_at.get_or_insert_with(now_iso);
            })?;
            println!("{}", yellow("All telemetry is now OFF (Tier A and Tier B)."));
        }
        TelemetryCommand::EnableContent => {
            update_telemetry_state(|s| {
                s.tier_a.enabled = true; // content requires metadata
                s.tier_b.enabled = true;
                s.tier_b.enabled_at = Some(now_iso());
                s.tier_a.notice_shown_at.get_or_insert_with(now_iso);
            })?;
            println!("{}", green("Content sharing (Tier B) is now ON — redacted inputs/outputs help improve Horus."));
            println!("{}", dim("Content is scrubbed of secrets/PII before it ever leaves your machine."));
            println!("{}", dim(&format!("What this means: {PRIVACY_URL}")));
            warn_if_env_overrides();
        }
        TelemetryCommand::DisableContent => {
            update_telemetry_state(|s| s.tier_b.enabled = false)?;
            println!("{}", yellow("Content sharing (Tier B) is now OFF. Usage metadata is unchanged."));
        }
        TelemetryCommand::ResetId => {
            let next = uuid::Uuid::new_v4().to_string();
            update_telemetry_state(|s| s.install_id = next.clone())?;
            println!("{}", green("Install ID reset."));
            println!("{}", dim(&format!("  New install ID: {next}")));
        }
        TelemetryCommand::Delete => {
            // Read the install id before deleting, then ask the server to purge its rows.
            if let Some(state) = read_telemetry_state() {
                delete_remote_telemetry(&state.install_id, None).await;
            }
            delete_telemetry_state();
            clear_spool();
            println!("{}", green("Telemetry deleted — local state cleared and a server purge requested."));
            println!(
                "{}",
                dim("Next run will treat this as a fresh install and re-show the notice. If the purge could not reach the server (offline), re-run this command when back online.")
            );
        }
    }
    Ok(())
}

fn status() {
    let state = read_telemetry_state();
    let decision = resolve_consent(Some(state.as_ref()));

    println!("{}", bold("Horus telemetry"));
    println!(
        "  Usage metadata (Tier A): {}  {}",
        on_off(decision.tier_a),
        dim(&format!("[{}]", decision.source.as_str()))
    );
    println!("  Content sharing (Tier B): {}", on_off(decision.tier_b));
    println!("{}", dim(&format!("  Reason: {}", decision.reason)));
    match &state {
        Some(s) => {
            println!("{}", dim(&format!("  Install ID: {}", s.install_id)));
            let oo = |b: bool| if b { "on" } else { "off" };
            println!("{}", dim(&format!("  Saved: Tier A {}, Tier B {}", oo(s.tier_a.enabled), oo(s.tier_b.enabled))));
        }
        None => println!("{}", dim("  No saved preference yet (defaults apply).")),
    }
    println!("{}", dim(&format!("  Config: {}", telemetry_path().display())));
    println!("{}", dim(&format!("  Privacy: {PRIVACY_URL}")));

    if state.is_none() || matches!(decision.source, ConsentSource::Env | ConsentSource::Ci) {
        warn_if_env_overrides();
    }
}
