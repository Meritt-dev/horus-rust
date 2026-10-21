//! `horus` binary entry point. Port of `apps/horus/src/index.ts` + the `run()` tail of
//! `packages/cli/src/index.ts`: argv pre-processing, parse, dispatch, exit code.

mod cli;
mod commander;
mod commands;
#[path = "lib/mod.rs"]
mod lib;

use std::ffi::OsString;
use std::process::ExitCode;

use clap::{ColorChoice, CommandFactory, FromArgMatches};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    // TS `run(process.argv)`: the hooks read the ORIGINAL argv (including `--no-input`).
    let raw_argv: Vec<String> = std::env::args().collect();

    // One-time telemetry disclosure + install-identity bootstrap (stderr only; never blocks).
    // Honors HORUS_TELEMETRY=0 / DO_NOT_TRACK / CI / non-TTY stderr inside.
    lib::telemetry::notice::maybe_show_first_run_notice(&raw_argv);

    // `--no-input` is a global, position-independent kill-switch for interactive prompts
    // (CI/agents). Strip it before clap parses so no subcommand sees an unknown option.
    // `HORUS_NO_INPUT=1` works too (read by the prompting helpers, not here).
    let mut argv: Vec<OsString> = std::env::args_os().filter(|a| a != "--no-input").collect();

    // commander: a repeated single-value option keeps the last value (`--topics a --topics b`);
    // clap 4 rejects the repeat unless args override themselves. Append options still collect.
    let mut cmd = cli::Cli::command().args_override_self(true);
    if !lib::format::color_enabled() {
        cmd = cmd.color(ColorChoice::Never);
    }
    cmd.build();

    // Removed-command hardening (TS `run()`): `horus setup --help` must fail exactly like
    // `horus setup`, so when the first operand is not a registered command drop the help flags
    // and let the unknown-command error fire.
    let mut args: Vec<String> = argv.iter().skip(1).map(|a| a.to_string_lossy().into_owned()).collect();
    if let Some(first) = args.iter().find(|a| !a.starts_with('-')) {
        let known = first == "help"
            || cmd.get_subcommands().any(|c| c.get_name() == first || c.get_all_aliases().any(|a| a == first));
        if !known {
            argv.retain(|a| a != "--help" && a != "-h");
            args.retain(|a| a != "--help" && a != "-h");
        }
    }

    // Help, --version and usage errors print exactly what commander prints and exit with its
    // code — like commander, no preAction hook, telemetry flush, or nudge runs for them.
    let version = format!("horus {}", horus_core::HORUS_VERSION); // TS `.version(`horus ${HORUS_VERSION}`)`
    let exit = match commander::preflight(&cmd, &version, &args) {
        Ok(excess) => {
            // commander 12 ignores excess operands; clap would reject them.
            let mut i = 0;
            argv.retain(|_| {
                let keep = i == 0 || !excess.contains(&(i - 1));
                i += 1;
                keep
            });
            match cmd.try_get_matches_from(argv) {
                Ok(m) => Ok(m),
                Err(e) => Err(commander::clap_error(&e)),
            }
        }
        Err(exit) => Err(exit),
    };
    let matches = match exit {
        Ok(m) => m,
        Err(exit) => {
            use std::io::Write;
            let _ = std::io::stdout().write_all(exit.stdout.as_bytes());
            let _ = std::io::stderr().write_all(exit.stderr.as_bytes());
            let _ = std::io::stdout().flush();
            return ExitCode::from(exit.code);
        }
    };
    let cli = cli::Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // The action command's path (commander `commandPath(actionCommand)`), e.g. ["cloud","sync"].
    let mut path: Vec<String> = vec![];
    let mut cur = &matches;
    while let Some((name, sub)) = cur.subcommand() {
        path.push(name.to_string());
        cur = sub;
    }
    let leaf = path.last().map(String::as_str).unwrap_or("");

    // preAction hooks, in TS registration order: update notifier, then command telemetry.
    // The notifier writes to stderr only and is suppressed for non-TTY / CI / --json.
    if !matches!(leaf, "update" | "service" | "watch") {
        lib::update_notifier::maybe_notify_update();
    }
    commands::db::maybe_hint_migrate_from_ts(&path, &raw_argv);
    let telemetry = lib::telemetry::command_hooks::command_invoked(&raw_argv, path.join(" "));

    let result = commands::dispatch(&cli).await;
    let exit_code: u8 = match &result {
        Ok(()) => 0,
        Err(err) => match err.downcast_ref::<commands::SilentExit>() {
            Some(commands::SilentExit(code)) => *code,
            None => {
                // An uncaught error: TS rejects out of `run()` (reportCrash, exit 1) before the
                // postAction hook, the telemetry flush, and the feedback nudge. Node's
                // `console.error(err)` leads with `Error: <message>` (stack frames: DIVERGENCES.md).
                // Errors TS handles in-command (`failCommand`) return `SilentExit` and never land here.
                lib::report_crash::report_crash(&anyhow::anyhow!("Error: {err:#}"));
                return ExitCode::from(1);
            }
        },
    };

    // postAction: command.completed (spooled; gated on consent).
    lib::telemetry::command_hooks::command_completed(telemetry, i64::from(exit_code));
    // Best-effort, time-boxed drain of spooled events. Never fails.
    if path != ["service", "activity"] {
        lib::telemetry::transport::flush_telemetry(None).await;
    }
    // Resolution-time feedback nudge: suppressed on non-TTY / CI / --json / --no-input inside.
    if !raw_argv.iter().any(|a| a == "service" || a == "watch") {
        lib::feedback_nudge::maybe_prompt_resolution_feedback(&raw_argv, None).await;
    }
    ExitCode::from(exit_code)
}

/// Quiet by default: only `HORUS_LOG` (preferred) or `RUST_LOG` turn on tracing, to stderr.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("HORUS_LOG")
        .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
        .unwrap_or_else(|_| EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
