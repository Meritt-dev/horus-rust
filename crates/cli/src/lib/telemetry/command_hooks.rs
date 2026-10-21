//! Single-point command telemetry wiring (HOR-324). Port of
//! `packages/cli/src/lib/telemetry/command-hooks.ts`. Commander's pre/post-action hooks have no
//! clap equivalent, so the dispatcher calls `command_invoked` before and `command_completed`
//! after running a command. Only flag NAMES and the command path are recorded.

use std::time::Instant;

use serde_json::json;

use super::client::track;
use super::events::extract_flag_names;

/// Full command path from argv — the leading non-flag tokens that name (sub)commands, e.g.
/// `["horus","cloud","sync","--x"]` → "cloud sync". `depth` is how many tokens clap consumed as
/// command names (1 for a leaf command, 2 for `cloud sync`).
pub fn command_path(argv: &[String], depth: usize) -> String {
    argv.iter().skip(1).filter(|a| !a.starts_with('-')).take(depth).cloned().collect::<Vec<_>>().join(" ")
}

pub struct CommandTelemetry {
    command: String,
    flags: Vec<String>,
    started: Instant,
}

/// `preAction`: emit `command.invoked` and start the timer.
pub fn command_invoked(argv: &[String], command: String) -> CommandTelemetry {
    let flags = extract_flag_names(argv);
    track(json!({ "type": "command.invoked", "command": command, "flags": flags }));
    CommandTelemetry { command, flags, started: Instant::now() }
}

/// `postAction`: emit `command.completed` with duration + exit code.
pub fn command_completed(t: CommandTelemetry, exit_code: i64) {
    track(json!({
        "type": "command.completed",
        "command": t.command,
        "flags": t.flags,
        "durationMs": t.started.elapsed().as_millis() as i64,
        "exitCode": exit_code,
        "ok": exit_code == 0,
    }));
}
