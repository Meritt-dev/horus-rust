//! Shared machine-JSON failure contract (dogfood 0.21.1 A1). Port of
//! `packages/cli/src/lib/command-failure.ts`.
//!
//! Agents pipe a data command's stdout straight into a JSON parser. A pre-output failure must
//! still emit ONE parseable `{ ok: false, detail }` object on stdout under `--json` (the
//! `status` config-error shape); the human detail stays on stderr. Exit code is always 1.

use crate::commands::SilentExit;
use crate::lib::format::red;

/// Report a command failure; returns the `SilentExit(1)` error for the command to return.
pub fn fail_command(err: anyhow::Error, json: bool) -> anyhow::Error {
    let detail = err.to_string();
    if json {
        let v = serde_json::json!({ "ok": false, "detail": detail });
        if let Ok(s) = horus_core::json::to_js_json_pretty(&v) {
            println!("{s}");
        }
    }
    eprintln!("{}", red(&detail));
    SilentExit(1).into()
}
