//! Tier-A usage event taxonomy (HOR-324). Port of `packages/cli/src/lib/telemetry/events.ts`.
//!
//! Tier A is ANONYMOUS METADATA only — no free text, no flag values, no file contents. Events
//! are JSON objects: the base context (stamped by the client) followed by the caller's input
//! (`type` first, then its structured fields), the same key order as the TS spread.

use std::collections::BTreeSet;

pub const TELEMETRY_EVENT_SCHEMA_VERSION: i64 = 1;

/// Event types that carry Tier-B content and require explicit content opt-in.
pub const TIER_B_EVENT_TYPES: &[&str] = &["investigation.content"];

/// The consent tier (`"A"` | `"B"`) an event type belongs to.
pub fn tier_for_event_type(t: &str) -> &'static str {
    if TIER_B_EVENT_TYPES.contains(&t) {
        "B"
    } else {
        "A"
    }
}

/// Extract long-flag NAMES from argv, dropping any values — the privacy-critical boundary for
/// command events. `argv[0]` is the program (TS `argv.slice(2)` after node + script).
pub fn extract_flag_names(argv: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut names = Vec::new();
    for token in argv.iter().skip(1) {
        if let Some(rest) = token.strip_prefix("--").filter(|r| !r.is_empty()) {
            let name = rest.split('=').next().unwrap_or("");
            if !name.is_empty() && seen.insert(name.to_string()) {
                names.push(name.to_string());
            }
        }
    }
    names
}
