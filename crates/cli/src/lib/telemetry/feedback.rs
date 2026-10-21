//! Impact feedback (HOR-326). Port of `packages/cli/src/lib/telemetry/feedback.ts`. Tier-A event
//! with coarse buckets, no free text; interactive only on a TTY.

use std::io::{BufRead, Write};

use serde_json::json;

use super::client::track;
use crate::lib::format::{bold, dim};

/// Map the manual-time bucket key to representative minutes (5 = unsure → None).
fn manual_minutes(key: &str) -> Option<i64> {
    match key {
        "1" => Some(5),
        "2" => Some(30),
        "3" => Some(120),
        "4" => Some(480),
        _ => None,
    }
}

/// `yes` | `partly` | `no`, or None.
pub fn parse_resolved(raw: &str) -> Option<&'static str> {
    let v = raw.trim().to_lowercase();
    if v.starts_with('y') {
        Some("yes")
    } else if v.starts_with('p') {
        Some("partly")
    } else if v.starts_with('n') {
        Some("no")
    } else {
        None
    }
}

pub fn parse_manual_estimate(raw: &str) -> Option<i64> {
    manual_minutes(raw.trim())
}

/// Emit a feedback event (Tier A). Self-gates on consent inside track(). `source` is `prompt`
/// (a human answered) or `flag` (`--resolved`, typically an agent).
pub fn submit_feedback(
    investigation_id: &str,
    resolved: Option<&str>,
    manual_estimate_minutes: Option<i64>,
    horus_seconds: Option<i64>,
    source: &str,
) {
    track(json!({
        "type": "feedback.submitted",
        "investigationId": investigation_id,
        "resolved": resolved,
        "manualEstimateMinutes": manual_estimate_minutes,
        "horusSeconds": horus_seconds,
        "source": source,
    }));
}

/// The verdict a completed prompt yields.
pub struct FeedbackAnswer {
    pub resolved: Option<&'static str>,
    pub manual_estimate_minutes: Option<i64>,
}

fn question(prompt: &str) -> String {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// Run the interactive prompt and emit the telemetry event. None if the user skipped.
pub fn run_feedback_prompt(investigation_id: &str, horus_seconds: Option<i64>) -> Option<FeedbackAnswer> {
    println!("{}", dim("\nQuick feedback to improve Horus (press Enter to skip):"));
    let a1 = question(&format!("{}{}", bold("  Did this point you at the cause? "), dim("[y / partly / n] ")));
    if a1.trim().is_empty() {
        return None;
    }
    let a2 = question(&format!(
        "{}{}",
        bold("  Manually, finding this would have taken? "),
        dim("[1:<5m  2:~30m  3:~2h  4:half-day+  5:unsure] ")
    ));
    let resolved = parse_resolved(&a1);
    let manual_estimate_minutes = parse_manual_estimate(&a2);
    submit_feedback(investigation_id, resolved, manual_estimate_minutes, horus_seconds, "prompt");
    println!("{}", dim("  Thanks — recorded."));
    Some(FeedbackAnswer { resolved, manual_estimate_minutes })
}
