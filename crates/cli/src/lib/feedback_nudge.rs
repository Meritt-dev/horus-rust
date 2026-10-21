//! Resolution-time feedback nudge (HOR-431, Mechanism 2). Port of
//! `packages/cli/src/lib/feedback-nudge.ts`.
//!
//! On a LATER run, if the most-recent investigation is still unlabeled and old enough that the
//! outcome is likely known, ask ONCE. Decided from a cheap state file so the common run touches
//! no DB; one-time per investigation, rate-limited, suppressed on non-TTY / CI / `--json` /
//! `--no-input` / `HORUS_NO_INPUT` and during `feedback` / `mcp`. Never blocks or fails.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use horus_core::{load_config, resolve_environment, ResolveOptions};
use horus_db::{get_latest_outcome_label, list_investigations, open_db};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::feedback::persist_outcome_label;
use crate::lib::format::dim;
use crate::lib::telemetry::feedback::run_feedback_prompt;

fn state_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".horus").join("feedback-nudge.json")
}
/// Don't ask until the investigation is at least this old.
pub const MIN_AGE_MS: i64 = 2 * 60 * 60 * 1000;
/// Ask at most once per this window.
pub const RATE_LIMIT_MS: i64 = 20 * 60 * 60 * 1000;
/// Bound the remembered-id list.
const MAX_REMEMBERED: usize = 50;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NudgeState {
    /// Epoch ms of the last time we surfaced the nudge (any answer, including skip).
    pub last_prompt_ms: i64,
    /// Investigation ids already nudged — one-time per investigation.
    pub prompted_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LastInvestigation {
    pub id: String,
    pub title: Option<String>,
    pub created_at_ms: i64,
}

/// Reasons to stay silent. `argv[0]` is the program.
pub fn is_suppressed(argv: &[String]) -> bool {
    if std::env::var_os("HORUS_NO_INPUT").is_some_and(|v| !v.is_empty()) {
        return true;
    }
    if std::env::var_os("CI").is_some_and(|v| !v.is_empty()) {
        return true;
    }
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return true;
    }
    if argv.iter().any(|a| a == "--json" || a == "--no-input") {
        return true;
    }
    // Not during the feedback command itself or the long-running MCP server.
    matches!(argv.iter().skip(1).find(|a| !a.starts_with('-')).map(String::as_str), Some("feedback" | "mcp"))
}

pub fn read_state(path: &Path) -> NudgeState {
    let Some(j) = std::fs::read_to_string(path).ok().and_then(|r| serde_json::from_str::<Value>(&r).ok()) else {
        return NudgeState::default();
    };
    NudgeState {
        last_prompt_ms: j.get("lastPromptMs").and_then(Value::as_f64).map_or(0, |n| n as i64),
        prompted_ids: j
            .get("promptedIds")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
    }
}

fn write_state(state: &NudgeState, path: &Path) {
    let skip = state.prompted_ids.len().saturating_sub(MAX_REMEMBERED);
    let trimmed = NudgeState { last_prompt_ms: state.last_prompt_ms, prompted_ids: state.prompted_ids[skip..].to_vec() };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = horus_core::json::to_js_json(&trimmed) {
        let _ = std::fs::write(path, s + "\n");
    }
}

/// Pure decision: the investigation to ask about, or None to stay silent.
pub fn decide_feedback_nudge(
    last: Option<LastInvestigation>,
    labeled: bool,
    state: &NudgeState,
    now_ms: i64,
) -> Option<LastInvestigation> {
    let last = last?;
    if labeled
        || now_ms - last.created_at_ms < MIN_AGE_MS
        || state.prompted_ids.contains(&last.id)
        || now_ms - state.last_prompt_ms < RATE_LIMIT_MS
    {
        return None;
    }
    Some(last)
}

/// Human-friendly age ("3 hours ago", "2 days ago").
fn format_age(ms: i64) -> String {
    let hours = ms / (60 * 60 * 1000);
    if hours < 24 {
        return format!("{hours} hour{} ago", if hours == 1 { "" } else { "s" });
    }
    let days = hours / 24;
    format!("{days} day{} ago", if days == 1 { "" } else { "s" })
}

/// The deferred nudge. Safe to call at the end of every run — never blocks, fails, or corrupts output.
pub async fn maybe_prompt_resolution_feedback(argv: &[String], config: Option<&str>) {
    let _ = async {
        if is_suppressed(argv) {
            return Ok(());
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        let path = state_path();
        let state = read_state(&path);
        // Cheap gate: within the rate-limit window, skip WITHOUT opening the DB.
        if now_ms - state.last_prompt_ms < RATE_LIMIT_MS {
            return Ok(());
        }
        let cfg = load_config(config.map(Path::new), None)?;
        let project = resolve_environment(&cfg, &ResolveOptions::default()).ok().map(|e| e.project);
        let db = open_db().await?;
        let (mut last, mut labeled) = (None, false);
        let rows = list_investigations(&db, 1, project.as_deref()).await;
        if let Some(row) = rows.as_ref().ok().and_then(|r| r.first()) {
            last = Some(LastInvestigation {
                id: row.id.clone(),
                title: Some(row.title.clone()),
                created_at_ms: row.created_at.timestamp_millis(),
            });
            labeled = matches!(get_latest_outcome_label(&db, &row.id).await, Ok(Some(_)));
        }
        db.end().await;
        rows?;

        let Some(target) = decide_feedback_nudge(last, labeled, &state, now_ms) else { return Ok(()) };
        println!(
            "{}",
            dim(&format!(
                "\nYou have an investigation from {} without an outcome — a quick note trains Horus:",
                format_age(now_ms - target.created_at_ms)
            ))
        );
        if let Some(t) = target.title.as_deref().filter(|t| !t.is_empty()) {
            println!("{}", dim(&format!("  “{t}”")));
        }
        if let Some(answer) = run_feedback_prompt(&target.id, None) {
            persist_outcome_label(&target.id, answer.resolved.unwrap_or(""), answer.manual_estimate_minutes, config, None, None, None)
                .await;
        }
        // Record that we surfaced it (one-time per id + rate-limit), regardless of answer.
        let mut ids = state.prompted_ids.clone();
        ids.push(target.id);
        write_state(&NudgeState { last_prompt_ms: now_ms, prompted_ids: ids }, &path);
        anyhow::Ok(())
    }
    .await;
}
