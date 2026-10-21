//! Port of `packages/cli/src/lib/worker-activity.ts` — bounded, privacy-preserving activity
//! events for the background worker's Claude runs (hook → private JSONL file → run logs).
//! The zod `workerActivitySchema` is enforced by `parse_activity` (strict keys, uuid ids,
//! offset datetime ≤ 40 chars, closed kind/action enums).

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use horus_core::redact_secrets;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const KINDS: &[&str] = &["stage", "tool-start", "tool-end", "tool-error", "agent-start", "agent-finish", "error"];
const ACTIONS: &[&str] = &[
    "engine", "recall", "collect", "ai", "upload", "notify", "complete", "done", "Read", "Grep", "Glob", "Bash",
    "connected-tool", "agent", "other-tool",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerActivity {
    pub id: String,
    pub at: String,
    pub job_id: String,
    pub kind: String,
    pub action: String,
}

/// zod `z.string().uuid()`: 8-4-4-4-12 hex, case-insensitive, any version.
pub fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts.iter().zip([8, 4, 4, 4, 12]).all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn require_uuid(s: &str) -> Result<()> {
    if !is_uuid(s) {
        bail!("Invalid uuid");
    }
    Ok(())
}

/// Validate one event against the strict schema; None when it does not conform.
pub fn parse_activity(v: &Value) -> Option<WorkerActivity> {
    let obj = v.as_object()?;
    if obj.keys().any(|k| !["id", "at", "jobId", "kind", "action"].contains(&k.as_str())) {
        return None; // .strict()
    }
    let s = |k: &str| obj.get(k)?.as_str().map(str::to_string);
    let ev = WorkerActivity { id: s("id")?, at: s("at")?, job_id: s("jobId")?, kind: s("kind")?, action: s("action")? };
    let at_ok = ev.at.len() <= 40 && chrono::DateTime::parse_from_rfc3339(&ev.at).is_ok();
    (is_uuid(&ev.id) && is_uuid(&ev.job_id) && at_ok && KINDS.contains(&ev.kind.as_str()) && ACTIONS.contains(&ev.action.as_str()))
        .then_some(ev)
}

pub fn activity_path(home: &Path, session_id: &str) -> Result<PathBuf> {
    require_uuid(session_id)?;
    Ok(home.join(format!("activity-{session_id}.jsonl")))
}

pub fn activity_event(job_id: &str, kind: &str, action: &str) -> Result<WorkerActivity> {
    let ev = WorkerActivity {
        id: uuid::Uuid::new_v4().to_string(),
        at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        job_id: job_id.to_string(),
        kind: kind.to_string(),
        action: action.to_string(),
    };
    match parse_activity(&serde_json::to_value(&ev)?) {
        Some(ev) => Ok(ev),
        None => bail!("invalid worker activity event"),
    }
}

/// Map one Claude hook payload to an activity event. Discards every raw field, including tool
/// arguments, output, paths and error text.
pub fn hook_activity(raw: &Value, session_id: &str, job_id: &str) -> Option<WorkerActivity> {
    if raw.get("session_id")?.as_str()? != session_id {
        return None;
    }
    let event = raw.get("hook_event_name")?.as_str()?;
    let tool = match raw.get("tool_name") {
        None => None,
        Some(Value::String(t)) => Some(t.as_str()),
        Some(_) => return None, // z.string().optional()
    };
    let kind = match event {
        "SessionStart" => "agent-start",
        "Stop" => "agent-finish",
        "PreToolUse" => "tool-start",
        "PostToolUse" => "tool-end",
        "PostToolUseFailure" => "tool-error",
        _ => return None,
    };
    let action = match tool {
        None | Some("") => "agent",
        Some(t @ ("Read" | "Grep" | "Glob" | "Bash")) => t,
        Some(t) if t.starts_with("mcp__") => "connected-tool",
        Some(_) => "other-tool",
    };
    activity_event(job_id, kind, action).ok()
}

/// Append the hook event from stdin to the worker's private activity file. Never fails:
/// observability never controls Claude execution.
pub fn record_activity_hook(home: &Path, session_id: &str, job_id: &str) {
    let _ = (|| -> Result<()> {
        let path = activity_path(home, session_id)?;
        require_uuid(job_id)?;
        // Only write the private file prepared by the owning worker, never arbitrary hook paths.
        // ponytail: lstat-then-open instead of O_NOFOLLOW (no libc dep); a racing symlink swap is the ceiling.
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.file_type().is_file() || meta.permissions().mode() & 0o077 != 0 || meta.len() > 64_000 {
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
        let mut input = String::new();
        std::io::stdin().take(1_000_001).read_to_string(&mut input)?;
        if input.len() > 1_000_000 {
            return Ok(());
        }
        if let Some(ev) = hook_activity(&serde_json::from_str(&input)?, session_id, job_id) {
            file.write_all((horus_core::json::to_js_json(&ev)? + "\n").as_bytes())?;
        }
        Ok(())
    })();
}

/// The last ≤100 valid events for `job_id` (a concurrent writer may leave an incomplete line).
pub fn read_activity(path: &Path, job_id: &str) -> Vec<WorkerActivity> {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return vec![] };
    if meta.file_type().is_symlink() || meta.len() > 65_000 {
        return vec![];
    }
    let Ok(text) = std::fs::read_to_string(path) else { return vec![] };
    let events: Vec<WorkerActivity> = text
        .split('\n')
        .filter_map(|line| parse_activity(&serde_json::from_str(line).ok()?))
        .filter(|e| e.job_id == job_id)
        .collect();
    let skip = events.len().saturating_sub(100);
    events.into_iter().skip(skip).collect()
}

/// `claude` CLI args wiring every hook to `horus service activity` for this session/job.
pub fn claude_activity_args(
    runtime: &str,
    runtime_args: &[String],
    entry: &str,
    session_id: &str,
    job_id: &str,
) -> Result<Vec<String>> {
    require_uuid(session_id)?;
    require_uuid(job_id)?;
    let quote = |v: &str| format!("'{}'", v.replace('\'', "'\"'\"'"));
    let mut parts: Vec<String> = vec![quote(runtime)];
    parts.extend(runtime_args.iter().map(|a| quote(a)));
    for p in [entry, "service", "activity", "--session", session_id, "--job", job_id] {
        parts.push(quote(p));
    }
    let hook = serde_json::json!([{ "hooks": [{ "type": "command", "command": parts.join(" "), "timeout": 5 }] }]);
    let settings = serde_json::json!({ "hooks": {
        "SessionStart": hook, "PreToolUse": hook, "PostToolUse": hook, "PostToolUseFailure": hook, "Stop": hook,
    } });
    Ok(vec!["--session-id".into(), session_id.into(), "--settings".into(), horus_core::json::to_js_json(&settings)?])
}

/// The AI judgment fields `workerRunLogs` summarizes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunLogResult {
    pub what: String,
    pub why: String,
    #[serde(default)]
    pub where_next: Vec<String>,
    pub confidence: f64,
    #[serde(default)]
    pub citations: Vec<RunLogCitation>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunLogCitation {
    pub evidence_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunLogs {
    pub logs_format: String,
    pub logs: String,
}

/// JS `String(n)` for the confidence line.
fn js_num(n: f64) -> String {
    match horus_core::json::to_js_json(&n) {
        Ok(s) => s,
        Err(_) => n.to_string(),
    }
}

/// Bounded durable run logs; project authorization/storage are owned by AgentRun.
pub fn worker_run_logs(events: &[WorkerActivity], result: Option<&RunLogResult>) -> RunLogs {
    let skip = events.len().saturating_sub(100);
    let events: Vec<&WorkerActivity> = events[skip..].iter().filter(|e| {
        serde_json::to_value(e).ok().and_then(|v| parse_activity(&v)).is_some()
    }).collect();
    let mut body = serde_json::json!({ "version": 1, "source": "worker", "events": events });
    if let Some(r) = result {
        let mut lines = vec![r.what.clone(), r.why.clone(), format!("Confidence: {}", js_num(r.confidence))];
        lines.extend(r.where_next.iter().map(|c| format!("Next check: {c}")));
        lines.push(format!(
            "Evidence: {}",
            r.citations.iter().map(|c| c.evidence_id.as_str()).collect::<Vec<_>>().join(", ")
        ));
        let text: String = redact_secrets(&lines.join("\n")).chars().take(64_000).collect();
        body["result"] = Value::String(text);
    }
    RunLogs {
        logs_format: "application/vnd.horus.activity+json".into(),
        logs: horus_core::json::to_js_json(&body).unwrap_or_default(),
    }
}
