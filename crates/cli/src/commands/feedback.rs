//! `horus feedback [investigationId]` — leave impact feedback on a past investigation.
//! Port of `packages/cli/src/commands/feedback.ts`.
//!
//! Non-interactive (`--resolved yes|partly|no`, the path `horus skill` tells agents to use) or
//! interactive (TTY prompt, HOR-326). Both emit the Tier-A telemetry event AND persist a durable
//! outcome label into the local eval store (source=feedback, HOR-390).

use std::io::IsTerminal;
use std::path::Path;

use anyhow::Result;
use horus_core::{load_config, resolve_environment, ResolveOptions};
use horus_db::{get_last_investigation_id, is_outcome_resolved, open_db, record_outcome_label, OutcomeLabelInput};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{dim, red, yellow};
use crate::lib::telemetry::feedback::{parse_resolved, run_feedback_prompt, submit_feedback};

/// Persist a verdict into the outcome-label / eval store (same sink as `memory confirm`).
/// BEST-EFFORT: never fails — the telemetry emit is the floor, this is additive.
pub async fn persist_outcome_label(
    investigation_id: &str,
    resolved: &str,
    manual_estimate_minutes: Option<i64>,
    config: Option<&str>,
    repo: Option<&str>,
    note: Option<&str>,
    cause: Option<&str>,
) {
    // Only a concrete verdict (yes|partly|no) is an eval data point.
    if !is_outcome_resolved(resolved) {
        return;
    }
    let _ = async {
        let cfg = load_config(config.map(Path::new), None)?;
        let project = resolve_environment(&cfg, &ResolveOptions { project: repo, ..Default::default() })
            .ok()
            .map(|e| e.project);
        let db = open_db().await?;
        // The human-confirmed cause/note ride onto the label so the corpus carries a real root cause.
        let trimmed = |s: Option<&str>| s.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let res = record_outcome_label(
            &db,
            OutcomeLabelInput {
                investigation_id: investigation_id.to_string(),
                resolved: resolved.to_string(),
                source: "feedback".into(),
                project: project.clone(),
                confirmed_cause: trimmed(cause),
                note: trimmed(note),
                payload: manual_estimate_minutes
                    .map(|m| horus_core::json::to_js_json(&serde_json::json!({ "manualEstimateMinutes": m })))
                    .transpose()?,
                at: None,
            },
        )
        .await;
        if res.is_ok() {
            if let Some(project) = &project {
                sync_memory(&db, &cfg, project).await;
            }
        }
        db.end().await;
        res.map(|_| ())
    }
    .await
    .map_err(|e: anyhow::Error| e);
}

/// `syncLinkedMemory` after a label lands; prints the sync state to stderr.
async fn sync_memory(db: &horus_db::DbHandle, cfg: &horus_core::HorusConfig, project: &str) {
    let Ok(env) = resolve_environment(cfg, &ResolveOptions { project: Some(project), ..Default::default() }) else {
        return;
    };
    use crate::lib::cloud::memory_sync::{sync_linked_memory, MemorySyncOptions};
    let Ok(state) = sync_linked_memory(db, Path::new(&env.path), project, MemorySyncOptions::default()).await else {
        return;
    };
    let err = state.error.as_deref().map(|e| format!(" — {e}")).unwrap_or_default();
    eprintln!("Memory: {}; {} pending{err}", state.state, state.pending);
}

pub async fn run(args: &FeedbackArgs) -> Result<()> {
    let mut id = args.investigation_id.as_deref().map(str::trim).unwrap_or("").to_string();
    // No id → the LAST investigation of THIS project (HOR-431, dogfood N1).
    if id.is_empty() {
        let last = async {
            let cfg = load_config(args.config.as_deref().map(Path::new), None)?;
            let project = resolve_environment(&cfg, &ResolveOptions::default()).ok().map(|e| e.project);
            let db = open_db().await?;
            let last = get_last_investigation_id(&db, project.as_deref()).await;
            db.end().await;
            last
        }
        .await
        .ok()
        .flatten();
        let Some(last) = last else {
            eprintln!("{}", red("No investigations yet — run: horus investigate \"<hint>\""));
            return Err(SilentExit(1).into());
        };
        id = last;
    }

    let persist = |resolved: String, minutes: Option<i64>| {
        let id = id.clone();
        async move {
            persist_outcome_label(
                &id,
                &resolved,
                minutes,
                args.config.as_deref(),
                args.repo.as_deref(),
                args.note.as_deref(),
                args.cause.as_deref(),
            )
            .await
        }
    };

    // Non-interactive path — agent/scripted feedback via flags. Works without a TTY.
    if let Some(raw) = &args.resolved {
        let Some(resolved) = parse_resolved(raw) else {
            eprintln!("{}", red(&format!("Invalid --resolved \"{raw}\". Use: yes | partly | no.")));
            return Err(SilentExit(1).into());
        };
        let mut minutes = None;
        if let Some(m) = &args.manual_estimate_min {
            match parse_int(m).filter(|n| *n >= 0) {
                Some(n) => minutes = Some(n),
                None => {
                    eprintln!(
                        "{}",
                        red(&format!("Invalid --manual-estimate-min \"{m}\" (expect a non-negative integer)."))
                    );
                    return Err(SilentExit(1).into());
                }
            }
        }
        submit_feedback(&id, Some(resolved), minutes, None, "flag");
        persist(resolved.to_string(), minutes).await;
        println!("{}", dim(&format!("Feedback recorded ({resolved}) — thanks, this helps improve Horus.")));
        return Ok(());
    }

    // Interactive path — requires a TTY.
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "{}",
            yellow("horus feedback needs an interactive terminal — or pass --resolved yes|partly|no for non-interactive (agent) use.")
        );
        return Err(SilentExit(1).into());
    }
    if let Some(answer) = run_feedback_prompt(&id, None) {
        persist(answer.resolved.unwrap_or("").to_string(), answer.manual_estimate_minutes).await;
    }
    Ok(())
}

/// JS `Number.parseInt(s, 10)`: optional sign + leading digits after whitespace.
fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim_start();
    let (sign, rest) = match s.strip_prefix('-') {
        Some(r) => (-1, r),
        None => (1, s.strip_prefix('+').unwrap_or(s)),
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<i64>().ok().map(|n| sign * n)
}
