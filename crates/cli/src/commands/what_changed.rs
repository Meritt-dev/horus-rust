//! Port of `packages/cli/src/commands/what-changed.ts`.

use std::sync::LazyLock;

use anyhow::Result;
use horus_engine::code_provider::resolves_to_commit;
use horus_engine::render_what_changed::{render_what_changed, what_changed_to_json};
use horus_engine::what_changed::{what_changed, WhatChangedInput};
use regex::Regex;

use crate::cli::*;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use horus_ai::InterpretationPromptKind;
use crate::lib::cloud::api::ChangeReportBody;
use crate::lib::cloud::context_store::{is_cloud_active, read_cloud_config};
use crate::lib::cloud::session::{authed_client, repo_root_or_cwd};
use crate::lib::engine_code::fail;
use crate::lib::engine_code::{create_code, load_config, resolve_env};
use crate::lib::format::{dim, yellow};
use horus_engine::what_changed::WhatChangedReport;
use serde_json::{json, Value};

const DEFAULT_SINCE: &str = "7 days ago";

pub const WHAT_CHANGED_AI_CONTRACT: &str = "Provide a clearly separated AI interpretation section with:

Evidence used
- List the concrete changes/files/commits/timestamps Horus found

Interpretation
- Which change(s) look most incident-relevant and why
- Which changes are likely noise and why
- Any suspicious ordering or coverage gaps

Confidence
- High / Medium / Low with a one-line reason

Next checks
- Exact Horus commands or files to inspect next";

static ISO_DATE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}").unwrap());
static HEAD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^HEAD\b").unwrap());
static SHA_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[0-9a-f]{7,40}$").unwrap());
static VERSION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^v?\d+\.\d+").unwrap());

/// Heuristic: does this --since value look like a git ref (HEAD~10, a sha, v1.2) rather than a date?
pub fn looks_like_git_ref(s: &str) -> bool {
    let t = s.trim();
    if t.chars().any(char::is_whitespace) || ISO_DATE_RE.is_match(t) {
        return false; // "7 days ago", ISO date
    }
    t.contains(['~', '^']) || HEAD_RE.is_match(t) || SHA_RE.is_match(t) || VERSION_RE.is_match(t)
}

pub async fn run(args: &WhatChangedArgs) -> Result<()> {
    run_inner(args).await.map_err(|e| fail(e, args.json))
}

async fn run_inner(args: &WhatChangedArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    let renv = resolve_env(&config, args.repo.as_deref())?;
    let code = create_code(&config)?;

    let since = args.since.clone().unwrap_or_else(|| DEFAULT_SINCE.to_string());

    // HOR-371: a ref-like --since that doesn't resolve (e.g. HEAD~10 on a shallow clone) is
    // silently treated as a date by git and yields zero commits. Warn instead of misleading.
    if let Some(s) = &args.since {
        if looks_like_git_ref(s) && !resolves_to_commit(&renv.path, s).await {
            eprintln!(
                "{}",
                yellow(&format!(
                    "Warning: --since \"{s}\" does not resolve to a commit (shallow clone or unknown ref?); it will be treated as a date filter and likely return no commits."
                ))
            );
        }
    }

    let r = what_changed(
        WhatChangedInput { repo_path: renv.path.clone(), since: Some(since), until: args.until.clone(), service: args.service.clone() },
        &code,
    )
    .await?;

    println!("{}", if args.json { what_changed_to_json(&r, args.full) } else { render_what_changed(&r) });

    if args.ai && !args.json {
        print_ai_interpretation(AiInterpretationOpts {
            command: "what-changed",
            user_intent: args.service.as_ref().map(|s| format!("service: {s}")),
            evidence: horus_core::json::to_js_value(&r)?,
            prompt_kind: InterpretationPromptKind::ChangeRisk,
            output_contract: WHAT_CHANGED_AI_CONTRACT,
            config: args.config.as_deref(),
            model_override: args.ai_model.as_deref(),
        })
        .await;
    }

    if args.push {
        push_change_report(&r, args.repo.as_deref()).await;
    }

    Ok(())
}

/// Push a what-changed report to the linked Horus Cloud project so the team can see it in the
/// dashboard. Best-effort: a missing login/link or a network error warns but never fails the
/// command (the local report already printed).
async fn push_change_report(r: &WhatChangedReport, repo_cwd: Option<&str>) {
    let Some(session) = authed_client() else {
        eprintln!("{}", yellow("[cloud] not logged in — run `horus login` to push reports."));
        return;
    };
    let cfg = read_cloud_config(&repo_root_or_cwd(repo_cwd.map(std::path::Path::new)));
    if !is_cloud_active(cfg.as_ref()) {
        eprintln!("{}", yellow("[cloud] repo not linked — run `horus cloud link` to push reports."));
        return;
    }
    let Some(project_id) = cfg.as_ref().and_then(|c| c.project.as_ref()).map(|p| p.id.clone()).filter(|id| !id.is_empty()) else {
        return;
    };

    let sym_name = |s: &horus_core::Symbol| -> Value { json!(s.name) };
    let ci = r.change_impact.as_ref();
    let payload = json!({
        "summary": r.summary,
        "note": r.note,
        "window": r.window,
        "commitCount": r.commit_count,
        // Git truth + working-tree state (cloud treats payload as opaque; bounded fields only).
        "gitTruth": r.git_truth.as_ref().map(|g| json!({
            "base": g.base,
            "compare": g.compare,
            "fileCount": g.file_count,
            "insertions": g.insertions,
            "deletions": g.deletions,
            "buckets": g.buckets,
        })),
        "workingTree": r.repo_state.as_ref().map(|s| json!({
            "dirty": s.dirty,
            "stagedCount": s.staged_count,
            "unstagedCount": s.unstaged_count,
            "untrackedCount": s.untracked_count,
        })),
        "topCommits": r.top_commits.iter().map(|c| json!({
            "hash": c.short_sha,
            "message": c.subject,
            "author": c.author,
            "files": c.files.len(),
        })).collect::<Vec<_>>(),
        "changeImpact": ci.map(|ci| json!({
            "added": ci.added.iter().map(sym_name).collect::<Vec<_>>(),
            "modified": ci.modified.iter().map(|m| sym_name(&m.after)).collect::<Vec<_>>(),
            "removed": ci.removed.iter().map(sym_name).collect::<Vec<_>>(),
        })),
        "contributors": r.contributors,
        "queueTopology": r.queue_topology,
    });

    let body = ChangeReportBody {
        service: r.window.service.clone(),
        since: r.window.since.clone(),
        until: r.window.until.clone(),
        summary: r.summary.clone(),
        commit_count: Some(r.commit_count as f64),
        contributor_count: Some(r.contributors.len() as f64),
        symbols_added: Some(ci.map(|c| c.added.len()).unwrap_or(0) as f64),
        symbols_modified: Some(ci.map(|c| c.modified.len()).unwrap_or(0) as f64),
        symbols_removed: Some(ci.map(|c| c.removed.len()).unwrap_or(0) as f64),
        queue_topology_touched: Some(r.queue_topology.touched),
        payload: horus_core::json::to_js_value(&payload).ok(),
    };
    match session.client.create_change_report(&project_id, &body).await {
        Ok(_) => eprintln!("{}", dim("[cloud] pushed change report.")),
        Err(err) => eprintln!("{}", yellow(&format!("[cloud] push failed: {err}"))),
    }
}
