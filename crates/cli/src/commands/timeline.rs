//! Port of `packages/cli/src/commands/timeline.ts`.

use anyhow::Result;
use horus_engine::deploy_timeline::{reconstruct_change_timeline, ChangeTimelineInput, SourceIndexFreshness};
use horus_engine::render_timeline::{change_timeline_to_json, render_change_timeline};

use crate::cli::*;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use horus_ai::InterpretationPromptKind;
use crate::lib::engine_code::fail;
use crate::lib::engine_code::{create_code, load_config, resolve_env};
use crate::lib::format::{bold, dim};
use crate::lib::freshness::read_index_meta;

// Same default window as `horus what-changed` — a bounded, investigation-useful range instead
// of all history (which buried real signal under hundreds of commits, HOR-202).
const DEFAULT_SINCE: &str = "7 days ago";

pub const TIMELINE_AI_CONTRACT: &str = "Provide a clearly separated AI interpretation section with:

Evidence used
- List the timeline events, commits, and change-impact signals Horus found

Narrative
- Group events into phases (e.g. pre-change, change window, symptom onset, recovery)
- Highlight any suspicious ordering (e.g. a change immediately before first error)
- Note what happened before vs. after the first symptom if identifiable

Confidence
- High / Medium / Low with a one-line reason

Gaps / Next checks
- Missing evidence dimensions (logs, metrics, traces, etc.)
- Exact Horus commands to fill the gaps";

/// Resolve the git `--since` window. `--all` wins over `--since`; `using_default` is true only
/// when neither was given.
pub fn resolve_timeline_window(since: Option<&str>, all: bool) -> (Option<String>, bool) {
    let using_default = !all && since.is_none();
    let since = if all { None } else { Some(since.unwrap_or(DEFAULT_SINCE).to_string()) };
    (since, using_default)
}

pub async fn run(args: &TimelineArgs) -> Result<()> {
    run_inner(args).await.map_err(|e| fail(e, args.json))
}

async fn run_inner(args: &TimelineArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    let renv = resolve_env(&config, args.repo.as_deref())?;
    let code = create_code(&config)?;

    let (since, using_default_window) = resolve_timeline_window(args.since.as_deref(), args.all);

    // Source-index freshness travels with the timeline so a stale index is visible right next
    // to the git evidence it may lag behind.
    let source_index = read_index_meta(std::path::Path::new(&renv.path)).and_then(|m| m.last_indexed_at).map(|at| SourceIndexFreshness { last_indexed_at: Some(at) });
    let t = reconstruct_change_timeline(
        ChangeTimelineInput {
            repo_path: renv.path.clone(),
            since,
            until: args.until.clone(),
            service: args.service.clone(),
            source_index,
        },
        &code,
    )
    .await?;

    if args.json {
        println!("{}", change_timeline_to_json(&t, args.full));
        return Ok(());
    }
    println!("{}", render_change_timeline(&t));
    if using_default_window {
        println!(
            "{}",
            dim(&format!(
                "\n  Showing the last 7 days (default). Widen with {}, pin a range with {}, or see everything with {}.",
                bold("--since \"30 days ago\""),
                bold("--since <when> --until <when>"),
                bold("--all"),
            ))
        );
    }
    if args.ai {
        print_ai_interpretation(AiInterpretationOpts {
            command: "timeline",
            user_intent: args.service.as_ref().map(|s| format!("service: {s}")),
            evidence: horus_core::json::to_js_value(&t)?,
            prompt_kind: InterpretationPromptKind::TimelineNarrative,
            output_contract: TIMELINE_AI_CONTRACT,
            config: args.config.as_deref(),
            model_override: args.ai_model.as_deref(),
        })
        .await;
    }
    Ok(())
}
