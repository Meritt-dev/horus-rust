//! Port of `packages/cli/src/commands/architecture.ts`.

use anyhow::Result;
use horus_engine::architecture::{discover_architecture, ArchitectureDeps};
use horus_engine::code_provider::Provider;
use horus_engine::render_architecture::{architecture_to_json, render_architecture};

use crate::cli::*;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use horus_ai::InterpretationPromptKind;
use crate::commands::SilentExit;
use crate::lib::cloud::session::repo_root_or_cwd;
use crate::lib::engine_code::fail;
use crate::lib::engine_code::{create_code, engine_edges, load_config, resolve_env};
use crate::lib::format::red;
use crate::lib::own_packages::detect_own_packages;

pub const ARCHITECTURE_AI_CONTRACT: &str = "Provide a clearly separated AI interpretation section with:

System summary
- What the system appears to do based on subsystems, external systems, and key flows Horus found
- Major subsystems and their responsibilities

Critical paths
- Important flows and async boundaries found by Horus
- Queues, workers, and external API touch points

Fragility / risk points
- Areas where coupling, queues, external systems, or unclear ownership create risk
- Refer only to components and boundaries Horus discovered

How to investigate this system
- Useful Horus commands to explore further (blast-radius, investigate, timeline, etc.)
- Specific files or symbols worth inspecting

Confidence / gaps
- Where Horus evidence was strong (e.g. indexed source, queue edges)
- What evidence is missing and what to do to fill those gaps";

pub async fn run(args: &ArchitectureArgs) -> Result<()> {
    run_inner(args).await.map_err(|e| fail(e, args.json))
}

async fn run_inner(args: &ArchitectureArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    let code = create_code(&config)?;

    if !code.health().await.ok {
        eprintln!("{}", red("Source-intelligence host unreachable — run: horus init"));
        return Err(SilentExit(1).into());
    }

    // Resolve the active project so async boundaries (queue edges) are scoped to it —
    // otherwise another project's queues leak into this repo's architecture (HOR-207).
    let project = resolve_env(&config, None).ok().map(|r| r.project);

    // Queue edges: a failed/unavailable db degrades to no async boundaries (the engine's
    // per-section rule), never to a failed command.
    let db = horus_db::open_db().await?;
    let edges = horus_db::list_queue_edges(&db, project.as_deref(), None).await.map(engine_edges).unwrap_or_default();
    db.end().await;

    let m = discover_architecture(ArchitectureDeps {
        code: &code,
        queue_edges: edges,
        project,
        own_packages: detect_own_packages(&repo_root_or_cwd(None)),
    })
    .await;

    if args.json {
        println!("{}", architecture_to_json(&m));
    } else {
        println!("{}", render_architecture(&m));
        if args.ai {
            print_ai_interpretation(AiInterpretationOpts {
                command: "architecture",
                user_intent: None,
                evidence: horus_core::json::to_js_value(&m)?,
                prompt_kind: InterpretationPromptKind::SystemExplanation,
                output_contract: ARCHITECTURE_AI_CONTRACT,
                config: args.config.as_deref(),
                model_override: args.ai_model.as_deref(),
            })
            .await;
        }
    }
    Ok(())
}
