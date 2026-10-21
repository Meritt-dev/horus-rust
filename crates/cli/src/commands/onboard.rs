//! Port of `packages/cli/src/commands/onboard.ts`.

use std::path::Path;

use anyhow::Result;
use horus_ai::InterpretationPromptKind;
use horus_connectors::Provider;
use horus_engine::code_provider::InvestigationRow;
use horus_engine::onboard::{build_onboarding, OnboardingDeps};
use horus_engine::render_onboard::{onboarding_to_json, render_onboarding};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use crate::lib::engine_code::{code_for_repo, engine_edges, load_config, resolve_env};
use crate::lib::format::red;
use crate::lib::own_packages::detect_own_packages;

pub const ONBOARD_AI_CONTRACT: &str = "Provide a clearly separated AI onboarding guide with:

Start here
- Files and components a new engineer should read first (only those Horus found)
- Entry points, controllers, workers, or queue producers most relevant to the area

Mental model
- How this area works in plain language, grounded in what Horus discovered
- Key data flows and async handoffs

What breaks here
- Common failure modes based on discovered components, async boundaries, and past incidents
- Frame each as \"if X fails, then Y\" using only evidence Horus found

Useful commands
- Exact Horus commands to continue exploring this area

Confidence / gaps
- What Horus knows confidently (indexed source, queue edges, past incidents)
- What is missing and would require manual inspection or a broader index";

pub async fn run(args: &OnboardArgs) -> Result<()> {
    match inner(args).await {
        Err(err) if err.downcast_ref::<SilentExit>().is_none() => {
            eprintln!("{}", red(&err.to_string()));
            Err(SilentExit(1).into())
        }
        other => other,
    }
}

async fn inner(args: &OnboardArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    // --repo maps 1:1 to a project name (HOR-34 compat).
    let renv = match resolve_env(&config, args.repo.as_deref()) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{}", red(&err.to_string()));
            return Err(SilentExit(1).into());
        }
    };
    let code = code_for_repo(&config, Some(&renv.project))?;
    if !code.health().await.ok {
        eprintln!("{}", red("Source-intelligence host unreachable — run: horus init"));
        return Err(SilentExit(1).into());
    }

    // The engine takes the db reads pre-fetched (same queries the TS engine runs).
    let project = Some(renv.project.as_str());
    let db = horus_db::open_db().await?;
    let edges = horus_db::list_queue_edges(&db, project, None).await.map(engine_edges).unwrap_or_default();
    let recent = horus_db::list_investigations(&db, 8, project).await.unwrap_or_default();
    let with_reports = horus_db::list_investigations_with_reports(&db, 50, project).await.unwrap_or_default();
    db.end().await;

    let g = build_onboarding(
        args.area.as_deref(),
        OnboardingDeps {
            code: &code,
            repo_path: renv.path.clone(),
            project: Some(renv.project.clone()),
            own_packages: detect_own_packages(Path::new(&renv.path)),
            queue_edges: edges,
            recent_investigations: recent
                .into_iter()
                .map(|r| InvestigationRow {
                    id: r.id,
                    title: r.title,
                    created_at: Some(horus_db::format_ts(&r.created_at)),
                    report: None,
                })
                .collect(),
            investigations_with_reports: with_reports
                .into_iter()
                .map(|r| InvestigationRow {
                    id: r.id,
                    title: r.title,
                    created_at: Some(horus_db::format_ts(&r.created_at)),
                    report: r.report.and_then(|s| serde_json::from_str(&s).ok()),
                })
                .collect(),
        },
    )
    .await?;

    if args.json {
        println!("{}", onboarding_to_json(&g));
    } else {
        println!("{}", render_onboarding(&g));
        if args.ai {
            print_ai_interpretation(AiInterpretationOpts {
                command: "onboard",
                evidence: horus_core::json::to_js_value(&g)?,
                prompt_kind: InterpretationPromptKind::SystemExplanation,
                output_contract: ONBOARD_AI_CONTRACT,
                user_intent: args.area.as_ref().map(|a| format!("area: {a}")),
                config: args.config.as_deref(),
                model_override: args.ai_model.as_deref(),
            })
            .await;
        }
    }
    Ok(())
}
