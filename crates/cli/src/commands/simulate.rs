//! Port of `packages/cli/src/commands/simulate.ts`.

use anyhow::Result;
use horus_connectors::Provider;
use horus_engine::render_simulate::{render_scenario_list, render_simulation};
use horus_engine::simulate::{evaluate_scenario, get_scenario, SCENARIOS};
use horus_engine::types::InvestigationInput;
use horus_engine::{investigate, EngineDeps};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::engine_code::{code_for_repo, load_config, resolve_env};
use crate::lib::format::red;

pub async fn run(args: &SimulateArgs) -> Result<()> {
    match inner(args).await {
        Err(err) if err.downcast_ref::<SilentExit>().is_none() => {
            eprintln!("{}", red(&err.to_string()));
            Err(SilentExit(1).into())
        }
        other => other,
    }
}

async fn inner(args: &SimulateArgs) -> Result<()> {
    // No scenario id — list all available scenarios.
    let Some(scenario_id) = &args.scenario else {
        println!("{}", render_scenario_list(&SCENARIOS));
        return Ok(());
    };
    let Some(scenario) = get_scenario(scenario_id) else {
        eprintln!(
            "{}",
            red(&format!("Unknown scenario: \"{scenario_id}\". Run horus simulate to list available scenarios."))
        );
        return Err(SilentExit(1).into());
    };

    let config = load_config(&args.config)?;
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

    let db = horus_db::open_db().await?;
    let mut deps = EngineDeps::new(&db);
    deps.code = Some(&code);
    let result = investigate(
        InvestigationInput {
            report_id: None,
            incident: None,
            hint: scenario.hint.clone(),
            agent_session: None,
            repo: Some(renv.project.clone()),
            since: scenario.since.clone(),
            logs_since: None,
            service: None,
            environment: None,
            scope: None,
            duration_dimension: None,
            shopify_queries: None,
        },
        deps,
    )
    .await;
    db.end().await;
    let report = result?;
    let evaluation = evaluate_scenario(scenario, &report);
    println!("{}", render_simulation(scenario, &report, &evaluation));
    Ok(())
}
