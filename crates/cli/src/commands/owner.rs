//! Port of `packages/cli/src/commands/owner.ts` — `horus owner <query>`: estimate who likely
//! owns a component from git history (HOR-20). Probabilistic; never authoritative.

use anyhow::Result;
use horus_engine::ownership::{estimate_ownership, OwnershipDeps};
use horus_engine::render_ownership::{ownership_to_json, render_ownership};

use crate::cli::*;
use crate::lib::engine_code::fail;
use crate::lib::engine_code::{code_for_repo, load_config, resolve_env};

pub async fn run(args: &OwnerArgs) -> Result<()> {
    run_inner(args).await.map_err(|e| fail(e, args.json))
}

async fn run_inner(args: &OwnerArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    let renv = resolve_env(&config, args.repo.as_deref())?;
    let code = code_for_repo(&config, Some(&renv.project))?;

    let o = estimate_ownership(&args.query, OwnershipDeps { code: &code, repo_path: renv.path.clone(), symbol: None }).await?;

    println!("{}", if args.json { ownership_to_json(&o) } else { render_ownership(&o) });
    Ok(())
}
