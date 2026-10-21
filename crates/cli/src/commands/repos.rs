//! Port of `packages/cli/src/commands/repos.ts`.

use std::path::Path;

use anyhow::Result;
use horus_connectors::repo_providers;
use horus_core::load_config;
use horus_engine::multi_repo::repos_health;

use crate::cli::*;
use crate::lib::format::{bold, cyan, dim, green, red};

pub async fn run(args: &ReposArgs) -> Result<()> {
    let config = load_config(args.config.as_deref().map(Path::new), None)?;
    // connectors' RepoProvider holds a concrete SourceCodeProvider; the engine's boxes it.
    let providers: Vec<horus_engine::code_provider::RepoProvider> = repo_providers(&config)?
        .into_iter()
        .map(|p| horus_engine::code_provider::RepoProvider {
            name: p.name,
            path: p.path,
            host_url: p.host_url,
            code: Box::new(p.code),
        })
        .collect();

    if providers.is_empty() {
        println!("{}", dim("No repositories configured."));
        return Ok(());
    }

    for h in repos_health(&providers).await {
        let dot = if h.reachable { green("●") } else { red("●") };
        let name = bold(&format!("{:<20}", h.repo));
        let host_url = cyan(&format!("{:<30}", h.host_url));
        let path = dim(&h.path);
        let detail = if h.detail.is_empty() { String::new() } else { dim(&format!("({})", h.detail)) };
        println!("  {dot}  {name}  {host_url}  {path}  {detail}");
    }
    Ok(())
}
