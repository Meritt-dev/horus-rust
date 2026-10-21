//! Port of `packages/cli/src/commands/search.ts`.

use anyhow::Result;
use horus_connectors::repo_providers;
use horus_engine::code_provider::RepoProvider;
use horus_engine::multi_repo::search_across_repos;

use crate::cli::*;
use crate::lib::engine_code::{fail, load_config};
use crate::lib::format::{bold, dim, green, red};

pub async fn run(args: &SearchArgs) -> Result<()> {
    // Shared machine-JSON failure contract: clean one-liner on stderr, parseable object under --json.
    search(args).await.map_err(|e| fail(e, args.json))
}

async fn search(args: &SearchArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    let providers: Vec<RepoProvider> = repo_providers(&config)?
        .into_iter()
        .map(|p| RepoProvider { name: p.name, path: p.path, host_url: p.host_url, code: Box::new(p.code) })
        .collect();
    let results = search_across_repos(&args.query, &providers, Some(args.limit.unwrap_or(8) as usize)).await;

    if args.json {
        // Object contract (agent parity): `{ results: [...] }`, not a bare top-level array.
        println!("{}", horus_core::json::to_js_json_pretty(&serde_json::json!({ "results": results }))?);
        return Ok(());
    }

    let mut total = 0;
    for r in &results {
        let dot = if r.reachable { green("●") } else { red("●") };
        println!();
        println!("{dot}  {}  {}", bold(&format!("## {}", r.repo)), dim(&r.host_url));
        if !r.reachable {
            println!("{}", dim("  (unreachable)"));
        } else if r.symbols.is_empty() {
            println!("{}", dim("  (no matches)"));
        } else {
            for sym in &r.symbols {
                // Qualify with class + line so same-named hits are tellable apart.
                let owner = sym.class_name.as_deref().filter(|c| !c.is_empty()).map(|c| dim(&format!("{c}."))).unwrap_or_default();
                let line = sym.start_line.filter(|l| *l != 0).map(|l| dim(&format!(":{l}"))).unwrap_or_default();
                println!("  - {owner}{}  {}{line}", bold(&sym.name), dim(&sym.file_path));
            }
            total += r.symbols.len();
        }
    }
    println!();
    let reachable = results.iter().filter(|r| r.reachable).count();
    println!(
        "{}",
        dim(&format!(
            "{total} match(es) across {reachable}/{} reachable repo(s) for query: \"{}\"",
            results.len(),
            args.query
        ))
    );
    Ok(())
}
