//! `horus projects` — list projects registered in the global registry (HOR-37).
//! Port of `packages/cli/src/commands/projects.ts`.

use anyhow::Result;
use horus_core::read_registry;

use crate::lib::format::{bold, dim};

pub async fn run() -> Result<()> {
    let reg = read_registry();
    let mut names: Vec<&String> = reg.projects.keys().collect();
    names.sort();

    if names.is_empty() {
        println!("{}", dim("No registered projects. Run `horus init` inside a repo."));
        return Ok(());
    }

    println!("{}", bold("Registered Horus projects"));
    println!();
    for name in names {
        let Some(entry) = reg.projects.get(name) else { continue };
        println!("  {} {}", bold(&format!("{name:<22}")), dim(&entry.root));
    }
    println!();
    println!(
        "{}",
        dim("  cd <repo> && horus investigate \"<hint>\"   (or: horus investigate --config <path>)")
    );
    Ok(())
}
