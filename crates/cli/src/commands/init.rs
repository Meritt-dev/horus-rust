//! `horus init` — THE single onboarding command. Port of `packages/cli/src/commands/init.ts`:
//! check prerequisites (advisory), write/register `.horus/config.json`, then start the
//! source-intelligence host and index the repo (via `init_index::run_index`).
//!
//! Degradation policy:
//!   - `--source <url>`      → record the external host, skip local spawn/index, exit 0.
//!   - backend not installed → write + register config, print the install hint, exit 0.
//!   - backend present but analyze/host fails → exit 1.

use std::path::Path;

use anyhow::Result;
use horus_connectors::source::lifecycle::source_available;
use horus_core::{ensure_project_gitignore, find_repo_root, register_project, write_local_config, LocalConfigFile};
use serde_json::{json, Map};

use crate::cli::*;
use crate::commands::init_index::{resolve_path, run_index, IndexOptions};
use crate::commands::init_prereqs::check_prerequisites;
use crate::commands::SilentExit;
use crate::lib::bundled_backend::{install_bundled_backend, resolve_bundled_wheel};
use crate::lib::format::{bold, dim, green, red};

pub async fn run(args: &InitArgs) -> Result<()> {
    let code = run_init(args).await;
    if code != 0 {
        return Err(SilentExit(code).into());
    }
    Ok(())
}

pub async fn run_init(opts: &InitArgs) -> u8 {
    println!("{}", bold("\nHorus init\n"));
    // Advisory only — a red line here guides the user but never gates init.
    check_prerequisites().await;
    println!();

    let cwd = std::env::current_dir().unwrap_or_default();
    let root = match &opts.path {
        Some(p) => resolve_path(p),
        None => find_repo_root(&cwd).unwrap_or(cwd),
    };

    if let Some(source) = &opts.source {
        // External host: record it, skip local spawn/analyze/index.
        return write_config_only(&root, opts, Some(source));
    }

    if !source_available().await {
        // No backend on PATH — the bundle carries its wheel, so try installing it here.
        let installed = resolve_bundled_wheel().is_some()
            && install_bundled_backend(&|l| println!("{l}"), None, None, None).await
            && source_available().await;
        if !installed {
            // Config still gets written so connect/investigate (degraded runtime-only) work.
            let code = write_config_only(&root, opts, None);
            if code == 0 {
                println!("{}", dim("  indexing skipped — no source-intelligence backend found. Install it:"));
                println!("{}", dim("    curl -fsSL https://horus.sh/install.sh | bash"));
                println!("{}", dim("  then re-run `horus init` to index this repo"));
            }
            return code;
        }
    }

    // Backend available: the full HOR-37 flow.
    run_index(&IndexOptions {
        config: opts.config.clone(),
        env: opts.env.clone(),
        path: Some(root.to_string_lossy().into_owned()),
        full: opts.full,
        changed: opts.changed,
        fast: opts.fast,
        import_kb: opts.import_kb.clone(),
        reindex: opts.reindex,
    })
    .await
}

/// Write + register `.horus/config.json` without touching the backend.
fn write_config_only(root: &Path, opts: &InitArgs, host_url: Option<&str>) -> u8 {
    let result = (|| -> Result<std::path::PathBuf> {
        // The repo directory IS the project identity (edit .horus/config.json to rename).
        let name = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let env_name = opts.env.as_deref().unwrap_or("production");
        let root_s = root.to_string_lossy();
        let mut repo = json!({ "name": name, "path": root_s });
        if let Some(h) = host_url {
            repo["source"] = json!({ "hostUrl": h });
        }
        let file = LocalConfigFile {
            version: 1,
            project: json!({
                "name": name,
                "repositories": [repo],
                "environments": [{ "name": env_name, "readOnly": true, "connectors": {} }],
            }),
            database: None,
            ai: None,
            extra: Map::new(),
        };
        let config_path = write_local_config(root, &file)?;
        register_project(&name, &root_s, &config_path.to_string_lossy())?;
        ensure_project_gitignore(root);
        println!("{} Initialized Horus project {}", green("✓"), bold(&name));
        Ok(config_path)
    })();
    match result {
        Ok(config_path) => {
            println!("{}", dim(&format!("  config:     {}", config_path.display())));
            println!("{}", dim("  next: horus investigate \"<hint>\"  (from this repo)"));
            println!("{}", dim("  add runtime connectors with `horus connect <type>` (elasticsearch/mongodb/grafana/...) — credentials are encrypted, never hand-edited into config.json"));
            println!("{}", dim("  .horus/ is gitignored — local config and runtime state stay out of version control"));
            0
        }
        Err(e) => {
            eprintln!("{}", red(&e.to_string()));
            1
        }
    }
}
