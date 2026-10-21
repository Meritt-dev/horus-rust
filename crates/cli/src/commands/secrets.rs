//! `horus secrets` — manage encrypted connector credentials (HOR-452).
//! Port of `packages/cli/src/commands/secrets.ts`.
//!
//!   horus secrets status    inspect the master key, stored secrets, and gitignore
//!   horus secrets migrate   move plaintext secrets out of config.json into the encrypted
//!                           store and strip them from config.json
//!   horus secrets key --show  print the active master key (base64) for CI use
//!
//! Connector credentials are AES-256-GCM encrypted into `.horus/secrets.local.json`; the
//! master key lives in the OS keychain (see `horus_core::secrets`).

use std::path::{Path, PathBuf};

use anyhow::Result;
use base64::Engine as _;
use horus_core::{
    connector_secret_fields, decrypt_connector_secrets, discover_local_config, ensure_master_key,
    ensure_project_gitignore, find_plaintext_connector_secrets, find_repo_root, get_master_key_for_read,
    is_horus_gitignored, local_config_path, local_secrets_path, master_key_status, read_local_config,
    read_local_secrets, write_connector_secret, write_local_config,
};
use serde_json::Value;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red, yellow};

pub async fn run(args: &SecretsArgs) -> Result<()> {
    let code = match &args.command {
        SecretsCommand::Status => run_secrets_status(None),
        SecretsCommand::Migrate(a) => run_secrets_migrate(a.dry_run, None),
        SecretsCommand::Key(a) => run_secrets_key(a.show),
    };
    if code != 0 {
        return Err(SilentExit(code).into());
    }
    Ok(())
}

struct Located {
    root: PathBuf,
    config_path: PathBuf,
    exists: bool,
}

fn locate(cwd: Option<&Path>) -> Located {
    let cwd = cwd.map(Path::to_path_buf).unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let root = find_repo_root(&cwd).unwrap_or_else(|| cwd.clone());
    let config_path = discover_local_config(&cwd).unwrap_or_else(|| local_config_path(&root));
    let exists = config_path.exists();
    Located { root, config_path, exists }
}

/// Count encrypted secret fields stored across all envs/connectors.
fn count_stored_secrets(root: &Path) -> usize {
    read_local_secrets(root)
        .connectors
        .map(|c| c.values().flat_map(|by_conn| by_conn.values()).map(|by_field| by_field.len()).sum())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

pub fn run_secrets_status(cwd: Option<&Path>) -> u8 {
    let Located { root, config_path, exists } = locate(cwd);

    let key = master_key_status();
    println!("{}", bold("\nMaster key"));
    if key.available {
        println!("  {} {}", green("●"), key.detail);
    } else {
        println!("  {} {}", dim("○"), key.detail);
    }

    let stored = count_stored_secrets(&root);
    println!("{}", bold("\nEncrypted secrets"));
    println!("  {stored} stored → {}", dim(&local_secrets_path(&root).display().to_string()));
    if stored > 0 {
        let warnings = decrypt_connector_secrets(&root).warnings;
        if !warnings.is_empty() {
            println!("{}", yellow(&format!("  ⚠ {} cannot be decrypted with the current key:", warnings.len())));
            for w in &warnings {
                println!("{}", dim(&format!("    - {w}")));
            }
        } else {
            println!("{}", dim("  all decrypt cleanly with the current key"));
        }
    }

    println!("{}", bold("\nPlaintext in config.json"));
    if !exists {
        println!("{}", dim("  no .horus/config.json found"));
    } else {
        // TS lets a malformed config throw out of the command; an empty list is the closest
        // non-crashing equivalent here and is surfaced by `horus doctor` anyway.
        let plaintext =
            read_local_config(&config_path).map(|f| find_plaintext_connector_secrets(&f.project)).unwrap_or_default();
        if plaintext.is_empty() {
            println!("  {} none — config carries no credentials", green("✓"));
        } else {
            println!("{}", yellow(&format!("  ⚠ {} plaintext secret(s) — run `horus secrets migrate`:", plaintext.len())));
            for p in &plaintext {
                println!("{}", dim(&format!("    - {p}")));
            }
        }
    }

    println!("{}", bold("\nGitignore"));
    if is_horus_gitignored(&root) {
        println!("  {} .horus/ is gitignored", green("✓"));
    } else {
        println!(
            "{}",
            yellow("  ⚠ .horus/ is NOT gitignored — run `horus secrets migrate` or add `.horus/` to .gitignore")
        );
    }
    println!();
    0
}

// ---------------------------------------------------------------------------
// migrate
// ---------------------------------------------------------------------------

pub fn run_secrets_migrate(dry_run: bool, cwd: Option<&Path>) -> u8 {
    let Located { root, config_path, exists } = locate(cwd);
    if !exists {
        eprintln!("{}", red(&format!("No .horus/config.json found at {}.", config_path.display())));
        eprintln!("{}", dim("  Run `horus init` in this repo first."));
        return 1;
    }

    let mut file = match read_local_config(&config_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}", red(&e.to_string()));
            return 1;
        }
    };
    let plaintext = find_plaintext_connector_secrets(&file.project);

    // Always harden gitignore — the cheap fix for the "git added later" gap.
    ensure_project_gitignore(&root);

    if plaintext.is_empty() {
        println!("{} No plaintext connector secrets in config.json — nothing to migrate.", green("✓"));
        if !is_horus_gitignored(&root) {
            println!("{}", dim("  Ensured `.horus/` is gitignored."));
        }
        return 0;
    }

    if dry_run {
        println!("{}", bold(&format!("Would migrate {} plaintext secret(s) → encrypted store:", plaintext.len())));
        for p in &plaintext {
            println!("{}", dim(&format!("  - {p}")));
        }
        println!("{}", dim("\n  Re-run without --dry-run to apply."));
        return 0;
    }

    // Resolve/create the master key once.
    let key_result = match ensure_master_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{}", red(&e.to_string()));
            return 1;
        }
    };

    // Walk the structure directly (env name may contain '/', so don't re-parse the locator
    // string): encrypt each secret field, then strip it from config.
    let mut migrated = 0;
    if let Some(envs) = file.project.get_mut("environments").and_then(Value::as_array_mut) {
        for env in envs {
            let Some(env_name) = env.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
            else {
                continue;
            };
            let Some(connectors) = env.get_mut("connectors").and_then(Value::as_object_mut) else { continue };
            for (connector, cfg) in connectors.iter_mut() {
                let Some(cfg) = cfg.as_object_mut() else { continue };
                for field in connector_secret_fields(connector) {
                    let Some(val) = cfg.get(*field).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string)
                    else {
                        continue;
                    };
                    if let Err(e) = write_connector_secret(&root, &env_name, connector, field, &val, Some(&key_result.key)) {
                        eprintln!("{}", red(&e.to_string()));
                        return 1;
                    }
                    cfg.shift_remove(*field);
                    migrated += 1;
                }
            }
        }
    }

    // Persist the stripped config (write_local_config enforces mode 0600).
    if let Err(e) = write_local_config(&root, &file) {
        eprintln!("{}", red(&e.to_string()));
        return 1;
    }

    println!("{} Migrated {migrated} secret(s) → {}", green("✓"), dim(&local_secrets_path(&root).display().to_string()));
    println!("{}", dim(&format!("  master key: {}", master_key_status().detail)));
    println!("{}", dim("  config.json now carries no credentials."));
    if let Some(w) = &key_result.warning {
        eprintln!("{}", yellow(&format!("\n⚠ {w}")));
    }
    println!(
        "{}",
        dim("\n  If config.json was ever committed, scrub the old secret from history:\n    git rm --cached .horus/config.json   # if tracked\n    # then rotate the exposed credential at its provider.")
    );
    0
}

// ---------------------------------------------------------------------------
// key
// ---------------------------------------------------------------------------

pub fn run_secrets_key(show: bool) -> u8 {
    let status = master_key_status();
    if !status.available {
        println!("{}", dim("No master key yet — created on first `horus connect` or `horus secrets migrate`."));
        return 0;
    }
    println!("Master key source: {}", status.detail);
    if !show {
        println!("{}", dim("  Pass --show to print the key (base64) for CI use (HORUS_SECRET_KEY)."));
        return 0;
    }
    let Some(key) = get_master_key_for_read() else {
        eprintln!("{}", red("Could not read the master key."));
        return 1;
    };
    eprintln!("{}", yellow("⚠ Treat this as a credential. Anyone with it can decrypt your connector secrets."));
    // Explicitly requested (`--show`) — the one path that prints the key, exactly like TS.
    println!("\nexport HORUS_SECRET_KEY={}\n", base64::engine::general_purpose::STANDARD.encode(key));
    0
}
