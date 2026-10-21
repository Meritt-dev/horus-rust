//! Port of `packages/cli/src/commands/providers-doctor.ts` (`horus providers doctor`).

use std::time::Duration;

use anyhow::Result;
use horus_ai::{LocalProviderId, LocalProviderRegistry, LocalProviderResult, LocalProviderStatus, DEFAULT_LOCAL_PROVIDER_REGISTRY};
use horus_core::{load_config, resolve_ai_settings};

use crate::cli::*;
use crate::lib::format::{bold, dim, green, red, yellow};

fn status_mark(status: LocalProviderStatus) -> String {
    match status {
        LocalProviderStatus::Ready => green("✓"),
        LocalProviderStatus::Installed => yellow("~"),
        LocalProviderStatus::Unavailable => red("✗"),
    }
}

fn status_label(status: LocalProviderStatus) -> String {
    match status {
        LocalProviderStatus::Ready => green("ready"),
        LocalProviderStatus::Installed => yellow("installed (not configured)"),
        LocalProviderStatus::Unavailable => dim("not found on PATH"),
    }
}

/// Probe a provider binary by running it with `--version` (2s cap, like `spawnSync` timeout).
async fn detect_binary(id: LocalProviderId) -> LocalProviderResult {
    let name = id.as_str();
    let probe = tokio::process::Command::new(name)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .status();
    match tokio::time::timeout(Duration::from_millis(2000), probe).await {
        Ok(Ok(_)) => LocalProviderResult { id, status: LocalProviderStatus::Installed, detail: Some(format!("{name}: found on PATH")) },
        _ => LocalProviderResult { id, status: LocalProviderStatus::Unavailable, detail: Some(format!("{name}: command not found")) },
    }
}

/// Run the detector against every provider in the registry.
pub async fn build_provider_results(registry: &LocalProviderRegistry) -> Vec<LocalProviderResult> {
    futures::future::join_all(registry.providers.iter().map(|p| detect_binary(p.id))).await
}

pub async fn run(args: &ProvidersArgs) -> Result<()> {
    match args.command {
        ProvidersCommand::Doctor => run_providers_doctor_command(None).await,
    }
}

pub async fn run_providers_doctor_command(config: Option<&str>) -> Result<()> {
    let registry = &*DEFAULT_LOCAL_PROVIDER_REGISTRY;
    let results = build_provider_results(registry).await;

    println!("{}", bold("\nLocal AI providers\n"));
    for r in &results {
        let name = registry.get(r.id).map_or(r.id.as_str(), |d| d.display_name.as_str());
        println!("  {} {:<8}  {:<22}  {}", status_mark(r.status), r.id.as_str(), name, status_label(r.status));
        if let (false, Some(detail)) = (r.status == LocalProviderStatus::Ready, r.detail.as_deref().filter(|d| !d.is_empty())) {
            println!("    {}", dim(&format!("→ {detail}")));
        }
    }
    println!();

    // Cloud provider: Anthropic — saved config (horus connect ai) OR env var.
    println!("{}", bold("Cloud AI providers\n"));
    let source = match load_config(config.map(std::path::Path::new), None) {
        Ok(cfg) => {
            let ai = resolve_ai_settings(&cfg);
            match ai.anthropic_api_key.as_deref().filter(|k| !k.is_empty()) {
                Some(_) if ai.anthropic_key_from_config => Some("config"),
                Some(_) => Some("env"),
                None => None,
            }
        }
        // No config — fall back to a bare env check.
        Err(_) => std::env::var("ANTHROPIC_API_KEY").ok().filter(|k| !k.is_empty()).map(|_| "env"),
    };
    let row = |mark: String, status: String| println!("  {mark} {:<8}  {:<22}  {status}", "anthropic", "Anthropic Claude API");
    match source {
        // Key from local config (secrets.local.json via `connect ai`, or config.json).
        Some("config") => row(green("✓"), green("configured (local .horus config)")),
        Some(_) => row(green("✓"), green("configured (ANTHROPIC_API_KEY env)")),
        None => {
            row(red("✗"), dim("not configured"));
            println!("    {}", dim("→ run `horus connect ai` (or set ANTHROPIC_API_KEY) to enable `horus investigate --ai`"));
        }
    }
    println!();
    Ok(())
}
