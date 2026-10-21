//! HOR-206 — `horus connect ai`: configure an AI narrative provider without editing shell env.
//! Port of `packages/cli/src/commands/connect-ai.ts`. The Anthropic key goes to
//! `.horus/secrets.local.json` (gitignored, HOR-212); config.json only carries the `ai` block.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::Result;
use horus_ai::local_providers::{LOCAL_PROVIDER_IDS, DEFAULT_LOCAL_PROVIDER_REGISTRY};
use horus_core::{
    discover_local_config, ensure_project_gitignore, find_repo_root, local_config_path, read_local_config,
    read_local_secrets, write_local_config, write_local_secrets, AnthropicSecrets, LocalConfigFile, AI_PROVIDERS,
};
use serde_json::{json, Map, Value};

use crate::commands::connect::{ask, ask_password};
use crate::lib::format::{bold, dim, green, red};
use crate::lib::tty_selector::is_interactive;

#[derive(Debug, Clone, Default)]
pub struct ConnectAiOpts {
    pub provider: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub no_test: bool,
}

/// Is a local provider CLI on PATH? (`<id> --version` spawns within 2 s.)
fn cli_installed(id: &str) -> bool {
    let Ok(mut child) = Command::new(id).arg("--version").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_millis(2000);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            // Timed out (TS: spawnSync sets `error` → not installed).
            _ => {
                let _ = child.kill();
                return false;
            }
        }
    }
}

/// Validate an Anthropic API key with a cheap authenticated GET /v1/models.
async fn probe_anthropic(api_key: &str) -> (bool, String) {
    let res = reqwest::Client::new()
        .get("https://api.anthropic.com/v1/models?limit=1")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .timeout(Duration::from_secs(8))
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => (true, "API key valid".into()),
        Ok(r) if r.status().as_u16() == 401 => (false, "invalid API key (401)".into()),
        Ok(r) => (false, format!("HTTP {}", r.status().as_u16())),
        Err(e) => (false, e.to_string()),
    }
}

fn redact_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() <= 12 {
        return "***".into();
    }
    format!("{}…{}", chars[..7].iter().collect::<String>(), chars[chars.len() - 4..].iter().collect::<String>())
}

fn provider_name(p: &horus_core::AiProvider) -> String {
    serde_json::to_value(p).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

pub async fn run_connect_ai(opts: ConnectAiOpts) -> u8 {
    match run_inner(opts).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", red(&err.to_string()));
            1
        }
    }
}

async fn run_inner(opts: ConnectAiOpts) -> Result<u8> {
    let cwd = std::env::current_dir()?;
    let root = find_repo_root(&cwd).unwrap_or_else(|| cwd.clone());
    let config_path = discover_local_config(&cwd).unwrap_or_else(|| local_config_path(&root));

    // Surface which local provider CLIs are installed (context for the choice).
    let installed: Vec<&str> = LOCAL_PROVIDER_IDS.iter().map(|id| id.as_str()).filter(|id| cli_installed(id)).collect();
    println!("{}", bold("\nAI providers"));
    println!(
        "{}",
        dim(&format!(
            "  Local CLIs on PATH: {}",
            if installed.is_empty() { "none detected".to_string() } else { installed.join(", ") }
        ))
    );
    println!("{}", dim("  Cloud: anthropic (Anthropic Claude API — used by `investigate --ai`)\n"));

    // Resolve the provider.
    let provider = match opts.provider {
        Some(p) => p,
        None if is_interactive() => {
            let a = ask("Provider", "anthropic", false).to_lowercase();
            if a.is_empty() {
                "anthropic".into()
            } else {
                a
            }
        }
        None => "anthropic".into(),
    };
    let supported: Vec<String> = AI_PROVIDERS.iter().map(provider_name).collect();
    if !supported.contains(&provider) {
        eprintln!(
            "{}{}",
            red(&format!("Unknown AI provider: {provider}")),
            dim(&format!("\n  supported: {}", supported.join(", ")))
        );
        return Ok(1);
    }

    // Build the `ai` block.
    let mut ai_block = Map::new();
    ai_block.insert("provider".into(), json!(provider));
    let mut stored_key: Option<String> = None;

    if provider == "anthropic" {
        let mut api_key = opts.api_key.filter(|k| !k.is_empty());
        if api_key.is_none() && is_interactive() {
            api_key = Some(ask_password("Anthropic API key", false)).filter(|k| !k.is_empty());
        }
        let Some(api_key) = api_key else {
            eprintln!(
                "{}{}",
                red("No API key provided."),
                dim("\n  Pass --api-key sk-ant-… or set ANTHROPIC_API_KEY and re-run.")
            );
            return Ok(1);
        };
        if !opts.no_test {
            let (ok, detail) = probe_anthropic(&api_key).await;
            if !ok {
                eprintln!("\n{} {detail}", red("✗ Anthropic key check failed:"));
                eprintln!("{}", dim("  Fix the key and retry, or pass --no-test to skip."));
                return Ok(1);
            }
            println!("\n{} anthropic {}", green("✓"), dim(&format!("({detail})")));
        }
        // Only the non-secret model preference lives in config.json.
        if let Some(m) = opts.model.filter(|m| !m.is_empty()) {
            ai_block.insert("anthropic".into(), json!({ "model": m }));
        }
        stored_key = Some(api_key);
    } else {
        // Local CLI provider — record the preference.
        if !installed.contains(&provider.as_str()) {
            eprintln!(
                "{}{}",
                red(&format!("{provider} CLI not found on PATH.")),
                dim("\n  Install it first, or choose anthropic.")
            );
            return Ok(1);
        }
        let display = LOCAL_PROVIDER_IDS
            .iter()
            .find(|id| id.as_str() == provider)
            .and_then(|id| DEFAULT_LOCAL_PROVIDER_REGISTRY.get(*id))
            .map_or(provider.clone(), |d| d.display_name.clone());
        println!("\n{} {display} {}", green("✓"), dim("detected on PATH"));
        println!(
            "{}",
            dim("  Note: `investigate --ai` currently uses the Anthropic API for narrative.\n  Local-CLI narrative generation is recorded as your preference for future use.")
        );
    }

    // Persist into the local config's top-level `ai` block.
    let mut file = if discover_local_config(&cwd).is_some() {
        read_local_config(&config_path)?
    } else {
        let root_s = root.to_string_lossy().into_owned();
        let name = root_s.rsplit('/').next().unwrap_or("project").to_string();
        LocalConfigFile {
            version: 1,
            project: json!({
                "name": name,
                "repositories": [{ "name": name, "path": root_s }],
                "environments": [{ "name": "production", "readOnly": true, "connectors": {} }],
            }),
            database: None,
            ai: None,
            extra: Map::new(),
        }
    };
    file.ai = Some(Value::Object(ai_block));
    write_local_config(&root, &file)?;
    ensure_project_gitignore(&root);
    // The API key is a secret — .horus/secrets.local.json (gitignored), never config.json.
    let mut secrets_path = None;
    if let Some(key) = &stored_key {
        let mut existing = read_local_secrets(&root);
        let mut anthropic = existing.anthropic.take().unwrap_or(AnthropicSecrets { api_key: None });
        anthropic.api_key = Some(key.clone());
        existing.anthropic = Some(anthropic);
        secrets_path = Some(write_local_secrets(&root, &existing)?);
    }

    println!("\n{} {} provider saved → {}", green("✓"), bold("ai"), dim(&config_path.display().to_string()));
    println!("{}", dim(&format!("  provider: {provider}")));
    if let (Some(key), Some(p)) = (&stored_key, &secrets_path) {
        println!("{}", dim(&format!("  anthropic key: {} → {} (gitignored)", redact_key(key), p.display())));
    }
    println!("{}", dim("  run: horus investigate \"<hint>\" --ai"));
    Ok(0)
}
