//! `horus notify` — configure the outbound notify sink for `horus watch` (HOR-454).
//! Port of `packages/cli/src/commands/notify.ts`.
//!
//! set (webhook url/threshold/cloud; signing secret ENCRYPTED in .horus/secrets.local.json),
//! show (secret never printed), test (sample signed dispatch), remove. Mirrors `horus connect`.

use std::path::{Path, PathBuf};

use anyhow::Result;
use horus_core::{
    discover_local_config, ensure_master_key, ensure_project_gitignore, find_repo_root, load_config,
    local_config_path, read_local_config, resolve_environment, write_connector_secret, write_local_config,
    LocalConfigFile, ResolveOptions,
};
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red, yellow};
use crate::lib::notify_sink::{dispatch_notify, DispatchReport, NoPush};

fn fail() -> anyhow::Error {
    SilentExit(1).into()
}

/// Locate the repo root + config path, or print a hint.
fn locate(config: Option<&str>) -> Option<(PathBuf, PathBuf)> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let config_path = config.map(PathBuf::from).or_else(|| discover_local_config(&cwd));
    let Some(root) = find_repo_root(&cwd) else {
        eprintln!("{}", red("Not inside a git repository — run this from your project."));
        return None;
    };
    let resolved = config_path.unwrap_or_else(|| local_config_path(&root));
    Some((root, resolved))
}

fn read_config_or_error(path: &Path) -> Option<LocalConfigFile> {
    match read_local_config(path) {
        Ok(f) => Some(f),
        Err(_) => {
            eprintln!(
                "{}",
                red(&format!("No config found at {} — run `horus connect` or `horus init` first.", path.display()))
            );
            None
        }
    }
}

/// Index of the target environment by name (or the first), or None with a printed error.
fn pick_env(file: &LocalConfigFile, requested: Option<&str>) -> Option<usize> {
    let envs = file.project.get("environments").and_then(Value::as_array).cloned().unwrap_or_default();
    if envs.is_empty() {
        eprintln!("{}", red("No environments in config — run `horus connect` or `horus init` first."));
        return None;
    }
    match requested.filter(|r| !r.is_empty()) {
        Some(r) => {
            let found = envs.iter().position(|e| e.get("name").and_then(Value::as_str) == Some(r));
            if found.is_none() {
                eprintln!("{}", red(&format!("Environment \"{r}\" not found in config.")));
            }
            found
        }
        None => Some(0),
    }
}

fn env_mut(file: &mut LocalConfigFile, i: usize) -> &mut Map<String, Value> {
    file.project["environments"][i].as_object_mut().expect("environment is an object")
}

/// JS template interpolation of a JSON value (`${x}` → `undefined` for absent).
fn js(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => horus_core::json::to_js_json(other).unwrap_or_default(),
    }
}

pub async fn run(args: &NotifyArgs) -> Result<()> {
    match &args.command {
        NotifyCommand::Set(a) => run_set(a),
        NotifyCommand::Show(a) => run_show(a.config.as_deref(), a.env.as_deref()),
        NotifyCommand::Test(a) => run_test(a).await,
        NotifyCommand::Remove(a) => run_remove(a.config.as_deref(), a.env.as_deref()),
    }
}

fn run_set(a: &NotifySetArgs) -> Result<()> {
    let Some(url) = a.url.as_deref().filter(|u| !u.is_empty()) else {
        eprintln!(
            "{}",
            red("A webhook URL is required: horus notify set --url <https://…> [--secret <s>] [--min-confidence 0.6] [--cloud]")
        );
        return Err(fail());
    };
    if url::Url::parse(url).is_err() {
        eprintln!("{}", red(&format!("Invalid --url \"{url}\".")));
        return Err(fail());
    }
    let mut min_confidence = None;
    if let Some(raw) = &a.min_confidence {
        // JS Number(): trimmed decimal; empty string is 0.
        let n = if raw.trim().is_empty() { Some(0.0) } else { raw.trim().parse::<f64>().ok() };
        match n.filter(|n| n.is_finite() && (0.0..=1.0).contains(n)) {
            Some(n) => min_confidence = Some(n),
            None => {
                eprintln!("{}", red(&format!("--min-confidence must be between 0 and 1 (got \"{raw}\").")));
                return Err(fail());
            }
        }
    }
    // Tri-state --cloud / --no-cloud: true | false | unchanged.
    let cloud = if a.cloud { Some(true) } else if a.no_cloud { Some(false) } else { None };

    let Some((root, config_path)) = locate(a.config.as_deref()) else { return Err(fail()) };
    let Some(mut file) = read_config_or_error(&config_path) else { return Err(fail()) };
    let Some(i) = pick_env(&file, a.env.as_deref()) else { return Err(fail()) };
    let env = env_mut(&mut file, i);
    let env_name = env.get("name").and_then(Value::as_str).unwrap_or("production").to_string();

    // Non-secret fields → config.json. The signing secret → encrypted secrets store.
    let notify = env.entry("notify").or_insert_with(|| json!({}));
    if !notify.is_object() {
        *notify = json!({});
    }
    let n = notify.as_object_mut().expect("object");
    n.insert("webhook".into(), json!({ "url": url }));
    if let Some(m) = min_confidence {
        n.insert("minConfidence".into(), json!(m));
    }
    if let Some(c) = cloud {
        n.insert("cloud".into(), json!(c));
    }
    let threshold = n.get("minConfidence").cloned().unwrap_or(json!(0.6));
    let cloud_on = n.get("cloud") == Some(&json!(true));

    write_local_config(&root, &file)?;
    ensure_project_gitignore(&root);

    let mut secret_note = String::new();
    if let Some(secret) = a.secret.as_deref().filter(|s| !s.is_empty()) {
        let stored = ensure_master_key()
            .map_err(anyhow::Error::from)
            .and_then(|k| write_connector_secret(&root, &env_name, "notify", "webhookSecret", secret, Some(&k.key)));
        match stored {
            Ok(()) => secret_note = dim(" · signing secret stored encrypted (.horus/secrets.local.json)"),
            Err(e) => eprintln!(
                "{}",
                yellow(&format!("Notify URL saved, but the signing secret could not be encrypted: {e}"))
            ),
        }
    }

    println!(
        "{}\n  {} {url}\n  {} {}\n  {} {cloud_on}{secret_note}",
        green(&format!("✓ Notify sink configured for \"{env_name}\"")),
        dim("webhook:"),
        dim("threshold:"),
        js(Some(&threshold)),
        dim("cloud:"),
    );
    println!("{}", dim("  Run `horus notify test` to send a sample, or `horus watch` to start monitoring."));
    Ok(())
}

fn run_show(config: Option<&str>, env: Option<&str>) -> Result<()> {
    let Some((_, config_path)) = locate(config) else { return Err(fail()) };
    let Some(file) = read_config_or_error(&config_path) else { return Err(fail()) };
    let Some(i) = pick_env(&file, env) else { return Err(fail()) };
    let e = &file.project["environments"][i];
    let name = js(e.get("name"));
    let n = e.get("notify").filter(|n| !n.is_null());
    let url = n.and_then(|n| n.pointer("/webhook/url")).filter(|u| !matches!(u, Value::Null) && u.as_str() != Some(""));
    let (Some(n), Some(url)) = (n, url) else {
        println!("{}", dim(&format!("No notify sink configured for \"{name}\". Set one: horus notify set --url <https://…>")));
        return Ok(());
    };
    let threshold = n.get("minConfidence").filter(|v| !v.is_null()).cloned().unwrap_or(json!(0.6));
    println!(
        "{}\n  webhook:    {}\n  threshold:  {}\n  cloud:      {}",
        bold(&format!("Notify sink for \"{name}\"")),
        js(Some(url)),
        js(Some(&threshold)),
        n.get("cloud") == Some(&json!(true))
    );
    Ok(())
}

async fn run_test(a: &NotifyTestArgs) -> Result<()> {
    // Resolved view so the encrypted secret is hydrated (loadConfig path).
    let notify = match load_config(a.config.as_deref().map(Path::new), None)
        .and_then(|c| resolve_environment(&c, &ResolveOptions { env: a.env.as_deref(), ..Default::default() }))
    {
        Ok(renv) => renv.notify,
        Err(e) => {
            eprintln!("{}", red(&format!("Could not load config: {e}")));
            return Err(fail());
        }
    };
    let Some(mut notify) = notify.filter(|n| n.webhook.is_some()) else {
        eprintln!("{}", red("No webhook configured — run `horus notify set --url <https://…>` first."));
        return Err(fail());
    };
    let report = DispatchReport {
        id: format!("test-{}", to_base36(chrono::Utc::now().timestamp_millis() as u64)),
        confidence: notify.min_confidence.max(0.99),
        hint: "horus notify test".into(),
        cause: "This is a test dispatch from `horus notify test` — your sink is wired up correctly.".into(),
        notification_key: None,
        report_url: None,
    };
    notify.min_confidence = 0.0;
    let results = dispatch_notify(report, Some(&notify), None, None::<NoPush>).await;
    if results.is_empty() {
        eprintln!("{}", yellow("Nothing dispatched (no target enabled)."));
        return Err(fail());
    }
    let mut ok = true;
    for r in results {
        if r.ok {
            println!("{}", green(&format!("✓ {} — {}", r.target, r.detail)));
        } else {
            ok = false;
            eprintln!("{}", red(&format!("✗ {} — {}", r.target, r.detail)));
        }
    }
    if ok {
        Ok(())
    } else {
        Err(fail())
    }
}

fn to_base36(mut n: u64) -> String {
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    loop {
        out.push(digits[(n % 36) as usize]);
        n /= 36;
        if n == 0 {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

fn run_remove(config: Option<&str>, env: Option<&str>) -> Result<()> {
    let Some((root, config_path)) = locate(config) else { return Err(fail()) };
    let Some(mut file) = read_config_or_error(&config_path) else { return Err(fail()) };
    let Some(i) = pick_env(&file, env) else { return Err(fail()) };
    let e = env_mut(&mut file, i);
    let name = js(e.get("name"));
    if e.get("notify").is_none() {
        println!("{}", dim(&format!("No notify sink configured for \"{name}\".")));
        return Ok(());
    }
    e.shift_remove("notify");
    write_local_config(&root, &file)?;
    println!("{}", green(&format!("✓ Removed notify sink from \"{name}\".")));
    println!(
        "{}",
        dim("  (Any stored signing secret remains in .horus/secrets.local.json — remove it with `horus secrets` if needed.)")
    );
    Ok(())
}
