//! `horus service <action>` — macOS watcher: check, install, start, run, status, pause,
//! resume, stop, remove, retry (plus internal `worker` / `activity`).
//! Port of `packages/cli/src/commands/service.ts`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{bail, Result};
use horus_connectors::{logs_for_env, sentry_for_env, Provider};
use horus_core::{load_config, resolve_environment, ResolveOptions};
use horus_db::{acquire_db_lock, create_local_db};
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::lib::claude_investigation::{run_process, RunOptions};
use crate::lib::cloud::memory_sync::memory_sync_context;
use crate::lib::host_reaper::is_pid_alive;
use crate::lib::watch_service::{
    read_service_config, record_service_failure, route_key, run_service_worker, run_watch_service, same_path,
    service_home, service_webhook, ServiceConfig,
};
use crate::lib::watch_store::{jobs, read_watch_state, save_job};
use crate::lib::worker_activity::record_activity_hook;

fn xml(v: &str) -> String {
    v.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            other => other.to_string(),
        })
        .collect()
}

pub fn service_label(profile: &str) -> Result<String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9-]{1,40}$").unwrap());
    if !RE.is_match(profile) {
        bail!("Profile must be 1–40 lowercase letters, digits or hyphens");
    }
    Ok(format!("sh.horus.watch.{profile}"))
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_default()
}

pub fn launchd_plist(config: &ServiceConfig, settings: &str, profile: &str) -> Result<String> {
    let mut env: Vec<(String, String)> = vec![
        ("HOME".into(), home().to_string_lossy().into()),
        ("PATH".into(), std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())),
    ];
    for k in ["CLAUDE_CONFIG_DIR", "HORUS_HOME", "HORUS_DB_DIR", "HORUS_SERVICE_DIR"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                env.push((k.into(), v));
            }
        }
    }
    // Object spread: a later key overwrites an earlier one in place.
    for (k, v) in &config.environment {
        match env.iter_mut().find(|(ek, _)| ek == k) {
            Some(slot) => slot.1 = v.clone(),
            None => env.push((k.clone(), v.clone())),
        }
    }
    let mut args = vec![config.runtime.clone()];
    args.extend(config.command_args(&["service", "run", "--settings", settings]));
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict>
<key>Label</key><string>{}</string>
<key>ProgramArguments</key><array>{}</array>
<key>WorkingDirectory</key><string>{}</string>
<key>EnvironmentVariables</key><dict>{}</dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>30</integer>
<key>ProcessType</key><string>Background</string><key>ExitTimeOut</key><integer>5</integer>
</dict></plist>\n",
        xml(&service_label(profile)?),
        args.iter().map(|v| format!("<string>{}</string>", xml(v))).collect::<String>(),
        xml(&config.projects[0].root),
        env.iter().map(|(k, v)| format!("<key>{}</key><string>{}</string>", xml(k), xml(v))).collect::<String>(),
    ))
}

fn launchctl(args: &[&str], allow_missing: bool) -> Result<String> {
    let out = std::process::Command::new("/bin/launchctl").args(args).stdin(Stdio::null()).output()?;
    if !out.status.success() && !allow_missing {
        bail!("launchctl {}: {}", args[0], String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into())
}

/// Options shared by every action (the commander option bag).
#[derive(Debug, Clone, Default)]
pub struct ServiceOpts {
    pub settings: Option<String>,
    pub profile: Option<String>,
    pub job: Option<String>,
    pub session: Option<String>,
    pub once: bool,
    pub delivery_checked: bool,
    pub skip_checks: bool,
    pub path: Option<String>,
    pub env: Option<String>,
}

pub async fn run(args: &ServiceArgs) -> Result<()> {
    run_service(
        &args.action,
        &ServiceOpts {
            settings: args.settings.clone(),
            profile: Some(args.profile.clone()),
            job: args.job.clone(),
            session: args.session.clone(),
            once: args.once,
            delivery_checked: args.delivery_checked,
            skip_checks: args.skip_checks,
            path: args.path.clone(),
            env: args.env.clone(),
        },
    )
    .await
}

/// Lexical `path.resolve`.
fn resolve(p: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for c in std::env::current_dir().unwrap_or_default().join(p).components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub async fn run_service(action: &str, opts: &ServiceOpts) -> Result<()> {
    if action == "activity" {
        if let (Some(session), Some(job)) = (&opts.session, &opts.job) {
            record_activity_hook(&service_home(), session, job);
        }
        return Ok(());
    }
    let settings = match &opts.settings {
        Some(s) => resolve(s),
        None => service_home().join("settings.json"),
    };
    if action == "pause" || action == "resume" {
        let file = std::fs::canonicalize(&settings)?;
        let _release = acquire_db_lock(&file, Duration::from_millis(2000))?;
        let temporary = PathBuf::from(format!("{}.{}.tmp", file.display(), std::process::id()));
        let result = (|| -> Result<()> {
            let mut config = read_service_config(&file)?;
            let target = opts.path.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_default().to_string_lossy().into());
            let matches: Vec<usize> = config
                .projects
                .iter()
                .enumerate()
                .filter(|(_, p)| same_path(&p.root, &target) && opts.env.as_deref().map_or(true, |e| p.environment == e))
                .map(|(i, _)| i)
                .collect();
            if matches.len() != 1 {
                bail!("Select exactly one configured project with --path and --env");
            }
            let project = &mut config.projects[matches[0]];
            project.enabled = action == "resume";
            let (name, env, enabled) = (project.project.clone(), project.environment.clone(), project.enabled);
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary)?;
            f.write_all((horus_core::json::to_js_json_pretty(&config)? + "\n").as_bytes())?;
            std::fs::rename(&temporary, &file)?;
            println!(
                "{name}/{env}: {}. Applies on the next service cycle; an active investigation finishes. Queued work is preserved.",
                if enabled { "resumed" } else { "paused" }
            );
            Ok(())
        })();
        let _ = std::fs::remove_file(&temporary);
        return result;
    }
    if action == "worker" {
        let Some(job) = &opts.job else { bail!("--job required") };
        return run_service_worker(&settings, job).await;
    }
    if action == "run" {
        if let Err(error) = run_watch_service(&settings, opts.once).await {
            record_service_failure(&error);
            return Err(error);
        }
        return Ok(());
    }
    let profile = opts.profile.clone().unwrap_or_else(|| "default".into());
    let label = service_label(&profile)?;
    let domain = format!("gui/{}", uid());
    let plist = home().join("Library").join("LaunchAgents").join(format!("{label}.plist"));
    match action {
        "status" => status(&domain, &label),
        "retry" => retry(&settings, opts).await,
        "check" | "install" => check_or_install(action, &settings, &profile, &label, &domain, &plist, opts).await,
        "start" => {
            if !cfg!(target_os = "macos") || !plist.exists() {
                bail!("Install the macOS profile first");
            }
            launchctl(&["bootstrap", &domain, &plist.to_string_lossy()], false)?;
            Ok(())
        }
        "stop" | "remove" => {
            if !cfg!(target_os = "macos") {
                bail!("launchd management requires macOS");
            }
            launchctl(&["bootout", &format!("{domain}/{label}")], true)?;
            if action == "remove" && plist.exists() {
                std::fs::remove_file(&plist)?;
            }
            println!(
                "{} {label}; queue history and reports preserved.",
                if action == "remove" { "Removed" } else { "Stopped" }
            );
            Ok(())
        }
        _ => bail!("Use service check|install|start|run|status|pause|resume|stop|remove|retry"),
    }
}

fn status(domain: &str, label: &str) -> Result<()> {
    let status_path = service_home().join("status.json");
    let mut snapshot: Map<String, Value> = if status_path.exists() {
        match serde_json::from_str(&std::fs::read_to_string(&status_path)?)? {
            Value::Object(m) => m,
            _ => Map::new(),
        }
    } else {
        let mut m = Map::new();
        m.insert("state".into(), json!("not started"));
        m
    };
    let alive = snapshot.get("pid").and_then(Value::as_i64).filter(|p| *p != 0).is_some_and(is_pid_alive);
    let fresh = snapshot
        .get("at")
        .and_then(Value::as_str)
        .and_then(crate::lib::watch_store::parse_ms)
        .is_some_and(|at| chrono::Utc::now().timestamp_millis() - at < 120_000);
    let launchd = if cfg!(target_os = "macos") {
        let out = launchctl(&["print", &format!("{domain}/{label}")], true)?;
        out.split('\n')
            .find_map(|l| l.split_once("state = ").map(|(_, s)| s.to_string()))
            .unwrap_or_else(|| "not loaded".into())
    } else {
        "macOS only".into()
    };
    snapshot.insert("online".into(), json!(alive && fresh));
    snapshot.insert("launchd".into(), json!(launchd));
    println!("{}", horus_core::json::to_js_json_pretty(&Value::Object(snapshot))?);
    Ok(())
}

async fn retry(settings: &Path, opts: &ServiceOpts) -> Result<()> {
    let Some(job_id) = &opts.job else { bail!("--job required") };
    let db = create_local_db(None).await?;
    let result: Result<()> = async {
        let Some(mut job) = jobs(&db, None).await?.into_iter().find(|j| &j.id == job_id) else { bail!("Job not found") };
        if job.pid.is_some_and(is_pid_alive) {
            bail!("Job is still running");
        }
        if job.notification_key.is_some() && !opts.delivery_checked {
            bail!("Inspect destination, then use --delivery-checked to permit another send");
        }
        if let Some(req) = job.cloud_request.clone() {
            let config = read_service_config(settings)?;
            let p = config.projects.iter().find(|p| route_key(p) == job.route);
            let cloud = p.and_then(|p| {
                memory_sync_context(Path::new(&p.root), &p.project, Some(std::time::Instant::now() + Duration::from_secs(15)))
            });
            let (Some(cloud), Some(p)) = (cloud, p) else { bail!("Sign in to the job Cloud scope before retrying") };
            if read_watch_state::<String>(&db, &format!("scope:{}", job.route)).await?.as_deref() != Some(cloud.scope.as_str()) {
                bail!("Job Cloud scope mismatch");
            }
            let ws = cloud.config.workspace.as_ref().map(|w| w.id.clone()).unwrap_or_default();
            let project_id = cloud.config.project.as_ref().map(|p| p.id.clone()).unwrap_or_default();
            cloud
                .client
                .alert_request(&ws, &req.id, "retry", &json!({ "projectId": project_id, "environment": p.environment }))
                .await?;
        }
        if opts.delivery_checked {
            job.notification_key = None;
            job.notified = Some(false);
        }
        job.status = "pending".into();
        job.attempts.insert(job.stage.clone(), 0);
        job.next_attempt_at = 0;
        job.error = None;
        job.pid = None;
        save_job(&db, &job).await
    }
    .await;
    db.end().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn check_or_install(
    action: &str,
    settings: &Path,
    profile: &str,
    label: &str,
    domain: &str,
    plist: &Path,
    opts: &ServiceOpts,
) -> Result<()> {
    let config = read_service_config(settings)?;
    if config.environment.contains_key("ANTHROPIC_API_KEY") || config.environment.contains_key("ANTHROPIC_AUTH_TOKEN") {
        bail!("Use the local Claude Code login; do not configure API credentials for this adapter");
    }
    for (k, v) in &config.environment {
        std::env::set_var(k, v);
    }
    for executable in [&config.runtime, &config.claude] {
        let meta = std::fs::metadata(executable)?;
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            bail!("EACCES: permission denied, access '{executable}'");
        }
        std::fs::canonicalize(executable)?;
    }
    std::fs::File::open(&config.entry)?;
    println!(
        "Backlog: active events from previous 24h; at most ten bootstrap executions, remaining backlog retained. Daily limits: {} investigations / {} model calls.",
        config.daily_investigations, config.daily_model_calls
    );
    if !opts.skip_checks {
        let env: Vec<(String, String)> =
            std::env::vars().filter(|(k, _)| k != "ANTHROPIC_API_KEY" && k != "ANTHROPIC_AUTH_TOKEN").collect();
        let raw = run_process(
            &config.claude,
            &["auth".to_string(), "status".to_string()],
            RunOptions {
                cwd: Path::new(&config.projects[0].root),
                input: None,
                timeout_ms: 15_000,
                cancel: None,
                env: Some(env),
                inherit_process_group: false,
                on_message: None,
            },
        )
        .await?;
        let auth: Value = serde_json::from_str(&raw)?;
        if auth.get("loggedIn") != Some(&json!(true)) {
            bail!("Claude Code is not logged in; run claude auth login as this local user");
        }
        for p in config.projects.iter().filter(|p| p.enabled) {
            let root = Path::new(&p.root);
            let loaded = load_config(Some(Path::new(&p.config)), Some(root))?;
            let env = resolve_environment(
                &loaded,
                &ResolveOptions { project: Some(&p.project), env: Some(&p.environment), cwd: Some(root) },
            )?;
            if !same_path(&env.path, &p.root) {
                bail!("Project root mismatch: {}", p.project);
            }
            let Some(cloud) = memory_sync_context(root, &p.project, Some(std::time::Instant::now() + Duration::from_secs(15)))
            else {
                bail!("{}: sign in and link Cloud first", p.project);
            };
            let ws = cloud.config.workspace.as_ref().map(|w| w.id.clone()).unwrap_or_default();
            let project_id = cloud.config.project.as_ref().map(|p| p.id.clone()).unwrap_or_default();
            cloud.client.list_alert_requests(&ws, &project_id, &p.environment).await?;
            let source = if p.source == "auto" {
                if env.connectors.sentry.is_some() { "sentry" } else { "elasticsearch" }
            } else {
                p.source.as_str()
            };
            if source == "pagerduty"
                && !cloud.client.list_alert_sources(&ws).await?.iter().any(|s| {
                    s.enabled
                        && s.provider == "pagerduty"
                        && s.project_id.as_deref() == Some(project_id.as_str())
                        && s.environment.as_deref() == Some(p.environment.as_str())
                        && s.service_id.as_deref().is_some_and(|x| !x.is_empty())
                })
            {
                bail!("{}: configure and enable the native PagerDuty subscription first", p.project);
            }
            if source == "sentry" {
                let ok = match sentry_for_env(&env) {
                    Some(provider) => provider.health().await.ok,
                    None => false,
                };
                if !ok {
                    bail!("{}: Sentry unavailable", p.project);
                }
            }
            if source == "elasticsearch" {
                let ok = match logs_for_env(&env)? {
                    Some(provider) => provider.health().await.ok,
                    None => false,
                };
                if !ok {
                    bail!("{}: Elasticsearch unavailable", p.project);
                }
            }
            let webhook = p.notifications == "configured" && service_webhook(env.notify.as_ref())?.is_some();
            println!(
                "{}/{}: {source}; Slack reports and worker notices follow Cloud project settings; optional generic webhook {}",
                p.project,
                p.environment,
                if webhook { "selected" } else { "off" }
            );
        }
    } else if action == "install" && profile == "default" {
        bail!("--skip-checks is restricted to an explicitly named test profile");
    }
    if action == "check" {
        println!("Paths/auth/connectivity checked. Opus access requires a real investigation; no model substitution.");
        return Ok(());
    }
    if !cfg!(target_os = "macos") {
        bail!("launchd installation requires macOS");
    }
    std::fs::create_dir_all(home().join("Library").join("LaunchAgents"))?;
    if plist.exists() {
        bail!("Profile already installed; stop/remove before reinstalling");
    }
    let body = launchd_plist(&config, &settings.to_string_lossy(), profile)?;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(plist)?;
    f.write_all(body.as_bytes())?;
    launchctl(&["bootstrap", domain, &plist.to_string_lossy()], false)?;
    println!("Installed {label}. Settings: {}", settings.display());
    Ok(())
}
