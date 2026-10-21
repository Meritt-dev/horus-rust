//! Native vendor-CLI execution (`cloud-logs/native-cli.ts`): reuse the local user's
//! `az` / `aws` / `gcloud` login. Fixed argument arrays; never a shell or login prompt.

use anyhow::{anyhow, Result};
use horus_core::redact_error_message;
use serde_json::Value;
use std::process::Stdio;
use std::time::Duration;

/// Reuse the local user's vendor login. Fixed argument arrays; never a shell or login prompt.
pub async fn native_output(executable: &str, args: &[&str]) -> Result<String> {
    let run = tokio::process::Command::new(executable)
        .args(args)
        .env("AWS_PAGER", "")
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .env("AZURE_CORE_ONLY_SHOW_ERRORS", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();
    let fail = |msg: String| anyhow!(redact_error_message(&format!("{executable}: {msg}")).chars().take(1200).collect::<String>());
    let out = match tokio::time::timeout(Duration::from_secs(30), run).await {
        Err(_) => return Err(fail("timed out after 30000ms".into())),
        Ok(Err(e)) => return Err(fail(e.to_string())),
        Ok(Ok(o)) => o,
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let msg = if stderr.is_empty() { format!("exited with {}", out.status) } else { stderr };
        return Err(fail(msg));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub async fn native_json(executable: &str, args: &[&str]) -> Result<Value> {
    Ok(serde_json::from_str(&native_output(executable, args).await?)?)
}

