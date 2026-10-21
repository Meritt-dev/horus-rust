//! Cloud log providers (`cloud-logs/provider.ts`): Azure Monitor (Log Analytics REST with
//! an `az`-issued token), CloudWatch (`aws logs filter-log-events`) and GCP Logging
//! (`gcloud logging read`). Rows normalize into `AxiomLogRecord`s so they share the
//! structured-log evidence path.

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use horus_core::{
    redact_error_message, redact_secrets, validate_azure_monitor, validate_cloudwatch, validate_gcp_logging, AzureMonitorConfig,
    CloudWatchConfig, GcpLoggingConfig, HealthStatus, Issues, ProviderKind,
};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use super::native_cli::native_json;
use crate::axiom::client::AxiomLogRecord;
use crate::contract::Provider;
use crate::http::{fetch_with_retry, HttpRequestOptions};
use crate::jsutil::{iso_from_ms, issues_to_error, js_string, normalize_js_numbers, now_iso, now_ms, parse_js_date_ms, slice_chars};
pub use crate::sentry::provider::CollectOptions;

/// A provider that yields normalized structured log rows (Axiom + cloud logs).
#[async_trait]
pub trait StructuredLogSource: Provider {
    async fn collect(&self, opts: &CollectOptions) -> Result<Vec<AxiomLogRecord>>;
}

#[async_trait]
impl StructuredLogSource for crate::axiom::provider::AxiomProvider {
    async fn collect(&self, opts: &CollectOptions) -> Result<Vec<AxiomLogRecord>> {
        crate::axiom::provider::AxiomProvider::collect(self, opts).await
    }
}

/// `CloudLogConfig[K]` — the config for one cloud log connector kind.
#[derive(Debug, Clone, PartialEq)]
pub enum CloudLogConfig {
    AzureMonitor(AzureMonitorConfig),
    CloudWatch(CloudWatchConfig),
    GcpLogging(GcpLoggingConfig),
}

impl CloudLogConfig {
    /// The connector id (`azure-monitor` / `cloudwatch` / `gcp-logging`).
    pub fn id(&self) -> &'static str {
        match self {
            CloudLogConfig::AzureMonitor(_) => "azure-monitor",
            CloudLogConfig::CloudWatch(_) => "cloudwatch",
            CloudLogConfig::GcpLogging(_) => "gcp-logging",
        }
    }
}

/// Date-ish → ISO; None for anything `new Date(...)` would reject.
fn time(value: Option<&Value>) -> Option<String> {
    let ms = match value? {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite())? as i64,
        Value::String(s) => parse_js_date_ms(s)?,
        _ => return None,
    };
    let iso = iso_from_ms(ms);
    (!iso.is_empty()).then_some(iso)
}

/// `[a, b, c].find(v => typeof v === 'string' && v.length > 0)`.
fn first_str<'a>(cands: &[Option<&'a Value>]) -> Option<&'a str> {
    cands.iter().filter_map(|v| v.and_then(Value::as_str)).find(|s| !s.is_empty())
}

/// `a ?? b ?? c` (skips null/undefined).
fn coalesce<'a>(cands: &[Option<&'a Value>]) -> Option<&'a Value> {
    cands.iter().copied().flatten().find(|v| !v.is_null())
}

static ANSI_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").unwrap());
static TEXT_LEVEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\[(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)\]").unwrap());

/// Keep incident fields, not arbitrary cloud payloads or access tokens.
pub fn cloud_log_record(source: &str, row: &Map<String, Value>) -> AxiomLogRecord {
    let raw_message = first_str(&[
        row.get("message"),
        row.get("Message"),
        row.get("Log_s"),
        row.get("RenderedDescription"),
        row.get("textPayload"),
        row.get("OuterMessage"),
    ]);
    let nested: Map<String, Value> = raw_message
        .and_then(|m| match serde_json::from_str::<Value>(m) {
            Ok(Value::Object(o)) => Some(o),
            _ => None, // plain text
        })
        .unwrap_or_default();
    let mut data = row.clone();
    if let Some(Value::Object(jp)) = row.get("jsonPayload") {
        data.extend(jp.clone());
    }
    data.extend(nested);

    let raw_level = coalesce(&[data.get("level"), data.get("severity"), data.get("SeverityLevel")]);
    let message_src = first_str(&[data.get("message"), data.get("msg")]).or(raw_message).unwrap_or("(log event)");
    let message = slice_chars(&ANSI_RE.replace_all(&redact_secrets(message_src), ""), 8000);
    // Only explicit severity is authoritative. "Turn this warning into an error" is not an error.
    let text_level = TEXT_LEVEL_RE.captures(&message).map(|c| c[1].to_string());
    let mut level = match raw_level {
        Some(Value::Number(n)) => {
            let lv = n.as_f64().unwrap_or(f64::NAN);
            let azure_scale = data.get("SeverityLevel").is_some_and(Value::is_number) && !data.contains_key("level");
            if azure_scale {
                if lv >= 3.0 {
                    "error"
                } else if lv == 2.0 {
                    "warn"
                } else {
                    "info"
                }
            } else if lv >= 50.0 {
                "error"
            } else if lv >= 40.0 {
                "warn"
            } else {
                "info"
            }
            .to_string()
        }
        Some(v) => js_string(v).to_lowercase(),
        None => text_level.unwrap_or_else(|| "info".into()).to_lowercase(),
    };
    if level == "warning" {
        level = "warn".into();
    }
    if level == "alert" || level == "emergency" {
        level = "critical".into();
    }

    let event_id = match coalesce(&[data.get("insertId"), data.get("eventId")]) {
        Some(v) => js_string(v),
        None => {
            let mut r = Value::Object(row.clone());
            normalize_js_numbers(&mut r);
            Sha256::digest(serde_json::to_string(&r).unwrap_or_default().as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    let service = first_str(&[data.get("service_name"), data.get("service"), data.get("AppRoleName"), data.get("ContainerAppName_s")]).unwrap_or("");

    let mut fields = Map::new();
    fields.insert("source".into(), source.into());
    fields.insert("message".into(), message.into());
    fields.insert("level".into(), level.into());
    fields.insert("eventId".into(), event_id.into());
    fields.insert("service".into(), redact_secrets(service).into());
    for key in ["event_code", "errorCode", "orderId", "workflow", "correlationId", "traceId", "requestId"] {
        if let Some(Value::String(s)) = data.get(key) {
            fields.insert(key.into(), slice_chars(&redact_secrets(s), 500).into());
        }
    }
    let timestamp = time(coalesce(&[data.get("timestamp"), data.get("TimeGenerated"), data.get("time")]));
    AxiomLogRecord { timestamp, fields }
}

pub struct CloudLogsProvider {
    pub config: CloudLogConfig,
    client: reqwest::Client,
}

impl CloudLogsProvider {
    pub fn new(config: CloudLogConfig) -> Result<Self> {
        let mut issues = Issues::default();
        match &config {
            CloudLogConfig::AzureMonitor(c) => validate_azure_monitor(&mut issues, c),
            CloudLogConfig::CloudWatch(c) => validate_cloudwatch(&mut issues, c),
            CloudLogConfig::GcpLogging(c) => validate_gcp_logging(&mut issues, c),
        }
        issues_to_error(&issues)?;
        Ok(Self { config, client: reqwest::Client::new() })
    }

    async fn azure_rows(&self, c: &AzureMonitorConfig, from_ms: i64, to_ms: i64, terms: &[String], limit: usize) -> Result<Vec<Map<String, Value>>> {
        let term_clause = if terms.is_empty() {
            String::new()
        } else {
            format!(" | where {}", terms.iter().map(|t| format!("HorusText contains {}", serde_json::to_string(t).unwrap_or_default())).collect::<Vec<_>>().join(" or "))
        };
        let body = format!(
            "union isfuzzy=true {} | where TimeGenerated between (datetime({}) .. datetime({})) | extend HorusText=tostring(pack_all()){term_clause} | order by TimeGenerated desc | take {limit}",
            c.tables.join(", "),
            iso_from_ms(from_ms),
            iso_from_ms(to_ms)
        );
        // az rest can choose the default tenant even with --subscription. Bind the token explicitly.
        let mut args = vec!["account", "get-access-token", "--resource", "https://api.loganalytics.io"];
        if let Some(sub) = &c.subscription {
            args.extend(["--subscription", sub.as_str()]);
        }
        args.extend(["--output", "json"]);
        let auth = native_json(&c.executable, &args).await?;
        let token = auth.get("accessToken").and_then(Value::as_str).filter(|t| !t.is_empty()).ok_or_else(|| anyhow!("Azure CLI returned no access token"))?;
        let req = self
            .client
            .post(format!("https://api.loganalytics.azure.com/v1/workspaces/{}/query", c.workspace))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&json!({ "query": body }))?);
        let response = fetch_with_retry(req, &HttpRequestOptions::with_timeout_ms(30_000)).await.map_err(|e| anyhow!("{}", redact_error_message(&e)))?;
        if !response.status().is_success() {
            bail!("Azure Monitor HTTP {}", response.status().as_u16());
        }
        let raw: Value = response.json().await?;
        let tables = raw.get("tables").and_then(Value::as_array).ok_or_else(|| anyhow!("Invalid Azure Monitor response"))?;
        if raw.get("error").is_some_and(|e| !e.is_null()) {
            bail!("Azure Monitor returned partial/error results; inspect workspace query access");
        }
        let mut rows = Vec::new();
        for t in tables {
            let (Some(cols), Some(trows)) = (t.get("columns").and_then(Value::as_array), t.get("rows").and_then(Value::as_array)) else {
                bail!("Invalid Azure Monitor response");
            };
            let names: Vec<String> = cols.iter().map(|col| col.get("name").and_then(Value::as_str).map(str::to_string).ok_or_else(|| anyhow!("Invalid Azure Monitor response"))).collect::<Result<_>>()?;
            for r in trows {
                let r = r.as_array().ok_or_else(|| anyhow!("Invalid Azure Monitor response"))?;
                rows.push(names.iter().enumerate().map(|(i, n)| (n.clone(), r.get(i).cloned().unwrap_or(Value::Null))).collect());
            }
        }
        Ok(rows)
    }

    async fn cloudwatch_rows(&self, c: &CloudWatchConfig, from_ms: i64, to_ms: i64, terms: &[String], limit: usize) -> Result<Vec<Map<String, Value>>> {
        let mut rows: Vec<Map<String, Value>> = Vec::new();
        let mut next: Option<String> = None;
        let pattern = terms.iter().map(|t| format!("?{}", serde_json::to_string(t).unwrap_or_default())).collect::<Vec<_>>().join(" ");
        for _page in 0..5 {
            if rows.len() >= limit {
                break;
            }
            let (start, end, lim) = (from_ms.to_string(), to_ms.to_string(), (limit - rows.len()).to_string());
            let mut args: Vec<&str> = vec![
                "logs", "filter-log-events", "--region", &c.region, "--log-group-name", &c.log_group, "--start-time", &start, "--end-time", &end, "--limit", &lim,
                "--no-paginate", "--no-cli-pager", "--output", "json",
            ];
            if let Some(p) = &c.profile {
                args.extend(["--profile", p.as_str()]);
            }
            if !terms.is_empty() {
                args.extend(["--filter-pattern", pattern.as_str()]);
            }
            if let Some(n) = &next {
                args.extend(["--next-token", n.as_str()]);
            }
            let raw = native_json(&c.executable, &args).await?;
            let events = raw.get("events").and_then(Value::as_array).ok_or_else(|| anyhow!("Invalid CloudWatch response"))?;
            for e in events {
                rows.push(e.as_object().cloned().ok_or_else(|| anyhow!("Invalid CloudWatch response"))?);
            }
            let token = raw.get("nextToken").and_then(Value::as_str).map(str::to_string);
            match token {
                Some(t) if !t.is_empty() && Some(&t) != next.as_ref() => next = Some(t),
                _ => break,
            }
        }
        Ok(rows)
    }

    async fn gcp_rows(&self, c: &GcpLoggingConfig, from_ms: i64, to_ms: i64, terms: &[String], limit: usize) -> Result<Vec<Map<String, Value>>> {
        let q = |s: &str| serde_json::to_string(s).unwrap_or_default();
        let mut parts = vec![format!("timestamp >= {}", q(&iso_from_ms(from_ms))), format!("timestamp <= {}", q(&iso_from_ms(to_ms)))];
        if !c.filter.is_empty() {
            parts.push(format!("({})", c.filter));
        }
        if !terms.is_empty() {
            parts.push(format!("({})", terms.iter().map(|t| q(t)).collect::<Vec<_>>().join(" OR ")));
        }
        let filter = parts.join(" AND ");
        let lim = limit.to_string();
        let raw = native_json(&c.executable, &["logging", "read", &filter, "--project", &c.project, "--limit", &lim, "--order", "desc", "--format", "json", "--quiet"]).await?;
        raw.as_array()
            .ok_or_else(|| anyhow!("Invalid gcloud logging response"))?
            .iter()
            .map(|r| r.as_object().cloned().ok_or_else(|| anyhow!("Invalid gcloud logging response")))
            .collect()
    }
}

#[async_trait]
impl StructuredLogSource for CloudLogsProvider {
    async fn collect(&self, opts: &CollectOptions) -> Result<Vec<AxiomLogRecord>> {
        let to = opts.to.clone().unwrap_or_else(now_iso);
        let (to_ms, from_ms) = match parse_js_date_ms(&to) {
            Some(t) => (Some(t), match &opts.from {
                Some(f) => parse_js_date_ms(f),
                None => Some(t - 86_400_000),
            }),
            None => (None, None),
        };
        let (Some(from_ms), Some(to_ms)) = (from_ms, to_ms) else { bail!("Invalid log time window") };
        if from_ms > to_ms {
            bail!("Invalid log time window");
        }
        // ponytail: bounded evidence sample, not a lossless watcher cursor. Native trigger adapters must paginate separately.
        let limit = 200;
        let terms: Vec<String> = opts.hint_terms.iter().flatten().filter(|t| t.chars().count() > 2).take(8).cloned().collect();
        let rows = match &self.config {
            CloudLogConfig::AzureMonitor(c) => self.azure_rows(c, from_ms, to_ms, &terms, limit).await?,
            CloudLogConfig::CloudWatch(c) => self.cloudwatch_rows(c, from_ms, to_ms, &terms, limit).await?,
            CloudLogConfig::GcpLogging(c) => self.gcp_rows(c, from_ms, to_ms, &terms, limit).await?,
        };
        let id = self.config.id();
        Ok(rows.iter().map(|r| cloud_log_record(id, r)).collect())
    }
}

#[async_trait]
impl Provider for CloudLogsProvider {
    fn id(&self) -> &str {
        self.config.id()
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Logs
    }
    async fn health(&self) -> HealthStatus {
        let opts = CollectOptions { from: Some(iso_from_ms(now_ms() - 60_000)), to: Some(now_iso()), ..Default::default() };
        match self.collect(&opts).await {
            Ok(_) => HealthStatus { ok: true, detail: format!("{}: read access verified", self.config.id()) },
            Err(e) => HealthStatus { ok: false, detail: redact_error_message(&e) },
        }
    }
}
