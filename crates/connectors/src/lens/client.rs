//! Read-only Lens (Horus Cloud) client (HOR-CONNECTORS / HOR-470).
//!
//! Lens is Horus's issue-capture product: users file bug reports from the running app.
//! Reports live in Horus Cloud and are read through the workspace-scoped management API
//! (`/v1/workspaces/:workspaceId/lens/...`).
//!
//! NATIVE CONNECTOR: there is no `horus connect lens` and no config stanza — this client is
//! constructed straight from the CLI's cloud auth state (bearer token + apiBaseUrl) and the
//! repo's cloud-linked `workspace.id`. See `factory::lens_for_cloud`.
//!
//! Safety: only GET endpoints. Transport goes through `fetch_with_retry`. `list_sites` /
//! `list_reports` / `get_report` PROPAGATE non-2xx + transport failures so the engine can
//! tell "Lens is down/misconfigured" from "no reports matched"; `health()` never fails.

use horus_core::{redact_error_message, redact_upstream_body, HealthStatus};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::http::{fetch_with_retry, HttpRequestOptions};
use crate::source::client::{encode_uri_component, form_encode};

#[derive(Debug, Clone)]
pub struct LensClientOpts {
    /// Horus Cloud API base URL (from the CLI auth state's `apiBaseUrl`).
    pub api_base_url: String,
    /// Cloud bearer token (from the CLI auth state's `token`).
    pub token: String,
    /// The cloud-linked workspace id (from `<repo>/.horus/cloud.json`'s `workspace.id`).
    pub workspace_id: String,
    /// Transport overrides (timeout / retry) forwarded to fetch_with_retry.
    pub http: Option<HttpRequestOptions>,
}

/// A Lens site the workspace owns — the discovery unit reports hang off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensSite {
    pub id: String,
    pub name: String,
}

/// A condensed report row from the list endpoint (no heavy metadata).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LensReportSummary {
    pub id: String,
    pub lens_site_id: String,
    pub status: String,
    pub created_at: String,
    pub submitted_at: Option<String>,
    pub external_issue: Value,
    pub lens_issue_id: Option<String>,
    pub issue_occurrence_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub error_count: f64,
    pub has_replay: bool,
}

/// One frontend error captured on a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensErrorEntry {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    pub source: String,
    pub timestamp: f64,
}

/// One network request captured in the report's network tail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LensNetworkEntry {
    pub method: String,
    pub url: String,
    pub status: Option<i64>,
    pub ok: Option<bool>,
    pub duration_ms: Option<f64>,
    pub request_type: String,
    pub started_at: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The target element the user was pointing at when they filed the report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LensTargetElement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dom_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub react_components: Option<Vec<String>>,
}

/// The capture environment (page URL / route / browser).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LensEnvContext {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
}

/// App-level context the SDK attached (release / gitSha / flags). The wire `user` field
/// (PII) is deliberately NEVER read.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LensAppContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_flags: Option<Map<String, Value>>,
}

/// The report metadata blob (everything except heavy S3 assets).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LensReportMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<LensTargetElement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<LensEnvContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<LensAppContext>,
    pub errors: Vec<LensErrorEntry>,
    pub network_tail: Vec<LensNetworkEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
}

/// A full Lens report (from the single-report read).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LensReport {
    pub id: String,
    pub status: String,
    pub created_at: String,
    pub submitted_at: Option<String>,
    pub metadata: Option<LensReportMetadata>,
}

/// Query options for `reports_path` / `list_reports`.
#[derive(Debug, Clone, Default)]
pub struct LensReportsQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub q: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
}

pub struct LensCloudClient {
    api_base_url: String,
    token: String,
    workspace_id: String,
    http: HttpRequestOptions,
    client: reqwest::Client,
}

impl LensCloudClient {
    pub fn new(opts: LensClientOpts) -> Self {
        Self {
            api_base_url: opts.api_base_url.strip_suffix('/').unwrap_or(&opts.api_base_url).to_string(),
            token: opts.token,
            workspace_id: opts.workspace_id,
            http: opts.http.unwrap_or_default(),
            client: reqwest::Client::new(),
        }
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    async fn request(&self, path: &str) -> anyhow::Result<Value> {
        let url = format!("{}{}", self.api_base_url, path);
        let req = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json");
        let res = fetch_with_retry(req, &self.http).await?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("Lens GET {path} -> {status}: {}", redact_upstream_body(&text, None));
        }
        Ok(res.json().await?)
    }

    fn base(&self) -> String {
        format!("/v1/workspaces/{}/lens", encode_uri_component(&self.workspace_id))
    }

    /// List the Lens sites the workspace owns. Transport/auth failures PROPAGATE so an
    /// outage reads as a gap, not as "no sites".
    pub async fn list_sites(&self) -> anyhow::Result<Vec<LensSite>> {
        let raw = self.request(&format!("{}/sites", self.base())).await?;
        // The route returns a BARE array (verified against production 2026-07-11); tolerate a
        // `{ sites: [...] }` wrapper too so a future envelope change degrades gracefully.
        let sites = match &raw {
            Value::Array(a) => Some(a),
            Value::Object(o) => o.get("sites").and_then(Value::as_array),
            _ => None,
        };
        let Some(sites) = sites else { return Ok(vec![]) };
        Ok(sites
            .iter()
            .filter_map(|s| {
                let id = s.get("id").and_then(Value::as_str).unwrap_or("");
                let name = match s.get("name").and_then(Value::as_str) {
                    Some(n) if !n.is_empty() => n,
                    _ => id,
                };
                (!id.is_empty()).then(|| LensSite { id: id.to_string(), name: name.to_string() })
            })
            .collect())
    }

    /// Build the site-reports query path with the incident-window + filter params.
    pub fn reports_path(&self, site_id: &str, opts: &LensReportsQuery) -> String {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(f) = &opts.from {
            params.push(("from", f.clone()));
        }
        if let Some(t) = &opts.to {
            params.push(("to", t.clone()));
        }
        if let Some(q) = opts.q.as_deref().filter(|q| !q.is_empty()) {
            params.push(("q", q.to_string()));
        }
        if let Some(s) = &opts.status {
            params.push(("status", s.clone()));
        }
        params.push(("limit", opts.limit.unwrap_or(25).clamp(1, 200).to_string()));
        let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        format!("{}/sites/{}/reports?{}", self.base(), encode_uri_component(site_id), form_encode(&pairs))
    }

    /// List reports for a site within an optional incident window. `from`/`to` are inclusive
    /// `createdAt` ISO-8601 bounds; `q` is a single case-insensitive substring over the
    /// comment + env URL. Returns the first page; transport/auth failures PROPAGATE.
    pub async fn list_reports(&self, site_id: &str, opts: &LensReportsQuery) -> anyhow::Result<Vec<LensReportSummary>> {
        let raw = self.request(&self.reports_path(site_id, opts)).await?;
        let Some(reports) = raw.get("reports").and_then(Value::as_array) else { return Ok(vec![]) };
        Ok(reports
            .iter()
            .filter_map(Value::as_object)
            .map(|r| parse_summary(r, site_id))
            .collect())
    }

    /// Fetch one full report (with metadata) by id, scoped to its site. Transport/auth
    /// failures PROPAGATE; the provider wraps each call so one bad report never aborts.
    pub async fn get_report(&self, site_id: &str, report_id: &str) -> anyhow::Result<LensReport> {
        let raw = self
            .request(&format!(
                "{}/sites/{}/reports/{}",
                self.base(),
                encode_uri_component(site_id),
                encode_uri_component(report_id)
            ))
            .await?;
        Ok(parse_report(&raw))
    }

    /// Cheap reachability probe: `list_sites` succeeds → ok. Never fails.
    pub async fn health(&self) -> HealthStatus {
        match self.list_sites().await {
            Ok(sites) => HealthStatus {
                ok: true,
                detail: format!("lens reachable (workspace {}, {} site(s))", self.workspace_id, sites.len()),
            },
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }
}

/// JS `Number(v)` coerced to a finite number, else 0.
fn to_number(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()).unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok().filter(|f| f.is_finite()).unwrap_or(0.0),
        _ => 0.0,
    }
}

fn str_field(o: &Map<String, Value>, key: &str) -> Option<String> {
    o.get(key).and_then(Value::as_str).map(str::to_string)
}

/// JS `String(raw.id ?? '')`.
fn id_string(o: &Map<String, Value>) -> String {
    match o.get("id") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Coerce a list-endpoint report row into a LensReportSummary.
pub fn parse_summary(raw: &Map<String, Value>, site_id: &str) -> LensReportSummary {
    LensReportSummary {
        id: id_string(raw),
        lens_site_id: str_field(raw, "lensSiteId").unwrap_or_else(|| site_id.to_string()),
        status: str_field(raw, "status").unwrap_or_default(),
        created_at: str_field(raw, "createdAt").unwrap_or_default(),
        submitted_at: str_field(raw, "submittedAt"),
        external_issue: raw.get("externalIssue").cloned().unwrap_or(Value::Null),
        lens_issue_id: str_field(raw, "lensIssueId"),
        issue_occurrence_count: raw.get("issueOccurrenceCount").and_then(Value::as_i64),
        comment: str_field(raw, "comment"),
        url: str_field(raw, "url"),
        error_count: to_number(raw.get("errorCount")),
        has_replay: raw.get("hasReplay") == Some(&Value::Bool(true)),
    }
}

/// Coerce the single-report JSON into a LensReport, tolerating a null/partial metadata.
pub fn parse_report(raw: &Value) -> LensReport {
    let empty = Map::new();
    let o = raw.as_object().unwrap_or(&empty);
    LensReport {
        id: id_string(o),
        status: str_field(o, "status").unwrap_or_default(),
        created_at: str_field(o, "createdAt").unwrap_or_default(),
        submitted_at: str_field(o, "submittedAt"),
        metadata: o.get("metadata").and_then(parse_metadata),
    }
}

fn parse_metadata(raw: &Value) -> Option<LensReportMetadata> {
    let m = raw.as_object()?;
    let mut meta = LensReportMetadata {
        errors: parse_errors(m.get("errors")),
        network_tail: parse_network_tail(m.get("networkTail")),
        comment: str_field(m, "comment"),
        trigger: str_field(m, "trigger"),
        ..Default::default()
    };

    if let Some(t) = m.get("target").and_then(Value::as_object) {
        meta.target = Some(LensTargetElement {
            dom_path: str_field(t, "domPath"),
            tag_name: str_field(t, "tagName"),
            text: str_field(t, "text"),
            react_components: t.get("reactComponents").and_then(Value::as_array).map(|a| {
                a.iter().filter_map(Value::as_str).map(str::to_string).collect()
            }),
        });
    }

    if let Some(e) = m.get("env").and_then(Value::as_object) {
        meta.env = Some(LensEnvContext {
            url: str_field(e, "url").unwrap_or_default(),
            route: str_field(e, "route"),
            user_agent: str_field(e, "userAgent"),
            browser: str_field(e, "browser"),
            os: str_field(e, "os"),
        });
    }

    if let Some(a) = m.get("app").and_then(Value::as_object) {
        meta.app = Some(LensAppContext {
            release: str_field(a, "release"),
            git_sha: str_field(a, "gitSha"),
            environment: str_field(a, "environment"),
            feature_flags: a.get("featureFlags").and_then(Value::as_object).cloned(),
        });
    }
    Some(meta)
}

fn parse_errors(raw: Option<&Value>) -> Vec<LensErrorEntry> {
    let Some(arr) = raw.and_then(Value::as_array) else { return vec![] };
    arr.iter()
        .filter_map(Value::as_object)
        .filter_map(|e| {
            let message = e.get("message")?.as_str()?.to_string();
            Some(LensErrorEntry {
                message,
                stack: str_field(e, "stack"),
                source: str_field(e, "source").unwrap_or_default(),
                timestamp: to_number(e.get("timestamp")),
            })
        })
        .collect()
}

fn parse_network_tail(raw: Option<&Value>) -> Vec<LensNetworkEntry> {
    let Some(arr) = raw.and_then(Value::as_array) else { return vec![] };
    arr.iter()
        .filter_map(Value::as_object)
        .map(|n| LensNetworkEntry {
            method: str_field(n, "method").unwrap_or_default(),
            url: str_field(n, "url").unwrap_or_default(),
            status: n.get("status").and_then(Value::as_i64),
            ok: n.get("ok").and_then(Value::as_bool),
            duration_ms: n.get("durationMs").and_then(Value::as_f64),
            request_type: str_field(n, "requestType").unwrap_or_default(),
            started_at: to_number(n.get("startedAt")),
            error: str_field(n, "error"),
        })
        .collect()
}
