//! Read-only Sentry REST client (HOR-CONNECTORS). Only GET endpoints; auth is
//! `Authorization: Bearer <token>`; transport via `fetch_with_retry`.

use anyhow::{anyhow, Result};
use horus_core::{redact_error_message, redact_upstream_body, HealthStatus};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::LazyLock;

use crate::http::{fetch_with_retry, HttpRequestOptions};
use crate::jsutil::{as_arr, as_str, encode_uri_component, js_number_from_str, js_number_string, js_string_or_empty, url_search_params};

#[derive(Debug, Clone, Default)]
pub struct SentryClientOpts {
    /// API auth token (sent as `Authorization: Bearer <auth_token>`).
    pub auth_token: String,
    /// Sentry org slug (`""` for discovery-only use).
    pub org: String,
    /// Sentry project slug (`""` for org/project discovery).
    pub project: String,
    /// Base URL (default https://sentry.io). Configurable for self-hosted.
    pub base_url: Option<String>,
    /// Transport overrides (timeout / retry) forwarded to fetch_with_retry.
    pub http: Option<HttpRequestOptions>,
}

/// An org or project the token can access — the fields the connect picker needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentryNamedResource {
    pub slug: String,
    pub name: String,
}

/// A grouped Sentry issue, trimmed to the fields Horus turns into evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentryIssue {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_status_change: Option<String>,
    /// Group title, e.g. "TypeError: Cannot read property 'x' of undefined".
    pub title: String,
    /// The function/transaction where the error surfaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub culprit: Option<String>,
    /// Issue level (error / warning / fatal / …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Total event count for the group (string in the API; coerced to number).
    pub count: f64,
    /// Distinct users affected.
    pub user_count: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permalink: Option<String>,
}

/// The top in-app stack frame of an issue's latest event — a direct code seed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SentryTopFrame {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// 1-based line number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineno: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IssuesQuery {
    pub query: Option<String>,
    pub stats_period: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub limit: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentryIssuePage {
    pub issues: Vec<SentryIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SentryClient {
    base_url: String,
    auth_token: String,
    org: String,
    project: String,
    http: HttpRequestOptions,
    client: reqwest::Client,
}

impl SentryClient {
    pub fn new(opts: SentryClientOpts) -> Self {
        Self {
            base_url: opts.base_url.as_deref().unwrap_or("https://sentry.io").trim_end_matches('/').to_string(),
            auth_token: opts.auth_token,
            org: opts.org,
            project: opts.project,
            http: opts.http.unwrap_or_default(),
            client: reqwest::Client::new(),
        }
    }

    async fn response(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let req = self.client.get(&url).header("Authorization", format!("Bearer {}", self.auth_token)).header("Content-Type", "application/json");
        let res = fetch_with_retry(req, &self.http).await.map_err(|e| anyhow!("{}", redact_error_message(&e)))?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("Sentry GET {path} -> {status}: {}", redact_upstream_body(&text, None)));
        }
        Ok(res)
    }

    async fn request(&self, path: &str) -> Result<Value> {
        Ok(self.response(path).await?.json().await?)
    }

    /// Build the project-issues query path. Explicit `start`/`end` win over `stats_period`.
    pub fn issues_path(&self, opts: &IssuesQuery) -> String {
        let limit = js_number_string(opts.limit.unwrap_or(25.0).min(100.0).max(1.0));
        let mut pairs: Vec<(&str, &str)> = vec![("query", opts.query.as_deref().unwrap_or("is:unresolved"))];
        if let (Some(start), Some(end)) = (&opts.start, &opts.end) {
            pairs.push(("start", start));
            pairs.push(("end", end));
        } else if let Some(sp) = &opts.stats_period {
            pairs.push(("statsPeriod", sp));
        }
        pairs.push(("limit", &limit));
        format!("/api/0/projects/{}/{}/issues/?{}", encode_uri_component(&self.org), encode_uri_component(&self.project), url_search_params(&pairs))
    }

    /// List recent issues. Transport/auth failures PROPAGATE so the engine can
    /// distinguish an outage from "no issues matched".
    pub async fn list_issues(&self, opts: &IssuesQuery) -> Result<Vec<SentryIssue>> {
        let raw = self.request(&self.issues_path(opts)).await?;
        Ok(raw.as_array().map(|a| a.iter().filter_map(Value::as_object).map(parse_issue).collect()).unwrap_or_default())
    }

    pub async fn issue(&self, issue_id: &str) -> Result<SentryIssue> {
        let raw = self.request(&format!("/api/0/issues/{}/", encode_uri_component(issue_id))).await?;
        raw.as_object().map(parse_issue).ok_or_else(|| anyhow!("Invalid Sentry issue response"))
    }

    /// Durable watcher page; cursor is opaque and cannot redirect authenticated requests.
    pub async fn watch_issues(&self, from: &str, to: &str, environment: &str, cursor: Option<&str>) -> Result<SentryIssuePage> {
        static CURSOR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"cursor="([^"]+)""#).unwrap());
        let path = self.issues_path(&IssuesQuery {
            start: Some(from.to_string()),
            end: Some(to.to_string()),
            limit: Some(100.0),
            query: Some(format!("lastSeen:>={from} lastSeen:<={to} environment:{}", serde_json::to_string(environment)?)),
            stats_period: None,
        });
        let full = match cursor {
            Some(c) => format!("{path}&cursor={}", encode_uri_component(c)),
            None => path,
        };
        let res = self.response(&full).await?;
        let link = res.headers().get("link").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let raw: Value = res.json().await?;
        let Some(items) = raw.as_array() else { return Err(anyhow!("Invalid Sentry issues response")) };
        let next = link.split(',').find(|v| v.contains("rel=\"next\"") && v.contains("results=\"true\""));
        let next_cursor = next.and_then(|n| CURSOR_RE.captures(n)).map(|c| c[1].to_string());
        Ok(SentryIssuePage { issues: items.iter().filter_map(Value::as_object).map(parse_issue).collect(), next_cursor })
    }

    /// Fetch an issue's latest event and extract the top in-app stack frame. None when
    /// the event/frame can't be resolved (never errors past here).
    pub async fn latest_event_top_frame(&self, issue_id: &str) -> Option<SentryTopFrame> {
        let raw = self.request(&format!("/api/0/issues/{}/events/latest/", encode_uri_component(issue_id))).await.ok()?;
        extract_top_in_app_frame(&raw)
    }

    /// Organizations this token can access (first page). Failures propagate.
    pub async fn list_organizations(&self) -> Result<Vec<SentryNamedResource>> {
        Ok(parse_named_resources(&self.request("/api/0/organizations/").await?))
    }

    /// Projects in the configured org. Requires a non-empty `org`.
    pub async fn list_projects(&self) -> Result<Vec<SentryNamedResource>> {
        Ok(parse_named_resources(&self.request(&format!("/api/0/organizations/{}/projects/", encode_uri_component(&self.org))).await?))
    }

    /// Cheap reachability probe: the project issues endpoint with limit=1. Never errors.
    pub async fn health(&self) -> HealthStatus {
        match self.request(&self.issues_path(&IssuesQuery { limit: Some(1.0), ..Default::default() })).await {
            Ok(_) => HealthStatus { ok: true, detail: format!("sentry reachable ({}/{})", self.org, self.project) },
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }
}

/// Coerce a Sentry org/project list response into `{slug, name}` rows, dropping
/// anything without a slug. `name` falls back to the slug when absent.
pub fn parse_named_resources(raw: &Value) -> Vec<SentryNamedResource> {
    as_arr(Some(raw))
        .iter()
        .filter_map(|o| {
            let slug = as_str(o.get("slug")).unwrap_or("").to_string();
            let name = as_str(o.get("name")).filter(|n| !n.is_empty()).map(str::to_string).unwrap_or_else(|| slug.clone());
            (!slug.is_empty()).then_some(SentryNamedResource { slug, name })
        })
        .collect()
}

/// Coerce Sentry's issue JSON (counts come back as strings) into a SentryIssue.
pub fn parse_issue(raw: &Map<String, Value>) -> SentryIssue {
    let s = |k: &str| as_str(raw.get(k)).map(str::to_string);
    SentryIssue {
        id: js_string_or_empty(raw.get("id")),
        status: s("status"),
        last_status_change: s("lastStatusChange"),
        title: s("title").unwrap_or_else(|| "(untitled)".into()),
        culprit: s("culprit"),
        level: s("level"),
        count: to_number(raw.get("count")),
        user_count: to_number(raw.get("userCount")),
        last_seen: s("lastSeen"),
        first_seen: s("firstSeen"),
        permalink: s("permalink"),
    }
}

fn to_number(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| f.is_finite()).unwrap_or(0.0),
        Some(Value::String(s)) => js_number_from_str(s).unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Walk a Sentry event payload and return the top in-app stack frame. Frames are
/// ordered oldest→newest (the crashing frame is LAST). Prefer the last `in_app` frame;
/// failing that, the last frame of the first trace; failing that, None.
pub fn extract_top_in_app_frame(event: &Value) -> Option<SentryTopFrame> {
    let ev = event.as_object()?;
    let frame_lists = collect_frame_lists(ev);
    for frames in &frame_lists {
        for f in frames.iter().rev() {
            if f.get("in_app") == Some(&Value::Bool(true)) {
                return Some(to_frame(f));
            }
        }
    }
    frame_lists.first().and_then(|first| first.last()).map(|last| to_frame(last))
}

/// Gather every `frames[]` array reachable from an event's entries / exception / stacktrace.
fn collect_frame_lists<'a>(ev: &'a Map<String, Value>) -> Vec<Vec<&'a Map<String, Value>>> {
    let mut out: Vec<Vec<&Map<String, Value>>> = Vec::new();
    let push_from_stacktrace = |node: Option<&'a Value>, out: &mut Vec<Vec<&'a Map<String, Value>>>| {
        if let Some(frames) = node.and_then(|st| st.get("frames")).and_then(Value::as_array) {
            out.push(frames.iter().filter_map(Value::as_object).collect());
        }
    };
    let push_from_exception_values = |node: Option<&'a Value>, out: &mut Vec<Vec<&'a Map<String, Value>>>| {
        for v in as_arr(node.and_then(|exc| exc.get("values"))) {
            push_from_stacktrace(v.get("stacktrace"), out);
        }
    };
    // 1. Top-level `entries: [{ type, data }]` (events/latest/ shape).
    for entry in as_arr(ev.get("entries")) {
        match as_str(entry.get("type")) {
            Some("exception") => push_from_exception_values(entry.get("data"), &mut out),
            Some("stacktrace") => push_from_stacktrace(entry.get("data"), &mut out),
            _ => {}
        }
    }
    // 2. Top-level `exception: { values }` and `stacktrace: { frames }` (SDK/store shape).
    push_from_exception_values(ev.get("exception"), &mut out);
    push_from_stacktrace(ev.get("stacktrace"), &mut out);
    out
}

fn to_frame(f: &Map<String, Value>) -> SentryTopFrame {
    SentryTopFrame {
        filename: as_str(f.get("filename")).or_else(|| as_str(f.get("absPath"))).or_else(|| as_str(f.get("abs_path"))).map(str::to_string),
        function: as_str(f.get("function")).map(str::to_string),
        lineno: f.get("lineNo").and_then(Value::as_f64).or_else(|| f.get("lineno").and_then(Value::as_f64)),
    }
}
