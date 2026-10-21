//! Minimal Elasticsearch HTTP client (HOR-10). Transport goes through the shared
//! `fetch_with_retry` helper (per-request timeout + bounded retry on 429/5xx/network
//! errors).

use anyhow::{anyhow, Result};
use base64::Engine;
use horus_core::{redact_error_message, redact_upstream_body, HealthStatus};
use serde_json::Value;

use crate::http::{fetch_with_retry, HttpRequestOptions};
use crate::jsutil::{as_arr, js_string_or_empty};

#[derive(Debug, Clone, Default)]
pub struct ElasticsearchClientOpts {
    pub base_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Transport overrides (timeout / retry) forwarded to fetch_with_retry.
    pub http: Option<HttpRequestOptions>,
}

#[derive(Debug, Clone)]
pub struct ElasticsearchClient {
    base_url: String,
    auth_header: Option<String>,
    http: HttpRequestOptions,
    client: reqwest::Client,
}

/// `Basic <base64(user:pass)>` when both are present.
pub(crate) fn basic_auth_header(username: Option<&str>, password: Option<&str>) -> Option<String> {
    match (username, password) {
        (Some(u), Some(p)) => Some(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")))),
        _ => None,
    }
}

impl ElasticsearchClient {
    pub fn new(opts: ElasticsearchClientOpts) -> Self {
        Self {
            base_url: opts.base_url.trim_end_matches('/').to_string(),
            auth_header: basic_auth_header(opts.username.as_deref(), opts.password.as_deref()),
            http: opts.http.unwrap_or_default(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .client
            .request(reqwest::Method::from_bytes(method.as_bytes())?, &url)
            .header("Content-Type", "application/json");
        if let Some(auth) = &self.auth_header {
            req = req.header("Authorization", auth);
        }
        if let Some(b) = body {
            req = req.body(serde_json::to_string(b)?);
        }
        let res = fetch_with_retry(req, &self.http).await.map_err(|e| anyhow!("{}", redact_error_message(&e)))?;
        if !res.status().is_success() {
            // Redact + cap the upstream body — security-plugin 401/403 bodies can echo request context.
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("Elasticsearch {method} {path} -> {status}: {}", redact_upstream_body(&text, None)));
        }
        let result: Value = res.json().await?;
        // HTTP 200 may contain partial hits/counts. Never let a watcher acknowledge that window.
        let failed = result.get("_shards").and_then(|s| s.get("failed")).and_then(Value::as_f64).unwrap_or(0.0);
        if result.get("timed_out") == Some(&Value::Bool(true)) || result.get("terminated_early") == Some(&Value::Bool(true)) || failed > 0.0 {
            return Err(anyhow!("Elasticsearch returned incomplete results (timeout, early termination, or failed shards); retry the query"));
        }
        Ok(result)
    }

    pub async fn search(&self, index: &str, body: &Value) -> Result<Value> {
        self.request("POST", &format!("/{index}/_search"), Some(body)).await
    }

    pub async fn field_caps(&self, index: &str, fields: &[String]) -> Result<Value> {
        let encoded = fields.iter().map(|f| crate::jsutil::encode_uri_component(f)).collect::<Vec<_>>().join(",");
        // allow_no_indices + ignore_unavailable: return empty response instead of 404
        // when the index pattern matches nothing — lets validate_mapping_against_caps
        // produce the actionable "no indices" diagnostic rather than erroring.
        self.request("GET", &format!("/{index}/_field_caps?fields={encoded}&allow_no_indices=true&ignore_unavailable=true"), None).await
    }

    pub async fn count(&self, index: &str, body: &Value) -> Result<f64> {
        let res = self.request("POST", &format!("/{index}/_count"), Some(body)).await?;
        Ok(res.get("count").and_then(Value::as_f64).unwrap_or(0.0))
    }

    pub async fn health(&self) -> HealthStatus {
        match self.request("GET", "/_cluster/health", None).await {
            Ok(res) => HealthStatus { ok: true, detail: res.get("status").and_then(Value::as_str).unwrap_or("ok").to_string() },
            // fetch errors can embed the full URL (incl. userinfo) — redact.
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }

    /// Discover available index names: data streams, then aliases, then raw concrete
    /// indices (only when neither of the former yielded anything). System entries
    /// (starting with '.') are filtered. Returns [] on any error.
    pub async fn list_indices(&self) -> Vec<String> {
        let mut results: Vec<String> = Vec::new();
        let add = |name: String, results: &mut Vec<String>| {
            if !name.is_empty() && !name.starts_with('.') && !results.contains(&name) {
                results.push(name);
            }
        };
        // 1. Data streams
        if let Ok(ds) = self.request("GET", "/_data_stream", None).await {
            for s in as_arr(ds.get("data_streams")) {
                add(js_string_or_empty(s.get("name")), &mut results);
            }
        }
        // 2. Aliases
        if let Ok(aliases) = self.request("GET", "/_cat/aliases?format=json&h=alias&s=alias", None).await {
            for a in as_arr(Some(&aliases)) {
                add(js_string_or_empty(a.get("alias")), &mut results);
            }
        }
        // 3. Raw indices (only when neither data streams nor aliases were found)
        if results.is_empty() {
            if let Ok(idx) = self.request("GET", "/_cat/indices?format=json&h=index&s=index&expand_wildcards=open", None).await {
                for r in as_arr(Some(&idx)) {
                    add(js_string_or_empty(r.get("index")), &mut results);
                }
            }
        }
        results.sort();
        results
    }
}
