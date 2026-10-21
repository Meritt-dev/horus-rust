//! Grafana HTTP API client (HOR-11 reframe). All Prometheus queries are routed through
//! the Grafana datasource proxy — no direct Prometheus access required.

use anyhow::{anyhow, Result};
use horus_core::{redact_error_message, redact_secrets, redact_upstream_body, HealthStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::elasticsearch::client::basic_auth_header;
use crate::http::{fetch_with_retry, HttpRequestOptions};
use crate::jsutil::{encode_uri_component, js_number_string, js_string, js_string_or_empty, url_search_params};

#[derive(Debug, Clone, Default)]
pub struct GrafanaClientOpts {
    pub base_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Transport overrides (timeout / retry) forwarded to fetch_with_retry.
    pub http: Option<HttpRequestOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardRef {
    pub uid: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_title: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GrafanaClient {
    base_url: String,
    auth_header: Option<String>,
    http: HttpRequestOptions,
    client: reqwest::Client,
}

impl GrafanaClient {
    pub fn new(opts: GrafanaClientOpts) -> Self {
        Self {
            base_url: opts.base_url.trim_end_matches('/').to_string(),
            auth_header: basic_auth_header(opts.username.as_deref(), opts.password.as_deref()),
            http: opts.http.unwrap_or_default(),
            client: reqwest::Client::new(),
        }
    }

    /// `get_json` minus the decode: the raw body bytes (status-checked the same way).
    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let mut req = self.client.get(url);
        if let Some(auth) = &self.auth_header {
            req = req.header("Authorization", auth);
        }
        let res = fetch_with_retry(req, &self.http).await.map_err(|e| anyhow!("{}", redact_error_message(&e)))?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("{}", redact_secrets(&format!("Grafana GET {url} -> {status}: {}", redact_upstream_body(&text, None)))));
        }
        Ok(res.bytes().await.map_err(|_| anyhow!("Grafana GET {url}: response is not valid JSON"))?.to_vec())
    }

    async fn get_json(&self, url: &str) -> Result<Value> {
        let mut req = self.client.get(url);
        if let Some(auth) = &self.auth_header {
            req = req.header("Authorization", auth);
        }
        let res = fetch_with_retry(req, &self.http).await.map_err(|e| anyhow!("{}", redact_error_message(&e)))?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            // Redact the WHOLE message: the full request URL may carry userinfo.
            return Err(anyhow!("{}", redact_secrets(&format!("Grafana GET {url} -> {status}: {}", redact_upstream_body(&text, None)))));
        }
        res.json::<Value>().await.map_err(|_| anyhow!("Grafana GET {url}: response is not valid JSON"))
    }

    /// GET /api/health — ok:true on 200.
    pub async fn health(&self) -> HealthStatus {
        match self.get_json(&format!("{}/api/health", self.base_url)).await {
            Ok(_) => HealthStatus { ok: true, detail: "grafana ok".into() },
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }

    /// GET /api/search?type=dash-db[&query=<q>]
    pub async fn search_dashboards(&self, query: Option<&str>) -> Result<Vec<DashboardRef>> {
        let mut pairs = vec![("type", "dash-db")];
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            pairs.push(("query", q));
        }
        let url = format!("{}/api/search?{}", self.base_url, url_search_params(&pairs));
        let raw = self.get_json(&url).await?;
        let Some(items) = raw.as_array() else { return Ok(vec![]) };
        Ok(items
            .iter()
            .map(|it| DashboardRef {
                uid: js_string_or_empty(it.get("uid")),
                title: js_string_or_empty(it.get("title")),
                folder_title: it.get("folderTitle").map(js_string),
            })
            .collect())
    }

    /// GET /api/dashboards/uid/<uid> — returns the `.dashboard` object (Null when absent).
    pub async fn get_dashboard(&self, uid: &str) -> Result<Value> {
        let url = format!("{}/api/dashboards/uid/{}", self.base_url, encode_uri_component(uid));
        let raw = self.get_json(&url).await?;
        Ok(raw.get("dashboard").cloned().unwrap_or(Value::Null))
    }

    fn check_status(raw: Value) -> Result<Value> {
        if raw.get("status").and_then(Value::as_str) == Some("error") {
            let err_msg = raw.get("error").and_then(Value::as_str).unwrap_or("unknown error");
            // Upstream-controlled string — redact before it rides on an error.
            return Err(anyhow!("Prometheus datasource error: {}", redact_secrets(err_msg)));
        }
        Ok(raw)
    }

    /// GET /api/datasources/proxy/uid/<dsUid>/api/v1/query_range — raw Prometheus response.
    pub async fn datasource_range(&self, ds_uid: &str, expr: &str, start_secs: f64, end_secs: f64, step_secs: f64) -> Result<Value> {
        let qs = url_search_params(&[
            ("query", expr),
            ("start", &js_number_string(start_secs)),
            ("end", &js_number_string(end_secs)),
            ("step", &js_number_string(step_secs)),
        ]);
        let url = format!("{}/api/datasources/proxy/uid/{}/api/v1/query_range?{qs}", self.base_url, encode_uri_component(ds_uid));
        Self::check_status(self.get_json(&url).await?)
    }

    /// `datasource_range` decoded straight into series (typed, streaming — see
    /// [`crate::grafana::series::parse_range_bytes`]). Same errors and result as
    /// `parse_range(&datasource_range(..)?)`.
    pub async fn datasource_range_series(
        &self,
        ds_uid: &str,
        expr: &str,
        start_secs: f64,
        end_secs: f64,
        step_secs: f64,
    ) -> Result<Vec<crate::grafana::series::MetricSeries>> {
        let qs = url_search_params(&[
            ("query", expr),
            ("start", &js_number_string(start_secs)),
            ("end", &js_number_string(end_secs)),
            ("step", &js_number_string(step_secs)),
        ]);
        let url = format!("{}/api/datasources/proxy/uid/{}/api/v1/query_range?{qs}", self.base_url, encode_uri_component(ds_uid));
        let body = self.get_bytes(&url).await?;
        match crate::grafana::series::parse_range_bytes(&body) {
            Some((status, error, series)) => {
                if status.as_ref().and_then(Value::as_str) == Some("error") {
                    let err_msg = error.as_ref().and_then(Value::as_str).unwrap_or("unknown error");
                    return Err(anyhow!("Prometheus datasource error: {}", redact_secrets(err_msg)));
                }
                Ok(series)
            }
            None => {
                let raw: Value =
                    serde_json::from_slice(&body).map_err(|_| anyhow!("Grafana GET {url}: response is not valid JSON"))?;
                Ok(crate::grafana::series::parse_range(&Self::check_status(raw)?))
            }
        }
    }

    /// GET /api/datasources/proxy/uid/<dsUid>/api/v1/query — raw Prometheus instant response.
    pub async fn datasource_instant(&self, ds_uid: &str, expr: &str, time_secs: Option<f64>) -> Result<Value> {
        let mut pairs = vec![("query", expr.to_string())];
        if let Some(t) = time_secs {
            pairs.push(("time", js_number_string(t)));
        }
        let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let url = format!("{}/api/datasources/proxy/uid/{}/api/v1/query?{}", self.base_url, encode_uri_component(ds_uid), url_search_params(&borrowed));
        Self::check_status(self.get_json(&url).await?)
    }
}
