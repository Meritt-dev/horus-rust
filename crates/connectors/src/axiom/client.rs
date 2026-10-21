//! Read-only Axiom logs client (HOR-429). APL queries over a dataset; auth is
//! `Authorization: Bearer <token>`; transport via `fetch_with_retry`.

use anyhow::{anyhow, Result};
use horus_core::{redact_error_message, redact_upstream_body, HealthStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::http::{fetch_with_retry, HttpRequestOptions};
use crate::jsutil::{as_str, js_string_or_empty};

#[derive(Debug, Clone, Default)]
pub struct AxiomClientOpts {
    /// API token (sent as `Authorization: Bearer <token>`).
    pub token: String,
    /// Dataset to query (an Axiom dataset is the rough analogue of an ES index).
    pub dataset: String,
    /// Base URL. Defaults to the US region (https://api.axiom.co).
    pub base_url: Option<String>,
    /// Transport overrides (timeout / retry) forwarded to fetch_with_retry.
    pub http: Option<HttpRequestOptions>,
}

/// A dataset descriptor, trimmed to what Horus needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxiomDataset {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One log event row from an APL query — its fields plus a hoisted `_time`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AxiomLogRecord {
    /// ISO timestamp of the event (Axiom's `_time` field) when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// All row fields as a flat record (column name -> value).
    pub fields: Map<String, Value>,
}

const APL_PATH: &str = "/v1/datasets/_apl?format=tabular";

#[derive(Debug, Clone)]
pub struct AxiomClient {
    base_url: String,
    token: String,
    dataset: String,
    http: HttpRequestOptions,
    client: reqwest::Client,
}

impl AxiomClient {
    pub fn new(opts: AxiomClientOpts) -> Self {
        Self {
            base_url: opts.base_url.as_deref().unwrap_or("https://api.axiom.co").trim_end_matches('/').to_string(),
            token: opts.token,
            dataset: opts.dataset,
            http: opts.http.unwrap_or_default(),
            client: reqwest::Client::new(),
        }
    }

    async fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .client
            .request(reqwest::Method::from_bytes(method.as_bytes())?, &url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json");
        if let Some(b) = body {
            req = req.body(serde_json::to_string(b)?);
        }
        let res = fetch_with_retry(req, &self.http).await.map_err(|e| anyhow!("{}", redact_error_message(&e)))?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("Axiom {method} {path} -> {status}: {}", redact_upstream_body(&text, None)));
        }
        Ok(res.json().await?)
    }

    /// Datasets reachable with the configured token. [] on any error (never errors past here).
    pub async fn list_datasets(&self) -> Vec<AxiomDataset> {
        match self.request("GET", "/v1/datasets", None).await {
            Ok(raw) => raw.as_array().map(|a| a.iter().filter_map(Value::as_object).map(parse_dataset).collect()).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// Run an APL query over `[start_time, end_time]` (ISO). Transport/auth failures PROPAGATE.
    pub async fn query(&self, apl: &str, start_time: &str, end_time: &str) -> Result<Vec<AxiomLogRecord>> {
        let raw = self.request("POST", APL_PATH, Some(&json!({ "apl": apl, "startTime": start_time, "endTime": end_time }))).await?;
        Ok(parse_tabular(&raw))
    }

    /// Cheap reachability probe: list datasets. Never errors.
    pub async fn health(&self) -> HealthStatus {
        match self.request("GET", "/v1/datasets", None).await {
            Ok(_) => HealthStatus { ok: true, detail: format!("axiom reachable ({})", self.dataset) },
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }
}

/// Coerce a dataset JSON entry into an AxiomDataset.
pub fn parse_dataset(raw: &Map<String, Value>) -> AxiomDataset {
    AxiomDataset {
        name: js_string_or_empty(raw.get("name")),
        description: as_str(raw.get("description")).filter(|d| !d.is_empty()).map(str::to_string),
    }
}

/// Log levels that signal an active incident.
pub const AXIOM_ERROR_LEVELS: [&str; 3] = ["error", "warn", "fatal"];

/// APL-escaped dataset reference: `['name']`.
fn dataset_ref(dataset: &str) -> String {
    format!("['{}']", dataset.replace('\'', ""))
}

/// Domain-relevant hint tokens (length > 2) used in `search`/filter clauses.
fn search_terms(hint_terms: &[String]) -> Vec<String> {
    hint_terms.iter().map(|t| t.trim().to_string()).filter(|t| t.len() > 2).collect()
}

/// OR-joined full-text `search` clause for the supplied terms, or '' when none.
fn search_clause(hint_terms: &[String]) -> String {
    let terms = search_terms(hint_terms);
    if terms.is_empty() {
        return String::new();
    }
    format!(" | search {}", terms.iter().map(|t| format!("\"{}\"", t.replace('"', ""))).collect::<Vec<_>>().join(" or "))
}

/// `where` clause restricting to incident-level rows (case-insensitive on `level`).
fn error_level_clause() -> String {
    format!(" | where tolower(tostring(level)) in ({})", AXIOM_ERROR_LEVELS.iter().map(|l| format!("'{l}'")).collect::<Vec<_>>().join(", "))
}

fn clamp_limit(limit: f64) -> String {
    crate::jsutil::js_number_string(limit.min(1000.0).max(1.0))
}

/// Broad APL query over a dataset, newest-first, capped; hint terms bias via `search`.
pub fn build_apl(dataset: &str, hint_terms: &[String], limit: Option<f64>) -> String {
    format!("{}{} | sort by _time desc | limit {}", dataset_ref(dataset), search_clause(hint_terms), clamp_limit(limit.unwrap_or(100.0)))
}

/// Incident-aware query #1 — TOP ERROR SIGNATURES (`summarize count() + max(_time) by message, level`).
pub fn build_error_signature_apl(dataset: &str, hint_terms: &[String], top_n: Option<f64>) -> String {
    format!(
        "{}{}{} | summarize ['count'] = count(), ['_time'] = max(_time) by message, level | sort by ['count'] desc | limit {}",
        dataset_ref(dataset),
        error_level_clause(),
        search_clause(hint_terms),
        clamp_limit(top_n.unwrap_or(10.0))
    )
}

/// Incident-aware query #2 — a few RECENT RAW ERROR examples for grounding.
pub fn build_recent_errors_apl(dataset: &str, hint_terms: &[String], limit: Option<f64>) -> String {
    format!("{}{}{} | sort by _time desc | limit {}", dataset_ref(dataset), error_level_clause(), search_clause(hint_terms), clamp_limit(limit.unwrap_or(5.0)))
}

/// Parse Axiom's tabular APL response into flat log records. Supports both
/// column-oriented (`columns`) and row-oriented (`rows`) tables; `_time` → `timestamp`.
pub fn parse_tabular(raw: &Value) -> Vec<AxiomLogRecord> {
    let Some(tables) = raw.get("tables").and_then(Value::as_array) else { return vec![] };
    let mut records = Vec::new();
    for table in tables {
        let Some(fields) = table.get("fields").and_then(Value::as_array) else { continue };
        let names: Vec<String> = fields.iter().map(|f| js_string_or_empty(f.get("name"))).collect();
        if let Some(columns) = table.get("columns").and_then(Value::as_array) {
            // Column-oriented: columns[c][r] is the value of field c in row r.
            let row_count = columns.first().and_then(Value::as_array).map(Vec::len).unwrap_or(0);
            for r in 0..row_count {
                let mut row = Map::new();
                for (c, name) in names.iter().enumerate() {
                    if let Some(col) = columns.get(c).and_then(Value::as_array) {
                        row.insert(name.clone(), col.get(r).cloned().unwrap_or(Value::Null));
                    }
                }
                records.push(to_record(row));
            }
        } else if let Some(rows) = table.get("rows").and_then(Value::as_array) {
            // Row-oriented: rows[r][c] is the value of field c in row r.
            for row_vals in rows {
                let Some(vals) = row_vals.as_array() else { continue };
                let mut row = Map::new();
                for (c, name) in names.iter().enumerate() {
                    row.insert(name.clone(), vals.get(c).cloned().unwrap_or(Value::Null));
                }
                records.push(to_record(row));
            }
        }
    }
    records
}

fn to_record(fields: Map<String, Value>) -> AxiomLogRecord {
    let timestamp = as_str(fields.get("_time")).map(str::to_string);
    AxiomLogRecord { timestamp, fields }
}
