//! Pure Grafana dashboard panel extraction and classification (HOR-11 reframe). No I/O.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::LazyLock;

use crate::jsutil::{as_arr, js_string, js_string_or_empty};

use super::series::Labels;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetricKind {
    Latency,
    ErrorRate,
    Throughput,
    Queue,
    Saturation,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Panel {
    pub id: f64,
    pub title: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub unit: String,
    pub datasource_uid: String,
    pub exprs: Vec<String>,
    pub kind: MetricKind,
    /// Set by the provider after walking dashboards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard_uid: Option<String>,
}

/// Where a hint matched a panel / finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchSource {
    PanelTitle,
    QueryText,
    SeriesLabels,
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

static RE_QUEUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"queue|bullmq|backlog|depth|jobs").unwrap());
static RE_ERROR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"error|5xx|fail").unwrap());
static RE_LATENCY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"latency|duration|p9\d|histogram_quantile").unwrap());
static RE_THROUGHPUT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"rate\(|throughput|requests_total|operations_total|reqps").unwrap());
static RE_SATURATION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"cpu|memory|disk|saturation").unwrap());

/// Classify a panel into a MetricKind based on title, unit, and exprs. First match wins.
pub fn classify_panel(title: &str, unit: &str, exprs: &[String]) -> MetricKind {
    let lower_title = title.to_lowercase();
    let lower_exprs = exprs.iter().map(|e| e.to_lowercase()).collect::<Vec<_>>().join(" ");
    let combined = format!("{lower_title} {lower_exprs}");
    if RE_QUEUE.is_match(&combined) {
        return MetricKind::Queue;
    }
    if RE_ERROR.is_match(&combined) || lower_exprs.contains("status_code=~\"5") {
        return MetricKind::ErrorRate;
    }
    if unit == "s" || RE_LATENCY.is_match(&combined) {
        return MetricKind::Latency;
    }
    if unit == "reqps" || RE_THROUGHPUT.is_match(&combined) {
        return MetricKind::Throughput;
    }
    if unit == "percent" || RE_SATURATION.is_match(&combined) {
        return MetricKind::Saturation;
    }
    MetricKind::Other
}

// ---------------------------------------------------------------------------
// Panel extraction
// ---------------------------------------------------------------------------

/// Extract leaf panels from a raw Grafana dashboard object (recursing into rows).
pub fn extract_panels(dashboard: &Value) -> Vec<Panel> {
    let Some(panels) = dashboard.get("panels").and_then(Value::as_array) else { return vec![] };
    let mut result = Vec::new();
    walk_panels(panels, &mut result);
    result
}

fn walk_panels(panels: &[Value], result: &mut Vec<Panel>) {
    for p in panels {
        let type_ = js_string_or_empty(p.get("type"));
        if type_ == "row" {
            // Row panels may carry nested panels
            if let Some(nested) = p.get("panels").and_then(Value::as_array) {
                walk_panels(nested, result);
            }
            continue;
        }
        let id = match p.get("id") {
            Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
            Some(Value::Null) | None => 0.0,
            Some(v) => crate::jsutil::js_number_from_str(&js_string(v)).unwrap_or(f64::NAN),
        };
        let title = js_string_or_empty(p.get("title"));
        let unit = match p.get("fieldConfig").and_then(|f| f.get("defaults")).and_then(|d| d.get("unit")) {
            None | Some(Value::Null) => "none".to_string(),
            Some(v) => js_string(v),
        };
        let datasource_uid = match p.get("datasource") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Object(ds)) => js_string_or_empty(ds.get("uid")),
            _ => String::new(),
        };
        let exprs: Vec<String> = as_arr(p.get("targets"))
            .iter()
            .filter_map(|t| t.get("expr").and_then(Value::as_str))
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect();
        let kind = classify_panel(&title, &unit, &exprs);
        result.push(Panel { id, title, type_, unit, datasource_uid, exprs, kind, dashboard_uid: None });
    }
}

// ---------------------------------------------------------------------------
// Expression sanitization
// ---------------------------------------------------------------------------

/// Replace Grafana macro variables (`$__rate_interval`, `$__interval`) with "5m".
/// Returns None if a `$` remains (unresolvable template variable).
pub fn sanitize_expr(expr: &str) -> Option<String> {
    let replaced = expr.replace("$__rate_interval", "5m").replace("$__interval", "5m");
    if replaced.contains('$') {
        None
    } else {
        Some(replaced)
    }
}

// ---------------------------------------------------------------------------
// Hint matching
// ---------------------------------------------------------------------------

static RE_CAMEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-z])([A-Z])").unwrap());
static RE_ACRONYM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([A-Z]+)([A-Z][a-z])").unwrap());
static RE_NON_ALNUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9]+").unwrap());

/// Tokenize a hint string for panel matching: camelCase / acronym / snake_case splits,
/// lowercased, tokens shorter than 3 chars dropped.
pub fn extract_hint_tokens(hint: &str) -> Vec<String> {
    let camel_split = RE_CAMEL.replace_all(hint, "$1 $2");
    let acronym_split = RE_ACRONYM.replace_all(&camel_split, "$1 $2");
    RE_NON_ALNUM.split(&acronym_split.to_lowercase()).filter(|t| t.len() >= 3).map(str::to_string).collect()
}

/// True if the panel is relevant to the given hint (empty hint matches everything).
pub fn panel_matches_hint(p: &Panel, hint: &str) -> bool {
    if hint.is_empty() {
        return true;
    }
    let tokens = extract_hint_tokens(hint);
    if tokens.is_empty() {
        return true;
    }
    let haystack = format!("{} {}", p.title.to_lowercase(), p.exprs.iter().map(|e| e.to_lowercase()).collect::<Vec<_>>().join(" "));
    tokens.iter().any(|tok| haystack.contains(tok.as_str()))
}

/// Where in the panel the hint matched, or None when hint is empty / no match.
pub fn find_match_source(p: &Panel, hint: &str) -> Option<MatchSource> {
    if hint.is_empty() {
        return None;
    }
    let tokens = extract_hint_tokens(hint);
    if tokens.is_empty() {
        return None;
    }
    let title = p.title.to_lowercase();
    if tokens.iter().any(|tok| title.contains(tok.as_str())) {
        return Some(MatchSource::PanelTitle);
    }
    if tokens.iter().any(|tok| p.exprs.iter().any(|e| e.to_lowercase().contains(tok.as_str()))) {
        return Some(MatchSource::QueryText);
    }
    None
}

/// True if at least one label value matches a hint token (series-labels fallback pass).
pub fn finding_labels_match_hint(labels: &Labels, hint: &str) -> bool {
    let tokens = extract_hint_tokens(hint);
    if tokens.is_empty() {
        return true;
    }
    let haystack = labels.values().cloned().collect::<Vec<_>>().join(" ").to_lowercase();
    tokens.iter().any(|tok| haystack.contains(tok.as_str()))
}
