//! Pure normalization helpers for Elasticsearch log documents (HOR-10, HOR-47).
//! No I/O.

use horus_core::{redact_secrets, Evidence, EvidenceKind, EvidenceLinks, LevelFormat, Provenance, ProviderKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::jsutil::{as_arr, as_str, js_number_from_str, js_string_or_empty, js_value, slice_chars};

// ---------------------------------------------------------------------------
// Level utilities
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

/// `LEVEL_VALUE` in TS key order.
pub const LEVEL_VALUE: [(LogLevel, f64); 6] = [
    (LogLevel::Trace, 10.0),
    (LogLevel::Debug, 20.0),
    (LogLevel::Info, 30.0),
    (LogLevel::Warn, 40.0),
    (LogLevel::Error, 50.0),
    (LogLevel::Fatal, 60.0),
];

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Fatal => "fatal",
        }
    }
    /// Exact (already-lowercased) label lookup, like `LEVEL_VALUE[s]`.
    pub fn from_label(s: &str) -> Option<LogLevel> {
        LEVEL_VALUE.iter().find(|(l, _)| l.as_str() == s).map(|(l, _)| *l)
    }
}

/// Map a pino numeric level to the nearest floor bucket.
pub fn value_to_level(n: f64) -> LogLevel {
    if n >= 60.0 {
        LogLevel::Fatal
    } else if n >= 50.0 {
        LogLevel::Error
    } else if n >= 40.0 {
        LogLevel::Warn
    } else if n >= 30.0 {
        LogLevel::Info
    } else if n >= 20.0 {
        LogLevel::Debug
    } else {
        LogLevel::Trace
    }
}

pub fn level_to_value(l: LogLevel) -> f64 {
    LEVEL_VALUE.iter().find(|(x, _)| *x == l).map(|(_, v)| *v).unwrap_or(30.0)
}

// ---------------------------------------------------------------------------
// Field mapping (HOR-47)
// ---------------------------------------------------------------------------

/// Maps abstract log concepts to actual Elasticsearch field names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElasticsearchFieldMapping {
    /// ISO timestamp field used for range filtering and sorting. Meritt: 'time'. ECS: '@timestamp'.
    pub timestamp_field: String,
    /// Severity / log-level field. Meritt: 'level' (numeric long). ECS: 'log.level' (string keyword).
    pub level_field: String,
    /// Whether level_field stores Pino numeric values or string labels.
    pub level_format: LevelFormat,
    /// Service/application name field. Meritt: 'service_name'. ECS: 'service.name'.
    pub service_field: String,
    /// Whether service_field has a .keyword sub-field for exact term matching.
    pub service_keyword: bool,
    /// Primary message field.
    pub message_field: String,
    /// Fallback message field when message_field is absent (e.g. Pino 'msg').
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_fallback_field: Option<String>,
    /// Top-level trace/correlation ID field. Meritt: 'trace_id'. ECS: 'trace.id'.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id_field: Option<String>,
    /// Top-level request ID field, if distinct from trace_id_field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id_field: Option<String>,
    /// Structured event/error code field used for signature aggregations.
    pub event_code_field: String,
    /// Whether event_code_field has a .keyword sub-field for terms aggregations.
    pub event_code_keyword: bool,
    /// Fields holding the specific failure text behind a generic message template (dotted
    /// paths, e.g. `context.error_message`). Checked before the built-in detail discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detail_fields: Vec<String>,
}

/// Default mapping for the Meritt shared logger (pino-based).
pub static MERITT_FIELD_MAPPING: LazyLock<ElasticsearchFieldMapping> = LazyLock::new(|| ElasticsearchFieldMapping {
    timestamp_field: "time".into(),
    level_field: "level".into(),
    level_format: LevelFormat::Numeric,
    service_field: "service_name".into(),
    service_keyword: true,
    message_field: "message".into(),
    message_fallback_field: Some("msg".into()),
    trace_id_field: Some("trace_id".into()),
    request_id_field: None,
    event_code_field: "event_code".into(),
    event_code_keyword: true,
    detail_fields: vec![],
});

/// Mapping for ECS (Elastic Common Schema) deployments.
pub static ECS_FIELD_MAPPING: LazyLock<ElasticsearchFieldMapping> = LazyLock::new(|| ElasticsearchFieldMapping {
    timestamp_field: "@timestamp".into(),
    level_field: "log.level".into(),
    level_format: LevelFormat::String,
    // ECS service.name is already keyword-typed — no .keyword sub-field needed.
    service_field: "service.name".into(),
    service_keyword: false,
    message_field: "message".into(),
    message_fallback_field: None,
    trace_id_field: Some("trace.id".into()),
    request_id_field: Some("http.request.id".into()),
    // ECS event.code is already keyword-typed — no .keyword sub-field needed.
    event_code_field: "event.code".into(),
    event_code_keyword: false,
    detail_fields: vec![],
});

/// Validate a field mapping and return an actionable error for invalid config.
/// Call this once at provider construction time.
pub fn validate_field_mapping(m: &ElasticsearchFieldMapping) -> anyhow::Result<()> {
    if m.timestamp_field.is_empty() {
        anyhow::bail!("[Horus/Elasticsearch] timestampField must be non-empty. Common values: 'time' (Meritt), '@timestamp' (ECS).");
    }
    if m.level_field.is_empty() {
        anyhow::bail!("[Horus/Elasticsearch] levelField must be non-empty. Common values: 'level' (Meritt numeric), 'log.level' (ECS string).");
    }
    if m.service_field.is_empty() {
        anyhow::bail!("[Horus/Elasticsearch] serviceField must be non-empty. Common values: 'service_name' (Meritt), 'service.name' (ECS).");
    }
    if m.message_field.is_empty() {
        anyhow::bail!("[Horus/Elasticsearch] messageField must be non-empty.");
    }
    if m.event_code_field.is_empty() {
        anyhow::bail!("[Horus/Elasticsearch] eventCodeField must be non-empty.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogRecord {
    /// Native Elasticsearch document identity, separate from user-authored _source fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    pub timestamp: String,
    pub level: LogLevel,
    pub level_value: f64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Structured context object attached to the log (Meritt `context.*`) (HOR-215).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
    /// Free-form `detail` field — where some loggers bury the real error (HOR-216).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub index: String,
    pub raw: Map<String, Value>,
}

/// A structured field-equality filter, e.g. `context.brand_id = 42` (HOR-344).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhereClause {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Structured field-equality filters (HOR-344), AND-combined.
    #[serde(rename = "where", skip_serializing_if = "Option::is_none")]
    pub where_: Option<Vec<WhereClause>>,
    /// When true, `text` is matched across the message, `detail`, and `context.*` (HOR-216).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broad_text: Option<bool>,
    /// Scope an aggregation to a single error signature (event_code) (HOR-215).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBucket {
    pub key: String,
    pub count: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorDelta {
    pub key: String,
    pub baseline: f64,
    pub current: f64,
    pub delta: f64,
    pub ratio: f64,
}

// ---------------------------------------------------------------------------
// Internal helpers (exported so analyze.rs can reuse them)
// ---------------------------------------------------------------------------

/// Read a (possibly dotted) field path from an Elasticsearch _source object.
/// Handles flattened keys, nested ECS objects and pre-flattened ECS.
pub fn get_field<'a>(src: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    crate::duration::read_path(src, path)
}

/// Return the term-query field name for service filtering.
pub fn service_term_field(m: &ElasticsearchFieldMapping) -> String {
    if m.service_keyword {
        format!("{}.keyword", m.service_field)
    } else {
        m.service_field.clone()
    }
}

/// Return the terms-aggregation field name for event/error code.
pub fn signature_term_field(m: &ElasticsearchFieldMapping) -> String {
    if m.event_code_keyword {
        format!("{}.keyword", m.event_code_field)
    } else {
        m.event_code_field.clone()
    }
}

/// Build a level filter clause for an ES bool query.
pub fn build_level_filter(m: &ElasticsearchFieldMapping, min_level: LogLevel) -> Value {
    if m.level_format == LevelFormat::Numeric {
        return json!({ "range": { &m.level_field: { "gte": level_to_value(min_level) as i64 } } });
    }
    let min_value = level_to_value(min_level);
    let string_levels: Vec<&str> = LEVEL_VALUE.iter().filter(|(_, v)| *v >= min_value).map(|(l, _)| l.as_str()).collect();
    json!({ "terms": { &m.level_field: string_levels } })
}

/// Build AND-combined term filters for structured `--where field=value` clauses (HOR-344).
pub fn build_where_filters(where_: Option<&[WhereClause]>) -> Vec<Value> {
    where_
        .unwrap_or(&[])
        .iter()
        .map(|w| {
            json!({
                "bool": {
                    "should": [
                        { "term": { &w.field: &w.value } },
                        { "term": { format!("{}.keyword", w.field): &w.value } },
                    ],
                    "minimum_should_match": 1,
                }
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Query builders
// ---------------------------------------------------------------------------

/// Build the `must` clause for a text query (HOR-216 broad match when `broad_text`).
pub fn build_text_must(q: &LogQuery, mapping: &ElasticsearchFieldMapping) -> Vec<Value> {
    let Some(text) = &q.text else { return vec![json!({ "match_all": {} })] };
    if q.broad_text == Some(true) {
        let mut fields = vec![mapping.message_field.clone(), mapping.event_code_field.clone()];
        if let Some(fb) = &mapping.message_fallback_field {
            fields.push(fb.clone());
        }
        fields.push("detail".into());
        fields.push("context.*".into());
        return vec![json!({ "multi_match": { "query": text, "fields": fields, "type": "phrase", "lenient": true } })];
    }
    vec![json!({ "match": { &mapping.message_field: text } })]
}

fn range_filter(q: &LogQuery, mapping: &ElasticsearchFieldMapping) -> Option<Value> {
    if q.from.is_none() && q.to.is_none() {
        return None;
    }
    let mut range = Map::new();
    if let Some(from) = &q.from {
        range.insert("gte".into(), json!(from));
    }
    if let Some(to) = &q.to {
        range.insert("lte".into(), json!(to));
    }
    Some(json!({ "range": { &mapping.timestamp_field: range } }))
}

pub fn build_search_body(q: &LogQuery, mapping: &ElasticsearchFieldMapping) -> Value {
    let mut filters: Vec<Value> = Vec::new();
    if let Some(level) = q.level {
        filters.push(build_level_filter(mapping, level));
    }
    if let Some(r) = range_filter(q, mapping) {
        filters.push(r);
    }
    if let Some(service) = &q.service {
        filters.push(json!({ "term": { service_term_field(mapping): service } }));
    }
    filters.extend(build_where_filters(q.where_.as_deref()));
    let must = build_text_must(q, mapping);
    json!({
        "query": { "bool": { "filter": filters, "must": must } },
        "sort": [{ &mapping.timestamp_field: { "order": "desc" } }],
        "size": q.limit.unwrap_or(50),
    })
}

pub fn build_error_agg_body(q: &LogQuery, field: &str, mapping: &ElasticsearchFieldMapping) -> Value {
    let mut filters: Vec<Value> = Vec::new();
    // Force level >= error unless q.level is set higher.
    let min_level = match q.level {
        Some(l) if level_to_value(l) > 50.0 => l,
        _ => LogLevel::Error,
    };
    filters.push(build_level_filter(mapping, min_level));
    if let Some(r) = range_filter(q, mapping) {
        filters.push(r);
    }
    if let Some(service) = &q.service {
        filters.push(json!({ "term": { service_term_field(mapping): service } }));
    }
    if let Some(code) = &q.event_code {
        filters.push(json!({ "term": { signature_term_field(mapping): code } }));
    }
    filters.extend(build_where_filters(q.where_.as_deref()));
    // Use the mapping's keyword-aware term field when the field matches the
    // configured eventCodeField; otherwise fall back to appending .keyword.
    let agg_field = if field == mapping.event_code_field { signature_term_field(mapping) } else { format!("{field}.keyword") };
    json!({
        "size": 0,
        "query": { "bool": { "filter": filters, "must": build_text_must(q, mapping) } },
        "aggs": { "by_key": { "terms": { "field": agg_field, "size": 20 } } },
    })
}

// ---------------------------------------------------------------------------
// Hit normalization
// ---------------------------------------------------------------------------

fn resolve_level_from_source(src: &Map<String, Value>, m: &ElasticsearchFieldMapping) -> (f64, LogLevel) {
    let raw = get_field(src, &m.level_field);
    if m.level_format == LevelFormat::Numeric {
        if let Some(n) = raw.and_then(Value::as_f64) {
            return (n, value_to_level(n));
        }
        if let Some(s) = raw.and_then(Value::as_str) {
            if let Some(n) = js_number_from_str(s) {
                return (n, value_to_level(n));
            }
            let lower = s.to_lowercase();
            if let Some(l) = LogLevel::from_label(&lower) {
                return (level_to_value(l), l);
            }
        }
    } else if let Some(s) = raw.and_then(Value::as_str) {
        let lower = s.to_lowercase();
        if let Some(l) = LogLevel::from_label(&lower) {
            return (level_to_value(l), l);
        }
    }
    // Graceful fallbacks for Meritt shape when a non-standard mapping is in use
    if let Some(lv) = src.get("level").and_then(Value::as_f64) {
        return (lv, value_to_level(lv));
    }
    if let Some(ll) = src.get("log_level").and_then(Value::as_str) {
        let lower = ll.to_lowercase();
        if let Some(l) = LogLevel::from_label(&lower) {
            return (level_to_value(l), l);
        }
    }
    (30.0, LogLevel::Info)
}

/// Parse a JSON object out of a string, else None.
fn parse_json_object(s: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(s) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

pub fn normalize_hit(hit: &Value, mapping: &ElasticsearchFieldMapping) -> LogRecord {
    static EMPTY: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);
    let h = hit.as_object().unwrap_or(&EMPTY);
    let src = h.get("_source").and_then(Value::as_object).unwrap_or(&EMPTY);
    let s = |v: Option<&Value>| as_str(v).map(str::to_string);

    // Timestamp: use configured field, fall back to common alternatives.
    let timestamp = s(get_field(src, &mapping.timestamp_field))
        .or_else(|| s(src.get("@timestamp")))
        .or_else(|| s(src.get("time")))
        .unwrap_or_default();

    let (level_value, level) = resolve_level_from_source(src, mapping);

    // Message: use configured field, then fallback, then 'msg'.
    let message = s(get_field(src, &mapping.message_field))
        .or_else(|| mapping.message_fallback_field.as_ref().and_then(|f| s(get_field(src, f))))
        .or_else(|| s(src.get("msg")))
        .unwrap_or_default();

    let service = s(get_field(src, &mapping.service_field));
    let component = s(src.get("component")).or_else(|| s(src.get("log_logger")));
    let event_code = s(get_field(src, &mapping.event_code_field)).or_else(|| s(src.get("code")));

    // Trace ID: configured field, then a serialised context blob (legacy Meritt pattern).
    let mut trace_id = mapping.trace_id_field.as_ref().and_then(|f| s(get_field(src, f)));
    if trace_id.is_none() {
        if let Some(ctx) = src.get("context").and_then(Value::as_str) {
            if let Some(parsed) = parse_json_object(ctx) {
                let tid = match parsed.get("traceId") {
                    Some(Value::Null) | None => parsed.get("trace_id"),
                    other => other,
                };
                trace_id = s(tid);
            }
        }
    }

    let request_id = mapping.request_id_field.as_ref().and_then(|f| s(get_field(src, f)));
    let host = s(src.get("hostname")).or_else(|| s(src.get("host_name")));

    // Structured context: an object directly, or a JSON string the logger serialised (HOR-215).
    let context = match src.get("context") {
        Some(Value::Object(m)) => Some(m.clone()),
        Some(Value::String(st)) => parse_json_object(st),
        _ => None,
    };

    // `detail`: where some loggers bury the real error (e.g. AxiosError / ENOTFOUND).
    let detail = match get_field(src, "detail") {
        Some(Value::String(d)) => Some(d.clone()),
        Some(v @ (Value::Object(_) | Value::Array(_))) => serde_json::to_string(v).ok(),
        _ => None,
    };

    let index = s(h.get("_index")).unwrap_or_default();

    LogRecord {
        document_id: s(h.get("_id")),
        timestamp,
        level,
        level_value,
        message,
        service,
        component,
        event_code,
        trace_id,
        request_id,
        host,
        context,
        detail,
        index,
        raw: src.clone(),
    }
}

// ---------------------------------------------------------------------------
// Raw context display (HOR-215)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextField {
    pub key: String,
    pub value: String,
}

/// Stringify a scalar context value for display; objects/arrays compacted.
fn display_value(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(_) | Value::Bool(_) => Some(crate::jsutil::js_string(v)),
        _ => serde_json::to_string(v).ok(),
    }
}

/// Flatten a record's structured fields (eventCode + context.* + detail) into an
/// ordered, displayable key/value list for `horus logs --raw` (HOR-215).
pub fn extract_context_fields(record: &LogRecord, limit: Option<usize>) -> Vec<ContextField> {
    let limit = limit.unwrap_or(16);
    let mut out: Vec<ContextField> = Vec::new();
    let push = |key: &str, raw: &Value, out: &mut Vec<ContextField>| {
        if out.len() >= limit || out.iter().any(|f| f.key == key) {
            return;
        }
        let Some(value) = display_value(raw) else { return };
        if value.trim().is_empty() {
            return;
        }
        out.push(ContextField { key: key.to_string(), value });
    };
    if let Some(code) = &record.event_code {
        push("code", &Value::String(code.clone()), &mut out);
    }
    if let Some(ctx) = &record.context {
        for (k, v) in ctx {
            // traceId/requestId already shown via their own columns when present.
            if k == "traceId" || k == "trace_id" {
                continue;
            }
            push(k, v, &mut out);
        }
    }
    if let Some(detail) = &record.detail {
        push("detail", &Value::String(detail.clone()), &mut out);
    }
    out
}

pub fn hits_to_records(search_response: &Value, mapping: &ElasticsearchFieldMapping) -> Vec<LogRecord> {
    as_arr(search_response.get("hits").and_then(|h| h.get("hits"))).iter().map(|h| normalize_hit(h, mapping)).collect()
}

// ---------------------------------------------------------------------------
// Aggregation helpers
// ---------------------------------------------------------------------------

pub fn agg_to_error_buckets(search_response: &Value) -> Vec<ErrorBucket> {
    as_arr(search_response.get("aggregations").and_then(|a| a.get("by_key")).and_then(|b| b.get("buckets")))
        .iter()
        .map(|b| ErrorBucket {
            key: js_string_or_empty(b.get("key")),
            count: b.get("doc_count").and_then(Value::as_f64).unwrap_or(0.0),
        })
        .collect()
}

pub fn compute_error_deltas(baseline: &[ErrorBucket], current: &[ErrorBucket]) -> Vec<ErrorDelta> {
    let mut all_keys: Vec<&str> = Vec::new();
    for b in baseline.iter().chain(current.iter()) {
        if !all_keys.contains(&b.key.as_str()) {
            all_keys.push(&b.key);
        }
    }
    let baseline_map: HashMap<&str, f64> = baseline.iter().map(|b| (b.key.as_str(), b.count)).collect();
    let current_map: HashMap<&str, f64> = current.iter().map(|c| (c.key.as_str(), c.count)).collect();
    let mut deltas: Vec<ErrorDelta> = all_keys
        .into_iter()
        .map(|key| {
            let b = baseline_map.get(key).copied().unwrap_or(0.0);
            let c = current_map.get(key).copied().unwrap_or(0.0);
            let ratio = if b == 0.0 {
                if c > 0.0 {
                    f64::INFINITY
                } else {
                    0.0
                }
            } else {
                c / b
            };
            ErrorDelta { key: key.to_string(), baseline: b, current: c, delta: c - b, ratio }
        })
        .collect();
    deltas.sort_by(|a, b| b.delta.partial_cmp(&a.delta).unwrap_or(std::cmp::Ordering::Equal));
    deltas
}

// ---------------------------------------------------------------------------
// Evidence conversion
// ---------------------------------------------------------------------------

/// Recursively redact secret-bearing string leaves in a structured value.
pub(crate) fn deep_redact_secrets(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_secrets(s)),
        Value::Array(items) => Value::Array(items.iter().map(deep_redact_secrets).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), deep_redact_secrets(v))).collect()),
        other => other.clone(),
    }
}

pub fn logs_to_evidence(records: &[LogRecord], query: &str, collected_at: &str) -> Vec<Evidence> {
    records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let component_or_service = r.component.as_deref().or(r.service.as_deref()).unwrap_or("");
            // Raw log messages go straight into the title — redact like the other providers do.
            let title = slice_chars(&redact_secrets(&format!("[{}] {}: {}", r.level.as_str(), component_or_service, r.message)), 160);
            let relevance = match r.level {
                LogLevel::Fatal => 1.0,
                LogLevel::Error => 0.9,
                LogLevel::Warn => 0.6,
                _ => 0.3,
            };
            // The payload persists in the report and feeds AI input — `raw` is dropped and
            // the string fields are redacted.
            let mut payload = js_value(r);
            if let Some(p) = payload.as_object_mut() {
                p.remove("raw");
                p.insert("message".into(), Value::String(redact_secrets(&r.message)));
                if let Some(d) = &r.detail {
                    p.insert("detail".into(), Value::String(redact_secrets(d)));
                }
                if let Some(c) = &r.context {
                    p.insert("context".into(), deep_redact_secrets(&Value::Object(c.clone())));
                }
            }
            Evidence {
                id: format!("ev_log_{i}"),
                source: ProviderKind::Logs,
                kind: EvidenceKind::Log,
                title,
                timestamp: Some(r.timestamp.clone()),
                relevance,
                payload,
                links: EvidenceLinks { trace_id: r.trace_id.clone(), request_id: r.request_id.clone(), ..Default::default() },
                provenance: Provenance { query: query.to_string(), collected_at: collected_at.to_string() },
                priority: None,
                category: None,
                subject: None,
                is_new: None,
                ratio: None,
            }
        })
        .collect()
}

pub fn error_buckets_to_evidence(buckets: &[ErrorBucket], field: &str, query: &str, collected_at: &str) -> Vec<Evidence> {
    buckets
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let mut payload = json!({ "field": field, "key": b.key, "count": b.count });
            crate::jsutil::normalize_js_numbers(&mut payload);
            Evidence {
                id: format!("ev_logagg_{i}"),
                source: ProviderKind::Logs,
                kind: EvidenceKind::Log,
                title: format!("{}x {}={}", crate::jsutil::js_number_string(b.count), field, b.key),
                timestamp: None,
                relevance: (b.count / 100.0).min(1.0),
                payload,
                links: EvidenceLinks::default(),
                provenance: Provenance { query: query.to_string(), collected_at: collected_at.to_string() },
                priority: None,
                category: None,
                subject: None,
                is_new: None,
                ratio: None,
            }
        })
        .collect()
}
