//! Error-evidence synthesis for Elasticsearch logs (HOR-10).
//!
//! Horus does NOT dump logs — it converts them into Evidence. This module turns a
//! window of error-level logs into higher-level signals: distinct error signatures
//! with first/last occurrence and affected services, plus which signatures are NEW
//! or SPIKING relative to the preceding window. All builders/parsers are pure.

use horus_core::{redact_secrets, Evidence, EvidenceKind, EvidenceLinks, Provenance, ProviderKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use super::normalize::{
    build_level_filter, build_text_must, build_where_filters, get_field, level_to_value, service_term_field,
    signature_term_field, value_to_level, ElasticsearchFieldMapping, LogLevel, LogQuery,
};
use crate::jsutil::{as_arr, as_str, js_number_from_str, js_string_or_empty, js_value, slice_chars, to_fixed};
pub use crate::jsutil::short_ts;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorSignature {
    /// The error key (event_code), or '(none)' when absent.
    pub key: String,
    pub count: f64,
    /// ISO timestamp of the earliest occurrence in the window.
    pub first_seen: String,
    /// ISO timestamp of the latest occurrence in the window.
    pub last_seen: String,
    /// Services that emitted this signature.
    pub services: Vec<String>,
    /// Log level of a representative occurrence, when the level field is captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_component: Option<String>,
    /// Structured context from a representative log of this signature (HOR-215).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_context: Option<Map<String, Value>>,
    // The three baseline fields are assigned in this order by `annotate_against_baseline`
    // in TS, which fixes their JSON key order after `sampleContext`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_count: Option<f64>,
    /// True when this signature did not occur in the baseline (preceding) window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_new: Option<bool>,
    /// current/baseline volume ratio (Infinity → JSON null when new).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratio: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AnalysisWindow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogAnalysis {
    pub window: AnalysisWindow,
    pub total_errors: f64,
    pub signatures: Vec<ErrorSignature>,
    /// Keys of signatures absent from the baseline window.
    pub new_signatures: Vec<String>,
    pub affected_services: Vec<String>,
}

/// Bucket key for error docs that have NO value in the signature field. A `terms`
/// aggregation silently drops such docs; the `missing` bucket reconciles the count
/// with the signatures and still surfaces a sample message to triage from.
pub const UNCODED_SIGNATURE_KEY: &str = "(no code)";

/// Build the error-analysis aggregation body (HOR-47 mapping-driven).
pub fn build_error_analysis_body(q: &LogQuery, field: &str, mapping: &ElasticsearchFieldMapping) -> Value {
    let mut filters: Vec<Value> = Vec::new();

    // The error-level floor scopes the unfiltered top-N aggregation to error logs. A
    // SPECIFIC event_code lookup must match regardless of level, so apply the floor
    // ONLY when no specific event_code is requested.
    if q.event_code.is_none() {
        // HOR-453: a hint-text-scoped query may deliberately lower the floor to WARN.
        let has_text = !q.text.as_deref().unwrap_or("").trim().is_empty();
        let mut min_level = LogLevel::Error;
        if let Some(l) = q.level {
            if level_to_value(l) > 50.0 {
                min_level = l; // explicit raise above error
            } else if has_text && level_to_value(l) >= 40.0 {
                min_level = l; // text-scoped warn floor
            }
        }
        filters.push(build_level_filter(mapping, min_level));
    } else if let Some(l) = q.level.filter(|l| level_to_value(*l) > 50.0) {
        // Caller explicitly raised the floor above error — honor that even for a scoped lookup.
        filters.push(build_level_filter(mapping, l));
    }

    if q.from.is_some() || q.to.is_some() {
        let mut range = Map::new();
        if let Some(from) = &q.from {
            range.insert("gte".into(), json!(from));
        }
        if let Some(to) = &q.to {
            range.insert("lte".into(), json!(to));
        }
        filters.push(json!({ "range": { &mapping.timestamp_field: range } }));
    }

    if let Some(service) = &q.service {
        filters.push(json!({ "term": { service_term_field(mapping): service } }));
    }

    let svc_term = service_term_field(mapping);
    let sig_term = if field == mapping.event_code_field { signature_term_field(mapping) } else { format!("{field}.keyword") };

    // Scope the analysis to a single error signature (event_code) when requested (HOR-215).
    if let Some(code) = &q.event_code {
        filters.push(json!({ "term": { &sig_term: code } }));
    }

    filters.extend(build_where_filters(q.where_.as_deref()));
    let must = build_text_must(q, mapping);

    json!({
        "size": 0,
        "track_total_hits": true,
        "query": { "bool": { "filter": filters, "must": must } },
        "aggs": {
            "by_sig": {
                // `missing` routes docs with no signature-field value into a single
                // "(no code)" bucket instead of dropping them.
                "terms": { "field": sig_term, "size": 25, "missing": UNCODED_SIGNATURE_KEY },
                "aggs": {
                    "first_seen": { "min": { "field": &mapping.timestamp_field } },
                    "last_seen": { "max": { "field": &mapping.timestamp_field } },
                    "services": { "terms": { "field": &svc_term, "size": 10 } },
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": [
                                &mapping.message_field,
                                &mapping.level_field,
                                "component",
                                "log_logger",
                                "context",
                                "detail",
                            ],
                            "sort": [{ &mapping.timestamp_field: { "order": "desc" } }],
                        }
                    },
                }
            },
            "affected_services": { "terms": { "field": &svc_term, "size": 20 } },
        },
    })
}

fn buckets_of(node: Option<&Value>) -> &[Value] {
    as_arr(node.and_then(|n| n.get("buckets")))
}

/// Read a log level from a representative doc's source. Handles both Pino numeric levels
/// (50 → 'error') and string labels ('Error'/'warn' → normalized lowercase).
fn read_level(src: &Map<String, Value>, level_field: &str) -> Option<LogLevel> {
    let raw = match get_field(src, level_field) {
        Some(Value::Null) | None => src.get(level_field),
        v => v,
    }?;
    if let Some(n) = raw.as_f64().filter(|n| n.is_finite()) {
        return Some(value_to_level(n));
    }
    if let Some(s) = raw.as_str() {
        let v = s.trim().to_lowercase();
        if let Some(l) = LogLevel::from_label(&v) {
            return Some(l);
        }
        if v == "warning" {
            return Some(LogLevel::Warn);
        }
        if let Some(n) = js_number_from_str(&v) {
            return Some(value_to_level(n));
        }
    }
    None
}

/// Parse an error-analysis aggregation response into a LogAnalysis (no baseline).
/// `message_field` must match the field requested in the sample top_hits _source.
pub fn parse_error_analysis(resp: &Value, window: AnalysisWindow, message_field: &str, level_field: Option<&str>) -> LogAnalysis {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    let aggs = resp.get("aggregations").and_then(Value::as_object).unwrap_or(&EMPTY);
    let total_node = resp.get("hits").and_then(|h| h.get("total"));
    let total_errors = total_node
        .and_then(Value::as_f64)
        .or_else(|| total_node.and_then(|t| t.get("value")).and_then(Value::as_f64))
        .unwrap_or(0.0);

    let signatures: Vec<ErrorSignature> = buckets_of(aggs.get("by_sig"))
        .iter()
        .map(|b| {
            let first = b.get("first_seen").and_then(|f| f.get("value_as_string"));
            let last = b.get("last_seen").and_then(|f| f.get("value_as_string"));
            let services = buckets_of(b.get("services")).iter().map(|s| js_string_or_empty(s.get("key"))).collect();
            let sample_src = as_arr(b.get("sample").and_then(|s| s.get("hits")).and_then(|h| h.get("hits")))
                .first()
                .and_then(|h| h.get("_source"))
                .and_then(Value::as_object)
                .unwrap_or(&EMPTY);

            // Use the configured message field (supports dotted paths); fall back to 'message'.
            let sample_message = as_str(get_field(sample_src, message_field))
                .or_else(|| as_str(sample_src.get("message")))
                .map(str::to_string);
            let sample_context = sample_src.get("context").and_then(Value::as_object).cloned();
            let level = level_field.and_then(|lf| read_level(sample_src, lf));
            let key = js_string_or_empty(b.get("key"));

            ErrorSignature {
                key: if key.is_empty() { "(none)".into() } else { key },
                count: b.get("doc_count").and_then(Value::as_f64).unwrap_or(0.0),
                first_seen: as_str(first).unwrap_or("").to_string(),
                last_seen: as_str(last).unwrap_or("").to_string(),
                services,
                level,
                sample_message,
                sample_component: as_str(sample_src.get("component")).or_else(|| as_str(sample_src.get("log_logger"))).map(str::to_string),
                sample_context,
                baseline_count: None,
                is_new: None,
                ratio: None,
            }
        })
        .collect();

    let affected_services = buckets_of(aggs.get("affected_services")).iter().map(|s| js_string_or_empty(s.get("key"))).collect();

    LogAnalysis { window, total_errors, signatures, new_signatures: Vec::new(), affected_services }
}

/// Annotate a current analysis against a baseline window's signatures: mark NEW
/// signatures and compute spike ratios. Mutates `current`.
pub fn annotate_against_baseline(current: &mut LogAnalysis, baseline: &[ErrorSignature]) {
    let base_map: HashMap<&str, f64> = baseline.iter().map(|s| (s.key.as_str(), s.count)).collect();
    let mut new_signatures = Vec::new();
    for s in &mut current.signatures {
        let b = base_map.get(s.key.as_str()).copied().unwrap_or(0.0);
        s.baseline_count = Some(b);
        s.is_new = Some(b == 0.0);
        s.ratio = Some(if b == 0.0 {
            if s.count > 0.0 {
                f64::INFINITY
            } else {
                0.0
            }
        } else {
            s.count / b
        });
        if s.is_new == Some(true) {
            new_signatures.push(s.key.clone());
        }
    }
    current.new_signatures = new_signatures;
}

// ── Sensitive-field redaction (HOR-91; canonical impl in horus_core) ─────────

/// Scrub common sensitive patterns from a single string.
pub fn redact_sensitive_string(s: &str) -> String {
    redact_secrets(s)
}

/// Return a copy of an ErrorSignature with sample_message redacted.
pub fn redact_error_signature(sig: &ErrorSignature) -> ErrorSignature {
    let mut out = sig.clone();
    if let Some(m) = &sig.sample_message {
        out.sample_message = Some(redact_sensitive_string(m));
    }
    out
}

/// Convert a LogAnalysis into Evidence records (one per signature + an
/// affected-services summary). Synthesized signals, never raw log dumps.
pub fn analysis_to_evidence(analysis: &LogAnalysis, query: &str, collected_at: &str) -> Vec<Evidence> {
    let mut out = Vec::new();
    let provenance = || Provenance { query: query.to_string(), collected_at: collected_at.to_string() };

    for (i, s) in analysis.signatures.iter().enumerate() {
        let mut tags: Vec<String> = Vec::new();
        if s.is_new == Some(true) {
            tags.push("NEW".into());
        } else if let Some(r) = s.ratio.filter(|r| r.is_finite() && *r >= 1.5) {
            tags.push(format!("spike x{}", to_fixed(r, 1)));
        }
        let svc = if s.services.is_empty() { String::new() } else { format!(" · {}", s.services.iter().take(3).cloned().collect::<Vec<_>>().join(", ")) };
        let tag_str = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
        let title = slice_chars(
            &format!(
                "Error {}: {}x (first {}, last {}){}{}",
                s.key,
                crate::jsutil::js_number_string(s.count),
                short_ts(&s.first_seen),
                short_ts(&s.last_seen),
                svc,
                tag_str
            ),
            180,
        );
        let relevance = if s.is_new == Some(true) {
            0.95
        } else if s.ratio.is_some_and(|r| r >= 1.5) {
            0.9
        } else {
            0.8
        };
        out.push(Evidence {
            id: format!("ev_errsig_{i}"),
            source: ProviderKind::Logs,
            kind: EvidenceKind::Log,
            title,
            timestamp: if s.last_seen.is_empty() { None } else { Some(s.last_seen.clone()) },
            relevance,
            payload: js_value(s),
            links: EvidenceLinks::default(),
            provenance: provenance(),
            priority: None,
            category: None,
            subject: None,
            is_new: s.is_new,
            ratio: s.ratio.filter(|r| r.is_finite()),
        });
    }

    if !analysis.affected_services.is_empty() {
        let mut payload = json!({ "services": analysis.affected_services, "totalErrors": analysis.total_errors });
        crate::jsutil::normalize_js_numbers(&mut payload);
        out.push(Evidence {
            id: "ev_affected_services".into(),
            source: ProviderKind::Logs,
            kind: EvidenceKind::Log,
            title: format!(
                "Affected service(s): {} ({} error(s))",
                analysis.affected_services.join(", "),
                crate::jsutil::js_number_string(analysis.total_errors)
            ),
            timestamp: None,
            relevance: 0.6,
            payload,
            links: EvidenceLinks::default(),
            provenance: provenance(),
            priority: None,
            category: None,
            subject: None,
            is_new: None,
            ratio: None,
        });
    }
    out
}
