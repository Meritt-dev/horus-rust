//! Runtime mapping compatibility checks for Elasticsearch (HOR-47).
//!
//! Pure: takes a `_field_caps` response, returns structured diagnostics with
//! no I/O. Call from the provider's check_compatibility() method.

use horus_core::LevelFormat;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::normalize::ElasticsearchFieldMapping;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityIssue {
    pub severity: IssueSeverity,
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityReport {
    /// False when any error-severity issue is present.
    pub ok: bool,
    /// Number of indices the pattern matched. 0 means no data will ever be found.
    pub index_count: usize,
    pub issues: Vec<CompatibilityIssue>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompatibilityOptions {
    /// Whether the caller will apply a service filter (missing service field → error).
    pub requires_service: bool,
    /// Whether the caller will run terms aggregations on the service field.
    pub requires_service_aggregation: bool,
    /// Whether the caller will aggregate error signatures by event-code field.
    pub requires_event_code: bool,
}

const DATE_TYPES: &[&str] = &["date", "date_nanos"];
const NUMERIC_TYPES: &[&str] =
    &["long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float", "unsigned_long"];
const KEYWORD_TYPES: &[&str] = &["keyword", "constant_keyword", "wildcard"];
const STRING_LEVEL_TYPES: &[&str] = &["keyword", "constant_keyword", "wildcard", "text"];

fn sev(flag: bool) -> IssueSeverity {
    if flag {
        IssueSeverity::Error
    } else {
        IssueSeverity::Warning
    }
}

/// Validate an ElasticsearchFieldMapping against a `_field_caps` API response.
pub fn validate_mapping_against_caps(
    mapping: &ElasticsearchFieldMapping,
    field_caps_response: &Value,
    opts: CompatibilityOptions,
) -> CompatibilityReport {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    let indices = field_caps_response.get("indices").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let fields = field_caps_response.get("fields").and_then(Value::as_object).unwrap_or(&EMPTY);

    let mut issues: Vec<CompatibilityIssue> = Vec::new();
    let push = |issues: &mut Vec<CompatibilityIssue>, severity: IssueSeverity, field: &str, message: String| {
        issues.push(CompatibilityIssue { severity, field: field.to_string(), message });
    };

    if indices == 0 {
        push(
            &mut issues,
            IssueSeverity::Error,
            "(index)",
            "Index pattern matched no indices. Horus will find no evidence. Check the indexPattern in your connector config.".into(),
        );
        return CompatibilityReport { ok: false, index_count: 0, issues };
    }

    let present_types = |field_name: &str| -> Vec<String> {
        fields.get(field_name).and_then(Value::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default()
    };
    // All present types must be in the allowed set (not just one) — catches mixed mappings.
    let has_type = |field_name: &str, allowed: &[&str]| -> bool {
        let types = present_types(field_name);
        !types.is_empty() && types.iter().all(|t| allowed.contains(&t.as_str()))
    };
    let incompatible_types = |field_name: &str, allowed: &[&str]| -> Vec<String> {
        present_types(field_name).into_iter().filter(|t| !allowed.contains(&t.as_str())).collect()
    };
    let has_capability = |field_name: &str, allowed: &[&str], cap: &str| -> bool {
        let Some(type_map) = fields.get(field_name).and_then(Value::as_object) else { return false };
        let relevant: Vec<&Value> = type_map.iter().filter(|(t, _)| allowed.contains(&t.as_str())).map(|(_, v)| v).collect();
        !relevant.is_empty() && relevant.iter().all(|info| info.get(cap) == Some(&Value::Bool(true)))
    };

    // --- Timestamp field ---
    let ts = &mapping.timestamp_field;
    if present_types(ts).is_empty() {
        let date_fields: Vec<&String> = fields
            .iter()
            .filter(|(_, types)| types.as_object().is_some_and(|m| m.keys().any(|t| DATE_TYPES.contains(&t.as_str()))))
            .map(|(f, _)| f)
            .take(5)
            .collect();
        let listed = if date_fields.is_empty() { "(none)".to_string() } else { date_fields.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ") };
        push(&mut issues, IssueSeverity::Error, ts, format!("Timestamp field '{ts}' not found in index. Available date fields: {listed}. Set fields.timestamp in your connector config."));
    } else if !has_type(ts, DATE_TYPES) {
        let bad = incompatible_types(ts, DATE_TYPES).join(", ");
        push(&mut issues, IssueSeverity::Error, ts, format!("Timestamp field '{ts}' has incompatible type(s) [{bad}] — all observed types must be date or date_nanos. Horus cannot build time-range queries."));
    } else if !has_capability(ts, DATE_TYPES, "searchable") {
        push(&mut issues, IssueSeverity::Error, ts, format!("Timestamp field '{ts}' is not searchable — time-range queries will return no results."));
    }

    // --- Level field ---
    let lv = &mapping.level_field;
    let numeric = mapping.level_format == LevelFormat::Numeric;
    if present_types(lv).is_empty() {
        push(&mut issues, IssueSeverity::Error, lv, format!("Level field '{lv}' not found in index. Confirm levelField and levelFormat in your connector config."));
    } else if numeric && !has_type(lv, NUMERIC_TYPES) {
        let bad = incompatible_types(lv, NUMERIC_TYPES).join(", ");
        push(&mut issues, IssueSeverity::Error, lv, format!("Level field '{lv}' has incompatible type(s) [{bad}] but levelFormat is 'numeric'. Set fields.levelFormat: 'string' or point to a numeric field."));
    } else if !numeric && !has_type(lv, STRING_LEVEL_TYPES) {
        let bad = incompatible_types(lv, STRING_LEVEL_TYPES).join(", ");
        push(&mut issues, IssueSeverity::Error, lv, format!("Level field '{lv}' has incompatible type(s) [{bad}] but levelFormat is 'string'. Set fields.levelFormat: 'numeric' or point to a keyword/text field."));
    } else {
        let allowed = if numeric { NUMERIC_TYPES } else { STRING_LEVEL_TYPES };
        if !has_capability(lv, allowed, "searchable") {
            push(&mut issues, IssueSeverity::Error, lv, format!("Level field '{lv}' is not searchable — level filter queries will return no results."));
        }
    }

    // --- Service field ---
    let svc_severity = sev(opts.requires_service);
    let svc_agg_severity = sev(opts.requires_service_aggregation);
    let svc = &mapping.service_field;
    let svc_kw_field = format!("{svc}.keyword");
    if present_types(svc).is_empty() && present_types(&svc_kw_field).is_empty() {
        let tail = if opts.requires_service {
            "Cannot apply service filter — collection blocked to avoid a guaranteed empty result."
        } else {
            "Service filtering and aggregations will return no results."
        };
        push(&mut issues, svc_severity, svc, format!("Service field '{svc}' not found. {tail}"));
    } else if mapping.service_keyword && !has_type(&svc_kw_field, KEYWORD_TYPES) {
        let mid = if opts.requires_service { "Service filter will fail — collection blocked. " } else { "Service aggregations may fail. " };
        push(&mut issues, svc_severity, &svc_kw_field, format!("serviceKeyword is true but '{svc_kw_field}' has no keyword sub-field. {mid}Set fields.serviceKeyword: false if '{svc}' is already keyword-typed."));
    } else {
        let cap_field = if mapping.service_keyword { svc_kw_field.clone() } else { svc.clone() };
        if !present_types(&cap_field).is_empty() {
            if !has_capability(&cap_field, KEYWORD_TYPES, "searchable") {
                let tail = if opts.requires_service { "service filter will return empty results — collection blocked." } else { "service filter will return empty results." };
                push(&mut issues, svc_severity, &cap_field, format!("Service field '{cap_field}' is not searchable — {tail}"));
            }
            if !has_capability(&cap_field, KEYWORD_TYPES, "aggregatable") {
                let tail = if opts.requires_service_aggregation {
                    "analyzeErrors() runs service terms aggregations that Elasticsearch may reject — collection blocked."
                } else {
                    "affected services aggregation will return empty results."
                };
                push(&mut issues, svc_agg_severity, &cap_field, format!("Service field '{cap_field}' is not aggregatable — {tail}"));
            }
        }
    }

    // --- EventCode field ---
    let ec_severity = sev(opts.requires_event_code);
    let ec = &mapping.event_code_field;
    let ec_kw_field = format!("{ec}.keyword");
    if mapping.event_code_keyword && !has_type(&ec_kw_field, KEYWORD_TYPES) {
        let mid = if opts.requires_event_code {
            "Error signature aggregation blocked — collection would report zero signatures despite matching errors. "
        } else {
            "Error signature aggregations will fail. "
        };
        push(&mut issues, ec_severity, &ec_kw_field, format!("eventCodeKeyword is true but '{ec_kw_field}' not found or has no keyword type. {mid}Set fields.eventCodeKeyword: false if '{ec}' is already keyword-typed."));
    } else if !mapping.event_code_keyword && !has_type(ec, KEYWORD_TYPES) {
        let head = if opts.requires_event_code {
            format!("Event code field '{ec}' is not aggregatable — signature aggregation blocked. ")
        } else {
            format!("Event code field '{ec}' has no keyword type. ")
        };
        push(&mut issues, ec_severity, ec, format!("{head}Error signature aggregations may not work correctly."));
    } else {
        let ec_cap_field = if mapping.event_code_keyword { ec_kw_field.clone() } else { ec.clone() };
        if !has_capability(&ec_cap_field, KEYWORD_TYPES, "aggregatable") {
            let head = if opts.requires_event_code {
                format!("Event code field '{ec_cap_field}' is not aggregatable — signature aggregation blocked. ")
            } else {
                format!("Event code field '{ec_cap_field}' is not aggregatable — ")
            };
            push(&mut issues, ec_severity, &ec_cap_field, format!("{head}Error signatures cannot be grouped by event code."));
        }
    }

    let has_errors = issues.iter().any(|i| i.severity == IssueSeverity::Error);
    CompatibilityReport { ok: !has_errors, index_count: indices, issues }
}
