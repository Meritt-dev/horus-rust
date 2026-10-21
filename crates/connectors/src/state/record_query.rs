//! Bounded, projected, equality-only record reads (`record-query.ts`). serde +
//! manual checks replace the zod schema; the accepted inputs are identical.

use anyhow::{bail, Result};
use horus_core::redact_secrets;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::LazyLock;

static SENSITIVE_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(password|secret|token|authorization|credential|api_?key|__proto__|constructor|prototype)").unwrap()
});
static COLLECTION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());
static FIELD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$").unwrap());

pub fn is_sensitive_field(name: &str) -> bool {
    SENSITIVE_FIELD.is_match(name)
}

/// Parent projections can contain secret descendants; redact names recursively.
pub fn redact_record_value(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_secrets(&s)),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_record_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| {
                    let v = if SENSITIVE_FIELD.is_match(&key) { Value::from("[REDACTED]") } else { redact_record_value(item) };
                    (key, v)
                })
                .collect(),
        ),
        other => other,
    }
}

/// Equality value: string | finite number | boolean. `Number` keeps the JSON spelling so
/// `JSON.stringify(query)` provenance matches the TS output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecordValue {
    Str(String),
    Num(serde_json::Number),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordWhere {
    pub field: String,
    pub value: RecordValue,
}

fn default_limit() -> i64 {
    1
}

// Equality only, projected fields only. Never accept Mongo operators or executable queries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRecordQuery {
    pub collection: String,
    #[serde(rename = "where")]
    pub where_: Vec<RecordWhere>,
    pub fields: Vec<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn check_field(path: &str, value: &str) -> Result<()> {
    let n = value.chars().count();
    if n < 1 {
        bail!("{path}: String must contain at least 1 character(s)");
    }
    if n > 160 {
        bail!("{path}: String must contain at most 160 character(s)");
    }
    if !FIELD_RE.is_match(value) {
        bail!("{path}: Invalid");
    }
    if SENSITIVE_FIELD.is_match(value) {
        bail!("{path}: Sensitive or unsafe field");
    }
    Ok(())
}

/// The zod constraints of `stateRecordQuerySchema`, applied to an already-typed query.
pub fn validate_state_record_query(q: &StateRecordQuery) -> Result<()> {
    let n = q.collection.chars().count();
    if n < 1 {
        bail!("collection: String must contain at least 1 character(s)");
    }
    if n > 120 {
        bail!("collection: String must contain at most 120 character(s)");
    }
    if !COLLECTION_RE.is_match(&q.collection) {
        bail!("collection: Invalid");
    }
    if q.where_.is_empty() {
        bail!("where: Array must contain at least 1 element(s)");
    }
    if q.where_.len() > 8 {
        bail!("where: Array must contain at most 8 element(s)");
    }
    for (i, w) in q.where_.iter().enumerate() {
        check_field(&format!("where.{i}.field"), &w.field)?;
        match &w.value {
            RecordValue::Str(s) => {
                let n = s.chars().count();
                if n < 1 {
                    bail!("where.{i}.value: String must contain at least 1 character(s)");
                }
                if n > 512 {
                    bail!("where.{i}.value: String must contain at most 512 character(s)");
                }
            }
            RecordValue::Num(n) => {
                if !n.as_f64().is_some_and(f64::is_finite) {
                    bail!("where.{i}.value: Number must be finite");
                }
            }
            RecordValue::Bool(_) => {}
        }
    }
    if q.fields.is_empty() {
        bail!("fields: Array must contain at least 1 element(s)");
    }
    if q.fields.len() > 30 {
        bail!("fields: Array must contain at most 30 element(s)");
    }
    for (i, f) in q.fields.iter().enumerate() {
        check_field(&format!("fields.{i}"), f)?;
    }
    if q.limit < 1 {
        bail!("limit: Number must be greater than or equal to 1");
    }
    if q.limit > 5 {
        bail!("limit: Number must be less than or equal to 5");
    }
    Ok(())
}

/// `stateRecordQuerySchema.parse(input)`: strict shape + constraints.
pub fn parse_state_record_query(input: &Value) -> Result<StateRecordQuery> {
    let q: StateRecordQuery = serde_json::from_value(input.clone()).map_err(|e| anyhow::anyhow!("Invalid record query: {e}"))?;
    validate_state_record_query(&q)?;
    Ok(q)
}
