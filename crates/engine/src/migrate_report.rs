//! HOR-15 review — report migration boundary. Persisted reports may predate the
//! SuspectedCause → CauseCandidate rename (`statement → title`, `score → finalScore/confidence`,
//! `evidenceIds → sourceEvidenceIds`). Idempotent: current-shape causes pass through.

use crate::score_cause::get_band;
use crate::types::InvestigationReport;
use serde_json::{json, Map, Value};

fn migrate_cause(c: &Value, i: usize) -> Option<Value> {
    // Null or non-object entries cannot be migrated and would crash renderers; drop them.
    let cause = c.as_object()?;
    let num = |k: &str| cause.get(k).and_then(Value::as_f64);
    let arr = |k: &str| cause.get(k).and_then(Value::as_array).cloned().map(Value::Array).unwrap_or_else(|| json!([]));

    // Current CauseCandidate shape (has title + finalScore). Fill safe defaults for any
    // missing required fields so renderers cannot crash dereferencing undefined arrays.
    if let (Some(Value::String(title)), Some(fs)) = (cause.get("title"), num("finalScore")) {
        let mut out = Map::new();
        out.insert("id".into(), cause.get("id").filter(|v| v.is_string()).cloned().unwrap_or_else(|| json!(format!("cause:partial:{i}"))));
        out.insert("title".into(), json!(title));
        out.insert("category".into(), cause.get("category").filter(|v| v.is_string()).cloned().unwrap_or_else(|| json!("unknown")));
        out.insert("sourceEvidenceIds".into(), arr("sourceEvidenceIds"));
        out.insert("affectedNodeIds".into(), arr("affectedNodeIds"));
        out.insert("baseScore".into(), cause.get("baseScore").filter(|v| v.is_number()).cloned().unwrap_or_else(|| json!(fs)));
        out.insert("finalScore".into(), json!(fs));
        out.insert("confidence".into(), cause.get("confidence").filter(|v| v.is_number()).cloned().unwrap_or_else(|| json!(fs)));
        out.insert("band".into(), cause.get("band").filter(|v| v.is_string()).cloned().unwrap_or_else(|| json!(get_band(fs).as_str())));
        out.insert("explanations".into(), arr("explanations"));
        if let Some(m) = cause.get("metadata") {
            out.insert("metadata".into(), m.clone());
        }
        return Some(Value::Object(out));
    }

    // Legacy SuspectedCause shape: { statement, score, evidenceIds }. Drop entries with no statement.
    let statement = cause.get("statement").and_then(Value::as_str).unwrap_or("");
    if statement.is_empty() {
        return None;
    }
    let score = num("score").unwrap_or(0.0);
    let mut out = Map::new();
    out.insert("id".into(), json!(format!("cause:legacy:{i}")));
    out.insert("title".into(), json!(statement));
    out.insert("category".into(), json!("unknown"));
    out.insert("sourceEvidenceIds".into(), arr("evidenceIds"));
    out.insert("affectedNodeIds".into(), json!([]));
    out.insert("baseScore".into(), json!(score));
    out.insert("finalScore".into(), json!(score));
    out.insert("confidence".into(), json!(score));
    out.insert("band".into(), json!(get_band(score).as_str()));
    out.insert("explanations".into(), json!([]));
    if let Some(m) = cause.get("metadata") {
        out.insert("metadata".into(), m.clone());
    }
    Some(Value::Object(out))
}

/// Normalise a raw audit-store blob in place (legacy causes promoted, `nextActions` ensured).
/// Errors when `raw` is not an object (completely corrupt row).
pub fn migrate_report_value(raw: &mut Value) -> anyhow::Result<()> {
    let Some(r) = raw.as_object_mut() else {
        anyhow::bail!("migrateReport: expected an object, got {}", json_typeof(raw));
    };
    // Normalize nextActions — required since v0.1 but absent in pre-v0.1 packets.
    if !r.get("nextActions").is_some_and(Value::is_array) {
        r.insert("nextActions".into(), json!([]));
    }
    if let Some(Value::Array(causes)) = r.get("suspectedCauses").cloned() {
        let migrated: Vec<Value> = causes.iter().enumerate().filter_map(|(i, c)| migrate_cause(c, i)).collect();
        r.insert("suspectedCauses".into(), Value::Array(migrated));
    }
    Ok(())
}

/// Accept a raw JSON blob from the audit store and return a fully typed InvestigationReport.
pub fn migrate_report(mut raw: Value) -> anyhow::Result<InvestigationReport> {
    migrate_report_value(&mut raw)?;
    Ok(serde_json::from_value(raw)?)
}

fn json_typeof(v: &Value) -> &'static str {
    match v {
        Value::Null => "object",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) | Value::Object(_) => "object",
    }
}
