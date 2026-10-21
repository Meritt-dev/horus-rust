//! INFO-level duration-by-dimension analysis (HOR-434, lever #2).
//!
//! The error-only log path (analyzeErrors) reads ERROR signatures but is blind to the
//! ground truth for duration anomalies, which lives in INFO completion lines — e.g.
//! `Completed MANAGE_SALES:KSA ~2m10s` / `Completed MANAGE_SALES:UAE ~19ms`. This module
//! turns a window of INFO completion logs into per-dimension duration statistics
//! (region / market / tenant), so the engine can see that one segment is 2m10s while
//! another is 19ms instead of treating the job as a single uniform population.
//!
//! Every function here is PURE (no I/O) and shared by the Elasticsearch AND Axiom
//! providers. The graceful contract: no completion logs, no parseable duration, or no
//! extractable dimension → return `None`. Never panic.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use indexmap::IndexMap;
use std::sync::LazyLock;

use crate::jsutil::js_string;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single (dimension value, duration) observation extracted from one log line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DurationSample {
    /// The grouping value, e.g. 'KSA' / 'UAE' / 'tenant-7'.
    pub dimension: String,
    /// Duration in milliseconds.
    pub duration_ms: f64,
}

/// Aggregate duration statistics for one dimension value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DimensionStat {
    /// Mean duration (ms).
    pub avg: f64,
    /// 95th-percentile duration (ms, nearest-rank).
    pub p95: f64,
    /// Number of observations.
    pub count: usize,
    /// Smallest observed duration (ms).
    pub min: f64,
    /// Largest observed duration (ms).
    pub max: f64,
}

/// Per-dimension duration breakdown — the shape the engine consumes, e.g.
/// `{ dimension: 'region', unit: 'ms', byValue: { KSA: {...}, UAE: {...} }, sampleCount: 42 }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DurationByDimension {
    /// The dimension name, e.g. 'region' / 'market' / 'tenant'.
    pub dimension: String,
    /// Always `"ms"`.
    pub unit: String,
    /// Stats keyed by dimension value (insertion order = first-seen order, as in TS).
    pub by_value: IndexMap<String, DimensionStat>,
    /// Total number of (dimension, duration) samples observed.
    pub sample_count: usize,
}

/// How to extract the grouping dimension from a log line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DimensionSpec {
    /// Output name, e.g. 'region' / 'market' / 'tenant'.
    pub name: String,
    /// A structured field path holding the value (e.g. 'context.market', 'job_id').
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Regex (with a capture group) to extract the value from text. Applied to
    /// `pattern_field` (default 'message'). E.g. `:([A-Z]{2,})$` on a job id `NAME:KSA`.
    /// `field` takes precedence when both are set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Field the `pattern` is applied to. Defaults to the message body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_field: Option<String>,
}

/// Unit of a NUMERIC `duration_field`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DurationFieldUnit {
    Ms,
    S,
}

/// How to read the duration out of a log line.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DurationDimensionOptions {
    /// Dimension extraction config.
    pub dimension: DimensionSpec,
    /// Structured numeric/string field holding the duration. Numbers are read as `unit`
    /// (default ms); strings are parsed (`"2m10s"`, `"19ms"`). Takes precedence over
    /// message parsing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_field: Option<String>,
    /// Unit of a NUMERIC `duration_field`. Default 'ms'.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_field_unit: Option<DurationFieldUnit>,
    /// Regex (with a capture group) to isolate the duration substring inside the message
    /// before parsing. When omitted, the whole message is scanned for duration tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_pattern: Option<String>,
    /// Only consider lines whose message contains this text (case-insensitive), e.g.
    /// `"Completed"`. Used by providers to scope the query AND filter client-side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_text: Option<String>,
    /// Window / scope passthrough for the provider query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Minimum log level to query. Default 'info'.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Max rows to pull for client-side aggregation. Default 500.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// A normalized log line the pure extractors can read (provider-agnostic).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DurationLogLike {
    /// The message body, when known.
    pub message: Option<String>,
    /// All structured fields (flat or nested), keyed by name.
    pub fields: Map<String, Value>,
}

// ---------------------------------------------------------------------------
// Field access (local — no ES coupling)
// ---------------------------------------------------------------------------

/// Read a (possibly dotted) path from a record, supporting flat + nested keys.
pub(crate) fn read_path<'a>(obj: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(v) = obj.get(path) {
        return Some(v);
    }
    let mut node: &Value = &Value::Null;
    let mut first = true;
    for part in path.split('.') {
        let map = if first { Some(obj) } else { node.as_object() };
        first = false;
        node = map?.get(part)?;
    }
    Some(node)
}

// ---------------------------------------------------------------------------
// Duration parsing
// ---------------------------------------------------------------------------

fn unit_ms(unit: &str) -> Option<f64> {
    Some(match unit {
        "h" => 3_600_000.0,
        "m" => 60_000.0,
        "s" => 1_000.0,
        "ms" => 1.0,
        "us" | "µs" => 0.001,
        "ns" => 0.000_001,
        _ => return None,
    })
}

// 'ms' MUST precede 'm'/'s' in the alternation so "19ms" reads as milliseconds.
// The TS regex ends with a negative lookahead `(?![a-zA-Z])` (no following letter) so
// compound forms like "2m10s" parse while a unit letter inside a word ("5 markets" must
// NOT read '5m') is rejected. `regex` has no lookahead, so the following letter is
// captured as group 3 and the token is rejected when it is non-empty — same outcome.
static DURATION_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(\d+(?:\.\d+)?)\s*(ms|us|µs|ns|h|m|s)([a-zA-Z]?)").unwrap());
static BARE_NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+(?:\.\d+)?$").unwrap());

/// Parse a human duration string into milliseconds. Handles compound forms
/// (`"2m10s"`, `"1h2m3s"`), single units (`"19ms"`, `"1.5s"`, `"500us"`), an optional
/// leading `~`, and a bare number (treated as ms). Returns `None` when nothing parses.
pub fn parse_duration_ms(raw: &str) -> Option<f64> {
    let s = raw.trim();
    let s = s.strip_prefix('~').unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    let mut total = 0.0;
    let mut matched = false;
    for caps in DURATION_TOKEN.captures_iter(s) {
        if !caps[3].is_empty() {
            continue;
        }
        let value: f64 = match caps[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let unit = caps[2].to_lowercase();
        if let Some(factor) = unit_ms(&unit) {
            if value.is_finite() {
                total += value * factor;
                matched = true;
            }
        }
    }
    if matched {
        return Some(total);
    }
    // Bare number → milliseconds.
    if BARE_NUMBER.is_match(s) {
        return s.parse::<f64>().ok().filter(|n| n.is_finite());
    }
    None
}

/// First capture group of `regex` applied to `text`, trimmed; None when no match.
pub fn extract_by_regex(text: &str, regex: &Regex) -> Option<String> {
    let caps = regex.captures(text)?;
    let captured = caps.get(1).or_else(|| caps.get(0))?.as_str();
    let v = captured.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// Nearest-rank percentile over an ascending-sorted slice. `p` in [0,100].
pub fn percentile(sorted_asc: &[f64], p: f64) -> f64 {
    let n = sorted_asc.len();
    if n == 0 {
        return 0.0;
    }
    if n == 1 {
        return sorted_asc[0];
    }
    let rank = ((p / 100.0) * n as f64).ceil() as i64;
    let idx = (rank - 1).clamp(0, n as i64 - 1) as usize;
    sorted_asc[idx]
}

/// Compute avg/p95/count/min/max over a list of durations (ms).
pub fn compute_stat(durations: &[f64]) -> DimensionStat {
    let mut sorted: Vec<f64> = durations.iter().copied().filter(|d| d.is_finite()).collect();
    if sorted.is_empty() {
        return DimensionStat { avg: 0.0, p95: 0.0, count: 0, min: 0.0, max: 0.0 };
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let sum: f64 = sorted.iter().sum();
    DimensionStat {
        avg: sum / sorted.len() as f64,
        p95: percentile(&sorted, 95.0),
        count: sorted.len(),
        min: sorted[0],
        max: sorted[sorted.len() - 1],
    }
}

// ---------------------------------------------------------------------------
// Extraction + aggregation
// ---------------------------------------------------------------------------

fn read_dimension(rec: &DurationLogLike, spec: &DimensionSpec) -> Option<String> {
    if let Some(field) = &spec.field {
        match read_path(&rec.fields, field) {
            None | Some(Value::Null) => {
                // Fall through to a message pattern when configured, else give up.
                spec.pattern.as_ref()?;
            }
            Some(raw) => {
                let v = js_string(raw).trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
                spec.pattern.as_ref()?;
            }
        }
    }
    if let Some(pattern) = &spec.pattern {
        let text = match &spec.pattern_field {
            Some(source_field) => match read_path(&rec.fields, source_field) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => String::new(),
                Some(other) => js_string(other),
            },
            None => rec.message.clone().unwrap_or_default(),
        };
        if text.is_empty() {
            return None;
        }
        return match Regex::new(pattern) {
            Ok(re) => extract_by_regex(&text, &re),
            Err(_) => None,
        };
    }
    None
}

fn read_duration(rec: &DurationLogLike, opts: &DurationDimensionOptions) -> Option<f64> {
    if let Some(field) = &opts.duration_field {
        return match read_path(&rec.fields, field) {
            Some(Value::Number(n)) => {
                let raw = n.as_f64()?;
                if !raw.is_finite() {
                    return None;
                }
                Some(if opts.duration_field_unit == Some(DurationFieldUnit::S) { raw * 1000.0 } else { raw })
            }
            Some(Value::String(s)) => parse_duration_ms(s),
            _ => None,
        };
    }
    let msg = rec.message.as_deref().unwrap_or("");
    if msg.is_empty() {
        return None;
    }
    if let Some(pattern) = &opts.duration_pattern {
        let isolated = Regex::new(pattern).ok().and_then(|re| extract_by_regex(msg, &re));
        return isolated.and_then(|s| parse_duration_ms(&s));
    }
    parse_duration_ms(msg)
}

/// Extract (dimension, duration_ms) samples from a window of normalized log lines.
/// Skips lines without a completion match, a parseable duration, or an extractable
/// dimension. Pure — the network/query lives in the providers.
pub fn extract_duration_samples(records: &[DurationLogLike], opts: &DurationDimensionOptions) -> Vec<DurationSample> {
    let needle = opts.completion_text.as_ref().map(|t| t.to_lowercase());
    let mut out = Vec::new();
    for rec in records {
        if let Some(needle) = &needle {
            let hay = rec.message.as_deref().unwrap_or("").to_lowercase();
            if !hay.contains(needle.as_str()) {
                continue;
            }
        }
        let Some(dimension) = read_dimension(rec, &opts.dimension) else { continue };
        let Some(duration_ms) = read_duration(rec, opts) else { continue };
        if !duration_ms.is_finite() {
            continue;
        }
        out.push(DurationSample { dimension, duration_ms });
    }
    out
}

/// Aggregate samples into per-dimension stats. Returns `None` when there are no
/// samples (the graceful "nothing to report" signal). A single dimension value is
/// still returned — the engine decides whether cross-segment variance is meaningful.
pub fn aggregate_durations(samples: &[DurationSample], dimension_name: &str) -> Option<DurationByDimension> {
    if samples.is_empty() {
        return None;
    }
    let mut grouped: Vec<(String, Vec<f64>)> = Vec::new();
    for s in samples {
        match grouped.iter_mut().find(|(k, _)| k == &s.dimension) {
            Some((_, list)) => list.push(s.duration_ms),
            None => grouped.push((s.dimension.clone(), vec![s.duration_ms])),
        }
    }
    let by_value = grouped.into_iter().map(|(value, durations)| (value, compute_stat(&durations))).collect();
    Some(DurationByDimension { dimension: dimension_name.to_string(), unit: "ms".to_string(), by_value, sample_count: samples.len() })
}

/// One-shot convenience: extract samples from records and aggregate. Returns `None`
/// when nothing usable is found. Used by both the ES and Axiom providers.
pub fn durations_by_dimension(records: &[DurationLogLike], opts: &DurationDimensionOptions) -> Option<DurationByDimension> {
    let samples = extract_duration_samples(records, opts);
    aggregate_durations(&samples, &opts.dimension.name)
}
