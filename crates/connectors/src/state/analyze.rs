//! Pure state-evidence helpers, shared by every state provider (MongoDB, Postgres, …).
//!
//! A datastore holds system STATE, not just storage. These helpers turn container
//! (collection / table) shape + counts into Evidence — never raw records. Generic by
//! design: no project-specific field names are hard-coded as logic, only as detection hints.

use crate::jsutil::{js_num, js_num_opt, js_num_value, parse_js_date_ms};
use horus_core::{Evidence, EvidenceKind, EvidenceLinks, ProviderKind, Provenance};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::LazyLock;

/// Conventional date/activity field names, in priority order.
pub const DATE_FIELDS: &[&str] = &[
    "completedAt",
    "last_executed_at",
    "lastSyncedAt",
    "last_run_started_at",
    "updatedAt",
    "updated_at",
    "syncedAt",
    "startedAt",
    "createdAt",
    "created_at",
    "timestamp",
    "time",
    "date",
];

/// Conventional status/state field names, in priority order.
pub const STATUS_FIELDS: &[&str] = &["status", "last_run_status", "syncStatus", "state", "connectionStatus"];

/// Status values that indicate a problem state.
pub static ANOMALOUS_STATUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)fail|error|stuck|timeout|disconn|inactive|stale|cancel|dead|broken|pending|retry|unhealthy").unwrap()
});

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusCount {
    pub value: String,
    pub count: i64,
}

/// Operational classification of a container by last-activity age:
///  - active:  recent activity (< staleHours)
///  - stale:   no recent activity but within the legacy horizon
///  - legacy:  not touched in a very long time — likely an old/abandoned artifact
///  - unknown: no usable date field
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    Active,
    Stale,
    Legacy,
    Unknown,
}

impl Classification {
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::Active => "active",
            Classification::Stale => "stale",
            Classification::Legacy => "legacy",
            Classification::Unknown => "unknown",
        }
    }
}

/// Default legacy horizon: ~90 days. Beyond this, treat state as a legacy artifact.
pub const DEFAULT_LEGACY_HOURS: f64 = 90.0 * 24.0;

/// Field order follows the TS object's INSERTION order in `analyzeStateWith`
/// (`classification`/`anomalies` are set at construction, the date/status fields
/// afterwards), which is the order the TS JSON serializes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionState {
    /// Container name — a Mongo collection or a Postgres table.
    pub collection: String,
    pub count: i64,
    pub classification: Classification,
    /// Status buckets whose value matches ANOMALOUS_STATUS.
    pub anomalies: Vec<StatusCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "js_num_opt")]
    pub age_hours: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_stale: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_counts: Option<Vec<StatusCount>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateAnalysis {
    pub database: String,
    #[serde(serialize_with = "js_num")]
    pub stale_hours: f64,
    #[serde(serialize_with = "js_num")]
    pub legacy_hours: f64,
    pub collections: Vec<CollectionState>,
    /// True when no allowlist was configured — containers were discovered from the database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_discovered: Option<bool>,
}

pub fn classify_age(age_hours: Option<f64>, stale_hours: f64, legacy_hours: f64) -> Classification {
    match age_hours {
        None => Classification::Unknown,
        Some(a) if a >= legacy_hours => Classification::Legacy,
        Some(a) if a >= stale_hours => Classification::Stale,
        Some(_) => Classification::Active,
    }
}

/// First candidate present in `fields`.
pub fn pick_field(fields: &[String], candidates: &[&str]) -> Option<String> {
    candidates.iter().find(|c| fields.iter().any(|f| f == *c)).map(|c| c.to_string())
}

pub fn is_anomalous_status(value: &str) -> bool {
    ANOMALOUS_STATUS.is_match(value)
}

/// Hours between an ISO timestamp and `now_ms` (>= 0; NaN-safe -> 0).
pub fn age_hours_of(iso: &str, now_ms: i64) -> f64 {
    match parse_js_date_ms(iso) {
        None => 0.0,
        Some(t) => ((now_ms - t) as f64 / 3_600_000.0).max(0.0),
    }
}

fn fmt_age(hours: f64) -> String {
    if hours >= 48.0 {
        format!("{}d", (hours / 24.0).round() as i64)
    } else if hours >= 1.0 {
        format!("{}h", hours.round() as i64)
    } else {
        format!("{}m", (hours * 60.0).round() as i64)
    }
}

static CAMEL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-z0-9])([A-Z])").unwrap());
static NON_ALNUM_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^A-Za-z0-9]+").unwrap());

/// Split a string into lowercased word/identifier tokens of length >= 4.
pub fn tokenize(s: &str) -> Vec<String> {
    let spaced = CAMEL_RE.replace_all(s, "$1 $2");
    NON_ALNUM_RE
        .split(&spaced)
        .map(|t| t.to_lowercase())
        .filter(|t| t.chars().count() >= 4)
        .collect()
}

/// Does a container name relate to any of the hint/seed terms?
pub fn collection_matches_terms(collection: &str, terms: &[String]) -> bool {
    if terms.is_empty() {
        return true; // no hint context => everything is "relevant"
    }
    let cl = collection.to_lowercase();
    let singular = cl.strip_suffix('s').unwrap_or(&cl);
    terms.iter().any(|t| t.chars().count() >= 4 && (cl.contains(t.as_str()) || t.contains(singular)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateSignalKind {
    Anomaly,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateSignal {
    pub collection: String,
    pub kind: StateSignalKind,
    pub classification: Classification,
    pub relevant: bool,
    pub relevance: f64,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    pub payload: Value,
}

/// Insert only when present — JS `JSON.stringify` drops `undefined` members.
fn put_opt(m: &mut Map<String, Value>, key: &str, v: Option<Value>) {
    if let Some(v) = v {
        m.insert(key.to_string(), v);
    }
}

/// Select the notable state signals, filtered + weighted by relevance to the hint
/// terms and by classification. Relevance discipline:
///  - a stale/legacy container unrelated to the hint is dropped (it's just noise);
///  - an ACTIVE anomaly is always surfaced (a currently-failing container matters),
///    but down-weighted when it isn't hint-relevant;
///  - legacy artifacts are heavily down-weighted and only shown when hint-relevant.
pub fn select_state_signals(analysis: &StateAnalysis, terms: &[String]) -> Vec<StateSignal> {
    let mut signals: Vec<StateSignal> = Vec::new();

    for c in &analysis.collections {
        let relevant = collection_matches_terms(&c.collection, terms);
        let legacy = c.classification == Classification::Legacy;

        for a in &c.anomalies {
            // Drop legacy/irrelevant anomalies; keep active ones (even if not relevant).
            if !relevant && (legacy || c.classification != Classification::Active) {
                continue;
            }
            let relevance = if legacy {
                0.25
            } else if relevant {
                0.85
            } else {
                0.5
            };
            let tag = if legacy {
                " (legacy)"
            } else if c.classification == Classification::Stale {
                " (stale)"
            } else {
                ""
            };
            let mut payload = Map::new();
            payload.insert("collection".into(), Value::from(c.collection.clone()));
            put_opt(&mut payload, "statusField", c.status_field.clone().map(Value::from));
            payload.insert("status".into(), Value::from(a.value.clone()));
            payload.insert("count".into(), Value::from(a.count));
            payload.insert("totalRecords".into(), Value::from(c.count));
            payload.insert("classification".into(), Value::from(c.classification.as_str()));
            signals.push(StateSignal {
                collection: c.collection.clone(),
                kind: StateSignalKind::Anomaly,
                classification: c.classification,
                relevant,
                relevance,
                title: format!("{}: {} record(s) in state \"{}\"{}", c.collection, a.count, a.value, tag),
                timestamp: None,
                payload: Value::Object(payload),
            });
        }

        // Stale/legacy "no recent activity" is only worth surfacing when hint-relevant.
        if c.is_stale == Some(true) && relevant {
            if let Some(last) = c.last_activity.as_deref().filter(|s| !s.is_empty()) {
                let mut payload = Map::new();
                payload.insert("collection".into(), Value::from(c.collection.clone()));
                put_opt(&mut payload, "dateField", c.date_field.clone().map(Value::from));
                payload.insert("lastActivity".into(), Value::from(last));
                put_opt(&mut payload, "ageHours", c.age_hours.map(js_num_value));
                payload.insert("classification".into(), Value::from(c.classification.as_str()));
                signals.push(StateSignal {
                    collection: c.collection.clone(),
                    kind: StateSignalKind::Stale,
                    classification: c.classification,
                    relevant,
                    relevance: if legacy { 0.25 } else { 0.6 },
                    title: format!(
                        "{}: {} — last {} {} ago",
                        c.collection,
                        if legacy { "legacy" } else { "stale" },
                        c.date_field.as_deref().unwrap_or("undefined"),
                        fmt_age(c.age_hours.unwrap_or(0.0))
                    ),
                    timestamp: Some(last.to_string()),
                    payload: Value::Object(payload),
                });
            }
        }
    }

    // Stable sort, like `Array#sort` — ties keep insertion order.
    signals.sort_by(|x, y| y.relevance.partial_cmp(&x.relevance).unwrap_or(std::cmp::Ordering::Equal));
    signals
}

/// Convert a state analysis into Evidence. With no hint terms this surfaces all
/// notable signals (classification-weighted); pass hint terms to apply relevance
/// filtering. Counts + state only — never raw records.
pub fn state_to_evidence(analysis: &StateAnalysis, query: &str, collected_at: &str, terms: &[String]) -> Vec<Evidence> {
    select_state_signals(analysis, terms)
        .into_iter()
        .enumerate()
        .map(|(i, s)| Evidence {
            id: format!("ev_state_{i}"),
            source: ProviderKind::State,
            kind: EvidenceKind::State,
            title: s.title,
            timestamp: s.timestamp,
            relevance: s.relevance,
            payload: s.payload,
            links: EvidenceLinks::default(),
            provenance: Provenance { query: query.to_string(), collected_at: collected_at.to_string() },
            priority: None,
            category: None,
            subject: None,
            is_new: None,
            ratio: None,
        })
        .collect()
}
