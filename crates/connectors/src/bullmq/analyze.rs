//! Pure helpers for converting raw BullMQ queue state into typed Evidence (HOR-12).
//!
//! No network, no side effects. Thresholds are intentionally generous — the goal
//! is to surface anything an engineer would care about during an incident, not to
//! flag every non-zero count.

use crate::jsutil::{js_num_opt, js_num_value, to_locale_string};
use horus_core::{redact_secrets, Evidence, EvidenceKind, EvidenceLinks, ProviderKind, Provenance};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedBreakdown {
    pub reason: String,
    pub count: i64,
    /// Age (ms) of the most recent sampled failure for that reason (HOR-217).
    #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "js_num_opt")]
    pub last_failed_age_ms: Option<f64>,
}

/// Raw counts for a single queue, collected from Redis. Field order is the TS
/// insertion order (`failedBreakdown` is assigned before `newestFailedAgeMs`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueCounts {
    pub queue_name: String,
    pub waiting: i64,
    pub active: i64,
    pub failed: i64,
    pub delayed: i64,
    pub completed: i64,
    /// Non-zero only when the queue is paused (jobs accumulate in the paused list).
    pub paused: i64,
    pub is_paused: bool,
    /// Age of the oldest waiting job in milliseconds; None when the queue is empty.
    #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "js_num_opt")]
    pub oldest_waiting_ms: Option<f64>,
    /// Top failed-reason buckets, sorted by count descending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_breakdown: Option<Vec<FailedBreakdown>>,
    /// Age (ms) of the most recent failed job in the sample (HOR-217). Lets callers
    /// distinguish a job that failed minutes ago from a stale failure days old.
    #[serde(default, skip_serializing_if = "Option::is_none", serialize_with = "js_num_opt")]
    pub newest_failed_age_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueRuntimeState {
    pub prefix: String,
    pub collected_at: String,
    pub queues: Vec<QueueCounts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QueueSignalKind {
    Backlog,
    FailedSpike,
    DelayedAccumulation,
    WorkerStarvation,
    FailedBreakdown,
    OldestJob,
    Summary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueSignal {
    pub queue_name: String,
    pub kind: QueueSignalKind,
    pub title: String,
    pub relevance: f64,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

// ── Thresholds ────────────────────────────────────────────────────────────────

const BACKLOG_WARN: i64 = 100;
const BACKLOG_HIGH: i64 = 1_000;
const FAILED_WARN: i64 = 20;
const DELAYED_WARN: i64 = 50;
/// Starvation: queue has jobs waiting but no workers are processing.
const STARVATION_MIN: i64 = 10;
const OLD_JOB_WARN_MS: f64 = 5.0 * 60_000.0;
const OLD_JOB_HIGH_MS: f64 = 60.0 * 60_000.0;
/// Only emit a failed-breakdown signal when the top reason owns at least this share.
const BREAKDOWN_PCT_THRESHOLD: i64 = 30;
/// A failed job older than this is "stale" — its error reflects a past run, not a
/// live incident. Surfaced so investigations don't report an old 401 as current (HOR-217).
pub const STALE_FAILED_MS: f64 = 60.0 * 60_000.0;

/// Is a failed-job age stale (older than the threshold)?
pub fn is_stale_failure(age_ms: Option<f64>) -> bool {
    age_ms.is_some_and(|a| a > STALE_FAILED_MS)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn fmt_ms(ms: f64) -> String {
    if ms >= 86_400_000.0 {
        format!("{}d", (ms / 86_400_000.0).floor() as i64)
    } else if ms >= 3_600_000.0 {
        format!("{}h", (ms / 3_600_000.0).floor() as i64)
    } else if ms >= 60_000.0 {
        format!("{}m", (ms / 60_000.0).floor() as i64)
    } else {
        format!("{}s", (ms / 1_000.0).floor() as i64)
    }
}

fn opt_ms(v: Option<f64>) -> Value {
    v.map(js_num_value).unwrap_or(Value::Null)
}

// ── Signal extraction ─────────────────────────────────────────────────────────

/// Derive all notable signals for a single queue.
/// Always includes a `summary` signal so the AI sees raw counts even when
/// nothing is alarming.
pub fn analyze_queue_signals(q: &QueueCounts) -> Vec<QueueSignal> {
    let mut signals: Vec<QueueSignal> = Vec::new();
    let name = &q.queue_name;
    let sig = |kind: QueueSignalKind, title: String, relevance: f64, payload: Value| QueueSignal {
        queue_name: name.clone(),
        kind,
        title,
        relevance,
        payload,
        timestamp: None,
    };

    // Starvation-like signal: waiting jobs with no active workers in this snapshot.
    // A single zero-active observation is not proof of starvation — workers may be
    // idle between polls or all jobs may have just completed. Relevance is kept
    // moderate; the engine should not treat this alone as a confirmed cause.
    if q.waiting >= STARVATION_MIN && q.active == 0 {
        signals.push(sig(
            QueueSignalKind::WorkerStarvation,
            format!("{name}: {} waiting jobs, 0 active workers — possible starvation", q.waiting),
            0.7,
            json!({ "queueName": name, "waiting": q.waiting, "active": 0 }),
        ));
    } else if q.waiting > BACKLOG_HIGH {
        signals.push(sig(
            QueueSignalKind::Backlog,
            format!("{name}: {} jobs waiting (severe backlog)", to_locale_string(q.waiting)),
            0.88,
            json!({ "queueName": name, "waiting": q.waiting, "active": q.active }),
        ));
    } else if q.waiting > BACKLOG_WARN {
        signals.push(sig(
            QueueSignalKind::Backlog,
            format!("{name}: {} jobs waiting (backlog)", q.waiting),
            0.8,
            json!({ "queueName": name, "waiting": q.waiting, "active": q.active }),
        ));
    }

    if let Some(oldest) = q.oldest_waiting_ms.filter(|o| *o > OLD_JOB_WARN_MS) {
        let severe = oldest > OLD_JOB_HIGH_MS;
        signals.push(sig(
            QueueSignalKind::OldestJob,
            format!("{name}: oldest waiting job is {} old{}", fmt_ms(oldest), if severe { " (severe)" } else { "" }),
            if severe { 0.85 } else { 0.75 },
            json!({ "queueName": name, "oldestWaitingMs": js_num_value(oldest) }),
        ));
    }

    if q.failed > FAILED_WARN {
        let severe = q.failed > 100;
        let stale = is_stale_failure(q.newest_failed_age_ms);
        let age_str = match q.newest_failed_age_ms {
            Some(a) => format!(" (most recent {} ago{})", fmt_ms(a), if stale { ", STALE" } else { "" }),
            None => String::new(),
        };
        signals.push(sig(
            QueueSignalKind::FailedSpike,
            format!("{name}: {} failed jobs{}{}", q.failed, if severe { " (severe)" } else { "" }, age_str),
            // A purely stale failure pile is less likely to be the live incident — hedge.
            if stale {
                0.5
            } else if severe {
                0.85
            } else {
                0.75
            },
            json!({
                "queueName": name,
                "failed": q.failed,
                "newestFailedAgeMs": opt_ms(q.newest_failed_age_ms),
                "stale": stale,
            }),
        ));
    }

    if q.delayed > DELAYED_WARN {
        signals.push(sig(
            QueueSignalKind::DelayedAccumulation,
            format!("{name}: {} delayed jobs accumulated", q.delayed),
            0.7,
            json!({ "queueName": name, "delayed": q.delayed }),
        ));
    }

    // Failed breakdown: only when a single reason dominates (>= BREAKDOWN_PCT_THRESHOLD%).
    // Divide by sample total (not q.failed) — q.failed reflects all retained failures,
    // but breakdown counts come from a fixed-size sample (FAILED_SAMPLE), so the
    // denominator must match the sample to produce meaningful percentages.
    if let Some(breakdown) = q.failed_breakdown.as_ref().filter(|b| !b.is_empty() && q.failed > 0) {
        let top = &breakdown[0];
        let sample_total: i64 = breakdown.iter().map(|b| b.count).sum();
        let pct = ((top.count as f64 / sample_total.max(1) as f64) * 100.0).round() as i64;
        if pct >= BREAKDOWN_PCT_THRESHOLD {
            let stale = is_stale_failure(top.last_failed_age_ms);
            let age_str = match top.last_failed_age_ms {
                Some(a) => format!(", last failed {} ago{}", fmt_ms(a), if stale { " [STALE]" } else { "" }),
                None => String::new(),
            };
            // failedReason is a raw application error string (routinely a driver message
            // with a connection URL). It reaches reports/postmortems/AI input via the
            // title AND the payload (engine reads payload.topReason into cause titles),
            // so redact every copy.
            let safe_reason = redact_secrets(&top.reason);
            let redacted: Vec<FailedBreakdown> = breakdown
                .iter()
                .take(3)
                .map(|b| FailedBreakdown { reason: redact_secrets(&b.reason), ..b.clone() })
                .collect();
            signals.push(sig(
                QueueSignalKind::FailedBreakdown,
                format!(
                    "{name}: {pct}% of recently sampled failures ({}/{sample_total} sampled) are \"{safe_reason}\"{age_str}",
                    top.count
                ),
                // Demote a stale-only breakdown so a days-old error isn't read as live (HOR-217).
                if stale { 0.5 } else { 0.82 },
                json!({
                    "queueName": name,
                    "topReason": safe_reason,
                    "topCount": top.count,
                    "topPct": pct,
                    "totalFailed": q.failed,
                    "topLastFailedAgeMs": opt_ms(top.last_failed_age_ms),
                    "topStale": stale,
                    "breakdown": redacted,
                }),
            ));
        }
    }

    // Always emit a summary (low relevance) for raw counts
    signals.push(sig(
        QueueSignalKind::Summary,
        format!("{name}: {} waiting, {} active, {} failed, {} delayed", q.waiting, q.active, q.failed, q.delayed),
        0.4,
        json!({
            "queueName": name,
            "waiting": q.waiting,
            "active": q.active,
            "failed": q.failed,
            "delayed": q.delayed,
            "completed": q.completed,
            "isPaused": q.is_paused,
        }),
    ));

    signals
}

/// All signals across all queues in a runtime state snapshot.
pub fn analyze_queue_runtime(state: &QueueRuntimeState) -> Vec<QueueSignal> {
    state.queues.iter().flat_map(analyze_queue_signals).collect()
}

/// Convert queue runtime state into Evidence records.
/// Used by `QueueRuntimeProvider::to_evidence()`.
pub fn queue_state_to_evidence(state: &QueueRuntimeState, query: &str, collected_at: &str) -> Vec<Evidence> {
    let mut evs: Vec<Evidence> = Vec::new();
    let mut i = 0;
    for q in &state.queues {
        for s in analyze_queue_signals(q) {
            evs.push(Evidence {
                id: format!("ev_qs_{i}"),
                source: ProviderKind::Queue,
                kind: EvidenceKind::QueueState,
                title: s.title,
                timestamp: s.timestamp,
                relevance: s.relevance,
                payload: s.payload,
                links: EvidenceLinks { queue_name: Some(q.queue_name.clone()), ..Default::default() },
                provenance: Provenance { query: query.to_string(), collected_at: collected_at.to_string() },
                priority: None,
                category: None,
                subject: None,
                is_new: None,
                ratio: None,
            });
            i += 1;
        }
    }
    evs
}
