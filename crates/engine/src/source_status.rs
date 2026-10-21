//! HOR-70 — Runtime source status report: which evidence sources contributed to an
//! investigation, whether each connector was configured, how many items it produced,
//! and whether collection succeeded or failed.

use crate::gaps::ConnectorFlags;
use horus_core::{Evidence, EvidenceKind, ProviderKind};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeSourceKind {
    Logs,
    Metrics,
    State,
    Queue,
}

impl RuntimeSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeSourceKind::Logs => "logs",
            RuntimeSourceKind::Metrics => "metrics",
            RuntimeSourceKind::State => "state",
            RuntimeSourceKind::Queue => "queue",
        }
    }
}

/// `unavailable` = configured in the project config but the provider could not be
/// constructed for this run (missing secret / unset URL env). A different truth from
/// `not-configured` (no stanza) and from `failed` (provider ran and threw).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeSourceStatus {
    Contributed,
    Empty,
    Failed,
    NotConfigured,
    Unavailable,
}

impl RuntimeSourceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeSourceStatus::Contributed => "contributed",
            RuntimeSourceStatus::Empty => "empty",
            RuntimeSourceStatus::Failed => "failed",
            RuntimeSourceStatus::NotConfigured => "not-configured",
            RuntimeSourceStatus::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSourceEntry {
    pub source: RuntimeSourceKind,
    /// Whether the connector for this source was configured for the investigation.
    pub configured: bool,
    /// Number of runtime evidence items contributed by this source.
    pub evidence_count: i64,
    pub status: RuntimeSourceStatus,
    /// Human-readable failure detail when status is 'failed'.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSourceReport {
    pub sources: Vec<RuntimeSourceEntry>,
}

impl RuntimeSourceReport {
    /// Decode the report from the `Value` the report struct carries; `None` when absent/malformed.
    pub fn from_value(v: Option<&serde_json::Value>) -> Option<RuntimeSourceReport> {
        v.and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

fn build_entry(
    source: RuntimeSourceKind,
    configured: bool,
    evidence_count: i64,
    failed: bool,
    detail: Option<String>,
    unavailable: bool,
) -> RuntimeSourceEntry {
    let status = if !configured {
        RuntimeSourceStatus::NotConfigured
    } else if unavailable && evidence_count == 0 {
        RuntimeSourceStatus::Unavailable
    } else if failed {
        RuntimeSourceStatus::Failed
    } else if evidence_count > 0 {
        RuntimeSourceStatus::Contributed
    } else {
        RuntimeSourceStatus::Empty
    };
    RuntimeSourceEntry {
        source,
        configured,
        evidence_count,
        status,
        detail: detail.filter(|d| !d.is_empty()),
    }
}

/// Build a runtime source status report from the collected evidence and connector flags.
///
/// Queue evidenceCount counts only `kind === 'queue-state'` — not `queue-edge`, which is
/// structural topology produced by the stitcher, not a runtime signal.
pub fn build_runtime_source_status(evidence: &[Evidence], connectors: &ConnectorFlags) -> RuntimeSourceReport {
    let count = |k: ProviderKind| evidence.iter().filter(|e| e.source == k).count() as i64;
    let flag = |b: Option<bool>| b.unwrap_or(false);
    let cloud_logs = connectors.cloud_logs.as_deref().unwrap_or(&[]);

    // 'logs' is the runtime ERROR-evidence source — Elasticsearch, Sentry, and/or Axiom all
    // feed it. Configured = ANY is wired up; failed = a configured collector that did not run
    // to completion and produced no evidence.
    let logs_count = count(ProviderKind::Logs);
    let logs_configured =
        flag(connectors.elasticsearch) || flag(connectors.sentry) || flag(connectors.axiom) || !cloud_logs.is_empty();
    let es_failed = flag(connectors.elasticsearch) && !flag(connectors.logs_collected);
    let sentry_failed = flag(connectors.sentry) && !flag(connectors.sentry_collected);
    let axiom_failed = flag(connectors.axiom) && !flag(connectors.axiom_collected);
    let logs_failed = logs_configured
        && logs_count == 0
        && (es_failed || sentry_failed || axiom_failed || cloud_logs.iter().any(|p| !p.collected));

    let metrics_count = count(ProviderKind::Metrics);
    let metrics_configured = flag(connectors.grafana) || flag(connectors.prometheus);
    let metrics_failed = metrics_configured && !flag(connectors.metrics_collected);

    let state_count = count(ProviderKind::State);
    // Shopify Admin evidence is application `state`, so a configured Shopify credits the state
    // source exactly like Redis/Mongo/Postgres.
    let state_configured = flag(connectors.additional_state)
        || flag(connectors.redis)
        || flag(connectors.mongodb)
        || flag(connectors.postgres)
        || flag(connectors.shopify);
    // Failed only on an EXPLICIT collection failure with nothing contributed — strict `== false`
    // so old reports lacking the flags still read 'empty'.
    let shopify_failed = flag(connectors.shopify) && connectors.shopify_collected == Some(false);
    let state_failed = state_configured && state_count == 0 && (connectors.state_collected == Some(false) || shopify_failed);
    let mut state_detail_parts: Vec<String> = vec![];
    if let Some(r) = connectors.state_failure_reason.as_deref().filter(|r| !r.is_empty()) {
        state_detail_parts.push(r.to_string());
    }
    if shopify_failed {
        if let Some(r) = connectors.shopify_failure_reason.as_deref().filter(|r| !r.is_empty()) {
            state_detail_parts.push(format!("shopify: {r}"));
        }
    }
    let state_detail = if state_failed && !state_detail_parts.is_empty() { Some(state_detail_parts.join("; ")) } else { None };

    // Queue: configured when the BullMQ/queues connector is wired up (HOR-205) — not merely when
    // queue evidence happens to exist. Fall back to evidence presence for pre-HOR-205 reports.
    let queue_configured = connectors.queue.unwrap_or_else(|| evidence.iter().any(|e| e.source == ProviderKind::Queue));
    let queue_count = evidence.iter().filter(|e| e.kind == EvidenceKind::QueueState).count() as i64;
    let queue_failed = flag(connectors.queue) && queue_count == 0 && connectors.queue_collected == Some(false);

    // Configured-but-unavailable: a source is unavailable when EVERY connector configured for
    // it is unavailable.
    let un: HashSet<&str> = connectors.unavailable.as_deref().unwrap_or(&[]).iter().map(|s| s.as_str()).collect();
    let logs_unavailable = logs_configured
        && cloud_logs.is_empty()
        && (!flag(connectors.elasticsearch) || un.contains("elasticsearch"))
        && (!flag(connectors.sentry) || un.contains("sentry"))
        && (!flag(connectors.axiom) || un.contains("axiom"))
        && !un.is_empty();
    let metrics_unavailable =
        metrics_configured && un.contains(if flag(connectors.prometheus) { "prometheus" } else { "grafana" });
    let state_unavailable = state_configured
        && !flag(connectors.additional_state)
        && (!flag(connectors.redis) || un.contains("redis"))
        && (!flag(connectors.mongodb) || un.contains("mongodb"))
        && (!flag(connectors.postgres) || un.contains("postgres"))
        && (!flag(connectors.shopify) || un.contains("shopify"))
        && !un.is_empty();

    // Compatibility error keeps precedence over the generic failure category.
    let logs_detail = connectors
        .logs_compatibility_error
        .clone()
        .or_else(|| connectors.logs_failure_reason.clone())
        .or_else(|| {
            let parts: Vec<String> = cloud_logs
                .iter()
                .filter(|p| !p.collected)
                .map(|p| format!("{}: {}", p.id, p.failure_reason.as_deref().unwrap_or("undefined")))
                .collect();
            if cloud_logs.is_empty() {
                None
            } else {
                Some(parts.join("; "))
            }
        });

    RuntimeSourceReport {
        sources: vec![
            build_entry(RuntimeSourceKind::Logs, logs_configured, logs_count, logs_failed, logs_detail, logs_unavailable),
            build_entry(
                RuntimeSourceKind::Metrics,
                metrics_configured,
                metrics_count,
                metrics_failed,
                connectors.metrics_failure_reason.clone(),
                metrics_unavailable,
            ),
            build_entry(RuntimeSourceKind::State, state_configured, state_count, state_failed, state_detail, state_unavailable),
            build_entry(
                RuntimeSourceKind::Queue,
                queue_configured,
                queue_count,
                queue_failed,
                if queue_failed { connectors.queue_failure_reason.clone() } else { None },
                false,
            ),
        ],
    }
}
