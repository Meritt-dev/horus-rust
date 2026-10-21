//! HOR-19 — Missing-evidence detector.
//!
//! Identifies what Horus does NOT know for a given investigation, why each gap
//! matters, where to obtain the missing data, and the deterministic confidence
//! impact. The resulting `GapAnalysis` caps `report.confidence` in the engine.

use std::sync::LazyLock;

use horus_core::EvidenceKind;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::js;
use crate::types::{Intent, InvestigationReport, RouteStep};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudLogStatus {
    pub id: String,
    pub collected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Which connectors are configured for the active project/environment.
/// `Option<bool>` fields mirror TS optional booleans (absent ≠ false where the
/// TS code uses strict `=== false`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorFlags {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_logs: Option<Vec<CloudLogStatus>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elasticsearch: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grafana: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prometheus: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_state: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mongodb: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentry: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axiom: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_collected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shopify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shopify_collected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redis: Option<bool>,
    /// True when a BullMQ/queues runtime connector is configured (HOR-205).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs_collected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs_compatibility_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentry_collected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axiom_collected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_collected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sentry_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axiom_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shopify_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_collected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_collected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_provided: Option<bool>,
    /// Connector kinds CONFIGURED but whose provider could not be constructed this run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<Vec<String>>,
}

fn truthy(b: Option<bool>) -> bool {
    b == Some(true)
}

fn nonempty(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

impl ConnectorFlags {
    fn has_cloud_logs(&self) -> bool {
        self.cloud_logs.as_ref().is_some_and(|c| !c.is_empty())
    }
}

/// The ONE definition of "this environment has a runtime connector" — shared by the
/// gap consolidation and the engine's next-step routing.
pub fn has_any_runtime_connector(c: &ConnectorFlags) -> bool {
    truthy(c.elasticsearch)
        || truthy(c.sentry)
        || truthy(c.lens)
        || truthy(c.axiom)
        || truthy(c.grafana)
        || truthy(c.prometheus)
        || truthy(c.additional_state)
        || c.has_cloud_logs()
        || truthy(c.mongodb)
        || truthy(c.postgres)
        || truthy(c.redis)
        || truthy(c.queue)
        || truthy(c.shopify)
}

/// Is `kind` configured in the config but unavailable in this run (missing secret/env)?
fn is_unavailable(c: &ConnectorFlags, kind: &str) -> bool {
    c.unavailable.as_ref().is_some_and(|u| u.iter().any(|k| k == kind))
}

/// A single dimension of missing evidence and its investigation impact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceGap {
    pub dimension: String,
    pub why: String,
    pub next_source: String,
    /// How much this gap shaves off the confidence ceiling (0–1).
    pub confidence_impact: f64,
    /// HOR-386 — the REAL command that closes this gap; omitted when none exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_hint: Option<RouteStep>,
}

/// Structured output of the missing-evidence analysis.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GapAnalysis {
    pub gaps: Vec<EvidenceGap>,
    pub blind_spots: Vec<String>,
    /// `max(0.3, 1 − Σ confidenceImpact)`, rounded to 2 dp.
    pub confidence_ceiling: f64,
}

fn route(next_tool: &str, args: &str, reason: &str) -> RouteStep {
    RouteStep { next_tool: next_tool.into(), args: args.into(), reason: reason.into() }
}

static STATE_CONNECTOR_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(mongodb|postgres|redis|shopify|firestore|sqlserver):").unwrap());

/// Analyse `r` to find missing evidence dimensions and compute the confidence ceiling.
/// `mode == Some(Intent::SourceImpact)` suppresses runtime gaps and forces the ceiling to 1.
pub fn detect_missing_evidence(
    r: &InvestigationReport,
    connectors: Option<&ConnectorFlags>,
    mode: Option<Intent>,
) -> GapAnalysis {
    let default_flags = ConnectorFlags::default();
    let connectors = connectors.unwrap_or(&default_flags);
    let source_impact = mode == Some(Intent::SourceImpact);

    let has_kind = |k: EvidenceKind| r.evidence.iter().any(|e| e.kind == k);
    let has_log = has_kind(EvidenceKind::Log);
    let has_metric = has_kind(EvidenceKind::Metric);
    let has_queue_state = has_kind(EvidenceKind::QueueState);
    let has_commit = has_kind(EvidenceKind::Commit);
    let has_trace = r.evidence.iter().any(|e| e.links.trace_id.is_some());
    let has_queue_topology = !r.timeline.boundary_crossings.is_empty();
    let ownership_known = r
        .ownership
        .as_ref()
        .and_then(|o| o.as_ref())
        .is_some_and(|o| o.likely_maintainer.is_some());

    // HOR-386 — args for the colocated `routeHint` commands.
    let service = r.input.service.clone().unwrap_or_default();
    let seed_name = r.seeds.first().map(|s| s.name.clone()).unwrap_or_default();

    let mut gaps: Vec<EvidenceGap> = vec![];
    let mut blind_spots: Vec<String> = vec![];

    if !has_log && !source_impact {
        let log_source_unavailable = (truthy(connectors.elasticsearch) && is_unavailable(connectors, "elasticsearch"))
            || (truthy(connectors.sentry) && is_unavailable(connectors, "sentry"))
            || (truthy(connectors.axiom) && is_unavailable(connectors, "axiom"));
        let no_log_source = !truthy(connectors.elasticsearch) && !truthy(connectors.sentry) && !truthy(connectors.axiom);
        let (log_why, log_next_source): (String, String) = if connectors.has_cloud_logs() {
            let why = connectors
                .cloud_logs
                .as_ref()
                .unwrap()
                .iter()
                .map(|p| {
                    format!(
                        "{}: {}",
                        p.id,
                        if p.collected {
                            "no matching rows in the bounded window".to_string()
                        } else {
                            format!("collection failed ({})", p.failure_reason.as_deref().unwrap_or("unknown"))
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            (why, "Check the selected cloud account, resource scope and log window, then retry".into())
        } else if no_log_source {
            (
                "No Elasticsearch connector (nor Sentry / Axiom) configured for this environment — no runtime error evidence.".into(),
                "Add an `elasticsearch`, `sentry`, and/or `axiom` connector to the project/environment".into(),
            )
        } else if log_source_unavailable {
            let kinds: Vec<&str> = [
                ("elasticsearch", connectors.elasticsearch),
                ("sentry", connectors.sentry),
                ("axiom", connectors.axiom),
            ]
            .iter()
            .filter(|(k, flag)| truthy(*flag) && is_unavailable(connectors, k))
            .map(|(k, _)| *k)
            .collect();
            (
                format!(
                    "{} configured but unavailable in this run (missing credentials or URL) — no runtime error evidence.",
                    kinds.join(" / ")
                ),
                "Provide the connector credentials/URL (see `horus doctor`), then retry".into(),
            )
        } else if !truthy(connectors.elasticsearch) && truthy(connectors.sentry) {
            let detail = nonempty(&connectors.sentry_failure_reason).map(|r| format!(" ({r})")).unwrap_or_default();
            if truthy(connectors.sentry_collected) {
                (
                    "No open Sentry issues matched in the window — cannot confirm the actual error signatures.".into(),
                    "Widen the window (--since) or check the Sentry project for open issues".into(),
                )
            } else {
                (
                    format!("Sentry collection failed or timed out{detail} — cannot confirm the actual error signatures."),
                    "Check the Sentry auth token / project, then retry".into(),
                )
            }
        } else if !truthy(connectors.elasticsearch) && truthy(connectors.axiom) {
            let detail = nonempty(&connectors.axiom_failure_reason).map(|r| format!(" ({r})")).unwrap_or_default();
            if truthy(connectors.axiom_collected) {
                (
                    "No Axiom log rows matched in the window — cannot confirm the actual error signatures.".into(),
                    "Widen the window (--since) or check the Axiom dataset for matching rows".into(),
                )
            } else {
                (
                    format!("Axiom log collection failed or timed out{detail} — cannot confirm the actual error signatures."),
                    "Check the Axiom API token / dataset, then retry".into(),
                )
            }
        } else if let Some(compat) = nonempty(&connectors.logs_compatibility_error) {
            (
                format!("Elasticsearch field mapping is incompatible with the index — log collection was blocked. {compat}"),
                "Fix fields.* overrides in your connector config or choose the correct preset (meritt / ecs)".into(),
            )
        } else if !truthy(connectors.logs_collected) {
            let detail = nonempty(&connectors.logs_failure_reason).map(|r| format!(" ({r})")).unwrap_or_default();
            (
                format!("Log collection failed or timed out{detail} — cannot confirm the actual error signatures."),
                "Check Elasticsearch connectivity, then run `horus logs <service>` manually".into(),
            )
        } else {
            (
                "No error logs matched in the window — cannot confirm the actual error signatures.".into(),
                "Widen the window (--since) or inspect `horus logs <service>`".into(),
            )
        };
        let log_route_hint = if no_log_source && !connectors.has_cloud_logs() {
            route("connect", "elasticsearch", &log_next_source)
        } else if log_source_unavailable {
            route("doctor", "", &log_next_source)
        } else {
            route("logs", &service, &log_next_source)
        };
        gaps.push(EvidenceGap {
            dimension: "logs".into(),
            why: log_why,
            next_source: log_next_source,
            confidence_impact: 0.1,
            route_hint: Some(log_route_hint),
        });
        blind_spots.push("Cannot see the real error.".into());
    }

    // Only add a metrics gap when metrics are genuinely missing.
    let metrics_configured = truthy(connectors.grafana) || truthy(connectors.prometheus);
    if !has_metric && !(metrics_configured && truthy(connectors.metrics_collected)) && !source_impact {
        let failure_detail = nonempty(&connectors.metrics_failure_reason).map(|r| format!(" ({r})")).unwrap_or_default();
        let grafana_unavailable = metrics_configured
            && is_unavailable(connectors, if truthy(connectors.prometheus) { "prometheus" } else { "grafana" });
        let metrics_label = if truthy(connectors.prometheus) { "Prometheus" } else { "Grafana" };
        let metrics_why = if !metrics_configured {
            "No Grafana connector configured — cannot see latency/error-rate trends.".to_string()
        } else if grafana_unavailable {
            format!("{metrics_label} configured but unavailable in this run (missing credentials or URL) — cannot see latency/error-rate trends.")
        } else {
            format!("{metrics_label} metrics collection failed or timed out{failure_detail} — metric trends unavailable for this investigation.")
        };
        let metrics_next_source = if !metrics_configured {
            "Add a `grafana` connector to the environment".to_string()
        } else if grafana_unavailable {
            format!("Provide the {metrics_label} credentials/URL (see horus doctor), then retry")
        } else {
            format!("Check {metrics_label} connectivity, then run horus metrics manually")
        };
        let metrics_route_hint = if !metrics_configured {
            route("connect", "grafana", &metrics_next_source)
        } else if grafana_unavailable {
            route("doctor", "", &metrics_next_source)
        } else {
            route("metrics", &service, &metrics_next_source)
        };
        gaps.push(EvidenceGap {
            dimension: "metrics".into(),
            why: metrics_why,
            next_source: metrics_next_source,
            confidence_impact: 0.1,
            route_hint: Some(metrics_route_hint),
        });
        blind_spots.push("Cannot validate latency-based hypotheses.".into());
    }

    // A configured queue connector that threw is a real gap even without static topology.
    let queue_failed = connectors.queue == Some(true) && connectors.queue_collected == Some(false);
    if (has_queue_topology || queue_failed) && !has_queue_state && !source_impact {
        let queue_detail = nonempty(&connectors.queue_failure_reason).map(|r| format!(" ({r})")).unwrap_or_default();
        let queue_advice_live = "Run `horus queues --live` to see real-time queue depths and failed-job counts";
        let queue_advice_connect = if truthy(connectors.redis) {
            "Give a Redis DB the queues role (`horus connect redis --db <n>:queues`) to read live queue state"
        } else {
            "Add a `redis` connector with a queues-role DB to read live queue state"
        };
        let has_queue = truthy(connectors.queue);
        gaps.push(EvidenceGap {
            dimension: "queue runtime state".into(),
            why: if queue_failed {
                format!("Live queue state collection failed{queue_detail} — depth/failed/delayed counts unavailable.")
            } else if has_queue {
                "Queue topology is known but live depth + failed/delayed counts were not collected.".into()
            } else {
                "Queue topology is known but there is no queue-role Redis connector for live queue depth/failures.".into()
            },
            next_source: if has_queue { queue_advice_live.into() } else { queue_advice_connect.into() },
            confidence_impact: 0.1,
            route_hint: Some(if has_queue {
                route("queues", "--live", queue_advice_live)
            } else {
                route("connect", "redis", queue_advice_connect)
            }),
        });
        blind_spots.push("Cannot determine if the queue is actually backed up.".into());
    }

    // Failure-only application-state gap (HOR-33): strict `=== false` semantics.
    let has_state = r.evidence.iter().any(|e| matches!(e.kind, EvidenceKind::State | EvidenceKind::RedisKey));
    let shopify_failed = connectors.shopify == Some(true) && connectors.shopify_collected == Some(false);
    let state_failed = connectors.state_collected == Some(false) || shopify_failed;
    if !has_state && state_failed && !source_impact {
        let mut state_reasons: Vec<String> = vec![];
        if let Some(r) = nonempty(&connectors.state_failure_reason) {
            state_reasons.push(r.to_string());
        }
        if shopify_failed {
            state_reasons.push(format!(
                "shopify: {}",
                connectors.shopify_failure_reason.as_deref().unwrap_or("request failed")
            ));
        }
        let state_detail =
            if state_reasons.is_empty() { String::new() } else { format!(" ({})", state_reasons.join("; ")) };
        let state_next_source = "Check the failing state connector auth/connectivity (horus connect <type>), then retry";
        let failed_connector = STATE_CONNECTOR_PREFIX
            .captures(state_reasons.first().map(String::as_str).unwrap_or(""))
            .and_then(|c| c.get(1))
            .map(|g| g.as_str())
            .unwrap_or("mongodb");
        gaps.push(EvidenceGap {
            dimension: "application state".into(),
            why: format!("State collection failed{state_detail} — cannot check for stuck/failed records behind the symptom."),
            next_source: state_next_source.into(),
            confidence_impact: 0.08,
            route_hint: Some(route("connect", failed_connector, state_next_source)),
        });
        blind_spots.push("Cannot check application state for stuck or failed records.".into());
    }

    if !has_commit && !source_impact {
        let since = truthy(connectors.since_provided);
        let next_source = if since {
            "Use HEAD~N or a specific SHA/branch for git diff ranges (e.g. --since HEAD~5)"
        } else {
            "Re-run with --since <ref>, or `horus what-changed <service>`"
        };
        gaps.push(EvidenceGap {
            dimension: "deployment records".into(),
            why: if since {
                "No git changes found in the specified range — the ref may not be diffable or no commits fall in this window.".into()
            } else {
                "No deployment/change data in scope — cannot tell what shipped before the incident.".into()
            },
            next_source: next_source.into(),
            confidence_impact: 0.08,
            route_hint: Some(route("what-changed", &service, next_source)),
        });
        blind_spots.push("Cannot correlate with a recent change.".into());
    }

    if !ownership_known {
        gaps.push(EvidenceGap {
            dimension: "ownership".into(),
            why: "The owning team/maintainer of the implicated component is unknown.".into(),
            next_source: "`horus owner <symbol>` (git history)".into(),
            confidence_impact: 0.05,
            route_hint: Some(route("owner", &seed_name, "`horus owner <symbol>` (git history)")),
        });
        blind_spots.push("Cannot route to an owner.".into());
    }

    if !has_trace && !source_impact {
        // HOR-410: only invoke the async queue boundary when the repo has queue topology.
        gaps.push(EvidenceGap {
            dimension: "traces".into(),
            why: if has_queue_topology {
                "No distributed traces — cannot follow a single request across the async queue boundary.".into()
            } else {
                "No distributed traces — cannot follow a single request across service boundaries.".into()
            },
            next_source: "Tracing instrumentation".into(),
            confidence_impact: 0.07,
            // No routeHint: there is no `tracing` connector.
            route_hint: None,
        });
        blind_spots.push("Cannot trace the request end-to-end.".into());
    }

    // Consolidate runtime gaps when the CONFIG has no runtime connectors.
    if !has_any_runtime_connector(connectors) && !source_impact {
        const RUNTIME_DIMS: [&str; 5] =
            ["logs", "metrics", "queue runtime state", "application state", "traces"];
        let is_runtime = |g: &EvidenceGap| RUNTIME_DIMS.contains(&g.dimension.as_str());
        let runtime_gaps: Vec<&EvidenceGap> = gaps.iter().filter(|g| is_runtime(g)).collect();
        if !runtime_gaps.is_empty() {
            let impact =
                js::math_round(runtime_gaps.iter().fold(0.0, |a, g| a + g.confidence_impact) * 100.0) / 100.0;
            let kept: Vec<EvidenceGap> = gaps.iter().filter(|g| !is_runtime(g)).cloned().collect();
            gaps = vec![EvidenceGap {
                dimension: "runtime evidence".into(),
                why: "No runtime connectors in this config — the investigation proceeds on source, topology, git, ownership, and blast-radius evidence.".into(),
                next_source: "None — the run used the full evidence this config provides (runtime connectors would raise the confidence ceiling)".into(),
                confidence_impact: impact,
                // Deliberately NO routeHint: the router must never lead with connector setup.
                route_hint: None,
            }];
            gaps.extend(kept);
            const RUNTIME_BLIND_SPOTS: [&str; 5] = [
                "Cannot see the real error.",
                "Cannot see latency/error-rate trends.",
                "Cannot see queue backlogs or failed jobs.",
                "Cannot check for stuck/failed records behind the symptom.",
                "Cannot trace the request end-to-end.",
            ];
            let kept_blind: Vec<String> =
                blind_spots.iter().filter(|b| !RUNTIME_BLIND_SPOTS.contains(&b.as_str())).cloned().collect();
            blind_spots = vec!["No runtime visibility (no connectors configured).".into()];
            blind_spots.extend(kept_blind);
        }
    }

    let mut total_impact = 0.0;
    for gap in &gaps {
        total_impact += gap.confidence_impact;
    }
    // HOR-385: a structural source-impact answer is complete — runtime gaps don't cap it.
    let raw = if source_impact { 1.0 } else { 1.0 - total_impact };
    let confidence_ceiling = js::math_round(raw.max(0.3) * 100.0) / 100.0;

    GapAnalysis { gaps, blind_spots, confidence_ceiling }
}

/// Gap `nextSource` hints as next-action strings, sorted by confidence impact
/// (highest first); the consolidated "runtime evidence" gap trails everything.
pub fn gap_next_actions(gaps: &[EvidenceGap]) -> Vec<String> {
    let mut sorted: Vec<&EvidenceGap> = gaps.iter().collect();
    sorted.sort_by(|a, b| {
        let at = (a.dimension == "runtime evidence") as i32;
        let bt = (b.dimension == "runtime evidence") as i32;
        at.cmp(&bt).then_with(|| js::cmp_f64(b.confidence_impact, a.confidence_impact))
    });
    sorted.iter().map(|g| g.next_source.clone()).collect()
}

/// HOR-386 — structured sibling of `gap_next_actions`: each gap's `routeHint`, sorted by
/// confidence impact; gaps without a real remedy are dropped.
pub fn gap_next_steps(gaps: &[EvidenceGap]) -> Vec<RouteStep> {
    let mut sorted: Vec<&EvidenceGap> = gaps.iter().collect();
    sorted.sort_by(|a, b| js::cmp_f64(b.confidence_impact, a.confidence_impact));
    sorted.iter().filter_map(|g| g.route_hint.clone()).collect()
}
