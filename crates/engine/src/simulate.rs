//! HOR-31 — Incident simulation + training mode: a fixed catalogue of synthetic scenarios
//! so engineers can practice investigations on pre-canned inputs. Deterministic and pure.

use crate::types::InvestigationReport;
use horus_core::EvidenceKind;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpectedSignal {
    pub key: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scenario {
    pub id: String,
    pub title: String,
    pub category: String,
    pub symptom: String,
    pub hint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    pub expected_signals: Vec<ExpectedSignal>,
    pub coaching_tips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalCheck {
    pub label: String,
    pub ok: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioEvaluation {
    pub checks: Vec<SignalCheck>,
    pub passed: i64,
    pub total: i64,
}

fn sig(key: &str, label: &str) -> ExpectedSignal {
    ExpectedSignal { key: key.into(), label: label.into() }
}

fn scenario(id: &str, title: &str, category: &str, symptom: &str, hint: &str, since: Option<&str>, signals: Vec<ExpectedSignal>, tips: &[&str]) -> Scenario {
    Scenario {
        id: id.into(),
        title: title.into(),
        category: category.into(),
        symptom: symptom.into(),
        hint: hint.into(),
        since: since.map(String::from),
        expected_signals: signals,
        coaching_tips: tips.iter().map(|t| t.to_string()).collect(),
    }
}

pub static SCENARIOS: LazyLock<Vec<Scenario>> = LazyLock::new(|| {
    vec![
        scenario(
            "queue-backlog",
            "Queue backlog",
            "queue",
            "Zoho CRM records update minutes late and on-call suspects the worker cannot keep up with the queue.",
            "zoho realtime sync delays",
            None,
            vec![
                sig("seed", "Seed symbols resolved"),
                sig("queue-boundary", "Queue boundary crossing detected"),
                sig("hyp:queue-backlog", "queue-backlog hypothesis present"),
                sig("hyp:worker-slowdown", "worker-slowdown hypothesis present"),
                sig("gaps", "Evidence gaps identified"),
                sig("actions", "Next actions generated"),
            ],
            &[
                "Check BullMQ depth and failed/delayed counts for the zoho-sync queues.",
                "Compare producer enqueue rate vs worker drain rate to determine if the worker is keeping up.",
            ],
        ),
        scenario(
            "external-api-outage",
            "External API outage",
            "integration",
            "Zoho API calls are timing out and returning 5xx and downstream sync is failing.",
            "zoho api client request",
            None,
            vec![
                sig("seed", "Seed symbols resolved"),
                sig("hyp:external-api-latency", "external-api-latency hypothesis present"),
                sig("gaps", "Evidence gaps identified"),
                sig("actions", "Next actions generated"),
            ],
            &[
                "Pull request latency and error-rate metrics for the Zoho client.",
                "Check whether retries are amplifying load on the already-failing Zoho API.",
            ],
        ),
        scenario(
            "deployment-regression",
            "Deployment regression",
            "change",
            "Errors spiked shortly after the most recent deploy of the sync service.",
            "zoho sync processing",
            Some("HEAD~10"),
            vec![
                sig("seed", "Seed symbols resolved"),
                sig("commit", "Recent change evidence found"),
                sig("hyp:deployment-regression", "deployment-regression hypothesis present"),
                sig("actions", "Next actions generated"),
            ],
            &[
                "Run horus what-changed zoho to see what shipped in the last deploy.",
                "A change is evidence, not a conclusion — correlate the diff with the error spike timing.",
            ],
        ),
        scenario(
            "database-slowdown",
            "Database slowdown",
            "infra",
            "Everything touching the database is slow and queries are backing up.",
            "prisma service",
            None,
            vec![
                sig("seed", "Seed symbols resolved"),
                sig("hyp:infrastructure", "infrastructure hypothesis present"),
                sig("gaps", "Evidence gaps identified"),
            ],
            &[
                "Check DB pool saturation and slow-query logs for Prisma connections.",
                "Infrastructure issues propagate widely — look for correlated slowdowns across multiple services.",
            ],
        ),
        scenario(
            "cache-failure",
            "Cache failure",
            "infra",
            "Redis cache misses are hammering the source of truth and latency is climbing.",
            "redis cache",
            None,
            vec![
                sig("seed", "Seed symbols resolved"),
                sig("hyp:infrastructure", "infrastructure hypothesis present"),
                sig("gaps", "Evidence gaps identified"),
            ],
            &[
                "Check Redis hit/miss ratio and eviction rates.",
                "A cold cache becomes a database slowdown — check whether DB query volume spiked in tandem.",
            ],
        ),
    ]
});

/// Look up a scenario by id. `None` when not found so callers can branch cleanly.
pub fn get_scenario(id: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|s| s.id == id)
}

/// Compare a live InvestigationReport against the expected signals for a scenario.
///
/// Key mapping: seed → seeds non-empty; queue-boundary → boundaryCrossings non-empty;
/// gaps → gapAnalysis.gaps non-empty; actions → nextActions non-empty; commit → any
/// commit evidence; hyp:<category> → any hypothesis of that category; unknown → false.
pub fn evaluate_scenario(scenario: &Scenario, report: &InvestigationReport) -> ScenarioEvaluation {
    let checks: Vec<SignalCheck> = scenario
        .expected_signals
        .iter()
        .map(|signal| {
            let ok = match signal.key.as_str() {
                "seed" => !report.seeds.is_empty(),
                "queue-boundary" => !report.timeline.boundary_crossings.is_empty(),
                "gaps" => !report.gap_analysis.gaps.is_empty(),
                "actions" => !report.next_actions.is_empty(),
                "commit" => report.evidence.iter().any(|e| e.kind == EvidenceKind::Commit),
                k if k.starts_with("hyp:") => {
                    let category = &k[4..];
                    report.hypotheses.iter().any(|h| h.category == category)
                }
                _ => false,
            };
            SignalCheck { label: signal.label.clone(), ok }
        })
        .collect();
    let passed = checks.iter().filter(|c| c.ok).count() as i64;
    ScenarioEvaluation { total: checks.len() as i64, checks, passed }
}
