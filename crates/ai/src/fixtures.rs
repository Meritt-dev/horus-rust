//! HOR-60 — Reusable narrative fixtures.
//!
//! Pre-built NarrativeInput / NarrativeOutput values used by the fake provider and
//! the CLI's non-network paths. All fixtures are offline and deterministic.

use std::sync::LazyLock;

use crate::contract::{
    AIHypothesisJudgment, AIRootCauseAssessment, HypothesisVerdict, NarrativeCauseItem, NarrativeCitation,
    NarrativeEvidenceItem, NarrativeFinding, NarrativeHypothesisItem, NarrativeInput, NarrativeOutput, Uncertainty,
};

fn s(v: &str) -> String {
    v.to_string()
}

fn ids(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn cite(evidence_id: &str, rationale: Option<&str>) -> NarrativeCitation {
    NarrativeCitation { evidence_id: s(evidence_id), rationale: rationale.map(s) }
}

/// Bare output with only the fields every fixture sets; callers fill the optional ones.
fn base_output(what: &str, why: &str, where_next: &[&str], citations: Vec<NarrativeCitation>, confidence: f64) -> NarrativeOutput {
    NarrativeOutput {
        what: s(what),
        why: s(why),
        where_next: ids(where_next),
        citations,
        confidence,
        mentioned_services: None,
        hypothesis_judgments: None,
        root_cause_assessment: None,
        degraded: None,
    }
}

// ---------------------------------------------------------------------------
// Shared input packet — referenced by all output fixtures below
// ---------------------------------------------------------------------------

/// Base investigation input used by all output fixtures in this file.
pub static FIXTURE_INPUT: LazyLock<NarrativeInput> = LazyLock::new(|| NarrativeInput {
    investigation_id: s("inv-fixture-001"),
    hint: s("job queue backed up after deploy"),
    report_confidence: 0.72,
    evidence: vec![
        NarrativeEvidenceItem {
            id: s("ev-log-001"),
            kind: s("log"),
            title: s("BullMQ worker stalled: job exceeded lockDuration"),
            service: Some(s("leadcall-api")),
            excerpt: Some(s("Job id=42 stalled after 30000ms")),
        },
        NarrativeEvidenceItem {
            id: s("ev-metric-001"),
            kind: s("metric"),
            title: s("Queue depth spiked to 1 200 jobs"),
            service: Some(s("leadcall-api")),
            excerpt: None,
        },
        NarrativeEvidenceItem {
            id: s("ev-commit-001"),
            kind: s("commit"),
            title: s("Increase worker concurrency from 2 to 10"),
            service: None,
            excerpt: None,
        },
    ],
    known_services: ids(&["leadcall-api", "zoho-sync"]),
    suspected_causes: vec![NarrativeCauseItem {
        label: s("Redis connection pool exhausted under high concurrency"),
        score: 0.81,
        evidence_ids: ids(&["ev-log-001", "ev-commit-001"]),
    }],
    deterministic_summary: s(
        "BullMQ workers stalled in leadcall-api after a concurrency increase caused Redis pool exhaustion.",
    ),
    findings: vec![
        NarrativeFinding { title: s("Concurrency bump correlates with stall onset"), evidence_ids: ids(&["ev-commit-001"]) },
        NarrativeFinding { title: s("Queue depth spike follows stall events"), evidence_ids: ids(&["ev-metric-001"]) },
    ],
    hypotheses: Some(vec![
        NarrativeHypothesisItem {
            id: s("hyp-worker-slowdown"),
            category: s("worker-slowdown"),
            statement: s("Workers consuming the default queue stalled or processing slowly."),
            deterministic_verdict: HypothesisVerdict::Supported,
            deterministic_confidence: 0.68,
            supporting_evidence_ids: ids(&["ev-log-001", "ev-metric-001"]),
        },
        NarrativeHypothesisItem {
            id: s("hyp-deployment-regression"),
            category: s("deployment-regression"),
            statement: s("A recent deployment changed worker concurrency configuration."),
            deterministic_verdict: HypothesisVerdict::Weakened,
            deterministic_confidence: 0.45,
            supporting_evidence_ids: ids(&["ev-commit-001"]),
        },
    ]),
});

// ---------------------------------------------------------------------------
// Fixture 1: Valid narrative output
// ---------------------------------------------------------------------------

/// A fully valid NarrativeOutput for FIXTURE_INPUT.
/// All citation IDs exist in the input, confidence is below the ceiling,
/// and all required sections are populated, including structured hypothesis judgments (HOR-197).
/// validate_narrative(&FIXTURE_VALID_OUTPUT, &FIXTURE_INPUT) must return valid.
pub static FIXTURE_VALID_OUTPUT: LazyLock<NarrativeOutput> = LazyLock::new(|| {
    let mut out = base_output(
        "BullMQ job workers began stalling across the leadcall-api service shortly after a concurrency increase was deployed.",
        "Raising worker concurrency from 2 to 10 saturated the Redis connection pool. Each stalled worker held an open connection and never released it, causing subsequent workers to time out waiting for a free slot.",
        &[
            "Roll back worker concurrency to 2 and confirm stall rate drops",
            "Increase Redis max connection pool size before re-raising concurrency",
            "Add a BullMQ stall-rate alert so the next concurrency change is caught early",
        ],
        vec![
            cite("ev-log-001", Some("Direct evidence of stall event")),
            cite("ev-commit-001", Some("Config change that triggered the issue")),
            cite("ev-metric-001", Some("Confirms downstream queue depth impact")),
        ],
        0.68,
    );
    out.mentioned_services = Some(ids(&["leadcall-api"]));
    out.hypothesis_judgments = Some(vec![
        AIHypothesisJudgment {
            hypothesis_id: s("hyp-worker-slowdown"),
            category: s("worker-slowdown"),
            verdict: HypothesisVerdict::Supported,
            rationale: s("The stall logs (ev-log-001) directly confirm workers exceeded lockDuration, and the queue depth spike (ev-metric-001) is consistent with a slowdown. The deterministic verdict of supported is well-grounded."),
            cited_evidence_ids: ids(&["ev-log-001", "ev-metric-001"]),
            confidence: 0.65,
        },
        AIHypothesisJudgment {
            hypothesis_id: s("hyp-deployment-regression"),
            category: s("deployment-regression"),
            verdict: HypothesisVerdict::Supported,
            rationale: s("The commit (ev-commit-001) directly changed concurrency settings and the timing aligns with the stall onset. I upgrade this from weakened to supported given the direct causal link."),
            cited_evidence_ids: ids(&["ev-commit-001"]),
            confidence: 0.60,
        },
    ]);
    out.root_cause_assessment = Some(AIRootCauseAssessment {
        summary: s("The concurrency increase (ev-commit-001) caused Redis connection pool exhaustion, leading to BullMQ worker stalls (ev-log-001) and a queue depth spike (ev-metric-001). The deployment change is the root cause; the worker slowdown is the mechanism."),
        primary_hypothesis_id: Some(s("hyp-worker-slowdown")),
        cited_evidence_ids: ids(&["ev-commit-001", "ev-log-001", "ev-metric-001"]),
        uncertainty: Uncertainty::Low,
    });
    out
});

// ---------------------------------------------------------------------------
// Fixture 2: Unknown-evidence citation (hallucinated citation)
// ---------------------------------------------------------------------------

/// A NarrativeOutput that cites an evidence ID not present in FIXTURE_INPUT.
/// Validation must fail with an error containing 'hallucinated citation'.
pub static FIXTURE_UNKNOWN_CITATION: LazyLock<NarrativeOutput> = LazyLock::new(|| {
    base_output(
        "Workers stalled after the deploy.",
        "Redis pool was exhausted.",
        &["Roll back the concurrency change"],
        vec![cite("ev-log-001", None), cite("ev-DOES-NOT-EXIST", Some("Invented evidence ID"))],
        0.60,
    )
});

// ---------------------------------------------------------------------------
// Fixture 3: Confidence inflation
// ---------------------------------------------------------------------------

/// A NarrativeOutput whose confidence exceeds the FIXTURE_INPUT ceiling (0.72).
/// Validation must fail with an error containing 'confidence'.
pub static FIXTURE_CONFIDENCE_INFLATION: LazyLock<NarrativeOutput> = LazyLock::new(|| {
    base_output(
        "Workers stalled after the deploy.",
        "Redis pool was exhausted by the concurrency increase.",
        &["Reduce worker concurrency"],
        vec![cite("ev-commit-001", None)],
        0.95,
    )
});

// ---------------------------------------------------------------------------
// Fixture 4: Hallucinated service
// ---------------------------------------------------------------------------

/// A NarrativeOutput that declares a service not present in FIXTURE_INPUT.knownServices.
/// Validation must fail with an error containing 'hallucination'.
pub static FIXTURE_HALLUCINATED_SERVICE: LazyLock<NarrativeOutput> = LazyLock::new(|| {
    let mut out = base_output(
        "Workers stalled after the deploy.",
        "Redis pool was exhausted.",
        &["Reduce worker concurrency"],
        vec![cite("ev-log-001", None)],
        0.60,
    );
    out.mentioned_services = Some(ids(&["leadcall-api", "invented-service-xyz"]));
    out
});
