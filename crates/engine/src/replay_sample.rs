//! HOR-110 — Canonical v0.1 replay sample fixture: payment-gateway timeouts after a timeout
//! value increase deploy. Source-only (no runtime connectors configured). Synthetic.

use crate::types::InvestigationReport;
use serde_json::json;
use std::sync::LazyLock;

/// Minimal v0.1 investigation packet — the shape Horus writes to `investigations.report` at v0.1.
pub static V01_REPLAY_SAMPLE: LazyLock<InvestigationReport> = LazyLock::new(|| {
    serde_json::from_value(json!({
        "id": "replay-sample-v01",
        "input": { "hint": "payment-gateway timeouts after deploy", "service": "checkout-api", "since": "2026-06-01" },
        "summary": "Structural evidence points to a gateway timeout value increase in checkout-api deployed on 2026-06-01. No runtime log evidence is available — Elasticsearch is not configured.",
        "seeds": [
            { "id": "sym-gw-001", "name": "GatewayClient", "filePath": "src/gateway/client.ts", "startLine": 12, "signature": "class GatewayClient" }
        ],
        "evidence": [
            {
                "id": "ev-commit-001",
                "source": "history",
                "kind": "commit",
                "title": "Increase gateway timeout from 3 s to 30 s",
                "relevance": 0.85,
                "payload": { "sha": "abc1234", "author": "dev@example.com", "message": "Increase gateway timeout from 3 s to 30 s" },
                "links": {},
                "provenance": { "query": "git log src/gateway/client.ts", "collectedAt": "2026-06-01T10:00:00Z" }
            },
            {
                "id": "ev-symbol-001",
                "source": "code",
                "kind": "symbol",
                "title": "GatewayClient — wraps all payment gateway HTTP calls",
                "relevance": 0.9,
                "payload": {},
                "links": { "symbolId": "sym-gw-001" },
                "provenance": { "query": "GatewayClient", "collectedAt": "2026-06-01T10:00:00Z" }
            }
        ],
        "timeline": { "events": [], "boundaryCrossings": [] },
        "correlation": { "groups": [], "chains": [], "missing": [] },
        "findings": [
            {
                "kind": "correlation",
                "title": "Timeout increase in GatewayClient correlates with service slowdown",
                "confidence": 0.72,
                "evidenceIds": ["ev-commit-001", "ev-symbol-001"]
            }
        ],
        "suspectedCauses": [
            {
                "id": "cause-001",
                "title": "Gateway timeout increase caused cascading payment delays",
                "category": "configuration",
                "sourceEvidenceIds": ["ev-commit-001"],
                "affectedNodeIds": [],
                "baseScore": 0.65,
                "finalScore": 0.72,
                "confidence": 0.72,
                "band": "likely",
                "explanations": []
            }
        ],
        "hypotheses": [],
        "similarIncidents": [],
        "gapAnalysis": {
            "gaps": [
                {
                    "dimension": "logs",
                    "why": "No Elasticsearch connector configured — cannot see actual gateway error responses.",
                    "nextSource": "Add an `elasticsearch` connector to the project/environment",
                    "confidenceImpact": 0.1
                }
            ],
            "blindSpots": ["Cannot see the real gateway error responses."],
            "confidenceCeiling": 0.9
        },
        "graph": { "nodes": [], "edges": [] },
        "confidence": 0.62,
        "nextActions": [
            "Diff recent commits touching src/gateway/client.ts",
            "Add an `elasticsearch` connector to the project/environment"
        ]
    }))
    .expect("V01_REPLAY_SAMPLE must deserialize into InvestigationReport")
});
