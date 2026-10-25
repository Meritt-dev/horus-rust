//! Public types for the deterministic investigation pipeline (HOR-5).
//! Field order mirrors the TS object construction in `engine.ts` so the
//! persisted JSON serializes with identical key order.

use horus_core::{Evidence, EvidenceKind, EvidenceSubject, ProviderKind, ShopifyQuerySpec, Symbol};
use serde::{Deserialize, Serialize};

use crate::cause_chain::CauseChain;
use crate::correlate::CorrelationResult;
use crate::gaps::GapAnalysis;
use crate::graph::InvestigationGraph;
use crate::score_cause::CauseCandidate;
use crate::timeline::Timeline;
use crate::validate::ValidatedHypothesis;

// ── Types owned by other crates / modules (re-exported for the report shape) ──

pub use horus_connectors::duration::{DimensionSpec, DurationDimensionOptions};
pub use horus_connectors::git::provider::{GitCommit, RepoFileChange, RepoState};

pub use crate::changes::ChangeImpactReport;
pub use crate::git_collector::BoundedGitChange;
pub use crate::memory::SimilarIncident;
pub use crate::memory_recall::{IncidentContext, StartupIncident};
pub use crate::ownership::OwnershipEstimate;
pub use crate::source_status::RuntimeSourceReport;

// ── Name helpers (needs upstreaming to horus-core) ───────────────────────────

/// The serialized name of a `ProviderKind` (`'code' | 'logs' | …`).
pub fn provider_kind_name(k: ProviderKind) -> &'static str {
    match k {
        ProviderKind::Code => "code",
        ProviderKind::Logs => "logs",
        ProviderKind::Metrics => "metrics",
        ProviderKind::State => "state",
        ProviderKind::Queue => "queue",
        ProviderKind::History => "history",
    }
}

/// The serialized name of an `EvidenceKind` (`'log' | 'queue-edge' | …`).
pub fn evidence_kind_name(k: EvidenceKind) -> &'static str {
    match k {
        EvidenceKind::Log => "log",
        EvidenceKind::Metric => "metric",
        EvidenceKind::Symbol => "symbol",
        EvidenceKind::Flow => "flow",
        EvidenceKind::Commit => "commit",
        EvidenceKind::QueueState => "queue-state",
        EvidenceKind::QueueEdge => "queue-edge",
        EvidenceKind::RedisKey => "redis-key",
        EvidenceKind::State => "state",
        EvidenceKind::Impact => "impact",
    }
}

// ── Investigation input ──────────────────────────────────────────────────────

/// The user-supplied incident hint plus optional scoping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationInput {
    /// Durable job identity; interactive callers may omit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incident: Option<IncidentContext>,
    /// Free-text hint naming a symbol, file, or behaviour to investigate.
    pub hint: String,
    /// Calling agent session (Claude Code `CLAUDE_CODE_SESSION_ID`, or `HORUS_AGENT_SESSION`), recorded
    /// so recall can later be measured against real session continuity. Context only; never scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Optional git ref or range (e.g. `v1.2.0` or `abc123..HEAD`) to bound history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Optional runtime-log window as a duration (e.g. `30d`), independent of `since`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs_since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Optional path scope — resolve the seed only from symbols under this directory (HOR-356).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// HOR-435: how to break a duration anomaly down by an INFO-level dimension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_dimension: Option<DurationDimensionOptions>,
    /// Shopify Admin GraphQL queries to run as evidence for THIS investigation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shopify_queries: Option<Vec<ShopifyQuerySpec>>,
}

impl InvestigationInput {
    pub fn new(hint: impl Into<String>) -> Self {
        Self {
            report_id: None,
            incident: None,
            hint: hint.into(),
            agent_session: None,
            repo: None,
            since: None,
            logs_since: None,
            service: None,
            environment: None,
            scope: None,
            duration_dimension: None,
            shopify_queries: None,
        }
    }
}

/// HOR-386 — a single deterministic next-step suggestion produced by the shared router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteStep {
    /// The next command/tool to run, e.g. `blast-radius`, `connect`, `index`, `search`.
    pub next_tool: String,
    /// Arguments to pass; may be empty.
    pub args: String,
    /// Why this step is suggested — templated, never LLM prose.
    pub reason: String,
}

/// Coarse classification of a deterministic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingKind {
    Observation,
    Anomaly,
    Correlation,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::Observation => "observation",
            FindingKind::Anomaly => "anomaly",
            FindingKind::Correlation => "correlation",
        }
    }
}

/// A deterministic, evidence-backed finding asserted by the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportFinding {
    pub kind: FindingKind,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// 0–1 confidence in the assertion.
    pub confidence: f64,
    /// Ids of the Evidence rows this finding draws from.
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Diagnosis {
    Supported,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FixPrStatus {
    Open,
    Closed,
    Merged,
    Skipped,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixPr {
    pub status: FixPrStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnattendedStatus {
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Unattended {
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub status: UnattendedStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_only: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecallTraceEntry {
    pub memory_id: String,
    pub check: String,
    pub stage: String,
    pub evidence_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// HOR-385: the deterministic structural intent the engine classified the hint as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Intent {
    Incident,
    SourceImpact,
    Explain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Degraded {
    pub source_intelligence: bool,
    pub reason: String,
}

/// The full investigation report — also the persisted shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_recall: Option<Vec<StartupIncident>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recall_trace: Option<Vec<RecallTraceEntry>>,
    pub id: String,
    pub input: InvestigationInput,
    /// The entity under investigation — absent when neither service nor environment is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<EvidenceSubject>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<Intent>,
    /// Symbols that the hint resolved to.
    pub seeds: Vec<Symbol>,
    pub evidence: Vec<Evidence>,
    pub timeline: Timeline,
    pub correlation: CorrelationResult,
    pub findings: Vec<ReportFinding>,
    /// Ranked cause candidates produced by the Cause Scoring Engine (HOR-15).
    pub suspected_causes: Vec<CauseCandidate>,
    pub hypotheses: Vec<ValidatedHypothesis>,
    /// Similar past incidents recalled from institutional memory (context only).
    pub similar_incidents: Vec<SimilarIncident>,
    /// Structured analysis of what evidence is absent and its confidence impact (HOR-19).
    pub gap_analysis: GapAnalysis,
    pub graph: InvestigationGraph,
    /// 0–1 overall confidence in the investigation.
    pub confidence: f64,
    pub next_actions: Vec<String>,
    /// Null when repoPath is not supplied; absent on the empty-seed path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership: Option<Option<OwnershipEstimate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause_chains: Option<Vec<CauseChain>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_changes: Option<BoundedGitChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavioral: Option<BehavioralWalkthrough>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<Degraded>,
    // Assigned after construction in engine.ts (JS appends keys in assignment order).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_steps: Option<Vec<RouteStep>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_status: Option<RuntimeSourceReport>,
    // persist() stamps `createdAt` before the engine assigns `persisted`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_capture_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_judgment: Option<StoredAIJudgment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnosis: Option<Diagnosis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub followup_rounds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_pr: Option<FixPr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unattended: Option<Unattended>,
}

/// A "how does X work" behavioral walkthrough.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralWalkthrough {
    pub question: String,
    /// Always serialized (`null` when absent).
    pub entry: Option<Symbol>,
    pub steps: Vec<Symbol>,
    pub external_calls: Vec<String>,
    pub persistence: Vec<String>,
    pub narrative: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AICitation {
    pub evidence_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HypothesisJudgment {
    pub hypothesis_id: String,
    pub category: String,
    /// `'supported' | 'weakened' | 'eliminated' | 'unconfirmed'`
    pub verdict: String,
    pub rationale: String,
    pub cited_evidence_ids: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootCauseAssessment {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_hypothesis_id: Option<String>,
    pub cited_evidence_ids: Vec<String>,
    /// `'low' | 'medium' | 'high'`
    pub uncertainty: String,
}

/// AI judgment persisted as part of the investigation report (HOR-198).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAIJudgment {
    pub what: String,
    pub why: String,
    pub where_next: Vec<String>,
    pub citations: Vec<AICitation>,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentioned_services: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypothesis_judgments: Option<Vec<HypothesisJudgment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_cause_assessment: Option<RootCauseAssessment>,
    /// AI provider name (e.g. 'anthropic') or 'deterministic' for fallback.
    pub provider: String,
    /// ISO 8601 timestamp when the judgment was generated.
    pub generated_at: String,
}
