//! Thin client for the Horus Cloud `/v1` API (HOR-236). Port of
//! `packages/cli/src/lib/cloud/api.ts`. The CLI talks to the cloud ONLY through this contract —
//! it never holds DB credentials (HOR-221).
//!
//! Request bodies serialize through `horus_core::json` (JS number semantics). Bodies the callers
//! assemble dynamically (memory sync requests, alert payloads) are `serde_json::Value`.

use std::fmt;
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const DEFAULT_API_BASE_URL: &str = "https://api.horus.sh";
/// Snapshot uploads and responses can each contain several megabytes.
const KNOWLEDGE_TRANSFER_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_TIMEOUT_MS: u64 = 15_000;

/// Cloud writes and telemetry are on, as in TS. `HORUS_RUST_CLOUD_WRITE=0` turns them off (e.g. while
/// benchmarking beside the TS CLI against the same workspace and telemetry spool).
pub fn cloud_writes_enabled() -> bool {
    std::env::var("HORUS_RUST_CLOUD_WRITE").as_deref() != Ok("0")
}

/// TS `CloudError` (HTTP failure with the API's error envelope) and `CloudOfflineError`
/// (network/connection failure). `Other` covers a 2xx body that isn't valid JSON / the expected
/// shape (TS throws the raw `SyntaxError` there).
#[derive(Debug)]
pub enum CloudError {
    Http { status: u16, code: String, message: String, retry_after_ms: Option<u64> },
    Offline(String),
    Other(String),
}

impl CloudError {
    /// HTTP status for a `CloudError` (None for offline/other).
    pub fn status(&self) -> Option<u16> {
        match self {
            CloudError::Http { status, .. } => Some(*status),
            _ => None,
        }
    }
    pub fn is_offline(&self) -> bool {
        matches!(self, CloudError::Offline(_))
    }
    /// True for the TS `err instanceof CloudError || err instanceof CloudOfflineError`.
    pub fn is_cloud(&self) -> bool {
        !matches!(self, CloudError::Other(_))
    }
}

impl fmt::Display for CloudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudError::Http { message, .. } => f.write_str(message),
            CloudError::Offline(m) | CloudError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CloudError {}

/// `CloudError` status of an anyhow error, when it is one.
pub fn cloud_status(err: &anyhow::Error) -> Option<u16> {
    err.downcast_ref::<CloudError>().and_then(CloudError::status)
}

// ── Response / request shapes ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserRef {
    pub id: String,
    pub primary_email: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub organization_id: String,
    pub role: String,
    pub workspace_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub user: UserRef,
    pub memberships: Vec<Membership>,
}

/// Response from POST /v1/cli-sessions/start (device-login init).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliSessionStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: f64,
    pub interval: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PollAccount {
    pub user_id: String,
    pub email: String,
}

/// Response from POST /v1/cli-sessions/poll. `token` is present only once, on approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliSessionPoll {
    /// `pending` | `slow_down` | `approved` | `denied` | `expired`.
    pub status: String,
    #[serde(default)]
    pub interval: Option<f64>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub account: Option<PollAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextOrganization {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextWorkspace {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub organization_id: String,
}

/// A project IS the repository/codebase (HOR-280); repo/sync metadata is optional so the CLI
/// degrades gracefully against an older cloud build (HOR-277).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextProject {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub workspace_id: String,
    pub organization_id: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub remote_url: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub last_seen_commit: Option<String>,
    #[serde(default)]
    pub last_synced_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextResponse {
    pub user: UserRef,
    pub organizations: Vec<ContextOrganization>,
    pub workspaces: Vec<ContextWorkspace>,
    pub projects: Vec<ContextProject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSummary {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenList {
    pub tokens: Vec<TokenSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationRecord {
    pub id: String,
    pub project_id: String,
    pub workspace_id: String,
    pub organization_id: String,
    pub title: String,
    pub hint: Option<String>,
    pub status: String,
    pub idempotency_key: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationDetail {
    #[serde(flatten)]
    pub record: InvestigationRecord,
    #[serde(default)]
    pub repository_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationList {
    pub investigations: Vec<InvestigationRecord>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// The human outcome label that rides the tenant-scoped investigation sync (HOR-390 → cloud).
/// FROZEN CONTRACT; absent when the local eval store carries no label.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationOutcome {
    /// `yes` | `partly` | `no`.
    pub resolved: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_cause: Option<String>,
    /// `feedback` | `confirm`.
    pub source: String,
    /// ISO-8601 attestation time of the label.
    pub labeled_at: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvestigationBody {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<InvestigationOutcome>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInvestigationBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRecord {
    pub id: String,
    pub investigation_id: String,
    pub project_id: String,
    pub organization_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub source: String,
    pub title: String,
    pub content: String,
    pub content_format: String,
    #[serde(default)]
    pub payload: Value,
    pub idempotency_key: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEvidenceBody {
    #[serde(rename = "type")]
    pub kind: String,
    pub source: String,
    pub title: String,
    pub content: String,
    pub content_format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// The cloud `AgentRun` schema carries `startedAt`, not `createdAt`/`repositoryId`, and a nullable
/// `projectId`. TS types these fields but never reads them (only `id`), so every field but `id`
/// tolerates absence or null here; requiring them failed each upload with "missing field `createdAt`".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AgentRunRecord {
    pub id: String,
    pub investigation_id: String,
    pub project_id: Option<String>,
    pub organization_id: String,
    pub repository_id: Option<String>,
    pub status: String,
    pub cli_version: Option<String>,
    pub summary: Option<String>,
    pub idempotency_key: Option<String>,
    pub started_at: Option<String>,
    pub created_at: Option<String>,
}

/// Body for `createAgentRun` / `updateAgentRun` (the update ignores the create-only fields).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRunBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

// ── Investigation provenance graph (Stage 1 dual-write) ─────────────────────

/// One endpoint of a citation edge (`type`: investigation | cause | hypothesis | finding |
/// evidence | outcome).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationNode {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub band: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Value>,
}

/// A directed, typed citation edge (`role`: derives | supports | contradicts | cites | explains).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CitationEdgeInput {
    pub from: CitationNode,
    pub to: CitationNode,
    pub role: String,
}

/// A per-item evidence row materialized from the engine report (Stage 1).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvenanceEvidenceInput {
    #[serde(rename = "type")]
    pub kind_bucket: String,
    pub source: String,
    pub title: String,
    pub content: String,
    pub content_format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub engine_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_name: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBatchRecord {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub engine_ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceBatchResult {
    #[serde(default)]
    pub evidence: Option<Vec<EvidenceBatchRecord>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CitationsResult {
    pub created: f64,
}

/// A knowledge snapshot record stored in Horus Cloud (HOR-296).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeSnapshotRecord {
    pub id: String,
    pub project_id: String,
    pub schema_version: f64,
    pub content_hash: String,
    pub git_sha: Option<String>,
    pub branch: Option<String>,
    pub generated_at: String,
    #[serde(default)]
    pub counts: IndexMap<String, f64>,
    #[serde(default)]
    pub snapshot: Option<Value>,
    #[serde(default)]
    pub manifest: Option<Value>,
    #[serde(default)]
    pub archived: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushKnowledgeSnapshotBody {
    pub schema_version: u32,
    pub content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<IndexMap<String, u64>>,
    pub snapshot: Value,
    pub manifest: Value,
    /// Defaults to the content hash — server dedups idempotent re-pushes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeReportBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contributor_count: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols_added: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols_modified: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols_removed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_topology_touched: Option<bool>,
    /// The full deterministic WhatChangedReport, stored for the dashboard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeReportRecord {
    pub id: String,
    pub project_id: String,
    pub summary: String,
    pub created_at: String,
}

// ── Memory items (M3) ───────────────────────────────────────────────────────

/// One memory item as it travels to the cloud sync endpoint. PRIVACY: no payload/embedding/
/// vector field — vectors never cross the trust boundary.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryItemSyncInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<Map<String, Value>>,
    /// CLI memory_item.id (ULID) — the upsert key.
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_hash: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_created_at: Option<Option<String>>,
}

/// One authored link as it travels to the cloud sync endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryLinkSyncInput {
    pub idempotency_key: String,
    pub from_client_id: String,
    pub rel: String,
    pub to_kind: String,
    pub to_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_file_path: Option<String>,
}

/// One APPEND-ONLY audit row mirrored from the CLI.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryAuditSyncInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Map<String, Value>>,
    pub client_audit_id: String,
    pub memory_client_id: String,
    pub action: String,
    pub actor: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub at: String,
}

/// A link as the cloud returns it on a memory record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryLinkRecord {
    #[serde(flatten)]
    pub link: MemoryLinkSyncInput,
    pub created_at: String,
}

/// A memory item as the cloud returns it. `client_id` round-trips the CLI ULID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryItemRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_paged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<MemoryLinkRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<Vec<MemoryAuditSyncInput>>,
    pub id: String,
    pub client_id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub project_id: Option<String>,
    pub created_by_user_id: Option<String>,
    pub visibility: String,
    pub kind: String,
    pub claim: String,
    pub scope: String,
    pub source: String,
    pub status: String,
    /// Typed `number` in TS but never validated — the server may omit it (packet run hit
    /// "missing field `confidence`"), so it is optional here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
    pub last_verified_at: Option<String>,
    pub last_verified_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_created_at: Option<Option<String>>,
    pub created_at: String,
    pub updated_at: String,
}

/// Per-array outcome of one sync transaction (links/audit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySyncBatchCounts {
    pub created: f64,
    pub skipped: f64,
    pub total: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySyncConflict {
    pub reason: String,
    pub current_revision: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemorySyncResult {
    #[serde(default)]
    pub staged: Option<bool>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub conflict: Option<MemorySyncConflict>,
    #[serde(default)]
    pub items: Option<Vec<MemoryItemRecord>>,
    #[serde(default)]
    pub created: Option<f64>,
    #[serde(default)]
    pub updated: Option<f64>,
    #[serde(default)]
    pub total: Option<f64>,
    /// clientId (ULID) → cloud uuid.
    #[serde(default)]
    pub id_map: Option<IndexMap<String, String>>,
    #[serde(default)]
    pub links: Option<MemorySyncBatchCounts>,
    #[serde(default)]
    pub audit: Option<MemorySyncBatchCounts>,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryListQuery {
    pub include_history: Option<bool>,
    pub after_revision: Option<String>,
    pub status: Option<String>,
    pub kind: Option<String>,
    /// ilike on claim.
    pub search: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryItemList {
    pub items: Vec<MemoryItemRecord>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub next_revision: Option<String>,
    #[serde(default)]
    pub has_more: Option<bool>,
}

/// Query for the paginated memory link/audit history endpoints.
#[derive(Debug, Clone)]
pub struct MemoryHistoryQuery {
    pub memory_item_id: String,
    pub expected_revision: String,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryLinkPage {
    pub links: Vec<Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryAuditPage {
    pub audit: Vec<Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

// ── Team memory (HOR-464 / M4) ──────────────────────────────────────────────

/// One item as the server team-memory store returns it (workspace-scoped).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemoryItem {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub source_project_id: Option<String>,
    /// The promoting CLI's local `memory_item.id` — the cross-device dedup + cache join key.
    pub origin_client_id: String,
    /// DISPLAY-ONLY attribution (never feeds rank).
    pub author_name: Option<String>,
    pub promoted_by_user_id: Option<String>,
    pub kind: String,
    pub claim: String,
    pub scope: String,
    pub source: String,
    pub status: String,
    pub confidence: Option<f64>,
    pub content_hash: Option<String>,
    #[serde(default)]
    pub provenance: Map<String, Value>,
    /// bigint serialized as a STRING — the pull cursor.
    pub seq: String,
    pub deleted_at: Option<String>,
    pub promoted_at: String,
    pub updated_at: String,
}

/// One item promoted into the team store (POSITIVE allowlist — never a vector/payload).
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemoryPromoteInput {
    pub origin_client_id: String,
    pub kind: String,
    pub claim: String,
    pub scope: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Option<f64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TeamMemoryPromoteResult {
    pub promoted: f64,
    pub skipped: f64,
    pub total: f64,
    pub items: Vec<TeamMemoryItem>,
}

#[derive(Debug, Clone, Default)]
pub struct TeamMemoryListQuery {
    /// The seq high-water mark (v1 client pulls `since:'0'` full).
    pub since: String,
    pub limit: Option<u32>,
    pub include_deleted: bool,
    pub search: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemoryListResult {
    pub items: Vec<TeamMemoryItem>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

// ── Alert routing (watch service) ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertSource {
    pub provider: String,
    pub project_id: Option<String>,
    pub environment: Option<String>,
    pub enabled: bool,
    pub service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_api_token: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRequest {
    pub id: String,
    pub local_report_id: String,
    pub hint: String,
    pub payload: Map<String, Value>,
    pub project_id: String,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertClaim {
    pub id: String,
    pub claim_token: String,
    pub local_report_id: String,
    #[serde(default)]
    pub hint: Option<String>,
    #[serde(default)]
    pub payload: Option<Map<String, Value>>,
}

/// `{ state: 'off' | 'delivered' | 'failed'; error? }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyResult {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotifyInvestigationInput {
    pub notification_key: String,
    pub hint: String,
    pub cause: String,
    /// Optional on the wire (TS reads `typeof record.confidence === 'number' ? … : 0`): a missing
    /// or null confidence decodes as 0 instead of failing the whole sync.
    #[serde(default, deserialize_with = "null_as_zero")]
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceNoticeInput {
    /// `budget` | `terminal`.
    pub kind: String,
    pub environment: String,
    pub job_id: String,
    pub day: String,
    pub hint: String,
    pub cause: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedWorkspace {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub organization_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedProject {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub workspace_id: String,
    pub organization_id: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProjectBody {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>().replace('+', "%20")
}

/// `new URLSearchParams(pairs).toString()`.
fn query_string(pairs: &[(&str, String)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

/// `reqwest::Error`'s Display omits its cause; append the innermost source (TS `fetch` errors
/// surface e.g. "The operation was aborted due to timeout" / the socket error here).
fn error_chain(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(e);
    let mut last = None;
    while let Some(s) = src {
        last = Some(s.to_string());
        src = s.source();
    }
    if let Some(cause) = last.filter(|c| !msg.contains(c.as_str())) {
        msg.push_str(": ");
        msg.push_str(&cause);
    }
    msg
}

// ── Client ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct CloudClient {
    base_url: String,
    token: Option<String>,
    /// TS `AbortSignal`: every request is capped so it cannot outlive this instant.
    deadline: Option<Instant>,
    http: reqwest::Client,
}

impl CloudClient {
    pub fn new(base_url: &str, token: Option<&str>) -> Self {
        Self {
            base_url: base_url.to_string(),
            token: token.map(str::to_string),
            deadline: None,
            http: reqwest::Client::new(),
        }
    }

    /// Cap every request at `deadline` (the TS `signal` argument: an AbortController timeout).
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub(crate) async fn request<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
        timeout_ms: Option<u64>,
    ) -> Result<T, CloudError> {
        // Port safety: the Rust CLI runs beside the TS CLI against the same cloud workspace,
        // so writes are refused unless explicitly enabled. Surfaced as Offline because every
        // caller already degrades gracefully on an unreachable cloud.
        if method != reqwest::Method::GET && !cloud_writes_enabled() {
            return Err(CloudError::Offline(format!(
                "Horus Cloud writes are disabled in the Rust port ({method} {path}); unset HORUS_RUST_CLOUD_WRITE to enable."
            )));
        }
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let mut timeout = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
        if let Some(d) = self.deadline {
            timeout = timeout.min(d.saturating_duration_since(Instant::now()));
        }
        let offline = |m: String| CloudError::Offline(format!("Cannot reach Horus Cloud at {} ({m}).", self.base_url));
        if timeout.is_zero() {
            return Err(offline("This operation was aborted".into()));
        }
        let mut req = self.http.request(method, url).timeout(timeout);
        if let Some(t) = self.token.as_deref().filter(|t| !t.is_empty()) {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        if let Some(b) = body {
            let text = horus_core::json::to_js_json(b).map_err(|e| CloudError::Other(e.to_string()))?;
            req = req.header("content-type", "application/json").body(text);
        }
        let sent = req.send().await;
        let res = sent.map_err(|e| offline(error_chain(&e)))?;
        let status = res.status();
        if status.as_u16() == 204 {
            return serde_json::from_value(Value::Null).map_err(|e| CloudError::Other(e.to_string()));
        }
        let retry_after = res.headers().get("retry-after").and_then(|v| v.to_str().ok()).map(str::to_string);
        let text = res.text().await.map_err(|e| offline(error_chain(&e)))?;
        let json: Option<Value> = if text.is_empty() {
            None
        } else {
            match serde_json::from_str(&text) {
                Ok(v) => Some(v),
                Err(e) if status.is_success() => return Err(CloudError::Other(e.to_string())),
                Err(_) => None,
            }
        };
        if !status.is_success() {
            let err = json.as_ref().and_then(|e| e.get("error"));
            let field = |k: &str| err.and_then(|e| e.get(k)).and_then(Value::as_str).map(str::to_string);
            let retry_after_ms = retry_after.and_then(|ra| {
                if !ra.is_empty() && ra.chars().all(|c| c.is_ascii_digit()) {
                    ra.parse::<u64>().ok().map(|s| s * 1000)
                } else {
                    chrono::DateTime::parse_from_rfc2822(&ra)
                        .ok()
                        .map(|t| (t.timestamp_millis() - chrono::Utc::now().timestamp_millis()).max(0) as u64)
                }
            });
            return Err(CloudError::Http {
                status: status.as_u16(),
                code: field("code").unwrap_or_else(|| "http_error".into()),
                message: field("message").unwrap_or_else(|| format!("Request failed ({}).", status.as_u16())),
                retry_after_ms,
            });
        }
        serde_json::from_value(json.unwrap_or(Value::Null)).map_err(|e| CloudError::Other(e.to_string()))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CloudError> {
        self.request(reqwest::Method::GET, path, None::<&Value>, None).await
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: &(impl Serialize + ?Sized)) -> Result<T, CloudError> {
        self.request(reqwest::Method::POST, path, Some(body), None).await
    }

    async fn patch<T: DeserializeOwned>(&self, path: &str, body: &(impl Serialize + ?Sized)) -> Result<T, CloudError> {
        self.request(reqwest::Method::PATCH, path, Some(body), None).await
    }

    // ── Alert routing ──────────────────────────────────────────────────────

    pub async fn list_alert_sources(&self, workspace_id: &str) -> Result<Vec<AlertSource>, CloudError> {
        self.get(&format!("/v1/workspaces/{workspace_id}/alert-sources")).await
    }

    pub async fn list_alert_requests(
        &self,
        workspace_id: &str,
        project_id: &str,
        environment: &str,
    ) -> Result<Vec<AlertRequest>, CloudError> {
        let qs = query_string(&[
            ("projectId", project_id.into()),
            ("environment", environment.into()),
            ("ready", "true".into()),
        ]);
        self.get(&format!("/v1/workspaces/{workspace_id}/investigation-requests?{qs}")).await
    }

    /// `action`: claim | heartbeat | complete | fail | retry.
    pub async fn alert_request(
        &self,
        workspace_id: &str,
        request_id: &str,
        action: &str,
        body: &Value,
    ) -> Result<AlertClaim, CloudError> {
        self.post(&format!("/v1/workspaces/{workspace_id}/investigation-requests/{request_id}/{action}"), body).await
    }

    pub async fn worker_heartbeat(&self, workspace_id: &str, body: &Value) -> Result<Value, CloudError> {
        self.post(&format!("/v1/workspaces/{workspace_id}/alert-workers"), body).await
    }

    pub async fn notify_investigation(
        &self,
        project_id: &str,
        investigation_id: &str,
        input: &NotifyInvestigationInput,
    ) -> Result<NotifyResult, CloudError> {
        self.post(
            &format!(
                "/v1/projects/{}/investigations/{}/notify",
                encode_uri_component(project_id),
                encode_uri_component(investigation_id)
            ),
            input,
        )
        .await
    }

    pub async fn notify_service_notice(&self, project_id: &str, input: &ServiceNoticeInput) -> Result<NotifyResult, CloudError> {
        self.post(&format!("/v1/projects/{}/notifications/slack/notices", encode_uri_component(project_id)), input).await
    }

    // ── Account / context ──────────────────────────────────────────────────

    pub async fn me(&self) -> Result<MeResponse, CloudError> {
        self.get("/v1/me").await
    }

    /// Begin a browser device-login session (no auth required).
    pub async fn start_cli_session(&self) -> Result<CliSessionStart, CloudError> {
        self.request(reqwest::Method::POST, "/v1/cli-sessions/start", None::<&Value>, None).await
    }

    /// Poll a device-login session until it is approved, denied, or expires.
    pub async fn poll_cli_session(&self, device_code: &str) -> Result<CliSessionPoll, CloudError> {
        self.post("/v1/cli-sessions/poll", &serde_json::json!({ "deviceCode": device_code })).await
    }

    pub async fn context(&self) -> Result<ContextResponse, CloudError> {
        self.get("/v1/context").await
    }

    /// Create a workspace in an org (HOR-307 — used by `cloud link` create-from-repo).
    pub async fn create_workspace(&self, organization_id: &str, name: &str) -> Result<CreatedWorkspace, CloudError> {
        self.post(&format!("/v1/organizations/{organization_id}/workspaces"), &serde_json::json!({ "name": name }))
            .await
    }

    /// Create a project in a workspace, optionally with its repo identity (HOR-307).
    pub async fn create_project(
        &self,
        organization_id: &str,
        workspace_id: &str,
        body: &CreateProjectBody,
    ) -> Result<CreatedProject, CloudError> {
        self.post(&format!("/v1/organizations/{organization_id}/workspaces/{workspace_id}/projects"), body).await
    }

    pub async fn list_tokens(&self) -> Result<TokenList, CloudError> {
        self.get("/v1/cli/tokens").await
    }

    pub async fn revoke_token(&self, id: &str) -> Result<(), CloudError> {
        let _: Value = self.request(reqwest::Method::DELETE, &format!("/v1/cli/tokens/{id}"), None::<&Value>, None).await?;
        Ok(())
    }

    // ── Investigations ─────────────────────────────────────────────────────

    pub async fn create_investigation(
        &self,
        project_id: &str,
        body: &CreateInvestigationBody,
    ) -> Result<InvestigationRecord, CloudError> {
        self.post(&format!("/v1/projects/{project_id}/investigations"), body).await
    }

    pub async fn list_investigations(&self, project_id: &str) -> Result<InvestigationList, CloudError> {
        self.get(&format!("/v1/projects/{project_id}/investigations")).await
    }

    pub async fn get_investigation(&self, project_id: &str, investigation_id: &str) -> Result<InvestigationDetail, CloudError> {
        self.get(&format!("/v1/projects/{project_id}/investigations/{investigation_id}")).await
    }

    pub async fn update_investigation(
        &self,
        project_id: &str,
        investigation_id: &str,
        body: &UpdateInvestigationBody,
    ) -> Result<InvestigationRecord, CloudError> {
        self.patch(&format!("/v1/projects/{project_id}/investigations/{investigation_id}"), body).await
    }

    pub async fn add_investigation_repositories(
        &self,
        project_id: &str,
        investigation_id: &str,
        repository_ids: &[String],
    ) -> Result<InvestigationDetail, CloudError> {
        self.post(
            &format!("/v1/projects/{project_id}/investigations/{investigation_id}/repositories"),
            &serde_json::json!({ "repositoryIds": repository_ids }),
        )
        .await
    }

    pub async fn create_evidence(
        &self,
        project_id: &str,
        investigation_id: &str,
        body: &CreateEvidenceBody,
    ) -> Result<EvidenceRecord, CloudError> {
        self.post(&format!("/v1/projects/{project_id}/investigations/{investigation_id}/evidence"), body).await
    }

    pub async fn list_evidence(&self, project_id: &str, investigation_id: &str) -> Result<Vec<EvidenceRecord>, CloudError> {
        self.get(&format!("/v1/projects/{project_id}/investigations/{investigation_id}/evidence")).await
    }

    /// Batch-materialize per-item evidence rows (Stage 1 dual-write). The response echoes every
    /// row's `engineRef` so the caller can build the engineRef→cloudId map for citation edges.
    pub async fn create_evidence_batch(
        &self,
        project_id: &str,
        investigation_id: &str,
        items: &[ProvenanceEvidenceInput],
    ) -> Result<EvidenceBatchResult, CloudError> {
        self.post(
            &format!("/v1/projects/{project_id}/investigations/{investigation_id}/evidence/batch"),
            &serde_json::json!({ "items": items }),
        )
        .await
    }

    /// Batch-insert citation edges over the typed provenance nodes (Stage 1 dual-write).
    pub async fn create_citations(
        &self,
        project_id: &str,
        investigation_id: &str,
        edges: &[CitationEdgeInput],
    ) -> Result<CitationsResult, CloudError> {
        self.post(
            &format!("/v1/projects/{project_id}/investigations/{investigation_id}/citations"),
            &serde_json::json!({ "edges": edges }),
        )
        .await
    }

    pub async fn create_agent_run(
        &self,
        project_id: &str,
        investigation_id: &str,
        body: &AgentRunBody,
    ) -> Result<AgentRunRecord, CloudError> {
        self.post(&format!("/v1/projects/{project_id}/investigations/{investigation_id}/agent-runs"), body).await
    }

    /// Complete metadata for a run already created by durable memory/report sync.
    pub async fn update_agent_run(
        &self,
        project_id: &str,
        investigation_id: &str,
        run_id: &str,
        body: &AgentRunBody,
    ) -> Result<AgentRunRecord, CloudError> {
        self.patch(&format!("/v1/projects/{project_id}/investigations/{investigation_id}/agent-runs/{run_id}"), body)
            .await
    }

    // ── Knowledge snapshots (HOR-296) ──────────────────────────────────────

    /// Upload a local knowledge snapshot. Content-hash idempotent (server dedups).
    pub async fn push_knowledge_snapshot(
        &self,
        project_id: &str,
        body: &PushKnowledgeSnapshotBody,
    ) -> Result<KnowledgeSnapshotRecord, CloudError> {
        self.request(
            reqwest::Method::POST,
            &format!("/v1/projects/{project_id}/knowledge-snapshots"),
            Some(body),
            Some(KNOWLEDGE_TRANSFER_TIMEOUT_MS),
        )
        .await
    }

    /// Fetch the latest (non-archived) knowledge snapshot for a project.
    pub async fn get_latest_knowledge_snapshot(&self, project_id: &str) -> Result<KnowledgeSnapshotRecord, CloudError> {
        self.request(
            reqwest::Method::GET,
            &format!("/v1/projects/{project_id}/knowledge-snapshots/latest"),
            None::<&Value>,
            Some(KNOWLEDGE_TRANSFER_TIMEOUT_MS),
        )
        .await
    }

    /// Push a `horus what-changed` report to the linked cloud project.
    pub async fn create_change_report(&self, project_id: &str, body: &ChangeReportBody) -> Result<ChangeReportRecord, CloudError> {
        self.post(&format!("/v1/projects/{project_id}/changes"), body).await
    }

    // ── Memory items (M3) ──────────────────────────────────────────────────

    /// Batch-upsert authored memory items + links + audit in ONE cloud transaction. Idempotent
    /// per element on the CLI's stable ids. Body: `{ operation?, history?, items?, links?, audit? }`.
    /// Vectors are NEVER part of the body (privacy invariant).
    pub async fn sync_memory_items(&self, project_id: &str, body: &Value) -> Result<MemorySyncResult, CloudError> {
        self.post(&format!("/v1/projects/{project_id}/memory-items/sync"), body).await
    }

    /// List a project's memory items (server-side org + visibility filtered).
    pub async fn list_memory_items(&self, project_id: &str, q: &MemoryListQuery) -> Result<MemoryItemList, CloudError> {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        if let Some(h) = q.include_history {
            pairs.push(("includeHistory", h.to_string()));
        }
        if let Some(r) = &q.after_revision {
            pairs.push(("afterRevision", r.clone()));
        }
        if let Some(s) = q.status.as_ref().filter(|s| !s.is_empty()) {
            pairs.push(("status", s.clone()));
        }
        if let Some(k) = q.kind.as_ref().filter(|s| !s.is_empty()) {
            pairs.push(("kind", k.clone()));
        }
        if let Some(s) = q.search.as_ref().filter(|s| !s.is_empty()) {
            pairs.push(("search", s.clone()));
        }
        if let Some(l) = q.limit {
            pairs.push(("limit", l.to_string()));
        }
        if let Some(c) = q.cursor.as_ref().filter(|s| !s.is_empty()) {
            pairs.push(("cursor", c.clone()));
        }
        let qs = query_string(&pairs);
        let path = if qs.is_empty() {
            format!("/v1/projects/{project_id}/memory-items")
        } else {
            format!("/v1/projects/{project_id}/memory-items?{qs}")
        };
        self.get(&path).await
    }

    fn history_qs(q: &MemoryHistoryQuery) -> String {
        let mut pairs = vec![
            ("memoryItemId", q.memory_item_id.clone()),
            ("expectedRevision", q.expected_revision.clone()),
            ("limit", "100".to_string()),
        ];
        if let Some(c) = q.cursor.as_ref().filter(|c| !c.is_empty()) {
            pairs.push(("cursor", c.clone()));
        }
        query_string(&pairs)
    }

    /// Paginated history endpoints; every page is pinned to the item revision.
    pub async fn list_memory_links(&self, project_id: &str, q: &MemoryHistoryQuery) -> Result<MemoryLinkPage, CloudError> {
        self.get(&format!("/v1/projects/{project_id}/memory-links?{}", Self::history_qs(q))).await
    }

    pub async fn list_memory_audit(&self, project_id: &str, q: &MemoryHistoryQuery) -> Result<MemoryAuditPage, CloudError> {
        self.get(&format!("/v1/projects/{project_id}/memory-audit?{}", Self::history_qs(q))).await
    }

    // ── Team memory (HOR-464 / M4) ─────────────────────────────────────────

    /// One-way PROMOTE local items into the workspace's shared team-memory store. Server-wins &
    /// idempotent; the body is a positive allowlist — vectors NEVER cross the wire.
    pub async fn promote_team_memory(
        &self,
        project_id: &str,
        items: &[TeamMemoryPromoteInput],
    ) -> Result<TeamMemoryPromoteResult, CloudError> {
        self.post(&format!("/v1/projects/{project_id}/team-memory/promote"), &serde_json::json!({ "items": items }))
            .await
    }

    /// Read the workspace's team-memory items with `seq > since`, ORDER BY seq ASC.
    pub async fn list_team_memory_since(&self, project_id: &str, q: &TeamMemoryListQuery) -> Result<TeamMemoryListResult, CloudError> {
        let mut pairs = vec![("since", q.since.clone())];
        if let Some(l) = q.limit {
            pairs.push(("limit", l.to_string()));
        }
        if q.include_deleted {
            pairs.push(("includeDeleted", "true".into()));
        }
        if let Some(s) = q.search.as_ref().filter(|s| !s.is_empty()) {
            pairs.push(("search", s.clone()));
        }
        self.get(&format!("/v1/projects/{project_id}/team-memory?{}", query_string(&pairs))).await
    }
}

/// Decode an absent/null JSON number as 0 (TS `typeof x === 'number' ? x : 0`).
fn null_as_zero<'de, D: serde::Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    Ok(<Option<f64> as serde::Deserialize>::deserialize(d)?.unwrap_or(0.0))
}
