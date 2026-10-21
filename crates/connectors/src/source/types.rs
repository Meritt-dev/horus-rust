//! Wire shapes for the source-intelligence host (`horus-source host`). Field names and
//! order mirror `packages/connectors/src/source/types.ts` exactly — these are deserialized
//! from (and, for memory requests, serialized to) the live host.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use indexmap::IndexMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceNode {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub start_line: i64,
    #[serde(default)]
    pub end_line: i64,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub class_name: String,
    #[serde(default)]
    pub is_dead: bool,
    #[serde(default)]
    pub is_entry_point: bool,
    #[serde(default)]
    pub is_exported: bool,
    /// B2: for a public export-alias stub, the impl symbol name it redirects to (else absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_of: Option<String>,
    /// Only present on the extended node-detail endpoint (`SourceNodeDetail.node`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceSearchResult {
    pub node_id: String,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub snippet: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCypherResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: i64,
    #[serde(default)]
    pub duration_ms: f64,
}

/// Recorded code relationships, without source bodies or embeddings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceCodeRelationship {
    pub source: String,
    pub target: String,
    /// One of `calls` | `extends` | `implements` | `uses_type`.
    pub rel: String,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceImpactResult {
    pub target: SourceNode,
    pub affected: i64,
    pub depths: IndexMap<String, Vec<SourceNode>>,
}

/// One node on a traced relationship path.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceTraceNode {
    pub id: String,
    pub label: String,
    pub name: String,
    pub file_path: String,
    pub start_line: i64,
}

/// One hop's edge: `segments[i]` connects `path[i]` to `path[i+1]`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceTraceSegment {
    pub rel_type: String,
    pub confidence: f64,
    /// `out` when the edge points forward along the path, `in` when it points back.
    pub direction: String,
}

/// GET /api/trace — shortest relationship path between two symbols.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceTraceResult {
    pub found: bool,
    /// Present when `found` is false: resolution failure or unreachable target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hops: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<SourceTraceNode>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<SourceTraceSegment>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
}

/// One hub node in the graph-insights report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceInsightHub {
    pub id: String,
    pub name: String,
    pub label: String,
    pub file_path: String,
    pub start_line: i64,
    pub degree: i64,
}

/// One community-bridging ("surprising") edge in the graph-insights report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceInsightBridge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub source_community: String,
    pub target_community: String,
    pub source_id: String,
    pub target_id: String,
}

/// GET /api/insights — hubs, surprising connections, suggested questions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceInsightsResult {
    #[serde(default)]
    pub hubs: Vec<SourceInsightHub>,
    #[serde(default)]
    pub bridges: Vec<SourceInsightBridge>,
    #[serde(default)]
    pub questions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceModifiedNode {
    pub before: SourceNode,
    pub after: SourceNode,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceDiffResult {
    #[serde(default)]
    pub added: Vec<SourceNode>,
    #[serde(default)]
    pub removed: Vec<SourceNode>,
    #[serde(default)]
    pub modified: Vec<SourceModifiedNode>,
    #[serde(default)]
    pub added_edges: Vec<Value>,
    #[serde(default)]
    pub removed_edges: Vec<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceOverview {
    #[serde(default)]
    pub nodes_by_label: IndexMap<String, i64>,
    #[serde(default)]
    pub edges_by_type: IndexMap<String, i64>,
    #[serde(default)]
    pub total_nodes: i64,
    #[serde(default)]
    pub total_edges: i64,
}

// ---------------------------------------------------------------------------
// Typed read-path endpoints (HOR-392) — the host serves these instead of the CLI emitting
// raw Cypher. Shapes mirror horus-source route serializers.
// ---------------------------------------------------------------------------

/// POST /api/content-search result row — full (untruncated) node content.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceContentHit {
    pub node_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub content: String,
}

/// GET /api/symbols/exact result row — exact-name hit with line ranges (file label excluded).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceExactSymbol {
    pub node_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub start_line: i64,
    #[serde(default)]
    pub end_line: i64,
    /// Export-alias redirect target (B2/HOR-465): the impl name a synthesized stub points at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_of: Option<String>,
}

/// GET /api/symbols result row — symbol node for the requested label(s).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLabelSymbol {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub start_line: i64,
    #[serde(default)]
    pub end_line: i64,
    #[serde(default)]
    pub class_name: String,
    #[serde(default)]
    pub is_entry_point: bool,
    #[serde(default)]
    pub is_exported: bool,
    #[serde(default)]
    pub signature: String,
}

/// POST /api/nodes/lines value — line range for one resolved node id.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceNodeLine {
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub start_line: i64,
    #[serde(default)]
    pub end_line: i64,
}

/// GET /api/flows/{id} step — a flow step carrying its symbol name/file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceFlowStep {
    pub node_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub start_line: i64,
    #[serde(default)]
    pub step_number: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceFlowProcess {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
}

/// GET /api/flows/{id} response — the processes a symbol is a step in + their merged ordered steps.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceFlowsResult {
    #[serde(default)]
    pub processes: Vec<SourceFlowProcess>,
    #[serde(default)]
    pub steps: Vec<SourceFlowStep>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCommunity {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub member_count: i64,
    #[serde(default)]
    pub cohesion: Option<f64>,
    #[serde(default)]
    pub members: Vec<String>,
}

/// GET /api/communities response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceCommunitiesResult {
    #[serde(default)]
    pub communities: Vec<SourceCommunity>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceDeadSymbol {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub line: i64,
}

/// GET /api/dead-code response — total + symbols grouped by file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceDeadCodeResult {
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub by_file: IndexMap<String, Vec<SourceDeadSymbol>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCouplingPair {
    #[serde(default)]
    pub file_a: String,
    #[serde(default)]
    pub file_b: String,
    #[serde(default)]
    pub strength: f64,
    #[serde(default)]
    pub co_changes: i64,
}

/// GET /api/coupling response — temporal (co-change) coupling pairs between files.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceCouplingResult {
    #[serde(default)]
    pub pairs: Vec<SourceCouplingPair>,
}

/// POST /api/content-search filesOnly response — per-token distinct FILE paths.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceFilesContainingResult {
    #[serde(default)]
    pub matches: IndexMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceProcessStep {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub step_number: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceProcess {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub step_count: i64,
    #[serde(default)]
    pub steps: Vec<SourceProcessStep>,
}

/// GET /api/processes response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceProcessesResult {
    #[serde(default)]
    pub processes: Vec<SourceProcess>,
}

/// One caller/callee neighbour with its edge confidence (GET /api/node).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceNeighbour {
    pub node: SourceNode,
    #[serde(default)]
    pub confidence: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceCoupledWith {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub strength: Option<f64>,
    #[serde(default)]
    pub co_changes: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceCommunityRef {
    #[serde(default)]
    pub id: Value,
    #[serde(default)]
    pub name: Value,
}

/// GET /api/node/{id} extended detail — node + content + neighbours + file context + communities.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceNodeDetail {
    pub node: SourceNode,
    #[serde(default)]
    pub callers: Vec<SourceNeighbour>,
    #[serde(default)]
    pub callees: Vec<SourceNeighbour>,
    #[serde(default)]
    pub type_refs: Vec<SourceNode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_memberships: Option<Value>,
    #[serde(default)]
    pub imports: Vec<Value>,
    #[serde(default)]
    pub coupled_with: Vec<SourceCoupledWith>,
    #[serde(default)]
    pub communities: Vec<SourceCommunityRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceHostInfo {
    #[serde(default)]
    pub repo_path: String,
    #[serde(default)]
    pub host_url: String,
    #[serde(default)]
    pub mcp_url: String,
    #[serde(default)]
    pub watch: bool,
    #[serde(default)]
    pub mode: String,
    /// B1.4 symbol-only degraded-mode contract. Optional for back-compat: older backends omit them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structural_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings_pending: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceHealth {
    pub ok: bool,
    pub status: u16,
}

// ---------------------------------------------------------------------------
// Memory vector bridge (M2) — wire shapes for the host's /api/memory/* routes.
// ---------------------------------------------------------------------------

/// POST /api/memory/upsert body. `scope` carries the recall specificity (symbol:/module:/repo/global).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceMemoryUpsertRequest {
    pub memory_id: String,
    pub claim: String,
    pub repo: String,
    pub scope: String,
}

/// POST /api/memory/search body. `repo` is required (fail-closed isolation, HOR-46).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceMemorySearchRequest {
    pub query: String,
    pub repo: String,
    pub limit: i64,
}

/// A single scored candidate returned by the host vector search. `score` is cosine in 0..1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceMemorySearchHit {
    pub memory_id: String,
    pub score: f64,
}

/// POST /api/memory/search response envelope.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceMemorySearchResult {
    #[serde(default)]
    pub results: Vec<SourceMemorySearchHit>,
}
