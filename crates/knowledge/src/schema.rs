//! Local project-knowledge index schema (HOR-291).
//!
//! Defines the first-version contract for the `.horus/index/` knowledge layer that
//! `horus init`, `horus knowledge`, and Horus MCP build against. This is the
//! PROJECT-KNOWLEDGE layer — distinct from:
//!
//!   - SOURCE INTELLIGENCE: the raw code graph in `.horus/source/` (Kùzu),
//!     queried over HTTP. Project knowledge *references* it (file/line/symbol) but
//!     keeps raw source bodies and embeddings local. An optional bounded relationship
//!     projection connects existing knowledge entities for Cloud path tracing.
//!   - RUNTIME EVIDENCE: investigation observations in the CLI's local store
//!     (evidence/findings/hypotheses). Time-stamped, per-incident — not durable
//!     project facts.
//!
//! Local-first: indexing and querying never require Horus Cloud.
//!
//! serde does the structural parse (unknown keys are stripped, like `z.object`);
//! `validate_snapshot` / `validate_manifest` reproduce zod's value constraints
//! (`min(1)`, `datetime()`, `literal(1)`, `max(20000)`, `0..=1`). Struct fields
//! are declared in zod schema order so the JSON key order matches the TS output.

use anyhow::{bail, Result};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Bump when the on-disk shape changes incompatibly.
pub const KNOWLEDGE_SCHEMA_VERSION: u32 = 1;

// ── Provenance ──────────────────────────────────────────────────────────────

/// How a knowledge item was obtained. Drives trust + staleness:
/// - parsed:          extracted deterministically from source (highest trust)
/// - inferred:        derived/heuristic (e.g. domain grouping)
/// - manual:          authored by a human
/// - runtime:         observed from live runtime evidence
/// - agent-confirmed: proposed by an agent and confirmed against source
/// - imported:        brought in from an external knowledge tool (HOR-292, e.g.
///   the MCP knowledge-base), not freshly parsed by Horus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SourceType {
    #[default]
    Parsed,
    Inferred,
    Manual,
    Runtime,
    AgentConfirmed,
    Imported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Inclusive 1-based source line range `[start, end]`.
pub type LineRange = (u64, u64);

/// Per-item provenance. Every field is optional except `sourceType` — knowledge
/// is captured "where available", and inferred/cross-repo items may have no single
/// file. `contentHash` + `gitSha` + `lastSeen` are the staleness anchors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub source_type: SourceType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// Repository name (matches a RepositoryProfile.key / HorusConfig repository).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_range: Option<LineRange>,
    /// Commit the item was generated from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    /// ISO-8601 timestamp the item was generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    /// ISO-8601 timestamp the item was last confirmed present in source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// Hash of the source span/file the item derives from (staleness check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// Optional tenancy scope (which project/repo a fact belongs to).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
}

// ── Categories ──────────────────────────────────────────────────────────────

/// A repository's role/profile in the project landscape (projectProfiles).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryProfile {
    /// Stable, deterministic ID (e.g. `repo:<name>`).
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub key: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default)]
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub state_management: Vec<String>,
    #[serde(default)]
    pub auth: Vec<String>,
    #[serde(default)]
    pub data_sources: Vec<String>,
    #[serde(default)]
    pub main_scripts: Vec<String>,
    #[serde(default)]
    pub integrations: Vec<String>,
    #[serde(default)]
    pub deployment_notes: Vec<String>,
    #[serde(default)]
    pub important_directories: Vec<String>,
}

/// A typed argument or field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Auth requirement attached to an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationAuth {
    pub required: bool,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// An API operation / contract entry — protocol-agnostic so GraphQL (first),
/// REST/OpenAPI, and RPC can all be represented.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub name: String,
    /// query | mutation | subscription | endpoint | rpc | function.
    pub kind: String,
    /// graphql | rest | grpc | function | ... (defaults to graphql for the prototype).
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_file: Option<String>,
    /// REST path / GraphQL field path when relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<OperationAuth>,
    #[serde(default)]
    pub args: Vec<Field>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
}

fn default_protocol() -> String {
    "graphql".to_string()
}

/// A type definition: input, response, object, scalar, interface, union.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeDefinition {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub name: String,
    /// input | response | object | scalar | interface | union.
    pub kind: String,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// An enum and its values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnumDefinition {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub name: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
}

/// An authorization rule (who may invoke what).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    /// What the rule guards (operation name, route, resource).
    pub subject: String,
    pub required: bool,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Operation/resource IDs this rule applies to.
    #[serde(default)]
    pub applies_to: Vec<String>,
}

/// A higher-level domain concept tying operations + types together.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainConcept {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default)]
    pub related_operations: Vec<String>,
    #[serde(default)]
    pub related_types: Vec<String>,
}

/// A frontend pattern: hook, store, provider, server-function, component.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrontendPattern {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One ordered step of a data flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowStep {
    pub component: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A data flow: an ordered path data takes across components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlow {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub steps: Vec<DataFlowStep>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub sinks: Vec<String>,
}

/// A deployable/runtime component: service, worker, cron, queue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeComponent {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub name: String,
    /// service | worker | cron | queue | function | gateway | ...
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default)]
    pub entrypoints: Vec<String>,
}

/// An external system the project integrates with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalIntegration {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<KnowledgeScope>,
    pub provenance: Provenance,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// api | db | queue | auth | payment | storage | email | ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub used_by: Vec<String>,
}

// ── Snapshot ────────────────────────────────────────────────────────────────

/// Relationship kind between two knowledge entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRel {
    Calls,
    Extends,
    Implements,
    UsesType,
}

impl SourceRel {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceRel::Calls => "calls",
            SourceRel::Extends => "extends",
            SourceRel::Implements => "implements",
            SourceRel::UsesType => "uses_type",
        }
    }
}

/// One bounded relationship edge between two retained knowledge entities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceRelationshipEdge {
    pub id: String,
    pub from: String,
    pub to: String,
    pub rel: SourceRel,
    /// `number | null` — serialized like JS (`1`, not `1.0`) so content hashes match.
    #[serde(serialize_with = "js_number::serialize_opt")]
    pub confidence: Option<f64>,
}

/// Bounded relationships between existing knowledge entities. Raw source bodies,
/// embeddings and the rest of the source graph remain local.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceKnowledgeRelationships {
    pub edges: Vec<SourceRelationshipEdge>,
    pub truncated: bool,
}

/// Upper bound on projected relationship edges (`.max(20000)` in the TS schema).
pub const MAX_SOURCE_RELATIONSHIP_EDGES: usize = 20_000;

/// The canonical in-memory project-knowledge snapshot. Persisted as
/// `.horus/index/knowledge-base.json`; derived per-category view files and the
/// `manifest.json` index are written alongside it (see store.rs / layout.rs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeSnapshot {
    pub schema_version: u32,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_relationships: Option<SourceKnowledgeRelationships>,
    #[serde(default)]
    pub repositories: Vec<RepositoryProfile>,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub types: Vec<TypeDefinition>,
    #[serde(default)]
    pub enums: Vec<EnumDefinition>,
    #[serde(default)]
    pub auth_rules: Vec<AuthRule>,
    #[serde(default)]
    pub domain_concepts: Vec<DomainConcept>,
    #[serde(default)]
    pub frontend_patterns: Vec<FrontendPattern>,
    #[serde(default)]
    pub data_flows: Vec<DataFlow>,
    #[serde(default)]
    pub runtime_components: Vec<RuntimeComponent>,
    #[serde(default)]
    pub external_integrations: Vec<ExternalIntegration>,
}

impl KnowledgeSnapshot {
    /// An empty snapshot at the current schema version.
    pub fn empty(generated_at: impl Into<String>, project: Option<String>) -> Self {
        KnowledgeSnapshot {
            schema_version: KNOWLEDGE_SCHEMA_VERSION,
            generated_at: generated_at.into(),
            project,
            source_relationships: None,
            repositories: vec![],
            operations: vec![],
            types: vec![],
            enums: vec![],
            auth_rules: vec![],
            domain_concepts: vec![],
            frontend_patterns: vec![],
            data_flows: vec![],
            runtime_components: vec![],
            external_integrations: vec![],
        }
    }

    /// Number of items in a category.
    pub fn category_len(&self, category: KnowledgeCategory) -> usize {
        match category {
            KnowledgeCategory::Repositories => self.repositories.len(),
            KnowledgeCategory::Operations => self.operations.len(),
            KnowledgeCategory::Types => self.types.len(),
            KnowledgeCategory::Enums => self.enums.len(),
            KnowledgeCategory::AuthRules => self.auth_rules.len(),
            KnowledgeCategory::DomainConcepts => self.domain_concepts.len(),
            KnowledgeCategory::FrontendPatterns => self.frontend_patterns.len(),
            KnowledgeCategory::DataFlows => self.data_flows.len(),
            KnowledgeCategory::RuntimeComponents => self.runtime_components.len(),
            KnowledgeCategory::ExternalIntegrations => self.external_integrations.len(),
        }
    }

    /// Validate zod constraints (`KnowledgeSnapshotSchema.parse`).
    pub fn validate(&self) -> Result<()> {
        let issues = validate_snapshot(self);
        if issues.is_empty() {
            Ok(())
        } else {
            bail!("Invalid knowledge snapshot:\n  {}", issues.join("\n  "))
        }
    }
}

/// Category keys carrying arrays of knowledge items in a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KnowledgeCategory {
    Repositories,
    Operations,
    Types,
    Enums,
    AuthRules,
    DomainConcepts,
    FrontendPatterns,
    DataFlows,
    RuntimeComponents,
    ExternalIntegrations,
}

pub const KNOWLEDGE_CATEGORIES: [KnowledgeCategory; 10] = [
    KnowledgeCategory::Repositories,
    KnowledgeCategory::Operations,
    KnowledgeCategory::Types,
    KnowledgeCategory::Enums,
    KnowledgeCategory::AuthRules,
    KnowledgeCategory::DomainConcepts,
    KnowledgeCategory::FrontendPatterns,
    KnowledgeCategory::DataFlows,
    KnowledgeCategory::RuntimeComponents,
    KnowledgeCategory::ExternalIntegrations,
];

impl KnowledgeCategory {
    /// The TS key (`repositories`, `authRules`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            KnowledgeCategory::Repositories => "repositories",
            KnowledgeCategory::Operations => "operations",
            KnowledgeCategory::Types => "types",
            KnowledgeCategory::Enums => "enums",
            KnowledgeCategory::AuthRules => "authRules",
            KnowledgeCategory::DomainConcepts => "domainConcepts",
            KnowledgeCategory::FrontendPatterns => "frontendPatterns",
            KnowledgeCategory::DataFlows => "dataFlows",
            KnowledgeCategory::RuntimeComponents => "runtimeComponents",
            KnowledgeCategory::ExternalIntegrations => "externalIntegrations",
        }
    }

    /// Parse a TS category key.
    pub fn parse(s: &str) -> Option<Self> {
        KNOWLEDGE_CATEGORIES.iter().copied().find(|c| c.as_str() == s)
    }
}

impl std::fmt::Display for KnowledgeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Manifest ────────────────────────────────────────────────────────────────

/// A repository covered by a snapshot + the commit it was indexed at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestRepository {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
}

/// A persisted file in the index dir + integrity/coverage info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFile {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// `{ tool, version? }` — what produced a snapshot, or the source-intelligence backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRef {
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Git state the snapshot was built at (HOR-293).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManifestGit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

/// `.horus/index/manifest.json` — the index entrypoint. Cheap to read; lets a
/// tool know what exists, how fresh it is, and what produced it without parsing
/// the full snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnowledgeManifest {
    pub schema_version: u32,
    pub generated_at: String,
    /// What produced the snapshot (e.g. horus-cli, mcp-kb-import).
    pub generator: ToolRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Git state the snapshot was built at (HOR-293).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<ManifestGit>,
    #[serde(default)]
    pub repositories: Vec<ManifestRepository>,
    #[serde(default)]
    pub files: Vec<ManifestFile>,
    /// Per-category item counts.
    #[serde(default)]
    pub counts: IndexMap<String, u64>,
    /// Pointer to the source-intelligence backend this snapshot references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_intelligence: Option<ToolRef>,
}

impl KnowledgeManifest {
    /// Validate zod constraints (`KnowledgeManifestSchema.parse`).
    pub fn validate(&self) -> Result<()> {
        let issues = validate_manifest(self);
        if issues.is_empty() {
            Ok(())
        } else {
            bail!("Invalid knowledge manifest:\n  {}", issues.join("\n  "))
        }
    }
}

// ── Validation (zod value constraints) ──────────────────────────────────────

/// zod `z.string().datetime()` (no offset, any precision): strict ISO-8601 UTC.
pub fn is_iso_datetime(s: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        let date = r"((\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\d|3[01])|(0[469]|11)-(0[1-9]|[12]\d|30)|(02)-(0[1-9]|1\d|2[0-8])))";
        let time = r"([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?";
        Regex::new(&format!("^{date}T{time}(Z)$")).expect("datetime regex")
    });
    re.is_match(s)
}

fn check_datetime(issues: &mut Vec<String>, path: &str, value: Option<&str>) {
    if let Some(v) = value {
        if !is_iso_datetime(v) {
            issues.push(format!("{path}: Invalid datetime"));
        }
    }
}

fn check_nonempty(issues: &mut Vec<String>, path: &str, value: &str) {
    if value.is_empty() {
        issues.push(format!("{path}: String must contain at least 1 character(s)"));
    }
}

fn check_provenance(issues: &mut Vec<String>, path: &str, p: &Provenance) {
    check_datetime(issues, &format!("{path}.generatedAt"), p.generated_at.as_deref());
    check_datetime(issues, &format!("{path}.lastSeen"), p.last_seen.as_deref());
}

fn check_item(issues: &mut Vec<String>, path: &str, id: &str, provenance: &Provenance) {
    check_nonempty(issues, &format!("{path}.id"), id);
    check_provenance(issues, &format!("{path}.provenance"), provenance);
}

/// Every zod constraint `KnowledgeSnapshotSchema` enforces beyond structure.
/// Returns `path: message` issues (empty = valid).
pub fn validate_snapshot(s: &KnowledgeSnapshot) -> Vec<String> {
    let mut issues = Vec::new();
    if s.schema_version != KNOWLEDGE_SCHEMA_VERSION {
        issues.push(format!(
            "schemaVersion: Invalid literal value, expected {KNOWLEDGE_SCHEMA_VERSION}"
        ));
    }
    check_datetime(&mut issues, "generatedAt", Some(&s.generated_at));
    if let Some(rel) = &s.source_relationships {
        if rel.edges.len() > MAX_SOURCE_RELATIONSHIP_EDGES {
            issues.push(format!(
                "sourceRelationships.edges: Array must contain at most {MAX_SOURCE_RELATIONSHIP_EDGES} element(s)"
            ));
        }
        for (i, e) in rel.edges.iter().enumerate() {
            let p = format!("sourceRelationships.edges.{i}");
            check_nonempty(&mut issues, &format!("{p}.id"), &e.id);
            check_nonempty(&mut issues, &format!("{p}.from"), &e.from);
            check_nonempty(&mut issues, &format!("{p}.to"), &e.to);
            if let Some(c) = e.confidence {
                if c < 0.0 {
                    issues.push(format!("{p}.confidence: Number must be greater than or equal to 0"));
                } else if c > 1.0 {
                    issues.push(format!("{p}.confidence: Number must be less than or equal to 1"));
                }
            }
        }
    }
    for (i, x) in s.repositories.iter().enumerate() {
        check_item(&mut issues, &format!("repositories.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.operations.iter().enumerate() {
        check_item(&mut issues, &format!("operations.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.types.iter().enumerate() {
        check_item(&mut issues, &format!("types.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.enums.iter().enumerate() {
        check_item(&mut issues, &format!("enums.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.auth_rules.iter().enumerate() {
        check_item(&mut issues, &format!("authRules.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.domain_concepts.iter().enumerate() {
        check_item(&mut issues, &format!("domainConcepts.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.frontend_patterns.iter().enumerate() {
        check_item(&mut issues, &format!("frontendPatterns.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.data_flows.iter().enumerate() {
        check_item(&mut issues, &format!("dataFlows.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.runtime_components.iter().enumerate() {
        check_item(&mut issues, &format!("runtimeComponents.{i}"), &x.id, &x.provenance);
    }
    for (i, x) in s.external_integrations.iter().enumerate() {
        check_item(&mut issues, &format!("externalIntegrations.{i}"), &x.id, &x.provenance);
    }
    issues
}

/// Every zod constraint `KnowledgeManifestSchema` enforces beyond structure.
pub fn validate_manifest(m: &KnowledgeManifest) -> Vec<String> {
    let mut issues = Vec::new();
    if m.schema_version != KNOWLEDGE_SCHEMA_VERSION {
        issues.push(format!(
            "schemaVersion: Invalid literal value, expected {KNOWLEDGE_SCHEMA_VERSION}"
        ));
    }
    check_datetime(&mut issues, "generatedAt", Some(&m.generated_at));
    issues
}

/// Serialize `f64` the way `JSON.stringify` does: integral values without a
/// fractional part (`1`, not `1.0`). Needed for byte-identical content hashes.
pub mod js_number {
    use serde::Serializer;

    pub fn serialize<S: Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
        if v.is_finite() && v.fract() == 0.0 && v.abs() < 1e15 {
            s.serialize_i64(*v as i64)
        } else {
            s.serialize_f64(*v)
        }
    }

    pub fn serialize_opt<S: Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(x) => serialize(x, s),
            None => s.serialize_none(),
        }
    }
}

// ── Staleness ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KnowledgeItemStatus {
    Current,
    Stale,
    Unknown,
}

impl KnowledgeItemStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            KnowledgeItemStatus::Current => "current",
            KnowledgeItemStatus::Stale => "stale",
            KnowledgeItemStatus::Unknown => "unknown",
        }
    }
}

/// What the source currently looks like, for `item_status`.
#[derive(Debug, Clone, Default)]
pub struct CurrentSource<'a> {
    pub content_hash: Option<&'a str>,
    pub head_sha: Option<&'a str>,
}

/// Derive an item's freshness against the current source. An item is `stale` when
/// the source it was parsed from has changed (content hash mismatch, or the repo
/// HEAD advanced past the recorded gitSha for parsed items); `unknown` when there
/// is nothing to compare (no contentHash, or a non-parsed/manual item).
pub fn item_status(provenance: &Provenance, current: &CurrentSource<'_>) -> KnowledgeItemStatus {
    // Manual/inferred/agent items aren't tied 1:1 to a file hash — don't flag them.
    if provenance.source_type != SourceType::Parsed && provenance.source_type != SourceType::Runtime {
        return KnowledgeItemStatus::Unknown;
    }
    if let (Some(a), Some(b)) = (provenance.content_hash.as_deref(), current.content_hash) {
        // TS: truthy check — an empty string counts as absent.
        if !a.is_empty() && !b.is_empty() {
            return if a == b { KnowledgeItemStatus::Current } else { KnowledgeItemStatus::Stale };
        }
    }
    if let (Some(a), Some(b)) = (provenance.git_sha.as_deref(), current.head_sha) {
        if !a.is_empty() && !b.is_empty() {
            return if a == b { KnowledgeItemStatus::Current } else { KnowledgeItemStatus::Unknown };
        }
    }
    KnowledgeItemStatus::Unknown
}
