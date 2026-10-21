//! Horus Memory — the MemoryStore seam (M1, spec §6).
//!
//! Engine-domain types for the authored-memory substrate. This file is a PURE seam: it defines the
//! `MemoryStore` + `MemoryVectorIndex` traits and the domain types, plus the row shapes that
//! `@horus/db` provides in TypeScript. The concrete `LocalMemoryStore` (in `memory.rs`) talks to
//! persistence only through the narrow [`MemoryStorage`] trait so the engine never depends on the
//! SQLite store crate.
//!
//! HONESTY INVARIANT (spec §8): memory is CONTEXT ONLY. Nothing in this module is read by the
//! confidence/verdict scoring path. In M1 the vector index is the Jaccard/scope `NoopVectorIndex`
//! only — there are NO embeddings. The index merely PROPOSES candidates; the deterministic store
//! filter/rank is the sole authority on what surfaces.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::memory::{tag_overlap, SimilarIncident};
use crate::types::InvestigationReport;

// ---------------------------------------------------------------------------
// JS-compatible date (de)serialization: `2026-10-21T05:05:00.000Z`
// ---------------------------------------------------------------------------

/// Format a timestamp exactly like `Date.prototype.toISOString()` (millisecond precision, `Z`).
pub fn to_iso_string(d: &DateTime<Utc>) -> String {
    d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Best-effort `Date.parse` for the ISO shapes Horus writes. Non-ISO inputs return `None`
/// (TS would accept more formats — see DIVERGENCES.md).
pub fn js_date_parse(s: &str) -> Option<DateTime<Utc>> {
    let t = s.trim();
    if let Ok(d) = DateTime::parse_from_rfc3339(t) {
        return Some(d.with_timezone(&Utc));
    }
    if let Ok(d) = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(d.and_utc());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
    }
    None
}

/// serde helpers for `DateTime<Utc>` fields rendered in JS `toISOString()` form.
pub mod js_date {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_iso_string(d))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(d)?;
        js_date_parse(&raw).ok_or_else(|| serde::de::Error::custom(format!("invalid date: {raw}")))
    }

    pub mod option {
        use super::*;

        pub fn serialize<S: Serializer>(d: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
            match d {
                Some(d) => s.serialize_some(&to_iso_string(d)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
            let raw = Option::<String>::deserialize(d)?;
            match raw {
                None => Ok(None),
                Some(raw) => js_date_parse(&raw)
                    .map(Some)
                    .ok_or_else(|| serde::de::Error::custom(format!("invalid date: {raw}"))),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Row shapes
// ---------------------------------------------------------------------------

// ported-from: @horus/db IncidentMemory
/// The legacy per-run incident recall row (`incident_memory`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentMemory {
    pub id: String,
    pub investigation_id: Option<String>,
    pub project: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub signature: Option<String>,
    pub tags: Option<Vec<String>>,
    pub payload: Option<Value>,
    #[serde(with = "js_date")]
    pub created_at: DateTime<Utc>,
}

// ported-from: @horus/db NewIncidentMemory
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewIncidentMemory {
    pub investigation_id: Option<String>,
    pub project: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub signature: Option<String>,
    pub tags: Option<Vec<String>>,
    pub payload: Option<Value>,
}

// ported-from: @horus/db MemoryItem
/// An authored memory item (`memory_item`). Field order = column order (JSON key order).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryItem {
    pub id: String,
    pub kind: String,
    pub claim: String,
    pub scope: String,
    pub source: String,
    pub evidence: Value,
    pub confidence: f64,
    pub status: String,
    #[serde(with = "js_date")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "js_date::option")]
    pub last_verified_at: Option<DateTime<Utc>>,
    pub last_verified_hash: Option<String>,
    pub org_id: Option<String>,
    pub workspace_id: Option<String>,
    pub repo: String,
    pub user_id: Option<String>,
    pub visibility: String,
    pub sync_scope: Option<String>,
    pub sync_generation: i64,
    pub origin: String,
    pub cloud_id: Option<String>,
    pub author_name: Option<String>,
    #[serde(with = "js_date::option")]
    pub pulled_at: Option<DateTime<Utc>>,
    pub payload: Option<Value>,
    pub signature: Option<String>,
    pub tags: Option<Vec<String>>,
}

// ported-from: @horus/db NewMemoryItem
/// Insert shape: every column with a DB default is optional.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewMemoryItem {
    #[serde(default)]
    pub id: String,
    pub kind: String,
    pub claim: String,
    pub scope: String,
    pub source: String,
    #[serde(default)]
    pub evidence: Option<Value>,
    pub confidence: f64,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, with = "js_date::option")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, with = "js_date::option")]
    pub last_verified_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_verified_hash: Option<String>,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub repo: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub sync_scope: Option<String>,
    #[serde(default)]
    pub sync_generation: Option<i64>,
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub cloud_id: Option<String>,
    #[serde(default)]
    pub author_name: Option<String>,
    #[serde(default, with = "js_date::option")]
    pub pulled_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

// ported-from: @horus/db MemoryLink
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryLink {
    pub id: String,
    pub from_memory_id: String,
    pub rel: String,
    pub to_kind: String,
    pub to_ref: String,
    pub to_file_path: Option<String>,
    #[serde(with = "js_date")]
    pub created_at: DateTime<Utc>,
}

// ported-from: @horus/db NewMemoryLink
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewMemoryLink {
    #[serde(default)]
    pub id: String,
    pub from_memory_id: String,
    pub rel: String,
    pub to_kind: String,
    pub to_ref: String,
    #[serde(default)]
    pub to_file_path: Option<String>,
}

// ported-from: @horus/db MemoryAudit
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryAudit {
    pub id: String,
    pub memory_id: String,
    pub action: String,
    pub actor: Value,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub note: Option<String>,
    pub detail: Option<Value>,
    #[serde(with = "js_date")]
    pub at: DateTime<Utc>,
}

// ported-from: @horus/db NewMemoryAudit
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewMemoryAudit {
    pub id: String,
    pub memory_id: String,
    pub action: String,
    pub actor: Value,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub note: Option<String>,
    pub detail: Option<Value>,
}

// ported-from: @horus/db investigations (the columns `getInvestigation` /
// `listInvestigationsWithReports` return)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationRow {
    pub id: String,
    pub title: String,
    #[serde(with = "js_date")]
    pub created_at: DateTime<Utc>,
    pub report: Option<Value>,
}

// ---------------------------------------------------------------------------
// MemoryStorage — the persistence operations memory.rs / memory_view.rs need
// ---------------------------------------------------------------------------

/// Partial column update for `memory_item`. `None` = leave untouched. Nullable columns use
/// `Option<Option<_>>` so an explicit `Some(None)` writes SQL NULL.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryItemPatch {
    pub claim: Option<String>,
    pub confidence: Option<f64>,
    pub payload: Option<Option<Value>>,
    pub status: Option<String>,
    pub visibility: Option<String>,
    pub last_verified_hash: Option<Option<String>>,
    pub last_verified_at: Option<Option<DateTime<Utc>>>,
    pub origin: Option<String>,
    pub cloud_id: Option<Option<String>>,
    pub author_name: Option<Option<String>>,
}

impl MemoryItemPatch {
    pub fn is_empty(&self) -> bool {
        *self == MemoryItemPatch::default()
    }
}

/// Equality filter for `memory_item` rows. `None` = no constraint; a `Vec` is an OR of values.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryItemFilter {
    pub repo: String,
    pub scope: Option<String>,
    pub origin: Option<String>,
    pub visibility: Option<String>,
    pub org_id: Option<String>,
    pub workspace_id: Option<String>,
    pub user_id: Option<String>,
    pub status: Option<Vec<String>>,
    pub kind: Option<Vec<String>>,
}

// ported-from: @horus/db (drizzle queries issued by memory.ts / memory-view.ts)
/// The exact persistence operations the engine's memory modules need. Implemented by the
/// integration layer on the real SQLite store. Every method maps to one drizzle statement in TS.
#[async_trait]
pub trait MemoryStorage: Send + Sync {
    // ---- incident_memory ----
    /// `select * from incident_memory where project = $1 limit $2`.
    async fn select_incident_memory_by_project(&self, project: &str, limit: usize) -> Result<Vec<IncidentMemory>>;
    /// `insert into incident_memory values (...)` (id/createdAt defaulted by the DB).
    async fn insert_incident_memory(&self, row: &NewIncidentMemory) -> Result<()>;

    // ---- memory_item ----
    /// `select * from memory_item where id = $1 limit 1`.
    async fn get_memory_item(&self, id: &str) -> Result<Option<MemoryItem>>;
    /// `insert into memory_item values (...) returning *`. Columns left `None` take their DB
    /// default (`evidence` = `[]`, `status` = `fresh`, `visibility` = `private`,
    /// `syncGeneration` = 1, `origin` = `local`, `createdAt` = now()).
    async fn insert_memory_item(&self, item: &NewMemoryItem) -> Result<MemoryItem>;
    /// `insert into memory_item ... on conflict (id) do update set kind, claim, scope, source, status,
    /// confidence, visibility, evidence, cloudId, authorName, lastVerifiedAt, lastVerifiedHash,
    /// origin, repo, syncScope, pulledAt` (all taken from `item`; other columns keep their stored
    /// value on conflict). On conflict a `None` visibility becomes `team`; on insert it takes the
    /// DB default (`private`) — exactly the TS `onConflictDoUpdate` asymmetry.
    async fn upsert_cached_memory_item(&self, item: &NewMemoryItem) -> Result<()>;
    /// `update memory_item set <patch> where id = $1`.
    async fn update_memory_item(&self, id: &str, patch: &MemoryItemPatch) -> Result<()>;
    /// `select * from memory_item where <filter> order by created_at desc, id asc`.
    async fn query_memory_items(&self, filter: &MemoryItemFilter) -> Result<Vec<MemoryItem>>;
    /// `delete from memory_item where repo = $1 and origin = 'cloud' and id not in ($keep)`
    /// (an empty `keep_ids` deletes every cloud row for the repo). Returns the deleted count.
    async fn delete_cloud_memory_items(&self, repo: &str, keep_ids: &[String]) -> Result<usize>;

    // ---- memory_link ----
    /// `insert into memory_link values (...) returning *` (`createdAt` defaulted by the DB).
    async fn insert_memory_link(&self, link: &NewMemoryLink) -> Result<MemoryLink>;
    /// `select * from memory_link where from_memory_id = $1 and rel = $2 and to_ref = $3 and to_kind = $4 limit 1`.
    async fn find_memory_link(&self, from_memory_id: &str, rel: &str, to_ref: &str, to_kind: &str) -> Result<Option<MemoryLink>>;
    /// `delete from memory_link where from_memory_id = $1 and rel = $2 and to_ref = $3 and to_kind = $4`. Returns the deleted count.
    async fn delete_memory_links(&self, from_memory_id: &str, rel: &str, to_ref: &str, to_kind: &str) -> Result<usize>;
    /// `select * from memory_link where from_memory_id = $1` (any order; the caller sorts).
    async fn links_from(&self, from_memory_id: &str) -> Result<Vec<MemoryLink>>;
    /// `select * from memory_link where to_kind = $1 and to_ref = $2` (any order; the caller sorts).
    async fn links_to(&self, to_kind: &str, to_ref: &str) -> Result<Vec<MemoryLink>>;

    // ---- memory_audit ----
    /// `insert into memory_audit values (...)` (`at` defaulted by the DB).
    async fn insert_memory_audit(&self, row: &NewMemoryAudit) -> Result<()>;
    /// `select * from memory_audit where memory_id = $1 order by at desc, id desc`.
    async fn audit_history(&self, memory_id: &str) -> Result<Vec<MemoryAudit>>;

    // ---- investigations (memory-view) ----
    /// `select id, title, created_at, report from investigations where id = $1 limit 1`.
    async fn get_investigation(&self, id: &str) -> Result<Option<InvestigationRow>>;
    /// `select id, title, created_at, report from investigations [where project = $2] order by created_at desc limit $1`.
    async fn list_investigations_with_reports(&self, limit: usize, project: Option<&str>) -> Result<Vec<InvestigationRow>>;
}

// ---------------------------------------------------------------------------
// Domain enums / value types
// ---------------------------------------------------------------------------

/// Lifecycle status of a MemoryItem (spec §2). `forgotten` is a SOFT delete — row is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryStatus {
    Fresh,
    PossiblyStale,
    Contradicted,
    Deprecated,
    Pinned,
    Forgotten,
}

impl MemoryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryStatus::Fresh => "fresh",
            MemoryStatus::PossiblyStale => "possibly-stale",
            MemoryStatus::Contradicted => "contradicted",
            MemoryStatus::Deprecated => "deprecated",
            MemoryStatus::Pinned => "pinned",
            MemoryStatus::Forgotten => "forgotten",
        }
    }

    pub fn parse(s: &str) -> Option<MemoryStatus> {
        Some(match s {
            "fresh" => MemoryStatus::Fresh,
            "possibly-stale" => MemoryStatus::PossiblyStale,
            "contradicted" => MemoryStatus::Contradicted,
            "deprecated" => MemoryStatus::Deprecated,
            "pinned" => MemoryStatus::Pinned,
            "forgotten" => MemoryStatus::Forgotten,
            _ => return None,
        })
    }
}

/// Visibility scope. `team` activates for cloud/multi-tenant later; M1 stays `private`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Private,
    Team,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Private => "private",
            Visibility::Team => "team",
        }
    }
}

/// Provenance of a stored row (HOR-464 / M4). `local` = authored on this device; `cloud` = a
/// disposable read-cache row pulled from the server-owned team store (READONLY locally).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryOrigin {
    Local,
    Cloud,
}

impl MemoryOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryOrigin::Local => "local",
            MemoryOrigin::Cloud => "cloud",
        }
    }
}

/// Authored-item kind (validated in code, stored as text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryKind {
    CodeFact,
    Contract,
    Decision,
    Pitfall,
    IncidentPattern,
    ConfirmedOutcome,
    /// HOR-432: an auto-captured record of a single investigation. CONTEXT-ONLY.
    Investigation,
}

impl MemoryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryKind::CodeFact => "code-fact",
            MemoryKind::Contract => "contract",
            MemoryKind::Decision => "decision",
            MemoryKind::Pitfall => "pitfall",
            MemoryKind::IncidentPattern => "incident-pattern",
            MemoryKind::ConfirmedOutcome => "confirmed-outcome",
            MemoryKind::Investigation => "investigation",
        }
    }
}

/// Link relation. FROZEN CONTRACT (day-0): the memory-rel vocabulary is exactly
/// supersedes|contradicts|recurs-with. These edges are CONTEXT ONLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rel {
    AboutSymbol,
    AboutFile,
    HasEvidence,
    AboutIncident,
    Supersedes,
    Contradicts,
    RecursWith,
}

impl Rel {
    pub fn as_str(self) -> &'static str {
        match self {
            Rel::AboutSymbol => "about-symbol",
            Rel::AboutFile => "about-file",
            Rel::HasEvidence => "has-evidence",
            Rel::AboutIncident => "about-incident",
            Rel::Supersedes => "supersedes",
            Rel::Contradicts => "contradicts",
            Rel::RecursWith => "recurs-with",
        }
    }
}

/// The memory→memory rel subset — every one of these REQUIRES `toKind:'memory'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryRel {
    Supersedes,
    Contradicts,
    RecursWith,
}

impl MemoryRel {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryRel::Supersedes => "supersedes",
            MemoryRel::Contradicts => "contradicts",
            MemoryRel::RecursWith => "recurs-with",
        }
    }
}

/// How an edge was produced — a NON-OPTIONAL, honest provenance label recorded in the link audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinkDetection {
    #[serde(rename = "manual")]
    Manual,
    #[serde(rename = "auto:recurrence")]
    AutoRecurrence,
    #[serde(rename = "auto:contradiction")]
    AutoContradiction,
    #[serde(rename = "auto:investigation-recurrence")]
    AutoInvestigationRecurrence,
    #[serde(rename = "auto:recurrence-consolidate")]
    AutoRecurrenceConsolidate,
    #[serde(rename = "structural")]
    Structural,
}

impl LinkDetection {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkDetection::Manual => "manual",
            LinkDetection::AutoRecurrence => "auto:recurrence",
            LinkDetection::AutoContradiction => "auto:contradiction",
            LinkDetection::AutoInvestigationRecurrence => "auto:investigation-recurrence",
            LinkDetection::AutoRecurrenceConsolidate => "auto:recurrence-consolidate",
            LinkDetection::Structural => "structural",
        }
    }
}

/// Per-edge traversal direction relative to the queried item (`out` = authored from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkDirection {
    Out,
    In,
}

/// Direction selector for [`MemoryStore::links`]; `both` unions in+out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkDirectionFilter {
    Out,
    In,
    Both,
}

/// A persisted edge annotated with its direction relative to the item it was read for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnnotatedMemoryLink {
    #[serde(flatten)]
    pub link: MemoryLink,
    pub direction: LinkDirection,
}

/// Who/what performed a mutation — recorded verbatim in the append-only audit trail (spec §7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditActor {
    pub kind: AuditActorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditActorKind {
    User,
    Agent,
    System,
}

impl AuditActor {
    pub fn system() -> AuditActor {
        AuditActor { kind: AuditActorKind::System, id: None, name: None }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditCtx {
    pub actor: AuditActor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Options for [`MemoryStore::add_link`]. `detection` defaults to `manual`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AddLinkOpts {
    pub detection: Option<LinkDetection>,
    pub audit: Option<AuditCtx>,
    /// Extra structured provenance merged into the edge's `link` audit detail. Context only.
    pub detail: Option<serde_json::Map<String, Value>>,
}

/// The unordered endpoints + relation that identify a memory→memory edge to remove.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoveLinkSpec {
    pub from_memory_id: String,
    pub rel: MemoryRel,
    pub to_ref: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RemoveLinkOpts {
    pub audit: Option<AuditCtx>,
}

/// The mutable authored fields [`MemoryStore::update`] may refresh IN PLACE. Status is
/// DELIBERATELY not updatable through this path.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryUpdate {
    pub claim: Option<String>,
    pub confidence: Option<f64>,
    /// `Some(None)` clears the payload (TS `payload: null`).
    pub payload: Option<Option<Value>>,
}

/// Options for [`MemoryStore::update`]. `action` defaults to `update`.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateOpts {
    pub audit: AuditCtx,
    pub action: Option<String>,
    pub detection: Option<LinkDetection>,
    pub detail: Option<serde_json::Map<String, Value>>,
}

/// Options for [`MemoryStore::links`]. `direction` defaults to `both`; `rels` filters by relation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinksOpts {
    pub rels: Option<Vec<Rel>>,
    pub direction: Option<LinkDirectionFilter>,
}

/// Statuses excluded from default recall (spec §4 step 3).
pub const HIDDEN_STATUSES: [MemoryStatus; 3] =
    [MemoryStatus::Forgotten, MemoryStatus::Deprecated, MemoryStatus::Contradicted];

/// True when the stored status string is one of [`HIDDEN_STATUSES`].
pub fn is_hidden_status(status: &str) -> bool {
    HIDDEN_STATUSES.iter().any(|s| s.as_str() == status)
}

/// A single piece of evidence attached to a claim (engine evidence shape, spec §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryEvidence {
    pub kind: String,
    pub r#ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
}

/// Recall/listing query for the MemoryItem substrate. `repo` is REQUIRED and fails closed (HOR-46).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryQuery {
    pub repo: String,
    pub scope: Option<String>,
    pub status: Option<Vec<MemoryStatus>>,
    pub visibility: Option<Visibility>,
    pub kind: Option<Vec<MemoryKind>>,
    pub org_id: Option<String>,
    pub workspace_id: Option<String>,
    pub user_id: Option<String>,
    pub origin: Option<MemoryOrigin>,
    pub limit: Option<f64>,
}

/// The legacy incident-recall record (map #4).
pub type MemoryRecord = IncidentMemory;

/// Argument bundle for [`MemoryStore::recall`].
#[derive(Debug, Clone, PartialEq)]
pub struct RecallInput {
    pub tags: Vec<String>,
    pub project: Option<String>,
    pub exclude_investigation_id: Option<String>,
}

/// Argument bundle for [`MemoryStore::load_scoped`].
#[derive(Debug, Clone, PartialEq)]
pub struct LoadScopedInput {
    pub project: String,
    pub tokens: Vec<String>,
}

/// Staleness snapshot passed to [`MemoryStore::verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifySnapshot {
    pub last_verified_hash: Option<String>,
}

/// Provenance passed to [`LocalMemoryStore::mark_promoted`].
#[derive(Debug, Clone, PartialEq)]
pub struct PromoteProvenance {
    pub cloud_id: String,
    pub author_name: Option<String>,
}

// ---------------------------------------------------------------------------
// MemoryStore seam
// ---------------------------------------------------------------------------

/// The durable system-of-record seam. All writes are best-effort at the call site (memory must
/// never block report delivery — spec §7).
#[async_trait]
pub trait MemoryStore: Send + Sync {
    // ---- existing incident-recall seam (map #4) — backed by incident_memory ----
    async fn recall(&self, i: RecallInput) -> Vec<SimilarIncident>;
    async fn record(&self, investigation_id: Option<&str>, report: &InvestigationReport);
    async fn load_scoped(&self, i: LoadScopedInput) -> Vec<MemoryRecord>;

    // ---- MemoryItem substrate — backed by memory_item/_link/_audit ----
    /// Insert an authored item (appends an `add` audit row).
    async fn add(&self, item: NewMemoryItem, audit: &AuditCtx) -> Result<MemoryItem>;
    /// Refresh an existing item's mutable authored fields IN PLACE and append an audit row.
    async fn update(&self, id: &str, patch: MemoryUpdate, opts: UpdateOpts) -> Result<MemoryItem>;
    async fn get(&self, id: &str) -> Result<Option<MemoryItem>>;
    /// Scope/tenancy/status/visibility query. Fails closed on a missing repo (HOR-46).
    async fn query(&self, q: MemoryQuery) -> Result<Vec<MemoryItem>>;
    /// confirm/forget/pin/mark-stale all route here; appends a status-transition audit row.
    async fn set_status(&self, id: &str, status: MemoryStatus, audit: &AuditCtx) -> Result<()>;
    async fn set_visibility(&self, id: &str, v: Visibility, audit: &AuditCtx) -> Result<()>;
    /// Refresh the staleness snapshot (lastVerifiedHash/At) and audit the verification.
    async fn verify(&self, id: &str, snap: VerifySnapshot, audit: &AuditCtx) -> Result<()>;
    /// Insert a typed link and append a `link` audit row. Memory→memory rels require
    /// `toKind:'memory'`, both endpoints to exist and share a repo, and reject self-links;
    /// `recurs-with` is canonicalized + deduped (symmetric).
    async fn add_link(&self, link: NewMemoryLink, opts: Option<AddLinkOpts>) -> Result<MemoryLink>;
    /// Remove a memory→memory edge and append an `unlink` audit row. Returns the number removed.
    async fn remove_link(&self, spec: RemoveLinkSpec, opts: Option<RemoveLinkOpts>) -> Result<usize>;
    /// Traverse an item's edges, each annotated with its direction (default `both`).
    async fn links(&self, id: &str, opts: Option<LinksOpts>) -> Result<Vec<AnnotatedMemoryLink>>;
    /// The append-only audit trail for an item, most-recent-first.
    async fn history(&self, id: &str) -> Result<Vec<MemoryAudit>>;
}

/// The LOCAL store — a `MemoryStore` PLUS the disposable team-memory read-cache primitives
/// (HOR-464 / M4).
#[async_trait]
pub trait LocalMemoryStore: MemoryStore {
    /// Upsert a pulled team item as a disposable cache row (forces `origin='cloud'`, stamps
    /// `pulledAt`), appending exactly ONE `pulled` audit row.
    async fn upsert_cached(&self, item: NewMemoryItem, audit: &AuditCtx) -> Result<MemoryItem>;
    /// Delete the repo's `origin='cloud'` cache rows whose id is NOT in `keep_ids`.
    async fn reconcile_cache(&self, repo: &str, keep_ids: &[String]) -> Result<usize>;
    /// One-way local promotion bookkeeping (HOR-464).
    async fn mark_promoted(&self, id: &str, provenance: PromoteProvenance, audit: &AuditCtx) -> Result<MemoryItem>;
}

// ---------------------------------------------------------------------------
// MemoryVectorIndex seam
// ---------------------------------------------------------------------------

/// A scored candidate proposed by the vector index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorHit {
    pub memory_id: String,
    /// Similarity in 0..1. In M1 (Noop) this is Jaccard token overlap, NOT cosine.
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VectorUpsert {
    pub memory_id: String,
    pub claim: String,
    pub repo: String,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VectorSearch {
    pub query: String,
    pub repo: String,
    pub limit: f64,
}

/// The retrieval collaborator. `search` is best-effort — callers must always be able to fall
/// through to the store's lexical query if the index is empty or unavailable.
#[async_trait]
pub trait MemoryVectorIndex: Send + Sync {
    async fn upsert(&self, i: VectorUpsert) -> Result<()>;
    async fn search(&self, i: VectorSearch) -> Result<Vec<VectorHit>>;
    async fn remove(&self, memory_id: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// NoopVectorIndex — the M1 vector index (Jaccard/scope only, NO embeddings)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct NoopEntry {
    memory_id: String,
    repo: String,
    scope: String,
    tokens: Vec<String>,
}

static TOKEN_SPLIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z0-9]+").unwrap());
static HINT_WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9_]+").unwrap());

/// Tokenize free text into a deterministic, lowercase, de-duplicated token set: split on any
/// non-alphanumeric run, drop empties.
pub fn tokenize(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in TOKEN_SPLIT_RE.split(&lower) {
        if !raw.is_empty() && seen.insert(raw.to_string()) {
            out.push(raw.to_string());
        }
    }
    out
}

/// Result of [`incident_hint_overlap`].
#[derive(Debug, Clone, PartialEq)]
pub struct HintOverlap {
    pub shared: Vec<String>,
    pub overlap: f64,
}

const HINT_STOPWORDS: [&str; 10] =
    ["the", "and", "for", "error", "failed", "failure", "incident", "investigation", "with", "from"];

/// Symptom overlap excludes boilerplate error words; shared by recall and recurrence.
pub fn incident_hint_overlap(left: &str, right: &str) -> HintOverlap {
    // Insertion-ordered set (JS `Set` iteration order) so `shared` is stable.
    fn words(s: &str) -> Vec<String> {
        let lower = s.to_lowercase();
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for m in HINT_WORD_RE.find_iter(&lower) {
            let w = m.as_str();
            if w.len() > 2 && !HINT_STOPWORDS.contains(&w) && seen.insert(w.to_string()) {
                out.push(w.to_string());
            }
        }
        out
    }
    let a = words(left);
    let b = words(right);
    let b_set: HashSet<&str> = b.iter().map(String::as_str).collect();
    let shared: Vec<String> = a.iter().filter(|w| b_set.contains(w.as_str())).cloned().collect();
    let union: BTreeSet<&str> = a.iter().chain(b.iter()).map(String::as_str).collect();
    let overlap = shared.len() as f64 / (union.len().max(1)) as f64;
    HintOverlap { shared, overlap }
}

/// Scope specificity rank — symbol > module > repo > global.
pub fn scope_specificity(scope: &str) -> i32 {
    if scope.starts_with("symbol:") {
        return 3;
    }
    if scope.starts_with("module:") {
        return 2;
    }
    if scope == "repo" {
        return 1;
    }
    0
}

/// In-memory, embedding-free vector index. Ranks stored claims (pre-filtered to the query's repo —
/// HOR-46 fail-closed) by Jaccard token overlap with the query, breaking ties by scope
/// specificity then memoryId for full determinism.
#[derive(Debug, Default)]
pub struct NoopVectorIndex {
    // Insertion order is irrelevant: results are fully sorted before return.
    entries: Mutex<HashMap<String, NoopEntry>>,
}

impl NoopVectorIndex {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MemoryVectorIndex for NoopVectorIndex {
    async fn upsert(&self, i: VectorUpsert) -> Result<()> {
        let entry = NoopEntry {
            memory_id: i.memory_id.clone(),
            repo: i.repo,
            scope: i.scope,
            tokens: tokenize(&i.claim),
        };
        self.entries.lock().unwrap().insert(i.memory_id, entry);
        Ok(())
    }

    async fn search(&self, i: VectorSearch) -> Result<Vec<VectorHit>> {
        let repo = i.repo.trim();
        if repo.is_empty() {
            return Ok(vec![]); // fail closed — no repo identity sees nothing (HOR-46)
        }
        let query_tokens = tokenize(&i.query);
        if query_tokens.is_empty() {
            return Ok(vec![]);
        }
        let mut scored: Vec<(String, f64, i32)> = self
            .entries
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.repo == repo)
            .map(|e| (e.memory_id.clone(), tag_overlap(&query_tokens, &e.tokens), scope_specificity(&e.scope)))
            .filter(|h| h.1 > 0.0)
            .collect();
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.2.cmp(&a.2))
                .then(a.0.cmp(&b.0))
        });
        let limit = if i.limit.is_finite() && i.limit > 0.0 { i.limit.floor() as usize } else { scored.len() };
        Ok(scored
            .into_iter()
            .take(limit)
            .map(|(memory_id, score, _)| VectorHit { memory_id, score })
            .collect())
    }

    async fn remove(&self, memory_id: &str) -> Result<()> {
        self.entries.lock().unwrap().remove(memory_id);
        Ok(())
    }
}
