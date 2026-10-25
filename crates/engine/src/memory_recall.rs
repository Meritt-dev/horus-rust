//! Horus Memory — deterministic recall + read-time freshness (M1, spec §4 + §5 + §8).
//!
//! `recall_memory` is the read path: it takes a repo-scoped query, asks the MemoryStore for the
//! authoritative candidate pool, applies the deterministic STATUS filter, lets the vector index
//! PROPOSE relevance, then sorts by confidence × READ-TIME freshness-decay. Freshness is derived
//! at read time from the `lastVerifiedAt` age plus an optional PULL re-hash of symbol links.
//!
//! HONESTY INVARIANT (spec §8): the result is CONTEXT ONLY. The read-time downgrade to
//! `possibly-stale` is DISPLAY-ONLY and is NOT persisted. The vector index merely proposes; the
//! deterministic filter/rank below is the sole authority on what surfaces.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use indexmap::IndexSet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::code_provider::CodeProvider;
use crate::js;
use crate::memory_store::{
    incident_hint_overlap, is_hidden_status, to_iso_string, MemoryItem, MemoryKind, MemoryQuery, MemoryStore,
    MemoryVectorIndex, Rel, VectorSearch, VectorUpsert,
};
use crate::types::InvestigationInput;

// ---------------------------------------------------------------------------
// Tunables (deterministic, bounded)
// ---------------------------------------------------------------------------

/// Days after which the read-time freshness decay multiplier halves.
pub const FRESHNESS_HALF_LIFE_DAYS: f64 = 30.0;

/// Decay applied when an item has no verify/creation anchor at all (should be rare).
const NO_ANCHOR_DECAY: f64 = 0.5;

/// Multiplier applied to the rank of a `possibly-stale` item — it is downranked, never hidden.
const STALE_RANK_FACTOR: f64 = 0.5;

/// Additive boost so a `pinned` item floats to the top while STILL surfacing its freshness/drift.
const PINNED_RANK_BOOST: f64 = 1.0;

/// Default cap on surfaced results.
const DEFAULT_LIMIT: usize = 10;

const MS_PER_DAY: f64 = 86_400_000.0;

// ---------------------------------------------------------------------------
// Code provider seam (narrow, in-process; best-effort)
// ---------------------------------------------------------------------------

/// The minimal slice of the code graph that read-time staleness needs: the CURRENT content of a
/// code node, addressed by its node id. Returns None when the node is missing/renamed or the host
/// is unreachable — re-hash is then simply skipped (best-effort).
#[async_trait]
pub trait RecallCodeProvider: Send + Sync {
    async fn get_node_content(&self, node_id: &str) -> Option<String>;
}

/// Adapt a full `CodeProvider` into the narrow [`RecallCodeProvider`]. Reads the node's full source
/// body (falling back to the display snippet) and swallows all errors → None.
pub struct CodeProviderRecallAdapter {
    pub code: Arc<dyn CodeProvider>,
}

pub fn recall_code_provider_from_code_provider(code: Arc<dyn CodeProvider>) -> CodeProviderRecallAdapter {
    CodeProviderRecallAdapter { code }
}

#[async_trait]
impl RecallCodeProvider for CodeProviderRecallAdapter {
    async fn get_node_content(&self, node_id: &str) -> Option<String> {
        match self.code.context(node_id).await {
            Ok(ctx) => ctx.source_body.or(ctx.snippet),
            Err(_) => None,
        }
    }
}

/// Hash code-node content the same way for verify-time snapshot and read-time re-hash comparison.
pub fn hash_node_content(content: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(content.as_bytes()))
}

// ---------------------------------------------------------------------------
// Public shapes
// ---------------------------------------------------------------------------

/// A human-facing freshness label derived from the effective status + age.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FreshnessLabel {
    Pinned,
    PossiblyStale,
    Unverified,
    Fresh,
    Recent,
    Aging,
    Stale,
}

/// Read-time freshness for one recalled item. Never persisted — recomputed every recall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryFreshness {
    /// The EFFECTIVE status used for display + ranking (stored status unless drift downgraded it).
    pub status: String,
    /// Days since `lastVerifiedAt` (or `createdAt` when never verified); null when neither exists.
    pub age_days: Option<f64>,
    /// True when the age anchor is a real verification (`lastVerifiedAt`).
    pub verified: bool,
    /// 0..1 decay multiplier (1 = just verified; halves every FRESHNESS_HALF_LIFE_DAYS).
    pub decay: f64,
    /// True when a pull re-hash detected the symbol-linked content changed since last verify.
    pub drift_detected: bool,
    pub label: FreshnessLabel,
}

/// One recalled item, returned as CONTEXT for the human render / evidence step (never scoring).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecalledMemory {
    pub item: MemoryItem,
    /// Retrieval relevance proposed by the vector index (Jaccard in M1); 0 when scope-only.
    pub relevance: f64,
    pub freshness: MemoryFreshness,
    /// Deterministic combined ordering score (confidence × decay, status-adjusted).
    pub rank: f64,
}

/// Recall query: the authoritative `MemoryQuery` filter plus an optional free-text relevance.
#[derive(Debug, Clone, Default)]
pub struct RecallQuery {
    pub query: MemoryQuery,
    /// Free-text query handed to the vector index for relevance proposals (best-effort).
    pub text: Option<String>,
}

#[derive(Default)]
pub struct RecallOptions<'a> {
    /// Vector index (M1: NoopVectorIndex). Best-effort; absence/failure falls through to scope-only.
    pub vector_index: Option<&'a dyn MemoryVectorIndex>,
    /// In-process code provider for read-time pull re-hash of `about-symbol` links.
    pub code: Option<&'a dyn RecallCodeProvider>,
    /// Clock for deterministic freshness-decay. Defaults to now.
    pub now: Option<DateTime<Utc>>,
    /// Half-life (days) for the freshness decay. Defaults to FRESHNESS_HALF_LIFE_DAYS.
    pub half_life_days: Option<f64>,
    /// Cap on surfaced results. Defaults to DEFAULT_LIMIT.
    pub limit: Option<f64>,
}

// ---------------------------------------------------------------------------
// Freshness (read-time)
// ---------------------------------------------------------------------------

fn clamp01(n: f64) -> f64 {
    if !n.is_finite() {
        return 0.0;
    }
    n.clamp(0.0, 1.0)
}

fn label_for(status: &str, age_days: Option<f64>) -> FreshnessLabel {
    if status == "pinned" {
        return FreshnessLabel::Pinned;
    }
    if status == "possibly-stale" {
        return FreshnessLabel::PossiblyStale;
    }
    match age_days {
        None => FreshnessLabel::Unverified,
        Some(d) if d < 7.0 => FreshnessLabel::Fresh,
        Some(d) if d < 30.0 => FreshnessLabel::Recent,
        Some(d) if d < 90.0 => FreshnessLabel::Aging,
        Some(_) => FreshnessLabel::Stale,
    }
}

/// Derive read-time freshness for an item. The age anchor is `lastVerifiedAt` when present, else
/// `createdAt`. Decay is a half-life curve. `effective_status`/`drift_detected` come from the
/// optional pull re-hash and override the stored status for DISPLAY only.
pub fn derive_freshness(
    item: &MemoryItem,
    now: DateTime<Utc>,
    half_life_days: f64,
    effective_status: &str,
    drift_detected: bool,
) -> MemoryFreshness {
    let verified_at = item.last_verified_at;
    let anchor = verified_at.unwrap_or(item.created_at);
    let age_days = Some(((now - anchor).num_milliseconds() as f64 / MS_PER_DAY).max(0.0));

    let hl = if half_life_days > 0.0 { half_life_days } else { FRESHNESS_HALF_LIFE_DAYS };
    let decay = match age_days {
        None => NO_ANCHOR_DECAY,
        Some(d) => clamp01(0.5f64.powf(d / hl)),
    };

    MemoryFreshness {
        status: effective_status.to_string(),
        age_days,
        verified: verified_at.is_some(),
        decay,
        drift_detected,
        label: label_for(effective_status, age_days),
    }
}

// ---------------------------------------------------------------------------
// Pull re-hash (read-time staleness, best-effort)
// ---------------------------------------------------------------------------

/// Re-hash an item's `about-symbol` links against the live code provider and report drift.
/// Returns false when: no code provider, no baseline hash, no symbol links, or nothing resolved.
async fn detect_drift(store: &dyn MemoryStore, item: &MemoryItem, code: Option<&dyn RecallCodeProvider>) -> bool {
    let Some(code) = code else { return false };
    // No baseline snapshot → nothing to compare against; the 'unverified' label carries the doubt.
    let Some(baseline) = item.last_verified_hash.as_deref().filter(|h| !h.is_empty()) else { return false };

    let links = match store
        .links(&item.id, Some(crate::memory_store::LinksOpts { rels: Some(vec![Rel::AboutSymbol]), direction: None }))
        .await
    {
        Ok(l) => l,
        Err(_) => return false,
    };
    if links.is_empty() {
        return false;
    }

    for link in &links {
        let Some(content) = code.get_node_content(&link.link.to_ref).await else { continue };
        if hash_node_content(&content) != baseline {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Recall
// ---------------------------------------------------------------------------

/// Compare two recalled items for a fully deterministic, stable ordering.
fn compare_recalled(a: &RecalledMemory, b: &RecalledMemory) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if b.rank != a.rank {
        return js::cmp_f64(b.rank, a.rank);
    }
    if b.relevance != a.relevance {
        return js::cmp_f64(b.relevance, a.relevance);
    }
    if b.item.confidence != a.item.confidence {
        return js::cmp_f64(b.item.confidence, a.item.confidence);
    }
    let av = a.item.last_verified_at.map(|d| d.timestamp_millis()).unwrap_or(0);
    let bv = b.item.last_verified_at.map(|d| d.timestamp_millis()).unwrap_or(0);
    if bv != av {
        return bv.cmp(&av);
    }
    a.item.id.cmp(&b.item.id).then(Ordering::Equal)
}

/// Recall authored memory for `query`, returned as CONTEXT (spec §4 minimal cut + §5 read-time).
///
/// 1. FILTER — `store.query` (repo fail-closed HOR-46), then drop hidden statuses unless the
///    caller pins a status set.
/// 2. RETRIEVE — the vector index PROPOSES relevance for the free-text query (annotation only).
/// 3. FRESHNESS — read-time decay + a pull re-hash that downgrades a changed-underneath item to
///    `possibly-stale` for DISPLAY (pinned keeps its status).
/// 4. RANK — confidence × decay, `possibly-stale` downranked, `pinned` boosted; deterministic ties.
pub async fn recall_memory(store: &dyn MemoryStore, query: RecallQuery, opts: RecallOptions<'_>) -> anyhow::Result<Vec<RecalledMemory>> {
    let repo = query.query.repo.trim().to_string();
    if repo.is_empty() {
        return Ok(vec![]); // HOR-46 fail-closed — no repo identity sees nothing
    }

    let now = opts.now.unwrap_or_else(Utc::now);
    let half_life_days = opts.half_life_days.unwrap_or(FRESHNESS_HALF_LIFE_DAYS);
    let limit = match opts.limit {
        Some(l) if l > 0.0 => l.floor() as usize,
        _ => DEFAULT_LIMIT,
    };

    // 1. Authoritative candidate pool (no status filter here → apply it deterministically below).
    let q = query.query;
    let pool = store
        .query(MemoryQuery {
            repo: repo.clone(),
            scope: q.scope,
            visibility: q.visibility,
            kind: q.kind,
            org_id: q.org_id,
            workspace_id: q.workspace_id,
            user_id: q.user_id,
            ..Default::default()
        })
        .await?;

    // STATUS filter (deterministic, authoritative).
    let allow: Option<HashSet<&str>> = q.status.as_ref().filter(|s| !s.is_empty()).map(|s| s.iter().map(|x| x.as_str()).collect());
    let filtered: Vec<MemoryItem> = pool
        .into_iter()
        .filter(|it| match &allow {
            Some(allow) => allow.contains(it.status.as_str()),
            None => !is_hidden_status(&it.status),
        })
        .collect();
    if filtered.is_empty() {
        return Ok(vec![]);
    }

    // 2. Vector retrieval — best-effort relevance annotation (never a hard gate in M1).
    let mut relevance_by_id: HashMap<String, f64> = HashMap::new();
    let text = query.text.unwrap_or_default().trim().to_string();
    if let (Some(index), false) = (opts.vector_index, text.is_empty()) {
        if let Ok(hits) = index
            .search(VectorSearch { query: text, repo: repo.clone(), limit: filtered.len().max(1) as f64 })
            .await
        {
            for h in hits {
                relevance_by_id.insert(h.memory_id, h.score);
            }
        }
        // else: best-effort — degrade to scope-only recall
    }

    // 3 + 4. Freshness (with pull re-hash) → rank.
    let mut recalled: Vec<RecalledMemory> = Vec::new();
    for item in filtered {
        let stored = item.status.clone();
        let drift = detect_drift(store, &item, opts.code).await;
        // Pinned is never auto-flipped — it surfaces driftDetected but keeps status (spec §5/§8).
        let effective_status = if drift && stored != "pinned" { "possibly-stale".to_string() } else { stored };

        let freshness = derive_freshness(&item, now, half_life_days, &effective_status, drift);

        let mut rank = clamp01(item.confidence) * freshness.decay;
        if effective_status == "possibly-stale" {
            rank *= STALE_RANK_FACTOR;
        }
        if effective_status == "pinned" {
            rank += PINNED_RANK_BOOST;
        }

        let relevance = relevance_by_id.get(&item.id).copied().unwrap_or(0.0);
        recalled.push(RecalledMemory { item, relevance, freshness, rank });
    }

    recalled.sort_by(compare_recalled);
    recalled.truncate(limit);
    Ok(recalled)
}

// ---------------------------------------------------------------------------
// Startup recall (structured incident context)
// ---------------------------------------------------------------------------

/// Structured trigger context is available before hypotheses exist.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IncidentContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    ConfirmedIncident,
    ExpectedBehavior,
    DuplicateAlert,
    MonitoringError,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Certainty {
    Confirmed,
    Inferred,
}

/// Where a disposition applies. Key order mirrors `readIncidentDisposition`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Applicability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<String>>,
}

impl Applicability {
    /// The subset `loggerOnlyMessage` reads, as an incident context.
    fn as_incident_context(&self) -> IncidentContext {
        IncidentContext {
            fingerprint: self.fingerprint.clone(),
            event_code: self.event_code.clone(),
            error_code: self.error_code.clone(),
            workflow: self.workflow.clone(),
            operation: self.operation.clone(),
            source: self.source.clone(),
            event_id: self.event_id.clone(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentDisposition {
    pub disposition: Disposition,
    pub certainty: Certainty,
    pub source_investigation: String,
    pub source_refs: Vec<String>,
    pub invalidating_conditions: Vec<String>,
    pub checks: Vec<String>,
    pub applicability: Applicability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_cause: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attester: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StartupValidation {
    Unverified,
    Contradicted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupIncident {
    pub memory_id: String,
    pub claim: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    /// `Record<string, string>` in TS; passed through verbatim from the payload.
    pub report_refs: Value,
    pub matching_fields: Vec<String>,
    pub last_verified_at: Option<String>,
    pub environment: String,
    pub outcome: Option<IncidentDisposition>,
    pub checks: Vec<String>,
    pub relevance: f64,
    pub validation: StartupValidation,
    pub contradicting_evidence_ids: Vec<String>,
}

fn string_array(v: Option<&Value>) -> Option<Vec<String>> {
    let arr = v?.as_array()?;
    arr.iter().map(|s| s.as_str().map(str::to_string)).collect()
}

fn opt_str(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}

/// Reject malformed or unproven attestations; strip unknown nested fields before sync/prompt use.
pub fn read_incident_disposition(value: Option<&Value>) -> Option<IncidentDisposition> {
    let v = value?.as_object()?;
    let disposition = match v.get("disposition").map(|d| js_string(d)).as_deref() {
        Some("confirmed-incident") => Disposition::ConfirmedIncident,
        Some("expected-behavior") => Disposition::ExpectedBehavior,
        Some("duplicate-alert") => Disposition::DuplicateAlert,
        Some("monitoring-error") => Disposition::MonitoringError,
        Some("unknown") => Disposition::Unknown,
        _ => return None,
    };
    let certainty = match v.get("certainty").map(|d| js_string(d)).as_deref() {
        Some("confirmed") => Certainty::Confirmed,
        Some("inferred") => Certainty::Inferred,
        _ => return None,
    };
    let source_investigation = opt_str(v.get("sourceInvestigation"))?;
    let source_refs = string_array(v.get("sourceRefs"))?;
    let invalidating_conditions = string_array(v.get("invalidatingConditions"))?;
    let checks = string_array(v.get("checks"))?;
    // `typeof [] === 'object'` in JS: an array passes the gate and reads as an empty applicability.
    let a_val = v.get("applicability").filter(|a| a.is_object() || a.is_array())?;
    let empty = Map::new();
    let a = a_val.as_object().unwrap_or(&empty);

    let attester = opt_str(v.get("attester"));
    let verified_at = opt_str(v.get("verifiedAt"));
    if certainty == Certainty::Confirmed
        && (attester.as_deref().is_none_or(|s| s.trim().is_empty())
            || verified_at.as_deref().is_none_or(|s| !js::date_parse(s).is_finite())
            || source_refs.is_empty())
    {
        return None;
    }

    let applicability = Applicability {
        fingerprint: opt_str(a.get("fingerprint")),
        event_code: opt_str(a.get("eventCode")),
        error_code: opt_str(a.get("errorCode")),
        workflow: opt_str(a.get("workflow")),
        operation: opt_str(a.get("operation")),
        service: opt_str(a.get("service")),
        environment: opt_str(a.get("environment")),
        source: opt_str(a.get("source")),
        event_id: opt_str(a.get("eventId")),
        conditions: string_array(a.get("conditions")),
    };
    Some(IncidentDisposition {
        disposition,
        certainty,
        source_investigation,
        source_refs,
        invalidating_conditions,
        checks,
        applicability,
        actual_cause: opt_str(v.get("actualCause")),
        resolution: opt_str(v.get("resolution")),
        attester,
        verified_at,
    })
}

/// `String(value)` for the disposition/certainty membership checks.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.as_f64().map(js::number_string).unwrap_or_else(|| n.to_string()),
        other => other.to_string(),
    }
}

static WS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static STATUS_TAIL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?::[1-5][0-9]{2})?$").unwrap());

fn truthy(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.is_empty())
}

/// Recognize only the watcher's native-code-only fingerprint, including its legacy errorCode fallback.
fn logger_only_message(incident: &IncidentContext, hint: &str) -> Option<String> {
    let native = incident.event_code.as_deref().or(incident.error_code.as_deref())?;
    if incident.source.as_deref() != Some("elasticsearch")
        || truthy(incident.event_id.as_deref()).is_none()
        || native.is_empty()
        || (truthy(incident.event_code.as_deref()).is_some() && truthy(incident.error_code.as_deref()).is_some())
        || !hint.starts_with(&format!("{native} "))
    {
        return None;
    }
    let tail = incident.fingerprint.as_deref().and_then(|f| f.strip_prefix(native))?;
    if !STATUS_TAIL_RE.is_match(tail) {
        return None;
    }
    let message = WS_RE.replace_all(&hint[native.len()..].trim().to_lowercase(), " ").into_owned();
    let shared = incident_hint_overlap(&message, &message).shared;
    // Generic wrapper messages cannot establish an operation across different logger codes.
    if shared.len() < 2 || shared.iter().all(|w| w == "store" || w == "client") {
        return None;
    }
    Some(format!("{tail}:{message}"))
}

/// Read the structured incident context off an input. Round-trips through JSON so it works whether
/// `InvestigationInput.incident` is the typed struct or the raw `Value` alias.
pub fn incident_context_of(input: &InvestigationInput) -> IncidentContext {
    let Some(v) = input.incident.as_ref().and_then(|i| serde_json::to_value(i).ok()) else { return IncidentContext::default() };
    let Some(o) = v.as_object() else { return IncidentContext::default() };
    // Field-by-field so one non-string value never discards the rest (TS reads each key independently).
    IncidentContext {
        fingerprint: opt_str(o.get("fingerprint")),
        event_code: opt_str(o.get("eventCode")),
        error_code: opt_str(o.get("errorCode")),
        workflow: opt_str(o.get("workflow")),
        operation: opt_str(o.get("operation")),
        incident_id: opt_str(o.get("incidentId")),
        event_id: opt_str(o.get("eventId")),
        occurred_at: opt_str(o.get("occurredAt")),
        source: opt_str(o.get("source")),
        source_url: opt_str(o.get("sourceUrl")),
    }
}

fn ctx_field<'a>(ctx: &'a IncidentContext, key: &str) -> Option<&'a str> {
    match key {
        "fingerprint" => ctx.fingerprint.as_deref(),
        "errorCode" => ctx.error_code.as_deref(),
        "workflow" => ctx.workflow.as_deref(),
        "operation" => ctx.operation.as_deref(),
        _ => None,
    }
}

fn applicability_field<'a>(a: &'a Applicability, key: &str) -> Option<&'a str> {
    match key {
        "fingerprint" => a.fingerprint.as_deref(),
        "errorCode" => a.error_code.as_deref(),
        "workflow" => a.workflow.as_deref(),
        "operation" => a.operation.as_deref(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Typed-hint matching (used when no structured incident field matches)
// ---------------------------------------------------------------------------
// Benchmarked on 207 chronological investigations of a production codebase against two independent relevance label
// sets (5-fold cross-validation): IDF keyword coverage + local nomic similarity of stored hints
// found 83-85% of repeats with 95-96% of unrelated incidents left unmatched; keyword-only (host
// down) 65-66% / 96-98%. The previous word-overlap rule found 39% / 100%.
const HINT_KEYWORD_WEIGHT: f64 = 0.4;
const HINT_COMBINED_MIN: f64 = 0.86;
const HINT_KEYWORD_ONLY_MIN: f64 = 0.45;
/// A shared exact code-shaped identifier carried by at most this many stored hints matches alone.
const RARE_CODE_MAX_HINTS: usize = 2;
const MAX_STORED_HINTS: usize = 20;
const BACKFILL_BUDGET_MS: u128 = 2000;
const HINT_STOP: &[&str] = &[
    "the", "and", "for", "error", "failed", "failure", "incident", "investigation", "with", "from", "are", "not", "that",
    "this", "what", "how", "does", "why", "when", "keeps", "keep", "getting", "was", "were", "has", "have", "into", "after",
    "its", "all", "any", "can", "could", "should", "did", "work", "works", "working",
];

static HINT_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9_]+").unwrap());

fn stem_term(word: &str) -> String {
    for suffix in ["ments", "ment", "ings", "ing", "ed", "es", "s"] {
        if word.len() >= suffix.len() + 4 && word.ends_with(suffix) {
            return word[..word.len() - suffix.len()].to_string();
        }
    }
    word.to_string()
}

/// TS `/[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+/g` (the regex crate has no lookahead).
fn camel_parts(token: &str) -> Vec<&str> {
    let b = token.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        if b[i].is_ascii_uppercase() {
            while i < b.len() && b[i].is_ascii_uppercase() {
                i += 1;
            }
            let run = i - start;
            if i < b.len() && b[i].is_ascii_lowercase() {
                if run >= 2 {
                    // Acronym before a capitalised word (`HTTPServer` → `HTTP`, `Server`).
                    out.push(&token[start..i - 1]);
                    i -= 1;
                    continue;
                }
                while i < b.len() && b[i].is_ascii_lowercase() {
                    i += 1;
                }
            }
        } else if b[i].is_ascii_lowercase() {
            while i < b.len() && b[i].is_ascii_lowercase() {
                i += 1;
            }
        } else if b[i].is_ascii_digit() {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            i += 1;
            continue;
        }
        out.push(&token[start..i]);
    }
    out
}

/// Hint terms: exact code-shaped tokens (`#err4624`) plus stemmed camelCase/snake_case words.
pub fn hint_terms(text: &str) -> IndexSet<String> {
    let mut out = IndexSet::new();
    for m in HINT_TOKEN_RE.find_iter(text) {
        let token = m.as_str();
        if token.len() >= 4 && token.bytes().any(|c| c.is_ascii_digit() || c == b'_') {
            out.insert(format!("#{}", token.to_lowercase()));
        }
        for part in camel_parts(token) {
            let word = part.to_lowercase();
            if word.len() > 2 && !HINT_STOP.contains(&word.as_str()) && !word.bytes().all(|c| c.is_ascii_digit()) {
                out.insert(stem_term(&word));
            }
        }
    }
    out
}

/// Every hint a memory has been investigated under (oldest first), falling back to the latest hint/claim.
pub fn stored_hints(item: &MemoryItem) -> Vec<String> {
    let payload = item.payload.as_ref().and_then(Value::as_object);
    let hints: Vec<String> = payload
        .and_then(|p| p.get("hints"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).filter(|h| !h.trim().is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    if !hints.is_empty() {
        return hints;
    }
    vec![payload.and_then(|p| p.get("hint")).and_then(Value::as_str).unwrap_or(&item.claim).to_string()]
}

/// Append a hint to a memory's rolling hint history (deduplicated, bounded).
pub fn append_hint(previous: Option<&Value>, hint: &str) -> Vec<String> {
    let mut out: IndexSet<String> =
        previous.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
    out.insert(hint.to_string());
    let skip = out.len().saturating_sub(MAX_STORED_HINTS);
    out.into_iter().skip(skip).collect()
}

/// Separate per-repo partition in the local memory vector index, so hint vectors never mix with claims.
pub fn incident_hint_partition(repo: &str) -> String {
    format!("{repo}#incident-hints")
}

fn hint_vector_id(memory_id: &str, hint: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(hint.as_bytes()));
    format!("{memory_id}#hint:{}", &digest[..16])
}

/// Index one hint for embedding recall. Content-addressed and best-effort: never fails.
pub async fn index_incident_hint(index: &dyn MemoryVectorIndex, repo: &str, memory_id: &str, hint: &str) {
    if repo.trim().is_empty() || hint.trim().is_empty() {
        return;
    }
    // ignore failures — embedding recall degrades to keyword matching
    let _ = index
        .upsert(VectorUpsert {
            memory_id: hint_vector_id(memory_id, hint),
            claim: hint.to_string(),
            repo: incident_hint_partition(repo),
            scope: "repo".into(),
        })
        .await;
}

/// Best stored-hint similarity per memory id. Empty on any index failure.
async fn hint_similarities(index: &dyn MemoryVectorIndex, repo: &str, hint: &str) -> HashMap<String, f64> {
    let mut best: HashMap<String, f64> = HashMap::new();
    let hits = index
        .search(VectorSearch { query: hint.to_string(), repo: incident_hint_partition(repo), limit: 200.0 })
        .await
        .unwrap_or_default();
    for hit in hits {
        let memory_id = hit.memory_id.split("#hint:").next().unwrap_or_default().to_string();
        let prev = best.get(&memory_id).copied().unwrap_or(-1.0);
        best.insert(memory_id, prev.max(hit.score));
    }
    best
}

struct HintMatch {
    accepted: bool,
    score: f64,
    shared: Vec<String>,
}

/// Score one memory's stored hints against the query. Keyword coverage is an IDF-weighted f1 of
/// query and stored-hint terms (>=2 shared terms); IDF comes from all stored hints in the pool.
fn match_hint(
    query: &IndexSet<String>,
    hints: &[IndexSet<String>],
    df: &HashMap<String, usize>,
    docs: usize,
    similarity: Option<f64>,
) -> HintMatch {
    let idf = |t: &str| {
        let n = df.get(t).copied().unwrap_or(0) as f64;
        (1.0 + (docs as f64 - n + 0.5) / (n + 0.5)).ln()
    };
    let nonzero = |w: f64| if w == 0.0 { 1.0 } else { w };
    let query_weight = nonzero(query.iter().map(|t| idf(t)).sum());
    let mut keyword: f64 = 0.0;
    let mut rare_code = false;
    let mut shared: BTreeSet<String> = BTreeSet::new();
    for terms in hints {
        let hit: Vec<&String> = query.iter().filter(|t| terms.contains(*t)).collect();
        if hit.iter().any(|t| t.starts_with('#') && t.len() > 6 && df.get(t.as_str()).copied().unwrap_or(0) <= RARE_CODE_MAX_HINTS) {
            rare_code = true;
        }
        if hit.len() < 2 {
            continue;
        }
        shared.extend(hit.iter().map(|t| t.trim_start_matches('#').to_string()));
        let matched: f64 = hit.iter().map(|t| idf(t)).sum();
        let q = matched / query_weight;
        let d = matched / nonzero(terms.iter().map(|t| idf(t)).sum());
        keyword = keyword.max((2.0 * q * d) / (q + d));
    }
    let score = match similarity {
        None => keyword,
        Some(sim) => sim + HINT_KEYWORD_WEIGHT * keyword,
    };
    let min = if similarity.is_none() { HINT_KEYWORD_ONLY_MIN } else { HINT_COMBINED_MIN };
    HintMatch { accepted: rare_code || score >= min, score, shared: shared.into_iter().collect() }
}

#[derive(Clone, Default)]
pub struct StartupRecallOpts<'a> {
    pub sync_scope: Option<String>,
    pub now: Option<DateTime<Utc>>,
    /// Local memory vector index; adds embedding similarity of stored hints when present.
    pub index: Option<&'a dyn MemoryVectorIndex>,
}

/// Bounded, deterministic startup retrieval. No hypothesis/category from the current run is used.
pub async fn recall_startup_incidents(
    store: &dyn MemoryStore,
    input: &InvestigationInput,
    opts: StartupRecallOpts<'_>,
) -> anyhow::Result<Vec<StartupIncident>> {
    let Some(repo) = input.repo.as_deref().filter(|r| !r.trim().is_empty()) else { return Ok(vec![]) };
    let pool = store
        .query(MemoryQuery {
            repo: repo.to_string(),
            kind: Some(vec![MemoryKind::Investigation, MemoryKind::ConfirmedOutcome, MemoryKind::IncidentPattern]),
            limit: Some(200.0),
            ..Default::default()
        })
        .await?;
    let now = opts.now.unwrap_or_else(Utc::now);
    let now_ms = now.timestamp_millis() as f64;
    let input_incident = incident_context_of(input);
    let empty = Map::new();
    let query_terms = hint_terms(&input.hint);
    let hint_terms_by_id: HashMap<&str, Vec<IndexSet<String>>> =
        pool.iter().map(|item| (item.id.as_str(), stored_hints(item).iter().map(|h| hint_terms(h)).collect())).collect();
    let mut df: HashMap<String, usize> = HashMap::new();
    let mut hint_docs = 0usize;
    for docs in hint_terms_by_id.values() {
        for terms in docs {
            hint_docs += 1;
            for t in terms {
                *df.entry(t.clone()).or_default() += 1;
            }
        }
    }
    let similarities = match opts.index {
        Some(index) => hint_similarities(index, repo, &input.hint).await,
        None => HashMap::new(),
    };
    // First run after upgrade: the hint partition is empty, so index the pool for later investigations.
    // Bounded so a slow host can never hold up the investigation; unindexed memories use keyword matching.
    if let Some(index) = opts.index.filter(|_| similarities.is_empty()) {
        let started = std::time::Instant::now();
        'backfill: for item in &pool {
            for hint in stored_hints(item) {
                if started.elapsed().as_millis() > BACKFILL_BUDGET_MS {
                    break 'backfill;
                }
                index_incident_hint(index, repo, &item.id, &hint).await;
            }
        }
    }

    let mut ranked: Vec<StartupIncident> = Vec::new();
    for item in &pool {
        if item.repo != repo
            || is_hidden_status(&item.status)
            || (opts.sync_scope.is_some() && item.sync_scope.is_some() && item.sync_scope != opts.sync_scope)
            || item.created_at > now
        {
            continue;
        }
        let payload = item.payload.as_ref().and_then(Value::as_object).unwrap_or(&empty);
        let outcome = read_incident_disposition(payload.get("outcome"));
        let last_seen_future = payload.get("lastSeenAt").and_then(Value::as_str).is_some_and(|s| js::date_parse(s) > now_ms);
        let verified_future = outcome
            .as_ref()
            .and_then(|o| truthy(o.verified_at.as_deref()))
            .is_some_and(|s| js::date_parse(s) > now_ms);
        if last_seen_future || verified_future {
            continue;
        }
        let default_app = Applicability::default();
        let applicability = outcome.as_ref().map(|o| &o.applicability).unwrap_or(&default_app);
        if let (Some(a), Some(b)) = (truthy(applicability.environment.as_deref()), truthy(input.environment.as_deref())) {
            if a != b {
                continue;
            }
        }
        if let (Some(a), Some(b)) = (truthy(applicability.service.as_deref()), truthy(input.service.as_deref())) {
            if a != b {
                continue;
            }
        }
        let payload_hint = payload.get("hint").and_then(Value::as_str);
        let prior_hint = payload_hint.unwrap_or(&item.claim);
        let prior_message = logger_only_message(&applicability.as_incident_context(), prior_hint);
        // This is useful prior operation context, not proof of a cause or recurrence consolidation.
        let logger_context = item.kind == "investigation"
            && outcome.as_ref().is_some_and(|o| {
                o.disposition == Disposition::Unknown
                    && o.certainty == Certainty::Inferred
                    && truthy(o.actual_cause.as_deref()).is_none()
                    && truthy(o.resolution.as_deref()).is_none()
            })
            && prior_message.is_some()
            && prior_message == logger_only_message(&input_incident, &input.hint);
        let mut fields: Vec<String> = Vec::new();
        let mut mismatch = false;
        for key in ["fingerprint", "errorCode", "workflow", "operation"] {
            if logger_context && (key == "fingerprint" || key == "errorCode") {
                continue;
            }
            let expected = truthy(applicability_field(applicability, key));
            let actual = truthy(ctx_field(&input_incident, key));
            if let (Some(e), Some(a)) = (expected, actual) {
                if e != a {
                    mismatch = true;
                } else {
                    fields.push(key.to_string());
                }
            }
        }
        if mismatch {
            continue;
        }
        let hint = match_hint(
            &query_terms,
            hint_terms_by_id.get(item.id.as_str()).map(Vec::as_slice).unwrap_or_default(),
            &df,
            hint_docs,
            similarities.get(&item.id).copied(),
        );
        if fields.is_empty() && !hint.accepted {
            continue;
        }
        if !hint.shared.is_empty() {
            fields.push(format!("hint:{}", hint.shared.join(",")));
        }
        let refs = match payload.get("reportRefs") {
            Some(v @ (Value::Object(_) | Value::Array(_))) => v.clone(),
            _ => Value::Object(Map::new()),
        };
        let checks = match outcome.as_ref().filter(|o| !o.checks.is_empty()) {
            Some(o) => o.checks.clone(),
            None => vec![format!("Check current evidence for {}", payload_hint.unwrap_or(&item.claim))],
        };
        let relevance = fields.iter().filter(|f| !f.starts_with("hint:")).count() as f64 + hint.score;
        ranked.push(StartupIncident {
            memory_id: item.id.clone(),
            claim: item.claim.clone(),
            incident_id: payload.get("investigationId").and_then(Value::as_str).map(str::to_string),
            report_refs: refs,
            matching_fields: fields,
            last_verified_at: outcome
                .as_ref()
                .and_then(|o| o.verified_at.clone())
                .or_else(|| item.last_verified_at.as_ref().map(to_iso_string)),
            environment: applicability.environment.clone().unwrap_or_else(|| "unknown (legacy)".to_string()),
            outcome,
            checks,
            relevance,
            validation: StartupValidation::Unverified,
            contradicting_evidence_ids: vec![],
        });
    }
    ranked.sort_by(|a, b| js::cmp_f64(b.relevance, a.relevance).then_with(|| js::locale_compare(&a.memory_id, &b.memory_id)));
    let mut seen: HashSet<String> = HashSet::new();
    let out: Vec<StartupIncident> = ranked
        .into_iter()
        .filter(|c| {
            let origin = c.outcome.as_ref().map(|o| &o.applicability);
            let mut keys = vec![c.incident_id.clone().unwrap_or_else(|| c.claim.to_lowercase())];
            if let Some(o) = origin {
                if let (Some(source), Some(event_id)) = (truthy(o.source.as_deref()), truthy(o.event_id.as_deref())) {
                    keys.push(serde_json::to_string(&[source, event_id]).unwrap_or_default());
                }
            }
            if keys.iter().any(|k| seen.contains(k)) {
                return false;
            }
            seen.extend(keys);
            true
        })
        .take(3)
        .collect();
    Ok(out)
}
