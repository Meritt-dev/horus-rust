//! HOR-18 — Deterministic incident memory & pattern recognition.
//!
//! Stores past investigations as tagged + signed memory rows, and recalls similar past incidents
//! via Jaccard overlap on tags. NO vectors / embeddings. Past incidents are CONTEXT ONLY — they
//! must never override current evidence.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::memory_store::{
    AddLinkOpts, AnnotatedMemoryLink, AuditActor, AuditCtx, IncidentMemory, LinkDirection, LinkDirectionFilter,
    LinksOpts, LoadScopedInput, LocalMemoryStore, MemoryAudit, MemoryItem, MemoryItemFilter, MemoryItemPatch,
    MemoryLink, MemoryQuery, MemoryRecord, MemoryStatus, MemoryStorage, MemoryStore, MemoryUpdate, NewIncidentMemory,
    NewMemoryAudit, NewMemoryItem, NewMemoryLink, PromoteProvenance, RecallInput, RemoveLinkOpts, RemoveLinkSpec,
    UpdateOpts, VerifySnapshot, Visibility,
};
use crate::types::InvestigationReport;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimilarIncident {
    pub investigation_id: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    /// Jaccard overlap score (0..1).
    pub overlap: f64,
    pub shared_tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tag / signature derivation
// ---------------------------------------------------------------------------

/// Derive the "module area" from a file path: up to the first 3 path segments.
/// e.g. 'src/modules/zoho/zoho.service.ts' -> 'src/modules/zoho'; 'a.ts' -> 'a.ts'.
pub fn module_area(file_path: &str) -> String {
    if file_path.is_empty() {
        return String::new();
    }
    let stripped = file_path.strip_prefix('/').unwrap_or(file_path);
    let parts: Vec<&str> = stripped.split('/').collect();
    // Guard: if the path has 3 or fewer segments, return the whole thing.
    if parts.len() <= 3 {
        return file_path.to_string();
    }
    parts[..3].join("/")
}

/// Derive a deterministic, lowercase tag set from an InvestigationReport: queue names from
/// timeline boundary crossings, top hypothesis category, module area of the first seed, service.
pub fn derive_tags(r: &InvestigationReport) -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();

    for bc in &r.timeline.boundary_crossings {
        if !bc.queue_name.is_empty() {
            raw.push(bc.queue_name.clone());
        }
    }

    if let Some(top) = r.hypotheses.first() {
        if !top.category.is_empty() {
            raw.push(top.category.clone());
        }
    }

    if let Some(seed) = r.seeds.first() {
        if !seed.file_path.is_empty() {
            let area = module_area(&seed.file_path);
            if !area.is_empty() {
                raw.push(area);
            }
        }
    }

    if let Some(service) = r.input.service.as_deref() {
        if !service.is_empty() {
            raw.push(service.to_string());
        }
    }

    let mut seen = HashSet::new();
    let mut tags = Vec::new();
    for t in raw {
        let lower = t.to_lowercase();
        if !lower.is_empty() && seen.insert(lower.clone()) {
            tags.push(lower);
        }
    }
    tags
}

/// Derive a compact, deterministic signature string: '<area>|<topHypCategory>|<sortedQueues>'.
pub fn derive_signature(r: &InvestigationReport) -> String {
    let area = r.seeds.first().map(|s| module_area(&s.file_path)).unwrap_or_default();
    let top_hyp_category = r.hypotheses.first().map(|h| h.category.clone()).unwrap_or_default();
    let mut queues: Vec<&str> = r
        .timeline
        .boundary_crossings
        .iter()
        .map(|bc| bc.queue_name.as_str())
        .filter(|q| !q.is_empty())
        .collect();
    queues.sort();
    format!("{area}|{top_hyp_category}|{}", queues.join(","))
}

/// Hypothesis-category tags — generic, shared by many unrelated incidents.
const GENERIC_HYPOTHESIS_TAGS: [&str; 6] = [
    "queue-backlog",
    "worker-slowdown",
    "external-api-latency",
    "deployment-regression",
    "retry-storm",
    "infrastructure",
];

static ENV_TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|-)(prod|production|staging|dev|local)$").unwrap());

/// True for tags too generic to imply two incidents are actually related.
pub fn is_generic_tag(tag: &str) -> bool {
    GENERIC_HYPOTHESIS_TAGS.contains(&tag) || ENV_TAG_RE.is_match(tag)
}

// ---------------------------------------------------------------------------
// Jaccard tag overlap
// ---------------------------------------------------------------------------

/// Jaccard similarity: |intersection| / |union|, clamped to 0..1. Returns 0 when the union is empty.
pub fn tag_overlap(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let set_a: HashSet<&str> = a.iter().map(String::as_str).collect();
    let set_b: HashSet<&str> = b.iter().map(String::as_str).collect();
    let intersection = set_a.iter().filter(|t| set_b.contains(*t)).count();
    let union = set_a.len() + set_b.len() - intersection;
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}

// ---------------------------------------------------------------------------
// Recall
// ---------------------------------------------------------------------------

/// Read up to ~200 incident_memory rows scoped to the given project and return the top-3 most
/// similar (by Jaccard overlap) that are NOT the current investigation. Fails closed when
/// project is null (HOR-46). Past incidents are CONTEXT ONLY.
pub async fn recall_similar(
    db: &dyn MemoryStorage,
    tags: &[String],
    exclude_investigation_id: Option<&str>,
    project: Option<&str>,
) -> Vec<SimilarIncident> {
    let p = match project.map(str::trim) {
        Some(p) if !p.is_empty() => p,
        _ => return vec![],
    };

    let rows = match db.select_incident_memory_by_project(p, 200).await {
        Ok(rows) => rows,
        Err(_) => return vec![],
    };

    let tag_set: HashSet<&str> = tags.iter().map(String::as_str).collect();
    let mut candidates: Vec<SimilarIncident> = Vec::new();
    for row in &rows {
        if let Some(excl) = exclude_investigation_id {
            if row.investigation_id.as_deref() == Some(excl) {
                continue;
            }
        }
        // Defense in depth: skip rows from other projects even if the DB query leaked them.
        if row.project.as_deref() != Some(p) {
            continue;
        }
        let row_tags: &[String] = row.tags.as_deref().unwrap_or(&[]);
        let overlap = tag_overlap(tags, row_tags);
        if overlap <= 0.0 {
            continue;
        }
        let shared_tags: Vec<String> = row_tags.iter().filter(|t| tag_set.contains(t.as_str())).cloned().collect();
        // A match is only meaningful if it shares a SPECIFIC tag (HOR-39).
        if shared_tags.iter().all(|t| is_generic_tag(t)) {
            continue;
        }
        candidates.push(SimilarIncident {
            investigation_id: row.investigation_id.clone(),
            title: row.title.clone(),
            summary: row.summary.clone(),
            overlap,
            shared_tags,
        });
    }

    // Deduplicate by title, keeping the best-overlap representative (first-seen position wins,
    // like a JS Map), then take the top 3 distinct incidents.
    let mut order: Vec<String> = Vec::new();
    let mut by_title: HashMap<String, SimilarIncident> = HashMap::new();
    for c in candidates {
        match by_title.get(&c.title) {
            Some(existing) if c.overlap <= existing.overlap => {}
            Some(_) => {
                by_title.insert(c.title.clone(), c);
            }
            None => {
                order.push(c.title.clone());
                by_title.insert(c.title.clone(), c);
            }
        }
    }
    let mut out: Vec<SimilarIncident> = order.into_iter().filter_map(|t| by_title.remove(&t)).collect();
    out.sort_by(|a, b| crate::js::cmp_f64(b.overlap, a.overlap));
    out.truncate(3);
    out
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Persist a memory row for the current investigation. Non-fatal — a DB failure here never
/// surfaces and never prevents the report from being returned. Skips when no project (HOR-46).
pub async fn store_incident_memory(db: &dyn MemoryStorage, investigation_id: Option<&str>, r: &InvestigationReport) {
    let project = match r.input.repo.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => p,
        _ => return,
    };
    let top_hyp = r.hypotheses.first();
    let row = NewIncidentMemory {
        investigation_id: investigation_id.map(str::to_string),
        project: Some(project.to_string()),
        title: r.input.hint.clone(),
        summary: Some(r.summary.clone()),
        signature: Some(derive_signature(r)),
        tags: Some(derive_tags(r)),
        payload: Some(json!({
            "confidence": r.confidence,
            "topHypothesis": top_hyp.map(|h| Value::String(h.category.clone())).unwrap_or(Value::Null),
            "queues": r.timeline.boundary_crossings.iter().map(|b| b.queue_name.clone()).collect::<Vec<_>>(),
        })),
    };
    // Non-fatal — institutional memory must never prevent report delivery.
    let _ = db.insert_incident_memory(&row).await;
}

// ---------------------------------------------------------------------------
// PII / secret gate (spec §7 privacy)
// ---------------------------------------------------------------------------

/// Raised when a claim contains an obvious secret/credential. The add/confirm path REJECTS rather
/// than silently storing — credentials must never enter a durable, syncable memory claim.
#[derive(Debug, Clone, thiserror::Error)]
#[error("refusing to store memory claim: detected {kind}")]
pub struct MemorySecretError {
    pub kind: String,
}

/// Raised when a local mutation targets a cloud-owned cache row (HOR-464 / M4).
#[derive(Debug, Clone, thiserror::Error)]
#[error("refusing to mutate a cloud-owned cached memory item ({id}); the team store owns it — re-promote to change it")]
pub struct MemoryCacheReadonlyError {
    pub id: String,
}

/// Obvious-secret detectors for the claim gate. Only high-confidence credentials/keys reject;
/// PII like bare emails/IPs is intentionally NOT rejected here.
static CLAIM_SECRET_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        ("private-key", Regex::new(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----").unwrap()),
        ("jwt", Regex::new(r"(?-u:\b)eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?-u:\b)").unwrap()),
        ("aws-key", Regex::new(r"(?-u:\b)(?:AKIA|ASIA)[0-9A-Z]{16}(?-u:\b)").unwrap()),
        ("gcp-key", Regex::new(r"(?-u:\b)AIza[0-9A-Za-z_-]{35}(?-u:\b)").unwrap()),
        ("slack-token", Regex::new(r"(?-u:\b)xox[baprs]-[0-9A-Za-z-]{10,}(?-u:\b)").unwrap()),
        ("github-token", Regex::new(r"(?-u:\b)gh[pousr]_[0-9A-Za-z]{36,}(?-u:\b)").unwrap()),
        ("auth-header", Regex::new(r"(?i)authorization\s*[=:]\s*(?:bearer|basic)\s+\S+").unwrap()),
        (
            "credential-kv",
            Regex::new(r#"(?i)"?(?:password|passwd|secret|token|api[_-]?key|apikey|x-api-key)"?\s*[=:]\s*"?[^"',\s)>]+"#).unwrap(),
        ),
        (
            "connection-string-creds",
            Regex::new(r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?)://[^:@/\s]+:[^@\s]+@").unwrap(),
        ),
        ("card-number", Regex::new(r"(?-u:\b)[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}(?-u:\b)").unwrap()),
    ]
});

/// Return a label for the first obvious secret found in `claim`, or None when it is clean.
pub fn detect_claim_secret(claim: &str) -> Option<&'static str> {
    CLAIM_SECRET_PATTERNS.iter().find(|(_, re)| re.is_match(claim)).map(|(label, _)| *label)
}

fn assert_claim_clean(claim: &str) -> Result<()> {
    match detect_claim_secret(claim) {
        Some(kind) => Err(MemorySecretError { kind: kind.to_string() }.into()),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// create_local_memory_store — the MemoryStorage-backed impl of the MemoryStore seam
// ---------------------------------------------------------------------------

/// Stable, prefixed id for a memory row. A UUID suffices.
fn gen_id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::new_v4())
}

/// M1 link relations with concrete code/incident/evidence resolvers (any `toKind`).
const M1_RELS: [&str; 4] = ["about-symbol", "about-file", "has-evidence", "about-incident"];

/// M3 memory→memory relations (FROZEN day-0 vocabulary). Each REQUIRES `toKind:'memory'`.
const MEMORY_RELS: [&str; 3] = ["supersedes", "contradicts", "recurs-with"];

/// True for the symmetric memory rel that gets canonicalized + deduped on write.
fn is_symmetric_rel(rel: &str) -> bool {
    rel == "recurs-with"
}

/// Kinds whose items carry an incident-family `signature`/`tags`. Only these participate in
/// recurrence detection.
const INCIDENT_DERIVED_KINDS: [&str; 3] = ["confirmed-outcome", "incident-pattern", "investigation"];

static ALL_DELIMITER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\|*$").unwrap());

/// Trim a stored signature; treat blank / all-delimiter ("", "||", "|") as absent.
fn normalize_stored_signature(sig: Option<&str>) -> Option<String> {
    let s = sig.unwrap_or("").trim();
    if s.is_empty() || ALL_DELIMITER_RE.is_match(s) {
        return None;
    }
    Some(s.to_string())
}

/// Lowercase + dedupe + drop-empty stored tags; an empty result is stored as null.
fn normalize_stored_tags(tags: Option<&[String]>) -> Option<Vec<String>> {
    let tags = tags?;
    if tags.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for t in tags {
        let lower = t.trim().to_lowercase();
        if !lower.is_empty() && seen.insert(lower.clone()) {
            out.push(lower);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Map a target status onto the audit action that produced it (user-facing provenance).
fn status_action(status: MemoryStatus) -> &'static str {
    match status {
        MemoryStatus::Forgotten => "forget",
        MemoryStatus::Pinned => "pin",
        MemoryStatus::PossiblyStale => "mark-stale",
        MemoryStatus::Deprecated => "deprecate",
        MemoryStatus::Contradicted => "contradict",
        MemoryStatus::Fresh => "confirm",
    }
}

fn actor_value(actor: &AuditActor) -> Value {
    serde_json::to_value(actor).unwrap_or(Value::Null)
}

struct AuditRow<'a> {
    memory_id: &'a str,
    action: &'a str,
    actor: &'a AuditActor,
    from_status: Option<&'a str>,
    to_status: Option<&'a str>,
    note: Option<&'a str>,
    detail: Option<Value>,
}

/// Options for [`create_local_memory_store`].
#[derive(Debug, Clone, Default)]
pub struct LocalMemoryStoreOpts {
    pub sync_scope: Option<String>,
}

/// Local implementation of the `MemoryStore` seam over a [`MemoryStorage`].
///
/// Invariants:
///   - HOR-46 fail-closed: every `memory_item` requires a `repo`; `query` returns nothing for a
///     blank repo and filters defensively against leaking another repo's rows.
///   - Soft-forget: `set_status(id, Forgotten)` flips status only — the row is retained.
///   - Append-only audit: every mutation writes a `memory_audit` row.
///   - PII/secret gate (spec §7): `add` and `verify` reject claims carrying obvious secrets.
///   - Confirmed-outcome stays `private`: never auto-promoted to team.
///
/// HONESTY INVARIANT (spec §8): storage only. Nothing here is read by the scoring path.
pub struct LocalStore {
    db: Arc<dyn MemoryStorage>,
    sync_scope: Option<String>,
}

pub fn create_local_memory_store(db: Arc<dyn MemoryStorage>, opts: LocalMemoryStoreOpts) -> LocalStore {
    LocalStore { db, sync_scope: opts.sync_scope }
}

impl LocalStore {
    fn in_scope(&self, row_scope: Option<&str>) -> bool {
        match &self.sync_scope {
            None => true,
            Some(s) => row_scope.is_none() || row_scope == Some(s.as_str()),
        }
    }

    async fn get_by_id(&self, id: &str) -> Result<Option<MemoryItem>> {
        Ok(self.db.get_memory_item(id).await?.filter(|row| self.in_scope(row.sync_scope.as_deref())))
    }

    async fn append_audit(&self, a: AuditRow<'_>) -> Result<()> {
        self.db
            .insert_memory_audit(&NewMemoryAudit {
                id: gen_id("aud"),
                memory_id: a.memory_id.to_string(),
                action: a.action.to_string(),
                actor: actor_value(a.actor),
                from_status: a.from_status.map(str::to_string),
                to_status: a.to_status.map(str::to_string),
                note: a.note.map(str::to_string),
                detail: a.detail,
            })
            .await
    }

    async fn require(&self, id: &str) -> Result<MemoryItem> {
        self.get_by_id(id).await?.ok_or_else(|| anyhow!("memory item not found: {id}"))
    }
}

#[async_trait]
impl MemoryStore for LocalStore {
    // ---- existing incident-recall seam (map #4) — backed by incident_memory ----
    async fn recall(&self, i: RecallInput) -> Vec<SimilarIncident> {
        recall_similar(self.db.as_ref(), &i.tags, i.exclude_investigation_id.as_deref(), i.project.as_deref()).await
    }

    async fn record(&self, investigation_id: Option<&str>, report: &InvestigationReport) {
        store_incident_memory(self.db.as_ref(), investigation_id, report).await
    }

    async fn load_scoped(&self, i: LoadScopedInput) -> Vec<MemoryRecord> {
        load_scoped_memory(self.db.as_ref(), &i.project, &i.tokens).await
    }

    // ---- MemoryItem substrate — backed by memory_item/_link/_audit ----
    async fn add(&self, item: NewMemoryItem, audit: &AuditCtx) -> Result<MemoryItem> {
        // Gate first — a claim carrying a secret must never be persisted (spec §7).
        assert_claim_clean(&item.claim)?;

        let repo = item.repo.trim().to_string();
        if repo.is_empty() {
            return Err(anyhow!("memory_item requires a repo (HOR-46 fail-closed)"));
        }

        let id = match item.id.trim() {
            "" => gen_id("mem"),
            s => s.to_string(),
        };
        let status = item.status.clone().unwrap_or_else(|| "fresh".to_string());
        // Confirmed-outcome items stay private; never auto-promote to team (spec §7).
        let is_confirmed_outcome = item.source == "confirmed-outcome" || item.kind == "confirmed-outcome";
        let visibility = if is_confirmed_outcome {
            "private".to_string()
        } else {
            item.visibility.clone().unwrap_or_else(|| "private".to_string())
        };

        // Incident-family recall keys are populated at WRITE for incident-derived kinds only.
        let is_incident_derived = INCIDENT_DERIVED_KINDS.contains(&item.kind.as_str());
        let signature = if is_incident_derived { normalize_stored_signature(item.signature.as_deref()) } else { None };
        let tags = if is_incident_derived { normalize_stored_tags(item.tags.as_deref()) } else { None };

        let row = self
            .db
            .insert_memory_item(&NewMemoryItem {
                id: id.clone(),
                repo,
                status: Some(status.clone()),
                visibility: Some(visibility),
                signature,
                tags,
                ..item
            })
            .await?;

        self.append_audit(AuditRow {
            memory_id: &id,
            action: "add",
            actor: &audit.actor,
            from_status: None,
            to_status: Some(&status),
            note: audit.note.as_deref(),
            detail: None,
        })
        .await?;
        Ok(row)
    }

    async fn update(&self, id: &str, patch: MemoryUpdate, opts: UpdateOpts) -> Result<MemoryItem> {
        let current = self.require(id).await?;
        // A cloud-owned cache row is server-authoritative — refuse a local edit (HOR-464).
        if current.origin == "cloud" {
            return Err(MemoryCacheReadonlyError { id: id.to_string() }.into());
        }

        // HONESTY: `status` is NEVER updatable here.
        let mut set = MemoryItemPatch::default();
        if let Some(claim) = patch.claim {
            assert_claim_clean(&claim)?; // a refreshed claim is re-scanned for secrets (spec §7)
            set.claim = Some(claim);
        }
        if let Some(c) = patch.confidence {
            set.confidence = Some(c);
        }
        if let Some(p) = patch.payload {
            set.payload = Some(p);
        }
        if !set.is_empty() {
            self.db.update_memory_item(id, &set).await?;
        }

        let mut detail = Map::new();
        if let Some(d) = opts.detection {
            detail.insert("detection".into(), Value::String(d.as_str().to_string()));
        }
        if let Some(extra) = opts.detail {
            for (k, v) in extra {
                detail.insert(k, v);
            }
        }
        self.append_audit(AuditRow {
            memory_id: id,
            action: opts.action.as_deref().unwrap_or("update"),
            actor: &opts.audit.actor,
            from_status: None,
            to_status: None,
            note: opts.audit.note.as_deref(),
            detail: Some(Value::Object(detail)),
        })
        .await?;

        self.get_by_id(id).await?.ok_or_else(|| anyhow!("memory item vanished during update: {id}"))
    }

    async fn get(&self, id: &str) -> Result<Option<MemoryItem>> {
        self.get_by_id(id).await
    }

    async fn query(&self, q: MemoryQuery) -> Result<Vec<MemoryItem>> {
        let repo = q.repo.trim().to_string();
        if repo.is_empty() {
            return Ok(vec![]); // HOR-46 fail-closed — no repo identity sees nothing
        }
        let filter = MemoryItemFilter {
            repo: repo.clone(),
            scope: q.scope,
            origin: q.origin.map(|o| o.as_str().to_string()),
            visibility: q.visibility.map(|v| v.as_str().to_string()),
            org_id: q.org_id,
            workspace_id: q.workspace_id,
            user_id: q.user_id,
            status: q.status.filter(|s| !s.is_empty()).map(|s| s.iter().map(|x| x.as_str().to_string()).collect()),
            kind: q.kind.filter(|k| !k.is_empty()).map(|k| k.iter().map(|x| x.as_str().to_string()).collect()),
        };
        // Deterministic: newest first, id as the stable tie-break (ordered by the storage).
        let mut rows = self.db.query_memory_items(&filter).await?;
        // Defense in depth (never leak another repo).
        rows.retain(|r| r.repo == repo && self.in_scope(r.sync_scope.as_deref()));
        if let Some(limit) = q.limit {
            if limit > 0.0 {
                rows.truncate(limit.floor() as usize);
            }
        }
        Ok(rows)
    }

    async fn set_status(&self, id: &str, status: MemoryStatus, audit: &AuditCtx) -> Result<()> {
        let current = self.require(id).await?;
        if current.origin == "cloud" {
            return Err(MemoryCacheReadonlyError { id: id.to_string() }.into());
        }
        self.db
            .update_memory_item(id, &MemoryItemPatch { status: Some(status.as_str().to_string()), ..Default::default() })
            .await?;
        self.append_audit(AuditRow {
            memory_id: id,
            action: status_action(status),
            actor: &audit.actor,
            from_status: Some(&current.status),
            to_status: Some(status.as_str()),
            note: audit.note.as_deref(),
            detail: None,
        })
        .await
    }

    async fn set_visibility(&self, id: &str, v: Visibility, audit: &AuditCtx) -> Result<()> {
        let current = self.require(id).await?;
        if current.origin == "cloud" {
            return Err(MemoryCacheReadonlyError { id: id.to_string() }.into());
        }
        self.db
            .update_memory_item(id, &MemoryItemPatch { visibility: Some(v.as_str().to_string()), ..Default::default() })
            .await?;
        let default_note = format!("visibility -> {}", v.as_str());
        self.append_audit(AuditRow {
            memory_id: id,
            action: "set-visibility",
            actor: &audit.actor,
            from_status: None,
            to_status: None,
            note: Some(audit.note.as_deref().unwrap_or(&default_note)),
            detail: None,
        })
        .await
    }

    async fn verify(&self, id: &str, snap: VerifySnapshot, audit: &AuditCtx) -> Result<()> {
        let current = self.require(id).await?;
        // Re-scan at confirm time (defense in depth — covers items added before the gate existed).
        assert_claim_clean(&current.claim)?;
        // Confirm resets possibly-stale -> fresh (spec §5). Other statuses are left untouched.
        let next_status = if current.status == "possibly-stale" { "fresh".to_string() } else { current.status.clone() };
        self.db
            .update_memory_item(
                id,
                &MemoryItemPatch {
                    last_verified_hash: Some(snap.last_verified_hash),
                    last_verified_at: Some(Some(Utc::now())),
                    status: Some(next_status.clone()),
                    ..Default::default()
                },
            )
            .await?;
        self.append_audit(AuditRow {
            memory_id: id,
            action: "verify",
            actor: &audit.actor,
            from_status: Some(&current.status),
            to_status: Some(&next_status),
            note: audit.note.as_deref(),
            detail: None,
        })
        .await
    }

    async fn add_link(&self, link: NewMemoryLink, opts: Option<AddLinkOpts>) -> Result<MemoryLink> {
        let opts = opts.unwrap_or_default();
        let rel = link.rel.as_str();
        let is_memory_rel = MEMORY_RELS.contains(&rel);

        // Gate: an M1 rel (any toKind) OR a memory rel that explicitly targets another memory item.
        if !M1_RELS.contains(&rel) && !(is_memory_rel && link.to_kind == "memory") {
            return Err(anyhow!("unsupported memory_link rel in M1: {rel} (toKind={})", link.to_kind));
        }

        let mut from_id = link.from_memory_id.clone();
        let mut to_ref = link.to_ref.clone();

        // Memory→memory edges are validated against the live store: both endpoints must exist,
        // share a repo, and not be a self-link. `recurs-with` is canonicalized + deduped.
        if is_memory_rel {
            if from_id == to_ref {
                return Err(anyhow!("memory_link rejects a self-link: {rel} {from_id} -> {to_ref}"));
            }
            let from_item =
                self.get_by_id(&from_id).await?.ok_or_else(|| anyhow!("memory_link from item not found: {from_id}"))?;
            let to_item = self.get_by_id(&to_ref).await?.ok_or_else(|| anyhow!("memory_link to item not found: {to_ref}"))?;
            if from_item.repo != to_item.repo {
                return Err(anyhow!("memory_link rejects a cross-repo edge: {} -> {}", from_item.repo, to_item.repo));
            }
            if is_symmetric_rel(rel) {
                // Canonicalize the unordered pair so (a,b) and (b,a) collapse to one stored row.
                if from_id > to_ref {
                    std::mem::swap(&mut from_id, &mut to_ref);
                }
                // Dedupe: if the canonical edge already exists, return it rather than inserting a twin.
                if let Some(dup) = self.db.find_memory_link(&from_id, rel, &to_ref, "memory").await? {
                    return Ok(dup);
                }
            }
        }

        let id = match link.id.trim() {
            "" => gen_id("lnk"),
            s => s.to_string(),
        };
        let row = self
            .db
            .insert_memory_link(&NewMemoryLink { id, from_memory_id: from_id, to_ref, ..link })
            .await?;

        // Append a `link` audit row keyed to the FROM item — honest provenance for every edge.
        let audit_note = opts.audit.as_ref().and_then(|a| a.note.clone());
        let mut detail = Map::new();
        detail.insert("rel".into(), Value::String(row.rel.clone()));
        detail.insert("toKind".into(), Value::String(row.to_kind.clone()));
        detail.insert("toRef".into(), Value::String(row.to_ref.clone()));
        detail.insert("detection".into(), Value::String(opts.detection.unwrap_or(crate::memory_store::LinkDetection::Manual).as_str().to_string()));
        if let Some(note) = audit_note.as_deref().filter(|n| !n.is_empty()) {
            detail.insert("note".into(), Value::String(note.to_string()));
        }
        // Extra structured provenance — recorded context only (spec §8).
        if let Some(extra) = opts.detail {
            for (k, v) in extra {
                detail.insert(k, v);
            }
        }
        let system = AuditActor::system();
        let actor = opts.audit.as_ref().map(|a| &a.actor).unwrap_or(&system);
        self.append_audit(AuditRow {
            memory_id: &row.from_memory_id,
            action: "link",
            actor,
            from_status: None,
            to_status: None,
            note: audit_note.as_deref(),
            detail: Some(Value::Object(detail)),
        })
        .await?;
        Ok(row)
    }

    async fn remove_link(&self, spec: RemoveLinkSpec, opts: Option<RemoveLinkOpts>) -> Result<usize> {
        let opts = opts.unwrap_or_default();
        let rel = spec.rel.as_str();
        let mut from_id = spec.from_memory_id;
        let mut to_ref = spec.to_ref;
        // `recurs-with` is stored canonically (smaller id first) — canonicalize the query the same way.
        if is_symmetric_rel(rel) && from_id > to_ref {
            std::mem::swap(&mut from_id, &mut to_ref);
        }

        let deleted = self.db.delete_memory_links(&from_id, rel, &to_ref, "memory").await?;
        // No matching edge → a no-op (not an error), and nothing is audited.
        if deleted == 0 {
            return Ok(0);
        }

        let audit_note = opts.audit.as_ref().and_then(|a| a.note.clone());
        let mut detail = Map::new();
        detail.insert("rel".into(), Value::String(rel.to_string()));
        detail.insert("toKind".into(), Value::String("memory".into()));
        detail.insert("toRef".into(), Value::String(to_ref));
        detail.insert("removed".into(), json!(deleted));
        if let Some(note) = audit_note.as_deref().filter(|n| !n.is_empty()) {
            detail.insert("note".into(), Value::String(note.to_string()));
        }
        let system = AuditActor::system();
        let actor = opts.audit.as_ref().map(|a| &a.actor).unwrap_or(&system);
        self.append_audit(AuditRow {
            memory_id: &from_id,
            action: "unlink",
            actor,
            from_status: None,
            to_status: None,
            note: audit_note.as_deref(),
            detail: Some(Value::Object(detail)),
        })
        .await?;
        Ok(deleted)
    }

    async fn links(&self, id: &str, opts: Option<LinksOpts>) -> Result<Vec<AnnotatedMemoryLink>> {
        let opts = opts.unwrap_or_default();
        let direction = opts.direction.unwrap_or(LinkDirectionFilter::Both);
        let rel_filter: Option<Vec<&str>> = opts.rels.as_ref().filter(|r| !r.is_empty()).map(|r| r.iter().map(|x| x.as_str()).collect());
        let keep = |l: &MemoryLink| rel_filter.as_ref().is_none_or(|rels| rels.contains(&l.rel.as_str()));

        let mut out: Vec<AnnotatedMemoryLink> = Vec::new();
        if matches!(direction, LinkDirectionFilter::Out | LinkDirectionFilter::Both) {
            for l in self.db.links_from(id).await? {
                if keep(&l) {
                    out.push(AnnotatedMemoryLink { link: l, direction: LinkDirection::Out });
                }
            }
        }
        if matches!(direction, LinkDirectionFilter::In | LinkDirectionFilter::Both) {
            // Incoming = a memory→memory edge pointing AT this item.
            for l in self.db.links_to("memory", id).await? {
                if keep(&l) {
                    out.push(AnnotatedMemoryLink { link: l, direction: LinkDirection::In });
                }
            }
        }
        // Deterministic order: oldest-first by createdAt, id as the stable tie-break.
        out.sort_by(|a, b| a.link.created_at.cmp(&b.link.created_at).then_with(|| a.link.id.cmp(&b.link.id)));
        Ok(out)
    }

    async fn history(&self, id: &str) -> Result<Vec<MemoryAudit>> {
        // Most-recent-first; id as the stable tie-break (ordered by the storage).
        self.db.audit_history(id).await
    }
}

#[async_trait]
impl LocalMemoryStore for LocalStore {
    // ---- HOR-464 / M4: disposable team-memory read-cache + one-way promote ----
    async fn upsert_cached(&self, item: NewMemoryItem, audit: &AuditCtx) -> Result<MemoryItem> {
        // Gate first — even a pulled claim is re-scanned for obvious secrets (defense in depth, §7).
        assert_claim_clean(&item.claim)?;

        let repo = item.repo.trim().to_string();
        if repo.is_empty() {
            return Err(anyhow!("memory_item requires a repo (HOR-46 fail-closed)"));
        }
        let id = item.id.trim().to_string();
        if id.is_empty() {
            return Err(anyhow!("upsertCached requires a stable item id (the origin client id)"));
        }

        let status = item.status.clone().unwrap_or_else(|| "fresh".to_string());
        let cloud_id = item.cloud_id.clone();
        // FORCE origin='cloud' + stamp pulledAt. Cache rows carry NO incident-family recall keys.
        self.db
            .upsert_cached_memory_item(&NewMemoryItem {
                id: id.clone(),
                repo,
                status: Some(status.clone()),
                origin: Some("cloud".to_string()),
                pulled_at: Some(Utc::now()),
                signature: None,
                tags: None,
                ..item
            })
            .await?;

        let row = self.get_by_id(&id).await?.ok_or_else(|| anyhow!("memory_item upsertCached returned no row"))?;

        // Exactly ONE audit row per refresh.
        let mut detail = Map::new();
        detail.insert("origin".into(), Value::String("cloud".into()));
        if let Some(c) = cloud_id.filter(|c| !c.is_empty()) {
            detail.insert("cloudId".into(), Value::String(c));
        }
        self.append_audit(AuditRow {
            memory_id: &id,
            action: "pulled",
            actor: &audit.actor,
            from_status: None,
            to_status: Some(&status),
            note: audit.note.as_deref(),
            detail: Some(Value::Object(detail)),
        })
        .await?;
        Ok(row)
    }

    async fn reconcile_cache(&self, repo: &str, keep_ids: &[String]) -> Result<usize> {
        let r = repo.trim();
        if r.is_empty() {
            return Ok(0); // HOR-46 fail-closed — never reconcile without a repo identity.
        }
        self.db.delete_cloud_memory_items(r, keep_ids).await
    }

    async fn mark_promoted(&self, id: &str, provenance: PromoteProvenance, audit: &AuditCtx) -> Result<MemoryItem> {
        let current = self.require(id).await?;
        // Flip the authored row to a server-owned team item. Idempotent.
        self.db
            .update_memory_item(
                id,
                &MemoryItemPatch {
                    visibility: Some("team".into()),
                    origin: Some("cloud".into()),
                    cloud_id: Some(Some(provenance.cloud_id.clone())),
                    author_name: Some(provenance.author_name.clone().or(current.author_name.clone())),
                    ..Default::default()
                },
            )
            .await?;
        let default_note = format!("promoted to team (cloud id {})", provenance.cloud_id);
        self.append_audit(AuditRow {
            memory_id: id,
            action: "promote",
            actor: &audit.actor,
            from_status: None,
            to_status: None,
            note: Some(audit.note.as_deref().unwrap_or(&default_note)),
            detail: Some(json!({ "origin": "cloud", "visibility": "team", "cloudId": provenance.cloud_id })),
        })
        .await?;
        self.get_by_id(id).await?.ok_or_else(|| anyhow!("memory item vanished during promote: {id}"))
    }
}

/// Load incident_memory rows scoped to the project AND matched to the tokens. Mirrors the filter
/// inside `recall_similar` but keeps the pre-dedup rows. Shared by `load_scoped` and memory-view.
pub async fn load_scoped_memory(db: &dyn MemoryStorage, project: &str, tokens: &[String]) -> Vec<IncidentMemory> {
    let p = project.trim();
    if p.is_empty() {
        return vec![];
    }
    let rows = match db.select_incident_memory_by_project(p, 200).await {
        Ok(rows) => rows,
        Err(_) => return vec![],
    };
    let tag_set: HashSet<&str> = tokens.iter().map(String::as_str).collect();
    rows.into_iter()
        .filter(|row| {
            if row.project.as_deref() != Some(p) {
                return false; // defense in depth
            }
            let row_tags: &[String] = row.tags.as_deref().unwrap_or(&[]);
            if tag_overlap(tokens, row_tags) <= 0.0 {
                return false;
            }
            let shared: Vec<&String> = row_tags.iter().filter(|t| tag_set.contains(t.as_str())).collect();
            // Only meaningful if it shares a SPECIFIC tag, not generic categories/env labels (HOR-39).
            !(!shared.is_empty() && shared.iter().all(|t| is_generic_tag(t)))
        })
        .collect()
}
