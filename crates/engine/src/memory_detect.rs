//! Horus Memory M3 — conservative auto-detection of memory→memory edges (`horus memory detect`).
//!
//! Two detectors scan the authored substrate for relationships between SAME-REPO items and PROPOSE
//! typed edges for an operator to confirm:
//!   - `auto:recurrence`    → two items describe the same recurring incident   (rel: `recurs-with`)
//!   - `auto:contradiction` → two confirmed outcomes disagree                  (rel: `contradicts`)
//!
//! HONESTY INVARIANTS (spec §8): auto-detectors are CONTEXT-ONLY and PROPOSE edges; `contradicts`
//! is a FLAG, never a deletion or status flip; `supersedes` is NEVER auto-detected; detection is
//! strictly repo-scoped. READ-ONLY: `detect_memory_edges` never writes.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::js;
use crate::memory::{is_generic_tag, tag_overlap};
use crate::memory_store::{incident_hint_overlap, tokenize, LinkDirectionFilter, LinksOpts, MemoryItem, MemoryQuery, MemoryRel, MemoryStore, MemoryVectorIndex};

/// The two auto-detector provenance labels a proposed edge can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutoDetection {
    #[serde(rename = "auto:recurrence")]
    Recurrence,
    #[serde(rename = "auto:contradiction")]
    Contradiction,
}

/// A single proposed memory→memory edge. `id` is resync-stable for `recurs-with` (hash of the
/// canonicalized pair); a directional `contradicts` edge leaves `id` empty for the store to mint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedEdge {
    pub id: String,
    pub from_memory_id: String,
    pub to_memory_id: String,
    pub rel: MemoryRel,
    pub detection: AutoDetection,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Resolved {
    Yes,
    Partly,
    No,
}

impl Resolved {
    fn as_str(self) -> &'static str {
        match self {
            Resolved::Yes => "yes",
            Resolved::Partly => "partly",
            Resolved::No => "no",
        }
    }
}

/// A confirmed outcome verdict, resolved for the contradiction join (CONTEXT-ONLY).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeVerdict {
    pub investigation_id: String,
    pub resolved: Resolved,
    pub confirmed_cause: Option<String>,
}

/// Inputs to [`detect_memory_edges`]. `repo` is REQUIRED + fails closed (HOR-46).
#[derive(Debug, Clone, Default)]
pub struct DetectMemoryOpts {
    pub repo: String,
    /// Cap on items scanned (deterministic, bounded).
    pub limit: Option<f64>,
}

/// Resolves the latest confirmed-outcome verdict for an investigation (the contradiction join).
#[async_trait]
pub trait OutcomeResolver: Send + Sync {
    async fn outcome_for(&self, investigation_id: &str) -> Result<Option<OutcomeVerdict>>;
}

/// Optional collaborators. Without `outcome_for`, contradiction detection is disabled.
#[derive(Default)]
pub struct DetectMemoryDeps<'a> {
    pub vector_index: Option<&'a dyn MemoryVectorIndex>,
    pub outcome_for: Option<&'a dyn OutcomeResolver>,
}

// ---------------------------------------------------------------------------
// Tunable, conservative thresholds (deterministic)
// ---------------------------------------------------------------------------

const TAG_OVERLAP_MIN: f64 = 0.6;
const CLAIM_JACCARD_MIN: f64 = 0.6;
const MIN_CLAIM_TOKENS: usize = 4;

/// Kinds that carry an incident-family signature/tags and can participate in recurrence detection.
const INCIDENT_DERIVED_KINDS: [&str; 2] = ["confirmed-outcome", "incident-pattern"];

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

static ALL_DELIMITER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\|*$").unwrap());
static WS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

/// Return a USABLE signature or None: blank, all-delimiter, or no non-generic component ⇒ None.
pub fn usable_signature(sig: Option<&str>) -> Option<String> {
    let s = sig.unwrap_or("").trim();
    if s.is_empty() || ALL_DELIMITER_RE.is_match(s) {
        return None;
    }
    let components: Vec<&str> = s.split(['|', ',']).map(str::trim).filter(|c| !c.is_empty()).collect();
    if components.is_empty() || components.iter().all(|c| is_generic_tag(c)) {
        return None;
    }
    Some(s.to_string())
}

/// The de-duplicated NON-GENERIC tags shared by two tag lists (the "specific" overlap, HOR-39).
pub fn shared_non_generic_tags(a: &[String], b: &[String]) -> Vec<String> {
    let set_b: HashSet<&str> = b.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for t in a {
        if set_b.contains(t.as_str()) && !is_generic_tag(t) && seen.insert(t.as_str()) {
            out.push(t.clone());
        }
    }
    out
}

/// Resync-stable id for a `recurs-with` edge: a hash of the canonicalized (ordered) pair.
pub fn recurrence_edge_id(id_a: &str, id_b: &str) -> String {
    let (lo, hi) = if id_a <= id_b { (id_a, id_b) } else { (id_b, id_a) };
    let h = format!("{:x}", Sha256::digest(format!("recurs-with {lo} {hi}").as_bytes()));
    format!("lnk_recurs_{}", &h[..32])
}

/// Normalize a confirmed-cause string for material comparison (lowercase, collapse whitespace).
fn normalize_cause(s: Option<&str>) -> String {
    WS_RE.replace_all(&s.unwrap_or("").trim().to_lowercase(), " ").into_owned()
}

/// Decide whether two confirmed outcomes CONFLICT, returning a human-readable reason or None.
pub fn outcome_conflict(a: &OutcomeVerdict, b: &OutcomeVerdict) -> Option<String> {
    let opposite = (a.resolved == Resolved::Yes && b.resolved == Resolved::No)
        || (a.resolved == Resolved::No && b.resolved == Resolved::Yes);
    if opposite {
        return Some(format!("outcome verdicts disagree ({} vs {})", a.resolved.as_str(), b.resolved.as_str()));
    }
    let ca = normalize_cause(a.confirmed_cause.as_deref());
    let cb = normalize_cause(b.confirmed_cause.as_deref());
    if !ca.is_empty() && !cb.is_empty() && ca != cb {
        return Some(format!(
            "confirmed causes differ (\"{}\" vs \"{}\")",
            a.confirmed_cause.as_deref().unwrap_or(""),
            b.confirmed_cause.as_deref().unwrap_or("")
        ));
    }
    None
}

/// The slice of an item `recurrence_reason` reads — so a not-yet-persisted probe can be compared.
#[derive(Debug, Clone, Default)]
pub struct RecurrenceSide<'a> {
    pub signature: Option<&'a str>,
    pub tags: Option<&'a [String]>,
    pub claim: &'a str,
    /// `payload.hint` when it is a string.
    pub hint: Option<&'a str>,
}

impl<'a> From<&'a MemoryItem> for RecurrenceSide<'a> {
    fn from(m: &'a MemoryItem) -> Self {
        RecurrenceSide {
            signature: m.signature.as_deref(),
            tags: m.tags.as_deref(),
            claim: &m.claim,
            hint: m.payload.as_ref().and_then(|p| p.get("hint")).and_then(Value::as_str),
        }
    }
}

/// Whether two incident-derived items RECUR (same pattern), returning a reason or None.
pub fn recurrence_reason(a: RecurrenceSide<'_>, b: RecurrenceSide<'_>) -> Option<String> {
    if let (Some(ha), Some(hb)) = (a.hint, b.hint) {
        if ha.trim().to_lowercase() != hb.trim().to_lowercase() {
            let o = incident_hint_overlap(ha, hb);
            // A module/hypothesis signature is not an incident identity. Keep distinct symptoms intact.
            if o.shared.len() < 2 || o.overlap < 0.45 {
                return None;
            }
        }
    }
    let sig_a = usable_signature(a.signature);
    let sig_b = usable_signature(b.signature);

    // Strongest signal: an identical, usable incident signature.
    if let (Some(sa), Some(sb)) = (&sig_a, &sig_b) {
        if sa == sb {
            return Some(format!("identical incident signature \"{sa}\""));
        }
    }

    let tags_a = a.tags.unwrap_or(&[]);
    let tags_b = b.tags.unwrap_or(&[]);
    let shared = shared_non_generic_tags(tags_a, tags_b);
    let overlap = tag_overlap(tags_a, tags_b);

    if overlap >= TAG_OVERLAP_MIN && !shared.is_empty() {
        return Some(format!("tag overlap {} on [{}]", js::to_fixed(overlap, 2), shared.join(", ")));
    }

    // Claim-text Jaccard FALLBACK: only when NEITHER item has a usable signature, gated behind a
    // min token count, and corroborated by ≥1 non-generic shared tag.
    if sig_a.is_none() && sig_b.is_none() && !shared.is_empty() {
        let ta = tokenize(a.claim);
        let tb = tokenize(b.claim);
        if ta.len() >= MIN_CLAIM_TOKENS && tb.len() >= MIN_CLAIM_TOKENS {
            let j = tag_overlap(&ta, &tb);
            if j >= CLAIM_JACCARD_MIN {
                return Some(format!("claim similarity {} corroborated by [{}]", js::to_fixed(j, 2), shared.join(", ")));
            }
        }
    }
    None
}

/// Canonical key for an existing memory→memory edge. `recurs-with` AND `contradicts` are stored
/// canonically (lo→hi), so their dedup key is order-free too (HOR-417).
fn edge_key(rel: &str, from: &str, to: &str) -> String {
    if rel == "recurs-with" || rel == "contradicts" {
        let (lo, hi) = if from <= to { (from, to) } else { (to, from) };
        return format!("{rel}|{lo}|{hi}");
    }
    format!("{rel}|{from}|{to}")
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Scan a repo's authored items and PROPOSE memory→memory edges. READ-ONLY. Deterministic +
/// idempotent: pairs are generated `i<j`, and any pair that ALREADY has the edge is skipped.
pub async fn detect_memory_edges(store: &dyn MemoryStore, opts: DetectMemoryOpts, deps: DetectMemoryDeps<'_>) -> Result<Vec<ProposedEdge>> {
    let repo = opts.repo.trim().to_string();
    if repo.is_empty() {
        return Ok(vec![]); // HOR-46 fail-closed
    }

    let items = store.query(MemoryQuery { repo, limit: Some(opts.limit.unwrap_or(1000.0)), ..Default::default() }).await?;

    let candidates: Vec<MemoryItem> = items.into_iter().filter(|i| INCIDENT_DERIVED_KINDS.contains(&i.kind.as_str())).collect();
    if candidates.len() < 2 {
        return Ok(vec![]);
    }

    // Pre-load each candidate's outgoing memory→memory edges (idempotency) and about-incident ids.
    let mut existing: HashSet<String> = HashSet::new();
    let mut investigation_of: HashMap<String, String> = HashMap::new();
    for item in &candidates {
        let out = store.links(&item.id, Some(LinksOpts { rels: None, direction: Some(LinkDirectionFilter::Out) })).await?;
        for l in out {
            if l.link.to_kind == "memory" {
                existing.insert(edge_key(&l.link.rel, &l.link.from_memory_id, &l.link.to_ref));
            } else if l.link.to_kind == "incident" && l.link.rel == "about-incident" {
                // First about-incident link wins (deterministic; links() is oldest-first).
                investigation_of.entry(item.id.clone()).or_insert(l.link.to_ref);
            }
        }
    }

    let mut proposals: Vec<ProposedEdge> = Vec::new();
    let mut outcome_cache: HashMap<String, Option<OutcomeVerdict>> = HashMap::new();

    for i in 0..candidates.len() {
        let a = &candidates[i];
        for b in &candidates[i + 1..] {
            // ---- RECURRENCE (recurs-with): symmetric, canonicalized, resync-stable id ----
            if !existing.contains(&edge_key("recurs-with", &a.id, &b.id)) {
                if let Some(reason) = recurrence_reason(a.into(), b.into()) {
                    let (lo, hi) = if a.id <= b.id { (&a.id, &b.id) } else { (&b.id, &a.id) };
                    proposals.push(ProposedEdge {
                        id: recurrence_edge_id(&a.id, &b.id),
                        from_memory_id: lo.clone(),
                        to_memory_id: hi.clone(),
                        rel: MemoryRel::RecursWith,
                        detection: AutoDetection::Recurrence,
                        reason,
                        detail: None,
                    });
                }
            }

            // ---- CONTRADICTION (contradicts): ONLY two confirmed-outcome items, SAME incident family ----
            let Some(resolver) = deps.outcome_for else { continue };
            if a.kind != "confirmed-outcome" || b.kind != "confirmed-outcome" || existing.contains(&edge_key("contradicts", &a.id, &b.id)) {
                continue;
            }
            let sig_a = usable_signature(a.signature.as_deref());
            let sig_b = usable_signature(b.signature.as_deref());
            let (Some(sig_a), Some(inv_a), Some(inv_b)) = (sig_a, investigation_of.get(&a.id), investigation_of.get(&b.id)) else { continue };
            if Some(&sig_a) != sig_b.as_ref() {
                continue;
            }
            // Cache so a repeated investigationId isn't re-resolved per pair; a failed join → None
            // (a single bad join never blocks the rest of detection).
            for id in [inv_a, inv_b] {
                if !outcome_cache.contains_key(id) {
                    let v = resolver.outcome_for(id).await.unwrap_or(None);
                    outcome_cache.insert(id.clone(), v);
                }
            }
            let oa = outcome_cache.get(inv_a).cloned().flatten();
            let ob = outcome_cache.get(inv_b).cloned().flatten();
            // No fabrication: a missing label on EITHER side ⇒ no edge.
            let (Some(oa), Some(ob)) = (oa, ob) else { continue };
            let Some(reason) = outcome_conflict(&oa, &ob) else { continue };
            let (lo, hi) = if a.id <= b.id { (&a.id, &b.id) } else { (&b.id, &a.id) };
            let (inv_lo, inv_hi) = if lo == &a.id { (inv_a, inv_b) } else { (inv_b, inv_a) };
            let mut detail = Map::new();
            detail.insert("investigationIds".into(), Value::Array(vec![Value::String(inv_lo.clone()), Value::String(inv_hi.clone())]));
            proposals.push(ProposedEdge {
                id: String::new(), // directional — the store mints the id
                from_memory_id: lo.clone(),
                to_memory_id: hi.clone(),
                rel: MemoryRel::Contradicts,
                detection: AutoDetection::Contradiction,
                reason,
                detail: Some(detail),
            });
        }
    }

    Ok(proposals)
}
