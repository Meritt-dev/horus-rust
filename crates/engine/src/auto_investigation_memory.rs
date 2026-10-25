//! HOR-432 — auto-capture a recurrence-aware memory from EVERY investigation, CONSOLIDATING
//! recurrences. The FIRST time an incident-pattern is investigated a new `investigation` memory is
//! created; each LATER recurrence UPDATES that memory IN PLACE (bump count + last-seen, refresh
//! claim/confidence to the LATEST finding) rather than minting a twin.
//!
//! HONESTY INVARIANTS (spec §8): the captured memory is CONTEXT-ONLY; it stores the HONEST verdict
//! and the report's real `confidence` (NEVER inflated); consolidation never mutates status; a blank
//! repo produces NO memory (HOR-46). NON-BLOCKING by contract — the caller wraps this in a catch.
//! DETERMINISM: nothing here reads the clock; `report_time` is passed in.

use std::sync::LazyLock;

use anyhow::Result;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::js;
use crate::memory::{derive_signature, derive_tags};
use crate::memory_detect::{recurrence_reason, RecurrenceSide};
use crate::memory_recall::{append_hint, incident_context_of, read_incident_disposition};
use crate::memory_store::{
    is_hidden_status, to_iso_string, AddLinkOpts, AuditCtx, LinkDetection, MemoryItem, MemoryKind, MemoryQuery, MemoryStore,
    MemoryUpdate, NewMemoryItem, NewMemoryLink, UpdateOpts,
};
use crate::types::{InvestigationInput, InvestigationReport};

/// Max prior memories scanned for a recurrence match (deterministic, bounded).
const RECURRENCE_SCAN_LIMIT: f64 = 100.0;

/// Cap on the rolling list of source investigation ids kept in the consolidated payload.
const MAX_INVESTIGATION_IDS: usize = 20;

fn truthy(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.is_empty())
}

static WS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

/// Trim + cap a free-text fragment so the auto claim stays a concise one-liner.
fn snippet(text: &str, max: usize) -> String {
    let s = WS_RE.replace_all(text.trim(), " ").into_owned();
    if s.chars().count() > max {
        format!("{}…", js::slice_chars(&s, max - 1))
    } else {
        s
    }
}

/// Default-ON env gate: on unless `HORUS_AUTO_INVESTIGATION_MEMORY` is `0`/`false`/`off`/`no`.
pub fn auto_investigation_memory_enabled() -> bool {
    let v = std::env::var("HORUS_AUTO_INVESTIGATION_MEMORY").unwrap_or_default().trim().to_lowercase();
    v != "0" && v != "false" && v != "off" && v != "no"
}

/// The deterministic incident fingerprint + claim derived from a report (shared by create + consolidate).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationFields {
    pub hint: String,
    /// `Investigation: <hint> -> <top hypothesis | summary>` (the latest finding).
    pub claim: String,
    /// HONEST confidence — the report's own value, never inflated.
    pub confidence: f64,
    pub signature: String,
    pub tags: Vec<String>,
    /// The top hypothesis CATEGORY (recorded as a hypothesis, never a confirmed fact), or None.
    pub top_hypothesis_category: Option<String>,
}

fn first_non_empty<'a>(parts: &[&'a str]) -> &'a str {
    parts.iter().copied().find(|s| !s.is_empty()).unwrap_or("")
}

/// Derive the (deterministic) incident fingerprint + claim a report contributes to memory. PURE.
pub fn derive_investigation_fields(report: &InvestigationReport) -> InvestigationFields {
    let hint = report.input.hint.clone();
    let top_hyp = report.hypotheses.first();
    // The headline is the top hypothesis (recorded AS a hypothesis), falling back to the summary.
    let headline = match top_hyp {
        Some(h) => snippet(first_non_empty(&[&h.statement, &h.category, &report.summary]), 140),
        None => snippet(first_non_empty(&[&report.summary, "(no leading hypothesis)"]), 140),
    };
    InvestigationFields {
        claim: format!("Investigation: {} -> {headline}", snippet(&hint, 140)),
        hint,
        confidence: report.confidence,
        signature: derive_signature(report),
        tags: derive_tags(report),
        top_hypothesis_category: top_hyp.map(|h| h.category.clone()),
    }
}

/// Read a payload's `recurrenceCount` (>=1), defaulting to 1 when absent/invalid.
pub fn recurrence_count_of(payload: Option<&Value>) -> i64 {
    if let Some(c) = payload.and_then(|p| p.get("recurrenceCount")).and_then(Value::as_f64) {
        if c.is_finite() && c >= 1.0 {
            return c.floor() as i64;
        }
    }
    1
}

fn structural_link(from: &str, investigation_id: &str, audit: &AuditCtx) -> (NewMemoryLink, Option<AddLinkOpts>) {
    (
        NewMemoryLink {
            id: String::new(),
            from_memory_id: from.to_string(),
            rel: "about-incident".into(),
            to_kind: "incident".into(),
            to_ref: investigation_id.to_string(),
            to_file_path: None,
        },
        Some(AddLinkOpts { detection: Some(LinkDetection::Structural), audit: Some(audit.clone()), detail: None }),
    )
}

/// Build + persist a NEW `kind:investigation` memory from a finished report, with an
/// `about-incident` link back to the source investigation. None when there is no repo (HOR-46).
pub async fn create_investigation_memory(
    store: &dyn MemoryStore,
    investigation_id: Option<&str>,
    report: &InvestigationReport,
    audit: &AuditCtx,
) -> Result<Option<MemoryItem>> {
    let Some(repo) = report.input.repo.as_deref().map(str::trim).filter(|r| !r.is_empty()) else { return Ok(None) };

    let fields = derive_investigation_fields(report);

    // applicability = { environment, service, ...incident } (undefined keys are dropped by JSON).
    let mut applicability = Map::new();
    if let Some(e) = &report.input.environment {
        applicability.insert("environment".into(), Value::String(e.clone()));
    }
    if let Some(s) = &report.input.service {
        applicability.insert("service".into(), Value::String(s.clone()));
    }
    if let Some(Value::Object(incident)) = report.input.incident.as_ref().and_then(|i| serde_json::to_value(i).ok()) {
        for (k, v) in incident {
            applicability.insert(k, v);
        }
    }

    let item = NewMemoryItem {
        id: String::new(),
        kind: MemoryKind::Investigation.as_str().into(),
        source: "investigation".into(),
        scope: "repo".into(),
        visibility: Some("private".into()),
        // HONEST confidence — the report's own value, never inflated.
        confidence: fields.confidence,
        claim: fields.claim.clone(),
        repo: repo.to_string(),
        evidence: Some(Value::Array(vec![])),
        // Incident-family recall keys (same derivation as incident_memory) so this memory recurs.
        signature: Some(fields.signature.clone()),
        tags: Some(fields.tags.clone()),
        payload: Some(json!({
            "investigationId": investigation_id,
            "hint": fields.hint,
            "hints": [fields.hint],
            "topHypothesis": fields.top_hypothesis_category,
            // First sighting: a single investigation is "recurred 1×". Bumped on each later recurrence.
            "recurrenceCount": 1,
            "outcome": {
                "disposition": "unknown",
                "certainty": "inferred",
                "sourceInvestigation": investigation_id.unwrap_or(""),
                "sourceRefs": [],
                "applicability": applicability,
                "invalidatingConditions": [],
                "checks": [],
            },
        })),
        ..Default::default()
    };

    let created = store.add(item, audit).await?;

    // about-incident link back to the source investigation (a derived, structural relationship).
    if let Some(id) = investigation_id.filter(|i| !i.trim().is_empty()) {
        let (link, opts) = structural_link(&created.id, id, audit);
        store.add_link(link, opts).await?;
    }
    Ok(Some(created))
}

/// A deterministic PROBE: the signature/tags/claim of the not-yet-persisted current investigation.
#[derive(Debug, Clone, Default)]
pub struct RecurrenceProbe {
    pub signature: Option<String>,
    pub tags: Option<Vec<String>>,
    pub claim: String,
    pub hint: Option<String>,
}

/// Find an existing `kind:investigation` memory in the SAME repo that THIS investigation recurs
/// with, or None. Reuses `recurrence_reason` from memory_detect. Newest-first, so the most recent
/// matching memory wins. Fails closed on a blank repo (HOR-46). Read seam only.
pub async fn detect_recurrence(
    store: &dyn MemoryStore,
    probe: &RecurrenceProbe,
    repo: &str,
    input: Option<&InvestigationInput>,
) -> Result<Option<MemoryItem>> {
    let r = repo.trim();
    if r.is_empty() {
        return Ok(None);
    }
    let existing = store
        .query(MemoryQuery {
            repo: r.to_string(),
            kind: Some(vec![MemoryKind::Investigation]),
            limit: Some(RECURRENCE_SCAN_LIMIT),
            ..Default::default()
        })
        .await?;

    let input_incident = input.map(incident_context_of);

    for candidate in &existing {
        if is_hidden_status(&candidate.status) {
            continue;
        }
        let a = read_incident_disposition(candidate.payload.as_ref().and_then(|p| p.get("outcome"))).map(|d| d.applicability);
        if let (Some(a), Some(input), Some(ctx)) = (&a, input, &input_incident) {
            let differs = |x: Option<&str>, y: Option<&str>| matches!((truthy(x), truthy(y)), (Some(x), Some(y)) if x != y);
            if differs(a.environment.as_deref(), input.environment.as_deref())
                || differs(a.service.as_deref(), input.service.as_deref())
                || differs(a.error_code.as_deref(), ctx.error_code.as_deref())
                || differs(a.fingerprint.as_deref(), ctx.fingerprint.as_deref())
                || differs(a.workflow.as_deref(), ctx.workflow.as_deref())
                || differs(a.operation.as_deref(), ctx.operation.as_deref())
            {
                continue;
            }
        }
        let structured_match = match (&a, &input_incident) {
            (Some(a), Some(ctx)) => truthy(a.fingerprint.as_deref()).is_some() && a.fingerprint == ctx.fingerprint,
            _ => false,
        };
        let compared = RecurrenceSide {
            signature: probe.signature.as_deref(),
            tags: probe.tags.as_deref(),
            claim: &probe.claim,
            hint: if structured_match { None } else { input.map(|i| i.hint.as_str()).or(probe.hint.as_deref()) },
        };
        if recurrence_reason(candidate.into(), compared).is_some() {
            return Ok(Some(candidate.clone()));
        }
    }
    Ok(None)
}

/// CONSOLIDATE a recurring investigation into an EXISTING `investigation` memory IN PLACE (HOR-432).
/// Bumps `recurrenceCount`, stamps `lastSeenAt`, rolls `investigationIds`, refreshes the latest
/// finding (confidence VERBATIM), adds an `about-incident` link and a `recurrence` audit row.
pub async fn consolidate_recurrence(
    store: &dyn MemoryStore,
    existing: &MemoryItem,
    investigation_id: Option<&str>,
    fields: &InvestigationFields,
    report_time: DateTime<Utc>,
    audit: &AuditCtx,
) -> Result<MemoryItem> {
    let prev: Map<String, Value> = existing.payload.as_ref().and_then(Value::as_object).cloned().unwrap_or_default();
    let prev_ids: Vec<String> = prev
        .get("investigationIds")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let prev_single = prev.get("investigationId").and_then(Value::as_str).map(str::to_string);

    if let Some(id) = investigation_id.filter(|i| !i.is_empty()) {
        let already = prev_single.as_deref() == Some(id)
            || prev.get("investigationIds").and_then(Value::as_array).is_some_and(|a| a.iter().any(|x| x.as_str() == Some(id)));
        if already {
            return Ok(existing.clone());
        }
    }
    let recurrence_count = recurrence_count_of(existing.payload.as_ref()) + 1;

    // Roll the source investigation ids forward, capped to the most recent few.
    let seed_ids: Vec<String> = if !prev_ids.is_empty() { prev_ids } else { prev_single.clone().into_iter().collect() };
    let this_id = investigation_id.filter(|i| !i.trim().is_empty());
    let mut investigation_ids = seed_ids.clone();
    if let Some(id) = this_id {
        investigation_ids.push(id.to_string());
    }
    let skip = investigation_ids.len().saturating_sub(MAX_INVESTIGATION_IDS);
    let investigation_ids: Vec<String> = investigation_ids.into_iter().skip(skip).collect();

    // `{...prev, ...}` — existing keys keep their position, new keys append (JS spread order).
    let mut payload = prev;
    payload.insert("recurrenceCount".into(), json!(recurrence_count));
    payload.insert("lastSeenAt".into(), Value::String(to_iso_string(&report_time)));
    payload.insert("investigationIds".into(), json!(investigation_ids));
    // Refresh the "latest finding" provenance; keep the original first-seen id for reference.
    // Every hint this incident was investigated under, so recall matches any earlier wording too.
    let prior_hints = match payload.get("hints").filter(|h| !h.is_null()) {
        Some(h) => h.clone(),
        None => json!(payload.get("hint").and_then(Value::as_str).map(|h| vec![h]).unwrap_or_default()),
    };
    payload.insert("hint".into(), Value::String(fields.hint.clone()));
    payload.insert("hints".into(), json!(append_hint(Some(&prior_hints), &fields.hint)));
    payload.insert("topHypothesis".into(), fields.top_hypothesis_category.clone().map(Value::String).unwrap_or(Value::Null));
    let first_seen = prev_single.or_else(|| seed_ids.first().cloned()).or_else(|| this_id.map(str::to_string));
    payload.insert("investigationId".into(), first_seen.map(Value::String).unwrap_or(Value::Null));

    let mut detail = Map::new();
    detail.insert("recurrenceCount".into(), json!(recurrence_count));
    if let Some(id) = this_id {
        detail.insert("investigationId".into(), Value::String(id.to_string()));
    }

    let updated = store
        .update(
            &existing.id,
            MemoryUpdate {
                claim: Some(fields.claim.clone()),
                // HONEST: the LATEST report's confidence, verbatim — never inflated, never an average.
                confidence: Some(fields.confidence),
                payload: Some(Some(Value::Object(payload))),
            },
            UpdateOpts {
                audit: audit.clone(),
                action: Some("recurrence".into()),
                detection: Some(LinkDetection::AutoRecurrenceConsolidate),
                detail: Some(detail),
            },
        )
        .await?;

    // about-incident link to the LATEST investigation (a derived, structural relationship).
    if let Some(id) = this_id {
        let (link, opts) = structural_link(&existing.id, id, audit);
        store.add_link(link, opts).await?;
    }
    Ok(updated)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureAction {
    Created,
    Consolidated,
    Skipped,
}

/// What [`capture_investigation_memory`] did with a report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResult {
    pub action: CaptureAction,
    /// The affected memory id, or None when skipped / no row was written.
    pub memory_id: Option<String>,
    /// The memory's recurrence count after this capture (1 for a first sighting).
    pub recurrence_count: i64,
}

/// Capture ONE investigation into the authored-memory substrate, CONSOLIDATING recurrences.
/// `report_time` is the deterministic "seen at" stamp (the persisted investigation's `createdAt`).
pub async fn capture_investigation_memory(
    store: &dyn MemoryStore,
    investigation_id: Option<&str>,
    report: &InvestigationReport,
    report_time: DateTime<Utc>,
    audit: &AuditCtx,
) -> Result<CaptureResult> {
    let Some(repo) = report.input.repo.as_deref().map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(CaptureResult { action: CaptureAction::Skipped, memory_id: None, recurrence_count: 0 });
    };

    let fields = derive_investigation_fields(report);
    let probe = RecurrenceProbe {
        signature: Some(fields.signature.clone()),
        tags: Some(fields.tags.clone()),
        claim: fields.claim.clone(),
        hint: Some(fields.hint.clone()),
    };
    let existing = detect_recurrence(store, &probe, repo, Some(&report.input)).await?;

    if let Some(existing) = existing {
        let updated = consolidate_recurrence(store, &existing, investigation_id, &fields, report_time, audit).await?;
        return Ok(CaptureResult {
            action: CaptureAction::Consolidated,
            memory_id: Some(updated.id.clone()),
            recurrence_count: recurrence_count_of(updated.payload.as_ref()),
        });
    }

    let created = create_investigation_memory(store, investigation_id, report, audit).await?;
    Ok(CaptureResult {
        action: if created.is_some() { CaptureAction::Created } else { CaptureAction::Skipped },
        memory_id: created.map(|c| c.id),
        recurrence_count: 1,
    })
}
