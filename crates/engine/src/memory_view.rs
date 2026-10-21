//! HOR — `horus memory show <scope>` synthesis (read-only).
//!
//! Composes the live code-knowledge graph (via discover_architecture / estimate_ownership) with the
//! deterministic incident memory (via recall_similar + the incident_memory store) into a single
//! project-scoped view. NO new schema, NO writes. Mirrors the area-scoping flow of buildOnboarding.
//!
//! Past incidents are CONTEXT ONLY. The "confirmed" flag here is a DISPLAY-ONLY proxy derived from
//! verdict/band — there is no confirmed column in the store.

use std::collections::{BTreeSet, HashMap};

use horus_core::Symbol;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::architecture::{discover_architecture, is_testy_community, ArchitectureDeps, AsyncBoundary, ExternalSystem};
use crate::code_provider::{CodeProvider, QueueEdge};
use crate::memory::{load_scoped_memory, module_area, recall_similar, tag_overlap};
use crate::memory_store::{to_iso_string, IncidentMemory, MemoryStorage};
use crate::ownership::{estimate_ownership, OwnershipDeps, OwnershipEstimate};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

pub struct MemoryViewDeps<'a> {
    /// createConnectors(config).code — source-graph host + searchSymbols + ownership.
    pub code: &'a dyn CodeProvider,
    pub db: &'a dyn MemoryStorage,
    /// Pre-fetched queue edges for the project (the TS `discoverArchitecture` reads the db itself).
    pub queue_edges: Vec<QueueEdge>,
    /// Repo root — for git-history ownership.
    pub repo_path: String,
    /// Resolved project name — REQUIRED; memory is project-isolated (HOR-46).
    pub project: String,
}

/// A subsystem cluster scoped to the area, carrying the test/example flag (HOR-365).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemorySubsystem {
    pub name: String,
    pub members: i64,
    /// True when the cluster is dominated by test/example/docs symbols.
    pub testy: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SeedSymbol {
    pub name: String,
    pub file: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryOwnedAreas {
    pub subsystems: Vec<MemorySubsystem>,
    pub seed_symbol: Option<SeedSymbol>,
    /// Probabilistic (git commit history only — not an org chart).
    pub ownership: Option<OwnershipEstimate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRuntimePaths {
    pub async_boundaries: Vec<AsyncBoundary>,
    pub key_flows: Vec<String>,
    /// Union of queues seen across scope-matched past incidents (payload.queues).
    pub queues_seen_in_incidents: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuspectedCause {
    pub title: String,
    pub category: String,
    pub band: String,
}

/// One past investigation hydrated for the scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryPastInvestigation {
    pub investigation_id: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    /// ISO date of the investigation (createdAt), or null.
    pub date: Option<String>,
    /// Jaccard tag overlap with the scope (0 for broader-recall fallback rows).
    pub overlap: f64,
    pub shared_tags: Vec<String>,
    pub suspected_cause: Option<SuspectedCause>,
    pub confidence: Option<f64>,
    /// DISPLAY-ONLY proxy — there is no confirmed column.
    pub confirmed_proxy: bool,
    /// Distinct evidence source channels that fired for this incident (code|logs|metrics|...).
    pub sources: Vec<String>,
}

/// Recurrence: how many memory rows share the same incident signature (area|cat|queues).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryRecurringPattern {
    pub signature: String,
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryEvidenceSources {
    pub channels: Vec<String>,
    pub always_available: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FragileSpots {
    pub dead_code: i64,
    pub high_coupling_pairs: i64,
    /// Always `repo-wide`.
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryWeakSpots {
    pub fragile: FragileSpots,
    pub test_light_subsystems: Vec<String>,
    pub low_prior_evidence: bool,
    pub low_prior_evidence_reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryView {
    pub scope: String,
    pub project: String,
    /// module_area(scope) — the first-3-segment area shared with incident signatures/tags.
    pub area: String,
    pub tokens: Vec<String>,
    /// False when the source-intelligence host is unreachable (sections are then empty, not absent).
    pub source_available: bool,
    pub owned_areas: MemoryOwnedAreas,
    pub runtime_paths: MemoryRuntimePaths,
    pub external_systems: Vec<ExternalSystem>,
    pub past_investigations: Vec<MemoryPastInvestigation>,
    pub recurring_patterns: Vec<MemoryRecurringPattern>,
    pub evidence_sources: MemoryEvidenceSources,
    pub weak_spots: MemoryWeakSpots,
    pub summary: String,
}

// Area helpers are shared with onboard.rs (same semantics).
use crate::onboard::{best_area_symbol, build_area_tokens, filter_architecture, matches_area};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Confidence below this counts as "low prior evidence" for the weak-spots section.
const LOW_CONFIDENCE: f64 = 0.5;

/// Safe read of a payload object, empty on any shape mismatch.
fn payload_of(row: Option<&IncidentMemory>) -> serde_json::Map<String, Value> {
    row.and_then(|r| r.payload.as_ref()).and_then(Value::as_object).cloned().unwrap_or_default()
}

fn non_empty_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Distinct evidence source channels referenced by a (raw, saved) report.
fn report_sources(report: Option<&Value>) -> Vec<String> {
    let Some(report) = report else { return vec![] };
    let mut out: BTreeSet<String> = BTreeSet::new();
    for ev in report.get("evidence").and_then(Value::as_array).into_iter().flatten() {
        if let Some(s) = non_empty_str(ev.get("source")) {
            out.insert(s.to_string());
        }
    }
    // Fall back to per-source contribution summary when raw evidence is absent (HOR-70).
    for s in report.get("sourceStatus").and_then(|s| s.get("sources")).and_then(Value::as_array).into_iter().flatten() {
        if s.get("status").and_then(Value::as_str) == Some("contributed") {
            if let Some(src) = s.get("source").and_then(Value::as_str) {
                out.insert(src.to_string());
            }
        }
    }
    out.into_iter().collect()
}

struct PastArgs<'a> {
    investigation_id: Option<String>,
    title: String,
    summary: Option<String>,
    overlap: f64,
    shared_tags: Vec<String>,
    date: Option<String>,
    report: Option<&'a Value>,
    memory_row: Option<&'a IncidentMemory>,
}

fn str_of(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").to_string()
}

/// Hydrate one past investigation from its (raw) report + memory row into the product shape.
fn hydrate_past(args: PastArgs<'_>) -> MemoryPastInvestigation {
    let payload = payload_of(args.memory_row);
    let report = args.report;

    let cause = report.and_then(|r| r.get("suspectedCauses")).and_then(Value::as_array).and_then(|a| a.first()).filter(|c| !c.is_null());
    let suspected_cause = match cause {
        Some(c) => Some(SuspectedCause { title: str_of(c.get("title")), category: str_of(c.get("category")), band: str_of(c.get("band")) }),
        None => non_empty_str(payload.get("topHypothesis")).map(|th| SuspectedCause {
            title: th.to_string(),
            category: th.to_string(),
            band: "observation".to_string(),
        }),
    };

    let confidence = report
        .and_then(|r| r.get("confidence"))
        .and_then(Value::as_f64)
        .or_else(|| payload.get("confidence").and_then(Value::as_f64));

    let top_verdict = report.and_then(|r| r.get("hypotheses")).and_then(Value::as_array).and_then(|h| h.first()).and_then(|h| h.get("verdict")).and_then(Value::as_str);
    let confirmed_proxy = top_verdict == Some("supported") || cause.and_then(|c| c.get("band")).and_then(Value::as_str) == Some("highly-likely");

    MemoryPastInvestigation {
        investigation_id: args.investigation_id,
        title: args.title,
        summary: args.summary,
        date: args.date,
        overlap: args.overlap,
        shared_tags: args.shared_tags,
        suspected_cause,
        confidence,
        confirmed_proxy,
        sources: report_sources(report),
    }
}

/// Read a report jsonb blob defensively (objects only).
fn as_report(report: Option<&Value>) -> Option<&Value> {
    report.filter(|r| r.is_object())
}

/// `deriveTags` over a raw saved report. `None` mirrors the TS `try { deriveTags(report) } catch` —
/// a report missing one of the arrays it indexes throws there.
fn derive_tags_value(r: &Value) -> Option<Vec<String>> {
    let crossings = r.get("timeline")?.get("boundaryCrossings")?.as_array()?;
    let hypotheses = r.get("hypotheses")?.as_array()?;
    let seeds = r.get("seeds")?.as_array()?;
    let input = r.get("input")?;
    let mut raw: Vec<String> = Vec::new();
    for bc in crossings {
        if let Some(q) = non_empty_str(bc.get("queueName")) {
            raw.push(q.to_string());
        }
    }
    if let Some(cat) = hypotheses.first().and_then(|h| non_empty_str(h.get("category"))) {
        raw.push(cat.to_string());
    }
    if let Some(fp) = seeds.first().and_then(|s| non_empty_str(s.get("filePath"))) {
        let area = module_area(fp);
        if !area.is_empty() {
            raw.push(area);
        }
    }
    if let Some(svc) = non_empty_str(input.get("service")) {
        raw.push(svc.to_string());
    }
    let mut out: IndexSet<String> = IndexSet::new();
    for t in raw {
        let lower = t.to_lowercase();
        if !lower.is_empty() {
            out.insert(lower);
        }
    }
    Some(out.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build the read-only memory view for `scope` within the resolved project. Deterministic; deps
/// are injected.
pub async fn build_memory_view(scope: &str, deps: MemoryViewDeps<'_>) -> MemoryView {
    let MemoryViewDeps { code, db, queue_edges, repo_path, project } = deps;

    // 0. Is the source-intelligence host reachable? Surface that instead of silently "0 subsystems".
    let source_available = code.health().await.ok;

    // 1. Whole-repo architecture model (queue edges scoped to the project — HOR-207).
    let architecture = discover_architecture(ArchitectureDeps { code, queue_edges, project: Some(project.clone()), own_packages: vec![] }).await;

    // 2-5. Resolve the scope to tokens + a seed symbol, then narrow the architecture.
    let symbols: Vec<Symbol> = code.search_symbols(scope, Some(20)).await.unwrap_or_default();
    let tokens = build_area_tokens(scope, &symbols);
    let token_arr: Vec<String> = tokens.iter().cloned().collect();
    let area_symbol = best_area_symbol(scope, &symbols);
    let filtered = filter_architecture(&architecture, &tokens);

    // 6. The module area — the field shared with incident-memory signature/tags.
    let area = module_area(scope);

    // --- Owned areas -------------------------------------------------------
    let ownership = estimate_ownership(scope, OwnershipDeps { code, repo_path, symbol: Some(area_symbol.clone()) }).await.ok();
    let subsystems: Vec<MemorySubsystem> = filtered
        .subsystems
        .iter()
        .map(|s| MemorySubsystem { name: s.name.clone(), members: s.members, testy: is_testy_community(&s.name) })
        .collect();
    let seed_symbol = area_symbol.map(|s| SeedSymbol { name: s.name, file: s.file_path });

    // --- Incident-memory rows (scope-matched, pre-dedup) -------------------
    let scoped_memory = load_scoped_memory(db, &project, &token_arr).await;
    let mut memory_by_investigation: HashMap<&str, &IncidentMemory> = HashMap::new();
    for row in &scoped_memory {
        if let Some(id) = row.investigation_id.as_deref() {
            memory_by_investigation.entry(id).or_insert(row);
        }
    }

    // --- Past investigations ----------------------------------------------
    let similar = recall_similar(db, &token_arr, None, Some(&project)).await;
    let mut past: Vec<MemoryPastInvestigation> = Vec::new();

    if !similar.is_empty() {
        for inc in &similar {
            let mut inv_row = None;
            if let Some(id) = inc.investigation_id.as_deref() {
                inv_row = db.get_investigation(id).await.ok().flatten();
            }
            let report = as_report(inv_row.as_ref().and_then(|i| i.report.as_ref()));
            let mut date = inv_row.as_ref().map(|i| to_iso_string(&i.created_at));
            let memory_row = inc.investigation_id.as_deref().and_then(|id| memory_by_investigation.get(id).copied());
            if date.is_none() {
                date = memory_row.map(|m| to_iso_string(&m.created_at));
            }
            past.push(hydrate_past(PastArgs {
                investigation_id: inc.investigation_id.clone(),
                title: inc.title.clone(),
                summary: inc.summary.clone(),
                overlap: inc.overlap,
                shared_tags: inc.shared_tags.clone(),
                date,
                report,
                memory_row,
            }));
        }
    } else {
        // Broader recall fallback: reports whose derived tags overlap the scope, else title match; capped at 8.
        let invs = db.list_investigations_with_reports(50, Some(&project)).await.unwrap_or_default();
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for inv in &invs {
            if seen.contains(inv.id.as_str()) {
                continue;
            }
            let Some(report) = as_report(inv.report.as_ref()) else { continue };
            seen.insert(&inv.id);

            let mut shared_tags: Vec<String> = vec![];
            let mut overlap = 0.0;
            if let Some(tags) = derive_tags_value(report) {
                let tags: Vec<String> = tags.iter().map(|t| t.to_lowercase()).collect();
                shared_tags = tags.iter().filter(|t| tokens.contains(t.as_str())).cloned().collect();
                overlap = tag_overlap(&token_arr, &tags);
            }
            let relevant = !shared_tags.is_empty() || matches_area(&inv.title, &tokens);
            if !relevant {
                continue;
            }

            past.push(hydrate_past(PastArgs {
                investigation_id: Some(inv.id.clone()),
                title: inv.title.clone(),
                summary: report.get("summary").and_then(Value::as_str).map(str::to_string),
                overlap,
                shared_tags,
                date: Some(to_iso_string(&inv.created_at)),
                report: Some(report),
                memory_row: memory_by_investigation.get(inv.id.as_str()).copied(),
            }));
            if past.len() >= 8 {
                break;
            }
        }
    }

    // --- Runtime paths & queues -------------------------------------------
    let mut queues_seen: BTreeSet<String> = BTreeSet::new();
    for row in &scoped_memory {
        if let Some(queues) = payload_of(Some(row)).get("queues").and_then(Value::as_array) {
            for q in queues {
                if let Some(q) = non_empty_str(Some(q)) {
                    queues_seen.insert(q.to_string());
                }
            }
        }
    }
    let runtime_paths = MemoryRuntimePaths {
        async_boundaries: filtered.async_boundaries.clone(),
        key_flows: filtered.key_flows.clone(),
        queues_seen_in_incidents: queues_seen.into_iter().collect(),
    };

    // --- Recurring patterns (group scope-matched memory rows by signature) -
    let mut by_signature: indexmap::IndexMap<String, i64> = indexmap::IndexMap::new();
    for row in &scoped_memory {
        let sig = row.signature.as_deref().unwrap_or("");
        if sig.is_empty() {
            continue;
        }
        *by_signature.entry(sig.to_string()).or_insert(0) += 1;
    }
    let mut recurring_patterns: Vec<MemoryRecurringPattern> = by_signature
        .into_iter()
        .map(|(signature, count)| MemoryRecurringPattern { signature, count })
        .filter(|p| p.count > 1)
        .collect();
    recurring_patterns.sort_by(|a, b| b.count.cmp(&a.count));

    // --- Useful evidence sources ------------------------------------------
    let channels: BTreeSet<String> = past.iter().flat_map(|p| p.sources.iter().cloned()).collect();
    let evidence_sources = MemoryEvidenceSources {
        channels: channels.into_iter().collect(),
        always_available: vec!["source-intelligence graph (code structure)".into(), "git history".into()],
    };

    // --- Weak spots --------------------------------------------------------
    let test_light_subsystems: Vec<String> = subsystems.iter().filter(|s| s.testy).map(|s| s.name.clone()).collect();
    let (low_prior_evidence, low_prior_evidence_reason) = if past.is_empty() {
        // Key off the DISPLAYED investigations, not just tag-matched incident_memory rows.
        (true, "No prior investigations on record for this area — predictions rest on code structure + git history only.".to_string())
    } else {
        let any_confirmed = past.iter().any(|p| p.confirmed_proxy);
        let all_low = past.iter().all(|p| p.confidence.is_none_or(|c| c < LOW_CONFIDENCE));
        if !any_confirmed && all_low {
            (true, "This area has been investigated before but never with a confirmed cause (recurring-but-never-confirmed).".to_string())
        } else {
            (false, String::new())
        }
    };
    let weak_spots = MemoryWeakSpots {
        fragile: FragileSpots {
            dead_code: architecture.fragile.dead_code,
            high_coupling_pairs: architecture.fragile.high_coupling_pairs,
            scope: "repo-wide".into(),
        },
        test_light_subsystems,
        low_prior_evidence,
        low_prior_evidence_reason,
    };

    // --- Summary -----------------------------------------------------------
    let mut summary = format!(
        "Memory for \"{scope}\" in {project}: {} owned subsystem(s), {} queue boundary(ies), {} external system(s), {} past investigation(s)",
        subsystems.len(),
        runtime_paths.async_boundaries.len(),
        filtered.external_systems.len(),
        past.len()
    );
    if !recurring_patterns.is_empty() {
        summary.push_str(&format!(", {} recurring pattern(s)", recurring_patterns.len()));
    }
    summary.push('.');

    MemoryView {
        scope: scope.to_string(),
        project,
        area,
        tokens: token_arr,
        source_available,
        owned_areas: MemoryOwnedAreas { subsystems, seed_symbol, ownership },
        runtime_paths,
        external_systems: filtered.external_systems,
        past_investigations: past,
        recurring_patterns,
        evidence_sources,
        weak_spots,
        summary,
    }
}
