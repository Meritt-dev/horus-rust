//! HOR-384 — Agent Packet: a compact, honesty-framed projection of an `InvestigationReport`
//! for an agent's context window. Pure, synchronous, no I/O. Freshness and recalled memory
//! are computed in the CLI and passed in; memory is CONTEXT ONLY, never evidence.

use crate::architecture::is_test_or_example_path;
use crate::graph::GraphNodeType;
use crate::js::{iso_now, locale_compare, math_round, number_string, to_fixed};
use crate::memory_recall::{FreshnessLabel, RecalledMemory};
use crate::render::{format_symbol_location, recent_changes};
use crate::router::format_route_step;
use crate::score_cause::{get_band, CauseBand};
use crate::source_status::RuntimeSourceStatus;
use crate::types::{InvestigationReport, RouteStep};
use horus_core::{Evidence, EvidenceCategory, EvidencePriority, EvidenceKind, ProviderKind};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

// ── Public types ─────────────────────────────────────────────────────────────

/// A thin presentation preset selected via `--for <agent>`. Presentation-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentPreset {
    Claude,
    Cursor,
    Generic,
}

/// Honesty band for the headline confidence (mirrors `CauseBand`).
pub type HonestyBand = CauseBand;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceEntry {
    pub source: String,
    pub status: RuntimeSourceStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HonestyHeader {
    pub confidence: f64,
    pub band: HonestyBand,
    /// True when a confidence ceiling capped the headline below its base.
    pub working_hypothesis: bool,
    /// Caveats, integrity-ordered (never truncated).
    pub caveats: Vec<String>,
    /// Gap `nextSource` lines, highest confidence-impact first (never truncated).
    pub to_raise_confidence: Vec<String>,
    /// HOR-386 — the router's deterministic next-step suggestions, carried verbatim.
    pub routing: Vec<RouteStep>,
    /// Which sources backed the run, preserving empty-vs-failed honesty.
    pub sources: Vec<SourceEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadlineCause {
    pub title: String,
    pub band: CauseBand,
    pub final_score: f64,
    /// Re-derived: does the headline cite the seed's evidence/nodes?
    pub seed_linked: bool,
    pub category: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemSection {
    pub hint: String,
    /// report.summary (carries the seed disclaimer prefix + scope clause).
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headline_cause: Option<HeadlineCause>,
    /// formatSymbolLocation(report.seeds[0]) → "file:start-end".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelevantFile {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i64>,
    pub why: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceLink {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub title: String,
    pub source: ProviderKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<EvidenceCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<EvidencePriority>,
    pub relevance: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<EvidenceLink>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LowerPriorityArea {
    pub area: String,
    pub reasons: Vec<String>,
}

/// A remembered claim surfaced as CONTEXT in the packet — NOT live evidence; it never feeds
/// the confidence/verdict scoring path and carries its read-time freshness/status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryContextItem {
    pub id: String,
    pub claim: String,
    pub kind: String,
    pub scope: String,
    /// The claim's OWN stored confidence (0..1) — never the investigation's confidence.
    pub confidence: f64,
    /// EFFECTIVE (display) status from read-time freshness — may differ from the stored status.
    pub status: String,
    pub freshness: FreshnessLabel,
    /// Days since last verification (or creation when never verified); null when no anchor.
    pub age_days: Option<f64>,
    pub drift_detected: bool,
}

/// Repo identity for a packet — WHICH repo/branch/commit the evidence came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoIdentity {
    pub name: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Truncation {
    pub relevant_files: i64,
    pub evidence: i64,
    pub lower_priority: i64,
    pub memory: i64,
    pub next_steps: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub investigation_id: Option<String>,
    pub generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub truncated: bool,
    /// Presentation preset (render hint only; data is never dropped from the packet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<AgentPreset>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Packet {
    pub honesty: HonestyHeader,
    pub problem: ProblemSection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<RepoIdentity>,
    pub relevant_files: Vec<RelevantFile>,
    pub evidence: Vec<EvidenceItem>,
    pub lower_priority: Vec<LowerPriorityArea>,
    /// Remembered context — prior knowledge, clearly marked as NOT live evidence.
    pub memory: Vec<MemoryContextItem>,
    pub next_steps: Vec<String>,
    /// Per-section drop counts (how many items were cut by the hard caps).
    pub truncation: Truncation,
    pub meta: PacketMeta,
}

/// Freshness inputs consumed by the honesty header (CLI `Freshness` + `semanticSearchReady`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketFreshness {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commits_since_index: Option<Option<i64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_window: Option<Option<RuntimeWindow>>,
    /// Verbatim freshness caveat strings (freshness.ts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveats: Option<Vec<String>>,
    /// `semanticSearchReady(meta)` — false adds the recall-reduced caveat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_search_ready: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeWindow {
    pub from_iso: String,
    pub to_iso: String,
}

#[derive(Default)]
pub struct PacketOptions {
    pub top_files: Option<i64>,
    pub top_evidence: Option<i64>,
    pub top_lower: Option<i64>,
    pub top_steps: Option<i64>,
    pub top_memory: Option<i64>,
    pub preset: Option<AgentPreset>,
    pub freshness: Option<PacketFreshness>,
    /// Repo identity (name/branch/commit) — collected CLI-side from git; surfaced top-level.
    pub repo: Option<RepoIdentity>,
    /// Remembered context, ALREADY recalled in the CLI. Order is honoured verbatim.
    pub memory: Option<Vec<RecalledMemory>>,
    /// Injectable clock for deterministic `meta.generatedAt`. Defaults to now.
    pub now: Option<String>,
}

/// Machine-facing serialisation: arrays stay clean; truncation is a sibling count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketSection<T> {
    pub items: Vec<T>,
    pub truncated_count: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketJson {
    pub honesty: HonestyHeader,
    pub problem: ProblemSection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<RepoIdentity>,
    pub relevant_files: PacketSection<RelevantFile>,
    pub evidence: PacketSection<EvidenceItem>,
    pub lower_priority: PacketSection<LowerPriorityArea>,
    pub memory: PacketSection<MemoryContextItem>,
    pub next_steps: PacketSection<String>,
    pub meta: PacketMeta,
}

// ── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_TOP_FILES: i64 = 5;
const DEFAULT_TOP_EVIDENCE: i64 = 5;
const DEFAULT_TOP_LOWER: i64 = 3;
const DEFAULT_TOP_STEPS: i64 = 5;
const DEFAULT_TOP_MEMORY: i64 = 5;

struct Preset {
    top_files: Option<i64>,
    top_evidence: Option<i64>,
    top_memory: Option<i64>,
    show_timestamps: bool,
}

/// Thin presentation presets — only lower caps and toggle render verbosity.
fn preset(p: AgentPreset) -> Preset {
    match p {
        AgentPreset::Claude => Preset { top_files: Some(4), top_evidence: Some(4), top_memory: Some(4), show_timestamps: false },
        AgentPreset::Cursor => Preset { top_files: Some(3), top_evidence: Some(3), top_memory: Some(3), show_timestamps: false },
        AgentPreset::Generic => Preset { top_files: None, top_evidence: None, top_memory: None, show_timestamps: true },
    }
}

/// Priority tiers, critical → info, for evidence ranking.
fn priority_rank(p: Option<EvidencePriority>) -> u8 {
    match p {
        Some(EvidencePriority::Critical) => 0,
        Some(EvidencePriority::High) => 1,
        Some(EvidencePriority::Medium) => 2,
        Some(EvidencePriority::Low) => 3,
        Some(EvidencePriority::Info) => 4,
        None => 5,
    }
}

/// Structural/topology evidence kinds — the path, not the evidence.
fn is_structural_kind(k: EvidenceKind) -> bool {
    matches!(k, EvidenceKind::Symbol | EvidenceKind::Flow | EvidenceKind::Impact | EvidenceKind::QueueEdge)
}

/// Runtime anomaly evidence kinds that can attribute a signal to an area.
fn is_runtime_kind(k: EvidenceKind) -> bool {
    matches!(k, EvidenceKind::Log | EvidenceKind::Metric | EvidenceKind::QueueState | EvidenceKind::State | EvidenceKind::Commit)
}

/// The standing blast-radius caveat attached to every lower-priority entry.
const BLAST_RADIUS_CAVEAT: &str =
    "the component reporting an error is often not the cause; static reachability misses dynamic dispatch, event buses, and cross-service calls.";

const WORKING_HYPOTHESIS_LINE: &str = "Working hypothesis, not a root-cause conclusion.";

/// Fixed, conservative section title — never "ruled out" / "safe to ignore".
pub const LOWER_PRIORITY_TITLE: &str = "Lower-priority areas based on current evidence";

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Mirror of graph.ts `isExcludedFromImplication`: drop info-priority / structural kinds.
fn is_structural_evidence(ev: &Evidence) -> bool {
    match ev.priority {
        Some(p) => p == EvidencePriority::Info,
        None => is_structural_kind(ev.kind),
    }
}

/// Whether the seed reads as a low-confidence / fuzzy semantic guess (CAP C).
fn is_seed_low_confidence(report: &InvestigationReport) -> bool {
    if report.summary.starts_with("⚠ No symbol closely matched") {
        return true;
    }
    // A strong exact/colocated match (score ≥ 0.5) is authoritative; only flag fuzzy seeds
    // when a score is present and below the bar.
    report.seeds.first().and_then(|s| s.score).is_some_and(|s| s < 0.5)
}

static SEED_DISCLAIMER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)⚠.*?precisely\.").unwrap());

/// Extract the engine's "⚠ … precisely." seed disclaimer from the summary, if present.
fn extract_seed_disclaimer(summary: &str) -> Option<String> {
    SEED_DISCLAIMER_RE.find(summary).map(|m| m.as_str().trim().to_string())
}

struct SeedIdentity {
    evidence_ids: HashSet<String>,
    node_ids: HashSet<String>,
}

/// Evidence ids and node ids that identify the seed, for seed-link re-derivation.
fn seed_identity(report: &InvestigationReport) -> SeedIdentity {
    let mut id = SeedIdentity { evidence_ids: HashSet::new(), node_ids: HashSet::new() };
    let Some(seed) = report.seeds.first() else { return id };
    id.node_ids.insert(format!("symbol:{}", seed.name));
    id.node_ids.insert(format!("file:{}", seed.file_path));
    for ev in &report.evidence {
        let linked = ev.links.symbol_id.as_deref() == Some(seed.id.as_str())
            || (ev.links.file.as_deref() == Some(seed.file_path.as_str()) && is_structural_kind(ev.kind));
        if linked {
            id.evidence_ids.insert(ev.id.clone());
        }
    }
    id
}

/// True when a cause cites the seed's evidence or affected nodes (CAP A re-derivation).
fn is_cause_seed_linked(source_evidence_ids: &[String], affected_node_ids: &[String], seed: &SeedIdentity) -> bool {
    source_evidence_ids.iter().any(|id| seed.evidence_ids.contains(id)) || affected_node_ids.iter().any(|id| seed.node_ids.contains(id))
}

/// De-duplicate strings, preserving first-seen order.
fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

// ── Honesty header ───────────────────────────────────────────────────────────

fn build_honesty(
    report: &InvestigationReport,
    seed: &SeedIdentity,
    seed_low_confidence: bool,
    freshness: Option<&PacketFreshness>,
) -> (HonestyHeader, bool) {
    let confidence = report.confidence;
    let band = get_band(confidence);
    let headline = report.suspected_causes.first();
    let seed_linked = headline.map(|h| is_cause_seed_linked(&h.source_evidence_ids, &h.affected_node_ids, seed)).unwrap_or(true);

    let ceiling = report.gap_analysis.confidence_ceiling;
    let gap_ceiling_bit = ceiling < 1.0 && confidence >= ceiling - 0.001;
    let single_source_ceiling = headline.is_some_and(|h| h.explanations.iter().any(|e| e.factor == "single-source-ceiling"));

    // A ceiling "bit" below the base whenever any of these capping conditions hold.
    let ceiling_present = gap_ceiling_bit || single_source_ceiling || !seed_linked || seed_low_confidence;
    let working_hypothesis = !seed_linked || seed_low_confidence || (band != CauseBand::HighlyLikely && ceiling_present);

    let mut caveats: Vec<String> = vec![];
    if working_hypothesis {
        caveats.push(WORKING_HYPOTHESIS_LINE.into());
    }
    // 2 + CAP C — the fuzzy-seed disclaimer.
    if seed_low_confidence {
        caveats.push(extract_seed_disclaimer(&report.summary).unwrap_or_else(|| {
            "Seed is a low-confidence semantic guess — refine with an exact symbol or error code to target precisely.".into()
        }));
    }
    // CAP A — unlinked headline.
    if headline.is_some() && !seed_linked {
        caveats.push("No cause is structurally linked to the seed; the strongest signal is a lead to verify, not a diagnosis.".into());
    }
    // CAP B — gap ceiling.
    if gap_ceiling_bit {
        caveats.push(format!("Confidence is capped at {} until evidence gaps are filled.", number_string(ceiling)));
    }
    // CAP E — single-source ceiling.
    if single_source_ceiling {
        caveats.push("Headline rests on a single provider — no multi-source corroboration.".into());
    }
    // 4 — blind spots.
    caveats.extend(report.gap_analysis.blind_spots.iter().cloned());
    // 5 — freshness caveats + the semantic-search-off caveat.
    if let Some(f) = freshness {
        if let Some(c) = &f.caveats {
            caveats.extend(c.iter().cloned());
        }
        if f.semantic_search_ready == Some(false) {
            caveats.push(
                "semantic search degraded to keyword/FTS (index embeddings incomplete) — recall may be reduced; re-run `horus init`".into(),
            );
        }
    }
    // 6 — degraded banner.
    if report.degraded.as_ref().is_some_and(|d| d.source_intelligence) {
        caveats.push("Runtime-only (source intelligence unavailable)".into());
    }

    // toRaiseConfidence — gap nextSource lines, highest impact first (never truncated).
    let mut gaps: Vec<_> = report.gap_analysis.gaps.iter().collect();
    gaps.sort_by(|a, b| crate::js::cmp_f64(b.confidence_impact, a.confidence_impact));
    let to_raise_confidence: Vec<String> = gaps.iter().map(|g| g.next_source.clone()).collect();

    let sources: Vec<SourceEntry> = report.source_status.clone()
        .map(|s| s.sources.into_iter().map(|e| SourceEntry { source: e.source.as_str().to_string(), status: e.status }).collect())
        .unwrap_or_default();

    (
        HonestyHeader {
            confidence,
            band,
            working_hypothesis,
            caveats: dedupe(caveats),
            to_raise_confidence,
            routing: report.next_steps.clone().unwrap_or_default(),
            sources,
        },
        seed_linked,
    )
}

// ── Relevant files ───────────────────────────────────────────────────────────

struct FileAccum {
    path: String,
    symbol: Option<String>,
    line: Option<i64>,
    why: String,
    rank: u8, // 0 = seed, 1 = implicated node, 2 = evidence-derived
    relevance: f64,
}

fn build_relevant_files(report: &InvestigationReport) -> Vec<FileAccum> {
    let mut by_path: IndexMap<String, FileAccum> = IndexMap::new();
    let ev_by_id: HashMap<&str, &Evidence> = report.evidence.iter().map(|e| (e.id.as_str(), e)).collect();

    let consider = |by_path: &mut IndexMap<String, FileAccum>, acc: FileAccum| {
        match by_path.get(&acc.path) {
            None => {
                by_path.insert(acc.path.clone(), acc);
            }
            // Keep the stronger provenance (lower rank wins; then higher relevance).
            Some(existing) if acc.rank < existing.rank || (acc.rank == existing.rank && acc.relevance > existing.relevance) => {
                let merged = FileAccum {
                    symbol: acc.symbol.clone().or_else(|| existing.symbol.clone()),
                    line: acc.line.or(existing.line),
                    ..acc
                };
                by_path.insert(merged.path.clone(), merged);
            }
            Some(_) => {}
        }
    };

    // Primary: the seed file.
    let seed = report.seeds.first();
    if let Some(seed) = seed {
        consider(
            &mut by_path,
            FileAccum {
                path: seed.file_path.clone(),
                symbol: Some(seed.name.clone()),
                line: seed.start_line,
                why: "seed symbol resolved from hint".into(),
                rank: 0,
                relevance: 1.0,
            },
        );
    }

    // Files attached to suspected-cause evidence.
    let headline_id = report.suspected_causes.first().map(|c| c.id.as_str());
    for cause in &report.suspected_causes {
        for eid in &cause.source_evidence_ids {
            let Some(ev) = ev_by_id.get(eid.as_str()) else { continue };
            let Some(file) = ev.links.file.as_deref().filter(|f| !f.is_empty()) else { continue };
            consider(
                &mut by_path,
                FileAccum {
                    path: file.to_string(),
                    symbol: None,
                    line: ev.links.line,
                    why: if Some(cause.id.as_str()) == headline_id {
                        "file referenced by headline cause evidence".into()
                    } else {
                        "file referenced by suspected-cause evidence".into()
                    },
                    rank: 2,
                    relevance: ev.relevance,
                },
            );
        }
    }

    // Implicated graph nodes (file/symbol) — honour the contract for forward-compatibility.
    let seed_name = seed.map(|s| s.name.clone());
    for node in &report.graph.nodes {
        if !(node.node_type == GraphNodeType::File || node.node_type == GraphNodeType::Symbol) || !node.implicated {
            continue;
        }
        let path: Option<String> = if node.node_type == GraphNodeType::File {
            Some(node.label.clone())
        } else {
            node.evidence_ids.iter().find_map(|eid| ev_by_id.get(eid.as_str()).and_then(|e| e.links.file.clone()).filter(|f| !f.is_empty()))
        };
        let Some(path) = path.filter(|p| !p.is_empty()) else { continue };
        consider(
            &mut by_path,
            FileAccum {
                path,
                symbol: if node.node_type == GraphNodeType::Symbol { Some(node.label.clone()) } else { None },
                line: None,
                why: match &seed_name {
                    Some(n) => format!("caller within blast radius of {n}"),
                    None => "implicated node within blast radius".into(),
                },
                rank: 1,
                relevance: node.implication_score,
            },
        );
    }

    let mut out: Vec<FileAccum> = by_path.into_values().collect();
    out.sort_by(|a, b| {
        a.rank
            .cmp(&b.rank)
            .then_with(|| crate::js::cmp_f64(b.relevance, a.relevance))
            .then_with(|| locale_compare(&a.path, &b.path))
    });
    out
}

// ── Evidence ─────────────────────────────────────────────────────────────────

fn build_evidence(report: &InvestigationReport) -> Vec<EvidenceItem> {
    let mut items: Vec<(String, EvidenceItem)> = report
        .evidence
        .iter()
        .filter(|ev| !is_structural_evidence(ev))
        .map(|ev| {
            let link = EvidenceLink {
                file: ev.links.file.clone(),
                line: ev.links.line,
                commit: ev.links.commit.clone(),
                trace_id: ev.links.trace_id.clone(),
            };
            let item = EvidenceItem {
                title: ev.title.clone(),
                source: ev.source,
                relevance: ev.relevance,
                category: ev.category,
                priority: ev.priority,
                timestamp: ev.timestamp.clone(),
                link: if link == EvidenceLink::default() { None } else { Some(link) },
            };
            (ev.id.clone(), item)
        })
        .collect();

    items.sort_by(|(ida, a), (idb, b)| {
        priority_rank(a.priority)
            .cmp(&priority_rank(b.priority))
            .then_with(|| crate::js::cmp_f64(b.relevance, a.relevance))
            .then_with(|| locale_compare(ida, idb))
    });

    items.into_iter().map(|(_, item)| item).collect()
}

// ── Lower-priority areas (conservative anti-context) ──────────────────────────

fn build_lower_priority(report: &InvestigationReport, seed_low_confidence: bool, effective_top_lower: i64) -> (Vec<LowerPriorityArea>, usize) {
    let seed = report.seeds.first();

    // Hard gating — suppress the entire list unless ALL hold.
    let code_present = !report.degraded.as_ref().is_some_and(|d| d.source_intelligence);
    let recent = recent_changes(report);
    let Some(seed) = seed else { return (vec![], 0) };
    let Some(recent) = recent else { return (vec![], 0) };
    if !code_present || seed_low_confidence || effective_top_lower <= 0 {
        return (vec![], 0);
    }

    // Only claim negative runtime evidence when a runtime dimension actually ran.
    let runtime_ran = report.source_status.clone()
        .is_some_and(|s| s.sources.iter().any(|s| matches!(s.status, RuntimeSourceStatus::Contributed | RuntimeSourceStatus::Empty)));
    if !runtime_ran {
        return (vec![], 0);
    }

    let changed_files: HashSet<&str> = recent.changed_files.iter().map(String::as_str).collect();
    let change_range_label = format!("{}..{}", recent.window.since, recent.window.until.as_deref().unwrap_or("HEAD"));
    let seed_name = seed.name.as_str();
    let seed_file = seed.file_path.as_str();
    let seed_ids = seed_identity(report);
    let ev_by_id: HashMap<&str, &Evidence> = report.evidence.iter().map(|e| (e.id.as_str(), e)).collect();

    let mut on_path_evidence_ids: HashSet<String> =
        report.suspected_causes.first().map(|c| c.source_evidence_ids.iter().cloned().collect()).unwrap_or_default();
    on_path_evidence_ids.extend(seed_ids.evidence_ids.iter().cloned());

    // Protected names: alternative seeds surfaced as "Candidate areas (ranked)" must never be
    // lower-prioritised.
    let mut protected_names: HashSet<String> = HashSet::new();
    for f in &report.findings {
        if let Some(list) = f.title.strip_prefix("Candidate areas (ranked):") {
            for token in list.split(',') {
                let name = token.trim().split(" [").next().unwrap_or("").trim();
                if !name.is_empty() {
                    protected_names.insert(name.to_lowercase());
                }
            }
        }
    }

    struct Candidate<'a> {
        area: &'a str,
        evidence_ids: &'a [String],
        files: HashSet<&'a str>,
        implicated: bool,
    }
    let mut candidates: Vec<Candidate> = vec![];
    for node in &report.graph.nodes {
        if node.node_type == GraphNodeType::ExternalSystem {
            let files: HashSet<&str> = node
                .evidence_ids
                .iter()
                .filter_map(|eid| ev_by_id.get(eid.as_str()).and_then(|e| e.links.file.as_deref()).filter(|f| !f.is_empty()))
                .collect();
            candidates.push(Candidate { area: &node.label, evidence_ids: &node.evidence_ids, implicated: node.implicated, files });
        } else if node.node_type == GraphNodeType::File && is_test_or_example_path(&node.label) {
            candidates.push(Candidate {
                area: &node.label,
                evidence_ids: &node.evidence_ids,
                implicated: node.implicated,
                files: HashSet::from([node.label.as_str()]),
            });
        }
    }

    let mut out: Vec<LowerPriorityArea> = vec![];
    for c in &candidates {
        if protected_names.contains(&c.area.to_lowercase()) || c.files.contains(seed_file) {
            continue;
        }
        // Leg 1 — off-path.
        let off_path = !c.evidence_ids.iter().any(|id| on_path_evidence_ids.contains(id)) && !c.files.contains(seed_file);
        if !off_path {
            continue;
        }
        // Leg 2 — no attributed evidence (and the runtime dimensions ran, checked above).
        let has_runtime_evidence = c
            .evidence_ids
            .iter()
            .any(|id| ev_by_id.get(id.as_str()).is_some_and(|ev| is_runtime_kind(ev.kind) && !is_structural_evidence(ev)));
        if c.implicated || has_runtime_evidence {
            continue;
        }
        // Leg 3 — not in the change window.
        if c.files.iter().any(|f| changed_files.contains(f)) {
            continue;
        }
        out.push(LowerPriorityArea {
            area: c.area.to_string(),
            reasons: vec![
                format!("not reachable from {seed_name} within the analyzed blast radius; no queue-boundary link."),
                "no error logs, metric anomalies, or queue state attributed here.".into(),
                format!("no commits in {change_range_label} touched files here."),
                BLAST_RADIUS_CAVEAT.into(),
            ],
        });
    }

    out.sort_by(|a, b| locale_compare(&a.area, &b.area));
    let total = out.len();
    out.truncate(effective_top_lower as usize);
    (out, total)
}

// ── Remembered context (memory) ───────────────────────────────────────────────

/// Flatten the already-ranked `RecalledMemory[]` into the compact, honesty-framed shape, capped.
/// Order is preserved verbatim — the packet never re-ranks.
fn build_memory_context(recalled: &[RecalledMemory], cap: i64) -> (Vec<MemoryContextItem>, usize) {
    if cap <= 0 || recalled.is_empty() {
        return (vec![], recalled.len());
    }
    let items = recalled
        .iter()
        .take(cap as usize)
        .map(|r| MemoryContextItem {
            id: r.item.id.clone(),
            claim: r.item.claim.clone(),
            kind: r.item.kind.clone(),
            scope: r.item.scope.clone(),
            confidence: r.item.confidence,
            status: r.freshness.status.clone(),
            freshness: r.freshness.label,
            age_days: r.freshness.age_days,
            drift_detected: r.freshness.drift_detected,
        })
        .collect();
    (items, recalled.len())
}

// ── build_packet ─────────────────────────────────────────────────────────────

pub fn build_packet(report: &InvestigationReport, opts: PacketOptions) -> Packet {
    let p = opts.preset.map(preset);

    // Caps: defaults, lowered by an explicit option, then lowered (never raised) by a preset.
    let cap = |explicit: Option<i64>, def: i64, preset_val: Option<i64>| -> i64 {
        let mut n = explicit.unwrap_or(def);
        if let Some(pv) = preset_val {
            n = n.min(pv);
        }
        n.max(0)
    };
    let top_files = cap(opts.top_files, DEFAULT_TOP_FILES, p.as_ref().and_then(|p| p.top_files));
    let top_evidence = cap(opts.top_evidence, DEFAULT_TOP_EVIDENCE, p.as_ref().and_then(|p| p.top_evidence));
    let top_steps = cap(opts.top_steps, DEFAULT_TOP_STEPS, None);
    let top_memory = cap(opts.top_memory, DEFAULT_TOP_MEMORY, p.as_ref().and_then(|p| p.top_memory));
    let base_top_lower = cap(opts.top_lower, DEFAULT_TOP_LOWER, None);

    let seed_low_confidence = is_seed_low_confidence(report);
    let seed_ids = seed_identity(report);

    let (header, seed_linked) = build_honesty(report, &seed_ids, seed_low_confidence, opts.freshness.as_ref());

    let seed = report.seeds.first();
    let problem = ProblemSection {
        hint: report.input.hint.clone(),
        summary: report.summary.clone(),
        headline_cause: report.suspected_causes.first().map(|h| HeadlineCause {
            title: h.title.clone(),
            band: h.band,
            final_score: h.final_score,
            seed_linked,
            category: h.category.clone(),
        }),
        seed_location: seed.map(|s| format_symbol_location(&s.file_path, s.start_line, s.end_line)),
    };

    let all_files = build_relevant_files(report);
    let files_total = all_files.len();
    let relevant_files: Vec<RelevantFile> = all_files
        .into_iter()
        .take(top_files as usize)
        .map(|f| RelevantFile { path: f.path, symbol: f.symbol, line: f.line, why: f.why })
        .collect();
    let files_trunc = (files_total - relevant_files.len()) as i64;

    let all_evidence = build_evidence(report);
    let evidence_total = all_evidence.len();
    let evidence: Vec<EvidenceItem> = all_evidence.into_iter().take(top_evidence as usize).collect();
    let evidence_trunc = (evidence_total - evidence.len()) as i64;

    let next_steps: Vec<String> = report.next_actions.iter().take(top_steps as usize).cloned().collect();
    let steps_trunc = (report.next_actions.len() - next_steps.len()) as i64;

    // List length tracks honesty: wider gaps → shorter or empty list.
    let ceiling = report.gap_analysis.confidence_ceiling;
    let effective_top_lower = if ceiling >= 0.7 {
        base_top_lower
    } else if ceiling >= 0.5 {
        base_top_lower.min(1)
    } else {
        0
    };
    let (lower_items, lower_total) = build_lower_priority(report, seed_low_confidence, effective_top_lower);
    let lower_trunc = (lower_total - lower_items.len()) as i64;

    let (mem_items, mem_total) = build_memory_context(opts.memory.as_deref().unwrap_or(&[]), top_memory);
    let memory_trunc = (mem_total - mem_items.len()) as i64;

    let truncation = Truncation {
        relevant_files: files_trunc,
        evidence: evidence_trunc,
        lower_priority: lower_trunc,
        memory: memory_trunc,
        next_steps: steps_trunc,
    };
    let truncated = files_trunc > 0 || evidence_trunc > 0 || lower_trunc > 0 || memory_trunc > 0 || steps_trunc > 0;

    let meta = PacketMeta {
        investigation_id: Some(report.id.clone()).filter(|s| !s.is_empty()),
        generated_at: opts.now.unwrap_or_else(iso_now),
        scope: report.input.scope.clone(),
        service: report.input.service.clone(),
        truncated,
        preset: opts.preset,
    };

    Packet {
        honesty: header,
        problem,
        repo: opts.repo,
        relevant_files,
        evidence,
        lower_priority: lower_items,
        memory: mem_items,
        next_steps,
        truncation,
        meta,
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// Append a single synthetic "+N more" line when a section was truncated.
fn more_line(out: &mut Vec<String>, n: i64) {
    if n > 0 {
        out.push(format!("+{n} more"));
    }
}

fn freshness_label_name(l: FreshnessLabel) -> &'static str {
    match l {
        FreshnessLabel::Pinned => "pinned",
        FreshnessLabel::PossiblyStale => "possibly-stale",
        FreshnessLabel::Unverified => "unverified",
        FreshnessLabel::Fresh => "fresh",
        FreshnessLabel::Recent => "recent",
        FreshnessLabel::Aging => "aging",
        FreshnessLabel::Stale => "stale",
    }
}

pub fn render_packet_markdown(packet: &Packet) -> String {
    let show_timestamps = packet.meta.preset.map(|p| preset(p).show_timestamps).unwrap_or(true);
    let mut out: Vec<String> = vec![];

    // ── Honesty header (never truncated) ───────────────────────────────────────
    out.push(format!("# Agent Packet — {}", packet.problem.hint));
    out.push("".into());
    let wh = if packet.honesty.working_hypothesis { " · working hypothesis" } else { "" };
    out.push(format!("**Confidence:** {} ({}){wh}", to_fixed(packet.honesty.confidence, 2), packet.honesty.band.as_str()));
    out.push("".into());

    if !packet.honesty.caveats.is_empty() {
        out.push("## Honesty".into());
        for c in &packet.honesty.caveats {
            out.push(format!("- {c}"));
        }
        out.push("".into());
    }
    if !packet.honesty.to_raise_confidence.is_empty() {
        out.push("### To raise confidence".into());
        for t in &packet.honesty.to_raise_confidence {
            out.push(format!("- {t}"));
        }
        out.push("".into());
    }
    if !packet.honesty.sources.is_empty() {
        let src = packet.honesty.sources.iter().map(|s| format!("{}: {}", s.source, s.status.as_str())).collect::<Vec<_>>().join(" · ");
        out.push(format!("**Sources:** {src}"));
        out.push("".into());
    }

    // ── Problem ────────────────────────────────────────────────────────────────
    out.push("## Problem".into());
    out.push(packet.problem.summary.clone());
    if let Some(loc) = &packet.problem.seed_location {
        out.push(format!("- Seed: `{loc}`"));
    }
    if let Some(h) = &packet.problem.headline_cause {
        let link = if h.seed_linked { "seed-linked" } else { "not seed-linked" };
        out.push(format!("- Headline cause: {} _({}, {}, {link})_", h.title, to_fixed(h.final_score, 2), h.band.as_str()));
    }
    out.push("".into());

    // ── Relevant files ─────────────────────────────────────────────────────────
    out.push("## Relevant files".into());
    if packet.relevant_files.is_empty() {
        out.push("_none_".into());
    } else {
        for f in &packet.relevant_files {
            let loc = match f.line {
                Some(l) => format!("{}:{l}", f.path),
                None => f.path.clone(),
            };
            let sym = f.symbol.as_deref().filter(|s| !s.is_empty()).map(|s| format!(" `{s}`")).unwrap_or_default();
            out.push(format!("- `{loc}`{sym} — {}", f.why));
        }
        more_line(&mut out, packet.truncation.relevant_files);
    }
    out.push("".into());

    // ── Evidence ───────────────────────────────────────────────────────────────
    out.push("## Evidence".into());
    if packet.evidence.is_empty() {
        out.push("_none_".into());
    } else {
        for e in &packet.evidence {
            let mut tags: Vec<String> = vec![crate::types::provider_kind_name(e.source).to_string()];
            if let Some(p) = e.priority {
                tags.push(serde_json::to_value(p).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default());
            }
            if let Some(c) = e.category {
                tags.push(serde_json::to_value(c).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default());
            }
            let ts = match (&e.timestamp, show_timestamps) {
                (Some(t), true) if !t.is_empty() => format!(" _({t})_"),
                _ => String::new(),
            };
            out.push(format!("- [{}] {}{ts}", tags.join("/"), e.title));
        }
        more_line(&mut out, packet.truncation.evidence);
    }
    out.push("".into());

    // ── Lower-priority ─────────────────────────────────────────────────────────
    out.push(format!("## {LOWER_PRIORITY_TITLE}"));
    if packet.lower_priority.is_empty() {
        out.push("_none surfaced — insufficient evidence to lower-prioritise any area_".into());
    } else {
        for a in &packet.lower_priority {
            out.push(format!("- **{}**", a.area));
            for r in &a.reasons {
                out.push(format!("  - {r}"));
            }
        }
        more_line(&mut out, packet.truncation.lower_priority);
    }
    out.push("".into());

    // ── Remembered context (memory) — prior knowledge, NOT live evidence ─────────
    if !packet.memory.is_empty() {
        out.push("## Remembered context (not live evidence)".into());
        out.push("_Prior knowledge Horus has stored for this area. Context only — it does not feed confidence and never overrides the current run's evidence; it may be stale._".into());
        for m in &packet.memory {
            let conf = format!("{}%", number_string(math_round(m.confidence * 100.0)));
            let drift = if m.drift_detected { ", drift-detected" } else { "" };
            let age = match (show_timestamps, m.age_days) {
                (true, Some(d)) => format!(", {}d old", number_string(math_round(d))),
                _ => String::new(),
            };
            out.push(format!("- {} _({} · {}{drift}{age} · {conf} confidence)_", m.claim, m.kind, freshness_label_name(m.freshness)));
        }
        more_line(&mut out, packet.truncation.memory);
        out.push("".into());
    }

    // ── Next steps ─────────────────────────────────────────────────────────────
    out.push("## Suggested next steps".into());
    if packet.next_steps.is_empty() && packet.honesty.routing.is_empty() {
        out.push("_none_".into());
    } else {
        for s in &packet.next_steps {
            out.push(format!("- [ ] {s}"));
        }
        more_line(&mut out, packet.truncation.next_steps);
        for r in &packet.honesty.routing {
            out.push(format!("- [ ] {}", format_route_step(r)));
        }
    }

    out.join("\n")
}

/// Stable serialization: arrays stay clean, truncation is a sibling count.
pub fn packet_to_json(packet: &Packet) -> PacketJson {
    PacketJson {
        honesty: packet.honesty.clone(),
        problem: packet.problem.clone(),
        repo: packet.repo.clone(),
        relevant_files: PacketSection { items: packet.relevant_files.clone(), truncated_count: packet.truncation.relevant_files },
        evidence: PacketSection { items: packet.evidence.clone(), truncated_count: packet.truncation.evidence },
        lower_priority: PacketSection { items: packet.lower_priority.clone(), truncated_count: packet.truncation.lower_priority },
        memory: PacketSection { items: packet.memory.clone(), truncated_count: packet.truncation.memory },
        next_steps: PacketSection { items: packet.next_steps.clone(), truncated_count: packet.truncation.next_steps },
        meta: packet.meta.clone(),
    }
}
