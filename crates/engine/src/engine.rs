//! The deterministic investigation pipeline (HOR-5). NO AI/LLM.
//!
//! Given a free-text hint, it resolves seed symbols via the code provider, gathers structural
//! context (callers/callees, impact blast radius, execution flows, queue boundaries, and
//! optionally a change range), distills typed Evidence, derives deterministic findings + ranked
//! suspected causes, and persists everything.
//!
//! Determinism is a hard requirement: identical inputs and provider responses must produce the
//! same report (modulo generated UUIDs and timestamps). The clock is injected via
//! [`EngineDeps::now`].

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use horus_connectors::axiom::AxiomProvider;
use horus_connectors::bullmq::{analyze_queue_runtime, QueueRuntimeProvider, QueueRuntimeState, QueueSignalKind};
use horus_connectors::cloud_logs::StructuredLogSource;
use horus_connectors::duration::{DimensionSpec, DurationByDimension, DurationDimensionOptions};
use horus_connectors::elasticsearch::{CompatibilityOptions, IssueSeverity, LogAnalysis, LogLevel, LogQuery, LogsProvider};
use horus_connectors::git::provider::GitCommit;
use horus_connectors::grafana::{AnalyzeOptions, Anomaly, MetricsProvider};
use horus_connectors::jsutil::short_ts;
use horus_connectors::lens::{LensCollectOpts, LensProvider};
use horus_connectors::redis::{RedisStateAnalysis, RedisStateProvider};
use horus_connectors::runtime_queue::QueueEvidenceProvider;
use horus_connectors::sentry::{CollectOptions, SentryProvider};
use horus_connectors::shopify::{ShopifyCollectOpts, ShopifyProvider};
use horus_connectors::state::{select_state_signals, tokenize, AnalyzeStateOpts, StateAnalysis, StateProvider, StateSignalKind};
use horus_core::{
    redact_secrets, ChangeSet, Evidence, EvidenceKind, EvidenceLinks, EvidenceSubject, Flow, ImpactResult, ProviderKind,
    Provenance, Symbol, SymbolContext,
};
use horus_db::{
    list_investigations_with_reports, list_queue_edges, save_investigation_bundle, update_investigation_report, DbHandle,
    NewEvidenceRow, NewFindingRow, NewHypothesisRow, NewInvestigation, QueueEdge,
};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::auto_investigation_memory::{auto_investigation_memory_enabled, capture_investigation_memory};
use crate::cause_chain::build_cause_chains;
use crate::code_provider::CodeProvider;
use crate::confidence::compute_weighted_evidence_confidence;
use crate::correlate::{correlate, CorrelateOptions, CorrelationResult};
use crate::detect_data_flow_cause::detect_data_flow_cause_across;
use crate::gaps::{detect_missing_evidence, gap_next_actions, has_any_runtime_connector, CloudLogStatus, ConnectorFlags, GapAnalysis};
use crate::git_collector::{
    classify_config_change_files, collect_git_changes, commits_touching_range, default_change_window_since,
    latest_commit_date, BoundedGitChange, ConfigChangeCategory, ConfigChangeFile, GitChangeQuery,
    DEFAULT_CHANGE_WINDOW_DAYS,
};
use crate::graph::{build_graph, GraphNodeType, InvestigationGraph};
use crate::hint_matched_signal::{select_hint_matched_signal, SignalLike};
use crate::hypotheses::{generate_hypotheses, HypothesisContext};
use crate::js;
use crate::memory::{derive_tags, recall_similar, store_incident_memory};
use crate::memory_db::SqliteMemoryStorage;
use crate::memory_recall::{index_incident_hint, recall_startup_incidents, StartupIncident, StartupRecallOpts, StartupValidation};
use crate::memory_store::{AuditActor, AuditCtx, MemoryQuery, MemoryStore, MemoryVectorIndex};
use crate::normalize::{normalize_evidence, NormalizeContext};
use crate::ownership::{estimate_ownership, OwnershipDeps, OwnershipEstimate};
use crate::render::format_symbol_location;
use crate::router::{route, RouterCommand, RouterConditions};
use crate::score_cause::{rank_causes, select_headline_cause, CauseCandidate, CauseInput, ScoringContext, ScoringFinding, ScoringRequest};
use crate::seeds::{executable_base_name, is_type_like_name, parse_named_symbols, parse_seed_qualifier, parse_symbol_query, rank_seeds, RankedSeed};
use crate::source_status::build_runtime_source_status;
use crate::timeline::{build_timeline, Timeline};
pub use crate::types::Intent;
use crate::types::{
    BehavioralWalkthrough, Degraded, FindingKind, InvestigationInput, InvestigationReport, RecallTraceEntry, ReportFinding,
};
use crate::validate::validate_hypotheses;

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

/// Learned reranker (HOR-404): reorders ALREADY-ELIGIBLE causes; never changes scores.
pub type Reranker = dyn Fn(&[CauseCandidate]) -> Vec<CauseCandidate> + Send + Sync;

/// Dependencies the engine needs — every provider is optional and injected, exactly like the
/// TS options object. One failing provider never aborts the investigation.
pub struct EngineDeps<'a> {
    pub memory_scope: Option<String>,
    /// Optional local memory vector index; startup recall adds embedding similarity of stored hints.
    pub recall_index: Option<&'a dyn MemoryVectorIndex>,
    pub on_startup_recall: Option<&'a (dyn Fn(&[StartupIncident]) + Send + Sync)>,
    /// Source-intelligence provider. `None` ⇒ degraded, RUNTIME-ONLY run (HOR-319 layer-2).
    pub code: Option<&'a dyn CodeProvider>,
    pub db: &'a DbHandle,
    /// Optional learned reranker (HOR-404).
    pub rerank: Option<&'a Reranker>,
    pub logs: Option<&'a dyn LogsProvider>,
    pub mongo: Option<&'a dyn StateProvider>,
    pub postgres: Option<&'a dyn StateProvider>,
    pub sentry: Option<&'a SentryProvider>,
    pub lens: Option<&'a LensProvider>,
    pub axiom: Option<&'a AxiomProvider>,
    pub cloud_logs: Vec<&'a dyn StructuredLogSource>,
    pub additional_state: Vec<&'a dyn StateProvider>,
    pub additional_queues: Vec<&'a dyn QueueEvidenceProvider>,
    pub shopify: Option<&'a ShopifyProvider>,
    pub queue: Option<&'a dyn QueueRuntimeProvider>,
    pub redis_state: Option<&'a dyn RedisStateProvider>,
    pub metrics: Option<&'a dyn MetricsProvider>,
    /// Absolute path to the local git repository — enables ownership + change analysis.
    pub repo_path: Option<String>,
    /// Look-back window (days) for the auto change window (HOR-333).
    pub change_window_days: Option<i64>,
    /// Which connectors are configured for the env — drives honest gap text.
    pub connectors: Option<ConnectorFlags>,
    /// The CLI knows the source index is stale (routes `horus init`).
    pub stale_index: bool,
    /// Optional authored-memory store (HOR-432).
    pub store: Option<&'a dyn MemoryStore>,
    /// Injected clock (`Date.now()` in TS). `None` ⇒ `Utc::now()` once at entry.
    pub now: Option<DateTime<Utc>>,
}

impl<'a> EngineDeps<'a> {
    /// Deps with only the DB set — every provider absent.
    pub fn new(db: &'a DbHandle) -> Self {
        Self {
            memory_scope: None,
            recall_index: None,
            on_startup_recall: None,
            code: None,
            db,
            rerank: None,
            logs: None,
            mongo: None,
            postgres: None,
            sentry: None,
            lens: None,
            axiom: None,
            cloud_logs: vec![],
            additional_state: vec![],
            additional_queues: vec![],
            shopify: None,
            queue: None,
            redis_state: None,
            metrics: None,
            repo_path: None,
            change_window_days: None,
            connectors: None,
            stale_index: false,
            store: None,
            now: None,
        }
    }
}

/// Map an evidence kind to its originating provider.
fn source_for_kind(kind: EvidenceKind) -> ProviderKind {
    match kind {
        EvidenceKind::QueueEdge | EvidenceKind::QueueState => ProviderKind::Queue,
        EvidenceKind::Commit => ProviderKind::History,
        EvidenceKind::Log => ProviderKind::Logs,
        EvidenceKind::Metric => ProviderKind::Metrics,
        EvidenceKind::RedisKey | EvidenceKind::State => ProviderKind::State,
        _ => ProviderKind::Code,
    }
}

/// The entity under investigation (Stage 0); None when neither service nor environment is given.
fn investigation_subject(input: &InvestigationInput) -> Option<EvidenceSubject> {
    let service = input.service.clone().filter(|s| !s.is_empty());
    let environment = input.environment.clone().filter(|s| !s.is_empty());
    if service.is_none() && environment.is_none() {
        return None;
    }
    Some(EvidenceSubject { service, environment })
}

fn clamp01(n: f64) -> f64 {
    if n.is_nan() {
        return 0.0;
    }
    n.clamp(0.0, 1.0)
}

// Severity tiers for a seed-emitted runtime signal (dogfood GAP A).
const SEV_ERROR: i32 = 2;
const SEV_WARN: i32 = 1;
const SEV_INFO: i32 = 0;

/// Symbol names too generic to match queue-edge producers/workers (dogfood GAP G).
const GENERIC_SYMBOL_NAMES: &[&str] = &["", "constructor", "unknown", "unknown-producer", "unknown-worker", "anonymous", "default"];

re!(SEV_PREFIX, r"^([A-Z])_");
re!(SEV_INFO_WORDS, r"(?-u:\b)(skip|skipping|skipped|deprecat|info|debug|trace|notice)(?-u:\b)");
re!(SEV_WARN_WORDS, r"(?-u:\b)warn(ing)?(?-u:\b)");

/// Classify a seed-emitted code's severity: ES log level, then the event_code prefix
/// convention, then message keywords. Unknown ⇒ error (never silently downgrade a failure).
pub fn seed_emitted_severity_tier(level: Option<&str>, code: &str, message: Option<&str>) -> i32 {
    match level.map(str::to_lowercase).as_deref() {
        Some("error" | "fatal" | "critical") => return SEV_ERROR,
        Some("warn" | "warning") => return SEV_WARN,
        Some("info" | "debug" | "trace") => return SEV_INFO,
        _ => {}
    }
    match SEV_PREFIX.captures(code).and_then(|c| c.get(1)).map(|m| m.as_str()) {
        Some("W") => return SEV_WARN,
        Some("D" | "I" | "T") => return SEV_INFO,
        Some("E" | "F" | "C") => return SEV_ERROR,
        _ => {}
    }
    let text = format!("{code} {}", message.unwrap_or("")).to_lowercase();
    if SEV_INFO_WORDS.is_match(&text) {
        return SEV_INFO;
    }
    if SEV_WARN_WORDS.is_match(&text) {
        return SEV_WARN;
    }
    SEV_ERROR
}

/// Bind the overall-confidence CEILING to the headline cause's finalScore (HOR-336). Monotonic;
/// applied as a min ceiling by the caller — it never raises confidence.
pub fn confidence_ceiling_for_cause(score: f64) -> f64 {
    let s = clamp01(score);
    if s < 0.2 {
        return 0.6;
    }
    if s < 0.5 {
        return 0.6 + ((s - 0.2) / (0.5 - 0.2)) * (0.78 - 0.6);
    }
    if s < 0.85 {
        return 0.78 + ((s - 0.5) / (0.85 - 0.5)) * (1.0 - 0.78);
    }
    1.0
}

/// Heuristic relevance per kind, kept deterministic.
fn relevance_for_kind(kind: EvidenceKind) -> f64 {
    match kind {
        EvidenceKind::Symbol => 0.9,
        EvidenceKind::Impact => 0.7,
        EvidenceKind::QueueEdge => 0.75,
        EvidenceKind::Flow => 0.6,
        EvidenceKind::Commit => 0.65,
        _ => 0.5,
    }
}

re!(FAIL_TIMEOUT, r"(?i)abort|timed?\s*out|timeout|ETIMEDOUT");
re!(FAIL_CONN, r"(?i)ECONNREFUSED|ECONNRESET|ENOTFOUND|EAI_AGAIN|EPIPE|socket|network|fetch failed");
re!(FAIL_STATUS_ARROW, r"->\s*(?:HTTP\s+)?(\d{3})(?-u:\b)");
re!(FAIL_STATUS_HTTP, r"(?-u:\b)HTTP\s+(\d{3})(?-u:\b)");
re!(FAIL_AUTH, r"(?i)unauthoriz|forbidden|WRONGPASS|NOAUTH|authenticat|invalid[^']*(token|key|credential|password)");
re!(FAIL_RATE, r"(?i)rate.?limit|too many requests");
re!(FAIL_5XX, r"(?i)internal server error");

/// Classify a connector error into a short, LEAK-SAFE failure category (never the raw message,
/// which embeds hosts/ports/URLs).
pub fn connector_failure_reason(err: &anyhow::Error) -> String {
    let text = format!("{err:#}");
    if FAIL_TIMEOUT.is_match(&text) {
        return "timeout".into();
    }
    if FAIL_CONN.is_match(&text) {
        return "connection failed".into();
    }
    let status = FAIL_STATUS_ARROW
        .captures(&text)
        .or_else(|| FAIL_STATUS_HTTP.captures(&text))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());
    if let Some(status) = status {
        if status == "401" || status == "403" {
            return "auth failure".into();
        }
        if status == "429" {
            return "rate limited".into();
        }
        if status.starts_with('5') {
            return "server error".into();
        }
        return "request failed".into();
    }
    if FAIL_AUTH.is_match(&text) {
        return "auth failure".into();
    }
    if FAIL_RATE.is_match(&text) {
        return "rate limited".into();
    }
    if FAIL_5XX.is_match(&text) {
        return "server error".into();
    }
    "request failed".into()
}

re!(DURATION_RE, r"^(\d+)([smhd])$");

/// Start of the log query window from `since` (24h/7d/30m/90s); anything else ⇒ 7 days ago.
pub fn log_window_from(since: Option<&str>, now: DateTime<Utc>) -> String {
    let now_ms = now.timestamp_millis() as f64;
    if let Some(since) = since {
        if let Some(m) = DURATION_RE.captures(since.trim()) {
            let value: f64 = m[1].parse().unwrap_or(0.0);
            let unit = match &m[2] {
                "s" => 1_000.0,
                "m" => 60_000.0,
                "h" => 3_600_000.0,
                _ => 86_400_000.0,
            };
            return js::iso_from_ms(now_ms - value * unit);
        }
    }
    js::iso_from_ms(now_ms - 7.0 * 86_400_000.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogRelevanceClass {
    Direct,
    Ambient,
}

impl LogRelevanceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            LogRelevanceClass::Direct => "direct",
            LogRelevanceClass::Ambient => "ambient",
        }
    }
}

/// Generic error/severity words appear in EVERY error signature (HOR-338).
const GENERIC_RELEVANCE_TERMS: &[&str] = &[
    "error", "errors", "err", "fail", "failed", "failing", "failure", "exception", "exceptions", "crash", "crashing",
    "issue", "problem", "slow", "timeout", "broken", "down", "production", "prod", "staging",
];

/// Classify a log signature's relevance to the investigation seed (HOR-156).
pub fn classify_log_relevance(
    sig_key: &str,
    sig_services: &[String],
    seed_terms: &[String],
    input_service: Option<&str>,
) -> (LogRelevanceClass, String) {
    let domain_terms: Vec<&String> =
        seed_terms.iter().filter(|t| !GENERIC_RELEVANCE_TERMS.contains(&t.as_str())).collect();
    if domain_terms.is_empty() {
        return (LogRelevanceClass::Direct, "no specific seed context — included by default".into());
    }
    let mut combined: Vec<String> = tokenize(sig_key);
    for s in sig_services {
        combined.extend(tokenize(s));
    }
    let matching: Vec<&str> = domain_terms
        .iter()
        .filter(|t| combined.iter().any(|c| c.contains(t.as_str()) || t.contains(c.as_str())))
        .map(|t| t.as_str())
        .collect();
    if !matching.is_empty() {
        return (
            LogRelevanceClass::Direct,
            format!("matches seed terms: {}", matching.iter().take(3).copied().collect::<Vec<_>>().join(", ")),
        );
    }
    if let Some(svc) = input_service.filter(|s| !s.is_empty()) {
        let lower = svc.to_lowercase();
        if sig_services.iter().any(|s| s.to_lowercase().contains(&lower)) {
            return (LogRelevanceClass::Direct, format!("from configured service: {svc}"));
        }
    }
    (LogRelevanceClass::Ambient, "no structural link to seed — ambient runtime noise".into())
}

/// Axiom row field names (priority order) for message / level / service (HOR-429).
const AXIOM_MESSAGE_FIELDS: &[&str] = &["message", "msg", "body", "event", "log", "_raw"];
const AXIOM_LEVEL_FIELDS: &[&str] = &["level", "severity", "lvl", "loglevel", "status"];
const AXIOM_SERVICE_FIELDS: &[&str] = &["service", "app", "logger", "source", "namespace"];

fn pick_axiom_field(fields: &Map<String, Value>, candidates: &[&str]) -> Option<String> {
    for key in candidates {
        match fields.get(*key) {
            Some(Value::String(s)) if !s.is_empty() => return Some(s.clone()),
            Some(Value::Number(n)) => return Some(n.as_f64().map(js::number_string).unwrap_or_else(|| n.to_string())),
            _ => {}
        }
    }
    None
}

re!(EVENT_CODE_RE, r"(?-u:\b)[A-Z][A-Z0-9_]{3,}(?-u:\b)");

/// The event_code candidates in a text: `\b(?=[A-Z0-9_]*[0-9_])[A-Z][A-Z0-9_]{3,}\b` — an
/// UPPER_SNAKE/alnum token (≥4) containing a digit or underscore.
fn event_code_tokens(text: &str) -> impl Iterator<Item = &str> {
    EVENT_CODE_RE.find_iter(text).map(|m| m.as_str()).filter(|t| t.chars().any(|c| c.is_ascii_digit() || c == '_'))
}

/// Extract code-shaped tokens (event_code values like HTTPFLT001 / E_SYNC_04) from free text.
/// De-duplicated, original order preserved.
pub fn extract_event_codes(texts: &[Option<&str>]) -> Vec<String> {
    let mut out: IndexSet<String> = IndexSet::new();
    for text in texts.iter().flatten() {
        if text.is_empty() {
            continue;
        }
        for code in event_code_tokens(text) {
            out.insert(code.to_string());
        }
    }
    out.into_iter().collect()
}

re!(ENTITY_IDS, r"(?i)(^|_)ids?$");
re!(ENTITY_ID_SUFFIX, r"id$");
re!(ENTITY_PREFIX, r"(?i)^(brand|order|user|customer|account|tenant|shop|merchant|product|seller)");

/// Context field names that look like entity identifiers worth aggregating (HOR-215).
pub fn detect_entity_fields(context: Option<&Map<String, Value>>, limit: usize) -> Vec<String> {
    let Some(context) = context else { return vec![] };
    let mut out = vec![];
    for (k, v) in context {
        if !(v.is_string() || v.is_number()) {
            continue;
        }
        if ENTITY_IDS.is_match(k) || ENTITY_ID_SUFFIX.is_match(k) || ENTITY_PREFIX.is_match(k) {
            out.push(k.clone());
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

/// Result of seeding an investigation from a log match instead of the hint (HOR-216).
#[derive(Debug, Clone, PartialEq)]
pub struct LogReseed {
    pub seeds: Vec<Symbol>,
    pub note: String,
    pub component: Option<String>,
    pub event_code: Option<String>,
}

/// Fallback seed resolution for raw error-string hints (HOR-216): search the logs for the
/// hint, then back-resolve the matching log's component to a source symbol.
pub async fn reseed_from_logs(hint: &str, input: &InvestigationInput, deps: &EngineDeps<'_>, now: DateTime<Utc>) -> Option<LogReseed> {
    let logs = deps.logs?;
    let code = deps.code?;
    let from = log_window_from(input.logs_since.as_deref().or(input.since.as_deref()), now);
    let records = logs
        .search_logs(&LogQuery {
            text: Some(hint.to_string()),
            broad_text: Some(true),
            from: Some(from),
            limit: Some(5),
            service: input.service.clone(),
            ..Default::default()
        })
        .await
        .ok()?;
    if records.is_empty() {
        return None;
    }
    let candidates: IndexSet<String> =
        records.iter().filter_map(|r| r.component.clone()).filter(|c| !c.is_empty()).collect();
    for name in candidates {
        let syms = code.search_symbols(&name, Some(5)).await.ok()?;
        if !syms.is_empty() {
            let tokens: Vec<String> = tokenize(&name).into_iter().collect::<IndexSet<_>>().into_iter().collect();
            let ranked = rank_seeds(&syms, Some(tokens.as_slice()), None, false, None, None);
            let first = &records[0];
            let component_label = first.component.clone().unwrap_or_else(|| "log entry".into());
            let code_label = first.event_code.as_deref().filter(|c| !c.is_empty()).map(|c| format!(" ({c})")).unwrap_or_default();
            let seed_name = ranked.first().map(|r| r.symbol.name.clone()).unwrap_or_else(|| name.clone());
            return Some(LogReseed {
                seeds: ranked.into_iter().map(|r| r.symbol).collect(),
                note: format!("Hint matched no symbol; resolved via logs: {component_label}{code_label} → {seed_name}"),
                component: first.component.clone(),
                event_code: first.event_code.clone(),
            });
        }
    }
    None
}

/// Confidence for the queue-runtime anomaly finding: starvation-only ⇒ 0.65, else 0.85.
pub fn queue_finding_confidence(starved_count: usize, backlogged_count: usize, failing_count: usize) -> f64 {
    if starved_count > 0 && backlogged_count == 0 && failing_count == 0 { 0.65 } else { 0.85 }
}

/// HOR-438: a per-segment queue STRUCTURE detected from queue-edge topology.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerSegmentQueueStructure {
    pub base_name: String,
    pub segments: Vec<String>,
    pub count: usize,
}

re!(SEGMENT_SUFFIX_RE, r"^[A-Za-z0-9][A-Za-z0-9_-]{0,15}$");

/// HOR-438: flag a base when 2+ queues share it with DISTINCT segment-looking `:` suffixes.
pub fn detect_per_segment_queues(queue_names: &[&str]) -> Vec<PerSegmentQueueStructure> {
    let mut by_base: IndexMap<String, IndexSet<String>> = IndexMap::new();
    for queue_name in queue_names {
        let chars: Vec<char> = queue_name.chars().collect();
        let Some(idx) = chars.iter().position(|c| *c == ':') else { continue };
        if idx == 0 || idx >= chars.len() - 1 {
            continue;
        }
        let base = chars[..idx].iter().collect::<String>().trim().to_string();
        let suffix = chars[idx + 1..].iter().collect::<String>().trim().to_string();
        if base.is_empty() || suffix.is_empty() || !SEGMENT_SUFFIX_RE.is_match(&suffix) {
            continue;
        }
        by_base.entry(base).or_default().insert(suffix);
    }
    let mut out: Vec<PerSegmentQueueStructure> = by_base
        .into_iter()
        .filter(|(_, segs)| segs.len() >= 2)
        .map(|(base_name, segs)| {
            let mut segments: Vec<String> = segs.into_iter().collect();
            segments.sort();
            PerSegmentQueueStructure { base_name, count: segments.len(), segments }
        })
        .collect();
    out.sort_by(|a, b| js::locale_compare(&a.base_name, &b.base_name));
    out
}

/// HOR-438b: a per-segment DISPATCH detected from the seed's CODE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerSegmentDispatch {
    pub symbol: String,
    pub param_name: String,
    pub param_type: String,
    /// `'queue' | 'caller-loop' | 'none'`
    pub fan_out: String,
    /// `'name' | 'type'`
    pub matched_by: String,
}

re!(SEGMENT_DIM_NAME_RE, r"(?i)(?-u:\b)(market|markets|region|regions|tenant|tenants|segment|shard|zone|locale|country|org|account)(?-u:\b)");
const SEGMENT_DIM_TYPE_ROOTS: &[&str] = &["market", "region", "tenant", "segment", "shard", "zone", "locale", "country", "org", "account"];
const GENERIC_DISPATCH_PARAM_NAMES: &[&str] = &[
    "id", "data", "input", "item", "payload", "ctx", "context", "options", "opts", "args", "arg", "params", "param", "value",
    "val", "obj", "config", "req", "res",
];

fn is_open(c: char) -> bool {
    matches!(c, '<' | '(' | '[' | '{')
}
fn is_close(c: char) -> bool {
    matches!(c, '>' | ')' | ']' | '}')
}

/// Top-level char index of `ch`, ignoring `<> () [] {}` nesting.
fn top_level_index_of(s: &[char], ch: char) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s.iter().enumerate() {
        if is_open(*c) {
            depth += 1;
        } else if is_close(*c) {
            depth -= 1;
        } else if *c == ch && depth == 0 {
            return Some(i);
        }
    }
    None
}

/// The parenthesized parameter list of a signature/source-body head ('' if none).
fn extract_param_list(sig: &str) -> String {
    let chars: Vec<char> = sig.chars().collect();
    let Some(open) = chars.iter().position(|c| *c == '(') else { return String::new() };
    let mut depth = 0i32;
    for i in open..chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return chars[open + 1..i].iter().collect();
                }
            }
            _ => {}
        }
    }
    String::new()
}

/// Split a parameter list on top-level commas.
fn split_top_level_params(list: &str) -> Vec<String> {
    let mut out = vec![];
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in list.chars() {
        if is_open(c) {
            depth += 1;
        } else if is_close(c) {
            depth -= 1;
        }
        if c == ',' && depth == 0 {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

re!(DECORATED_ARG_RE, r#"^@(?:Arg|Param|Query|Body)\s*\(\s*['"`]([^'"`]+)['"`]"#);
re!(DECORATOR_HEAD, r"^@[A-Za-z_]\w*");
re!(ACCESS_MODIFIER, r"^(?:public|private|protected|readonly)\s+");

fn strip_leading_decorators(s: &str) -> String {
    let mut cur: Vec<char> = s.trim().chars().collect();
    while cur.first() == Some(&'@') {
        let as_str: String = cur.iter().collect();
        let Some(m) = DECORATOR_HEAD.find(&as_str) else { break };
        let mut i = as_str[..m.end()].chars().count();
        while i < cur.len() && cur[i].is_whitespace() {
            i += 1;
        }
        if cur.get(i) == Some(&'(') {
            let mut depth = 0i32;
            let mut j = i;
            while j < cur.len() {
                let c = cur[j];
                if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                    if depth == 0 {
                        j += 1;
                        break;
                    }
                }
                j += 1;
            }
            cur = cur[j.min(cur.len())..].iter().collect::<String>().trim().chars().collect();
        } else {
            cur = cur[i..].iter().collect::<String>().trim().chars().collect();
        }
    }
    cur.into_iter().collect()
}

/// Parse one parameter into (name, type); None for destructured/empty params.
fn parse_param(raw: &str) -> Option<(String, String)> {
    let s = ACCESS_MODIFIER.replace(raw.trim(), "").into_owned();
    let s = s.strip_prefix("...").unwrap_or(&s).to_string();
    if s.starts_with('{') || s.starts_with('[') {
        return None;
    }
    let decorated = DECORATED_ARG_RE.captures(s.trim()).map(|m| m[1].to_string());
    let stripped: Vec<char> = strip_leading_decorators(&s).chars().collect();
    let colon = top_level_index_of(&stripped, ':');
    let mut name_part: String = match colon {
        Some(c) => stripped[..c].iter().collect(),
        None => stripped.iter().collect(),
    };
    let mut type_part: Vec<char> = match colon {
        Some(c) => stripped[c + 1..].to_vec(),
        None => vec![],
    };
    if let Some(eq) = top_level_index_of(&type_part, '=') {
        type_part.truncate(eq);
    }
    let ty = type_part.iter().collect::<String>().trim().to_string();
    let name = match decorated {
        Some(d) => d,
        None => {
            if let Some(eq) = name_part.find('=') {
                name_part.truncate(eq);
            }
            name_part.strip_suffix('?').unwrap_or(&name_part).trim().to_string()
        }
    };
    if name.is_empty() {
        return None;
    }
    Some((name, ty))
}

re!(DECAMEL_1, r"([a-z0-9])([A-Z])");
re!(DECAMEL_2, r"[_-]+");
fn de_camel(s: &str) -> String {
    DECAMEL_2.replace_all(&DECAMEL_1.replace_all(s, "$1 $2"), " ").into_owned()
}

re!(TYPE_IDENT, r"^([A-Za-z_][A-Za-z0-9_]*)");
re!(PASCAL_WORD, r"^[A-Z][a-z0-9]*");
fn pascal_type_root(ty: &str) -> Option<String> {
    let ident = TYPE_IDENT.captures(ty)?.get(1)?.as_str();
    if !ident.starts_with(|c: char| c.is_ascii_uppercase()) {
        return None;
    }
    let word = PASCAL_WORD.find(ident).map(|m| m.as_str()).unwrap_or(ident);
    Some(word.to_lowercase())
}

/// A caller's name + (optional) source body, for the caller-loop corroboration.
#[derive(Debug, Clone, Default)]
pub struct CallerBody {
    pub name: Option<String>,
    pub source_body: Option<String>,
}

re!(LOOP_KW, r"(?-u:\b)(for|forEach|map|while)(?-u:\b)");

/// HOR-438b: detect that the seed is a per-segment DISPATCHER from its signature alone.
pub fn detect_per_segment_dispatch(
    seed_context: &SymbolContext,
    queue_hits: &[QueueEdge],
    callers: &[CallerBody],
) -> Option<PerSegmentDispatch> {
    let seed_name = seed_context.symbol.name.clone();
    let sig = match seed_context.symbol.signature.as_deref() {
        Some(d) if !d.trim().is_empty() => d.to_string(),
        _ => js::slice_chars(seed_context.source_body.as_deref().unwrap_or(""), 600),
    };
    let param_list = extract_param_list(&sig);
    if param_list.is_empty() {
        return None;
    }
    let mut matched: Option<(String, String, &str)> = None;
    for p in split_top_level_params(&param_list) {
        let Some((name, ty)) = parse_param(&p) else { continue };
        if GENERIC_DISPATCH_PARAM_NAMES.contains(&name.to_lowercase().as_str()) {
            continue;
        }
        if SEGMENT_DIM_NAME_RE.is_match(&name) || SEGMENT_DIM_NAME_RE.is_match(&de_camel(&name)) {
            matched = Some((name, ty, "name"));
            break;
        }
        if pascal_type_root(&ty).is_some_and(|r| SEGMENT_DIM_TYPE_ROOTS.contains(&r.as_str())) {
            matched = Some((name, ty, "type"));
            break;
        }
    }
    let (param_name, param_type, by) = matched?;

    let in_queue = !seed_name.is_empty()
        && queue_hits.iter().any(|q| {
            q.producer_symbol.as_deref() == Some(seed_name.as_str()) || q.worker_symbol.as_deref() == Some(seed_name.as_str())
        });
    let fan_out = if in_queue {
        "queue"
    } else if callers.iter().any(|c| {
        let body = c.source_body.as_deref().unwrap_or("");
        !body.is_empty() && LOOP_KW.is_match(body) && SEGMENT_DIM_NAME_RE.is_match(body) && !seed_name.is_empty() && body.contains(&seed_name)
    }) {
        "caller-loop"
    } else {
        "none"
    };
    Some(PerSegmentDispatch { symbol: seed_name, param_name, param_type, fan_out: fan_out.into(), matched_by: by.into() })
}

re!(DIFFABLE, r"^[A-Za-z0-9._/~^-]+$");
re!(DURATION_SPEC, r"(?i)^\d+[smhd]$");

/// Does `since` look like a range or a concrete ref worth diffing?
pub fn looks_diffable(since: &str) -> bool {
    let s = since.trim();
    if s.is_empty() {
        return false;
    }
    if s.contains("..") {
        return true;
    }
    if DURATION_SPEC.is_match(s) {
        return false;
    }
    DIFFABLE.is_match(s)
}

/// HOR-385: the SINGLE source of truth for "this hint describes a live symptom / incident".
pub static INCIDENT_SYMPTOM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)(fail|fails|failed|failing|failure|break|breaks|breaking|broke|broken|crash|crashes|crashing|down|outage|incident|regress(?:ion|ed)?|degrad(?:e|ed|ing)?|slow|stuck|hang|hangs|hung|timeout|timing\s*out|latency|wrong|exception|error|errors|leak|leaking|stopped|throwing|throws|reject|rejected|denied|not\s+work|doesn'?t\s+work|isn'?t\s+work|can'?t|cannot|caus(?:e|es|ing)|misbehav|500|5xx|oom|out\s+of\s+memory|panic|p9[59]|throttl|spike|stack\s*trace|flap)").unwrap()
});

re!(EXPLAIN_LEAD, r"(?i)^\s*(explain|describe|walk\s+me\s+through|tell\s+me\s+(?:about|how))(?-u:\b)");
re!(REGRESSION_PHRASE, r"(?i)(?-u:\b)(recently\s+changed|what\s+changed|changed\s+recently|regress|regression)(?-u:\b)");
re!(QUESTION_BEHAVIOR, r"(?i)(?-u:\b)(how|what|why|when|where)(?-u:\b).*(?-u:\b)(work|works|working|do|does|done|happen|happens|flow|flows|behave|called|invoked|triggered|used)(?-u:\b)");
re!(LEADING_QUESTION, r"(?i)^\s*(how|what|why|when|where)(?-u:\b)");

/// HOR-334: does the hint read as a behavioral "how does X work" question?
pub fn looks_explanatory(hint: &str) -> bool {
    let h = hint.trim();
    if h.is_empty() {
        return false;
    }
    if EXPLAIN_LEAD.is_match(h) {
        return true;
    }
    if REGRESSION_PHRASE.is_match(h) {
        return false;
    }
    if QUESTION_BEHAVIOR.is_match(h) {
        return true;
    }
    if INCIDENT_SYMPTOM_RE.is_match(h) {
        return false;
    }
    LEADING_QUESTION.is_match(h)
}

re!(PERF_RE, r"(?i)(?-u:\b)(slow|slowness|sluggish|laggy|(?-u:\b)lag(?-u:\b)|latency|perf|performance|throughput|degraded|degradation|response\s*time|p9[59])(?-u:\b)");
/// Gap 4 — does the hint read as a latency/performance question?
pub fn looks_performance(hint: &str) -> bool {
    PERF_RE.is_match(hint)
}

re!(DURATION_THEMED_RE, r"(?i)(?-u:\b)(duration|took|elapsed|anomal(?:y|ies|ous)|spike|variance|regress(?:ion|ed)?|p\d{2})(?-u:\b)");
/// HOR-435: a duration/latency/anomaly question that warrants the per-dimension breakdown.
pub fn looks_duration_themed(hint: &str) -> bool {
    looks_performance(hint) || DURATION_THEMED_RE.is_match(hint)
}

re!(SUGGESTIVE, r"(?i)(?-u:\b)(could indicate|may be|might be|maybe|possibly|suggest(?:s|ing|ed)?|likely (?:caused|due)|points? to|consistent with|indicat(?:es|ive)|appears? to be|seems? to be|probably)(?-u:\b)");
static CATEGORY_CUES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("deployment-regression", r"(?i)(?-u:\b)(deploy(?:ment|ed)?|release|rollout|regression|recent change|shipped)(?-u:\b)"),
        ("infrastructure", r"(?i)(?-u:\b)(database|db|infra(?:structure)?|network|cache|disk|memory|cpu|oom|out of memory|connection pool|datastore|redis|mongo|postgres)(?-u:\b)"),
        ("external-api-latency", r"(?i)(?-u:\b)(upstream|external api|third[- ]party|downstream|api latency|timeout|slow (?:api|service)|gateway)(?-u:\b)"),
        ("retry-storm", r"(?i)(?-u:\b)(retr(?:y|ies)|retry storm|thundering herd|amplif)"),
        ("queue-backlog", r"(?i)(?-u:\b)(queue|backlog|consumer lag|enqueue)(?-u:\b)"),
        ("worker-slowdown", r"(?i)(?-u:\b)(worker|consumer)(?-u:\b)"),
        ("benign-variance", r"(?i)(?-u:\b)(per[- ]segment|per[- ]region|skew(?:ed)?|variance|expected variation|noise)(?-u:\b)"),
    ]
    .into_iter()
    .map(|(c, p)| (c, Regex::new(p).unwrap()))
    .collect()
});

/// HOR-435 (lever #1, de-anchor): categories the alert/hint TEXT merely *suggested*.
pub fn parse_suggested_causes(hint: &str) -> Vec<String> {
    if !SUGGESTIVE.is_match(hint) {
        return vec![];
    }
    CATEGORY_CUES.iter().filter(|(_, cue)| cue.is_match(hint)).map(|(c, _)| c.to_string()).collect()
}

/// HOR-435: compact human duration ("2m10s", "19ms", "1.5s", "1h2m").
pub fn format_duration_ms(ms: f64) -> String {
    if !ms.is_finite() || ms < 0.0 {
        return "?".into();
    }
    if ms < 1000.0 {
        return format!("{}ms", js::int_string(js::math_round(ms)));
    }
    let total_sec = ms / 1000.0;
    if total_sec < 60.0 {
        let s = js::math_round(total_sec * 10.0) / 10.0;
        return format!("{}s", js::number_string(s));
    }
    let total_min = (total_sec / 60.0).floor();
    let rem_sec = js::math_round(total_sec % 60.0);
    if total_min < 60.0 {
        return if rem_sec > 0.0 {
            format!("{}m{}s", js::int_string(total_min), js::int_string(rem_sec))
        } else {
            format!("{}m", js::int_string(total_min))
        };
    }
    let h = (total_min / 60.0).floor();
    let rem_min = total_min % 60.0;
    if rem_min > 0.0 {
        format!("{}h{}m", js::int_string(h), js::int_string(rem_min))
    } else {
        format!("{}h", js::int_string(h))
    }
}

static SOURCE_IMPACT_RE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?-u:\b)what depends on(?-u:\b)",
        r"(?i)(?-u:\b)blast[- ]?radius(?-u:\b)",
        r"(?i)(?-u:\b)impact of (?:adding|serving|removing|changing|renaming|moving|deleting)(?-u:\b)",
        r"(?i)(?-u:\b)affected by(?-u:\b)",
        r"(?i)(?-u:\b)who (?:calls|uses|imports|consumes)(?-u:\b)",
        r"(?i)(?-u:\b)downstream of(?-u:\b)",
        r"(?i)(?-u:\b)upstream of(?-u:\b)",
        r"(?i)(?-u:\b)ripple(?-u:\b)",
        r"(?i)(?-u:\b)if i (?:change|remove|rename|move|delete)(?-u:\b)",
        r"(?i)(?-u:\b)safe to (?:remove|delete|rename|change)(?-u:\b)",
    ]
    .into_iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

static VERIFY_ISOLATION_RE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)(?-u:\b)verify(?-u:\b).*(?-u:\b)(?:does ?n[o']?t|not) affect(?-u:\b)",
        r"(?i)(?-u:\b)is(?-u:\b).+(?-u:\b)isolated(?-u:\b)",
        r"(?i)(?-u:\b)isolated\??$",
        r"(?i)(?-u:\b)does(?-u:\b).+(?-u:\b)affect(?-u:\b)",
        r"(?i)(?-u:\b)any (?:impact|effect) on(?-u:\b)",
        r"(?i)(?-u:\b)contained to(?-u:\b)",
        r"(?i)(?-u:\b)bleed (?:in)?to(?-u:\b)",
        r"(?i)(?-u:\b)coupled to(?-u:\b)",
    ]
    .into_iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// Does the hint read as a "is X isolated from Y / does X affect Y" question?
pub fn looks_verify_isolation(hint: &str) -> bool {
    VERIFY_ISOLATION_RE.iter().any(|re| re.is_match(hint))
}

/// Does the hint read as a structural blast-radius / refactor-impact question?
pub fn looks_source_impact(hint: &str) -> bool {
    SOURCE_IMPACT_RE.iter().any(|re| re.is_match(hint)) || looks_verify_isolation(hint)
}

/// HOR-385: deterministic intent classifier — a live symptom ALWAYS wins.
pub fn classify_intent(hint: &str, since: Option<&str>) -> Intent {
    if since.is_some_and(looks_diffable) {
        return Intent::Incident;
    }
    if INCIDENT_SYMPTOM_RE.is_match(hint) {
        return Intent::Incident;
    }
    if looks_source_impact(hint) {
        return Intent::SourceImpact;
    }
    if looks_explanatory(hint) {
        return Intent::Explain;
    }
    Intent::Incident
}

re!(SHORT_FILE, r"^.*?((?:src|app|lib|packages)/.*)$");
re!(NOISE_PATH, r"(?i)logger|logging|\.log(?-u:\b)|telemetry");
re!(NOISE_NAME, r"(?i)^(forcontext|getlogger|child|debug|info|warn|error|log|trace|tracer)$");
re!(PERSIST_RE, r"(?i)(^|[._])(save|insert|upsert|persist|bulkwrite|find|findone|findmany|aggregate|delete|remove)(?-u:\b)|repositor|(?-u:\b)repo(?-u:\b)|\.model|entity|prisma|mongoose|typeorm|knex|(?-u:\b)dao(?-u:\b)|datasource");
re!(EXTERNAL_RE, r"(?i)(^|[._])(request|publish|enqueue|dispatch|emit|notify)(?-u:\b)|http|axios|(?-u:\b)api(?-u:\b)|webhook|(?-u:\b)queue(?-u:\b)|processor|producer|gateway|\.client(?-u:\b)");

fn short_file(f: &str) -> String {
    SHORT_FILE.replace(f, "$1").into_owned()
}

fn is_noise_symbol(s: &Symbol) -> bool {
    NOISE_PATH.is_match(&s.file_path) || NOISE_NAME.is_match(&s.name)
}

fn dedup_symbols(xs: Vec<Symbol>) -> Vec<Symbol> {
    let mut seen: HashSet<String> = HashSet::new();
    xs.into_iter().filter(|s| seen.insert(format!("{}:{}", s.name, s.file_path))).collect()
}

/// The flow with the most steps (stable — first wins on ties).
fn richest_flow(flows: &[Flow]) -> Option<&Flow> {
    let mut best: Option<&Flow> = None;
    for f in flows {
        if best.is_none_or(|b| f.steps.len() > b.steps.len()) {
            best = Some(f);
        }
    }
    best
}

/// Gap #5 — a behavioral "how does X work" walkthrough from the seed's richest Flow (or its
/// callees), plus heuristic external-call and persistence detection.
pub fn build_behavioral_walkthrough(
    hint: &str,
    top: Option<&Symbol>,
    ctx: Option<&SymbolContext>,
    flows: &[Flow],
    class_methods: &[Symbol],
) -> BehavioralWalkthrough {
    let flow = richest_flow(flows);
    let callees: Vec<Symbol> = ctx.map(|c| c.callees.clone()).unwrap_or_default();
    let raw_steps: Vec<Symbol> = match (flow, top) {
        (Some(f), _) if f.steps.len() > 1 => f.steps.clone(),
        (_, Some(t)) => std::iter::once(t.clone()).chain(callees.iter().cloned()).collect(),
        _ => callees.clone(),
    };
    let steps: Vec<Symbol> = raw_steps.into_iter().filter(|s| !is_noise_symbol(s)).collect();
    let entry: Option<Symbol> = steps.first().cloned().or_else(|| top.cloned());

    let pool: Vec<Symbol> = dedup_symbols(steps.iter().chain(callees.iter()).chain(class_methods.iter()).cloned().collect())
        .into_iter()
        .filter(|s| !is_noise_symbol(s))
        .collect();
    let persistence: Vec<String> = dedup_symbols(
        pool.iter().filter(|s| PERSIST_RE.is_match(&s.name) || PERSIST_RE.is_match(&s.file_path)).cloned().collect(),
    )
    .into_iter()
    .take(6)
    .map(|s| format!("{} ({})", s.name, short_file(&s.file_path)))
    .collect();
    let persist_names: HashSet<String> =
        persistence.iter().map(|p| p.split(" (").next().unwrap_or("").to_string()).collect();
    let external_calls: Vec<String> = dedup_symbols(
        pool.iter()
            .filter(|s| (EXTERNAL_RE.is_match(&s.name) || EXTERNAL_RE.is_match(&s.file_path)) && !persist_names.contains(&s.name))
            .cloned()
            .collect(),
    )
    .into_iter()
    .take(6)
    .map(|s| format!("{} ({})", s.name, short_file(&s.file_path)))
    .collect();

    let mut lines: Vec<String> = vec![];
    if let Some(e) = &entry {
        let loc = match e.start_line {
            Some(l) if l != 0 => format!("{}:{l}", short_file(&e.file_path)),
            _ => short_file(&e.file_path),
        };
        lines.push(format!("Entry point: `{}` ({loc}).", e.name));
    }
    let method_list = dedup_symbols(class_methods.iter().filter(|s| !is_noise_symbol(s)).cloned().collect());
    if steps.len() > 1 {
        let chain = steps.iter().take(12).map(|s| s.name.as_str()).collect::<Vec<_>>().join(" → ");
        lines.push(format!(
            "Flow: {chain}{}{}.",
            if steps.len() > 12 { " → …" } else { "" },
            flow.map(|f| format!(" ({} steps)", f.steps.len())).unwrap_or_default()
        ));
    } else if let (Some(e), false) = (&entry, method_list.is_empty()) {
        let names = method_list.iter().take(12).map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ");
        lines.push(format!(
            "`{}` is a class — its methods are the entry points: {names}{}. Trace one with `horus explain <method>`.",
            e.name,
            if method_list.len() > 12 { ", …" } else { "" }
        ));
    } else if let Some(e) = &entry {
        lines.push(format!("No multi-step execution flow was indexed for `{}` — showing its direct calls.", e.name));
    }
    if !external_calls.is_empty() {
        lines.push(format!("Calls out to: {}.", external_calls.join(", ")));
    }
    if !persistence.is_empty() {
        lines.push(format!("Persists via: {}.", persistence.join(", ")));
    }
    if lines.is_empty() {
        lines.push("No execution flow could be reconstructed for this query from the source graph.".into());
    }
    BehavioralWalkthrough {
        question: hint.to_string(),
        entry,
        steps,
        external_calls,
        persistence,
        narrative: lines.join("\n"),
    }
}

/// True when a symbol id resolves to a CLASS node.
fn is_class_symbol(sym: Option<&Symbol>) -> bool {
    sym.is_some_and(|s| s.id.split(':').next().unwrap_or("").to_lowercase() == "class")
}

/// Methods of a class symbol (dogfood GAP C). Best-effort: [] on error / unsupported.
async fn fetch_class_methods(code: &dyn CodeProvider, cls: &Symbol) -> Vec<Symbol> {
    let name = cls.name.trim();
    if name.is_empty() {
        return vec![];
    }
    code.class_methods(&cls.file_path, name).await.ok().flatten().unwrap_or_default()
}

re!(NOISE_BOT, r"(?i)\[bot\]");
re!(NOISE_BOT_NAME, r"(?i)(?-u:\b)(dependabot|renovate)(?-u:\b)");
re!(NOISE_BUMP, r"(?i)^bump\s");
re!(NOISE_DEPS, r"(?i)^(build|chore|fix|deps)\(deps(-dev)?\)");
re!(NOISE_MERGE, r"(?i)^merge(?-u:\b)");
re!(NOISE_RELEASE, r"(?i)^(prepare release|release|bump version|version bump|chore\(release\))");
re!(NOISE_PRECOMMIT, r"(?i)pre-commit.*autoupdate");
re!(NOISE_PRECOMMIT_CI, r"(?i)\[pre-commit\.ci\]");
re!(NOISE_TYPE, r"(?i)^(docs|style|test|ci)(\([^)]*\))?[:!]");
re!(NOISE_FORMAT, r"(?i)(?-u:\b)(reformat|whitespace|prettier|eslint)(?-u:\b)");
re!(NOISE_CODE_STYLE, r"(?i)(?-u:\b)code\s*(style|formatting)(?-u:\b)");
re!(NOISE_CLEANUP_FORMAT, r"(?i)(?-u:\b)clean\s*up(?-u:\b)[^.]*(?-u:\b)format");
re!(NOISE_DOCS, r"(?i)(?-u:\b)(documentation|docs|readme)(?-u:\b)");
re!(NOISE_DOCS_CODE, r"(?i)(?-u:\b)(endpoint|api|service|handler|controller|component|module|feature|migration|schema|query|cache|queue|webhook|sdk|cli|route)(?-u:\b)");

/// HOR-406/451: a commit that could not plausibly have introduced a runtime fault.
pub fn is_noise_commit(commit: &GitCommit) -> bool {
    let subject = commit.subject.trim();
    let author = commit.author.trim();
    if NOISE_BOT.is_match(author) || NOISE_BOT_NAME.is_match(author) {
        return true;
    }
    if NOISE_BUMP.is_match(subject) || NOISE_BOT_NAME.is_match(subject) || NOISE_DEPS.is_match(subject) {
        return true;
    }
    if NOISE_MERGE.is_match(subject) || NOISE_RELEASE.is_match(subject) {
        return true;
    }
    if NOISE_PRECOMMIT.is_match(subject) || NOISE_PRECOMMIT_CI.is_match(subject) {
        return true;
    }
    if NOISE_TYPE.is_match(subject) || NOISE_FORMAT.is_match(subject) || NOISE_CODE_STYLE.is_match(subject) || NOISE_CLEANUP_FORMAT.is_match(subject) {
        return true;
    }
    NOISE_DOCS.is_match(subject) && !NOISE_DOCS_CODE.is_match(subject)
}

fn matches_seed_file(f: &str, seed_file: &str) -> bool {
    f == seed_file || seed_file.ends_with(f) || f.ends_with(seed_file)
}

/// HOR-406: a RELEVANT change (non-noise commit touching the seed file within a non-trivial,
/// non-degenerate diff) shipped in the window.
pub fn seed_touched_by_relevant_change(recent: Option<&BoundedGitChange>, seed_file: Option<&str>) -> bool {
    let (Some(rc), Some(seed_file)) = (recent, seed_file) else { return false };
    if rc.is_degenerate() || rc.total_insertions + rc.total_deletions == 0 {
        return false;
    }
    rc.commits.iter().any(|c| !is_noise_commit(c) && c.files.iter().any(|f| matches_seed_file(f, seed_file)))
}

/// HOR-451: smallest changed-file count among non-noise commits that touched the seed file.
pub fn seed_touching_commit_focus(recent: Option<&BoundedGitChange>, seed_file: Option<&str>) -> Option<usize> {
    let (Some(rc), Some(seed_file)) = (recent, seed_file) else { return None };
    if rc.is_degenerate() {
        return None;
    }
    rc.commits
        .iter()
        .filter(|c| !is_noise_commit(c) && c.files.iter().any(|f| matches_seed_file(f, seed_file)))
        .map(|c| c.files.len())
        .min()
}

/// HOR-451: the deployment-regression prior, scaled by change focus.
pub fn regression_seed_touched_score(focus: Option<usize>) -> f64 {
    match focus {
        None => 0.18,
        Some(n) if n <= 4 => 0.45,
        Some(n) if n <= 8 => 0.38,
        Some(n) if n <= 14 => 0.3,
        Some(_) => 0.2,
    }
}

/// Files-touched count above which a seed-touching commit is broad churn.
pub const BROAD_CHANGE_FILE_THRESHOLD: usize = 14;

re!(CHORE_LIKE, r"(?i)^(chore|style|docs|ci|build)(\(|:)|(?-u:\b)typo(?-u:\b)|(?-u:\b)formatting(?-u:\b)|(?-u:\b)lint(?-u:\b)");
/// A maintenance-intent commit must never ANCHOR a deployment-regression cause.
pub fn is_chore_like_commit(commit: &GitCommit) -> bool {
    CHORE_LIKE.is_match(commit.subject.trim())
}

re!(WS_RUN, r"\s+");

/// HOR-333 citation clauses for the regression cause title.
#[derive(Debug, Clone, PartialEq)]
pub struct RegressionCitation {
    pub commit_clause: String,
    pub symbol_clause: String,
    pub maintenance_only: bool,
}

pub fn format_regression_citation(
    recent: Option<&BoundedGitChange>,
    changes: Option<&ChangeSet>,
    seed_file: Option<&str>,
) -> RegressionCitation {
    let matches = |f: &str| seed_file.is_none_or(|sf| matches_seed_file(f, sf));
    let all: Vec<&GitCommit> = recent.map(|r| r.commits.iter().filter(|c| !is_noise_commit(c)).collect()).unwrap_or_default();
    let seed_commits: Vec<&GitCommit> = if seed_file.is_some() {
        all.iter().copied().filter(|c| c.files.iter().any(|f| matches(f))).collect()
    } else {
        all
    };
    let behavioural: Vec<&GitCommit> = seed_commits.iter().copied().filter(|c| !is_chore_like_commit(c)).collect();
    let maintenance_only = !seed_commits.is_empty() && behavioural.is_empty();
    let commit_parts: Vec<String> = behavioural
        .iter()
        .take(2)
        .map(|c| {
            let sha = if c.short_sha.is_empty() { js::slice_chars(&c.sha, 7) } else { c.short_sha.clone() };
            let subject = WS_RUN.replace_all(&c.subject, " ").trim().to_string();
            if subject.is_empty() { sha } else { format!("{sha} \"{}\"", js::slice_chars(&subject, 50)) }
        })
        .collect();
    let commit_clause = if commit_parts.is_empty() { String::new() } else { format!(" ({})", commit_parts.join(", ")) };

    let modified: Vec<_> = changes.map(|c| c.modified.iter().filter(|m| matches(&m.after.file_path)).collect()).unwrap_or_default();
    let mut symbol_names: Vec<String> = vec![];
    for m in &modified {
        let name = if m.after.name.is_empty() { &m.before.name } else { &m.after.name };
        if !name.is_empty() && !symbol_names.contains(name) {
            symbol_names.push(name.clone());
        }
        if symbol_names.len() >= 3 {
            break;
        }
    }
    let symbol_clause = if symbol_names.is_empty() {
        String::new()
    } else {
        format!(" touched {}{}", symbol_names.join(", "), if modified.len() > symbol_names.len() { ", …" } else { "" })
    };
    RegressionCitation { commit_clause, symbol_clause, maintenance_only }
}

// ── Evidence factory ──────────────────────────────────────────────────────────

struct EvidenceSink {
    items: Vec<Evidence>,
    hint: String,
    collected_at: String,
}

impl EvidenceSink {
    /// `mkEv`: push a new evidence row with a UUID id and return it for follow-up tweaks.
    fn mk(
        &mut self,
        kind: EvidenceKind,
        title: impl Into<String>,
        payload: Value,
        links: EvidenceLinks,
        timestamp: Option<String>,
        relevance: Option<f64>,
    ) -> &mut Evidence {
        self.items.push(Evidence {
            id: uuid::Uuid::new_v4().to_string(),
            source: source_for_kind(kind),
            kind,
            title: title.into(),
            timestamp,
            relevance: relevance.unwrap_or_else(|| relevance_for_kind(kind)),
            payload,
            links,
            provenance: Provenance { query: self.hint.clone(), collected_at: self.collected_at.clone() },
            priority: None,
            category: None,
            subject: None,
            is_new: None,
            ratio: None,
        });
        self.items.last_mut().unwrap()
    }
}

fn symbol_links(s: &Symbol) -> EvidenceLinks {
    EvidenceLinks {
        symbol_id: Some(s.id.clone()),
        file: Some(s.file_path.clone()),
        line: s.start_line.filter(|l| *l > 0),
        ..Default::default()
    }
}

fn file_base(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("").to_string()
}

/// Distinct tokens of the given texts (`[...new Set([...tokenize(a), ...])]`).
fn term_set(texts: &[&str]) -> Vec<String> {
    let mut set: IndexSet<String> = IndexSet::new();
    for t in texts {
        set.extend(tokenize(t));
    }
    set.into_iter().collect()
}

fn opt_str(v: Option<&str>) -> Value {
    v.map(|s| Value::String(s.to_string())).unwrap_or(Value::Null)
}

fn opt_f64(v: Option<f64>) -> Value {
    v.map(Value::from).unwrap_or(Value::Null)
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() { None } else { Some(s.to_string()) }
}

/// One seed-emitted error join (HOR-341 / GAP D / GAP F).
struct SeedEmittedJoin {
    code: String,
    count: f64,
    message: String,
    ev_id: String,
    level: Option<String>,
    raised_by_seed: bool,
    raiser_name: String,
}

struct DirectSignature {
    key: String,
    count: f64,
    message: String,
}

struct QueueFailureSignal {
    reason: String,
    queue_name: String,
    ev_id: String,
    count: f64,
    stale: bool,
}

fn meta(pairs: &[(&str, Value)]) -> Option<Map<String, Value>> {
    Some(pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
}

const GENERIC_HINT_TOKENS: &[&str] = &[
    "service", "services", "controller", "controllers", "resolver", "resolvers", "worker", "workers", "repository",
    "provider", "module", "manager", "util", "utils", "helper", "handler", "error", "errors", "exception", "exceptions",
    "fail", "failed", "failing", "failure", "throw", "throwing", "thrown", "fatal", "crash", "crashing", "timeout",
    "production", "prod", "staging", "application", "issue", "problem", "broken", "slow",
];

re!(LEADING_SLASHES, r"^\.?/+");
re!(TRAILING_SLASHES, r"/+$");
re!(HINT_IS_PERF, r"(?i)(?-u:\b)(latenc|slow|spike|perf|throughput|duration|p9[5-9]|timeout|response\s*time|degrad)");
re!(NON_ALNUM_RUN, r"[^a-z0-9]+");
re!(INFRA_RE, r"(?i)(?-u:\b)(ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|ECONNRESET|getaddrinfo|socket hang up|connection (?:refused|reset|timed out)|network (?:error|timeout)|DNS)(?-u:\b)");
re!(ENTRY_RE, r"(?i)controller|resolver|route|handler|command|consumer|listener|gateway|cron|scheduler|webhook|middleware");
re!(CONSTRUCTOR_SUFFIX, r"\.constructor$");
re!(STARTUP_RECALL_OFF, r"(?i)^(0|false|off)$");

fn norm_name(s: &str) -> String {
    NON_ALNUM_RUN.replace_all(&s.to_lowercase(), " ").trim().to_string()
}

/// The investigate entry point. Fails only when the seed's required `context()` query fails
/// (TS lets that reject to the caller); every other provider failure degrades.
pub async fn investigate(input: InvestigationInput, deps: EngineDeps<'_>) -> anyhow::Result<InvestigationReport> {
    let now = deps.now.unwrap_or_else(Utc::now);
    let now_iso = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let code = deps.code;
    let db = deps.db;

    // a. PARSE
    let hint = input.hint.trim().to_string();
    let intent = classify_intent(&hint, input.since.as_deref());
    let named_symbols = parse_named_symbols(&hint);
    let alert_suggested_categories = parse_suggested_causes(&hint);
    let source_impact_hint = intent == Intent::SourceImpact;
    let prefer_named: Option<String> = named_symbols.first().cloned();

    let mut ev = EvidenceSink { items: vec![], hint: hint.clone(), collected_at: now_iso.clone() };
    let logs_window = || log_window_from(input.logs_since.as_deref().or(input.since.as_deref()), now);

    // Startup recall (memory) — checked before broad collection.
    let mut startup_recall: Vec<StartupIncident> = match deps.store {
        Some(store) if !STARTUP_RECALL_OFF.is_match(&std::env::var("HORUS_STARTUP_RECALL").unwrap_or_default()) => {
            recall_startup_incidents(store, &input, StartupRecallOpts { sync_scope: deps.memory_scope.clone(), now: Some(now), index: deps.recall_index })
                .await
                .unwrap_or_default()
        }
        _ => vec![],
    };
    let allowed_prior_ids: Option<HashSet<String>> = match (&deps.memory_scope, deps.store, input.repo.as_deref()) {
        (Some(scope), Some(store), Some(repo)) if !scope.is_empty() && !repo.is_empty() => {
            let items = store.query(MemoryQuery { repo: repo.to_string(), ..Default::default() }).await.unwrap_or_default();
            Some(
                items
                    .iter()
                    .filter(|it| {
                        !["forgotten", "deprecated", "contradicted"].contains(&it.status.as_str())
                            && (it.sync_scope.is_none() || it.sync_scope.as_deref() == Some(scope.as_str()))
                    })
                    .flat_map(|it| {
                        let payload = it.payload.as_ref().and_then(Value::as_object);
                        let mut ids: Vec<String> = vec![];
                        if let Some(id) = payload.and_then(|p| p.get("investigationId")).and_then(Value::as_str) {
                            ids.push(id.to_string());
                        }
                        if let Some(arr) = payload.and_then(|p| p.get("investigationIds")).and_then(Value::as_array) {
                            ids.extend(arr.iter().filter_map(Value::as_str).map(str::to_string));
                        }
                        ids
                    })
                    .collect(),
            )
        }
        _ => None,
    };
    if let Some(cb) = deps.on_startup_recall {
        cb(&startup_recall);
    }
    let mut recall_trace: Vec<RecallTraceEntry> = vec![];
    for candidate in &startup_recall {
        let check = candidate.checks.first().cloned().unwrap_or_default();
        let text = candidate
            .outcome
            .as_ref()
            .and_then(|o| o.applicability.error_code.clone())
            .or_else(|| input.incident.as_ref().and_then(|i| i.event_code.clone()))
            .or_else(|| candidate.outcome.as_ref().and_then(|o| o.applicability.event_code.clone()))
            .unwrap_or_else(|| input.hint.clone());
        let records = match deps.logs {
            Some(logs) => {
                logs.query_evidence(
                    &LogQuery {
                        service: input.service.clone(),
                        from: Some(logs_window()),
                        limit: Some(10),
                        text: Some(text),
                        broad_text: Some(true),
                        ..Default::default()
                    },
                    Some(&now_iso),
                )
                .await
            }
            None => vec![],
        };
        let checked: Vec<String> = records
            .into_iter()
            .map(|r| ev.mk(r.kind, r.title, r.payload, r.links, r.timestamp, Some(r.relevance)).id.clone())
            .collect();
        recall_trace.push(RecallTraceEntry {
            memory_id: candidate.memory_id.clone(),
            check,
            stage: if deps.logs.is_some() { "before-broad-collection" } else { "provider-unavailable" }.into(),
            evidence_ids: checked,
            error: None,
        });
    }

    // b. RESOLVE seeds (HOR-39) — git change window first so --since steers the seed (HOR-328).
    let degraded_no_source = code.is_none();
    let change_window_days = deps.change_window_days.unwrap_or(DEFAULT_CHANGE_WINDOW_DAYS);
    let auto_anchor_iso = match (&input.since, &deps.repo_path) {
        (None, Some(rp)) => latest_commit_date(rp).await,
        _ => None,
    };
    let change_range_label = match (&input.since, &auto_anchor_iso) {
        (Some(s), _) => format!("{s}..HEAD"),
        (None, Some(anchor)) => {
            format!("the {change_window_days} days before the last commit ({})", js::slice_chars(anchor, 10))
        }
        _ => format!("the last {change_window_days} days"),
    };
    let mut recent_changes: Option<BoundedGitChange> = None;
    if let Some(rp) = deps.repo_path.as_deref().filter(|r| !r.is_empty()) {
        let since = match &input.since {
            Some(s) => Some(s.clone()),
            None => default_change_window_since(rp, change_window_days).await,
        };
        if let Some(since) = since {
            recent_changes = Some(collect_git_changes(&GitChangeQuery { repo_path: rp.to_string(), since, ..Default::default() }).await);
        }
    }
    let changed_file_paths: Option<HashSet<String>> = recent_changes
        .as_ref()
        .filter(|rc| !rc.changed_files.is_empty())
        .map(|rc| rc.changed_files.iter().cloned().collect());

    // HOR-356: path scope.
    let scope_prefix: Option<String> = input
        .scope
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| TRAILING_SLASHES.replace(&LEADING_SLASHES.replace(s, ""), "").into_owned());
    let in_scope = |s: &Symbol| -> bool {
        match scope_prefix.as_deref().filter(|p| !p.is_empty()) {
            None => true,
            Some(prefix) => {
                let fp = LEADING_SLASHES.replace(&s.file_path, "");
                fp == prefix || fp.starts_with(&format!("{prefix}/"))
            }
        }
    };
    let seed_search_limit = if scope_prefix.as_deref().is_some_and(|p| !p.is_empty()) { 30 } else { 20 };
    let raw_seeds: Vec<Symbol> = match code {
        Some(c) => c.search_symbols(&hint, Some(seed_search_limit)).await?.into_iter().filter(|s| in_scope(s)).collect(),
        None => vec![],
    };
    let hint_tokens: Vec<String> = term_set(&[&hint]);
    let hint_has_code = event_code_tokens(&hint).next().is_some();
    let seed_qualifier = parse_symbol_query(&hint).or_else(|| parse_seed_qualifier(&hint));
    let ranked: Vec<RankedSeed> = rank_seeds(
        &raw_seeds,
        Some(hint_tokens.as_slice()),
        changed_file_paths.as_ref(),
        hint_has_code,
        seed_qualifier.as_ref(),
        prefer_named.as_deref(),
    );
    let mut seeds: Vec<Symbol> = ranked.iter().take(5).map(|r| r.symbol.clone()).collect();
    let mut top: Option<Symbol> = seeds.first().cloned();

    // HOR-337: qualifier re-search/adopt.
    if let (Some(q), Some(c)) = (&seed_qualifier, code) {
        if top.as_ref().is_none_or(|t| t.name.to_lowercase() != q.symbol.to_lowercase()) {
            let pool: Vec<Symbol> = c.search_symbols(&q.symbol, Some(seed_search_limit)).await?.into_iter().filter(|s| in_scope(s)).collect();
            let alt = rank_seeds(&pool, Some(hint_tokens.as_slice()), changed_file_paths.as_ref(), hint_has_code, Some(q), None);
            if let Some(alt_top) = alt.first().map(|r| r.symbol.clone()) {
                if alt_top.name.to_lowercase() == q.symbol.to_lowercase() && top.as_ref().is_none_or(|t| t.id != alt_top.id) {
                    seeds = std::iter::once(alt_top.clone()).chain(seeds.into_iter().filter(|s| s.id != alt_top.id)).take(5).collect();
                    top = Some(alt_top);
                }
            }
        }
    }

    // HOR-337: a TYPE/DTO seed → re-search for its executable counterpart.
    if let (Some(t), Some(c)) = (top.clone(), code) {
        if is_type_like_name(&t.name) {
            if let Some(base) = executable_base_name(&t.name) {
                let pool: Vec<Symbol> = c.search_symbols(&base, Some(seed_search_limit)).await?.into_iter().filter(|s| in_scope(s)).collect();
                let alt = rank_seeds(&pool, Some(hint_tokens.as_slice()), None, hint_has_code, None, None)
                    .into_iter()
                    .find(|r| !is_type_like_name(&r.symbol.name))
                    .map(|r| r.symbol);
                if let Some(alt_top) = alt.filter(|a| a.id != t.id) {
                    seeds = std::iter::once(alt_top.clone()).chain(seeds.into_iter().filter(|s| s.id != alt_top.id)).collect();
                    top = Some(alt_top);
                }
            }
        }
    }

    // HOR-385: pin the PROMPT-named symbol.
    if let (Some(named), Some(c)) = (&prefer_named, code) {
        if top.as_ref().is_none_or(|t| t.name.to_lowercase() != named.to_lowercase()) {
            let pool: Vec<Symbol> = c.search_symbols(named, Some(seed_search_limit)).await?.into_iter().filter(|s| in_scope(s)).collect();
            let alt = rank_seeds(&pool, Some(hint_tokens.as_slice()), changed_file_paths.as_ref(), hint_has_code, seed_qualifier.as_ref(), Some(named));
            if let Some(alt_top) = alt.first().map(|r| r.symbol.clone()) {
                if alt_top.name.to_lowercase() == named.to_lowercase() && top.as_ref().is_none_or(|t| t.id != alt_top.id) {
                    seeds = std::iter::once(alt_top.clone()).chain(seeds.into_iter().filter(|s| s.id != alt_top.id)).take(5).collect();
                    top = Some(alt_top);
                }
            }
        }
    }

    // HOR-216: raw error-string hint → reseed from logs.
    let mut log_reseed: Option<LogReseed> = None;
    if top.is_none() && !degraded_no_source {
        log_reseed = reseed_from_logs(&hint, &input, &deps, now).await;
        if let Some(r) = &log_reseed {
            seeds = r.seeds.clone();
            top = seeds.first().cloned();
        }
    }

    // HOR-335: a seed with ZERO hint-token overlap is a semantic guess.
    let seed_hay = top.as_ref().map(|t| format!("{} {}", t.name, t.file_path).to_lowercase()).unwrap_or_default();
    let meaningful_hint_tokens: Vec<String> =
        hint_tokens.iter().filter(|t| !GENERIC_HINT_TOKENS.contains(&t.as_str())).cloned().collect();
    let seed_is_low_confidence = top.as_ref().is_some_and(|t| {
        log_reseed.is_none()
            && t.score.unwrap_or(0.0) < 0.5
            && !meaningful_hint_tokens.is_empty()
            && !meaningful_hint_tokens.iter().any(|tk| seed_hay.contains(tk.as_str()))
    });

    // Empty result only when source intelligence WAS available but resolved nothing.
    if top.is_none() && !degraded_no_source {
        let mut report = InvestigationReport {
            startup_recall: Some(startup_recall),
            recall_trace: Some(recall_trace),
            id: uuid::Uuid::new_v4().to_string(),
            subject: investigation_subject(&input),
            summary: "No source symbols matched the hint".into(),
            intent: None,
            seeds: vec![],
            evidence: vec![],
            timeline: Timeline::default(),
            correlation: CorrelationResult { groups: vec![], chains: vec![], missing: correlate(&[], None).missing },
            findings: vec![],
            suspected_causes: vec![],
            hypotheses: vec![],
            similar_incidents: vec![],
            gap_analysis: GapAnalysis { gaps: vec![], blind_spots: vec![], confidence_ceiling: 0.0 },
            graph: InvestigationGraph::default(),
            confidence: 0.0,
            next_actions: vec![if deps.logs.is_some() {
                format!("No symbols matched \"{hint}\", and no recent error log matched it either. Try a more specific hint — an exact function, class, or file name — or widen --since.")
            } else {
                format!("No symbols matched \"{hint}\". Try a more specific hint — an exact function, class, or file name.")
            }],
            ownership: None,
            cause_chains: None,
            recent_changes: None,
            behavioral: None,
            degraded: None,
            next_steps: Some(route(&RouterConditions {
                empty: true,
                query: Some(hint.clone()),
                ..RouterConditions::new(RouterCommand::Investigate)
            })),
            source_status: None,
            created_at: None,
            persisted: None,
            memory_capture_error: None,
            ai_judgment: None,
            diagnosis: None,
            followup_rounds: None,
            fix_pr: None,
            unattended: None,
            input,
        };
        if let Some((id, _)) = persist(db, &mut report, &now_iso).await {
            report.id = id;
        }
        return Ok(report);
    }

    // Structural-evidence accumulators (runtime-only defaults in degraded mode).
    let mut label = input.service.clone().unwrap_or_else(|| hint.clone());
    let mut seed_loc = String::new();
    let mut ctx: Option<SymbolContext> = None;
    let mut impact: Option<ImpactResult> = None;
    let mut flows: Vec<Flow> = vec![];
    let mut seed_ev_id: Option<String> = None;
    let mut impact_ev_id: Option<String> = None;
    let mut flow_ev_ids: Vec<String> = vec![];
    let mut queue_hits: Vec<QueueEdge> = vec![];
    let mut queue_ev_by_name: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut per_segment_queue_structure_ev_ids: Vec<String> = vec![];
    let mut changes: Option<ChangeSet> = None;
    let mut change_ev_id: Option<String> = None;

    if let (Some(t), Some(c)) = (top.clone(), code) {
        label = if t.name == "constructor" {
            let last = t.id.rsplit(':').next().unwrap_or("");
            let cls = CONSTRUCTOR_SUFFIX.replace(last, "");
            format!("{} (constructor)", if cls.is_empty() { t.name.as_str() } else { &cls })
        } else {
            t.name.clone()
        };

        // c. GATHER — impact/flows degrade (HOR-445); context() is required.
        let (ctx_res, impact_res, flows_res) =
            tokio::join!(c.context(&t.id), c.impact(&t.id, Some(2), None), c.flows_for(&t.id, None));
        let seed_ctx = ctx_res?;
        impact = impact_res.ok();
        flows = flows_res.unwrap_or_default();
        // Investigation-store DB unreachable → skip queue-edge evidence.
        let edges = list_queue_edges(db, input.repo.as_deref(), None).await.unwrap_or_default();

        // GAP G: never match queue edges on GENERIC symbol names.
        let symbol_names: HashSet<String> = std::iter::once(t.name.clone())
            .chain(seed_ctx.callers.iter().map(|s| s.name.clone()))
            .chain(seed_ctx.callees.iter().map(|s| s.name.clone()))
            .filter(|n| !GENERIC_SYMBOL_NAMES.contains(&n.as_str()))
            .collect();
        queue_hits = edges
            .into_iter()
            .filter(|e| {
                let by_symbol = e.producer_symbol.as_ref().is_some_and(|p| symbol_names.contains(p))
                    || e.worker_symbol.as_ref().is_some_and(|w| symbol_names.contains(w));
                let by_file = e.producer_file.as_deref() == Some(t.file_path.as_str())
                    || e.worker_file.as_deref() == Some(t.file_path.as_str());
                by_symbol || by_file
            })
            .collect();

        // GAP G: drop edges whose cited symbols don't RESOLVE in this repo's source graph.
        if !queue_hits.is_empty() {
            let mut validated = vec![];
            for e in std::mem::take(&mut queue_hits) {
                let mut keep = false;
                for name in [e.producer_symbol.as_deref(), e.worker_symbol.as_deref()] {
                    let Some(name) = name.filter(|n| !GENERIC_SYMBOL_NAMES.contains(n)) else { continue };
                    keep = match c.search_symbols(name, Some(3)).await {
                        Ok(found) => found.iter().any(|s| s.name == name),
                        Err(_) => true, // can't verify → don't drop
                    };
                    if keep {
                        break;
                    }
                }
                if keep {
                    validated.push(e);
                }
            }
            queue_hits = validated;
        }

        if let Some(since) = input.since.as_deref().filter(|s| looks_diffable(s)) {
            changes = c
                .detect_changes(&horus_connectors::contract::DiffRange { base: since.to_string(), compare: "HEAD".into() })
                .await
                .ok();
        }

        // d. BUILD Evidence
        seed_loc = format_symbol_location(&t.file_path, t.start_line, t.end_line);
        seed_ev_id = Some(
            ev.mk(
                EvidenceKind::Symbol,
                format!("Seed symbol {} ({seed_loc})", t.name),
                json!({ "symbol": t, "snippet": opt_str(seed_ctx.snippet.as_deref()) }),
                symbol_links(&t),
                None,
                None,
            )
            .id
            .clone(),
        );
        for flow in &flows {
            let id = ev
                .mk(
                    EvidenceKind::Flow,
                    format!("Flow \"{}\" ({} step(s))", flow.name, flow.steps.len()),
                    json!({ "flowId": flow.id, "name": flow.name, "steps": flow.steps.iter().map(|s| s.name.clone()).collect::<Vec<_>>() }),
                    EvidenceLinks { symbol_id: Some(t.id.clone()), file: Some(t.file_path.clone()), ..Default::default() },
                    None,
                    None,
                )
                .id
                .clone();
            flow_ev_ids.push(id);
        }
        if let Some(imp) = &impact {
            impact_ev_id = Some(
                ev.mk(
                    EvidenceKind::Impact,
                    format!("Impact of {}: {} affected symbol(s)", t.name, imp.affected),
                    json!({ "affected": imp.affected }),
                    EvidenceLinks { symbol_id: Some(t.id.clone()), file: Some(t.file_path.clone()), ..Default::default() },
                    None,
                    None,
                )
                .id
                .clone(),
            );
        }
        for edge in &queue_hits {
            let producer = edge.producer_symbol.clone().unwrap_or_else(|| "unknown-producer".into());
            let worker = edge.worker_symbol.clone().unwrap_or_else(|| "unknown-worker".into());
            let id = ev
                .mk(
                    EvidenceKind::QueueEdge,
                    format!("Queue \"{}\": {producer} -> {worker}", edge.queue_name),
                    json!({
                        "queueName": edge.queue_name,
                        "producerSymbol": edge.producer_symbol,
                        "producerFile": edge.producer_file,
                        "workerSymbol": edge.worker_symbol,
                        "workerFile": edge.worker_file,
                        "source": edge.source,
                    }),
                    EvidenceLinks { queue_name: Some(edge.queue_name.clone()), ..Default::default() },
                    None,
                    None,
                )
                .id
                .clone();
            queue_ev_by_name.entry(edge.queue_name.clone()).or_default().push(id);
        }
        let hit_names: Vec<&str> = queue_hits.iter().map(|q| q.queue_name.as_str()).collect();
        for st in detect_per_segment_queues(&hit_names) {
            let id = ev
                .mk(
                    EvidenceKind::QueueEdge,
                    format!(
                        "Per-segment queue structure: \"{}\" fans out to {} segment(s) ({})",
                        st.base_name,
                        st.count,
                        st.segments.join(", ")
                    ),
                    json!({ "kind": "per-segment-queue-pattern", "baseName": st.base_name, "segments": st.segments, "count": st.count }),
                    EvidenceLinks { queue_name: Some(st.base_name.clone()), ..Default::default() },
                    None,
                    Some(0.4),
                )
                .id
                .clone();
            per_segment_queue_structure_ev_ids.push(id);
        }
        let caller_bodies: Vec<CallerBody> =
            seed_ctx.callers.iter().map(|s| CallerBody { name: Some(s.name.clone()), source_body: None }).collect();
        if let Some(d) = detect_per_segment_dispatch(&seed_ctx, &queue_hits, &caller_bodies) {
            let fan_out_note = if d.fan_out == "none" { String::new() } else { format!(" (fan-out: {})", d.fan_out) };
            let id = ev
                .mk(
                    EvidenceKind::Symbol,
                    format!(
                        "Per-segment dispatch: {} takes segment-dimension param \"{}\"{}{fan_out_note}",
                        d.symbol,
                        d.param_name,
                        if d.param_type.is_empty() { String::new() } else { format!(": {}", d.param_type) }
                    ),
                    json!({ "kind": "per-segment-dispatch", "symbol": d.symbol, "paramName": d.param_name, "paramType": d.param_type, "fanOut": d.fan_out }),
                    symbol_links(&t),
                    None,
                    Some(0.4),
                )
                .id
                .clone();
            per_segment_queue_structure_ev_ids.push(id);
        }
        if let Some(ch) = &changes {
            let id = ev
                .mk(
                    EvidenceKind::Commit,
                    format!(
                        "Change range {}..HEAD: +{} -{} ~{} symbol(s)",
                        input.since.as_deref().unwrap_or(""),
                        ch.added.len(),
                        ch.removed.len(),
                        ch.modified.len()
                    ),
                    json!({ "added": ch.added.len(), "removed": ch.removed.len(), "modified": ch.modified.len() }),
                    EvidenceLinks::default(),
                    None,
                    None,
                )
                .id
                .clone();
            change_ev_id = Some(id);
        }
        ctx = Some(seed_ctx);
    }

    // HOR-193: synthesize commit evidence from git history when no ChangeSet.
    if let Some(rc) = recent_changes.as_ref().filter(|rc| changes.is_none() && !rc.commits.is_empty() && !rc.is_degenerate()) {
        let id = ev
            .mk(
                EvidenceKind::Commit,
                format!(
                    "Git history {change_range_label}: {} commit(s), {} file(s) changed (+{} -{})",
                    rc.commits.len(),
                    rc.changed_files.len(),
                    rc.total_insertions,
                    rc.total_deletions
                ),
                json!({
                    "commits": rc.commits.iter().take(10).collect::<Vec<_>>(),
                    "changedFiles": rc.changed_files.iter().take(30).collect::<Vec<_>>(),
                    "totalInsertions": rc.total_insertions,
                    "totalDeletions": rc.total_deletions,
                    "source": "git",
                }),
                EvidenceLinks::default(),
                None,
                None,
            )
            .id
            .clone();
        change_ev_id = Some(id);
    }

    // Bounded per-commit timeline events. (TS guards on `changeEvId !== undefined`, which is
    // always true for its `null` initializer — so this fires for any non-degenerate window.)
    if let Some(rc) = recent_changes.as_ref().filter(|rc| !rc.is_degenerate()) {
        const PER_COMMIT_EVENT_CAP: usize = 8;
        for c in rc.commits.iter().filter(|c| !is_noise_commit(c)).take(PER_COMMIT_EVENT_CAP) {
            let sha = if c.short_sha.is_empty() { js::slice_chars(&c.sha, 7) } else { c.short_sha.clone() };
            let subject = js::slice_chars(WS_RUN.replace_all(&c.subject, " ").trim(), 70);
            ev.mk(
                EvidenceKind::Commit,
                format!(
                    "Commit {sha}{} ({} file(s))",
                    if subject.is_empty() { String::new() } else { format!(" \"{subject}\"") },
                    c.files.len()
                ),
                json!({ "source": "git", "perCommit": true, "sha": c.sha, "files": c.files.iter().take(10).collect::<Vec<_>>() }),
                EvidenceLinks::default(),
                Some(c.date_iso.clone()),
                Some(0.35),
            );
        }
    }

    // HOR-332: config/migration change source.
    let mut config_change_ev_id: Option<String> = None;
    let mut config_changes: Vec<ConfigChangeFile> = vec![];
    if let Some(rc) = recent_changes.as_ref().filter(|rc| !rc.is_degenerate() && !rc.changed_files.is_empty()) {
        config_changes = classify_config_change_files(&rc.changed_files);
        if !config_changes.is_empty() {
            let migration_n = config_changes.iter().filter(|c| c.category == ConfigChangeCategory::Migration).count();
            let config_n = config_changes.len() - migration_n;
            let mut parts: Vec<String> = vec![];
            if migration_n > 0 {
                parts.push(format!("{migration_n} migration/schema file(s)"));
            }
            if config_n > 0 {
                parts.push(format!("{config_n} config/data file(s)"));
            }
            let id = ev
                .mk(
                    EvidenceKind::Commit,
                    format!("Config/migration change {change_range_label}: {} changed", parts.join(", ")),
                    json!({
                        "source": "git",
                        "kind": "config-change",
                        "files": config_changes.iter().take(30).collect::<Vec<_>>(),
                        "migrationCount": migration_n,
                        "configCount": config_n,
                    }),
                    EvidenceLinks::default(),
                    None,
                    None,
                )
                .id
                .clone();
            config_change_ev_id = Some(id);
        }
    }

    let top_ref = top.as_ref();
    let seed_terms_for = |extra: bool| -> Vec<String> {
        match top_ref {
            Some(t) if extra => term_set(&[&hint, &t.name, &file_base(&t.file_path)]),
            _ => term_set(&[&hint]),
        }
    };

    // e0. RUNTIME LOG EVIDENCE (HOR-10/13).
    let mut analysis: Option<LogAnalysis> = None;
    let mut log_ev_ids: Vec<String> = vec![];
    let mut direct_log_ev_ids: Vec<String> = vec![];
    let mut ambient_log_ev_ids: Vec<String> = vec![];
    let mut per_dimension_duration_ev_ids: Vec<String> = vec![];
    let mut direct_signatures: Vec<DirectSignature> = vec![];
    let mut direct_ev_id_by_key: HashMap<String, String> = HashMap::new();
    let mut seed_emitted_joins: Vec<SeedEmittedJoin> = vec![];
    let mut entity_ev_ids: Vec<String> = vec![];
    let mut entity_summaries: Vec<String> = vec![];
    let mut logs_collected = false;
    let mut logs_compatibility_error: Option<String> = None;
    let mut logs_failure_reason: Option<String> = None;

    if let Some(logs) = deps.logs {
        let res: anyhow::Result<()> = async {
            let compat = logs
                .check_compatibility(Some(CompatibilityOptions {
                    requires_service: input.service.is_some(),
                    requires_service_aggregation: true,
                    requires_event_code: true,
                }))
                .await?;
            let compat_errors: Vec<_> = compat.issues.iter().filter(|i| i.severity == IssueSeverity::Error).collect();
            if !compat_errors.is_empty() {
                logs_compatibility_error = Some(js::slice_chars(
                    &compat_errors.iter().map(|i| format!("{}: {}", i.field, i.message)).collect::<Vec<_>>().join("; "),
                    300,
                ));
                return Ok(());
            }
            let logs_since = input.logs_since.as_deref().or(input.since.as_deref());
            let from = log_window_from(logs_since, now);
            let mut a = logs
                .analyze_errors(&LogQuery { service: input.service.clone(), from: Some(from.clone()), ..Default::default() }, None)
                .await?;
            // Auto-widen once to 30d when nothing matched and no window was pinned.
            if a.signatures.is_empty() && logs_since.is_none() {
                let retry = logs
                    .analyze_errors(
                        &LogQuery { service: input.service.clone(), from: Some(log_window_from(Some("30d"), now)), ..Default::default() },
                        None,
                    )
                    .await?;
                if !retry.signatures.is_empty() {
                    a = retry;
                }
            }
            logs_collected = true;

            let log_seed_terms = seed_terms_for(true);
            for s in a.signatures.iter().take(15) {
                let (relevance_class, relevance_reason) =
                    classify_log_relevance(&s.key, &s.services, &log_seed_terms, input.service.as_deref());
                let is_new = s.is_new == Some(true);
                let spike = s.ratio.is_some_and(|r| r >= 1.5);
                let mut tags: Vec<String> = vec![];
                if relevance_class == LogRelevanceClass::Ambient {
                    tags.push("ambient".into());
                }
                if is_new {
                    tags.push("NEW".into());
                } else if let Some(r) = s.ratio.filter(|r| r.is_finite() && *r >= 1.5) {
                    tags.push(format!("spike x{}", js::to_fixed(r, 1)));
                }
                let svc = if s.services.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", s.services.iter().take(3).cloned().collect::<Vec<_>>().join(", "))
                };
                let tag_str = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
                let msg_str = s
                    .sample_message
                    .as_deref()
                    .filter(|m| !m.is_empty())
                    .map(|m| format!(" — \"{}\"", js::slice_chars(WS_RUN.replace_all(m, " ").trim(), 90)))
                    .unwrap_or_default();
                let title = js::slice_chars(
                    &format!(
                        "Error {}: {}x (first {}, last {}){svc}{tag_str}{msg_str}",
                        s.key,
                        js::number_string(s.count),
                        short_ts(&s.first_seen),
                        short_ts(&s.last_seen)
                    ),
                    220,
                );
                let relevance = match (relevance_class, is_new, spike) {
                    (LogRelevanceClass::Direct, true, _) => 0.95,
                    (LogRelevanceClass::Direct, false, true) => 0.90,
                    (LogRelevanceClass::Direct, false, false) => 0.85,
                    (LogRelevanceClass::Ambient, true, _) => 0.70,
                    (LogRelevanceClass::Ambient, false, true) => 0.55,
                    (LogRelevanceClass::Ambient, false, false) => 0.35,
                };
                let e = ev.mk(
                    EvidenceKind::Log,
                    title,
                    json!({
                        "signature": s.key,
                        "level": "error",
                        "count": s.count,
                        "firstSeen": s.first_seen,
                        "lastSeen": s.last_seen,
                        "services": s.services,
                        "isNew": is_new,
                        "ratio": opt_f64(s.ratio),
                        "sampleMessage": opt_str(s.sample_message.as_deref()),
                        "relevanceClass": relevance_class.as_str(),
                        "relevanceReason": relevance_reason,
                    }),
                    EvidenceLinks::default(),
                    non_empty(&s.last_seen),
                    Some(relevance),
                );
                if is_new {
                    e.is_new = Some(true);
                }
                if let Some(r) = s.ratio.filter(|r| r.is_finite()) {
                    e.ratio = Some(r);
                }
                let id = e.id.clone();
                log_ev_ids.push(id.clone());
                if relevance_class == LogRelevanceClass::Direct {
                    direct_log_ev_ids.push(id.clone());
                    direct_signatures.push(DirectSignature {
                        key: s.key.clone(),
                        count: s.count,
                        message: s.sample_message.clone().unwrap_or_default(),
                    });
                    direct_ev_id_by_key.entry(s.key.clone()).or_insert(id);
                } else {
                    ambient_log_ev_ids.push(id);
                }
            }

            // CROSS-SIGNAL event_code JOIN (prefer the FULL seed body over the snippet).
            let seed_snippet: Option<String> =
                ctx.as_ref().and_then(|c| c.source_body.clone().or_else(|| c.snippet.clone()));
            let source_codes = extract_event_codes(&[Some(&input.hint), top_ref.map(|t| t.name.as_str()), seed_snippet.as_deref()]);
            let seed_emitted_codes: HashSet<String> =
                seed_snippet.as_deref().map(|s| extract_event_codes(&[Some(s)]).into_iter().collect()).unwrap_or_default();
            let mut joined_codes: HashSet<String> = direct_signatures.iter().map(|d| d.key.clone()).collect();
            for code_str in source_codes {
                let already_joined = joined_codes.contains(&code_str);
                joined_codes.insert(code_str.clone());
                let Ok(code_analysis) = logs
                    .analyze_errors(
                        &LogQuery {
                            service: input.service.clone(),
                            from: Some(from.clone()),
                            event_code: Some(code_str.clone()),
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                else {
                    continue;
                };
                let Some(sig) = code_analysis.signatures.iter().find(|s| s.key == code_str) else { continue };
                if sig.count <= 0.0 {
                    continue;
                }
                let level = sig.level.map(|l| l.as_str().to_string());
                if already_joined {
                    if seed_emitted_codes.contains(&code_str) {
                        if let Some(existing) = direct_ev_id_by_key.get(&code_str) {
                            seed_emitted_joins.push(SeedEmittedJoin {
                                code: code_str.clone(),
                                count: sig.count,
                                message: sig.sample_message.clone().unwrap_or_default(),
                                ev_id: existing.clone(),
                                level,
                                raised_by_seed: true,
                                raiser_name: top_ref.map(|t| t.name.clone()).unwrap_or_default(),
                            });
                        }
                    }
                    continue;
                }
                let links = top_ref.map(symbol_links).unwrap_or_default();
                let e = ev.mk(
                    EvidenceKind::Log,
                    js::slice_chars(
                        &format!(
                            "event_code {code_str}: {}x in Elasticsearch (exact structured match to the source signal)",
                            js::number_string(sig.count)
                        ),
                        220,
                    ),
                    json!({
                        "signature": code_str,
                        "count": sig.count,
                        "firstSeen": sig.first_seen,
                        "lastSeen": sig.last_seen,
                        "services": sig.services,
                        "isNew": sig.is_new == Some(true),
                        "ratio": opt_f64(sig.ratio),
                        "sampleMessage": opt_str(sig.sample_message.as_deref()),
                        "relevanceClass": "direct",
                        "relevanceReason": format!("exact event_code match to the source signal ({code_str})"),
                        "crossSignalJoin": true,
                        "seedEmitted": seed_emitted_codes.contains(&code_str),
                    }),
                    links,
                    non_empty(&sig.last_seen),
                    Some(0.9),
                );
                if sig.is_new == Some(true) {
                    e.is_new = Some(true);
                }
                if let Some(r) = sig.ratio.filter(|r| r.is_finite()) {
                    e.ratio = Some(r);
                }
                let id = e.id.clone();
                log_ev_ids.push(id.clone());
                direct_log_ev_ids.push(id.clone());
                direct_signatures.push(DirectSignature {
                    key: code_str.clone(),
                    count: sig.count,
                    message: sig.sample_message.clone().unwrap_or_default(),
                });
                direct_ev_id_by_key.entry(code_str.clone()).or_insert(id.clone());
                if seed_emitted_codes.contains(&code_str) {
                    seed_emitted_joins.push(SeedEmittedJoin {
                        code: code_str.clone(),
                        count: sig.count,
                        message: sig.sample_message.clone().unwrap_or_default(),
                        ev_id: id,
                        level,
                        raised_by_seed: true,
                        raiser_name: top_ref.map(|t| t.name.clone()).unwrap_or_default(),
                    });
                }
            }

            // GAP D: resolve each observed ES code's raise-site; seed-emitted when it's the
            // seed or a direct callee.
            if let (Some(t), Some(c)) = (top_ref, code) {
                const GAP_D_MAX_RESOLVE: usize = 12;
                let seed_scope: HashSet<String> = std::iter::once(t.id.clone())
                    .chain(ctx.as_ref().map(|c| c.callees.iter().map(|s| s.id.clone()).collect::<Vec<_>>()).unwrap_or_default())
                    .collect();
                let already_emitted: HashSet<String> = seed_emitted_joins.iter().map(|j| j.code.clone()).collect();
                let eligible: Vec<usize> = a
                    .signatures
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| !s.key.is_empty() && s.key != "(none)" && s.count > 0.0 && !already_emitted.contains(&s.key))
                    .map(|(i, _)| i)
                    .collect();
                let meaningful: Vec<&String> = meaningful_hint_tokens.iter().filter(|t| t.chars().count() >= 4).collect();
                let hint_relevant = |i: usize| {
                    let s = &a.signatures[i];
                    let msg = s.sample_message.as_deref().unwrap_or("").to_lowercase();
                    meaningful.iter().any(|t| s.key.to_lowercase().contains(t.as_str()) || msg.contains(t.as_str()))
                };
                let mut by_count = eligible.clone();
                by_count.sort_by(|x, y| js::cmp_f64(a.signatures[*y].count, a.signatures[*x].count));
                let mut cand: IndexSet<usize> = by_count.into_iter().take(GAP_D_MAX_RESOLVE).collect();
                cand.extend(eligible.iter().copied().filter(|i| hint_relevant(*i)).take(GAP_D_MAX_RESOLVE));
                for i in cand.into_iter().take(GAP_D_MAX_RESOLVE * 2) {
                    let sig = &a.signatures[i];
                    let Ok(raisers) = c.search_symbols(&sig.key, Some(3)).await else { continue };
                    let Some(raiser) = raisers.iter().find(|r| r.id == t.id).or_else(|| raisers.iter().find(|r| seed_scope.contains(&r.id))) else {
                        continue;
                    };
                    let ev_id = match direct_ev_id_by_key.get(&sig.key) {
                        Some(id) => id.clone(),
                        None => {
                            let where_ = if raiser.id == t.id { "the seed" } else { "a callee of the seed" };
                            let e = ev.mk(
                                EvidenceKind::Log,
                                js::slice_chars(
                                    &format!(
                                        "event_code {}: {}x in Elasticsearch — raised by {} ({where_})",
                                        sig.key,
                                        js::number_string(sig.count),
                                        raiser.name
                                    ),
                                    220,
                                ),
                                json!({
                                    "signature": sig.key,
                                    "count": sig.count,
                                    "firstSeen": sig.first_seen,
                                    "lastSeen": sig.last_seen,
                                    "services": sig.services,
                                    "isNew": sig.is_new == Some(true),
                                    "ratio": opt_f64(sig.ratio),
                                    "sampleMessage": opt_str(sig.sample_message.as_deref()),
                                    "relevanceClass": "direct",
                                    "relevanceReason": format!("event_code {} is raised by {} ({where_})", sig.key, raiser.name),
                                    "crossSignalJoin": true,
                                    "seedEmitted": true,
                                }),
                                symbol_links(raiser),
                                non_empty(&sig.last_seen),
                                Some(0.9),
                            );
                            if sig.is_new == Some(true) {
                                e.is_new = Some(true);
                            }
                            if let Some(r) = sig.ratio.filter(|r| r.is_finite()) {
                                e.ratio = Some(r);
                            }
                            let id = e.id.clone();
                            log_ev_ids.push(id.clone());
                            direct_log_ev_ids.push(id.clone());
                            direct_signatures.push(DirectSignature {
                                key: sig.key.clone(),
                                count: sig.count,
                                message: sig.sample_message.clone().unwrap_or_default(),
                            });
                            direct_ev_id_by_key.insert(sig.key.clone(), id.clone());
                            id
                        }
                    };
                    seed_emitted_joins.push(SeedEmittedJoin {
                        code: sig.key.clone(),
                        count: sig.count,
                        message: sig.sample_message.clone().unwrap_or_default(),
                        ev_id,
                        level: sig.level.map(|l| l.as_str().to_string()),
                        raised_by_seed: raiser.id == t.id,
                        raiser_name: raiser.name.clone(),
                    });
                }
            }

            // HOR-215: distinct failing entities behind the dominant signature.
            if let Some(sig) = a.signatures.iter().find(|s| !detect_entity_fields(s.sample_context.as_ref(), 2).is_empty()) {
                for f in detect_entity_fields(sig.sample_context.as_ref(), 2) {
                    let field = format!("context.{f}");
                    let Ok(buckets) = logs
                        .aggregate_errors(
                            &LogQuery {
                                service: input.service.clone(),
                                from: Some(from.clone()),
                                event_code: if sig.key != "(none)" { Some(sig.key.clone()) } else { None },
                                ..Default::default()
                            },
                            Some(&field),
                        )
                        .await
                    else {
                        continue;
                    };
                    if buckets.is_empty() {
                        continue;
                    }
                    let top3 = buckets
                        .iter()
                        .take(3)
                        .map(|b| format!("{} ({}x)", b.key, js::number_string(b.count)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let plus = if buckets.len() >= 20 { "+" } else { "" };
                    let id = ev
                        .mk(
                            EvidenceKind::Log,
                            js::slice_chars(
                                &format!("Distinct {field} for {}: {}{plus} value(s) (top: {top3})", sig.key, buckets.len()),
                                180,
                            ),
                            json!({
                                "field": field,
                                "signature": sig.key,
                                "distinctShown": buckets.len(),
                                "capped": buckets.len() >= 20,
                                "top": buckets.iter().take(10).collect::<Vec<_>>(),
                            }),
                            EvidenceLinks::default(),
                            None,
                            Some(0.6),
                        )
                        .id
                        .clone();
                    entity_ev_ids.push(id);
                    entity_summaries.push(format!("{}{plus} {f}", buckets.len()));
                }
            }
            analysis = Some(a);
            Ok(())
        }
        .await;
        if let Err(err) = res {
            analysis = None;
            logs_failure_reason = Some(connector_failure_reason(&err));
        }
    }

    // e0a2. SENTRY ERROR EVIDENCE.
    let mut sentry_collected = false;
    let mut sentry_failure_reason: Option<String> = None;
    if let Some(sentry) = deps.sentry {
        let from = logs_window();
        let sentry_terms = seed_terms_for(true);
        let seed_file_base = top_ref.map(|t| file_base(&t.file_path).to_lowercase()).unwrap_or_default();
        match sentry
            .collect(&CollectOptions {
                from: Some(from),
                to: Some(now_iso.clone()),
                hint_terms: Some(sentry_terms.clone()),
                collected_at: None,
            })
            .await
        {
            Ok(signatures) => {
                sentry_collected = true;
                for sig in signatures.iter().take(15) {
                    let issue = &sig.issue;
                    let frame = sig.frame.as_ref();
                    let frame_file = frame.and_then(|f| f.filename.clone());
                    let sig_key = [
                        issue.title.clone(),
                        issue.culprit.clone().unwrap_or_default(),
                        frame.and_then(|f| f.function.clone()).unwrap_or_default(),
                        frame_file.clone().unwrap_or_default(),
                    ]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                    let frame_file_base = file_base(frame_file.as_deref().unwrap_or("")).to_lowercase();
                    let frame_matches_seed = !seed_file_base.is_empty()
                        && !frame_file_base.is_empty()
                        && (frame_file_base == seed_file_base
                            || frame_file_base.contains(&seed_file_base)
                            || seed_file_base.contains(&frame_file_base));
                    let services: Vec<String> = frame_file.iter().filter(|f| !f.is_empty()).cloned().collect();
                    let (classified, relevance_reason) =
                        classify_log_relevance(&sig_key, &services, &sentry_terms, input.service.as_deref());
                    let relevance_class = if frame_matches_seed { LogRelevanceClass::Direct } else { classified };
                    let reason = if frame_matches_seed {
                        format!("Sentry frame at seed file {}", frame_file.clone().unwrap_or_default())
                    } else {
                        relevance_reason
                    };
                    let frame_loc = match frame_file.as_deref().filter(|f| !f.is_empty()) {
                        Some(f) => format!(
                            " @ {f}{}",
                            frame.and_then(|fr| fr.lineno).map(|l| format!(":{}", js::number_string(l))).unwrap_or_default()
                        ),
                        None => String::new(),
                    };
                    let culprit = issue.culprit.as_deref().filter(|c| !c.is_empty()).map(|c| format!(" · {c}")).unwrap_or_default();
                    let tag = if relevance_class == LogRelevanceClass::Ambient { " [ambient]" } else { "" };
                    let title = js::slice_chars(
                        &format!(
                            "Sentry {}: {}x{} (last {}){culprit}{frame_loc}{tag}",
                            issue.title,
                            js::number_string(issue.count),
                            if issue.user_count > 0.0 { format!(" · {} user(s)", js::number_string(issue.user_count)) } else { String::new() },
                            short_ts(issue.last_seen.as_deref().unwrap_or(""))
                        ),
                        220,
                    );
                    let links = EvidenceLinks {
                        file: frame_file.clone(),
                        line: frame.and_then(|f| f.lineno).map(|l| l as i64),
                        ..Default::default()
                    };
                    let relevance = if relevance_class == LogRelevanceClass::Direct {
                        if frame_file.as_deref().is_some_and(|f| !f.is_empty()) { 0.95 } else { 0.85 }
                    } else {
                        0.4
                    };
                    let id = ev
                        .mk(
                            EvidenceKind::Log,
                            title,
                            json!({
                                "source": "sentry",
                                "issueId": issue.id,
                                "signature": issue.title,
                                "count": issue.count,
                                "userCount": issue.user_count,
                                "culprit": opt_str(issue.culprit.as_deref()),
                                "level": opt_str(issue.level.as_deref()),
                                "lastSeen": opt_str(issue.last_seen.as_deref()),
                                "firstSeen": opt_str(issue.first_seen.as_deref()),
                                "permalink": opt_str(issue.permalink.as_deref()),
                                "filePath": opt_str(frame_file.as_deref()),
                                "symbolName": opt_str(frame.and_then(|f| f.function.as_deref())),
                                "lineStart": opt_f64(frame.and_then(|f| f.lineno)),
                                "relevanceClass": relevance_class.as_str(),
                                "relevanceReason": reason,
                            }),
                            links,
                            issue.last_seen.clone().filter(|s| !s.is_empty()),
                            Some(relevance),
                        )
                        .id
                        .clone();
                    log_ev_ids.push(id.clone());
                    if relevance_class == LogRelevanceClass::Direct {
                        direct_log_ev_ids.push(id);
                        direct_signatures.push(DirectSignature { key: issue.title.clone(), count: issue.count, message: issue.title.clone() });
                    } else {
                        ambient_log_ev_ids.push(id);
                    }
                }
            }
            Err(err) => {
                sentry_collected = false;
                sentry_failure_reason = Some(connector_failure_reason(&err));
            }
        }
    }

    // e0a2b. LENS USER-REPORT EVIDENCE (HOR-470).
    let mut lens_collected = false;
    let mut lens_failure_reason: Option<String> = None;
    if let Some(lens) = deps.lens {
        let lens_terms = seed_terms_for(true);
        let seed_file_base = top_ref.map(|t| file_base(&t.file_path).to_lowercase()).unwrap_or_default();
        match lens
            .collect(&LensCollectOpts {
                from: Some(logs_window()),
                to: Some(now_iso.clone()),
                hint_terms: lens_terms.clone(),
                collected_at: None,
            })
            .await
        {
            Ok(signals) => {
                lens_collected = true;
                for sig in signals.iter().take(10) {
                    let frame = sig.top_frame.as_ref();
                    let frame_file: Option<String> = frame.map(|f| f.filename.clone()).filter(|f| !f.is_empty());
                    let sig_key = [
                        sig.comment.clone().unwrap_or_default(),
                        sig.top_error_message.clone().unwrap_or_default(),
                        frame.and_then(|f| f.function.clone()).unwrap_or_default(),
                        frame.map(|f| f.filename.clone()).unwrap_or_default(),
                    ]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                    let frame_file_base = file_base(frame.map(|f| f.filename.as_str()).unwrap_or("")).to_lowercase();
                    let frame_matches_seed = !seed_file_base.is_empty()
                        && !frame_file_base.is_empty()
                        && (frame_file_base == seed_file_base
                            || frame_file_base.contains(&seed_file_base)
                            || seed_file_base.contains(&frame_file_base));
                    let services: Vec<String> = frame_file.iter().cloned().collect();
                    let (classified, relevance_reason) =
                        classify_log_relevance(&sig_key, &services, &lens_terms, input.service.as_deref());
                    let relevance_class = if frame_matches_seed { LogRelevanceClass::Direct } else { classified };
                    let reason = if frame_matches_seed {
                        format!("Lens report frame at seed file {}", frame.map(|f| f.filename.clone()).unwrap_or_default())
                    } else {
                        relevance_reason
                    };
                    let comment_text = match sig.comment.as_deref().filter(|c| !c.is_empty()) {
                        Some(c) => js::slice_chars(&redact_secrets(c), 80),
                        None => "(no comment)".into(),
                    };
                    let where_ = sig.route.clone().or_else(|| sig.url.clone()).unwrap_or_default();
                    let where_str = if where_.is_empty() { String::new() } else { format!(" · {where_}") };
                    let frame_loc = match &frame_file {
                        Some(f) => format!(" @ {f}{}", frame.and_then(|fr| fr.lineno).map(|l| format!(":{l}")).unwrap_or_default()),
                        None => String::new(),
                    };
                    let tag = if relevance_class == LogRelevanceClass::Ambient { " [ambient]" } else { "" };
                    let title = js::slice_chars(
                        &format!(
                            "Lens report: \"{comment_text}\" · {} error(s){where_str} ({}){frame_loc}{tag}",
                            js::number_string(sig.error_count),
                            short_ts(&sig.created_at)
                        ),
                        220,
                    );
                    let links = EvidenceLinks { file: frame.map(|f| f.filename.clone()), line: frame.and_then(|f| f.lineno), ..Default::default() };
                    let relevance = if relevance_class == LogRelevanceClass::Direct {
                        if frame_file.is_some() { 0.95 } else { 0.9 }
                    } else {
                        0.45
                    };
                    let id = ev
                        .mk(
                            EvidenceKind::Log,
                            title,
                            json!({
                                "source": "lens",
                                "reportId": sig.id,
                                "comment": sig.comment.as_deref().filter(|c| !c.is_empty()).map(redact_secrets),
                                "route": opt_str(sig.route.as_deref()),
                                "url": opt_str(sig.url.as_deref()),
                                "release": opt_str(sig.release.as_deref()),
                                "gitSha": opt_str(sig.git_sha.as_deref()),
                                "trigger": opt_str(sig.trigger.as_deref()),
                                "errorCount": sig.error_count,
                                "topError": sig.top_error_message.as_deref().filter(|m| !m.is_empty()).map(redact_secrets),
                                "filePath": opt_str(frame.map(|f| f.filename.as_str())),
                                "symbolName": opt_str(frame.and_then(|f| f.function.as_deref())),
                                "lineStart": frame.and_then(|f| f.lineno),
                                "failingRequests": sig.failing_requests,
                                "reactComponents": sig.react_components,
                                "featureFlags": sig.feature_flags,
                                "relevanceClass": relevance_class.as_str(),
                                "relevanceReason": reason,
                            }),
                            links,
                            Some(sig.submitted_at.clone().unwrap_or_else(|| sig.created_at.clone())),
                            Some(relevance),
                        )
                        .id
                        .clone();
                    log_ev_ids.push(id.clone());
                    if relevance_class == LogRelevanceClass::Direct {
                        direct_log_ev_ids.push(id);
                        let sig_label = match sig.comment.as_deref().filter(|c| !c.trim().is_empty()) {
                            Some(c) => js::slice_chars(&redact_secrets(c), 120),
                            None => match sig.top_error_message.as_deref().filter(|m| !m.is_empty()) {
                                Some(m) => redact_secrets(m),
                                None => format!("Lens report {}", sig.id),
                            },
                        };
                        direct_signatures.push(DirectSignature { key: sig_label.clone(), count: sig.error_count.max(1.0), message: sig_label });
                    } else {
                        ambient_log_ev_ids.push(id);
                    }
                }
            }
            Err(err) => {
                lens_collected = false;
                lens_failure_reason = Some(connector_failure_reason(&err));
            }
        }
    }

    // e0a3. AXIOM + CLOUD LOG EVIDENCE (HOR-429).
    let mut axiom_collected = false;
    let mut axiom_failure_reason: Option<String> = None;
    let mut cloud_log_status: Vec<CloudLogStatus> = vec![];
    let mut log_sources: Vec<(String, &dyn StructuredLogSource)> = vec![];
    if let Some(ax) = deps.axiom {
        log_sources.push(("axiom".into(), ax as &dyn StructuredLogSource));
    }
    for src in &deps.cloud_logs {
        log_sources.push((src.id().to_string(), *src));
    }
    for (source_id, log_source) in log_sources {
        let is_axiom = source_id == "axiom";
        let mut status = CloudLogStatus { id: source_id.clone(), collected: false, failure_reason: None };
        let axiom_terms = seed_terms_for(true);
        match log_source
            .collect(&CollectOptions {
                from: Some(logs_window()),
                to: Some(now_iso.clone()),
                hint_terms: Some(axiom_terms.clone()),
                collected_at: None,
            })
            .await
        {
            Ok(records) => {
                status.collected = true;
                if is_axiom {
                    axiom_collected = true;
                }
                for rec in records.iter().take(15) {
                    let msg = pick_axiom_field(&rec.fields, AXIOM_MESSAGE_FIELDS);
                    let level = pick_axiom_field(&rec.fields, AXIOM_LEVEL_FIELDS);
                    let svc = pick_axiom_field(&rec.fields, AXIOM_SERVICE_FIELDS).unwrap_or_default();
                    let sig_key = [msg.clone().unwrap_or_default(), svc.clone()].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
                    let services: Vec<String> = if svc.is_empty() { vec![] } else { vec![svc.clone()] };
                    let (relevance_class, relevance_reason) =
                        classify_log_relevance(&sig_key, &services, &axiom_terms, input.service.as_deref());
                    let lvl = level.as_deref().map(|l| format!("[{l}] ")).unwrap_or_default();
                    let body = msg.clone().unwrap_or_else(|| "(log event)".into());
                    let tag = if relevance_class == LogRelevanceClass::Ambient { " [ambient]" } else { "" };
                    let title = js::slice_chars(&format!("{} log: {lvl}{body}{tag}", if is_axiom { "Axiom" } else { source_id.as_str() }), 220);
                    let is_error = matches!(level.as_deref().unwrap_or("").to_lowercase().as_str(), "error" | "fatal" | "critical");
                    let relevance = if relevance_class == LogRelevanceClass::Direct { if is_error { 0.9 } else { 0.75 } } else { 0.4 };
                    let id = ev
                        .mk(
                            EvidenceKind::Log,
                            title,
                            json!({
                                "source": source_id,
                                "signature": opt_str(msg.as_deref()),
                                "level": opt_str(level.as_deref()),
                                "service": if svc.is_empty() { Value::Null } else { Value::String(svc.clone()) },
                                "relevanceClass": relevance_class.as_str(),
                                "relevanceReason": relevance_reason,
                                "fields": rec.fields,
                            }),
                            EvidenceLinks::default(),
                            rec.timestamp.clone(),
                            Some(relevance),
                        )
                        .id
                        .clone();
                    log_ev_ids.push(id.clone());
                    if relevance_class == LogRelevanceClass::Direct {
                        direct_log_ev_ids.push(id);
                        direct_signatures.push(DirectSignature {
                            key: msg.clone().unwrap_or_else(|| "(log event)".into()),
                            count: 1.0,
                            message: msg.clone().unwrap_or_default(),
                        });
                    } else {
                        ambient_log_ev_ids.push(id);
                    }
                }
            }
            Err(err) => {
                status.failure_reason = Some(connector_failure_reason(&err));
                if is_axiom {
                    axiom_collected = false;
                    axiom_failure_reason = status.failure_reason.clone();
                }
            }
        }
        if !is_axiom {
            cloud_log_status.push(status);
        }
    }

    // e0a4. DURATION-BY-DIMENSION (HOR-435 lever #2).
    if looks_duration_themed(&hint) {
        let from = logs_window();
        let base = input.duration_dimension.clone().unwrap_or_else(|| DurationDimensionOptions {
            dimension: DimensionSpec {
                name: "region".into(),
                pattern: Some(r":\s*([A-Za-z][\w-]+)".into()),
                ..Default::default()
            },
            completion_text: Some("Completed".into()),
            ..Default::default()
        });
        let mut opts = base.clone();
        opts.from = base.from.clone().or(Some(from));
        if input.service.is_some() && base.service.is_none() {
            opts.service = input.service.clone();
        }
        opts.level = base.level.clone().or(Some("info".into()));
        let mut results: Vec<(&str, Option<DurationByDimension>)> = vec![];
        if let Some(logs) = deps.logs {
            results.push(("elasticsearch", logs.analyze_durations(&opts).await));
        }
        if let Some(ax) = deps.axiom {
            results.push(("axiom", ax.analyze_durations(&opts).await));
        }
        for (source, result) in results {
            let Some(result) = result else { continue };
            if result.by_value.is_empty() {
                continue;
            }
            let mut values: Vec<(&String, f64)> = result.by_value.iter().map(|(k, v)| (k, v.avg)).collect();
            values.sort_by(|a, b| js::cmp_f64(b.1, a.1));
            let summary = values.iter().map(|(k, avg)| format!("{k} {}", format_duration_ms(*avg))).collect::<Vec<_>>().join(", ");
            let id = ev
                .mk(
                    EvidenceKind::Log,
                    js::slice_chars(&format!("Duration by {}: {summary}", result.dimension), 220),
                    json!({
                        "source": source,
                        "kind": "duration-by-dimension",
                        "dimension": result.dimension,
                        "unit": result.unit,
                        "byValue": result.by_value,
                        "sampleCount": result.sample_count,
                    }),
                    EvidenceLinks::default(),
                    None,
                    Some(0.6),
                )
                .id
                .clone();
            per_dimension_duration_ev_ids.push(id);
        }
    }

    // e0b. STATE (HOR-33).
    let mut state_analysis: Option<StateAnalysis> = None;
    let mut state_ev_ids: Vec<String> = vec![];
    let mut state_collections: IndexSet<String> = IndexSet::new();
    let mut data_anomaly_ev_ids: Vec<String> = vec![];
    let mut data_anomaly_collections: Vec<String> = vec![];
    let mut state_providers: Vec<(String, &dyn StateProvider)> = vec![];
    if let Some(m) = deps.mongo {
        state_providers.push(("mongodb".into(), m));
    }
    if let Some(p) = deps.postgres {
        state_providers.push(("postgres".into(), p));
    }
    for p in &deps.additional_state {
        state_providers.push((p.id().to_string(), *p));
    }
    let mut state_collected: Option<bool> =
        if !state_providers.is_empty() || deps.redis_state.is_some() { Some(true) } else { None };
    let mut state_failures: Vec<String> = vec![];
    for (name, provider) in &state_providers {
        match provider.analyze_state(AnalyzeStateOpts::default()).await {
            Ok(sa) => {
                let state_terms = term_set(&[&hint]);
                for s in select_state_signals(&sa, &state_terms) {
                    let mut payload = s.payload.clone();
                    if let Value::Object(map) = &mut payload {
                        map.insert("provider".into(), Value::String(name.clone()));
                        map.insert("database".into(), Value::String(sa.database.clone()));
                    } else {
                        payload = json!({ "provider": name, "database": sa.database });
                    }
                    let id = ev.mk(EvidenceKind::State, s.title.clone(), payload, EvidenceLinks::default(), s.timestamp.clone(), Some(s.relevance)).id.clone();
                    state_ev_ids.push(id.clone());
                    state_collections.insert(s.collection.clone());
                    if s.kind == StateSignalKind::Anomaly {
                        data_anomaly_ev_ids.push(id);
                        data_anomaly_collections.push(s.collection.clone());
                    }
                }
                state_analysis = Some(sa);
            }
            Err(err) => {
                state_collected = Some(false);
                state_failures.push(format!("{name}: {}", connector_failure_reason(&err)));
            }
        }
    }

    // e0b2. REDIS RUNTIME STATE (HOR-201).
    let mut redis_state_analysis: Option<RedisStateAnalysis> = None;
    let mut redis_state_ev_ids: Vec<String> = vec![];
    if let Some(redis) = deps.redis_state {
        match redis.analyze_redis_state().await {
            Ok(ra) => {
                let redis_terms = term_set(&[&hint]);
                for s in &ra.signals {
                    let matched = redis_terms.iter().any(|t| t.chars().count() > 2 && s.match_text.contains(t.as_str()));
                    let relevance = if matched { (s.relevance + 0.3).min(1.0) } else { s.relevance };
                    let id = ev
                        .mk(EvidenceKind::RedisKey, s.title.clone(), s.payload.clone(), EvidenceLinks::default(), Some(ra.collected_at.clone()), Some(relevance))
                        .id
                        .clone();
                    redis_state_ev_ids.push(id);
                }
                redis_state_analysis = Some(ra);
            }
            Err(err) => {
                state_collected = Some(false);
                state_failures.push(format!("redis: {}", connector_failure_reason(&err)));
            }
        }
    }
    let state_failure_reason =
        if state_failures.is_empty() { None } else { Some(js::slice_chars(&state_failures.join("; "), 160)) };

    // e0c. QUEUE RUNTIME STATE (HOR-12).
    let mut queue_runtime_state: Option<QueueRuntimeState> = None;
    let mut queue_runtime_ev_ids: Vec<String> = vec![];
    let mut queue_runtime_ev_ids_by_queue: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut queue_backlog_ev_ids_by_queue: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut queue_starvation_ev_ids_by_queue: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut queue_failure_signals: Vec<QueueFailureSignal> = vec![];
    let mut queue_collected = false;
    let mut queue_failure_reason: Option<String> = None;

    if let Some(queue) = deps.queue {
        let res: anyhow::Result<()> = async {
            let static_names: IndexSet<String> = queue_hits.iter().map(|e| e.queue_name.clone()).collect();
            let discovered = queue.discover_queues().await.unwrap_or_default();
            let queue_names: Vec<String> = static_names.into_iter().chain(discovered).collect::<IndexSet<_>>().into_iter().collect();
            if !queue_names.is_empty() {
                queue_runtime_state = Some(queue.analyze_queues(Some(queue_names.as_slice())).await?);
            }
            let empty_state = QueueRuntimeState { prefix: String::new(), collected_at: String::new(), queues: vec![] };
            for s in analyze_queue_runtime(queue_runtime_state.as_ref().unwrap_or(&empty_state)) {
                let id = ev
                    .mk(
                        EvidenceKind::QueueState,
                        s.title.clone(),
                        s.payload.clone(),
                        EvidenceLinks { queue_name: Some(s.queue_name.clone()), ..Default::default() },
                        s.timestamp.clone(),
                        Some(s.relevance),
                    )
                    .id
                    .clone();
                queue_runtime_ev_ids.push(id.clone());
                queue_runtime_ev_ids_by_queue.entry(s.queue_name.clone()).or_default().push(id.clone());
                match s.kind {
                    QueueSignalKind::Backlog => queue_backlog_ev_ids_by_queue.entry(s.queue_name.clone()).or_default().push(id.clone()),
                    QueueSignalKind::WorkerStarvation => {
                        queue_starvation_ev_ids_by_queue.entry(s.queue_name.clone()).or_default().push(id.clone())
                    }
                    _ => {}
                }
                if s.kind == QueueSignalKind::FailedBreakdown {
                    if let Some(reason) = s.payload.get("topReason").and_then(Value::as_str) {
                        queue_failure_signals.push(QueueFailureSignal {
                            reason: reason.to_string(),
                            queue_name: s.queue_name.clone(),
                            ev_id: id,
                            count: s.payload.get("topCount").and_then(Value::as_f64).unwrap_or(0.0),
                            stale: s.payload.get("topStale") == Some(&Value::Bool(true)),
                        });
                    }
                }
            }
            queue_collected = true;
            Ok(())
        }
        .await;
        if let Err(err) = res {
            queue_runtime_state = None;
            queue_failure_reason = Some(connector_failure_reason(&err));
        }
    }
    for provider in &deps.additional_queues {
        match provider.collect().await {
            Ok(snapshots) => {
                for snap in snapshots {
                    ev.mk(EvidenceKind::QueueState, snap.title, snap.payload, snap.links, snap.timestamp, Some(snap.relevance));
                }
                queue_collected = true;
            }
            Err(err) => {
                let next = format!("{}: {}", provider.id(), connector_failure_reason(&err));
                queue_failure_reason = Some(match queue_failure_reason.filter(|r| !r.is_empty()) {
                    Some(prev) => format!("{prev}; {next}"),
                    None => next,
                });
            }
        }
    }

    // e0d. METRIC EVIDENCE (HOR-11/40) — 30 s budget.
    const METRICS_TIMEOUT: Duration = Duration::from_secs(30);
    let mut metric_ev_ids: Vec<String> = vec![];
    let mut latency_metric_ev_ids: Vec<String> = vec![];
    let mut bimodal_metric_ev_ids: Vec<String> = vec![];
    let mut queue_metric_ev_ids: Vec<String> = vec![];
    let mut queue_metric_ev_ids_by_queue: IndexMap<String, Vec<String>> = IndexMap::new();
    let mut nominal_metric_ev_ids: Vec<String> = vec![];
    let mut metrics_collected = false;
    let mut metrics_failure_reason: Option<String> = None;
    let mut metric_series_checked = 0usize;

    if let Some(metrics) = deps.metrics {
        let from_ms = js::date_parse(&logs_window());
        let to_ms = now.timestamp_millis() as f64;
        let opts = AnalyzeOptions {
            hint: Some(input.hint.clone()),
            from: (from_ms / 1000.0).floor(),
            to: (to_ms / 1000.0).floor(),
            step: None,
            deadline: Some(tokio::time::Instant::now() + METRICS_TIMEOUT),
        };
        let analyzed = match tokio::time::timeout(METRICS_TIMEOUT, metrics.analyze(&opts)).await {
            Ok(r) => r,
            Err(_) => Err(anyhow::anyhow!("metrics timeout")),
        };
        match analyzed {
            Ok(m_findings) => {
                let m_evidence = metrics.to_evidence(&m_findings);
                let anomalous: Vec<_> = m_findings.iter().filter(|f| f.anomaly != Anomaly::None).collect();
                let mut queue_norm_to_canonical: IndexMap<String, String> = IndexMap::new();
                for edge in &queue_hits {
                    queue_norm_to_canonical.entry(norm_name(&edge.queue_name)).or_insert_with(|| edge.queue_name.clone());
                }
                let service_filter = input.service.clone().unwrap_or_default().to_lowercase();
                let metric_collected_at = now_iso.clone();
                let mut seen_queue_metric: HashSet<String> = HashSet::new();
                let hint_is_perf = HINT_IS_PERF.is_match(&hint);
                for (i, mut e) in m_evidence.into_iter().enumerate() {
                    e.id = uuid::Uuid::new_v4().to_string();
                    e.provenance = Provenance { query: hint.clone(), collected_at: metric_collected_at.clone() };
                    let id = e.id.clone();
                    ev.items.push(e);
                    metric_ev_ids.push(id.clone());
                    let Some(f) = anomalous.get(i) else { continue };
                    let panel_lower = f.panel_title.to_lowercase();
                    let label_vals: Vec<String> = f.labels.values().map(|v| v.to_lowercase()).collect();
                    match f.anomaly {
                        Anomaly::LatencySpike | Anomaly::ErrorRateChange => {
                            let matches_service = !service_filter.is_empty()
                                && (panel_lower.contains(&service_filter) || label_vals.iter().any(|v| v.contains(&service_filter)));
                            let matches_hint = service_filter.is_empty()
                                && hint_is_perf
                                && hint_tokens.iter().any(|t| {
                                    t.chars().count() >= 4 && (panel_lower.contains(t.as_str()) || label_vals.iter().any(|v| v.contains(t.as_str())))
                                });
                            let generic_perf = service_filter.is_empty() && hint_is_perf && f.anomaly == Anomaly::LatencySpike;
                            if matches_service || matches_hint || generic_perf {
                                latency_metric_ev_ids.push(id);
                            }
                        }
                        Anomaly::BimodalPopulation => bimodal_metric_ev_ids.push(id),
                        Anomaly::QueueGrowth => {
                            let panel_norm = norm_name(&f.panel_title);
                            let label_norms: Vec<String> = f.labels.values().map(|v| norm_name(v)).collect();
                            for (norm, canonical) in &queue_norm_to_canonical {
                                let Ok(re) = Regex::new(&format!("(?:^| ){}(?:$| )", regex::escape(norm))) else { continue };
                                if re.is_match(&panel_norm) || label_norms.iter().any(|lv| re.is_match(lv)) {
                                    if seen_queue_metric.insert(id.clone()) {
                                        queue_metric_ev_ids.push(id.clone());
                                    }
                                    let list = queue_metric_ev_ids_by_queue.entry(canonical.clone()).or_default();
                                    if !list.contains(&id) {
                                        list.push(id.clone());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                metric_series_checked = m_findings.len();
                if metric_ev_ids.is_empty() && !m_findings.is_empty() {
                    let panels: Vec<String> = m_findings.iter().map(|f| f.panel_title.clone()).collect::<IndexSet<_>>().into_iter().collect();
                    let id = ev
                        .mk(
                            EvidenceKind::Metric,
                            format!(
                                "Metrics checked — {} series across {} panel(s), no anomalies in window",
                                m_findings.len(),
                                panels.len()
                            ),
                            json!({
                                "seriesChecked": m_findings.len(),
                                "panelCount": panels.len(),
                                "panels": panels.iter().take(10).collect::<Vec<_>>(),
                                "anomalies": 0,
                                "stance": "neutral",
                            }),
                            EvidenceLinks::default(),
                            Some(metric_collected_at.clone()),
                            Some(0.2),
                        )
                        .id
                        .clone();
                    nominal_metric_ev_ids.push(id);
                }
                metrics_collected = true;
            }
            Err(err) => metrics_failure_reason = Some(connector_failure_reason(&err)),
        }
    }

    // e0e. OWNERSHIP (HOR-20/40).
    let mut ownership_estimate: Option<OwnershipEstimate> = None;
    if let (Some(rp), Some(t), Some(c)) = (deps.repo_path.as_deref().filter(|r| !r.is_empty()), top_ref, code) {
        ownership_estimate = estimate_ownership(
            &t.name,
            OwnershipDeps { code: c, repo_path: rp.to_string(), symbol: Some(Some(t.clone())) },
        )
        .await
        .ok();
    }

    // e0e2. SHOPIFY EVIDENCE.
    let mut shopify_collected = false;
    let mut shopify_failure_reason: Option<String> = None;
    if let Some(shopify) = deps.shopify {
        let shopify_terms = seed_terms_for(true);
        match shopify
            .collect(&ShopifyCollectOpts {
                from: Some(logs_window()),
                to: Some(now_iso.clone()),
                hint_terms: shopify_terms.clone(),
                queries: input.shopify_queries.clone(),
                collected_at: None,
            })
            .await
        {
            Ok(records) => {
                shopify_collected = true;
                for mut e in shopify.to_evidence(&records, &shopify_terms, &now_iso) {
                    e.id = uuid::Uuid::new_v4().to_string();
                    ev.items.push(e);
                }
            }
            Err(err) => {
                shopify_collected = false;
                shopify_failure_reason = Some(connector_failure_reason(&err));
            }
        }
    }

    // e0f. NORMALIZE.
    normalize_evidence(&mut ev.items, Some(&NormalizeContext { service: input.service.clone(), environment: input.environment.clone() }));

    // e0g. GRAPH + e. TIMELINE.
    let graph = build_graph(&ev.items);
    let timeline = build_timeline(&ev.items);

    // HOR-406 / HOR-451: one shared relevance + focus verdict.
    let top_file = top_ref.map(|t| t.file_path.as_str());
    let recent_change_relevant = seed_touched_by_relevant_change(recent_changes.as_ref(), top_file);
    let seed_change_focus = if recent_change_relevant { seed_touching_commit_focus(recent_changes.as_ref(), top_file) } else { None };
    let seed_change_broad = seed_change_focus.is_some_and(|f| f > BROAD_CHANGE_FILE_THRESHOLD);

    let vague_perf_unconfirmed = looks_performance(&hint)
        && deps.metrics.is_none()
        && latency_metric_ev_ids.is_empty()
        && seed_is_low_confidence
        && !source_impact_hint;

    // e2. CORRELATION.
    let has_queue_topology = !queue_ev_by_name.is_empty();
    let correlation = correlate(
        &ev.items,
        Some(&CorrelateOptions { recent_change_relevant: Some(recent_change_relevant), has_queue_topology: Some(has_queue_topology) }),
    );

    // e3. HYPOTHESES (HOR-24).
    let queue_names: Vec<String> = queue_ev_by_name.keys().cloned().collect();
    let hyps = generate_hypotheses(
        &ev.items,
        &correlation,
        &HypothesisContext {
            seed_label: label.clone(),
            queues: queue_names,
            latency_metric_ev_ids: Some(latency_metric_ev_ids.clone()),
            queue_backlog_ev_ids_by_queue: Some(queue_backlog_ev_ids_by_queue.clone()),
            queue_starvation_ev_ids_by_queue: Some(queue_starvation_ev_ids_by_queue.clone()),
            queue_metric_ev_ids_by_queue: Some(queue_metric_ev_ids_by_queue.clone()),
            since_provided: Some(input.since.is_some()),
            suppress_runtime_hypotheses: Some(source_impact_hint),
            recent_change_relevant: Some(recent_change_relevant),
            seed_change_focus: Some(seed_change_focus.map(|f| f as i64)),
            seed_change_broad: Some(seed_change_broad),
            vague_perf_guess: Some(vague_perf_unconfirmed),
            graph: Some(&graph),
            per_dimension_duration_ev_ids: Some(per_dimension_duration_ev_ids.clone()),
            bimodal_metric_ev_ids: Some(bimodal_metric_ev_ids.clone()),
            per_segment_queue_structure_ev_ids: Some(per_segment_queue_structure_ev_ids.clone()),
            benign_variance_applicable: Some(
                looks_duration_themed(&hint)
                    || !per_dimension_duration_ev_ids.is_empty()
                    || !bimodal_metric_ev_ids.is_empty()
                    || !latency_metric_ev_ids.is_empty(),
            ),
            alert_suggested_categories: Some(alert_suggested_categories),
        },
    );

    // e4. VALIDATION + e4a. CAUSE CHAINS.
    let validated = validate_hypotheses(&hyps, &ev.items);
    let cause_chains = build_cause_chains(&validated, &ev.items, &graph, &label);

    // f. FINDINGS
    let mut findings: Vec<ReportFinding> = vec![];
    let finding = |kind: FindingKind, title: String, detail: Option<String>, confidence: f64, evidence_ids: Vec<String>| ReportFinding {
        kind,
        title,
        detail,
        confidence,
        evidence_ids,
    };

    if let (Some(t), Some(seed_id)) = (top_ref, &seed_ev_id) {
        let seed_confidence = if seed_is_low_confidence {
            t.score.unwrap_or(0.3).min(0.4)
        } else {
            t.score.unwrap_or(0.75).max(0.5).min(0.95)
        };
        findings.push(finding(
            FindingKind::Observation,
            format!("Seed resolves to {label} at {seed_loc}"),
            t.signature.clone(),
            js::round_to(seed_confidence, 2),
            vec![seed_id.clone()],
        ));
    }
    if let (Some(r), Some(seed_id)) = (&log_reseed, &seed_ev_id) {
        findings.push(finding(
            FindingKind::Observation,
            r.note.clone(),
            Some("Seed was resolved by matching the hint against recent logs, not source search.".into()),
            0.6,
            vec![seed_id.clone()],
        ));
    }
    if ranked.len() > 1 {
        if let Some(seed_id) = &seed_ev_id {
            let candidates = ranked.iter().take(4).map(|r| format!("{} [{}]", r.symbol.name, r.role)).collect::<Vec<_>>().join(", ");
            findings.push(finding(
                FindingKind::Observation,
                format!("Candidate areas (ranked): {candidates}"),
                Some(format!(
                    "Investigating {label} [{}]; re-run with a more specific hint to target another.",
                    ranked.first().map(|r| r.role.as_str()).unwrap_or("undefined")
                )),
                0.5,
                vec![seed_id.clone()],
            ));
        }
    }
    if !flows.is_empty() {
        let names = flows.iter().map(|f| f.name.clone()).collect::<Vec<_>>().join(", ");
        findings.push(finding(
            FindingKind::Observation,
            format!("Participates in {} execution flow(s)", flows.len()),
            non_empty(&names),
            clamp01(0.5 + flows.len() as f64 * 0.1),
            flow_ev_ids.clone(),
        ));
    }
    if let (Some(t), Some(imp_id), Some(imp)) = (top_ref, &impact_ev_id, &impact) {
        if imp.affected > 0 {
            findings.push(finding(
                FindingKind::Observation,
                format!("Changing {} impacts {} symbol(s) (blast radius)", t.name, imp.affected),
                None,
                clamp01(0.4 + (imp.affected.min(20) as f64) / 40.0),
                vec![imp_id.clone()],
            ));
        }
    }
    for (queue_name, ev_ids) in &queue_ev_by_name {
        let edge = queue_hits.iter().find(|e| &e.queue_name == queue_name);
        let producer = edge.and_then(|e| e.producer_symbol.clone()).unwrap_or_else(|| "unknown-producer".into());
        let worker = edge.and_then(|e| e.worker_symbol.clone()).unwrap_or_else(|| "unknown-worker".into());
        findings.push(finding(
            FindingKind::Correlation,
            format!("Crosses a queue boundary: {queue_name} ({producer} -> {worker})"),
            None,
            0.7,
            ev_ids.clone(),
        ));
    }
    match (&changes, &change_ev_id, &recent_changes) {
        (Some(ch), Some(cid), _) => {
            let m = ch.added.len() + ch.removed.len() + ch.modified.len();
            findings.push(finding(
                FindingKind::Observation,
                format!("{m} symbol(s) changed in range {}..HEAD", input.since.as_deref().unwrap_or("")),
                None,
                clamp01(0.4 + (m.min(20) as f64) / 40.0),
                vec![cid.clone()],
            ));
        }
        (None, Some(cid), Some(rc)) => {
            findings.push(finding(
                FindingKind::Observation,
                format!("{} commit(s) in {change_range_label} touching {} file(s)", rc.commits.len(), rc.changed_files.len()),
                None,
                clamp01(0.3 + (rc.commits.len().min(10) as f64) / 20.0),
                vec![cid.clone()],
            ));
        }
        _ => {}
    }
    if let Some(cid) = &config_change_ev_id {
        if !config_changes.is_empty() {
            let migration_n = config_changes.iter().filter(|c| c.category == ConfigChangeCategory::Migration).count();
            let config_n = config_changes.len() - migration_n;
            let label = if migration_n > 0 && config_n > 0 {
                format!("{migration_n} migration/schema + {config_n} config/data file(s)")
            } else if migration_n > 0 {
                format!("{migration_n} migration/schema file(s)")
            } else {
                format!("{config_n} config/data file(s)")
            };
            findings.push(finding(
                FindingKind::Observation,
                format!("Config/migration change in {change_range_label}: {label} — possible non-code change source"),
                None,
                clamp01(0.35 + (config_changes.len().min(10) as f64) / 20.0),
                vec![cid.clone()],
            ));
        }
    }
    if let Some(a) = analysis.as_ref().filter(|a| !a.signatures.is_empty()) {
        let new_n = a.new_signatures.len();
        let affected = if a.affected_services.is_empty() {
            input.service.clone().unwrap_or_else(|| "the service".into())
        } else {
            a.affected_services.join(", ")
        };
        let has_direct = !direct_log_ev_ids.is_empty();
        let ambient_count = ambient_log_ev_ids.len();
        let ambient_suffix = if !has_direct && ambient_count > 0 {
            format!(" ({ambient_count} ambient — no direct link to seed established)")
        } else if ambient_count > 0 {
            format!(" ({} direct, {ambient_count} ambient)", direct_log_ev_ids.len())
        } else {
            String::new()
        };
        findings.push(finding(
            FindingKind::Observation,
            format!(
                "{} error signature(s) ({new_n} new, {} error(s)) — affected: {affected}{ambient_suffix}",
                a.signatures.len(),
                js::number_string(a.total_errors)
            ),
            None,
            if has_direct { 0.65 } else { 0.40 },
            log_ev_ids.clone(),
        ));
        let top_sig = &a.signatures[0];
        let flag = if top_sig.is_new == Some(true) {
            " (NEW)".to_string()
        } else if let Some(r) = top_sig.ratio.filter(|r| r.is_finite() && *r >= 1.5) {
            format!(" (spike x{})", js::to_fixed(r, 1))
        } else {
            String::new()
        };
        if let Some(top_direct) = direct_log_ev_ids.first() {
            findings.push(finding(
                FindingKind::Anomaly,
                format!(
                    "Top error signature: {} — {}x{flag}, last {}",
                    top_sig.key,
                    js::number_string(top_sig.count),
                    short_ts(&top_sig.last_seen)
                ),
                None,
                0.7,
                vec![top_direct.clone()],
            ));
        } else if ambient_count > 0 {
            findings.push(finding(
                FindingKind::Observation,
                format!(
                    "Top error signature (ambient): {} — {}x{flag} — no structural link to seed",
                    top_sig.key,
                    js::number_string(top_sig.count)
                ),
                None,
                0.35,
                ambient_log_ev_ids.iter().take(1).cloned().collect(),
            ));
        }
    }
    if !entity_ev_ids.is_empty() {
        findings.push(finding(
            FindingKind::Observation,
            format!("Distinct failing entities: {}", entity_summaries.join(" × ")),
            None,
            0.6,
            entity_ev_ids.clone(),
        ));
    }
    if let Some(sa) = state_analysis.as_ref().filter(|_| !state_ev_ids.is_empty()) {
        findings.push(finding(
            FindingKind::Anomaly,
            format!(
                "Application state: {} relevant signal(s) across {} collection(s) in {}",
                state_ev_ids.len(),
                state_collections.len(),
                sa.database
            ),
            None,
            0.6,
            state_ev_ids.clone(),
        ));
    }
    if let Some(ra) = redis_state_analysis.as_ref().filter(|_| !redis_state_ev_ids.is_empty()) {
        let db_count = ra.databases.iter().filter(|d| d.key_count > 0).count();
        findings.push(finding(
            FindingKind::Observation,
            format!("Redis runtime state: {} signal(s) across {db_count} DB(s)", redis_state_ev_ids.len()),
            None,
            0.5,
            redis_state_ev_ids.clone(),
        ));
    }
    if let Some(qs) = queue_runtime_state.as_ref().filter(|_| !queue_runtime_ev_ids.is_empty()) {
        let starved: Vec<_> = qs.queues.iter().filter(|q| q.waiting >= 10 && q.active == 0).collect();
        let starved_names: HashSet<&str> = starved.iter().map(|q| q.queue_name.as_str()).collect();
        let backlogged: Vec<_> = qs.queues.iter().filter(|q| q.waiting > 100 && !starved_names.contains(q.queue_name.as_str())).collect();
        let failing: Vec<_> = qs.queues.iter().filter(|q| q.failed > 20).collect();
        if !backlogged.is_empty() || !starved.is_empty() || !failing.is_empty() {
            let mut parts: Vec<String> = vec![];
            if !starved.is_empty() {
                parts.push(format!(
                    "possible starvation: {} (0 active workers in snapshot)",
                    starved.iter().map(|q| q.queue_name.as_str()).collect::<Vec<_>>().join(", ")
                ));
            }
            if !backlogged.is_empty() {
                parts.push(format!(
                    "backlog: {}",
                    backlogged.iter().map(|q| format!("{} ({})", q.queue_name, q.waiting)).collect::<Vec<_>>().join(", ")
                ));
            }
            if !failing.is_empty() {
                parts.push(format!(
                    "failures: {}",
                    failing.iter().map(|q| format!("{} ({})", q.queue_name, q.failed)).collect::<Vec<_>>().join(", ")
                ));
            }
            findings.push(finding(
                FindingKind::Anomaly,
                format!("Queue runtime anomalies — {}", parts.join("; ")),
                None,
                queue_finding_confidence(starved.len(), backlogged.len(), failing.len()),
                queue_runtime_ev_ids.clone(),
            ));
        } else {
            let summary = qs.queues.iter().map(|q| format!("{}: {} waiting", q.queue_name, q.waiting)).collect::<Vec<_>>().join(", ");
            findings.push(finding(
                FindingKind::Observation,
                format!("Queue runtime healthy — {summary}"),
                None,
                0.5,
                queue_runtime_ev_ids.clone(),
            ));
        }
    }
    if !metric_ev_ids.is_empty() {
        let mut labels: Vec<&str> = vec![];
        if !latency_metric_ev_ids.is_empty() {
            labels.push("latency/error-rate");
        }
        if !queue_metric_ev_ids.is_empty() {
            labels.push("queue-growth");
        }
        let desc = if labels.is_empty() { "metric".to_string() } else { labels.join(", ") };
        findings.push(finding(
            FindingKind::Anomaly,
            format!("Metric anomalies: {} signal(s) — {desc}", metric_ev_ids.len()),
            None,
            0.7,
            metric_ev_ids.clone(),
        ));
    } else if !nominal_metric_ev_ids.is_empty() {
        findings.push(finding(
            FindingKind::Observation,
            format!("Metrics nominal — {metric_series_checked} series checked, no anomalies in window"),
            None,
            0.5,
            nominal_metric_ev_ids.clone(),
        ));
    }

    // f. SUSPECTED CAUSES (HOR-15).
    let mut cause_inputs: Vec<CauseInput> = vec![];
    let blast_radius = impact.as_ref().map(|i| i.affected).unwrap_or(0);
    let cause = |id: &str, title: String, category: &str, ids: Vec<String>, base: f64, metadata: Option<Map<String, Value>>| CauseInput {
        id: id.to_string(),
        title,
        category: category.to_string(),
        source_evidence_ids: ids,
        affected_node_ids: None,
        base_score: base,
        metadata,
    };

    if let Some(qs) = &queue_runtime_state {
        for q in &qs.queues {
            let is_starved = q.waiting >= 10 && q.active == 0;
            let is_backlogged = q.waiting > 100;
            if is_starved || is_backlogged {
                let edge = queue_hits.iter().find(|e| e.queue_name == q.queue_name);
                let producer = edge.and_then(|e| e.producer_symbol.clone()).unwrap_or_else(|| "producer".into());
                let worker = edge.and_then(|e| e.worker_symbol.clone()).unwrap_or_else(|| "worker".into());
                let detail = if is_starved { format!("{} waiting, no active workers", q.waiting) } else { format!("{} waiting jobs", q.waiting) };
                cause_inputs.push(cause(
                    &format!("cause:queue-backlog:{}", q.queue_name),
                    format!("Queue \"{}\" is backed up ({detail}) — {producer} → {worker} path implicated", q.queue_name),
                    "queue-backlog",
                    queue_runtime_ev_ids_by_queue.get(&q.queue_name).cloned().unwrap_or_default(),
                    clamp01(if is_starved { 0.45 } else { 0.45 + (q.waiting as f64 / 5_000.0).min(0.20) }),
                    meta(&[("waitingCount", json!(q.waiting)), ("isStarved", json!(is_starved)), ("blastRadius", json!(blast_radius))]),
                ));
            }
        }
    }

    for (queue_name, ev_ids) in &queue_ev_by_name {
        let edge = queue_hits.iter().find(|e| &e.queue_name == queue_name);
        let producer = edge.and_then(|e| e.producer_symbol.clone()).unwrap_or_else(|| "unknown-producer".into());
        let worker = edge.and_then(|e| e.worker_symbol.clone()).unwrap_or_else(|| "unknown-worker".into());
        cause_inputs.push(cause(
            &format!("cause:queue-path:{queue_name}"),
            format!("The {queue_name} processing path ({producer} -> {worker}) is implicated"),
            "queue-path",
            ev_ids.iter().cloned().chain(impact_ev_id.clone()).collect(),
            0.35,
            meta(&[("blastRadius", json!(blast_radius))]),
        ));
    }

    if let Some(cid) = change_ev_id.clone().filter(|_| !source_impact_hint) {
        let seed_in_changes = recent_change_relevant;
        let citation = format_regression_citation(recent_changes.as_ref(), changes.as_ref(), top_file);
        let seed_focus = seed_change_focus;
        let is_broad_change = seed_change_broad;
        let maintenance_only = seed_in_changes && citation.maintenance_only;
        let mut range_confirmed = false;
        if let (true, Some(t), Some(rp)) = (seed_in_changes, top_ref, deps.repo_path.as_deref()) {
            if let Some(start) = t.start_line {
                if !t.file_path.is_empty() {
                    let touching = commits_touching_range(
                        rp,
                        &t.file_path,
                        start,
                        t.end_line.unwrap_or(start),
                        recent_changes.as_ref().map(|r| r.window.since.as_str()),
                    )
                    .await;
                    if let Some(touching) = touching.filter(|t| !t.is_empty()) {
                        let in_range: HashSet<String> = touching.into_iter().collect();
                        range_confirmed = recent_changes
                            .as_ref()
                            .is_some_and(|rc| rc.commits.iter().any(|c| !is_noise_commit(c) && !is_chore_like_commit(c) && in_range.contains(&c.sha)));
                    }
                }
            }
        }
        let seed_ref = top_ref
            .map(|t| if range_confirmed { format!("to {}", t.name) } else { format!("touching {}", t.file_path) })
            .unwrap_or_default();
        let regression_title = match top_ref {
            Some(t) if seed_in_changes && maintenance_only => format!(
                "The change window in {change_range_label} contains only maintenance commits (chore/formatting/lint) touching {} — no behavioural change is evident; treat as unconfirmed without corroborating runtime evidence",
                t.file_path
            ),
            Some(_) if seed_in_changes && !is_broad_change => format!(
                "Recent change{} {seed_ref}{} in {change_range_label} may have introduced the regression",
                citation.commit_clause, citation.symbol_clause
            ),
            Some(t) if seed_in_changes && is_broad_change => format!(
                "No specific cause identified from the available evidence — a broad recent change ({} files) in {change_range_label} touched {}'s file but isn't clearly linked to the symptom; treat it as unconfirmed without corroborating runtime evidence",
                seed_focus.map(|f| f.to_string()).unwrap_or_else(|| "null".into()),
                t.name
            ),
            Some(t) => format!(
                "Changes shipped in {change_range_label} but none touched {} — a regression here is unlikely to be a code change to the seed itself (check upstream deps, data, or config)",
                t.name
            ),
            None => format!(
                "Recent change{}{} in {change_range_label} may have introduced the regression",
                citation.commit_clause, citation.symbol_clause
            ),
        };
        let base = (if seed_in_changes { regression_seed_touched_score(seed_focus) } else { 0.18 }
            + if queue_hits.is_empty() { 0.0 } else { 0.05 })
            * if maintenance_only { 0.5 } else { 1.0 };
        cause_inputs.push(cause(
            "cause:deployment-regression",
            regression_title,
            "deployment-regression",
            std::iter::once(cid).chain(seed_ev_id.clone()).collect(),
            clamp01(base),
            meta(&[("blastRadius", json!(blast_radius))]),
        ));
    }

    const MIN_FANOUT_FOR_CAUSE: i64 = 3;
    if let (Some(t), Some(imp_id), Some(seed_id), Some(imp)) = (top_ref, &impact_ev_id, &seed_ev_id, &impact) {
        if imp.affected >= MIN_FANOUT_FOR_CAUSE {
            cause_inputs.push(cause(
                "cause:blast-radius",
                format!("{} has wide code reach ({} dependent symbols) and may propagate the fault", t.name, imp.affected),
                "blast-radius",
                vec![imp_id.clone(), seed_id.clone()],
                clamp01(0.15 + if queue_hits.is_empty() { 0.0 } else { 0.05 }),
                meta(&[("blastRadius", json!(blast_radius))]),
            ));
        }
    }

    // HOR-341: SEED-EMITTED runtime-error cause.
    if let (false, Some(t), Some(seed_id)) = (seed_emitted_joins.is_empty(), top_ref, &seed_ev_id) {
        let hint_named_codes: HashSet<String> = extract_event_codes(&[Some(&hint)]).into_iter().collect();
        let mut ordered: Vec<&SeedEmittedJoin> = seed_emitted_joins.iter().collect();
        ordered.sort_by(|a, b| {
            if a.raised_by_seed != b.raised_by_seed {
                return if a.raised_by_seed { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater };
            }
            let (ha, hb) = (hint_named_codes.contains(&a.code), hint_named_codes.contains(&b.code));
            if ha != hb {
                return if ha { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater };
            }
            let ta = seed_emitted_severity_tier(a.level.as_deref(), &a.code, Some(&a.message));
            let tb = seed_emitted_severity_tier(b.level.as_deref(), &b.code, Some(&b.message));
            if ta != tb {
                return tb.cmp(&ta);
            }
            js::cmp_f64(b.count, a.count)
        });
        let lead = ordered[0];
        let source_ids: Vec<String> =
            ordered.iter().map(|j| j.ev_id.clone()).chain(std::iter::once(seed_id.clone())).collect::<IndexSet<_>>().into_iter().collect();
        let tier = seed_emitted_severity_tier(lead.level.as_deref(), &lead.code, Some(&lead.message));
        let volume_boost = (lead.count.max(1.0).log10() * 0.025).min(0.1);
        let msg_clause = if lead.message.is_empty() {
            String::new()
        } else {
            format!(" — \"{}\"", js::slice_chars(WS_RUN.replace_all(&lead.message, " ").trim(), 90))
        };
        let by_seed = lead.raised_by_seed;
        let raiser = if by_seed || lead.raiser_name.is_empty() { t.name.clone() } else { lead.raiser_name.clone() };
        let dep_clause = if by_seed { String::new() } else { format!(", a dependency of {}", t.name) };
        let callee_penalty = if by_seed { 0.0 } else { 0.18 };
        if tier == SEV_ERROR || tier == SEV_WARN {
            let count = js::number_string(lead.count);
            let (title, base) = if tier == SEV_ERROR {
                (
                    if by_seed {
                        format!("Runtime error {} ({count}x in Elasticsearch) is raised by {raiser} — the likely failure{msg_clause}", lead.code)
                    } else {
                        format!("Runtime error {} ({count}x in Elasticsearch) surfaces on {raiser}{dep_clause}{msg_clause}", lead.code)
                    },
                    clamp01(0.6 + volume_boost - callee_penalty),
                )
            } else {
                (
                    format!(
                        "Warning {} ({count}x in Elasticsearch) {} {raiser}{dep_clause}{msg_clause}",
                        lead.code,
                        if by_seed { "is raised by" } else { "surfaces on" }
                    ),
                    clamp01(0.42 + volume_boost - callee_penalty),
                )
            };
            cause_inputs.push(cause(
                "cause:seed-emitted-error",
                js::slice_chars(&title, 220),
                "error-correlation",
                source_ids,
                base,
                meta(&[
                    ("blastRadius", json!(blast_radius)),
                    ("seedEmitted", json!(true)),
                    ("code", json!(lead.code)),
                    ("count", json!(lead.count)),
                    ("severity", json!(if tier == SEV_ERROR { "error" } else { "warn" })),
                ]),
            ));
        }
    }

    // HOR-453: hint-matched WARN signal.
    if let Some(logs) = deps.logs.filter(|_| seed_emitted_joins.is_empty() && !source_impact_hint && !meaningful_hint_tokens.is_empty()) {
        let text = meaningful_hint_tokens.iter().filter(|t| t.chars().count() >= 4).cloned().collect::<Vec<_>>().join(" ");
        if let Ok(warn) = logs
            .analyze_errors(
                &LogQuery {
                    service: input.service.clone(),
                    from: Some(logs_window()),
                    level: Some(LogLevel::Warn),
                    text: Some(text),
                    ..Default::default()
                },
                None,
            )
            .await
        {
            let signals: Vec<SignalLike> =
                warn.signatures.iter().map(|s| SignalLike { key: s.key.clone(), count: s.count, message: s.sample_message.clone() }).collect();
            if let Some(picked) = select_hint_matched_signal(&signals, &meaningful_hint_tokens) {
                let tier = seed_emitted_severity_tier(None, &picked.code, Some(&picked.message));
                let volume_boost = (picked.count.max(1.0).log10() * 0.03).min(0.1);
                let msg_clause = if picked.message.is_empty() {
                    String::new()
                } else {
                    format!(" — \"{}\"", js::slice_chars(WS_RUN.replace_all(&picked.message, " ").trim(), 80))
                };
                let count = js::number_string(picked.count);
                let id = ev
                    .mk(
                        EvidenceKind::Log,
                        js::slice_chars(&format!("event_code {}: {count}x in Elasticsearch — matches the reported symptom", picked.code), 220),
                        json!({
                            "signature": picked.code,
                            "count": picked.count,
                            "sampleMessage": if picked.message.is_empty() { Value::Null } else { Value::String(picked.message.clone()) },
                            "relevanceClass": "direct",
                            "relevanceReason": format!("event_code {} matches the reported symptom (not structurally linked to the seed)", picked.code),
                            "hintMatched": true,
                        }),
                        EvidenceLinks::default(),
                        None,
                        Some(0.75),
                    )
                    .id
                    .clone();
                log_ev_ids.push(id.clone());
                cause_inputs.push(cause(
                    "cause:hint-matched-signal",
                    js::slice_chars(
                        &format!(
                            "Runtime signal {} ({count}x in Elasticsearch) matches the reported symptom but isn't structurally linked to {}{msg_clause} — verify",
                            picked.code,
                            top_ref.map(|t| t.name.as_str()).unwrap_or("the seed")
                        ),
                        220,
                    ),
                    "error-correlation",
                    vec![id],
                    clamp01(if tier == SEV_ERROR { 0.6 } else { 0.56 } + volume_boost),
                    meta(&[
                        ("blastRadius", json!(blast_radius)),
                        ("hintMatched", json!(true)),
                        ("code", json!(picked.code)),
                        ("count", json!(picked.count)),
                    ]),
                ));
            }
        }
    }

    // HOR-446/448: source-only data-flow mechanism (seed + next ranked seeds + callees).
    if let (Some(t), Some(seed_id), Some(seed_ctx), Some(c), false) = (top_ref, &seed_ev_id, &ctx, code, source_impact_hint) {
        let scan_ids: Vec<String> = seeds
            .iter()
            .skip(1)
            .take(3)
            .map(|s| s.id.clone())
            .chain(seed_ctx.callees.iter().take(4).map(|s| s.id.clone()))
            .collect::<IndexSet<_>>()
            .into_iter()
            .filter(|id| id != &t.id)
            .collect();
        let extra = futures::future::join_all(scan_ids.iter().map(|id| c.context(id))).await;
        let contexts: Vec<SymbolContext> = std::iter::once(seed_ctx.clone()).chain(extra.into_iter().filter_map(Result::ok)).collect();
        if let Some(df) = detect_data_flow_cause_across(&contexts) {
            cause_inputs.push(cause(
                "cause:seed-data-flow",
                js::slice_chars(&df.title, 220),
                "data-flow",
                vec![seed_id.clone()],
                df.base_score,
                meta(&[("dataFlowPattern", json!(df.pattern)), ("matched", json!(df.matched)), ("blastRadius", json!(blast_radius))]),
            ));
        }
    }

    if analysis.as_ref().is_some_and(|a| !a.signatures.is_empty()) && !queue_hits.is_empty() && !direct_log_ev_ids.is_empty() {
        let first_queue = &queue_hits[0];
        let queue_label = format!(
            "\"{}\" ({} -> {})",
            first_queue.queue_name,
            first_queue.producer_symbol.as_deref().unwrap_or("unknown"),
            first_queue.worker_symbol.as_deref().unwrap_or("unknown")
        );
        let direct_total: f64 = direct_signatures.iter().map(|d| d.count).sum();
        let top_clause = direct_signatures.first().map(|d| format!(", top {}", d.key)).unwrap_or_default();
        cause_inputs.push(cause(
            "cause:error-correlation",
            format!(
                "Runtime errors ({}{top_clause}) directly linked to the implicated queue path {queue_label}",
                js::number_string(direct_total)
            ),
            "error-correlation",
            direct_log_ev_ids.iter().take(3).cloned().collect(),
            0.30,
            meta(&[("blastRadius", json!(blast_radius))]),
        ));
    }

    // HOR-328 round-2: network/dependency cause from the dominant DIRECT error message.
    let infra_sig = direct_signatures.iter().find(|d| INFRA_RE.is_match(&d.message));
    let queue_hit_names: HashSet<String> = queue_hits.iter().map(|e| e.queue_name.to_lowercase()).collect();
    let infra_queue = queue_failure_signals.iter().find(|q| {
        if !INFRA_RE.is_match(&q.reason) {
            return false;
        }
        if queue_hit_names.contains(&q.queue_name.to_lowercase()) {
            return true;
        }
        let q_tokens: HashSet<String> = tokenize(&q.queue_name).into_iter().collect();
        hint_tokens.iter().any(|t| t.chars().count() >= 3 && q_tokens.contains(t))
    });
    if let Some(s) = infra_sig {
        cause_inputs.push(cause(
            "cause:dependency-failure",
            format!(
                "Dependency/network failure: {}x {} — \"{}\"",
                js::number_string(s.count),
                s.key,
                js::slice_chars(WS_RUN.replace_all(&s.message, " ").trim(), 100)
            ),
            "infrastructure",
            direct_log_ev_ids.iter().take(3).cloned().collect(),
            0.5,
            meta(&[("blastRadius", json!(blast_radius))]),
        ));
    } else if let Some(q) = infra_queue {
        cause_inputs.push(cause(
            "cause:dependency-failure",
            format!(
                "Dependency/network failure on queue {}: {} failed job(s) — \"{}\"{}",
                q.queue_name,
                js::number_string(q.count),
                js::slice_chars(WS_RUN.replace_all(&q.reason, " ").trim(), 100),
                if q.stale { " (stale — reflects a past run)" } else { "" }
            ),
            "infrastructure",
            vec![q.ev_id.clone()],
            if q.stale { 0.34 } else { 0.5 },
            meta(&[("blastRadius", json!(blast_radius))]),
        ));
    }

    if !data_anomaly_ev_ids.is_empty() {
        let collections: Vec<&String> = data_anomaly_collections.iter().collect::<IndexSet<_>>().into_iter().collect();
        let example = collections.first().map(|c| format!(" (e.g. {c})")).unwrap_or_default();
        cause_inputs.push(cause(
            "cause:data-state-anomaly",
            format!(
                "Data-state anomaly (co-occurring): {} collection(s) hold records in a failed/stale state{example} — verify whether it relates to this failure",
                collections.len()
            ),
            "data-state-anomaly",
            data_anomaly_ev_ids.iter().take(3).cloned().collect(),
            0.22,
            meta(&[("blastRadius", json!(blast_radius))]),
        ));
    }
    if !latency_metric_ev_ids.is_empty() {
        cause_inputs.push(cause(
            "cause:metric-latency",
            format!(
                "Metric anomalies ({} latency/error-rate signal(s)) — upstream dependency or component under load",
                latency_metric_ev_ids.len()
            ),
            "external-api-latency",
            latency_metric_ev_ids.clone(),
            0.45,
            meta(&[("blastRadius", json!(blast_radius))]),
        ));
    }
    if !queue_metric_ev_ids.is_empty() {
        cause_inputs.push(cause(
            "cause:metric-queue-growth",
            format!(
                "Queue-growth metric anomalies ({} signal(s)) — worker throughput may be insufficient",
                queue_metric_ev_ids.len()
            ),
            "queue-backlog",
            queue_metric_ev_ids.clone(),
            0.40,
            meta(&[("blastRadius", json!(blast_radius))]),
        ));
    }

    // Provider reliability keyed by Evidence.source.
    let mut provider_reliability: HashMap<String, f64> = HashMap::from([("code".to_string(), 0.80)]);
    if deps.logs.is_some() {
        provider_reliability.insert("logs".into(), 0.70);
    }
    if deps.mongo.is_some() || deps.redis_state.is_some() {
        provider_reliability.insert("state".into(), 0.85);
    }
    if deps.queue.is_some() {
        provider_reliability.insert("queue".into(), 0.90);
    }
    if deps.metrics.is_some() {
        provider_reliability.insert("metrics".into(), 0.75);
    }

    // Incident memory (HOR-363): code areas touched by PRIOR credible investigations.
    let mut prior_incidents: HashMap<String, i64> = HashMap::new();
    if let Ok(priors) = list_investigations_with_reports(db, 50, input.repo.as_deref()).await {
        for row in priors {
            if allowed_prior_ids.as_ref().is_some_and(|ids| !ids.contains(&row.id)) {
                continue;
            }
            let Some(rep) = row.report.as_deref().and_then(|r| serde_json::from_str::<Value>(r).ok()) else { continue };
            let Some(evs) = rep.get("evidence").and_then(|e| serde_json::from_value::<Vec<Evidence>>(e.clone()).ok()) else { continue };
            if evs.is_empty() {
                continue;
            }
            if rep.get("confidence").and_then(Value::as_f64).is_some_and(|c| c < 0.5) {
                continue;
            }
            let mut seen: HashSet<String> = HashSet::new();
            for n in build_graph(&evs).nodes {
                if matches!(n.node_type, GraphNodeType::Symbol | GraphNodeType::File) && seen.insert(n.id.clone()) {
                    *prior_incidents.entry(n.id).or_insert(0) += 1;
                }
            }
        }
    }

    let scoring_findings: Vec<ScoringFinding> = findings
        .iter()
        .map(|f| ScoringFinding { kind: f.kind.as_str().into(), confidence: f.confidence, evidence_ids: f.evidence_ids.clone() })
        .collect();
    let mut ranked_causes: Vec<CauseCandidate> = rank_causes(
        &cause_inputs,
        &ScoringContext {
            evidence: &ev.items,
            graph: &graph,
            findings: Some(scoring_findings),
            provider_reliability: Some(provider_reliability),
            request: Some(ScoringRequest { hint: Some(input.hint.clone()), service: input.service.clone() }),
            now: Some(now_iso.clone()),
            prior_incidents: if prior_incidents.is_empty() { None } else { Some(prior_incidents) },
            mode: if source_impact_hint { Some(Intent::SourceImpact) } else { None },
        },
        3,
    );

    if vague_perf_unconfirmed {
        for c in ranked_causes.iter_mut() {
            if !matches!(c.category.as_str(), "deployment-regression" | "blast-radius" | "queue-path") {
                continue;
            }
            c.final_score = c.final_score.min(0.18);
            if !c.title.contains("unconfirmed structural guess") {
                c.title.push_str(" — unconfirmed structural guess (vague performance hint: no metrics evidence, low-confidence seed)");
            }
        }
        ranked_causes.sort_by(|a, b| js::cmp_f64(b.final_score, a.final_score));
    }

    // g. confidence
    let ambient_set: Option<HashSet<String>> =
        if ambient_log_ev_ids.is_empty() { None } else { Some(ambient_log_ev_ids.iter().cloned().collect()) };
    let evidence_confidence = compute_weighted_evidence_confidence(&ev.items, ambient_set.as_ref());
    let seed_resolved = if seeds.is_empty() { 0.0 } else if seed_is_low_confidence { 0.3 } else { 1.0 };
    let mut confidence = clamp01(0.5 * evidence_confidence + 0.5 * seed_resolved);

    // h. summary
    let area = ctx
        .as_ref()
        .and_then(|c| c.community.as_ref().map(|cm| cm.name.clone()))
        .or_else(|| top_ref.map(|t| t.file_path.clone()))
        .or_else(|| input.service.clone())
        .unwrap_or_else(|| "runtime evidence".into());
    let mut seed_linked_ev_ids: HashSet<String> = direct_log_ev_ids.iter().cloned().collect();
    seed_linked_ev_ids.extend(seed_ev_id.clone());
    seed_linked_ev_ids.extend(impact_ev_id.clone());
    if looks_performance(&hint) {
        seed_linked_ev_ids.extend(latency_metric_ev_ids.iter().cloned());
    }
    let is_linked_to_seed = |ids: &[String]| ids.iter().any(|id| seed_linked_ev_ids.contains(id));
    let rerank = deps.rerank.map(|r| r as &dyn Fn(&[CauseCandidate]) -> Vec<CauseCandidate>);
    let selection = select_headline_cause(&ranked_causes, &is_linked_to_seed, rerank);
    let headline_cause = selection.headline_cause.clone();
    let headline_linked = selection.headline_linked;
    if headline_cause.is_some() && !headline_linked && !source_impact_hint {
        confidence = confidence.min(0.6);
    }
    let banner = if degraded_no_source { "Runtime-only (source intelligence unavailable). " } else { "" };
    let scope = match top_ref {
        Some(_) if seed_is_low_confidence => "could not be confidently localized from source alone".to_string(),
        Some(_) => format!("resolved to {label} ({area})"),
        None => format!("over runtime evidence ({area})"),
    };
    let seed_disclaimer = match top_ref {
        Some(t) if seed_is_low_confidence => format!(
            "⚠ No symbol closely matched \"{hint}\" — \"{}\" is a low-confidence closest match (semantic). Refine with an exact symbol or error code to target precisely. ",
            t.name
        ),
        _ => String::new(),
    };
    let mut summary = match &headline_cause {
        Some(h) if headline_linked => format!("{seed_disclaimer}{banner}Investigation of \"{hint}\" {scope}. Top suspected cause: {}.", h.title),
        Some(h) => format!(
            "{seed_disclaimer}{banner}Investigation of \"{hint}\" {scope}. No cause is structurally linked to the seed; the strongest co-occurring signal (a lead to verify, not a diagnosis) is: {}.",
            h.title
        ),
        None => format!(
            "{seed_disclaimer}{banner}Investigation of \"{hint}\" {scope}. No dominant suspected cause emerged from the available {} evidence.",
            if degraded_no_source { "runtime" } else { "structural" }
        ),
    };

    let has_incident_signal = !direct_log_ev_ids.is_empty()
        || !latency_metric_ev_ids.is_empty()
        || !queue_metric_ev_ids.is_empty()
        || !data_anomaly_ev_ids.is_empty()
        || !queue_failure_signals.is_empty()
        || findings.iter().any(|f| f.kind == FindingKind::Anomaly)
        || headline_cause.is_some();
    let explanatory_hint = looks_explanatory(&hint) && input.since.is_none() && !source_impact_hint;
    let mut behavioral: Option<BehavioralWalkthrough> = None;
    if explanatory_hint {
        let mut flow_pool: Vec<Flow> = flows.clone();
        let richest_seed_len = richest_flow(&flows).map(|f| f.steps.len());
        if let (Some(c), Some(seed_ctx)) = (code, &ctx) {
            if richest_seed_len.is_none_or(|n| n <= 1) && !seed_ctx.callers.is_empty() {
                let entry_callers: Vec<&Symbol> = seed_ctx
                    .callers
                    .iter()
                    .filter(|s| ENTRY_RE.is_match(&s.name) || ENTRY_RE.is_match(&s.file_path))
                    .take(3)
                    .collect();
                for caller in entry_callers {
                    if let Ok(more) = c.flows_for(&caller.id, None).await {
                        flow_pool.extend(more);
                    }
                }
            }
        }
        let mut class_methods: Vec<Symbol> = vec![];
        if let (Some(c), true) = (code, is_class_symbol(top_ref)) {
            if richest_flow(&flow_pool).is_none_or(|f| f.steps.len() <= 1) {
                class_methods = fetch_class_methods(c, top_ref.unwrap()).await;
            }
        }
        let b = build_behavioral_walkthrough(&hint, top_ref, ctx.as_ref(), &flow_pool, &class_methods);
        let noisy = if has_incident_signal {
            " (note: live error signals also exist in this codebase — rephrase as a symptom like \"X failing\" for a fault hunt)"
        } else {
            ""
        };
        summary = format!(
            "{seed_disclaimer}{banner}\"{hint}\" reads as a \"how does it work\" question — here is the code path{noisy}:\n\n{}",
            b.narrative
        );
        behavioral = Some(b);
    }

    let default_flags = ConnectorFlags::default();
    if !explanatory_hint && looks_performance(&hint) && deps.metrics.is_none() && seed_is_low_confidence {
        let perf_next = if has_any_runtime_connector(deps.connectors.as_ref().unwrap_or(&default_flags)) {
            "Connect a metrics source (`horus connect grafana`) and re-run, or name the specific slow operation."
        } else {
            "Name the specific slow operation for a structural walkthrough."
        };
        summary = format!(
            "{banner}\"{hint}\" reads as a latency/performance question, but no metrics connector (Grafana) is configured — response-time and error-rate trends can't be assessed from source structure alone{}. {perf_next}",
            top_ref
                .map(|t| format!(" (the closest structural match, {}, is a low-confidence guess, not a diagnosis)", t.name))
                .unwrap_or_default()
        );
    }

    // HOR-385: source-impact mode leads with the structural impact result.
    if let (true, Some(t), Some(imp)) = (source_impact_hint, top_ref, &impact) {
        let affected = imp.affected;
        let depth_chain =
            imp.by_depth.iter().filter(|d| !d.symbols.is_empty()).map(|d| format!("depth {}: {}", d.depth, d.symbols.len())).collect::<Vec<_>>().join(", ");
        let isolation_target = if looks_verify_isolation(&hint) && named_symbols.len() >= 2 { Some(&named_symbols[1]) } else { None };
        summary = match isolation_target {
            Some(target) => {
                let reach = imp.by_depth.iter().find(|d| d.symbols.iter().any(|s| s.name.to_lowercase() == target.to_lowercase())).map(|d| d.depth);
                match reach {
                    Some(depth) => format!(
                        "{} DOES affect {target} via a dependency path (reaches it at depth {depth}; {affected} affected symbol(s) total).",
                        t.name
                    ),
                    None => format!(
                        "{} is isolated from {target} — no dependency path found ({affected} affected symbol(s) total, none matching {target}).",
                        t.name
                    ),
                }
            }
            None => format!(
                "Impact of {}: {affected} affected symbol(s){}",
                t.name,
                if depth_chain.is_empty() { ".".to_string() } else { format!(" ({depth_chain}).") }
            ),
        };
    }

    // i. nextActions
    let mut next_actions = build_next_actions(top_ref, impact.as_ref(), &queue_hits, changes.as_ref(), &input);
    if let (true, Some(entry)) = (explanatory_hint, behavioral.as_ref().and_then(|b| b.entry.as_ref())) {
        next_actions.insert(0, format!("Trace the full call graph of the entry point: `horus explain {}`.", entry.name));
    }
    if degraded_no_source {
        next_actions.insert(
            0,
            "Source intelligence was unavailable — run `horus init` to enable code-aware analysis, then re-run for a full investigation.".into(),
        );
    }
    if let (Some(o), false) = (&ownership_estimate, seed_is_low_confidence) {
        if let Some(maintainer) = &o.likely_maintainer {
            next_actions.insert(
                0,
                format!(
                    "Route to likely maintainer: {maintainer} ({}% of commits to {})",
                    js::int_string(js::math_round(o.maintainer_share * 100.0)),
                    o.file.clone().or_else(|| top_ref.map(|t| t.file_path.clone())).unwrap_or_else(|| "the implicated file".into())
                ),
            );
        }
    }

    let mut report = InvestigationReport {
        startup_recall: None, // assigned below (moved after contradiction checks)
        recall_trace: Some(recall_trace),
        id: uuid::Uuid::new_v4().to_string(),
        subject: investigation_subject(&input),
        summary,
        intent: Some(intent),
        seeds,
        evidence: std::mem::take(&mut ev.items),
        timeline,
        correlation,
        findings,
        suspected_causes: ranked_causes,
        hypotheses: validated,
        similar_incidents: vec![],
        gap_analysis: GapAnalysis { gaps: vec![], blind_spots: vec![], confidence_ceiling: 1.0 },
        graph,
        confidence,
        next_actions,
        ownership: Some(ownership_estimate),
        cause_chains: if cause_chains.is_empty() { None } else { Some(cause_chains) },
        recent_changes,
        behavioral,
        degraded: if degraded_no_source {
            Some(Degraded { source_intelligence: false, reason: "source-intelligence host unreachable".into() })
        } else {
            None
        },
        next_steps: None,
        source_status: None,
        created_at: None,
        persisted: None,
        memory_capture_error: None,
        ai_judgment: None,
        diagnosis: None,
        followup_rounds: None,
        fix_pr: None,
        unattended: None,
        input,
    };

    // HOR-19 — gap analysis + confidence caps before persisting. CONFIGURED is split from
    // AVAILABLE: configured-but-unavailable is reported as exactly that.
    let unavailable: Vec<String> = match &deps.connectors {
        Some(c) => [
            ("elasticsearch", c.elasticsearch, deps.logs.is_some()),
            ("grafana", c.grafana, deps.metrics.is_some()),
            ("mongodb", c.mongodb, deps.mongo.is_some()),
            ("postgres", c.postgres, deps.postgres.is_some()),
            ("sentry", c.sentry, deps.sentry.is_some()),
            ("lens", c.lens, deps.lens.is_some()),
            ("axiom", c.axiom, deps.axiom.is_some()),
            ("shopify", c.shopify, deps.shopify.is_some()),
            ("redis", c.redis, deps.redis_state.is_some()),
        ]
        .into_iter()
        .filter(|(_, configured, present)| *configured == Some(true) && !present)
        .map(|(k, _, _)| k.to_string())
        .collect(),
        None => vec![],
    };
    let is_prometheus = deps.metrics.is_some_and(|m| m.id() == "prometheus");
    let has_queue = deps.queue.is_some() || !deps.additional_queues.is_empty();
    let connector_flags: ConnectorFlags = match &deps.connectors {
        Some(c) => ConnectorFlags {
            queue: Some(has_queue),
            sentry_collected: Some(sentry_collected),
            sentry_failure_reason: sentry_failure_reason.clone(),
            lens_collected: Some(lens_collected),
            lens_failure_reason: lens_failure_reason.clone(),
            cloud_logs: Some(cloud_log_status.clone()),
            additional_state: Some(!deps.additional_state.is_empty() || c.additional_state == Some(true)),
            prometheus: Some(is_prometheus),
            axiom_collected: Some(axiom_collected),
            axiom_failure_reason: axiom_failure_reason.clone(),
            shopify_collected: Some(shopify_collected),
            shopify_failure_reason: shopify_failure_reason.clone(),
            metrics_collected: Some(metrics_collected),
            metrics_failure_reason: metrics_failure_reason.clone(),
            logs_collected: Some(logs_collected),
            logs_compatibility_error: logs_compatibility_error.clone(),
            logs_failure_reason: logs_failure_reason.clone(),
            state_collected,
            state_failure_reason: state_failure_reason.clone(),
            queue_collected: Some(queue_collected),
            queue_failure_reason: queue_failure_reason.clone(),
            since_provided: Some(report.input.since.is_some()),
            unavailable: if unavailable.is_empty() { c.unavailable.clone() } else { Some(unavailable) },
            ..c.clone()
        },
        None => ConnectorFlags {
            elasticsearch: Some(deps.logs.is_some()),
            mongodb: Some(deps.mongo.is_some()),
            postgres: Some(deps.postgres.is_some()),
            sentry: Some(deps.sentry.is_some()),
            sentry_collected: Some(sentry_collected),
            sentry_failure_reason: sentry_failure_reason.clone(),
            lens: Some(deps.lens.is_some()),
            lens_collected: Some(lens_collected),
            lens_failure_reason: lens_failure_reason.clone(),
            axiom: Some(deps.axiom.is_some()),
            cloud_logs: Some(cloud_log_status.clone()),
            additional_state: Some(!deps.additional_state.is_empty()),
            prometheus: Some(is_prometheus),
            axiom_collected: Some(axiom_collected),
            axiom_failure_reason: axiom_failure_reason.clone(),
            shopify: Some(deps.shopify.is_some()),
            shopify_collected: Some(shopify_collected),
            shopify_failure_reason: shopify_failure_reason.clone(),
            grafana: Some(deps.metrics.is_some() && !is_prometheus),
            redis: Some(deps.redis_state.is_some()),
            queue: Some(has_queue),
            metrics_collected: Some(metrics_collected),
            metrics_failure_reason: metrics_failure_reason.clone(),
            logs_collected: Some(logs_collected),
            logs_compatibility_error: logs_compatibility_error.clone(),
            logs_failure_reason: logs_failure_reason.clone(),
            state_collected,
            state_failure_reason: state_failure_reason.clone(),
            queue_collected: Some(queue_collected),
            queue_failure_reason: queue_failure_reason.clone(),
            since_provided: Some(report.input.since.is_some()),
            unavailable: None,
        },
    };
    let gap_analysis =
        detect_missing_evidence(&report, Some(&connector_flags), if source_impact_hint { Some(Intent::SourceImpact) } else { None });
    if !source_impact_hint {
        report.confidence = report.confidence.min(gap_analysis.confidence_ceiling);
    }
    if seed_is_low_confidence && !source_impact_hint {
        report.confidence = report.confidence.min(0.45);
    }
    let top_cause_score = report.suspected_causes.first().map(|c| c.final_score).unwrap_or(0.0);
    if !source_impact_hint {
        report.confidence = report.confidence.min(confidence_ceiling_for_cause(top_cause_score));
    }
    report.next_actions.extend(gap_next_actions(&gap_analysis.gaps));
    let mut by_impact: Vec<_> = gap_analysis.gaps.iter().collect();
    by_impact.sort_by(|a, b| js::cmp_f64(b.confidence_impact, a.confidence_impact));
    let top_routable_gap = by_impact.into_iter().find(|g| g.route_hint.is_some()).cloned();
    report.gap_analysis = gap_analysis;
    report.next_steps = Some(route(&RouterConditions {
        intent: Some(intent),
        empty: false,
        low_confidence: report.confidence < 0.5,
        top_gap: top_routable_gap,
        any_runtime_connector: has_any_runtime_connector(&connector_flags),
        metrics_null: looks_performance(&hint) && deps.metrics.is_none(),
        degraded_source_intelligence: report.degraded.is_some(),
        stale_index: deps.stale_index,
        seed_name: top.as_ref().map(|t| t.name.clone()),
        query: Some(hint.clone()),
        ..RouterConditions::new(RouterCommand::Investigate)
    }));
    report.source_status = Some(build_runtime_source_status(&report.evidence, &connector_flags));

    // Startup-recall contradiction checks against the LIVE evidence.
    for candidate in startup_recall.iter_mut() {
        let invalidators: Vec<String> = candidate.outcome.as_ref().map(|o| o.invalidating_conditions.clone()).unwrap_or_default();
        candidate.contradicting_evidence_ids = report
            .evidence
            .iter()
            .filter(|e| {
                let hay = horus_core::json::to_js_json(&json!({ "title": e.title, "payload": e.payload })).unwrap_or_default().to_lowercase();
                invalidators.iter().any(|c| c.chars().count() > 8 && hay.contains(&c.to_lowercase()))
            })
            .map(|e| e.id.clone())
            .collect();
        if !candidate.contradicting_evidence_ids.is_empty() {
            candidate.validation = StartupValidation::Contradicted;
        }
    }
    report.startup_recall = Some(startup_recall);

    // j. PERSIST — may overwrite report.id with the DB-assigned id.
    let persisted = persist(db, &mut report, &now_iso).await;
    let persisted_id = persisted.as_ref().map(|p| p.0.clone());
    if let Some(id) = &persisted_id {
        report.id = id.clone();
    }
    report.persisted = Some(persisted_id.is_some());

    // k. INCIDENT MEMORY (HOR-18) — CONTEXT ONLY.
    if let Some(pid) = &persisted_id {
        let storage = SqliteMemoryStorage::new(db.clone());
        let tags = derive_tags(&report);
        report.similar_incidents = recall_similar(&storage, &tags, Some(pid), report.input.repo.as_deref())
            .await
            .into_iter()
            .filter(|item| {
                allowed_prior_ids.as_ref().is_none_or(|ids| item.investigation_id.as_ref().is_some_and(|i| ids.contains(i)))
            })
            .collect();
        store_incident_memory(&storage, Some(pid), &report).await;

        if let Some(store) = deps.store.filter(|_| auto_investigation_memory_enabled()) {
            let audit = AuditCtx { actor: AuditActor::system(), note: Some("auto: investigation memory (HOR-432)".into()) };
            let report_time = persisted.as_ref().and_then(|p| p.1).unwrap_or(now);
            match capture_investigation_memory(store, Some(pid), &report, report_time, &audit).await {
                Ok(captured) => {
                    if let (Some(index), Some(memory_id), Some(repo)) = (deps.recall_index, captured.memory_id.as_deref(), report.input.repo.as_deref()) {
                        index_incident_hint(index, repo, memory_id, &report.input.hint).await;
                    }
                }
                Err(err) => report.memory_capture_error = Some(connector_failure_reason(&err)),
            }
        }
    }

    // l. AUDIT BUNDLE (HOR-16) — the fully-finalized report, best-effort.
    if let Some(pid) = &persisted_id {
        if let Ok(json) = horus_core::json::to_js_json(&report) {
            let _ = update_investigation_report(db, pid, &json).await;
        }
    }

    Ok(report)
}

/// Deterministic, name-bearing next-step suggestions.
fn build_next_actions(
    top: Option<&Symbol>,
    impact: Option<&ImpactResult>,
    queue_hits: &[QueueEdge],
    changes: Option<&ChangeSet>,
    input: &InvestigationInput,
) -> Vec<String> {
    let mut actions: Vec<String> = vec![];
    let mut seen: HashSet<&str> = HashSet::new();
    for edge in queue_hits {
        if !seen.insert(edge.queue_name.as_str()) {
            continue;
        }
        let worker = edge.worker_symbol.as_deref().unwrap_or("the consumer");
        actions.push(format!("Inspect logs for worker {worker} on queue {}", edge.queue_name));
        actions.push(format!("Check depth/failures of queue {}", edge.queue_name));
    }
    if let (Some(t), Some(imp)) = (top, impact) {
        if imp.affected > 0 {
            actions.push(format!("Review impact set of {} ({} affected symbol(s))", t.name, imp.affected));
        }
    }
    if let Some(t) = top {
        match (changes, input.since.as_deref()) {
            (Some(_), Some(since)) => actions.push(format!("Diff recent commits touching {} in {since}..HEAD", t.file_path)),
            _ => actions.push(format!("Diff recent commits touching {}", t.file_path)),
        }
    }
    if actions.is_empty() {
        actions.push(match (top, input.service.as_deref().filter(|s| !s.is_empty())) {
            (Some(t), _) => format!("Inspect the source of {} at {}", t.name, t.file_path),
            (None, Some(svc)) => format!("Inspect runtime logs and metrics for service \"{svc}\""),
            (None, None) => "Inspect runtime logs and metrics for the affected service".into(),
        });
    }
    actions
}

/// Persist an investigation row. Never fails — a down DB just yields None. Returns the
/// persisted id + createdAt. Stamps `report.createdAt` first (`??=`).
async fn persist(db: &DbHandle, report: &mut InvestigationReport, now_iso: &str) -> Option<(String, Option<DateTime<Utc>>)> {
    if report.created_at.is_none() {
        report.created_at = Some(now_iso.to_string());
    }
    let id = report.input.report_id.clone().unwrap_or_else(|| report.id.clone());
    let created_at = report.created_at.as_deref().and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&Utc));
    let mut stored = report.clone();
    stored.id = id.clone();
    stored.persisted = Some(true);
    let hint = report.input.hint.trim();
    let row = NewInvestigation {
        id: Some(id),
        title: if hint.is_empty() { "Investigation".into() } else { hint.to_string() },
        incident_input: horus_core::json::to_js_json(&report.input).ok()?,
        status: Some("open".into()),
        summary: Some(report.summary.clone()),
        narrative: None,
        report: Some(horus_core::json::to_js_json(&stored).ok()?),
        project: report.input.repo.clone(),
        created_at,
    };
    // `new Date(e.timestamp)` on an unparseable timestamp throws in TS and aborts the whole
    // transaction (persist → null); mirror that rather than silently storing NULL.
    let mut evidence = Vec::with_capacity(report.evidence.len());
    for e in &report.evidence {
        let timestamp = match e.timestamp.as_deref().filter(|t| !t.is_empty()) {
            Some(t) => {
                let ms = js::date_parse(t);
                if ms.is_nan() {
                    return None;
                }
                Some(DateTime::from_timestamp_millis(ms as i64)?)
            }
            None => None,
        };
        evidence.push(NewEvidenceRow {
            id: e.id.clone(),
            source: crate::types::provider_kind_name(e.source).into(),
            kind: crate::types::evidence_kind_name(e.kind).into(),
            title: e.title.clone(),
            timestamp,
            relevance: e.relevance,
            payload: Some(horus_core::json::to_js_json(&e.payload).ok()?),
            links: Some(horus_core::json::to_js_json(&e.links).ok()?),
            provenance: Some(horus_core::json::to_js_json(&e.provenance).ok()?),
        });
    }
    let findings = report
        .findings
        .iter()
        .map(|f| NewFindingRow {
            kind: f.kind.as_str().into(),
            title: f.title.clone(),
            detail: f.detail.clone(),
            confidence: f.confidence,
            evidence_ids: horus_core::json::to_js_json(&f.evidence_ids).ok(),
        })
        .collect();
    let hypotheses = report
        .hypotheses
        .iter()
        .enumerate()
        .map(|(i, h)| NewHypothesisRow {
            rank: i as i64 + 1,
            statement: h.statement.clone(),
            score: h.confidence,
            supporting_evidence: horus_core::json::to_js_json(&h.supporting_evidence_ids).ok(),
            verdict: Some(h.verdict.as_str().into()),
        })
        .collect();
    let saved = save_investigation_bundle(db, row, evidence, findings, hypotheses).await.ok()?;
    Some((saved, created_at))
}
