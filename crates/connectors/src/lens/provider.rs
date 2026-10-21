//! Lens user-report evidence provider (HOR-CONNECTORS / HOR-470).
//!
//! Each report is BOTH "what the user saw" (the comment + route + captured errors) AND a
//! direct code seed — the top parseable frame of the first captured error stack is
//! `filename:function:lineno`, i.e. the raise site.
//!
//! Mirrors the Sentry provider: one `kind: 'log'` Evidence per report (never raw report
//! bodies). The top frame is surfaced in the payload (`filePath`/`symbolName`/`lineStart`)
//! and in `links.file`/`links.line`.
//!
//! Privacy: the comment + captured error messages are the only human text carried, and
//! both are REDACTED. The reporter's identity (`metadata.app.user`) is NEVER read, and
//! console-tail bodies are NEVER included.

use std::sync::Mutex;

use async_trait::async_trait;
use horus_core::{redact_secrets, Evidence, EvidenceKind, EvidenceLinks, HealthStatus, Provenance, ProviderKind};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::client::{LensCloudClient, LensErrorEntry, LensNetworkEntry, LensReport, LensReportSummary, LensReportsQuery};
use crate::contract::Provider;
use crate::jsutil::{js_number_string, normalize_js_numbers, now_iso, now_ms, parse_js_date_ms, short_ts, slice_chars};

#[derive(Debug, Clone, Default)]
pub struct LensProviderOpts {
    /// How many recent reports to fold in (capped 1–200). Default 25.
    pub limit: Option<i64>,
    /// Report status to fetch. Default 'submitted' (a finalized user report).
    pub status_filter: Option<String>,
}

/// A resolved top stack frame — a direct code seed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensTopFrame {
    /// Source file path (URL origin stripped — pathname only), e.g. "/assets/app.js".
    pub filename: String,
    /// Function/symbol name at the raise site, when the frame named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// 1-based line number, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lineno: Option<i64>,
}

/// A failing network request captured on the report (ok===false or status>=500).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensFailingRequest {
    pub method: String,
    pub url: String,
    pub status: Option<i64>,
}

/// A Lens report enriched with the fields Horus turns into evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LensReportSignal {
    pub id: String,
    pub lens_site_id: String,
    pub status: String,
    pub created_at: String,
    pub submitted_at: Option<String>,
    pub issue_occurrence_count: Option<i64>,
    pub error_count: f64,
    pub has_replay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_flags: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    /// Message of the error whose stack seeded `top_frame` (or the first error). Redact before display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_error_message: Option<String>,
    pub top_frame: Option<LensTopFrame>,
    pub failing_requests: Vec<LensFailingRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub react_components: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct LensCollectOpts {
    pub from: Option<String>,
    pub to: Option<String>,
    pub hint_terms: Vec<String>,
    /// Only used by `query_evidence`.
    pub collected_at: Option<String>,
}

pub struct LensProvider {
    client: LensCloudClient,
    opts: LensProviderOpts,
    /// In-instance site-id cache — reports are site-scoped and the site list is stable.
    sites_cache: Mutex<Option<Vec<String>>>,
}

impl LensProvider {
    pub fn new(client: LensCloudClient, opts: LensProviderOpts) -> Self {
        Self { client, opts, sites_cache: Mutex::new(None) }
    }

    fn limit(&self) -> i64 {
        self.opts.limit.unwrap_or(25)
    }

    fn status_filter(&self) -> String {
        self.opts.status_filter.clone().unwrap_or_else(|| "submitted".to_string())
    }

    /// Collect recent reports across every site within the window and resolve each one's
    /// top frame + failing requests. A failing site LIST or reports LIST PROPAGATES so the
    /// engine records a gap; per-report metadata fetches are best-effort. Use
    /// `query_evidence` for the degrade-to-[] contract.
    pub async fn collect(&self, opts: &LensCollectOpts) -> anyhow::Result<Vec<LensReportSignal>> {
        let site_ids = self.sites().await?;

        // Fetch the window unfiltered per site (q is a single substring, not hint fan-out),
        // then relevance-rank client-side and cap to `limit` before the metadata fetches.
        let mut summaries: Vec<LensReportSummary> = Vec::new();
        for site_id in &site_ids {
            let page = self
                .client
                .list_reports(
                    site_id,
                    &LensReportsQuery {
                        from: opts.from.clone(),
                        to: opts.to.clone(),
                        q: None,
                        status: Some(self.status_filter()),
                        limit: Some(self.limit()),
                    },
                )
                .await?;
            summaries.extend(page);
        }

        // Re-apply the window client-side: a cloud build that predates the from/to params
        // silently IGNORES them, which would leak out-of-window reports into the incident's
        // evidence. The server-side filter is an efficiency; this is the correctness guarantee.
        let windowed: Vec<LensReportSummary> = summaries
            .into_iter()
            .filter(|s| in_window(&s.created_at, opts.from.as_deref(), opts.to.as_deref()))
            .collect();

        let mut ranked = rank_summaries(windowed, &opts.hint_terms, now_ms() as f64);
        ranked.truncate(self.limit().max(0) as usize);
        let reports = futures::future::join_all(
            ranked.iter().map(|s| async move { self.client.get_report(&s.lens_site_id, &s.id).await.ok() }),
        )
        .await;
        Ok(ranked
            .into_iter()
            .zip(reports)
            .map(|(summary, report)| build_signal(&summary, report.as_ref()))
            .collect())
    }

    /// Synthesize Evidence from Lens reports. One `kind: 'log'` Evidence per report.
    pub fn to_evidence(&self, signals: &[LensReportSignal], hint_terms: &[String], collected_at: &str) -> Vec<Evidence> {
        let query = format!("lens reports (status:{}, up to {})", self.status_filter(), self.limit());
        signals
            .iter()
            .enumerate()
            .map(|(i, sig)| signal_to_evidence(sig, hint_terms, &query, collected_at, i))
            .collect()
    }

    /// One-shot evidence query: collect reports, convert to redacted Evidence. Degrades to []
    /// on any failure so a flaky Cloud never aborts an investigation.
    pub async fn query_evidence(&self, opts: &LensCollectOpts) -> Vec<Evidence> {
        match self.collect(opts).await {
            Ok(signals) => {
                let collected_at = opts.collected_at.clone().unwrap_or_else(now_iso);
                self.to_evidence(&signals, &opts.hint_terms, &collected_at)
            }
            Err(_) => vec![],
        }
    }

    async fn sites(&self) -> anyhow::Result<Vec<String>> {
        if let Some(cached) = self.sites_cache.lock().unwrap().clone() {
            return Ok(cached);
        }
        let ids: Vec<String> = self.client.list_sites().await?.into_iter().map(|s| s.id).collect();
        *self.sites_cache.lock().unwrap() = Some(ids.clone());
        Ok(ids)
    }
}

#[async_trait]
impl Provider for LensProvider {
    fn id(&self) -> &str {
        "lens"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Logs
    }
    async fn health(&self) -> HealthStatus {
        self.client.health().await
    }
}

/* ── Signal building ─────────────────────────────────────────────────────── */

/// Merge a summary with its (optional) full report metadata into a signal.
pub fn build_signal(summary: &LensReportSummary, report: Option<&LensReport>) -> LensReportSignal {
    let meta = report.and_then(|r| r.metadata.as_ref());
    let errors: &[LensErrorEntry] = meta.map(|m| m.errors.as_slice()).unwrap_or(&[]);
    let (frame, message) = top_frame_from_errors(errors);

    let env = meta.and_then(|m| m.env.as_ref());
    let app = meta.and_then(|m| m.app.as_ref());
    let url = match env.map(|e| e.url.as_str()).filter(|u| !u.is_empty()) {
        Some(u) => Some(u.to_string()),
        None => summary.url.clone(),
    };
    LensReportSignal {
        id: summary.id.clone(),
        lens_site_id: summary.lens_site_id.clone(),
        status: summary.status.clone(),
        created_at: summary.created_at.clone(),
        submitted_at: summary.submitted_at.clone(),
        issue_occurrence_count: summary.issue_occurrence_count,
        error_count: if summary.error_count != 0.0 { summary.error_count } else { errors.len() as f64 },
        has_replay: summary.has_replay,
        comment: meta.and_then(|m| m.comment.clone()).or_else(|| summary.comment.clone()),
        route: env.and_then(|e| e.route.clone()),
        url,
        release: app.and_then(|a| a.release.clone()),
        git_sha: app.and_then(|a| a.git_sha.clone()),
        environment: app.and_then(|a| a.environment.clone()),
        feature_flags: app.and_then(|a| a.feature_flags.clone()),
        trigger: meta.and_then(|m| m.trigger.clone()),
        top_error_message: message,
        top_frame: frame,
        failing_requests: failing_requests_from(meta.map(|m| m.network_tail.as_slice()).unwrap_or(&[])),
        react_components: meta
            .and_then(|m| m.target.as_ref())
            .and_then(|t| t.react_components.clone())
            .filter(|r| !r.is_empty()),
    }
}

/// Network-tail entries that failed (ok===false OR status>=500), capped ~5.
pub fn failing_requests_from(tail: &[LensNetworkEntry]) -> Vec<LensFailingRequest> {
    tail.iter()
        .filter(|n| n.ok == Some(false) || n.status.is_some_and(|s| s >= 500))
        .take(5)
        .map(|n| LensFailingRequest { method: n.method.clone(), url: n.url.clone(), status: n.status })
        .collect()
}

/* ── Stack parsing ───────────────────────────────────────────────────────── */

/// Take the FIRST parseable frame of the FIRST error that has a stack. Returns the frame plus
/// the message of the error it came from. When no error has a parseable stack, `frame` is
/// None but `message` is still the first error's message.
pub fn top_frame_from_errors(errors: &[LensErrorEntry]) -> (Option<LensTopFrame>, Option<String>) {
    let mut first_message: Option<String> = None;
    for err in errors {
        if first_message.is_none() && !err.message.is_empty() {
            first_message = Some(err.message.clone());
        }
        let Some(stack) = err.stack.as_deref().filter(|s| !s.is_empty()) else { continue };
        if let Some(frame) = parse_stack_top_frame(stack) {
            let message = if err.message.is_empty() { first_message.clone() } else { Some(err.message.clone()) };
            return (Some(frame), message);
        }
    }
    (None, first_message)
}

/// Schemes / markers we never seed on.
fn is_skippable_location(location: &str) -> bool {
    if location.is_empty() || location.contains("node_modules") {
        return true;
    }
    let ext = Regex::new(r"(?i)^[a-z-]+-extension://").unwrap(); // chrome-extension://, moz-extension://, ...
    if ext.is_match(location) {
        return true;
    }
    location.contains("[native code]") || location.contains("<anonymous>")
}

/// Parse the top (first non-skippable) frame of a BROWSER error stack. Handles:
///   - V8 named:     `    at fn (https://host/path/file.js:LINE:COL)`
///   - V8 anonymous: `    at https://host/path/file.js:LINE:COL`
///   - Firefox/Safari: `fn@https://host/path/file.js:LINE:COL` (and `@https://...`)
/// The URL origin is stripped — the pathname becomes `filename`. Frames from node_modules,
/// extension schemes, and blank/native locations are skipped.
pub fn parse_stack_top_frame(stack: &str) -> Option<LensTopFrame> {
    let paren = Regex::new(r"^(.*?)\s*\((.+)\)\s*$").unwrap();
    for raw in stack.split('\n') {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let fn_name: Option<String>;
        let location: String;
        if let Some(body) = line.strip_prefix("at ") {
            // V8 format.
            let body = body.trim();
            if let Some(m) = paren.captures(body) {
                fn_name = Some(m[1].trim().to_string()).filter(|s| !s.is_empty());
                location = m[2].trim().to_string();
            } else {
                fn_name = None;
                location = body.to_string();
            }
        } else if let Some(at) = line.rfind('@') {
            // Firefox/Safari format `fn@location`.
            fn_name = Some(line[..at].trim().to_string()).filter(|s| !s.is_empty());
            location = line[at + 1..].trim().to_string();
        } else {
            continue;
        }

        if is_skippable_location(&location) {
            continue;
        }
        let Some((filename, lineno)) = parse_location(&location) else { continue };
        if is_skippable_location(&filename) {
            continue;
        }
        return Some(LensTopFrame { filename, function: fn_name, lineno });
    }
    None
}

/// Split a `<url>:LINE[:COL]` location into a pathname filename + line number. The URL may
/// itself contain colons, so the `:LINE[:COL]` suffix is peeled from the END. The origin is
/// dropped — `https://host/a/b.js` → `/a/b.js`.
fn parse_location(location: &str) -> Option<(String, Option<i64>)> {
    let re = Regex::new(r"^(.*?):(\d+)(?::(\d+))?$").unwrap();
    let (raw_url, lineno) = match re.captures(location) {
        Some(m) => (m[1].to_string(), m[2].parse::<i64>().ok()),
        None => (location.to_string(), None),
    };
    let scheme = Regex::new(r"(?i)^[a-z]+://").unwrap();
    let filename = if scheme.is_match(&raw_url) {
        // Only strip origin when there is a real scheme (http/https).
        url::Url::parse(&raw_url).map(|u| u.path().to_string()).unwrap_or_else(|_| raw_url.clone())
    } else {
        raw_url
    };
    if filename.is_empty() {
        return None;
    }
    Some((filename, lineno))
}

/* ── Evidence + relevance ────────────────────────────────────────────────── */

fn signal_to_evidence(sig: &LensReportSignal, hint_terms: &[String], query: &str, collected_at: &str, index: usize) -> Evidence {
    let frame = sig.top_frame.as_ref();
    let title = build_title(sig);
    let relevance = compute_relevance(sig, hint_terms, now_ms() as f64);

    let mut payload = Map::new();
    payload.insert("source".into(), json!("lens"));
    payload.insert("reportId".into(), json!(sig.id));
    if let Some(c) = &sig.comment {
        payload.insert("comment".into(), json!(redact_secrets(c)));
    }
    if let Some(v) = &sig.route {
        payload.insert("route".into(), json!(v));
    }
    if let Some(v) = &sig.url {
        payload.insert("url".into(), json!(v));
    }
    if let Some(v) = &sig.release {
        payload.insert("release".into(), json!(v));
    }
    if let Some(v) = &sig.git_sha {
        payload.insert("gitSha".into(), json!(v));
    }
    if let Some(v) = &sig.trigger {
        payload.insert("trigger".into(), json!(v));
    }
    payload.insert("errorCount".into(), json!(sig.error_count));
    if let Some(m) = &sig.top_error_message {
        payload.insert("topError".into(), json!(redact_secrets(m)));
    }
    if !sig.failing_requests.is_empty() {
        payload.insert("failingRequests".into(), json!(sig.failing_requests));
    }
    if let Some(v) = &sig.react_components {
        payload.insert("reactComponents".into(), json!(v));
    }
    if let Some(v) = &sig.feature_flags {
        payload.insert("featureFlags".into(), json!(v));
    }
    // Direct code seed: the engine reads filePath/symbolName/lineStart off the payload.
    if let Some(f) = frame {
        payload.insert("filePath".into(), json!(f.filename));
        if let Some(func) = &f.function {
            payload.insert("symbolName".into(), json!(func));
        }
        if let Some(l) = f.lineno {
            payload.insert("lineStart".into(), json!(l));
        }
    }

    let links = EvidenceLinks {
        file: frame.map(|f| f.filename.clone()),
        line: frame.and_then(|f| f.lineno),
        ..Default::default()
    };

    let ts = sig.submitted_at.clone().or_else(|| Some(sig.created_at.clone())).filter(|t| !t.is_empty());
    let mut payload = Value::Object(payload);
    normalize_js_numbers(&mut payload);
    Evidence {
        id: format!("ev_lens_{index}"),
        source: ProviderKind::Logs,
        kind: EvidenceKind::Log,
        title,
        timestamp: ts,
        relevance,
        payload,
        links,
        provenance: Provenance { query: query.to_string(), collected_at: collected_at.to_string() },
        priority: None,
        category: None,
        subject: None,
        is_new: None,
        ratio: None,
    }
}

/// Build the human one-line title:
///   `Lens report: "<comment ~80>" · <N> error(s) · <route|url> · <shortTs(createdAt)>`.
pub fn build_title(sig: &LensReportSignal) -> String {
    let raw_comment = sig.comment.as_deref().map(redact_secrets).unwrap_or_default();
    let comment = if raw_comment.is_empty() { "(no comment)".to_string() } else { slice_chars(&raw_comment, 80) };
    let errs = format!("{} error(s)", js_number_string(sig.error_count));
    let where_ = sig.route.clone().or_else(|| sig.url.clone()).unwrap_or_default();
    let where_str = if where_.is_empty() { String::new() } else { format!(" · {where_}") };
    let when = if sig.created_at.is_empty() { String::new() } else { format!(" · {}", short_ts(&sig.created_at)) };
    slice_chars(&format!("Lens report: \"{comment}\" · {errs}{where_str}{when}"), 220)
}

/// Relevance-weight a report by hint-term match, recency, and recurrence. Range ~0.5–0.95.
pub fn compute_relevance(sig: &LensReportSignal, hint_terms: &[String], now: f64) -> f64 {
    let mut score: f64 = 0.6;
    let hay = [
        sig.comment.as_deref().unwrap_or(""),
        sig.route.as_deref().unwrap_or(""),
        sig.url.as_deref().unwrap_or(""),
        sig.top_error_message.as_deref().unwrap_or(""),
        sig.top_frame.as_ref().map(|f| f.filename.as_str()).unwrap_or(""),
        sig.top_frame.as_ref().and_then(|f| f.function.as_deref()).unwrap_or(""),
    ]
    .join(" ")
    .to_lowercase();
    if hint_terms.iter().filter(|t| t.len() > 2).any(|t| hay.contains(&t.to_lowercase())) {
        score += 0.2;
    }
    let ts = sig.submitted_at.as_deref().unwrap_or(&sig.created_at);
    if !ts.is_empty() {
        if let Some(t) = parse_js_date_ms(ts).map(|t| t as f64) {
            let age_ms = now - t;
            if age_ms <= 86_400_000.0 {
                score += 0.1;
            } else if age_ms <= 7.0 * 86_400_000.0 {
                score += 0.05;
            }
        }
    }
    if sig.issue_occurrence_count.unwrap_or(0) >= 3 {
        score += 0.05;
    }
    score.clamp(0.5, 0.95)
}

/// Preliminary client-side ranking used to pick which reports to fully fetch.
fn rank_summaries(mut summaries: Vec<LensReportSummary>, hint_terms: &[String], now: f64) -> Vec<LensReportSummary> {
    let domain_terms: Vec<String> = hint_terms.iter().filter(|t| t.len() > 2).map(|t| t.to_lowercase()).collect();
    let score = |s: &LensReportSummary| -> f64 {
        let mut v = 0.0;
        let hay = format!("{} {}", s.comment.as_deref().unwrap_or(""), s.url.as_deref().unwrap_or("")).to_lowercase();
        if domain_terms.iter().any(|t| hay.contains(t)) {
            v += 2.0;
        }
        if !s.created_at.is_empty() {
            if let Some(t) = parse_js_date_ms(&s.created_at).map(|t| t as f64) {
                if now - t <= 86_400_000.0 {
                    v += 1.0;
                }
            }
        }
        if s.issue_occurrence_count.unwrap_or(0) >= 3 {
            v += 0.5;
        }
        v
    };
    summaries.sort_by(|a, b| {
        let d = score(b) - score(a);
        if d != 0.0 {
            return d.partial_cmp(&0.0).unwrap_or(std::cmp::Ordering::Equal);
        }
        // Stable-ish tiebreak: newest first.
        let (ta, tb) = (parse_js_date_ms(&a.created_at).map(|t| t as f64).unwrap_or(0.0), parse_js_date_ms(&b.created_at).map(|t| t as f64).unwrap_or(0.0));
        tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
    });
    summaries
}

/// Inclusive createdAt window check; an unparseable bound is treated as unbounded.
pub fn in_window(created_at: &str, from: Option<&str>, to: Option<&str>) -> bool {
    let Some(t) = parse_js_date_ms(created_at) else { return true }; // never drop a report over a malformed timestamp
    if let Some(lo) = from.and_then(parse_js_date_ms) {
        if t < lo {
            return false;
        }
    }
    if let Some(hi) = to.and_then(parse_js_date_ms) {
        if t > hi {
            return false;
        }
    }
    true
}
