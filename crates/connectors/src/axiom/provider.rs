//! Axiom logs-evidence provider (HOR-429): one `kind: 'log'` Evidence per APL row.

use anyhow::Result;
use async_trait::async_trait;
use horus_core::{redact_secrets, Evidence, EvidenceKind, EvidenceLinks, HealthStatus, Provenance, ProviderKind};
use serde_json::{Map, Value};

use super::client::{build_apl, build_error_signature_apl, build_recent_errors_apl, AxiomClient, AxiomLogRecord};
use crate::contract::Provider;
use crate::duration::{durations_by_dimension, DurationByDimension, DurationDimensionOptions, DurationLogLike};
use crate::jsutil::{js_number_string, iso_from_ms, normalize_js_numbers, now_iso, now_ms, parse_js_date_ms, short_ts, slice_chars, to_locale_string_en_us};
pub use crate::sentry::provider::CollectOptions;

#[derive(Debug, Clone, Default)]
pub struct AxiomProviderOpts {
    /// Dataset to query (also used for evidence provenance + APL building).
    pub dataset: String,
    /// How many recent rows to fold in (capped 1–1000).
    pub limit: Option<f64>,
    /// Default lookback window in milliseconds when no explicit from/to is given.
    pub window_ms: Option<f64>,
}

/// Default lookback: 24h.
const DEFAULT_WINDOW_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

pub struct AxiomProvider {
    client: AxiomClient,
    opts: AxiomProviderOpts,
}

impl AxiomProvider {
    pub fn new(client: AxiomClient, opts: AxiomProviderOpts) -> Self {
        Self { client, opts }
    }

    fn window(&self, from: Option<&str>, to: Option<&str>) -> (String, String) {
        let to = to.map(str::to_string).unwrap_or_else(now_iso);
        let from = from
            .map(str::to_string)
            .unwrap_or_else(|| {
                // `Date.parse` NaN → `new Date(NaN).toISOString()` throws in TS; here it yields "".
                parse_js_date_ms(&to).map(|t| iso_from_ms(t - self.opts.window_ms.unwrap_or(DEFAULT_WINDOW_MS) as i64)).unwrap_or_default()
            });
        (from, to)
    }

    /// Collect log rows over the window, INCIDENT-AWARE: top error signatures + a few
    /// recent raw errors (in parallel); broadens to all levels when neither matches.
    /// A failing query errors so the engine records an evidence gap.
    pub async fn collect(&self, opts: &CollectOptions) -> Result<Vec<AxiomLogRecord>> {
        let (from, to) = self.window(opts.from.as_deref(), opts.to.as_deref());
        let hint_terms = opts.hint_terms.clone().unwrap_or_default();
        let limit = self.opts.limit.unwrap_or(100.0);
        let top_n = limit.min(10.0).max(1.0);
        let recent_n = limit.min(5.0).max(1.0);
        let (signatures, recent) = futures::future::try_join(
            self.client.query(&build_error_signature_apl(&self.opts.dataset, &hint_terms, Some(top_n)), &from, &to),
            self.client.query(&build_recent_errors_apl(&self.opts.dataset, &hint_terms, Some(recent_n)), &from, &to),
        )
        .await?;
        if signatures.is_empty() && recent.is_empty() {
            // No error-level rows matched — broaden to all levels (sensible fallback).
            return self.client.query(&build_apl(&self.opts.dataset, &hint_terms, Some(limit)), &from, &to).await;
        }
        // Signatures first (highest-volume errors lead), then recent raw examples for grounding.
        Ok(signatures.into_iter().chain(recent).collect())
    }

    /// One `kind: 'log'` Evidence per row.
    pub fn to_evidence(&self, records: &[AxiomLogRecord], hint_terms: &[String], collected_at: &str) -> Vec<Evidence> {
        let query = format!("axiom {}", self.opts.dataset);
        records.iter().enumerate().map(|(i, rec)| self.record_to_evidence(rec, hint_terms, &query, collected_at, i)).collect()
    }

    /// One-shot evidence query; degrades to [] on any failure.
    pub async fn query_evidence(&self, opts: &CollectOptions) -> Vec<Evidence> {
        let hint_terms = opts.hint_terms.clone().unwrap_or_default();
        match self.collect(opts).await {
            Ok(records) => self.to_evidence(&records, &hint_terms, &opts.collected_at.clone().unwrap_or_else(now_iso)),
            Err(_) => Vec::new(),
        }
    }

    /// INFO-level duration coverage (HOR-434). Graceful: `None`, never errors.
    pub async fn analyze_durations(&self, opts: &DurationDimensionOptions) -> Option<DurationByDimension> {
        let (from, to) = self.window(opts.from.as_deref(), opts.to.as_deref());
        // A broad all-levels scan biased to the completion text (these lines are INFO).
        let terms: Vec<String> = opts.completion_text.iter().cloned().collect();
        let apl = build_apl(&self.opts.dataset, &terms, Some(opts.limit.unwrap_or(500) as f64));
        let rows = self.client.query(&apl, &from, &to).await.ok()?;
        let normalized: Vec<DurationLogLike> = rows
            .into_iter()
            .map(|rec| DurationLogLike { message: Some(pick_field(&rec.fields, &MESSAGE_FIELDS).unwrap_or_default()), fields: rec.fields })
            .collect();
        durations_by_dimension(&normalized, opts)
    }

    fn record_to_evidence(&self, rec: &AxiomLogRecord, hint_terms: &[String], query: &str, collected_at: &str, index: usize) -> Evidence {
        let title = build_title(rec, &self.opts.dataset);
        let relevance = compute_relevance(rec, hint_terms, None);
        let mut payload = Map::new();
        payload.insert("source".into(), "axiom".into());
        payload.insert("dataset".into(), self.opts.dataset.clone().into());
        for (k, v) in &rec.fields {
            payload.insert(k.clone(), v.clone());
        }
        let mut payload = Value::Object(payload);
        normalize_js_numbers(&mut payload);
        Evidence {
            id: format!("ev_axiom_{index}"),
            source: ProviderKind::Logs,
            kind: EvidenceKind::Log,
            title,
            timestamp: rec.timestamp.clone(),
            relevance,
            payload,
            links: EvidenceLinks::default(),
            provenance: Provenance { query: query.to_string(), collected_at: collected_at.to_string() },
            priority: None,
            category: None,
            subject: None,
            is_new: None,
            ratio: None,
        }
    }
}

#[async_trait]
impl Provider for AxiomProvider {
    fn id(&self) -> &str {
        "axiom"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Logs
    }
    async fn health(&self) -> HealthStatus {
        self.client.health().await
    }
}

/// Common field names that hold the log message body, in priority order.
const MESSAGE_FIELDS: [&str; 6] = ["message", "msg", "body", "event", "log", "_raw"];
/// Common field names that hold the log level/severity, in priority order.
const LEVEL_FIELDS: [&str; 5] = ["level", "severity", "lvl", "loglevel", "status"];

/// Pick the first present, non-empty string-ish value among `candidates`.
fn pick_field(fields: &Map<String, Value>, candidates: &[&str]) -> Option<String> {
    for key in candidates {
        match fields.get(*key) {
            Some(Value::String(s)) if !s.is_empty() => return Some(s.clone()),
            Some(Value::Number(n)) => return Some(js_number_string(n.as_f64().unwrap_or(0.0))),
            _ => {}
        }
    }
    None
}

/// Human one-line title: dataset, level, redacted message, and short timestamp. Aggregated
/// signature rows carry a `count` folded into the title ("… ×3,302 (latest 06-22 17:16)").
pub fn build_title(rec: &AxiomLogRecord, dataset: &str) -> String {
    let msg = pick_field(&rec.fields, &MESSAGE_FIELDS);
    let level = pick_field(&rec.fields, &LEVEL_FIELDS);
    let lvl = level.filter(|l| !l.is_empty()).map(|l| format!("[{l}] ")).unwrap_or_default();
    let body = msg.filter(|m| !m.is_empty()).map(|m| redact_secrets(&m)).unwrap_or_else(|| "(log event)".into());
    let ts_of = |r: &AxiomLogRecord| r.timestamp.as_deref().filter(|t| !t.is_empty()).map(short_ts);
    let count = rec.fields.get("count").and_then(Value::as_f64).filter(|c| c.is_finite() && *c > 1.0);
    if let Some(count) = count {
        let latest = ts_of(rec).map(|t| format!(" (latest {t})")).unwrap_or_default();
        return slice_chars(&format!("Axiom {dataset}: {lvl}{body} ×{}{latest}", to_locale_string_en_us(count)), 220);
    }
    let ts = ts_of(rec).map(|t| format!(" · {t}")).unwrap_or_default();
    slice_chars(&format!("Axiom {dataset}: {lvl}{body}{ts}"), 220)
}

/// Relevance-weight a row by hint-term match (over all fields), recency, level and volume.
pub fn compute_relevance(rec: &AxiomLogRecord, hint_terms: &[String], now: Option<f64>) -> f64 {
    let now = now.unwrap_or_else(|| now_ms() as f64);
    let mut score: f64 = 0.6;
    let hay = serde_json::to_string(&rec.fields).unwrap_or_default().to_lowercase();
    if hint_terms.iter().filter(|t| t.len() > 2).any(|t| hay.contains(&t.to_lowercase())) {
        score += 0.2;
    }
    if let Some(ts) = rec.timestamp.as_deref().filter(|t| !t.is_empty()) {
        if let Some(seen) = parse_js_date_ms(ts).map(|t| t as f64) {
            let age_ms = now - seen;
            if age_ms <= 86_400_000.0 {
                score += 0.1;
            } else if age_ms <= 7.0 * 86_400_000.0 {
                score += 0.05;
            }
        }
    }
    let level = pick_field(&rec.fields, &LEVEL_FIELDS).unwrap_or_default().to_lowercase();
    if level == "error" || level == "fatal" || level == "critical" {
        score += 0.1;
    } else if level == "warn" || level == "warning" {
        score += 0.05;
    }
    if rec.fields.get("count").and_then(Value::as_f64).is_some_and(|c| c >= 10.0) {
        score += 0.1;
    }
    score.min(0.95).max(0.5)
}
