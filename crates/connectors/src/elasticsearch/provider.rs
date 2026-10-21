//! Elasticsearch logs provider (HOR-10). Collection + normalization only — no AI logic.

use anyhow::Result;
use async_trait::async_trait;
use horus_core::{Evidence, HealthStatus, ProviderKind};
use serde_json::Value;

use super::analyze::{
    analysis_to_evidence, annotate_against_baseline, build_error_analysis_body, parse_error_analysis, redact_sensitive_string,
    AnalysisWindow, LogAnalysis,
};
use super::client::ElasticsearchClient;
use super::compat::{validate_mapping_against_caps, CompatibilityOptions, CompatibilityReport};
use super::normalize::{
    agg_to_error_buckets, build_error_agg_body, build_search_body, compute_error_deltas, hits_to_records, logs_to_evidence,
    validate_field_mapping, ElasticsearchFieldMapping, ErrorBucket, ErrorDelta, LogLevel, LogQuery, LogRecord, MERITT_FIELD_MAPPING,
};
use crate::contract::Provider;
use crate::duration::{durations_by_dimension, DurationByDimension, DurationDimensionOptions, DurationLogLike};
use crate::jsutil::{iso_from_ms, now_iso, now_ms, parse_js_date_ms};

#[async_trait]
pub trait LogsProvider: Provider {
    async fn search_logs(&self, q: &LogQuery) -> Result<Vec<LogRecord>>;
    /// Aggregate error counts by signature field. Defaults to the provider's
    /// configured event_code_field when field is omitted.
    async fn aggregate_errors(&self, q: &LogQuery, field: Option<&str>) -> Result<Vec<ErrorBucket>>;
    async fn error_deltas(&self, baseline: &LogQuery, current: &LogQuery, field: Option<&str>) -> Result<Vec<ErrorDelta>>;
    /// Synthesize error EVIDENCE (not raw logs) with NEW/spike flags against the preceding window.
    async fn analyze_errors(&self, q: &LogQuery, field: Option<&str>) -> Result<LogAnalysis>;
    /// INFO-level duration coverage (HOR-434). Graceful: `None`, never errors.
    async fn analyze_durations(&self, opts: &DurationDimensionOptions) -> Option<DurationByDimension>;
    /// Check that the configured field mapping is compatible with the actual index.
    async fn check_compatibility(&self, opts: Option<CompatibilityOptions>) -> Result<CompatibilityReport>;
    fn to_evidence(&self, records: &[LogRecord]) -> Vec<Evidence>;
    /// Bounded evidence query: analyze_errors → Evidence[], redacted, degrades to [] on failure (HOR-91).
    async fn query_evidence(&self, q: &LogQuery, collected_at: Option<&str>) -> Vec<Evidence>;
}

#[derive(Debug, Clone)]
pub struct ElasticsearchLogsProviderOpts {
    pub index_pattern: String,
    /// Field mapping config. Defaults to MERITT_FIELD_MAPPING when omitted.
    pub field_mapping: Option<ElasticsearchFieldMapping>,
}

pub struct ElasticsearchLogsProvider {
    client: ElasticsearchClient,
    index_pattern: String,
    mapping: ElasticsearchFieldMapping,
}

impl ElasticsearchLogsProvider {
    pub fn new(client: ElasticsearchClient, opts: ElasticsearchLogsProviderOpts) -> Result<Self> {
        let mapping = opts.field_mapping.unwrap_or_else(|| MERITT_FIELD_MAPPING.clone());
        validate_field_mapping(&mapping)?;
        Ok(Self { client, index_pattern: opts.index_pattern, mapping })
    }

    pub fn mapping(&self) -> &ElasticsearchFieldMapping {
        &self.mapping
    }

    pub fn client(&self) -> &ElasticsearchClient {
        &self.client
    }

    fn resolve_index<'a>(&'a self, q: &'a LogQuery) -> &'a str {
        q.index.as_deref().unwrap_or(&self.index_pattern)
    }
}

#[async_trait]
impl Provider for ElasticsearchLogsProvider {
    fn id(&self) -> &str {
        "elasticsearch"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Logs
    }
    async fn health(&self) -> HealthStatus {
        self.client.health().await
    }
}

#[async_trait]
impl LogsProvider for ElasticsearchLogsProvider {
    async fn search_logs(&self, q: &LogQuery) -> Result<Vec<LogRecord>> {
        let res = self.client.search(self.resolve_index(q), &build_search_body(q, &self.mapping)).await?;
        Ok(hits_to_records(&res, &self.mapping))
    }

    async fn aggregate_errors(&self, q: &LogQuery, field: Option<&str>) -> Result<Vec<ErrorBucket>> {
        let sig_field = field.unwrap_or(&self.mapping.event_code_field);
        let res = self.client.search(self.resolve_index(q), &build_error_agg_body(q, sig_field, &self.mapping)).await?;
        Ok(agg_to_error_buckets(&res))
    }

    async fn error_deltas(&self, baseline: &LogQuery, current: &LogQuery, field: Option<&str>) -> Result<Vec<ErrorDelta>> {
        let (b, c) = futures::future::try_join(self.aggregate_errors(baseline, field), self.aggregate_errors(current, field)).await?;
        Ok(compute_error_deltas(&b, &c))
    }

    async fn analyze_errors(&self, q: &LogQuery, field: Option<&str>) -> Result<LogAnalysis> {
        let sig_field = field.unwrap_or(&self.mapping.event_code_field);
        // Default to a 24h window when none is given.
        let to = q.to.clone().unwrap_or_else(now_iso);
        let from = q.from.clone().unwrap_or_else(|| iso_from_ms(now_ms() - 86_400_000));

        let current = LogQuery { from: Some(from.clone()), to: Some(to.clone()), ..q.clone() };
        let cur_res = self.client.search(self.resolve_index(q), &build_error_analysis_body(&current, sig_field, &self.mapping)).await?;
        let mut analysis = parse_error_analysis(
            &cur_res,
            AnalysisWindow { from: Some(from.clone()), to: Some(to.clone()) },
            &self.mapping.message_field,
            Some(&self.mapping.level_field),
        );

        // Baseline = the immediately preceding window of equal length, so we can flag
        // NEW signatures and spikes. Best-effort: skip if the window can't be parsed.
        if let (Some(from_ms), Some(to_ms)) = (parse_js_date_ms(&from), parse_js_date_ms(&to)) {
            if to_ms > from_ms {
                let span = to_ms - from_ms;
                let baseline_q = LogQuery { from: Some(iso_from_ms(from_ms - span)), to: Some(from.clone()), ..q.clone() };
                let base_res = self.client.search(self.resolve_index(q), &build_error_analysis_body(&baseline_q, sig_field, &self.mapping)).await?;
                let baseline = parse_error_analysis(&base_res, AnalysisWindow::default(), &self.mapping.message_field, None);
                annotate_against_baseline(&mut analysis, &baseline.signatures);
            }
        }
        Ok(analysis)
    }

    async fn analyze_durations(&self, opts: &DurationDimensionOptions) -> Option<DurationByDimension> {
        // Query NON-error completion logs. Level defaults to 'info' (≥ info floor),
        // scoped to the completion text via a broad text match.
        let level = match opts.level.as_deref() {
            Some(l) => serde_json::from_value::<LogLevel>(Value::String(l.to_string())).ok()?,
            None => LogLevel::Info,
        };
        let q = LogQuery {
            level: Some(level),
            limit: Some(opts.limit.unwrap_or(500)),
            service: opts.service.clone(),
            from: opts.from.clone(),
            to: opts.to.clone(),
            text: opts.completion_text.clone(),
            broad_text: opts.completion_text.as_ref().map(|_| true),
            ..Default::default()
        };
        let records = self.search_logs(&q).await.ok()?;
        let normalized: Vec<DurationLogLike> = records
            .into_iter()
            .map(|r| {
                let mut fields = r.raw.clone();
                if let Some(c) = &r.context {
                    fields.insert("context".into(), Value::Object(c.clone()));
                }
                if let Some(ec) = &r.event_code {
                    fields.insert("event_code".into(), Value::String(ec.clone()));
                }
                if let Some(s) = &r.service {
                    fields.insert("service_name".into(), Value::String(s.clone()));
                }
                if let Some(d) = &r.detail {
                    fields.insert("detail".into(), Value::String(d.clone()));
                }
                fields.insert("message".into(), Value::String(r.message.clone()));
                DurationLogLike { message: Some(r.message), fields }
            })
            .collect();
        durations_by_dimension(&normalized, opts)
    }

    async fn check_compatibility(&self, opts: Option<CompatibilityOptions>) -> Result<CompatibilityReport> {
        let m = &self.mapping;
        let mut fields = vec![
            m.timestamp_field.clone(),
            m.level_field.clone(),
            m.service_field.clone(),
            format!("{}.keyword", m.service_field),
            m.event_code_field.clone(),
            format!("{}.keyword", m.event_code_field),
        ];
        fields.extend(m.trace_id_field.iter().cloned());
        fields.extend(m.request_id_field.iter().cloned());
        let caps = self.client.field_caps(&self.index_pattern, &fields).await?;
        Ok(validate_mapping_against_caps(m, &caps, opts.unwrap_or_default()))
    }

    fn to_evidence(&self, records: &[LogRecord]) -> Vec<Evidence> {
        logs_to_evidence(records, "searchLogs", &now_iso())
    }

    async fn query_evidence(&self, q: &LogQuery, collected_at: Option<&str>) -> Vec<Evidence> {
        let Ok(analysis) = self.analyze_errors(q, None).await else { return Vec::new() };
        let at = collected_at.map(str::to_string).unwrap_or_else(now_iso);
        let parts: Vec<&str> = [q.service.as_deref(), q.from.as_deref()].into_iter().flatten().filter(|s| !s.is_empty()).collect();
        let label = if parts.is_empty() { "investigate".to_string() } else { parts.join(" from ") };
        analysis_to_evidence(&analysis, &label, &at)
            .into_iter()
            .map(|mut ev| {
                // Only ErrorSignature payloads have a 'key' field — apply redaction to those.
                if let Some(p) = ev.payload.as_object_mut().filter(|p| p.get("key").is_some_and(Value::is_string)) {
                    if let Some(Value::String(m)) = p.get("sampleMessage").cloned() {
                        p.insert("sampleMessage".into(), Value::String(redact_sensitive_string(&m)));
                    }
                }
                ev
            })
            .collect()
    }
}
