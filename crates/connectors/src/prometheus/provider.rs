//! Direct Prometheus metrics provider — same normalization and anomaly analysis as Grafana.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use horus_core::{redact_error_message, validate_prometheus, Evidence, HealthStatus, Issues, PrometheusConfig, ProviderKind};
use serde_json::Value;
use tokio::time::Instant;

use crate::contract::Provider;
use crate::grafana::analyze::{build_findings, findings_to_evidence, Anomaly, MetricFinding};
use crate::grafana::panels::{classify_panel, find_match_source, finding_labels_match_hint, panel_matches_hint, MatchSource, Panel};
use crate::grafana::provider::{AnalyzeOptions, MetricsProvider};
use crate::grafana::series::{parse_range, parse_range_bytes, MetricSeries};
use crate::http::{fetch_with_retry, HttpRequestOptions};
use crate::jsutil::{issues_to_error, js_number_string, now_iso, now_ms};

pub struct PrometheusMetricsProvider {
    pub config: PrometheusConfig,
    client: reqwest::Client,
}

impl PrometheusMetricsProvider {
    pub fn new(config: PrometheusConfig) -> Result<Self> {
        let mut issues = Issues::default();
        validate_prometheus(&mut issues, &config);
        issues_to_error(&issues)?;
        Ok(Self { config, client: reqwest::Client::new() })
    }

    fn panels(&self) -> Vec<Panel> {
        self.config
            .queries
            .iter()
            .enumerate()
            .map(|(i, q)| Panel {
                id: i as f64,
                title: q.title.clone(),
                exprs: vec![q.expr.clone()],
                kind: classify_panel(&q.title, "", std::slice::from_ref(&q.expr)),
                type_: "timeseries".into(),
                unit: String::new(),
                datasource_uid: "prometheus".into(),
                dashboard_uid: Some("prometheus".into()),
            })
            .collect()
    }

    async fn query(&self, expr: &str, from: f64, to: f64, step: Option<f64>, deadline: Option<Instant>) -> Result<Vec<MetricSeries>> {
        let step = step.unwrap_or(60.0);
        if ![from, to, step].iter().all(|n| n.is_finite()) || from > to || step <= 0.0 {
            return Err(anyhow!("Invalid metric time window"));
        }
        let qs = crate::jsutil::url_search_params(&[
            ("query", expr),
            ("start", &js_number_string(from)),
            ("end", &js_number_string(to)),
            ("step", &js_number_string(step.max(((to - from) / 1000.0).ceil()))),
            ("timeout", "15s"),
            ("limit", "200"),
        ]);
        let url = format!("{}/api/v1/query_range?{qs}", self.config.url.trim_end_matches('/'));
        let mut req = self.client.get(&url);
        if let Some(token) = &self.config.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let opts = HttpRequestOptions::with_timeout_ms(20_000);
        let fut = fetch_with_retry(req, &opts);
        let response = match deadline {
            Some(d) => tokio::time::timeout_at(d, fut).await.map_err(|_| anyhow!("metrics timeout"))?,
            None => fut.await,
        }
        .map_err(|e| anyhow!("{}", redact_error_message(&e)))?;
        if !response.status().is_success() {
            return Err(anyhow!("Prometheus HTTP {}", response.status().as_u16()));
        }
        // Typed, streaming sample decode (see `parse_range_bytes`); an unexpected shape falls
        // back to the full `Value` parse so the result is unchanged.
        let body = response.bytes().await?;
        match parse_range_bytes(&body) {
            Some((status, _, series)) => {
                if status.as_ref().and_then(Value::as_str) != Some("success") {
                    return Err(anyhow!("Prometheus query failed"));
                }
                Ok(series)
            }
            None => {
                let data: Value = serde_json::from_slice(&body)?;
                if data.get("status").and_then(Value::as_str) != Some("success") {
                    return Err(anyhow!("Prometheus query failed"));
                }
                Ok(parse_range(&data))
            }
        }
    }
}

#[async_trait]
impl Provider for PrometheusMetricsProvider {
    fn id(&self) -> &str {
        "prometheus"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Metrics
    }
    async fn health(&self) -> HealthStatus {
        let now = now_ms() as f64 / 1000.0;
        match self.query("up", now - 60.0, now_ms() as f64 / 1000.0, None, None).await {
            Ok(_) => HealthStatus { ok: true, detail: "Prometheus query access verified".into() },
            Err(e) => HealthStatus { ok: false, detail: redact_error_message(&e) },
        }
    }
}

#[async_trait]
impl MetricsProvider for PrometheusMetricsProvider {
    async fn find_panels(&self, hint: Option<&str>) -> Result<Vec<Panel>> {
        Ok(self.panels().into_iter().filter(|p| hint.is_none_or(|h| h.is_empty() || panel_matches_hint(p, h))).collect())
    }

    async fn analyze(&self, opts: &AnalyzeOptions) -> Result<Vec<MetricFinding>> {
        let hint = opts.hint.as_deref().filter(|h| !h.is_empty());
        let panels = self.find_panels(hint).await?;
        let label_fallback = panels.is_empty() && hint.is_some();
        let panels = if label_fallback { self.find_panels(None).await? } else { panels };
        let mut findings = Vec::new();
        for p in &panels {
            let expr = &p.exprs[0];
            let (current, baseline) = futures::future::try_join(
                self.query(expr, opts.from, opts.to, opts.step, opts.deadline),
                self.query(expr, opts.from - (opts.to - opts.from), opts.from, opts.step, opts.deadline),
            )
            .await?;
            let matched = build_findings("prometheus", &p.title, p.kind, &baseline, &current);
            if label_fallback {
                let h = hint.unwrap_or("");
                findings.extend(matched.into_iter().filter(|f| finding_labels_match_hint(&f.labels, h)).map(|mut f| {
                    f.match_source = Some(Some(MatchSource::SeriesLabels));
                    f
                }));
            } else {
                findings.extend(matched.into_iter().map(|mut f| {
                    f.match_source = Some(hint.and_then(|h| find_match_source(p, h)));
                    f
                }));
            }
        }
        Ok(findings)
    }

    async fn raw_range(&self, expr: &str, from: f64, to: f64, step: Option<f64>) -> Result<Vec<MetricSeries>> {
        self.query(expr, from, to, step, None).await
    }

    fn to_evidence(&self, findings: &[MetricFinding]) -> Vec<Evidence> {
        let anomalous: Vec<MetricFinding> = findings.iter().filter(|f| f.anomaly != Anomaly::None).cloned().collect();
        findings_to_evidence(&anomalous, "prometheus.analyze", &now_iso())
    }
}
