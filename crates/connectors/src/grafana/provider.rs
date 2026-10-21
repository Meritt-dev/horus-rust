//! Grafana metrics provider (HOR-11 reframe). Entry point: Grafana. Prometheus
//! queries execute through the Grafana datasource proxy.

use anyhow::Result;
use async_trait::async_trait;
use horus_core::{Evidence, HealthStatus, ProviderKind};
use tokio::time::Instant;

use super::analyze::{build_findings, findings_to_evidence, Anomaly, MetricFinding};
use super::client::{DashboardRef, GrafanaClient};
use super::panels::{extract_panels, find_match_source, finding_labels_match_hint, panel_matches_hint, sanitize_expr, MatchSource, Panel};
use super::series::MetricSeries;
use crate::contract::Provider;
use crate::jsutil::now_iso;

/// Inputs for `MetricsProvider::analyze`. `deadline` replaces the TS `AbortSignal`
/// (the engine's metrics budget): per-panel fan-out stops at the deadline and the
/// findings gathered so far are returned (HOR-339 partial metrics).
#[derive(Debug, Clone, Default)]
pub struct AnalyzeOptions {
    pub hint: Option<String>,
    pub from: f64,
    pub to: f64,
    pub step: Option<f64>,
    pub deadline: Option<Instant>,
}

#[async_trait]
pub trait MetricsProvider: Provider {
    async fn find_panels(&self, hint: Option<&str>) -> Result<Vec<Panel>>;
    async fn analyze(&self, opts: &AnalyzeOptions) -> Result<Vec<MetricFinding>>;
    async fn raw_range(&self, expr: &str, from: f64, to: f64, step: Option<f64>) -> Result<Vec<MetricSeries>>;
    fn to_evidence(&self, findings: &[MetricFinding]) -> Vec<Evidence>;
}

#[derive(Debug, Clone)]
pub struct GrafanaMetricsProviderOpts {
    pub default_step: f64,
    pub dashboard_uids: Option<Vec<String>>,
}

pub struct GrafanaMetricsProvider {
    client: GrafanaClient,
    opts: GrafanaMetricsProviderOpts,
}

/// Run `fut` but give up at `deadline` (None = no budget).
async fn until<T>(deadline: Option<Instant>, fut: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    match deadline {
        Some(d) => tokio::time::timeout_at(d, fut).await.map_err(|_| anyhow::anyhow!("metrics timeout"))?,
        None => fut.await,
    }
}

fn past(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

impl GrafanaMetricsProvider {
    pub fn new(client: GrafanaClient, opts: GrafanaMetricsProviderOpts) -> Self {
        Self { client, opts }
    }

    async fn find_panels_until(&self, hint: Option<&str>, deadline: Option<Instant>) -> Result<Vec<Panel>> {
        // When specific dashboard UIDs are configured, fetch only those; else search all.
        let dashboards: Vec<DashboardRef> = match &self.opts.dashboard_uids {
            Some(uids) if !uids.is_empty() => uids.iter().map(|uid| DashboardRef { uid: uid.clone(), title: uid.clone(), folder_title: None }).collect(),
            _ => until(deadline, self.client.search_dashboards(None)).await?,
        };
        let mut all_panels = Vec::new();
        for dash in dashboards {
            if past(deadline) {
                anyhow::bail!("metrics timeout");
            }
            // Skip genuinely failed dashboard fetches; a budget timeout must propagate.
            let dashboard_obj = match until(deadline, self.client.get_dashboard(&dash.uid)).await {
                Ok(d) => d,
                Err(e) if past(deadline) => return Err(e),
                Err(_) => continue,
            };
            for mut panel in extract_panels(&dashboard_obj) {
                panel.dashboard_uid = Some(dash.uid.clone());
                if let Some(h) = hint {
                    if !panel_matches_hint(&panel, h) {
                        continue;
                    }
                }
                all_panels.push(panel);
            }
        }
        Ok(all_panels)
    }

    async fn query_panels(&self, panels: &[Panel], opts: &AnalyzeOptions, step: f64, window_secs: f64) -> Vec<MetricFinding> {
        let deadline = opts.deadline;
        let hint = opts.hint.as_deref().filter(|h| !h.is_empty());
        let mut results: Vec<MetricFinding> = Vec::new();
        for panel in panels {
            // HOR-339: on timeout, return the metrics gathered so far instead of discarding them.
            if past(deadline) {
                return results;
            }
            let panel_match_src: Option<MatchSource> = hint.and_then(|h| find_match_source(panel, h));
            for raw_expr in &panel.exprs {
                if past(deadline) {
                    return results;
                }
                let Some(expr) = sanitize_expr(raw_expr) else { continue };
                let pair = futures::future::try_join(
                    until(deadline, self.client.datasource_range_series(&panel.datasource_uid, &expr, opts.from, opts.to, step)),
                    until(deadline, self.client.datasource_range_series(&panel.datasource_uid, &expr, opts.from - window_secs, opts.from, step)),
                );
                match pair.await {
                    Ok((current, baseline)) => {
                        let findings = build_findings(panel.dashboard_uid.as_deref().unwrap_or(""), &panel.title, panel.kind, &baseline, &current)
                            .into_iter()
                            .map(|mut f| {
                                f.match_source = Some(panel_match_src);
                                f
                            });
                        results.extend(findings);
                    }
                    Err(_) => {
                        if past(deadline) {
                            return results; // HOR-339: keep partial metrics on timeout
                        }
                        continue;
                    }
                }
            }
        }
        results
    }
}

#[async_trait]
impl Provider for GrafanaMetricsProvider {
    fn id(&self) -> &str {
        "grafana"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Metrics
    }
    async fn health(&self) -> HealthStatus {
        self.client.health().await
    }
}

#[async_trait]
impl MetricsProvider for GrafanaMetricsProvider {
    /// Search all dashboards and return the leaf panels. The `hint` filters PANELS (by
    /// title/expr), not the dashboard search. Each panel is tagged with its dashboard uid.
    async fn find_panels(&self, hint: Option<&str>) -> Result<Vec<Panel>> {
        self.find_panels_until(hint, None).await
    }

    /// Two-pass hint matching: (1) panels by title / PromQL; (2) if none match, query ALL
    /// panels and filter the returned series by their label values.
    async fn analyze(&self, opts: &AnalyzeOptions) -> Result<Vec<MetricFinding>> {
        let step = opts.step.unwrap_or(self.opts.default_step);
        let window_secs = opts.to - opts.from;
        let hint = opts.hint.as_deref();

        let matched_panels = self.find_panels_until(hint, opts.deadline).await?;
        if !matched_panels.is_empty() || hint.is_none_or(|h| h.is_empty()) {
            return Ok(self.query_panels(&matched_panels, opts, step, window_secs).await);
        }
        let hint = hint.unwrap_or("");
        let all_panels = self.find_panels_until(None, opts.deadline).await?;
        let all_findings = self.query_panels(&all_panels, opts, step, window_secs).await;
        Ok(all_findings
            .into_iter()
            .filter(|f| finding_labels_match_hint(&f.labels, hint))
            .map(|mut f| {
                f.match_source = Some(Some(MatchSource::SeriesLabels));
                f
            })
            .collect())
    }

    /// Raw escape hatch: a single PromQL expression against the default Prometheus
    /// datasource (uid "Prometheus") or the first panel datasource found.
    async fn raw_range(&self, expr: &str, from: f64, to: f64, step: Option<f64>) -> Result<Vec<MetricSeries>> {
        let mut ds_uid = "Prometheus".to_string();
        if let Ok(panels) = self.find_panels(None).await {
            if let Some(p) = panels.iter().find(|p| !p.datasource_uid.is_empty()) {
                ds_uid = p.datasource_uid.clone();
            }
        }
        self.client.datasource_range_series(&ds_uid, expr, from, to, step.unwrap_or(self.opts.default_step)).await
    }

    fn to_evidence(&self, findings: &[MetricFinding]) -> Vec<Evidence> {
        let anomalous: Vec<MetricFinding> = findings.iter().filter(|f| f.anomaly != Anomaly::None).cloned().collect();
        findings_to_evidence(&anomalous, "grafana.analyze", &now_iso())
    }
}
