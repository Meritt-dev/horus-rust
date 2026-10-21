//! Pure analysis layer: compare metric windows, classify anomalies, build Evidence (HOR-11 reframe).

use horus_core::{Evidence, EvidenceKind, EvidenceLinks, Provenance, ProviderKind};
use serde::{Deserialize, Serialize};

use super::panels::{MatchSource, MetricKind};
use super::series::{compare_windows, detect_bimodal_population, summarize, BaselineComparison, Labels, MetricSeries};
use crate::jsutil::{js_value, slice_chars, to_fixed};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Anomaly {
    LatencySpike,
    ErrorRateChange,
    ThroughputDrop,
    QueueGrowth,
    Change,
    /// Two co-present sub-populations on one panel (HOR-435): possible per-segment
    /// variance, NOT a uniform regression. Carries LOWER relevance.
    BimodalPopulation,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricFinding {
    pub dashboard_uid: String,
    pub panel_title: String,
    pub kind: MetricKind,
    pub anomaly: Anomaly,
    pub labels: Labels,
    pub baseline_avg: f64,
    pub current_avg: f64,
    pub ratio: f64,
    pub last_value: f64,
    /// Where the hint matched — `Some(None)` is TS `null` (no hint / unknown source);
    /// `None` omits the key (finding never ran through the provider's match pass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_source: Option<Option<MatchSource>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AnomalyThresholds {
    pub spike: Option<f64>,
    pub drop: Option<f64>,
}

// ---------------------------------------------------------------------------
// Anomaly classification
// ---------------------------------------------------------------------------

pub fn classify_anomaly(kind: MetricKind, cmp: &BaselineComparison, opts: Option<AnomalyThresholds>) -> Anomaly {
    let o = opts.unwrap_or_default();
    let spike = o.spike.unwrap_or(1.5);
    let drop = o.drop.unwrap_or(0.67);

    // HOR-342: a "spike" on a metric with no baseline yields an Infinity ratio. Require a
    // meaningful absolute magnitude before flagging a zero-baseline jump.
    const NEAR_ZERO: f64 = 1e-9;
    if cmp.baseline_avg <= NEAR_ZERO && cmp.current_avg > 0.0 {
        let floor = match kind {
            MetricKind::Queue => 1.0,       // < 1 job is not a backlog (unit-independent)
            MetricKind::Latency => 0.05,    // 50ms p95 (latency series are in seconds)
            MetricKind::ErrorRate => 0.005,
            _ => 0.0, // throughput is about drops; generic 'change' keeps its own gate
        };
        if cmp.current_avg < floor {
            return Anomaly::None;
        }
    }
    if kind == MetricKind::Latency && cmp.ratio >= spike {
        return Anomaly::LatencySpike;
    }
    if kind == MetricKind::Queue && (cmp.ratio >= spike || cmp.current_avg > cmp.baseline_avg) && cmp.delta > 0.0 {
        return Anomaly::QueueGrowth;
    }
    if kind == MetricKind::Throughput && cmp.ratio > 0.0 && cmp.ratio <= drop {
        return Anomaly::ThroughputDrop;
    }
    if kind == MetricKind::ErrorRate && cmp.ratio >= spike {
        return Anomaly::ErrorRateChange;
    }
    if cmp.ratio >= spike || (cmp.ratio > 0.0 && cmp.ratio <= drop) {
        return Anomaly::Change;
    }
    Anomaly::None
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

/// Compare baseline and current series for a single panel and produce findings
/// (including anomaly "none" so callers can show a full summary).
pub fn build_findings(dashboard_uid: &str, panel_title: &str, kind: MetricKind, baseline: &[MetricSeries], current: &[MetricSeries]) -> Vec<MetricFinding> {
    let comparisons = compare_windows(baseline, current, None);

    // HOR-435: panel-level two-population check — reclassify members of BOTH clusters
    // as a single 'bimodal-population' signal when co-present.
    let bimodal = detect_bimodal_population(&comparisons, None);
    let spike = 1.5;
    let drop = 0.67;
    let is_bimodal_member = |cmp: &BaselineComparison| -> bool {
        let r = cmp.ratio;
        if !r.is_finite() {
            return true; // empty / Infinity run
        }
        if r >= spike {
            return true; // high cluster
        }
        if r == 0.0 {
            return true; // empty / zero
        }
        r > 0.0 && r <= drop // genuine low cluster
    };

    comparisons
        .into_iter()
        .map(|cmp| {
            let base_anomaly = classify_anomaly(kind, &cmp, None);
            let anomaly = if bimodal.bimodal && base_anomaly != Anomaly::None && is_bimodal_member(&cmp) {
                Anomaly::BimodalPopulation
            } else {
                base_anomaly
            };
            // last_value: last sample of the current series matching these labels
            let current_series = current.iter().find(|s| cmp.labels.iter().all(|(k, v)| s.labels.get(k) == Some(v)));
            let last_value = current_series.map(|s| summarize(s).last).unwrap_or(cmp.current_avg);
            MetricFinding {
                dashboard_uid: dashboard_uid.to_string(),
                panel_title: panel_title.to_string(),
                kind,
                anomaly,
                labels: cmp.labels,
                baseline_avg: cmp.baseline_avg,
                current_avg: cmp.current_avg,
                ratio: cmp.ratio,
                last_value,
                match_source: None,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Evidence conversion
// ---------------------------------------------------------------------------

fn anomaly_label(anomaly: Anomaly) -> &'static str {
    match anomaly {
        Anomaly::LatencySpike => "Latency Spike",
        Anomaly::ErrorRateChange => "Error Rate Change",
        Anomaly::ThroughputDrop => "Throughput Drop",
        Anomaly::QueueGrowth => "Queue Growth",
        Anomaly::Change => "Change",
        Anomaly::BimodalPopulation => "Bimodal Population (possible per-segment variance)",
        Anomaly::None => "No Anomaly",
    }
}

fn anomaly_relevance(anomaly: Anomaly) -> f64 {
    match anomaly {
        Anomaly::LatencySpike | Anomaly::ErrorRateChange | Anomaly::QueueGrowth => 0.85,
        Anomaly::ThroughputDrop => 0.8,
        Anomaly::Change => 0.55,
        // A two-population pattern is a hypothesis, not a uniform regression (HOR-435).
        Anomaly::BimodalPopulation => 0.6,
        Anomaly::None => 0.0,
    }
}

/// Convert MetricFindings (anomaly != "none") into Evidence, one per finding.
pub fn findings_to_evidence(findings: &[MetricFinding], query: &str, collected_at: &str) -> Vec<Evidence> {
    findings
        .iter()
        .filter(|f| f.anomaly != Anomaly::None)
        .enumerate()
        .map(|(i, f)| {
            let ratio_str = if f.ratio.is_finite() { format!("x{}", to_fixed(f.ratio, 2)) } else { "xinf".to_string() };
            let title = slice_chars(
                &format!("{}: {} {} -> {} ({})", anomaly_label(f.anomaly), f.panel_title, to_fixed(f.baseline_avg, 3), to_fixed(f.current_avg, 3), ratio_str),
                160,
            );
            Evidence {
                id: format!("ev_metric_{i}"),
                source: ProviderKind::Metrics,
                kind: EvidenceKind::Metric,
                title,
                timestamp: None,
                relevance: anomaly_relevance(f.anomaly),
                payload: js_value(f),
                links: EvidenceLinks::default(),
                provenance: Provenance { query: query.to_string(), collected_at: collected_at.to_string() },
                priority: None,
                category: None,
                subject: None,
                is_new: None,
                ratio: None,
            }
        })
        .collect()
}
