//! Pure normalization helpers for metric series data (HOR-11 reframe). No I/O.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jsutil::{as_arr, js_string};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MetricSample {
    /// Unix timestamp in seconds.
    pub t: f64,
    /// Numeric value (may be NaN or Infinity for special Prometheus values).
    pub v: f64,
}

/// Label set; insertion order preserved (JS object semantics).
pub type Labels = IndexMap<String, String>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSeries {
    pub labels: Labels,
    pub samples: Vec<MetricSample>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SeriesSummary {
    pub labels: Labels,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub last: f64,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineComparison {
    pub labels: Labels,
    pub baseline_avg: f64,
    pub current_avg: f64,
    pub delta: f64,
    pub ratio: f64,
    pub is_spike: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SpikePoint {
    pub t: f64,
    pub v: f64,
    pub mean: f64,
    pub std: f64,
    pub z: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Quartiles {
    pub min: f64,
    pub q1: f64,
    pub median: f64,
    pub q3: f64,
    pub max: f64,
    /// Inter-quartile range (q3 - q1).
    pub iqr: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HistogramBin {
    /// Inclusive lower bound.
    pub lo: f64,
    /// Exclusive upper bound (inclusive for the final bin).
    pub hi: f64,
    pub count: usize,
}

/// Result of the bimodal (two-population) detection over a panel's series comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BimodalResult {
    pub bimodal: bool,
    pub total: usize,
    pub high_count: usize,
    /// Genuine low/zero (finite, ≤ drop) members.
    pub low_count: usize,
    /// Non-finite / empty (Infinity / NaN) members — the "empty run".
    pub degenerate_count: usize,
    pub high_share: f64,
    /// Share of the counter-population (low + degenerate) over the total.
    pub low_share: f64,
    /// Median ratio of the high population (for the human label).
    pub high_ratio: f64,
    /// Median ratio of the genuine-low population (NaN when none).
    pub low_ratio: f64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BimodalOptions {
    pub spike: Option<f64>,
    pub drop: Option<f64>,
    pub min_share: Option<f64>,
    pub min_minority: Option<usize>,
    pub min_total: Option<usize>,
    pub gap_factor: Option<f64>,
}

// ---------------------------------------------------------------------------
// Value parsing
// ---------------------------------------------------------------------------

/// Parse a Prometheus string value into a number ("NaN" / "+Inf" / "-Inf" aware).
pub fn parse_value(raw: &str) -> f64 {
    match raw {
        "NaN" => f64::NAN,
        "+Inf" => f64::INFINITY,
        "-Inf" => f64::NEG_INFINITY,
        other => crate::jsutil::js_number_from_str(other).unwrap_or(f64::NAN),
    }
}

fn parse_labels(v: Option<&Value>) -> Labels {
    v.and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| (k.clone(), js_string(v))).collect()).unwrap_or_default()
}

fn ts_of(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => crate::jsutil::js_number_from_str(s).unwrap_or(f64::NAN),
        Some(Value::Null) | None => f64::NAN,
        Some(other) => crate::jsutil::js_number_from_str(&js_string(other)).unwrap_or(f64::NAN),
    }
}

// ---------------------------------------------------------------------------
// Response parsers
// ---------------------------------------------------------------------------

/// Parse a Prometheus instant query response (resultType: "vector").
pub fn parse_instant(resp: &Value) -> Vec<MetricSeries> {
    let Some(result) = resp.get("data").and_then(|d| d.get("result")).and_then(Value::as_array) else { return vec![] };
    result
        .iter()
        .map(|it| {
            let labels = parse_labels(it.get("metric"));
            let value = as_arr(it.get("value"));
            if value.len() < 2 {
                return MetricSeries { labels, samples: vec![] };
            }
            let t = ts_of(value.first());
            let v = parse_value(&js_string(&value[1]));
            MetricSeries { labels, samples: vec![MetricSample { t, v }] }
        })
        .collect()
}

/// Parse a Prometheus range query response (resultType: "matrix").
pub fn parse_range(resp: &Value) -> Vec<MetricSeries> {
    let Some(result) = resp.get("data").and_then(|d| d.get("result")).and_then(Value::as_array) else { return vec![] };
    result
        .iter()
        .map(|it| {
            let labels = parse_labels(it.get("metric"));
            let Some(values) = it.get("values").and_then(Value::as_array) else { return MetricSeries { labels, samples: vec![] } };
            let samples = values
                .iter()
                .map(|pair| {
                    let p = as_arr(Some(pair));
                    let t = ts_of(p.first());
                    let v = match p.get(1) {
                        None | Some(Value::Null) => f64::NAN,
                        Some(x) => parse_value(&js_string(x)),
                    };
                    MetricSample { t, v }
                })
                .collect();
            MetricSeries { labels, samples }
        })
        .collect()
}

/// Typed, streaming decode of a Prometheus range response straight into [`MetricSeries`] —
/// the same result as `parse_range(&serde_json::from_slice(body))`, without materializing every
/// `[ts, "value"]` sample as a `serde_json::Value` tree (a high-cardinality panel response is
/// tens of MB of JSON, which a full Value tree inflates ~10x). `None` when the body does not
/// have the expected shape — callers then fall back to the `Value` path so semantics are unchanged.
pub fn parse_range_bytes(body: &[u8]) -> Option<(Option<Value>, Option<Value>, Vec<MetricSeries>)> {
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        status: Option<Value>,
        #[serde(default)]
        error: Option<Value>,
        #[serde(default)]
        data: Option<Data>,
    }
    #[derive(Deserialize)]
    struct Data {
        #[serde(default)]
        result: Option<Vec<Item>>,
    }
    #[derive(Deserialize)]
    struct Item {
        #[serde(default)]
        metric: Option<Value>,
        #[serde(default)]
        values: Option<Vec<Pair>>,
    }
    /// One `[ts, value]` pair, decoded element-by-element into a sample (mirrors `parse_range`).
    struct Pair(MetricSample);
    impl<'de> Deserialize<'de> for Pair {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Pair;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a [ts, value] pair")
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Pair, A::Error> {
                    let t: Option<Value> = seq.next_element()?;
                    let v: Option<Value> = seq.next_element()?;
                    while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                    let v = match v {
                        None | Some(Value::Null) => f64::NAN,
                        Some(x) => parse_value(&js_string(&x)),
                    };
                    Ok(Pair(MetricSample { t: ts_of(t.as_ref()), v }))
                }
            }
            d.deserialize_seq(V)
        }
    }
    let resp: Resp = serde_json::from_slice(body).ok()?;
    let series = resp
        .data
        .and_then(|d| d.result)
        .unwrap_or_default()
        .into_iter()
        .map(|it| MetricSeries {
            labels: parse_labels(it.metric.as_ref()),
            samples: it.values.map(|vs| vs.into_iter().map(|p| p.0).collect()).unwrap_or_default(),
        })
        .collect();
    Some((resp.status, resp.error, series))
}

// ---------------------------------------------------------------------------
// Statistical helpers
// ---------------------------------------------------------------------------

/// Compute min/max/avg/last/count over a series' samples, ignoring NaN values.
pub fn summarize(series: &MetricSeries) -> SeriesSummary {
    let finite: Vec<&MetricSample> = series.samples.iter().filter(|s| !s.v.is_nan()).collect();
    if finite.is_empty() {
        return SeriesSummary { labels: series.labels.clone(), min: 0.0, max: 0.0, avg: 0.0, last: 0.0, count: 0 };
    }
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    let mut sum = 0.0;
    for s in &finite {
        if s.v < min {
            min = s.v;
        }
        if s.v > max {
            max = s.v;
        }
        sum += s.v;
    }
    let avg = sum / finite.len() as f64;
    // last is the sample with the greatest timestamp among finite values
    let last = finite.iter().copied().reduce(|a, b| if a.t >= b.t { a } else { b }).unwrap();
    SeriesSummary { labels: series.labels.clone(), min, max, avg, last: last.v, count: finite.len() }
}

/// Build a stable string key for a label set (for joining baseline vs current).
fn label_key(labels: &Labels) -> String {
    let mut sorted: Vec<(&String, &String)> = labels.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
    serde_json::to_string(&sorted).unwrap_or_default()
}

/// Compare two windows of metric series (baseline vs current). One comparison per
/// series present in `current`, sorted by delta desc. `spike_ratio` defaults to 1.5.
pub fn compare_windows(baseline: &[MetricSeries], current: &[MetricSeries], spike_ratio: Option<f64>) -> Vec<BaselineComparison> {
    let spike_ratio = spike_ratio.unwrap_or(1.5);
    let mut baseline_map: IndexMap<String, &MetricSeries> = IndexMap::new();
    for s in baseline {
        baseline_map.insert(label_key(&s.labels), s);
    }
    let mut comparisons: Vec<BaselineComparison> = current
        .iter()
        .map(|cs| {
            let baseline_avg = baseline_map.get(&label_key(&cs.labels)).map(|bs| summarize(bs).avg).unwrap_or(0.0);
            let current_avg = summarize(cs).avg;
            let delta = current_avg - baseline_avg;
            let ratio = if baseline_avg == 0.0 {
                if current_avg > 0.0 {
                    f64::INFINITY
                } else {
                    0.0
                }
            } else {
                current_avg / baseline_avg
            };
            BaselineComparison { labels: cs.labels.clone(), baseline_avg, current_avg, delta, ratio, is_spike: ratio >= spike_ratio }
        })
        .collect();
    comparisons.sort_by(|a, b| b.delta.partial_cmp(&a.delta).unwrap_or(std::cmp::Ordering::Equal));
    comparisons
}

/// Detect spike points in a single series using leave-one-out z-score thresholding.
pub fn detect_spikes(series: &MetricSeries, k: Option<f64>) -> Vec<SpikePoint> {
    let k = k.unwrap_or(3.0);
    let finite: Vec<&MetricSample> = series.samples.iter().filter(|s| s.v.is_finite()).collect();
    let n = finite.len();
    if n < 2 {
        return vec![];
    }
    let sum: f64 = finite.iter().map(|s| s.v).sum();
    let mean = sum / n as f64;
    let variance = finite.iter().map(|s| (s.v - mean).powi(2)).sum::<f64>() / n as f64;
    let std = variance.sqrt();
    if std == 0.0 {
        return vec![];
    }
    finite
        .iter()
        .filter_map(|s| {
            let mean_others = (sum - s.v) / (n as f64 - 1.0);
            let z = (s.v - mean_others) / std;
            (z > k).then_some(SpikePoint { t: s.t, v: s.v, mean, std, z })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Distribution helpers (HOR-435 — bimodal detection support)
// ---------------------------------------------------------------------------

/// Linear-interpolated percentile over an ascending-sorted finite slice. `p` in [0,1].
fn quantile_sorted(sorted_asc: &[f64], p: f64) -> f64 {
    let n = sorted_asc.len();
    if n == 0 {
        return f64::NAN;
    }
    if n == 1 {
        return sorted_asc[0];
    }
    let pos = (n as f64 - 1.0) * p;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        return sorted_asc[lo];
    }
    let frac = pos - lo as f64;
    sorted_asc[lo] * (1.0 - frac) + sorted_asc[hi] * frac
}

fn sorted_finite(values: &[f64]) -> Vec<f64> {
    let mut v: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v
}

/// Five-number summary over finite values; None when there are no finite values.
pub fn quartiles(values: &[f64]) -> Option<Quartiles> {
    let sorted = sorted_finite(values);
    if sorted.is_empty() {
        return None;
    }
    let q1 = quantile_sorted(&sorted, 0.25);
    let q3 = quantile_sorted(&sorted, 0.75);
    Some(Quartiles { min: sorted[0], q1, median: quantile_sorted(&sorted, 0.5), q3, max: sorted[sorted.len() - 1], iqr: q3 - q1 })
}

/// Equal-width histogram over finite values with `bins` buckets (default 10).
pub fn histogram(values: &[f64], bins: Option<f64>) -> Vec<HistogramBin> {
    let finite: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if finite.is_empty() {
        return vec![];
    }
    let count = (bins.unwrap_or(10.0).floor().max(1.0)) as usize;
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    for &v in &finite {
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    if min == max {
        return vec![HistogramBin { lo: min, hi: max, count: finite.len() }];
    }
    let width = (max - min) / count as f64;
    let mut out: Vec<HistogramBin> = (0..count).map(|i| HistogramBin { lo: min + i as f64 * width, hi: min + (i + 1) as f64 * width, count: 0 }).collect();
    for v in finite {
        let mut idx = ((v - min) / width).floor() as i64;
        if idx >= count as i64 {
            idx = count as i64 - 1; // the max lands in the final bin
        }
        if idx < 0 {
            idx = 0;
        }
        out[idx as usize].count += 1;
    }
    out
}

/// Median of a finite slice (NaN when empty).
fn median(values: &[f64]) -> f64 {
    let sorted = sorted_finite(values);
    if sorted.is_empty() {
        return f64::NAN;
    }
    quantile_sorted(&sorted, 0.5)
}

/// Detect a BIMODAL (two-population) pattern across a panel's series comparisons.
/// Conservative by design: both a HIGH-spike cluster and a low/zero/empty counter-
/// population must be co-present with a real share and a real gap between them.
pub fn detect_bimodal_population(comparisons: &[BaselineComparison], opts: Option<BimodalOptions>) -> BimodalResult {
    let o = opts.unwrap_or_default();
    let spike = o.spike.unwrap_or(1.5);
    let drop = o.drop.unwrap_or(0.67);
    let min_share = o.min_share.unwrap_or(0.2);
    let min_minority = o.min_minority.unwrap_or(2);
    let min_total = o.min_total.unwrap_or(3);
    let gap_factor = o.gap_factor.unwrap_or(2.0);

    let total = comparisons.len();
    let mut high_ratios: Vec<f64> = Vec::new();
    let mut low_ratios: Vec<f64> = Vec::new();
    let mut degenerate_count = 0usize;
    for c in comparisons {
        let r = c.ratio;
        if !r.is_finite() {
            // Infinity / NaN — an "empty run" or a no-baseline division. Counter-population.
            degenerate_count += 1;
        } else if r >= spike {
            high_ratios.push(r);
        } else if r > 0.0 && r <= drop {
            low_ratios.push(r);
        } else if r == 0.0 {
            // A true zero (empty/no current) — counts toward the low/empty population.
            degenerate_count += 1;
        }
        // ratios in (drop, spike) are the "stable / normal" middle and are ignored here.
    }
    let high_count = high_ratios.len();
    let low_count = low_ratios.len();
    let counter_count = low_count + degenerate_count;

    let mut result = BimodalResult {
        bimodal: false,
        total,
        high_count,
        low_count,
        degenerate_count,
        high_share: if total > 0 { high_count as f64 / total as f64 } else { 0.0 },
        low_share: if total > 0 { counter_count as f64 / total as f64 } else { 0.0 },
        high_ratio: median(&high_ratios),
        low_ratio: median(&low_ratios),
    };

    if total < min_total {
        return result;
    }
    if high_count < 1 || counter_count < 1 {
        return result;
    }
    if counter_count < min_minority {
        return result;
    }
    if result.low_share < min_share {
        return result;
    }
    if high_count < min_minority && result.high_share < min_share {
        return result;
    }
    if low_count > 0 {
        let (hi, lo) = (result.high_ratio, result.low_ratio);
        if hi.is_finite() && lo.is_finite() && lo > 0.0 && hi / lo < gap_factor {
            return result;
        }
    }
    result.bimodal = true;
    result
}
