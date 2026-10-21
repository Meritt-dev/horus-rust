//! Lens report work-queue (HOR-CLI). Port of `packages/cli/src/lib/lens/reports.ts` — the
//! shared "fetch + shape" core behind `horus lens` (list/show) and the MCP lens tools.
//!
//! NATIVE-CONNECTOR CONTRACT: available only when the CLI is logged in AND the repo is
//! cloud-linked (`workspace.id`); otherwise a typed `unavailable` reason (never an error).
//! Read-only; the connector helpers already redact comments/errors and never read reporter
//! identity. Cloud read path + seed resolution are REUSED from `horus_connectors::lens`.

use std::path::Path;

use anyhow::Result;
use horus_connectors::lens::{build_signal, LensClientOpts, LensCloudClient, LensReportSignal, LensReportSummary, LensReportsQuery, LensSite};
use serde::Serialize;
use serde_json::Value;

use crate::lib::cloud::auth_store::read_auth;
use crate::lib::cloud::context_store::read_cloud_config;

/// Why the Lens work queue can't be reached (`not-logged-in` | `not-cloud-linked`).
#[derive(Debug, Clone, Serialize)]
pub struct LensUnavailable {
    pub unavailable: String,
    pub remedy: String,
}

fn unavailable(reason: &str) -> LensUnavailable {
    let remedy = match reason {
        "not-logged-in" => "not logged into Horus Cloud — run `horus login`",
        _ => "repo not cloud-linked — run `horus cloud link`",
    };
    LensUnavailable { unavailable: reason.into(), remedy: remedy.into() }
}

pub struct LensClientHandle {
    pub client: LensCloudClient,
    pub workspace_id: String,
}

/// Build a read-only Lens Cloud client from the CLI's cloud auth + the repo's linked workspace,
/// or a typed `unavailable` reason. Same gate as `investigation_runner`.
pub fn resolve_lens_client(root: &Path) -> Result<LensClientHandle, LensUnavailable> {
    let Some(auth) = read_auth() else { return Err(unavailable("not-logged-in")) };
    let Some(workspace_id) = read_cloud_config(root).and_then(|c| c.workspace).map(|w| w.id) else {
        return Err(unavailable("not-cloud-linked"));
    };
    Ok(LensClientHandle {
        client: LensCloudClient::new(LensClientOpts {
            api_base_url: auth.api_base_url,
            token: auth.token,
            workspace_id: workspace_id.clone(),
            http: None,
        }),
        workspace_id,
    })
}

/// A condensed backlog row — cheap (list endpoint only). Field order = TS assignment order.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LensReportRow {
    pub id: String,
    pub site_id: String,
    pub status: String,
    pub created_at: String,
    pub submitted_at: Option<String>,
    pub error_count: f64,
    pub has_replay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Pathname of the page the report was filed on (origin stripped), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LensListResult {
    pub reports: Vec<LensReportRow>,
    /// Number of Lens sites the workspace owns (reports are merged across them).
    pub sites: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct LensListOpts {
    /// Report status filter. Default `submitted`.
    pub status: Option<String>,
    /// `--all` (or status `all`) drops the status filter.
    pub all: bool,
    /// Max reports across the merged result. 1–200. Default 50.
    pub limit: Option<f64>,
    /// Only reports created on/after this ISO date (the API `from` bound).
    pub since: Option<String>,
    /// Restrict to a single Lens site id (skips site discovery).
    pub site_id: Option<String>,
}

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

fn clamp_limit(n: Option<f64>) -> i64 {
    match n {
        Some(n) if n.is_finite() => (n.trunc() as i64).clamp(1, MAX_LIMIT),
        _ => DEFAULT_LIMIT,
    }
}

/// Strip a URL down to its pathname (the "route"); tolerate a bare/relative value.
fn route_from_url(url: Option<&str>) -> Option<String> {
    let url = url.filter(|u| !u.is_empty())?;
    match url::Url::parse(url) {
        Ok(u) => Some(u.path().to_string()),
        Err(_) => url.starts_with('/').then(|| url.to_string()),
    }
}

/// Sites to query: the single requested one, or all the workspace owns.
async fn sites_for(handle: &LensClientHandle, site_id: Option<&str>) -> Result<Vec<LensSite>> {
    match site_id.filter(|s| !s.is_empty()) {
        Some(id) => Ok(vec![LensSite { id: id.into(), name: id.into() }]),
        None => handle.client.list_sites().await,
    }
}

fn to_row(s: LensReportSummary) -> LensReportRow {
    let route = route_from_url(s.url.as_deref());
    LensReportRow {
        id: s.id,
        site_id: s.lens_site_id,
        status: s.status,
        created_at: s.created_at,
        submitted_at: s.submitted_at,
        error_count: s.error_count,
        has_replay: s.has_replay,
        comment: s.comment,
        url: s.url,
        route,
    }
}

/// List client-reported Lens issues across every site, newest first. `Err` of the outer result
/// is a transport/auth failure (an outage must not read as "no reports").
pub async fn list_lens_reports(root: &Path, opts: &LensListOpts) -> Result<Result<LensListResult, LensUnavailable>> {
    let handle = match resolve_lens_client(root) {
        Ok(h) => h,
        Err(u) => return Ok(Err(u)),
    };
    let limit = clamp_limit(opts.limit);
    let status = if opts.all || opts.status.as_deref() == Some("all") {
        None
    } else {
        Some(opts.status.clone().unwrap_or_else(|| "submitted".into()))
    };
    let sites = sites_for(&handle, opts.site_id.as_deref()).await?;
    let mut rows = Vec::new();
    for site in &sites {
        let q = LensReportsQuery { status: status.clone(), limit: Some(limit), from: opts.since.clone(), to: None, q: None };
        rows.extend(handle.client.list_reports(&site.id, &q).await?.into_iter().map(to_row));
    }
    rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let total = rows.len();
    rows.truncate(limit as usize);
    let notes = if total > rows.len() {
        // Merged across sites exceeded the cap — exact overflow count is known.
        Some(vec![format!("showing {} of {total} reports — raise --limit for more", rows.len())])
    } else if rows.len() as i64 == limit {
        // Hit the per-site API cap exactly; more may exist beyond it.
        Some(vec![format!("showing the first {limit} reports — raise --limit if more may exist")])
    } else {
        None
    };
    Ok(Ok(LensListResult { reports: rows, sites: sites.len(), notes }))
}

/// The raise site to work on — top parseable stack frame.
#[derive(Debug, Clone, Serialize)]
pub struct LensSeed {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

/// The actionable payload for one report: the shaped signal + a flattened code seed.
#[derive(Debug, Clone)]
pub struct LensReportDetail {
    pub signal: LensReportSignal,
    pub seed: Option<LensSeed>,
}

/// TS `buildSignal` assignment order (the connectors struct declares the optional fields
/// earlier); `{ ...signal, seed }` appends `seed`.
const SIGNAL_KEY_ORDER: &[&str] = &[
    "id", "lensSiteId", "status", "createdAt", "submittedAt", "issueOccurrenceCount", "errorCount", "hasReplay",
    "topFrame", "failingRequests", "comment", "route", "url", "release", "gitSha", "environment", "featureFlags",
    "trigger", "topErrorMessage", "reactComponents",
];

impl Serialize for LensReportDetail {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        let mut raw = serde_json::to_value(&self.signal).map_err(serde::ser::Error::custom)?;
        let obj = raw.as_object_mut().ok_or_else(|| serde::ser::Error::custom("signal is not an object"))?;
        let mut out = serde_json::Map::new();
        for k in SIGNAL_KEY_ORDER {
            if let Some(v) = obj.shift_remove(*k) {
                out.insert((*k).to_string(), v);
            }
        }
        out.extend(std::mem::take(obj));
        out.insert("seed".into(), serde_json::to_value(&self.seed).map_err(serde::ser::Error::custom)?);
        Value::Object(out).serialize(ser)
    }
}

pub enum LensDetail {
    Found(Box<LensReportDetail>),
    Unavailable(LensUnavailable),
    NotFound { report_id: String },
}

/// Fetch one report in full and shape it (comment, route, release/gitSha, failing requests,
/// top error, resolved code seed). Scans the workspace's sites when `site_id` isn't supplied.
pub async fn get_lens_report_detail(root: &Path, report_id: &str, site_id: Option<&str>) -> Result<LensDetail> {
    let handle = match resolve_lens_client(root) {
        Ok(h) => h,
        Err(u) => return Ok(LensDetail::Unavailable(u)),
    };
    for site in sites_for(&handle, site_id).await? {
        // Locate the summary (any status) so build_signal has the list-level fields.
        let q = LensReportsQuery { limit: Some(MAX_LIMIT), ..Default::default() };
        let summaries = handle.client.list_reports(&site.id, &q).await?;
        let Some(summary) = summaries.into_iter().find(|s| s.id == report_id) else { continue };
        let report = handle.client.get_report(&site.id, report_id).await?;
        let signal = build_signal(&summary, Some(&report));
        let seed = signal.top_frame.as_ref().map(|f| LensSeed { file: f.filename.clone(), line: f.lineno, symbol: f.function.clone() });
        return Ok(LensDetail::Found(Box::new(LensReportDetail { signal, seed })));
    }
    Ok(LensDetail::NotFound { report_id: report_id.into() })
}

/// JSON of the detail (signal fields then `seed`), JS number semantics.
pub fn detail_json(d: &LensReportDetail) -> Result<Value> {
    Ok(horus_core::json::to_js_value(d)?)
}
