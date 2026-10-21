//! Sentry error-evidence provider (HOR-CONNECTORS). Each grouped issue becomes one
//! `kind: 'log'` Evidence; the top in-app frame is surfaced in the payload
//! (`filePath` / `symbolName` / `lineStart`) and in `links.file` / `links.line`.

use anyhow::Result;
use async_trait::async_trait;
use horus_core::{redact_secrets, Evidence, EvidenceKind, EvidenceLinks, HealthStatus, Provenance, ProviderKind};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::client::{IssuesQuery, SentryClient, SentryIssue, SentryIssuePage, SentryTopFrame};
use crate::contract::Provider;
use crate::jsutil::{js_number_string, normalize_js_numbers, now_iso, now_ms, parse_js_date_ms, short_ts, slice_chars};

#[derive(Debug, Clone, Default)]
pub struct SentryProviderOpts {
    /// Org/project label for evidence provenance.
    pub org: String,
    pub project: String,
    /// Default issues query (Sentry search syntax). Defaults to "is:unresolved".
    pub query: Option<String>,
    /// How many recent issues to fold in (capped 1–100).
    pub limit: Option<f64>,
    /// Default lookback window as a Sentry statsPeriod (e.g. "24h", "14d").
    pub stats_period: Option<String>,
}

/// A Sentry issue enriched with its resolved top in-app frame (best-effort).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SentryErrorSignature {
    pub issue: SentryIssue,
    pub frame: Option<SentryTopFrame>,
}

/// Window / hint inputs shared by `collect` and `query_evidence`.
#[derive(Debug, Clone, Default)]
pub struct CollectOptions {
    pub from: Option<String>,
    pub to: Option<String>,
    pub hint_terms: Option<Vec<String>>,
    pub collected_at: Option<String>,
}

pub struct SentryProvider {
    client: SentryClient,
    opts: SentryProviderOpts,
}

impl SentryProvider {
    pub fn new(client: SentryClient, opts: SentryProviderOpts) -> Self {
        Self { client, opts }
    }

    pub async fn watch_issue(&self, issue_id: &str) -> Result<SentryIssue> {
        self.client.issue(issue_id).await
    }

    pub async fn watch_issues(&self, from: &str, to: &str, environment: &str, cursor: Option<&str>) -> Result<SentryIssuePage> {
        self.client.watch_issues(from, to, environment, cursor).await
    }

    /// Collect recent issues and resolve each one's top in-app frame (best-effort). A
    /// failing issue LIST errors so the engine records an evidence gap.
    pub async fn collect(&self, opts: &CollectOptions) -> Result<Vec<SentryErrorSignature>> {
        let mut q = IssuesQuery {
            query: Some(self.opts.query.clone().unwrap_or_else(|| "is:unresolved".into())),
            limit: Some(self.opts.limit.unwrap_or(25.0)),
            ..Default::default()
        };
        match (&opts.from, &opts.to) {
            (Some(from), Some(to)) => {
                q.start = Some(from.clone());
                q.end = Some(to.clone());
            }
            _ => q.stats_period = Some(self.opts.stats_period.clone().unwrap_or_else(|| "14d".into())),
        }
        let issues = self.client.list_issues(&q).await?;
        // Resolve top frames in parallel — each call is bounded + self-healing.
        let frames = futures::future::join_all(issues.iter().map(|i| self.client.latest_event_top_frame(&i.id))).await;
        Ok(issues.into_iter().zip(frames).map(|(issue, frame)| SentryErrorSignature { issue, frame }).collect())
    }

    /// Synthesize Evidence from Sentry issues (one `kind: 'log'` Evidence per issue).
    pub fn to_evidence(&self, signatures: &[SentryErrorSignature], hint_terms: &[String], collected_at: &str) -> Vec<Evidence> {
        let query = format!("sentry {}/{} ({})", self.opts.org, self.opts.project, self.opts.query.as_deref().unwrap_or("is:unresolved"));
        signatures.iter().enumerate().map(|(i, sig)| signature_to_evidence(sig, hint_terms, &query, collected_at, i)).collect()
    }

    /// One-shot evidence query; degrades to [] on any failure.
    pub async fn query_evidence(&self, opts: &CollectOptions) -> Vec<Evidence> {
        let hint_terms = opts.hint_terms.clone().unwrap_or_default();
        match self.collect(opts).await {
            Ok(signatures) => self.to_evidence(&signatures, &hint_terms, &opts.collected_at.clone().unwrap_or_else(now_iso)),
            Err(_) => Vec::new(),
        }
    }
}

#[async_trait]
impl Provider for SentryProvider {
    fn id(&self) -> &str {
        "sentry"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Logs
    }
    async fn health(&self) -> HealthStatus {
        self.client.health().await
    }
}

fn signature_to_evidence(sig: &SentryErrorSignature, hint_terms: &[String], query: &str, collected_at: &str, index: usize) -> Evidence {
    let (issue, frame) = (&sig.issue, sig.frame.as_ref());
    let title = build_title(issue, frame);
    let relevance = compute_relevance(issue, frame, hint_terms, None);

    let mut payload = Map::new();
    payload.insert("source".into(), "sentry".into());
    payload.insert("issueId".into(), issue.id.clone().into());
    payload.insert("signature".into(), issue.title.clone().into());
    payload.insert("title".into(), redact_secrets(&issue.title).into());
    payload.insert("count".into(), issue.count.into());
    payload.insert("userCount".into(), issue.user_count.into());
    for (k, v) in [
        ("culprit", &issue.culprit),
        ("level", &issue.level),
        ("lastSeen", &issue.last_seen),
        ("firstSeen", &issue.first_seen),
        ("permalink", &issue.permalink),
    ] {
        if let Some(v) = v {
            payload.insert(k.into(), v.clone().into());
        }
    }
    // Direct code seed: the engine reads filePath/symbolName/lineStart off the payload.
    let mut links = EvidenceLinks::default();
    if let Some(f) = frame {
        if let Some(fname) = &f.filename {
            payload.insert("filePath".into(), fname.clone().into());
            links.file = Some(fname.clone());
        }
        if let Some(func) = &f.function {
            payload.insert("symbolName".into(), func.clone().into());
        }
        if let Some(line) = f.lineno {
            payload.insert("lineStart".into(), line.into());
            links.line = Some(line as i64);
        }
    }
    let mut payload = Value::Object(payload);
    normalize_js_numbers(&mut payload);

    Evidence {
        id: format!("ev_sentry_{index}"),
        source: ProviderKind::Logs,
        kind: EvidenceKind::Log,
        title,
        timestamp: issue.last_seen.clone(),
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

/// Build the human one-line title: signature, count, users, last-seen, culprit, frame.
pub fn build_title(issue: &SentryIssue, frame: Option<&SentryTopFrame>) -> String {
    let sig = redact_secrets(&issue.title);
    let freq = format!("{}x", js_number_string(issue.count));
    let users = if issue.user_count > 0.0 { format!(" · {} user(s)", js_number_string(issue.user_count)) } else { String::new() };
    let last = issue.last_seen.as_deref().filter(|s| !s.is_empty()).map(|s| format!(" · last {}", short_ts(s))).unwrap_or_default();
    let culprit = issue.culprit.as_deref().filter(|s| !s.is_empty()).map(|c| format!(" · {c}")).unwrap_or_default();
    let at = frame
        .and_then(|f| f.filename.as_deref().filter(|s| !s.is_empty()).map(|fname| (fname, f.lineno)))
        .map(|(fname, lineno)| format!(" @ {fname}{}", lineno.map(|l| format!(":{}", js_number_string(l))).unwrap_or_default()))
        .unwrap_or_default();
    slice_chars(&format!("Sentry {sig}: {freq}{users}{last}{culprit}{at}"), 220)
}

/// Relevance-weight an issue by hint-term match, recency, and frequency. Range ~0.5–0.95.
pub fn compute_relevance(issue: &SentryIssue, frame: Option<&SentryTopFrame>, hint_terms: &[String], now: Option<f64>) -> f64 {
    let now = now.unwrap_or_else(|| now_ms() as f64);
    let mut score: f64 = 0.6;
    let hay = [
        issue.title.as_str(),
        issue.culprit.as_deref().unwrap_or(""),
        frame.and_then(|f| f.filename.as_deref()).unwrap_or(""),
        frame.and_then(|f| f.function.as_deref()).unwrap_or(""),
    ]
    .join(" ")
    .to_lowercase();
    if hint_terms.iter().filter(|t| t.len() > 2).any(|t| hay.contains(&t.to_lowercase())) {
        score += 0.2;
    }
    // Recency: events seen in the last 24h are the most actionable.
    if let Some(ls) = issue.last_seen.as_deref().filter(|s| !s.is_empty()) {
        if let Some(seen) = parse_js_date_ms(ls).map(|t| t as f64) {
            let age_ms = now - seen;
            if age_ms <= 86_400_000.0 {
                score += 0.1;
            } else if age_ms <= 7.0 * 86_400_000.0 {
                score += 0.05;
            }
        }
    }
    // Frequency: a high-volume group is more likely the active incident.
    if issue.count >= 100.0 {
        score += 0.05;
    }
    if issue.count >= 1000.0 {
        score += 0.05;
    }
    // A resolved raise-site frame makes the evidence directly actionable.
    if frame.is_some_and(|f| f.filename.is_some()) {
        score += 0.05;
    }
    score.min(0.95).max(0.5)
}
