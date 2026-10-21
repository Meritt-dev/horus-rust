//! Foreground entry point for the durable watcher shared with the macOS service.
//! Port of `packages/cli/src/commands/watch.ts`. Pure hint/detection helpers remain exported for
//! compatibility with existing callers; persistent event/episode acceptance lives in watch_store.

// The compatibility helpers below have no in-binary callers (same as TS outside its tests).
#![allow(dead_code)]

use std::collections::HashSet;

use anyhow::Result;
use horus_connectors::elasticsearch::analyze::ErrorSignature;
use horus_connectors::sentry::client::SentryIssue;
use horus_engine::types::InvestigationReport;

use crate::cli::*;
use crate::commands::service::{run_service, ServiceOpts};

// ---------------------------------------------------------------------------
// Pure detection + hint derivation
// ---------------------------------------------------------------------------

/// Of `issues`, return those whose id is not already in `seen`, and record them as seen. Dedup is
/// by issue id, so the same incident triggers an investigation exactly once across polls. Issues
/// with an empty id are skipped (un-trackable).
pub fn detect_new_sentry_incidents(issues: &[SentryIssue], seen: &mut HashSet<String>) -> Vec<SentryIssue> {
    issues.iter().filter(|i| !i.id.is_empty() && seen.insert(i.id.clone())).cloned().collect()
}

/// Of `signatures`, return those the analyzer flagged `is_new` (absent from the baseline window)
/// that we haven't acted on before, keyed by signature `key` (the event_code). Records each
/// returned key as seen so it never re-triggers.
pub fn detect_new_es_signatures(signatures: &[ErrorSignature], seen: &mut HashSet<String>) -> Vec<ErrorSignature> {
    signatures
        .iter()
        .filter(|s| s.is_new == Some(true) && !s.key.is_empty() && seen.insert(s.key.clone()))
        .cloned()
        .collect()
}

/// JS `s.slice(0, n)` on UTF-16 code units, approximated per `char`.
fn slice_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Derive the investigation hint for a Sentry issue: prefer the issue title, append the culprit
/// (where it surfaced) when present. Bounded so the hint stays a clean one-liner.
///
/// TS also falls back to a `shortId` token read off the raw issue via a cast; `SentryIssue`
/// doesn't declare it in either implementation and the Rust struct drops undeclared keys, so
/// that rung goes straight to the untitled placeholder.
pub fn hint_from_sentry_issue(issue: &SentryIssue) -> String {
    let title = issue.title.trim();
    let culprit = issue.culprit.as_deref().unwrap_or("").trim();
    let hint = if !title.is_empty() {
        if culprit.is_empty() { title.to_string() } else { format!("{title} ({culprit})") }
    } else if !culprit.is_empty() {
        culprit.to_string()
    } else {
        "(untitled Sentry issue)".to_string()
    };
    slice_chars(&hint, 200)
}

/// Derive the investigation hint for an Elasticsearch error signature: its `key` is the
/// event_code. Append a sample message when present so the hint is human-meaningful.
pub fn hint_from_es_signature(sig: &ErrorSignature) -> String {
    let key = sig.key.trim();
    let sample = sig.sample_message.as_deref().unwrap_or("").trim();
    let hint = if !key.is_empty() && key != "(none)" {
        if sample.is_empty() { key.to_string() } else { format!("{key}: {sample}") }
    } else if !sample.is_empty() {
        sample.to_string()
    } else {
        "(new error signature)".to_string()
    };
    slice_chars(&hint, 200)
}

/// The headline cause + confidence line for one finished investigation.
pub fn headline_for(report: &InvestigationReport) -> (String, f64) {
    let cause = report.suspected_causes.first().map_or_else(|| "no clear cause".to_string(), |c| c.title.clone());
    (cause, report.confidence)
}

/// Foreground execution uses the same durable watcher as launchd.
pub async fn run(args: &WatchArgs) -> Result<()> {
    run_service("run", &ServiceOpts { settings: args.settings.clone(), once: args.once, ..Default::default() }).await
}
