//! HOR-362 — Investigation freshness. Port of `packages/cli/src/lib/freshness.ts`.
//!
//! A clean-looking report shouldn't hide that it was built on a stale code index or on runtime
//! evidence outside the incident window. This computes, from the repo's index metadata
//! (`.horus/source/meta.json`, written by horus-source) and the report's own evidence
//! timestamps, how fresh the inputs are — surfaced as a banner.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::lib::format::{dim, yellow};

/// How many commits on HEAD landed after `since_iso` — how far the code index is behind the
/// working tree. None when it can't be determined (not a git repo, bad date, timeout).
pub async fn commits_since(repo_root: &Path, since_iso: &str) -> Option<i64> {
    let out = tokio::time::timeout(
        Duration::from_millis(5000),
        tokio::process::Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["rev-list", "--count", &format!("--since={since_iso}"), "HEAD"])
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_int_prefix(String::from_utf8_lossy(&out.stdout).trim())
}

/// JS `parseInt(s, 10)`: leading integer prefix, None when there is none.
fn parse_int_prefix(s: &str) -> Option<i64> {
    let end = s
        .char_indices()
        .find(|(i, c)| !(c.is_ascii_digit() || (*i == 0 && (*c == '-' || *c == '+'))))
        .map_or(s.len(), |(i, _)| i);
    s[..end].parse().ok()
}

/// Runtime evidence ages; code/history don't carry a meaningful "window".
const RUNTIME_SOURCES: &[&str] = &["logs", "metrics", "state", "queue"];
/// Code index older than this is flagged stale.
pub const STALE_INDEX_MS: i64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Default)]
pub struct IndexMeta {
    pub last_indexed_at: Option<String>,
    pub version: Option<String>,
    pub stats: Option<HashMap<String, f64>>,
    /// HOR-375: false until the (possibly background) embedding phase persisted vectors.
    pub embeddings_complete: Option<bool>,
}

/// Read `.horus/source/meta.json` for the repo, or None when absent/unreadable.
pub fn read_index_meta(repo_root: &Path) -> Option<IndexMeta> {
    let raw = std::fs::read_to_string(repo_root.join(".horus").join("source").join("meta.json")).ok()?;
    let j: Value = serde_json::from_str(&raw).ok()?;
    let str_field = |k: &str| j.get(k).and_then(Value::as_str).map(str::to_string);
    Some(IndexMeta {
        last_indexed_at: str_field("last_indexed_at"),
        version: str_field("version"),
        stats: j.get("stats").and_then(Value::as_object).map(|m| {
            m.iter().filter_map(|(k, v)| v.as_f64().map(|n| (k.clone(), n))).collect()
        }),
        embeddings_complete: j.get("embeddings_complete").and_then(Value::as_bool),
    })
}

/// Whether a repo's index has usable semantic-search vectors (HOR-373/375). Symbols but zero
/// embeddings — or an explicit `embeddings_complete: false` — silently degrades search to
/// keyword/FTS only, so readiness/doctor can surface it.
pub fn semantic_search_ready(meta: Option<&IndexMeta>) -> bool {
    let Some(meta) = meta else { return false };
    if meta.embeddings_complete == Some(false) {
        return false;
    }
    let stat = |k: &str| meta.stats.as_ref().and_then(|s| s.get(k)).copied().unwrap_or(0.0);
    !(stat("symbols") > 0.0 && stat("embeddings") == 0.0)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeWindow {
    pub from_iso: String,
    pub to_iso: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Freshness {
    /// ms since the repo was indexed, or None when unknown.
    pub index_age_ms: Option<i64>,
    pub index_age_label: String,
    pub index_stale: bool,
    /// Commits on HEAD since the index was built.
    pub commits_since_index: Option<i64>,
    /// Span of runtime evidence actually used, when any carried timestamps.
    pub runtime_window: Option<RuntimeWindow>,
    /// Distinct runtime sources that contributed evidence (logs/metrics/state/queue).
    pub runtime_sources: Vec<String>,
    pub caveats: Vec<String>,
}

/// Compact human age, e.g. `45s`, `12m`, `3h`, `5d`.
pub fn human_age(ms: i64) -> String {
    let s = (ms / 1000).max(0);
    if s < 60 {
        return format!("{s}s");
    }
    let m = s / 60;
    if m < 60 {
        return format!("{m}m");
    }
    let h = m / 60;
    if h < 24 {
        return format!("{h}h");
    }
    format!("{}d", h / 24)
}

#[derive(Debug, Clone, Default)]
pub struct FreshnessEvidence {
    pub source: Option<String>,
    pub timestamp: Option<String>,
}

/// JS `Date.parse` for the ISO forms Horus emits; None for NaN.
fn parse_ms(s: &str) -> Option<i64> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.timestamp_millis());
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"] {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            // JS parses offset-less date-times as LOCAL time.
            return t.and_local_timezone(chrono::Local).single().map(|t| t.timestamp_millis());
        }
    }
    // Date-only forms are UTC in JS.
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis())
}

fn iso(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .unwrap_or_default()
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub struct FreshnessOpts<'a> {
    pub repo_root: &'a Path,
    pub evidence: &'a [FreshnessEvidence],
    pub now_iso: &'a str,
    /// `Some(meta)` injects metadata; `None` reads meta.json under `repo_root`.
    pub meta: Option<Option<IndexMeta>>,
    /// Commits since the index was built (from `commits_since`).
    pub commits_since_index: Option<i64>,
    /// Whether the config has ANY runtime connector stanza (from `report.sourceStatus`):
    /// zero ⇒ a neutral statement of the evidence basis; configured-but-empty ⇒ point at
    /// `horus doctor`. Absent (legacy callers) ⇒ the neutral statement.
    pub any_runtime_connector: Option<bool>,
}

/// Derive a freshness summary from the index metadata + the report's evidence.
pub fn compute_freshness(opts: FreshnessOpts<'_>) -> Freshness {
    let now = parse_ms(opts.now_iso);
    let meta = match opts.meta {
        Some(m) => m,
        None => read_index_meta(opts.repo_root),
    };
    let commits_since_index = opts.commits_since_index;
    let mut caveats = Vec::new();

    // ── Code index age ──────────────────────────────────────────────────────
    let mut index_age_ms = None;
    let mut index_age_label = "index age unknown".to_string();
    let mut index_stale = false;
    let indexed_at = meta.as_ref().and_then(|m| m.last_indexed_at.as_deref()).filter(|s| !s.is_empty()).and_then(parse_ms);
    match (indexed_at, now) {
        (Some(at), Some(now)) => {
            let age = (now - at).max(0);
            index_age_ms = Some(age);
            index_age_label = format!("indexed {} ago", human_age(age));
            index_stale = age > STALE_INDEX_MS;
            if index_stale {
                caveats.push(format!(
                    "code index is {} old — re-run `horus init` so analysis reflects current code",
                    human_age(age)
                ));
            }
        }
        // ponytail: an unparseable `now` with a valid index date yields NaN in TS (label "indexed NaNd ago");
        // treated as unknown here — callers always pass a valid ISO now.
        _ => caveats.push("code index age unknown (no .horus/source/meta.json) — freshness unverified".into()),
    }

    // ── Index drift vs git ───────────────────────────────────────────────────
    if let Some(n) = commits_since_index.filter(|n| *n > 0) {
        caveats.push(format!("{n} commit(s) since the last index — re-run `horus init` so analysis reflects current code"));
    }

    // ── Runtime evidence window ─────────────────────────────────────────────
    let runtime: Vec<&FreshnessEvidence> = opts
        .evidence
        .iter()
        .filter(|e| e.source.as_deref().is_some_and(|s| RUNTIME_SOURCES.contains(&s)))
        .collect();
    let runtime_sources: Vec<String> = runtime
        .iter()
        .filter_map(|e| e.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut stamps: Vec<i64> =
        runtime.iter().filter_map(|e| e.timestamp.as_deref().filter(|t| !t.is_empty()).and_then(parse_ms)).collect();
    stamps.sort_unstable();
    let runtime_window = match (stamps.first(), stamps.last()) {
        (Some(a), Some(b)) => Some(RuntimeWindow { from_iso: iso(*a), to_iso: iso(*b) }),
        _ => None,
    };
    if runtime.is_empty() {
        caveats.push(if opts.any_runtime_connector == Some(true) {
            "no runtime evidence collected despite configured connectors — check `horus doctor`".into()
        } else {
            "no runtime evidence — findings rest on code, git history, and topology".into()
        });
    }

    Freshness { index_age_ms, index_age_label, index_stale, commits_since_index, runtime_window, runtime_sources, caveats }
}

/// Render the freshness summary as a dim banner (text/markdown output).
pub fn render_freshness(f: &Freshness) -> String {
    let mut lines = Vec::new();
    let behind = match f.commits_since_index {
        Some(n) if n > 0 => format!(" ({n} behind)"),
        _ => String::new(),
    };
    let label = format!("{}{behind}", f.index_age_label);
    let idx = if f.index_stale || !behind.is_empty() { yellow(&label) } else { label };
    let runtime = match &f.runtime_window {
        Some(w) => {
            let sources =
                if f.runtime_sources.is_empty() { String::new() } else { format!(" ({})", f.runtime_sources.join(", ")) };
            format!("runtime {}→{}{sources}", &w.from_iso[..10], &w.to_iso[..10])
        }
        None => "no runtime window".into(),
    };
    lines.push(dim(&format!("Freshness: code {idx} · {runtime}")));
    for c in &f.caveats {
        lines.push(yellow(&format!("  ⚠ {c}")));
    }
    lines.join("\n")
}
