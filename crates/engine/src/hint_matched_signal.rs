//! HOR-453 — pick the strongest SYMPTOM-matched runtime signal the seed↔error-join
//! couldn't link. Precision-gated: a signal qualifies only when its EVENT_CODE shares a
//! DISTINCTIVE (non-generic) hint token, OR its message shares >=2 distinctive tokens.

use std::sync::LazyLock;

use indexmap::IndexSet;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub struct SignalLike {
    pub key: String,
    pub count: f64,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchVia {
    Code,
    Message,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HintMatchedSignal {
    pub code: String,
    pub count: f64,
    pub message: String,
    /// How the match was made (audit).
    pub via: MatchVia,
}

/// Generic, near-vacuous tokens in an e-commerce/incident domain.
const GENERIC_MATCH_STOP: &[&str] = &[
    "product", "products", "order", "orders", "sync", "syncing", "synced", "fetch", "fetching",
    "api", "data", "service", "services", "update", "updating", "request", "requests", "response",
    "error", "errors", "get", "getting", "save", "saving", "load", "loading", "create", "creating",
    "delete", "failing", "failed", "failure", "broken", "value", "values", "record", "records",
    "found", "not", "with", "the", "and", "for", "from", "into", "this", "that", "when", "returns",
    "returning", "stale", "wrong", "issue", "issues", "problem", "slow", "down", "production",
];

/// Distinctive (>=4 chars, non-generic) hint tokens — the only ones that can match.
pub fn distinctive_hint_tokens(meaningful_hint_tokens: &[String]) -> Vec<String> {
    meaningful_hint_tokens
        .iter()
        .map(|t| t.to_lowercase())
        .collect::<IndexSet<String>>()
        .into_iter()
        .filter(|t| t.chars().count() >= 4 && !GENERIC_MATCH_STOP.contains(&t.as_str()))
        .collect()
}

static NON_ALPHA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-z]+").unwrap());

/// event_code alpha segments of >=4 chars, lowercased.
fn code_segments(code: &str) -> Vec<String> {
    NON_ALPHA
        .split(&code.to_lowercase())
        .filter(|s| s.chars().count() >= 4)
        .map(str::to_string)
        .collect()
}

/// The best symptom-matched signal for the hint, or None. Ranked by match quality
/// (code match first) then volume. Pure.
pub fn select_hint_matched_signal(
    signals: &[SignalLike],
    meaningful_hint_tokens: &[String],
) -> Option<HintMatchedSignal> {
    let distinctive = distinctive_hint_tokens(meaningful_hint_tokens);
    if distinctive.is_empty() {
        return None;
    }

    let mut best: Option<(HintMatchedSignal, f64)> = None;
    for s in signals {
        if s.key.is_empty() || s.key == "(none)" || s.count < 2.0 {
            continue;
        }
        let code_hit = code_segments(&s.key).iter().any(|seg| distinctive.contains(seg));
        let msg = s.message.as_deref().unwrap_or("").to_lowercase();
        let msg_hits = distinctive.iter().filter(|t| msg.contains(t.as_str())).count();
        if !code_hit && msg_hits < 2 {
            continue;
        }
        let score = (if code_hit { 1000.0 } else { 0.0 })
            + msg_hits as f64 * 10.0
            + s.count.max(1.0).log10().min(9.0);
        if best.as_ref().is_none_or(|(_, b)| score > *b) {
            best = Some((
                HintMatchedSignal {
                    code: s.key.clone(),
                    count: s.count,
                    message: s.message.clone().unwrap_or_default(),
                    via: if code_hit { MatchVia::Code } else { MatchVia::Message },
                },
                score,
            ));
        }
    }
    best.map(|(r, _)| r)
}
