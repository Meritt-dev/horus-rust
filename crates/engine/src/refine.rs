//! HOR-21 — Conversational investigation refinement (deterministic v1). Reuses a persisted
//! report's evidence to apply a follow-up directive without re-querying any connector.

use crate::score_cause::CauseCandidate;
use crate::types::{evidence_kind_name, InvestigationReport};
use crate::validate::ValidatedHypothesis;
use horus_core::Evidence;
use indexmap::IndexSet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefineMode {
    Focus,
    Ignore,
    Mixed,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefinedView {
    pub directive: String,
    pub mode: RefineMode,
    pub topics: Vec<String>,
    pub hypotheses: Vec<ValidatedHypothesis>,
    pub suspected_causes: Vec<CauseCandidate>,
    pub evidence: Vec<Evidence>,
    pub note: String,
}

pub struct TopicEntry {
    pub name: &'static str,
    pub keywords: &'static [&'static str],
    pub categories: &'static [&'static str],
    pub kinds: &'static [&'static str],
}

pub const TOPIC_MAP: &[TopicEntry] = &[
    TopicEntry { name: "queue", keywords: &["queue", "backlog", "enqueue", "drain"], categories: &["queue-backlog"], kinds: &["queue-edge"] },
    TopicEntry { name: "worker", keywords: &["worker", "processor", "slowdown", "stall", "consume"], categories: &["worker-slowdown"], kinds: &["queue-edge"] },
    TopicEntry {
        name: "deployment",
        keywords: &["deploy", "deployment", "change", "commit", "regression", "shipped", "release"],
        categories: &["deployment-regression"],
        kinds: &["commit"],
    },
    TopicEntry { name: "api", keywords: &["api", "external", "upstream", "latency"], categories: &["external-api-latency"], kinds: &["metric"] },
    TopicEntry { name: "retry", keywords: &["retry", "storm"], categories: &["retry-storm"], kinds: &["log"] },
    TopicEntry { name: "infra", keywords: &["infra", "infrastructure", "redis", "database", "network"], categories: &["infrastructure"], kinds: &["redis-key"] },
];

// Stop-words and mode verbs stripped before text-based fallback matching.
const STOP_WORDS: &[&str] = &[
    "on", "the", "a", "an", "at", "in", "of", "and", "or", "for", "with", "by", "to", "from", "that", "this", "is", "are",
    "was", "were", "it", "be", "about", "focus", "ignore", "exclude", "only", "just", "concentrate", "look", "without",
    "skip", "drop",
];

static FOCUS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(focus|only|just|concentrate|look at)\b").unwrap());
static IGNORE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(ignore|exclude|without|skip|drop)\b").unwrap());
static CLAUSE_SPLIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+and\s+|\s*,\s*").unwrap());
static NON_WORD_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^\w\s]").unwrap());
static WS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static QUESTION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\?|\b(where|which|what|how|why|when|does|do|is|are|can|should)\b").unwrap());

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verb {
    Focus,
    Ignore,
}

fn detect_mode(d: &str) -> Option<Verb> {
    if IGNORE_RE.is_match(d) {
        return Some(Verb::Ignore);
    }
    if FOCUS_RE.is_match(d) {
        return Some(Verb::Focus);
    }
    None
}

/// Split a mixed directive into focus/ignore clauses by "and" / "," separators.
fn split_into_clauses(d: &str) -> Vec<(String, Verb)> {
    CLAUSE_SPLIT_RE
        .split(d)
        .filter_map(|part| {
            let trimmed = part.trim();
            if FOCUS_RE.is_match(trimmed) {
                Some((trimmed.to_string(), Verb::Focus))
            } else if IGNORE_RE.is_match(trimmed) {
                Some((trimmed.to_string(), Verb::Ignore))
            } else {
                None
            }
        })
        .collect()
}

fn matched_topics(d: &str) -> Vec<String> {
    TOPIC_MAP.iter().filter(|t| t.keywords.iter().any(|k| d.contains(k))).map(|t| t.name.to_string()).collect()
}

fn union_of(topics: &[String], pick: fn(&TopicEntry) -> &'static [&'static str]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for t in topics {
        if let Some(entry) = TOPIC_MAP.iter().find(|e| e.name == t) {
            for c in pick(entry) {
                if !out.iter().any(|x| x == c) {
                    out.push(c.to_string());
                }
            }
        }
    }
    out
}

fn union_categories(topics: &[String]) -> Vec<String> {
    union_of(topics, |e| e.categories)
}
fn union_kinds(topics: &[String]) -> Vec<String> {
    union_of(topics, |e| e.kinds)
}
fn topic_keywords(topics: &[String]) -> Vec<String> {
    union_of(topics, |e| e.keywords)
}

/// Extract significant words from a free-text directive for text-based fallback filtering.
fn extract_significant_terms(directive: &str) -> Vec<String> {
    let lowered = directive.to_lowercase();
    let cleaned = NON_WORD_RE.replace_all(&lowered, " ");
    WS_RE
        .split(&cleaned)
        .filter(|w| w.chars().count() > 2 && !STOP_WORDS.contains(w))
        .map(String::from)
        .collect()
}

fn dedupe(items: Vec<String>) -> Vec<String> {
    items.into_iter().collect::<IndexSet<_>>().into_iter().collect()
}

fn ev_kind(e: &Evidence) -> &'static str {
    evidence_kind_name(e.kind)
}

fn contains_any(text: &str, terms: &[String]) -> bool {
    let lower = text.to_lowercase();
    terms.iter().any(|t| lower.contains(t.as_str()))
}

/// Apply a directive that contains both focus and ignore verbs — split, apply both.
fn apply_mixed_directive(r: &InvestigationReport, directive: &str, d: &str) -> RefinedView {
    let clauses = split_into_clauses(d);
    let focus_clauses: Vec<&String> = clauses.iter().filter(|c| c.1 == Verb::Focus).map(|c| &c.0).collect();
    let ignore_clauses: Vec<&String> = clauses.iter().filter(|c| c.1 == Verb::Ignore).map(|c| &c.0).collect();

    let focus_topics = dedupe(focus_clauses.iter().flat_map(|c| matched_topics(c)).collect());
    let ignore_topics = dedupe(ignore_clauses.iter().flat_map(|c| matched_topics(c)).collect());

    // Text terms for clauses that didn't match any predefined topic
    let focus_terms: Vec<String> =
        focus_clauses.iter().filter(|c| matched_topics(c).is_empty()).flat_map(|c| extract_significant_terms(c)).collect();
    let ignore_terms: Vec<String> =
        ignore_clauses.iter().filter(|c| matched_topics(c).is_empty()).flat_map(|c| extract_significant_terms(c)).collect();

    let mut hypotheses: Vec<ValidatedHypothesis> = r.hypotheses.clone();
    let mut evidence: Vec<Evidence> = r.evidence.clone();
    let mut suspected_causes: Vec<CauseCandidate> = r.suspected_causes.clone();

    // Apply focus filter (topic-based first, text fallback second)
    if !focus_topics.is_empty() {
        let cats = union_categories(&focus_topics);
        let kinds = union_kinds(&focus_topics);
        let kws = topic_keywords(&focus_topics);
        hypotheses.retain(|h| cats.contains(&h.category));
        evidence.retain(|e| kinds.iter().any(|k| k == ev_kind(e)) || ev_kind(e) == "symbol");
        let filtered: Vec<CauseCandidate> = suspected_causes.iter().filter(|c| contains_any(&c.title, &kws)).cloned().collect();
        if !filtered.is_empty() {
            suspected_causes = filtered;
        }
    } else if !focus_terms.is_empty() {
        hypotheses.retain(|h| contains_any(&h.statement, &focus_terms) || contains_any(&h.category, &focus_terms));
        evidence.retain(|e| contains_any(&e.title, &focus_terms) || contains_any(ev_kind(e), &focus_terms));
        let filtered: Vec<CauseCandidate> = suspected_causes.iter().filter(|c| contains_any(&c.title, &focus_terms)).cloned().collect();
        if !filtered.is_empty() {
            suspected_causes = filtered;
        }
    }

    // Apply ignore filter on top of whatever the focus filter produced
    if !ignore_topics.is_empty() {
        let cats = union_categories(&ignore_topics);
        let kinds = union_kinds(&ignore_topics);
        let kws = topic_keywords(&ignore_topics);
        hypotheses.retain(|h| !cats.contains(&h.category));
        evidence.retain(|e| !kinds.iter().any(|k| k == ev_kind(e)));
        suspected_causes.retain(|c| !contains_any(&c.title, &kws));
    }
    if !ignore_terms.is_empty() {
        hypotheses.retain(|h| !contains_any(&h.statement, &ignore_terms) && !contains_any(&h.category, &ignore_terms));
        evidence.retain(|e| !contains_any(&e.title, &ignore_terms) && !contains_any(ev_kind(e), &ignore_terms));
        suspected_causes.retain(|c| !contains_any(&c.title, &ignore_terms));
    }

    let all_topics = dedupe(focus_topics.iter().chain(ignore_topics.iter()).cloned().collect());

    let focus_desc = if !focus_topics.is_empty() {
        Some(format!("focus: {}", focus_topics.join(", ")))
    } else if !focus_terms.is_empty() {
        Some(format!("focus on: {}", focus_terms.join(", ")))
    } else {
        None
    };
    let ignore_desc = if !ignore_topics.is_empty() {
        Some(format!("ignore: {}", ignore_topics.join(", ")))
    } else if !ignore_terms.is_empty() {
        Some(format!("ignore: {}", ignore_terms.join(", ")))
    } else {
        None
    };
    let mode_desc = [focus_desc, ignore_desc].into_iter().flatten().collect::<Vec<_>>().join("; ");
    let note = format!("{mode_desc}. Reused the saved investigation's evidence — no re-query of production.");

    RefinedView { directive: directive.to_string(), mode: RefineMode::Mixed, topics: all_topics, hypotheses, suspected_causes, evidence, note }
}

/// Filter evidence/hypotheses by text match when no predefined topic matched.
fn apply_text_filter(r: &InvestigationReport, directive: &str, mode: Verb, terms: &[String]) -> RefinedView {
    let note = format!(
        "{} terms: {}. No predefined topic matched; filtered by text search. Reused the saved investigation's evidence — no re-query of production.",
        if mode == Verb::Focus { "Focused on" } else { "Excluding" },
        terms.join(", ")
    );

    if mode == Verb::Focus {
        let hypotheses: Vec<_> =
            r.hypotheses.iter().filter(|h| contains_any(&h.statement, terms) || contains_any(&h.category, terms)).cloned().collect();
        let evidence: Vec<_> = r.evidence.iter().filter(|e| contains_any(&e.title, terms) || contains_any(ev_kind(e), terms)).cloned().collect();
        let suspected_causes: Vec<_> = r.suspected_causes.iter().filter(|c| contains_any(&c.title, terms)).cloned().collect();
        return RefinedView {
            directive: directive.to_string(),
            mode: RefineMode::Focus,
            topics: vec![],
            hypotheses,
            evidence,
            suspected_causes: if suspected_causes.is_empty() { r.suspected_causes.clone() } else { suspected_causes },
            note,
        };
    }

    RefinedView {
        directive: directive.to_string(),
        mode: RefineMode::Ignore,
        topics: vec![],
        hypotheses: r.hypotheses.iter().filter(|h| !contains_any(&h.statement, terms) && !contains_any(&h.category, terms)).cloned().collect(),
        evidence: r.evidence.iter().filter(|e| !contains_any(&e.title, terms) && !contains_any(ev_kind(e), terms)).cloned().collect(),
        suspected_causes: r.suspected_causes.iter().filter(|c| !contains_any(&c.title, terms)).cloned().collect(),
        note,
    }
}

/// Apply a follow-up directive to a persisted investigation report and return a filtered
/// view. Never re-queries any connector — only the data already in `r` is used.
pub fn refine_investigation(r: &InvestigationReport, directive: &str) -> RefinedView {
    let d = directive.to_lowercase();

    // A directive with BOTH a focus and an ignore verb is split into clauses so neither
    // overrides the other (detect_mode alone would read it as pure ignore).
    if FOCUS_RE.is_match(&d) && IGNORE_RE.is_match(&d) {
        return apply_mixed_directive(r, directive, &d);
    }

    let mode = detect_mode(&d);
    let topics = matched_topics(&d);

    if mode.is_none() || topics.is_empty() {
        if let Some(mode) = mode {
            let terms = extract_significant_terms(&d);
            if !terms.is_empty() {
                return apply_text_filter(r, directive, mode, &terms);
            }
        }

        let recognized_list = TOPIC_MAP.iter().map(|t| t.name).collect::<Vec<_>>().join(", ");
        // HOR-331: `horus ask` reuses saved evidence and cannot run a new lookup — for a
        // code-locating QUESTION, be explicit and don't dump the full evidence list.
        let looks_like_question = QUESTION_RE.is_match(directive);
        let note = if looks_like_question {
            format!(
                "This question can't be answered from the saved evidence — `horus ask` reuses the report and does not run a new source/runtime lookup. For a fresh answer run:  horus investigate \"{}\". (To filter the saved evidence instead, use a topic: {recognized_list}.)",
                crate::js::slice_chars(directive, 80)
            )
        } else {
            format!(
                "No specific topic directive recognized. Recognized topics: {recognized_list}. Example usage: \"focus on queue behavior\", \"ignore deployment changes\"."
            )
        };
        return RefinedView {
            directive: directive.to_string(),
            mode: RefineMode::None,
            topics,
            hypotheses: r.hypotheses.clone(),
            suspected_causes: r.suspected_causes.clone(),
            evidence: if looks_like_question { vec![] } else { r.evidence.clone() },
            note,
        };
    }

    let matched_categories = union_categories(&topics);
    let matched_kinds = union_kinds(&topics);
    let keywords = topic_keywords(&topics);

    if mode == Some(Verb::Focus) {
        let hypotheses: Vec<_> = r.hypotheses.iter().filter(|h| matched_categories.contains(&h.category)).cloned().collect();
        let evidence: Vec<_> =
            r.evidence.iter().filter(|e| matched_kinds.iter().any(|k| k == ev_kind(e)) || ev_kind(e) == "symbol").cloned().collect();
        let mut suspected_causes: Vec<_> = r.suspected_causes.iter().filter(|c| contains_any(&c.title, &keywords)).cloned().collect();
        if suspected_causes.is_empty() {
            suspected_causes = r.suspected_causes.clone();
        }
        let note = format!("Focused on {}. Reused the saved investigation's evidence — no re-query of production.", topics.join(", "));
        return RefinedView { directive: directive.to_string(), mode: RefineMode::Focus, topics, hypotheses, suspected_causes, evidence, note };
    }

    let hypotheses: Vec<_> = r.hypotheses.iter().filter(|h| !matched_categories.contains(&h.category)).cloned().collect();
    let evidence: Vec<_> = r.evidence.iter().filter(|e| !matched_kinds.iter().any(|k| k == ev_kind(e))).cloned().collect();
    let suspected_causes: Vec<_> = r.suspected_causes.iter().filter(|c| !contains_any(&c.title, &keywords)).cloned().collect();
    let note = format!("Excluding {}. Reused the saved investigation's evidence — no re-query of production.", topics.join(", "));
    RefinedView { directive: directive.to_string(), mode: RefineMode::Ignore, topics, hypotheses, suspected_causes, evidence, note }
}
