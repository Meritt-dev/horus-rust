//! HOR-446 — source-only DATA-FLOW cause detector.
//!
//! Scans the seed's source body for a small set of HIGH-SIGNAL, tightly-guarded
//! patterns and returns the single best match as a HEDGED, low-prior cause (never a
//! verdict). Text-only (no AST): every pattern pairs a curated vocabulary with a
//! corroborating gate and a deny-list, strips comments first, and returns None on doubt.

use std::sync::LazyLock;

use horus_core::SymbolContext;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::js;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataFlowPattern {
    FixedCadence,
    ExactMatchQuery,
    InPlaceMutation,
    UnawaitedAsyncWrite,
    HardcodedBound,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowFinding {
    pub pattern: DataFlowPattern,
    /// Short matched fragment (for audit + title).
    pub matched: String,
    /// Low prior (0.18–0.22): a candidate in source-only runs, below any genuine cause.
    pub base_score: f64,
    /// Hedged, source-only cause title (includes the seed name).
    pub title: String,
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

re!(BLOCK_COMMENT, r"(?s)/\*.*?\*/");
re!(LINE_COMMENT, r"//[^\n]*");

/// Strip block + line comments so a pattern can't match commented-out or doc code.
fn strip_comments(s: &str) -> String {
    LINE_COMMENT.replace_all(&BLOCK_COMMENT.replace_all(s, " "), " ").into_owned()
}

fn hedged(symbol_name: &str, clause: &str) -> String {
    format!("{symbol_name} could explain this — it {clause}. Source-only signal: verify against runtime evidence.")
}

re!(CONFIG_SRC, r"process\.env|config\.|opts\.|options\.|this\.|props\.|import\.meta");

// 1. fixed-cadence — the most distinctive, lowest-false-positive family.
re!(TIMER, r"(?-u:\b)set(?:Interval|Timeout)\s*\(\s*[^,]+,\s*([0-9_]{3,})\s*\)");
// Backreference-free form of /(['"`])(cron)\1/: one alternation per quote char.
re!(CRON, r#"(?:'(?:\*|[0-9,*/-]+)(?:\s+[0-9,*/-]+){4}'|"(?:\*|[0-9,*/-]+)(?:\s+[0-9,*/-]+){4}"|`(?:\*|[0-9,*/-]+)(?:\s+[0-9,*/-]+){4}`)"#);
re!(CADENCE, r"(?-u:\b)(?:pollInterval|refetchInterval|cadence|intervalMs|tickMs)(?-u:\b)\s*[:=]\s*[0-9_]{2,}");

fn detect_fixed_cadence(body: &str, name: &str) -> Option<DataFlowFinding> {
    if let Some(m) = TIMER.find(body) {
        let frag = js::slice_chars(m.as_str().trim(), 48);
        return Some(DataFlowFinding {
            pattern: DataFlowPattern::FixedCadence,
            title: hedged(name, &format!("polls/schedules on a fixed interval (`{frag}`), so data freshness is bounded by that cadence rather than the event")),
            matched: frag,
            base_score: 0.2,
        });
    }
    if let Some(m) = CRON.find(body) {
        let frag = m.as_str();
        return Some(DataFlowFinding {
            pattern: DataFlowPattern::FixedCadence,
            matched: js::slice_chars(frag, 48),
            base_score: 0.2,
            title: hedged(name, &format!("runs on a fixed cron cadence (`{frag}`), so an effect activates on the next tick, not at its target time")),
        });
    }
    if let Some(m) = CADENCE.find(body) {
        if !CONFIG_SRC.is_match(m.as_str()) {
            let frag = js::slice_chars(m.as_str().trim(), 40);
            return Some(DataFlowFinding {
                pattern: DataFlowPattern::FixedCadence,
                title: hedged(name, &format!("uses a fixed cadence (`{frag}`); the symptom may track that interval")),
                matched: frag,
                base_score: 0.2,
            });
        }
    }
    None
}

// 1b. exact-match-query — an equality lookup with no normalization (HOR-448).
re!(SQL_EQ, r#"(?i)(?-u:\b)WHERE(?-u:\b)[^;]*?["'`]?(?-u:\b)(?-u:\w)+(?-u:\b)["'`]?\s*=\s*[$?:](?-u:\w)*"#);
re!(SQL_NORMALIZED, r"(?i)(?-u:\b)(?:LIKE|ILIKE|LOWER|UPPER|TRIM|SIMILAR|REGEXP)(?-u:\b)");
re!(ORM_FIND, r"\.(?:find|findOne|findFirst|findUnique)\s*\(\s*\{\s*(?-u:\w)+\s*:");

fn detect_exact_match_query(body: &str, name: &str) -> Option<DataFlowFinding> {
    if let Some(m) = SQL_EQ.find(body) {
        if !SQL_NORMALIZED.is_match(m.as_str()) {
            let frag = js::slice_chars(m.as_str().trim(), 48);
            return Some(DataFlowFinding {
                pattern: DataFlowPattern::ExactMatchQuery,
                title: hedged(name, &format!("matches on an exact-equality query (`{frag}`) with no normalization, so a value differing only in formatting (case, whitespace, leading zeros) returns no rows")),
                matched: frag,
                base_score: 0.2,
            });
        }
    }
    // ORM exact-field lookup with an OBJECT-literal arg (Array.prototype.find takes a fn).
    if let Some(m) = ORM_FIND.find(body) {
        let frag = js::slice_chars(m.as_str().trim(), 40);
        return Some(DataFlowFinding {
            pattern: DataFlowPattern::ExactMatchQuery,
            title: hedged(name, &format!("looks up by an exact field match (`{frag}`) with no normalization, so a value differing only in formatting returns no match")),
            matched: frag,
            base_score: 0.2,
        });
    }
    None
}

// 2. in-place-mutation — gated on a reducer/store/mutator context.
re!(MUTATION_CONTEXT, r"(?i)reduc|(?-u:\b)slice(?-u:\b)|store|mutat|(?-u:\b)state(?-u:\b)");
re!(STATE_LIB_IMPORT, r"(?i)redux|zustand|immer|valtio|mobx");
re!(IMMUTABLE_RETURN, r"return\s*\{\s*\.\.\.|=>\s*\(?\s*\{\s*\.\.\.|\.\.\.(?:state|prev|draft)(?-u:\b)");
// `=(?!=)` is checked manually below (regex crate has no lookahead).
re!(MUTATION_ASSIGN, r"(?-u:\b)(state|store|draft|cache|acc|accumulator)(?:\.[A-Za-z0-9_]+)+\s*=");
re!(MUTATION_METHOD, r"(?-u:\b)(state|store|draft|cache)(?:\.[A-Za-z0-9_]+)*\.(?:push|splice|sort|reverse|pop|shift|unshift)\s*\(");

/// First `MUTATION_ASSIGN` match whose `=` is not followed by another `=`.
fn find_assign(body: &str) -> Option<(String, String)> {
    for c in MUTATION_ASSIGN.captures_iter(body) {
        let whole = c.get(0).unwrap();
        if body[whole.end()..].starts_with('=') {
            continue;
        }
        return Some((c.get(1).map(|g| g.as_str()).unwrap_or("").to_string(), whole.as_str().to_string()));
    }
    None
}

fn detect_in_place_mutation(body: &str, ctx: &SymbolContext) -> Option<DataFlowFinding> {
    let hay = format!(
        "{} {} {}",
        ctx.symbol.name,
        ctx.symbol.file_path,
        ctx.symbol.signature.as_deref().unwrap_or("")
    );
    let contextual = MUTATION_CONTEXT.is_match(&hay) || ctx.imports.iter().any(|i| STATE_LIB_IMPORT.is_match(i));
    if !contextual {
        return None;
    }
    // If the body clearly produces a NEW reference (the correct immutable path), don't flag it.
    if IMMUTABLE_RETURN.is_match(body) {
        return None;
    }
    let m = find_assign(body).or_else(|| {
        MUTATION_METHOD
            .captures(body)
            .map(|c| (c.get(1).map(|g| g.as_str()).unwrap_or("").to_string(), c.get(0).unwrap().as_str().to_string()))
    })?;
    let obj = if m.0.is_empty() { "state".to_string() } else { m.0 };
    let frag = js::slice_chars(m.1.trim(), 40);
    Some(DataFlowFinding {
        pattern: DataFlowPattern::InPlaceMutation,
        title: hedged(&ctx.symbol.name, &format!("appears to mutate the shared `{obj}` object in place (`{frag}`) rather than producing a new reference, so downstream readers may observe stale or partially-updated state")),
        matched: frag,
        base_score: 0.2,
    })
}

// 3. unawaited-async-write — a fire-and-forget write whose result is depended on.
re!(ASYNC_KW, r"(?-u:\b)async(?-u:\b)");
re!(AWAIT_KW, r"(?-u:\b)await(?-u:\b)");
re!(CALL_HEAD, r"^([A-Za-z_$][\w.$]*)\s*\(");
re!(STATEMENT_KW, r"^(?:await|return|void|yield|const|let|var|if|for|while|\}|else|switch|throw|case)(?-u:\b)");
re!(LOGGY_FN, r"^(?:emit|log|console|track|debug|warn|error|info|print|notify|next|push|set[A-Z])");
re!(WRITE_LIKE, r"(?i)^(?:save|write|flush|persist|commit|sync|update|insert|upsert|fetch|load|send|post)");
re!(ASYNC_SUFFIX, r"Async$");

fn detect_unawaited_write(body: &str, ctx: &SymbolContext) -> Option<DataFlowFinding> {
    let is_async = ASYNC_KW.is_match(ctx.symbol.signature.as_deref().unwrap_or("")) || AWAIT_KW.is_match(body);
    if !is_async || !AWAIT_KW.is_match(body) {
        return None; // require the seed awaits elsewhere
    }
    let callee_names: std::collections::HashSet<&str> = ctx.callees.iter().map(|c| c.name.as_str()).collect();
    for line in body.split('\n') {
        let t = line.trim();
        let Some(call) = CALL_HEAD.captures(t) else { continue };
        if STATEMENT_KW.is_match(t) {
            continue;
        }
        if t.contains(".then(") || t.contains(".catch(") || t.contains("await ") {
            continue;
        }
        let callee = call.get(1).map(|g| g.as_str()).unwrap_or("");
        let func = callee.rsplit('.').next().unwrap_or("");
        if LOGGY_FN.is_match(func) {
            continue;
        }
        let write_like = WRITE_LIKE.is_match(func) || ASYNC_SUFFIX.is_match(func);
        if !write_like {
            continue;
        }
        if !callee_names.contains(callee) && !callee_names.contains(func) {
            continue; // must be a real callee
        }
        return Some(DataFlowFinding {
            pattern: DataFlowPattern::UnawaitedAsyncWrite,
            matched: js::slice_chars(t, 60),
            base_score: 0.19,
            title: hedged(&ctx.symbol.name, &format!("calls `{func}` without `await` while awaiting elsewhere, so a later read may race ahead of that write")),
        });
    }
    None
}

// 4. hardcoded-bound — a threshold/retry/limit gate against a bare literal, or an exact-equality bail-out.
re!(EQUALITY_FN, r"(?-u:\b)(Object\.is|shallowEqual|isEqual)\s*\(");
re!(BOUND_CMP, r"(?-u:\b)([A-Za-z_$][\w$]*)\s*(?:<=|>=|<|>|===|!==)\s*([0-9]+(?:\.[0-9]+)?)(?-u:\b)");
re!(BOUND_VOCAB, r"(?i)thresh|limit|max|min|retr|attempt|backoff|count|rate|ratio|ttl|timeout|delay|capacity|tolerance|distance|score");
re!(INDEX_LIKE, r"\.length(?-u:\b)|(?-u:\b)idx(?-u:\b)|(?-u:\b)index(?-u:\b)|(?-u:\b)i(?-u:\b)");

fn detect_hardcoded_bound(body: &str, name: &str) -> Option<DataFlowFinding> {
    if let Some(c) = EQUALITY_FN.captures(body) {
        let fn_name = c.get(1).map(|g| g.as_str()).unwrap_or("");
        return Some(DataFlowFinding {
            pattern: DataFlowPattern::HardcodedBound,
            matched: js::slice_chars(c.get(0).unwrap().as_str(), 40),
            base_score: 0.18,
            title: hedged(name, &format!("gates on a reference/shallow equality check (`{fn_name}`), so an in-place or structurally-equal update can be skipped and a change goes unobserved")),
        });
    }
    for m in BOUND_CMP.captures_iter(body) {
        let id = m.get(1).map(|g| g.as_str()).unwrap_or("");
        let n: f64 = m.get(2).and_then(|g| g.as_str().parse().ok()).unwrap_or(f64::NAN);
        if n == 0.0 || n == 1.0 {
            continue; // boundary/index checks are not thresholds
        }
        if !BOUND_VOCAB.is_match(id) {
            continue;
        }
        if INDEX_LIKE.is_match(id) {
            continue;
        }
        let frag = js::slice_chars(m.get(0).unwrap().as_str().trim(), 40);
        return Some(DataFlowFinding {
            pattern: DataFlowPattern::HardcodedBound,
            title: hedged(name, &format!("gates the flow on a fixed bound (`{frag}`), so behavior can flip at that constant independent of any deploy")),
            matched: frag,
            base_score: 0.2,
        });
    }
    None
}

/// Detect the single most-specific source-only data-flow mechanism in the seed's body.
/// Priority order = ascending false-positive risk.
pub fn detect_data_flow_cause(ctx: &SymbolContext) -> Option<DataFlowFinding> {
    let raw = ctx.source_body.as_deref().or(ctx.snippet.as_deref()).unwrap_or("");
    if raw.chars().count() < 40 {
        return None; // too little source to judge — stay silent rather than guess
    }
    let body = strip_comments(raw);
    let nm = &ctx.symbol.name;
    detect_fixed_cadence(&body, nm)
        .or_else(|| detect_exact_match_query(&body, nm))
        .or_else(|| detect_in_place_mutation(&body, ctx))
        .or_else(|| detect_unawaited_write(&body, ctx))
        .or_else(|| detect_hardcoded_bound(&body, nm))
}

/// HOR-448: scan several symbols' contexts in priority order; first match wins.
pub fn detect_data_flow_cause_across(contexts: &[SymbolContext]) -> Option<DataFlowFinding> {
    contexts.iter().find_map(detect_data_flow_cause)
}
