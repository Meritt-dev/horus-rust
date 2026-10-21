//! The ONE queue-edge hygiene module.
//!
//! The stitcher's content-search extraction can pick up queue-name look-alikes from
//! test fixtures, template placeholders and malformed multiline code fragments.
//! Every consumer of `queue_edges` filters through here so a garbage edge can never
//! be stored or rendered twice.
//!
//! Rules (in order):
//!  1. Name plausibility — reject empty/oversized names and template/code characters.
//!  2. Fixture-only edges — producer AND worker both outside product code.
//!  3. Generic-with-no-files — a bare generic word with zero file evidence.
//!  4. Type-declaration-only edges — every file is a `.d.ts` / `*.interface(s).ts`.
//!  5. Generic-without-a-real-worker (group level) — a generic/enum-shaped name
//!     survives only when a NAMED worker symbol in a product file vouches for it.

use crate::path_classify::is_product_path;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Bare generic words that only ever name a REAL queue alongside file evidence.
pub const GENERIC_QUEUE_NAMES: &[&str] = &[
    "name", "queue", "queues", "test", "example", "sample", "demo", "default", "data", "items",
    "jobs", "events", "messages", "tasks", "emails", "reports", "alpha", "beta", "seed",
    "seed_products",
];

/// True when `name` is a bare generic word (case-insensitive).
pub fn is_generic_queue_name(name: &str) -> bool {
    GENERIC_QUEUE_NAMES.contains(&name.to_lowercase().as_str())
}

static CONSTANT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$").unwrap());
static IMPLAUSIBLE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"[\s<>{}()`"';$]"#).unwrap());
static ENUM_FILE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(enum|constant|attribute|telemetry)").unwrap());
static DTS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.d\.[cm]?ts$").unwrap());
static INTERFACE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.interfaces?\.[cm]?ts$").unwrap());
static IDENT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*$").unwrap());
static FILE_SHAPED_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.[a-z]{1,4}$").unwrap());

/// A SCREAMING_SNAKE_CASE constant/enum-member name (≥2 segments) — the stitcher grazed an
/// enum key, not a queue. Survives only if a REAL worker vouches for it.
pub fn is_constant_shaped_queue_name(name: &str) -> bool {
    CONSTANT_RE.is_match(name)
}

fn needs_worker_vouch(name: &str) -> bool {
    is_generic_queue_name(name) || is_constant_shaped_queue_name(name)
}

/// Plausible queue identifier: non-empty, bounded, no whitespace and no template/code
/// characters. A name with ≥2 dots is a dotted telemetry/config attribute key.
pub fn is_plausible_queue_name(name: &str) -> bool {
    let len = name.encode_utf16().count();
    if len == 0 || len > 100 {
        return false;
    }
    if IMPLAUSIBLE_RE.is_match(name) {
        return false;
    }
    name.matches('.').count() < 2
}

/// The producer/worker fields hygiene needs — implemented by `QueueEdge`/`NewQueueEdge`.
pub trait QueueEdgeLike {
    fn queue_name(&self) -> &str;
    fn producer_symbol(&self) -> Option<&str>;
    fn producer_file(&self) -> Option<&str>;
    fn worker_symbol(&self) -> Option<&str>;
    fn worker_file(&self) -> Option<&str>;
}

fn files_of(edge: &impl QueueEdgeLike) -> Vec<&str> {
    [edge.producer_file(), edge.worker_file()].into_iter().flatten().filter(|f| !f.is_empty()).collect()
}

fn basename(file: &str) -> &str {
    file.rsplit('/').next().unwrap_or(file)
}

/// Fixture-only edge: every file behind it is non-product code, or — with no file
/// evidence at all — its name is a bare generic word.
pub fn is_fixture_queue_edge(edge: &impl QueueEdgeLike) -> bool {
    let files = files_of(edge);
    if !files.is_empty() {
        return files.iter().all(|f| !is_product_path(f));
    }
    is_generic_queue_name(edge.queue_name())
}

/// A same-file enum/constants edge: producer and worker are two constants in ONE
/// enum/constants/attributes/telemetry module.
fn is_enum_constant_edge(edge: &impl QueueEdgeLike) -> bool {
    let (Some(pf), Some(wf)) = (edge.producer_file(), edge.worker_file()) else { return false };
    if pf.is_empty() || pf != wf {
        return false;
    }
    ENUM_FILE_RE.is_match(&basename(pf).to_lowercase())
}

fn is_type_declaration_file(file: &str) -> bool {
    let base = basename(file).to_lowercase();
    DTS_RE.is_match(&base) || INTERFACE_RE.is_match(&base)
}

/// A type-declaration-only edge: EVERY file behind it is a type-declaration file.
fn is_type_declaration_edge(edge: &impl QueueEdgeLike) -> bool {
    let files = files_of(edge);
    !files.is_empty() && files.iter().all(|f| is_type_declaration_file(f))
}

/// Edge-level keep/drop: plausible name, not fixture-only, not an enum-constant
/// self-match, not a type-declaration-only edge.
pub fn should_keep_queue_edge(edge: &impl QueueEdgeLike) -> bool {
    is_plausible_queue_name(edge.queue_name())
        && !is_fixture_queue_edge(edge)
        && !is_enum_constant_edge(edge)
        && !is_type_declaration_edge(edge)
}

/// A worker that can VOUCH for a generic queue name: a named symbol in a product file.
/// A module-level string match or a test-file worker cannot.
fn is_real_worker_evidence(edge: &impl QueueEdgeLike) -> bool {
    let Some(sym) = edge.worker_symbol().filter(|s| !s.is_empty()) else { return false };
    // A SCREAMING_SNAKE constant is another enum member, not consuming code.
    if is_constant_shaped_queue_name(sym) {
        return false;
    }
    if let Some(file) = edge.worker_file().filter(|f| !f.is_empty()) {
        if !is_product_path(file) {
            return false;
        }
        let base = basename(file);
        // `base.replace(/\.[^.]+$/, '')`
        let stem = match base.rfind('.') {
            Some(i) if i + 1 < base.len() => &base[..i],
            _ => base,
        };
        // Symbol == file name is always a module-level match. Symbol == file STEM is one
        // only when the stem cannot be a code identifier (kebab-case `queue-hygiene`).
        if sym == base {
            return false;
        }
        if sym == stem && !IDENT_RE.is_match(stem) {
            return false;
        }
    }
    !FILE_SHAPED_RE.is_match(sym)
}

/// Filter a set of queue edges down to production-believable ones: edge-level rules,
/// then the group-level rule that a GENERIC queue name survives only when a real
/// worker vouches for it somewhere in the group.
pub fn filter_queue_edges<T: QueueEdgeLike>(edges: Vec<T>) -> Vec<T> {
    let kept: Vec<T> = edges.into_iter().filter(should_keep_queue_edge).collect();
    let has_real_worker: HashSet<String> =
        kept.iter().filter(|e| is_real_worker_evidence(*e)).map(|e| e.queue_name().to_string()).collect();
    kept.into_iter()
        .filter(|e| !needs_worker_vouch(e.queue_name()) || has_real_worker.contains(e.queue_name()))
        .collect()
}
