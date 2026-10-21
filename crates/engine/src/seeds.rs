//! Seed ranking (HOR-39) and THE canonical symbol-query resolver.
//!
//! Search returns several candidate symbols for a vague hint; we should not lock
//! onto a tiny helper. Prefer architectural entry points (resolver / controller /
//! service / route / worker) over utils, scripts, and legacy/migration code.

use std::collections::HashSet;
use std::sync::LazyLock;

use anyhow::Result;
use horus_core::{classify_path, PathKind, Symbol};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::code_provider::CodeProvider;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RankedSeed {
    pub symbol: Symbol,
    pub score: f64,
    pub role: String,
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).unwrap());
    };
}

re!(PREFER, r"(?i)resolver|controller|(?-u:\b)service(?-u:\b)|route|router|handler|gateway|processor|worker|consumer|repository|usecase|use-case|endpoint");
re!(DEMOTE, r"(?i)(?-u:\b)util|helper|(?-u:\b)script|backfill|legacy|migration|seeder|fixture|(?-u:\b)mock(?-u:\b)|(?-u:\b)test(?-u:\b)|(?-u:\b)spec(?-u:\b)");
// dogfood GAP H: a PRESENTATION/format helper builds a display artifact — it must not
// outrank the symbol that does the work.
re!(PRESENTATION_NAME, r"^(build|format|render|compose|serialize)[A-Z].*(Message|Markup|Html|Text|Label|Summary|Notification|String)$");
// A boolean PREDICATE is a DECISION point, exempt from the short-symbol getter penalty.
re!(PREDICATE_NAME, r"^(is|has|can|should|was|were|are|does|did|needs|allows?|must)[A-Z]");
// Type/DTO/interface declarations are not where a fault ORIGINATES (HOR-337).
re!(TYPE_SUFFIX, r"(Result|Input|Response|Payload|Args|Dto|Props|Edge|Connection)$");

/// `/^I(?=[A-Z][a-z])/` — regex crate has no lookahead; checked by hand.
fn has_interface_prefix(name: &str) -> bool {
    let mut it = name.chars();
    it.next() == Some('I') && it.next().is_some_and(|c| c.is_ascii_uppercase()) && it.next().is_some_and(|c| c.is_ascii_lowercase())
}

/// True when a symbol NAME follows type/DTO/interface declaration conventions.
pub fn is_type_like_name(name: &str) -> bool {
    TYPE_SUFFIX.is_match(name) || has_interface_prefix(name)
}

// HOR-447: auto-generated codegen artifacts are never the incident surface.
re!(CODEGEN_PATH_RE, r"(?i)(^|/)(?:__generated__|generated)/");
re!(CODEGEN_FILE_RE, r"(?i)(?:(?:^|/)generated|[._-](?:generated|gen))\.[jt]sx?$");
re!(GQL_GEN_FILE_RE, r"(?i)\.(?:graphql|gql)\.[jt]sx?$");
/// True when a file path looks auto-generated (codegen).
pub fn is_codegen_path(file_path: &str) -> bool {
    CODEGEN_PATH_RE.is_match(file_path) || CODEGEN_FILE_RE.is_match(file_path) || GQL_GEN_FILE_RE.is_match(file_path)
}

// HOR-447: a symbol's graph KIND is the prefix of its id (`<kind>:<path>:<name>`).
re!(TYPE_DECL_KIND_RE, r"(?i)^(?:type_alias|typealias|type|interface|enum)$");
fn id_kind(s: &Symbol) -> &str {
    s.id.split(':').next().unwrap_or("")
}
pub fn is_type_declaration_symbol(s: &Symbol) -> bool {
    TYPE_DECL_KIND_RE.is_match(id_kind(s))
}

/// Derive the executable counterpart name for a type-like name, or None.
/// e.g. "SyncBrandFulfillmentsResult" -> "SyncBrandFulfillments"; "IOrderService" -> "OrderService".
pub fn executable_base_name(name: &str) -> Option<String> {
    let mut stripped = TYPE_SUFFIX.replace(name, "").into_owned();
    if has_interface_prefix(&stripped) {
        stripped.remove(0);
    }
    if stripped != name && stripped.chars().count() >= 4 {
        Some(stripped)
    } else {
        None
    }
}

/// A `Class.method` or `path/to/file:symbol` disambiguator parsed out of a hint (HOR-337).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedQualifier {
    /// The bare symbol/method name (the part after the dot or colon).
    pub symbol: String,
    /// The container — a class name (`Foo.bar`) or a file-path fragment (`path:symbol`).
    pub container: String,
    /// True when the qualifier is the `path:symbol` form.
    pub is_path: bool,
}

const PATH_QUALIFIER_SRC: &str = r"((?:[\w.@/-]*/[\w.@/-]+)|(?:[\w@/-]+\.[A-Za-z]{1,5})):([A-Za-z_$][\w$]*)";
// <left>:<ident> where <left> looks like a path (contains a slash or a file extension).
re!(PATH_QUALIFIER, r"(?:^|[\s(])((?:[\w.@/-]*/[\w.@/-]+)|(?:[\w@/-]+\.[A-Za-z]{1,5})):([A-Za-z_$][\w$]*)");
// Capitalised container (class convention) dot method — avoids matching `file.ts` / `obj.x`.
re!(CLASS_QUALIFIER, r"(?-u:\b)([A-Z][A-Za-z0-9_]*)\.([A-Za-z_$][\w$]*)(?-u:\b)");
re!(LEADING_SLASHES, r"^\.?/+");

/// Parse a `Class.method` or `path/to/file:symbol` disambiguator out of a hint.
pub fn parse_seed_qualifier(hint: &str) -> Option<SeedQualifier> {
    if let Some(m) = PATH_QUALIFIER.captures(hint) {
        let container = LEADING_SLASHES.replace(&m[1], "").into_owned();
        let symbol = &m[2];
        if container.chars().count() >= 2 && symbol.chars().count() >= 2 {
            return Some(SeedQualifier { symbol: symbol.into(), container, is_path: true });
        }
    }
    if let Some(m) = CLASS_QUALIFIER.captures(hint) {
        if m[1].chars().count() >= 2 && m[2].chars().count() >= 2 {
            return Some(SeedQualifier { symbol: m[2].into(), container: m[1].into(), is_path: false });
        }
    }
    None
}

// HOR-385: named-symbol extraction tiers (most-specific first).
re!(QUOTED_SYMBOL, r"[`'\x22]([A-Za-z_$][\w$.]*)[`'\x22]");
re!(PASCAL_SYMBOL, r"(?-u:\b)([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+)(?-u:\b)");
re!(CAMEL_SYMBOL, r"(?-u:\b)([a-z][a-z0-9]*(?:[A-Z][a-z0-9]+)+)(?-u:\b)");
re!(SNAKE_SYMBOL, r"(?-u:\b)([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?-u:\b)");

/// HOR-385: extract the symbol name(s) a structural hint refers to. Tiered extraction
/// (qualified → quoted → PascalCase → camelCase → snake_case); a higher tier masks the
/// text it claims. The result is ordered by SOURCE-STRING POSITION, not tier.
pub fn parse_named_symbols(hint: &str) -> Vec<String> {
    if hint.is_empty() {
        return vec![];
    }
    let mut found: Vec<(String, usize)> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    // Mutable mask: a claimed span is blanked (same byte length) before a lower tier runs.
    let mut masked = hint.to_string();
    fn consume(masked: &mut String, start: usize, end: usize) {
        masked.replace_range(start..end, &" ".repeat(end - start));
    }
    let mut push = |name: &str, index: usize| {
        if name.chars().count() < 2 {
            return; // single chars are never a symbol pin
        }
        let key = name.to_lowercase();
        if seen.contains(&key) {
            return;
        }
        seen.insert(key);
        found.push((name.to_string(), index));
    };

    // Tier 1: qualified — pin the symbol part, claim the whole span.
    for re in [&*PATH_QUALIFIER, &*CLASS_QUALIFIER] {
        let spans: Vec<(usize, usize, String, usize)> = re
            .captures_iter(&masked)
            .filter_map(|m| {
                let whole = m.get(0)?;
                let container = m.get(1)?.as_str();
                let symbol = m.get(2)?;
                if container.chars().count() >= 2 && symbol.as_str().chars().count() >= 2 {
                    let sym_pos = whole.start() + whole.as_str().rfind(symbol.as_str()).unwrap_or(0);
                    Some((whole.start(), whole.end(), symbol.as_str().to_string(), sym_pos))
                } else {
                    None
                }
            })
            .collect();
        for (start, end, symbol, sym_pos) in spans {
            push(&symbol, sym_pos);
            consume(&mut masked, start, end);
        }
    }

    // Tiers 2-5: quoted, PascalCase, camelCase, snake_case.
    for re in [&*QUOTED_SYMBOL, &*PASCAL_SYMBOL, &*CAMEL_SYMBOL, &*SNAKE_SYMBOL] {
        let spans: Vec<(usize, usize, String, usize)> = re
            .captures_iter(&masked)
            .filter_map(|m| {
                let whole = m.get(0)?;
                let name = m.get(1)?;
                let pos = whole.start() + whole.as_str().find(name.as_str()).unwrap_or(0);
                Some((whole.start(), whole.end(), name.as_str().to_string(), pos))
            })
            .collect();
        for (start, end, name, pos) in spans {
            push(&name, pos);
            consume(&mut masked, start, end);
        }
    }

    found.sort_by_key(|f| f.1);
    found.into_iter().map(|f| f.0).collect()
}

re!(IDENT_RE, r"^[A-Za-z_$][\w$]*$");

/// The symbol's owning container (class/receiver), from `className` or the graph id
/// (`<kind>:<path>:<Owner>.<name>`).
pub fn symbol_owner(s: &Symbol) -> Option<String> {
    if let Some(c) = s.class_name.as_deref().filter(|c| !c.is_empty()) {
        return Some(c.to_string());
    }
    let last_segment = s.id.rsplit(':').next().unwrap_or("");
    if let Some(dot) = last_segment.rfind('.') {
        if dot > 0 {
            let owner = &last_segment[..dot];
            let member = &last_segment[dot + 1..];
            if member.to_lowercase() == s.name.to_lowercase() && IDENT_RE.is_match(owner) {
                return Some(owner.to_string());
            }
        }
    }
    None
}

re!(CAMEL_SPLIT_1, r"([a-z0-9])([A-Z])");
re!(CAMEL_SPLIT_2, r"([A-Z]+)([A-Z][a-z])");
re!(IDENT_SEP, r"[\s_./-]+");

/// Split a camel/Pascal/snake/kebab identifier into lowercase word tokens.
fn ident_tokens(s: &str) -> Vec<String> {
    let s1 = CAMEL_SPLIT_1.replace_all(s, "$1 $2");
    let s2 = CAMEL_SPLIT_2.replace_all(&s1, "$1 $2");
    IDENT_SEP.split(&s2).filter(|t| !t.is_empty()).map(|t| t.to_lowercase()).collect()
}

/// Score contribution for a `Class.method` / `path:symbol` qualifier (HOR-337): +6 for a
/// bare-name match, +40 more when the container matches.
pub fn qualifier_boost(s: &Symbol, q: &SeedQualifier) -> f64 {
    if s.name.to_lowercase() != q.symbol.to_lowercase() {
        return 0.0;
    }
    let mut boost = 6.0;
    let fp = s.file_path.to_lowercase();
    let container_match = if q.is_path {
        fp.contains(&q.container.to_lowercase())
    } else {
        let want = ident_tokens(&q.container);
        let joined = want.join("");
        let owner = symbol_owner(s);
        owner.is_some_and(|o| o.to_lowercase() == q.container.to_lowercase())
            || (!want.is_empty() && want.iter().all(|t| fp.contains(t.as_str())))
            || (!joined.is_empty() && fp.contains(&joined))
            || s.signature.as_deref().is_some_and(|sig| sig.to_lowercase().contains(&q.container.to_lowercase()))
    };
    if container_match {
        boost += 40.0; // decisive: this is the exact symbol the hint named
    }
    boost
}

re!(ROLE_RESOLVER, r"(?i)\.resolver\.|resolver");
re!(ROLE_CONTROLLER, r"(?i)\.controller\.|controller");
re!(ROLE_SERVICE, r"(?i)\.service\.|service");
re!(ROLE_WORKER, r"(?i)processor|worker|consumer");
re!(ROLE_ROUTE, r"(?i)route|router|endpoint|handler|gateway");
re!(ROLE_REPOSITORY, r"(?i)repository|(?-u:\b)repo(?-u:\b)");
re!(ROLE_SCRIPT, r"(?i)(^|/)scripts?/|backfill|migration|seeder");
re!(ROLE_UTIL, r"(?i)util|helper");

/// A coarse architectural role for display.
pub fn seed_role(s: &Symbol) -> String {
    let hay = format!("{} {}", s.name, s.file_path);
    let role = if ROLE_RESOLVER.is_match(&hay) {
        "resolver"
    } else if ROLE_CONTROLLER.is_match(&hay) {
        "controller"
    } else if ROLE_SERVICE.is_match(&hay) {
        "service"
    } else if ROLE_WORKER.is_match(&hay) {
        "worker"
    } else if ROLE_ROUTE.is_match(&hay) {
        "route"
    } else if ROLE_REPOSITORY.is_match(&hay) {
        "repository"
    } else if ROLE_SCRIPT.is_match(&hay) {
        "script"
    } else if ROLE_UTIL.is_match(&hay) {
        "util"
    } else {
        "code"
    };
    role.into()
}

re!(ARCH_FILE_SUFFIX, r"(?i)\.(resolver|controller|service)\.[jt]sx?$");
re!(SCRIPTS_DIR, r"(?i)(^|/)scripts?/");
re!(TEST_DIR, r"(?i)(^|/)(tests?|__tests__|spec)/");
re!(TEST_FILE_TS, r"(?i)(\.|_)(test|spec)\.[jt]sx?$");
re!(TEST_FILE_PY, r"(?i)(^|/)test_[^/]*\.py$");
re!(TEST_FILE_PY2, r"(?i)_test\.py$");
re!(EXAMPLE_DIR, r"(?i)(^|/)(examples?|samples?|demos?|fixtures?|sandbox|playground|docs|docs_src|tutorials?)(/|$)");
re!(FILE_NAME_SYMBOL, r"(?i)\.[jt]sx?$");

/// Score a seed; higher = a more likely investigation entry point.
#[allow(clippy::too_many_arguments)]
pub fn score_seed(
    s: &Symbol,
    index: usize,
    hint_tokens: Option<&[String]>,
    changed_files: Option<&HashSet<String>>,
    hint_has_code: bool,
    qualifier: Option<&SeedQualifier>,
    // HOR-385: `prefer_named` is the PROMPT-named symbol to pin in source-impact mode.
    prefer_named: Option<&str>,
) -> f64 {
    let hay = format!("{} {}", s.name, s.file_path).to_lowercase();
    let mut score = 0.0;
    // Architectural-role signals are SUPPRESSED for a code hint or a named-symbol pin.
    let suppress_role = hint_has_code || prefer_named.is_some();
    if PREFER.is_match(&hay) {
        score += if suppress_role { 0.0 } else { 3.0 };
    }
    if DEMOTE.is_match(&hay) {
        score -= 3.0;
    }
    // GAP H: a presentation/format helper is not the failing actor.
    if PRESENTATION_NAME.is_match(&s.name) {
        score -= 3.0;
    }
    // Demote type/DTO/interface-named symbols (HOR-337).
    if is_type_like_name(&s.name) {
        score -= 4.0;
    }
    // Demote thin getters/passthroughs (a few lines), except boolean predicates.
    if let (Some(start), Some(end)) = (s.start_line, s.end_line) {
        if end - start <= 3 && !PREDICATE_NAME.is_match(&s.name) {
            score -= 3.0;
        }
    }
    // Regression investigations (--since): a candidate in a changed file is far more likely.
    if changed_files.is_some_and(|c| c.contains(&s.file_path)) {
        score += 5.0;
    }
    if ARCH_FILE_SUFFIX.is_match(&s.file_path) {
        score += if suppress_role { 0.0 } else { 2.0 };
    }
    // Scripts/migrations are rarely the incident surface.
    if SCRIPTS_DIR.is_match(&s.file_path) {
        score -= 2.0;
    }
    // Tests hug hints; the implementation under test should win on a tie (HOR-361).
    if TEST_DIR.is_match(&s.file_path)
        || TEST_FILE_TS.is_match(&s.file_path)
        || TEST_FILE_PY.is_match(&s.file_path)
        || TEST_FILE_PY2.is_match(&s.file_path)
    {
        score -= 4.0;
    }
    // Examples, tutorials, and docs snippets hug hints just like tests (HOR-365).
    if EXAMPLE_DIR.is_match(&s.file_path) {
        score -= 4.0;
    }
    // Tie-break toward earlier search rank (strong for a code hint).
    score += (5.0 - index as f64).max(0.0) * if hint_has_code { 0.8 } else { 0.1 };
    // Source relevance: weighted HEAVILY only for a CODE-shaped hint (HOR-430).
    if let Some(sc) = s.score {
        score += sc * if hint_has_code { 8.0 } else { 2.0 };
    }
    // A File node is rarely the right seed.
    if FILE_NAME_SYMBOL.is_match(&s.name) {
        score -= 5.0;
    }
    // HOR-447: demote codegen files and non-executable type declarations.
    if is_codegen_path(&s.file_path) {
        score -= 5.0;
    }
    if is_type_declaration_symbol(s) {
        score -= 6.0;
    }
    // Domain-hint boost: +2 per matching token, capped at +6.
    if let Some(tokens) = hint_tokens.filter(|t| !t.is_empty()) {
        let mut hint_boost = 0.0;
        for tok in tokens {
            if hay.contains(tok.as_str()) {
                hint_boost += 2.0;
                if hint_boost >= 6.0 {
                    break;
                }
            }
        }
        score += hint_boost;
    }
    // Class.method / path:symbol EXACT disambiguator (HOR-337).
    if let Some(q) = qualifier {
        score += qualifier_boost(s, q);
    }
    // HOR-385: decisive boost for the PROMPT-named symbol in source-impact mode.
    if prefer_named.is_some_and(|p| s.name.to_lowercase() == p.to_lowercase()) {
        score += 40.0;
    }
    score
}

/// Test / example / docs / fixture paths that must never be the seed when real source
/// exists — delegates to the ONE shared path classifier.
pub fn is_deprioritized_seed_path(file_path: &str) -> bool {
    matches!(classify_path(file_path), PathKind::Test | PathKind::Docs | PathKind::Example | PathKind::Vendored)
}

/// HOR-447: the FULL set of seeds hard-demoted below real executable code when any exists.
pub fn is_deprioritized_seed(s: &Symbol) -> bool {
    is_deprioritized_seed_path(&s.file_path) || is_codegen_path(&s.file_path) || is_type_declaration_symbol(s)
}

re!(DECLARATION_FILE, r"(?i)\.d\.[cm]?ts$");
/// A TypeScript DECLARATION file (`.d.ts`/`.d.mts`/`.d.cts`).
pub fn is_declaration_file(file_path: &str) -> bool {
    DECLARATION_FILE.is_match(file_path)
}

/// dogfood 0.21.1 (A5): product-vs-deprioritized is a LEXICOGRAPHIC tier for exact/qualified
/// resolution; within the product tier a `.d.ts` namesake is demoted below any impl (HOR-465).
pub fn product_tier(candidates: &[Symbol], include_tests: bool) -> Vec<Symbol> {
    if include_tests {
        return candidates.to_vec();
    }
    let product: Vec<Symbol> = candidates.iter().filter(|s| !is_deprioritized_seed_path(&s.file_path)).cloned().collect();
    let pool = if product.is_empty() { candidates.to_vec() } else { product };
    let impl_: Vec<Symbol> = pool.iter().filter(|s| !is_declaration_file(&s.file_path)).cloned().collect();
    if impl_.is_empty() { pool } else { impl_ }
}

/// HOR-430: a deprioritized candidate the request anchors on exactly (decisive qualifier /
/// prompt-named / high-confidence code-hint hit) is exempt from the hard demotion.
pub fn is_anchored_exact_seed(
    s: &Symbol,
    qualifier: Option<&SeedQualifier>,
    hint_has_code: bool,
    prefer_named: Option<&str>,
) -> bool {
    if qualifier.is_some_and(|q| qualifier_boost(s, q) >= 40.0) {
        return true;
    }
    if prefer_named.is_some_and(|p| s.name.to_lowercase() == p.to_lowercase()) {
        return true;
    }
    if hint_has_code && s.score.is_some_and(|sc| sc >= 0.9) {
        return true;
    }
    false
}

/// Graph kind (the id's `<kind>:` prefix) weight for an exact-name explain query.
fn explain_kind_weight(s: &Symbol) -> f64 {
    match id_kind(s).to_lowercase().as_str() {
        "class" => 4.0,
        "interface" | "enum" => 3.0,
        "function" => 2.0,
        "type_alias" | "typealias" => 1.0,
        _ => 0.0,
    }
}

/// Score one exact-name candidate (shared by `rank_exact_candidates` and `resolve_symbol_query`).
fn score_exact_candidate(query: &str, symbol: &Symbol, include_tests: bool) -> f64 {
    let mut score = 0.0;
    if symbol.name == query {
        score += 8.0; // exact case: Command ≠ command
    }
    score += explain_kind_weight(symbol);
    if (!include_tests && is_deprioritized_seed_path(&symbol.file_path)) || is_codegen_path(&symbol.file_path) {
        score -= 6.0;
    }
    // A .d.ts describes the API; the implementation IS the symbol.
    if is_declaration_file(&symbol.file_path) {
        score -= 3.0;
    }
    // Body size as a centrality proxy, log-dampened.
    let loc = symbol.end_line.unwrap_or(0) - symbol.start_line.unwrap_or(0);
    if loc > 0 {
        score += ((loc + 1) as f64).log2().min(4.0);
    }
    score
}

fn rank_by<F: Fn(&Symbol) -> f64>(pool: &[Symbol], score: F) -> Vec<Symbol> {
    let mut scored: Vec<(f64, usize, &Symbol)> = pool.iter().enumerate().map(|(i, s)| (score(s), i, s)).collect();
    scored.sort_by(|a, b| if a.0 == b.0 { a.1.cmp(&b.1) } else { crate::js::cmp_f64(b.0, a.0) });
    scored.into_iter().map(|(_, _, s)| s.clone()).collect()
}

/// Rank same-named candidates for an exact-name query (`explain Foo`), best first; empty
/// when none match exactly.
pub fn rank_exact_candidates(query: &str, symbols: &[Symbol]) -> Vec<Symbol> {
    let q = query.to_lowercase();
    let exact: Vec<Symbol> = symbols.iter().filter(|s| s.name.to_lowercase() == q).cloned().collect();
    let tier = product_tier(&exact, false);
    let in_tier: HashSet<&str> = tier.iter().map(|s| s.id.as_str()).collect();
    let rest: Vec<Symbol> = exact.iter().filter(|s| !in_tier.contains(s.id.as_str())).cloned().collect();
    let mut out = rank_by(&tier, |s| score_exact_candidate(query, s, false));
    out.extend(rank_by(&rest, |s| score_exact_candidate(query, s, false)));
    out
}

/// How a query resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionKind {
    ExactQualified,
    Exact,
    Fuzzy,
    None,
}

impl ResolutionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolutionKind::ExactQualified => "exact-qualified",
            ResolutionKind::Exact => "exact",
            ResolutionKind::Fuzzy => "fuzzy",
            ResolutionKind::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SymbolResolution {
    pub kind: ResolutionKind,
    /// Best-first, deterministic. `[0]` is the resolution every command must use.
    pub candidates: Vec<Symbol>,
    /// True when ≥2 top-tier exact candidates tie at the top score in different files.
    pub ambiguous: bool,
    pub qualifier: Option<SeedQualifier>,
}

re!(FILE_EXT_RE, r"(?i)^(js|cjs|mjs|jsx|ts|tsx|d|py|go|rs|java|kt|rb|php|cs|c|h|cpp|hpp|json|ya?ml|toml|md|txt|sh|css|html|xml|sql|lock)$");
static PATH_QUALIFIER_WHOLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!("^{PATH_QUALIFIER_SRC}$")).unwrap());
re!(DOTTED_PAIR, r"^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.([A-Za-z_$][\w$]*)$");

/// Parse a WHOLE QUERY as a symbol reference: `Reply.hijack`, `app.use`, `path:sym` are
/// qualified regardless of receiver case; a trailing file extension stays a filename.
pub fn parse_symbol_query(query: &str) -> Option<SeedQualifier> {
    let t = query.trim();
    if let Some(m) = PATH_QUALIFIER_WHOLE.captures(t) {
        let container = LEADING_SLASHES.replace(&m[1], "").into_owned();
        if container.chars().count() >= 2 && m[2].chars().count() >= 2 {
            return Some(SeedQualifier { symbol: m[2].into(), container, is_path: true });
        }
    }
    if t.contains('/') {
        return None; // path-like without the :symbol form
    }
    let m = DOTTED_PAIR.captures(t)?;
    if FILE_EXT_RE.is_match(&m[2]) {
        return None; // `index.js`, `config.yaml`
    }
    let container = m[1].rsplit('.').next().unwrap_or(&m[1]).to_string();
    if container.chars().count() < 2 || m[2].chars().count() < 2 {
        return None;
    }
    Some(SeedQualifier { symbol: m[2].into(), container, is_path: false })
}

/// B2 EXPORTS_ALIAS following: if the head candidate is an alias stub (`aliasOf`) and its
/// implementation is in the pool, promote the impl to the head (same-file preferred).
pub fn redirect_export_alias(candidates: Vec<Symbol>) -> Vec<Symbol> {
    let Some(head) = candidates.first() else { return candidates };
    let Some(alias_of) = head.alias_of.as_deref().filter(|a| !a.is_empty()) else { return candidates };
    let impl_name = alias_of.to_lowercase();
    let head_id = head.id.clone();
    let head_file = head.file_path.clone();
    let impl_ = candidates
        .iter()
        .find(|s| s.id != head_id && s.name.to_lowercase() == impl_name && s.file_path == head_file)
        .or_else(|| candidates.iter().find(|s| s.id != head_id && s.name.to_lowercase() == impl_name))
        .cloned();
    let Some(impl_) = impl_ else { return candidates }; // impl not in pool — keep the stub
    let impl_id = impl_.id.clone();
    let mut out = vec![impl_];
    out.extend(candidates.into_iter().filter(|s| s.id != impl_id));
    out
}

/// Resolve a symbol-shaped query against a candidate pool (default: tests excluded).
pub fn resolve_symbol_query(query: &str, symbols: Vec<Symbol>) -> SymbolResolution {
    resolve_symbol_query_with(query, symbols, false)
}

/// THE shared resolution semantics: exact-qualified > exact > fuzzy; product code before
/// tests (unless `include_tests`); declaration kinds and bigger bodies win; exact case beats
/// case-folded; top ties in different files set `ambiguous`.
pub fn resolve_symbol_query_with(query: &str, symbols: Vec<Symbol>, include_tests: bool) -> SymbolResolution {
    let qualifier = parse_symbol_query(query);
    let target = qualifier.as_ref().map(|q| q.symbol.clone()).unwrap_or_else(|| query.trim().to_string()).to_lowercase();

    let exact_all: Vec<Symbol> = symbols.iter().filter(|s| s.name.to_lowercase() == target).cloned().collect();
    // A5: the product-vs-deprioritized split is decided BEFORE the container qualifier.
    let name_tier = product_tier(&exact_all, include_tests);
    let qualified: Vec<Symbol> = match &qualifier {
        Some(q) => name_tier.iter().filter(|s| qualifier_boost(s, q) >= 40.0).cloned().collect(),
        None => vec![],
    };

    let tier = if qualified.is_empty() { name_tier } else { qualified.clone() };
    let kind = if !qualified.is_empty() {
        ResolutionKind::ExactQualified
    } else if !exact_all.is_empty() {
        ResolutionKind::Exact
    } else if !symbols.is_empty() {
        ResolutionKind::Fuzzy
    } else {
        ResolutionKind::None
    };

    let case_target = qualifier.as_ref().map(|q| q.symbol.clone()).unwrap_or_else(|| query.trim().to_string());
    // A class-owner match is STRONGER evidence than a path-token match (axum dogfood).
    let owner_exact = |s: &Symbol| -> f64 {
        match &qualifier {
            Some(q) if !q.is_path && symbol_owner(s).is_some_and(|o| o.to_lowercase() == q.container.to_lowercase()) => 4.0,
            _ => 0.0,
        }
    };
    let mut scored_tier: Vec<(f64, usize, Symbol)> = tier
        .iter()
        .enumerate()
        .map(|(i, s)| (score_exact_candidate(&case_target, s, include_tests) + owner_exact(s), i, s.clone()))
        .collect();
    scored_tier.sort_by(|a, b| if a.0 == b.0 { a.1.cmp(&b.1) } else { crate::js::cmp_f64(b.0, a.0) });

    // Remainder keeps the provider's relevance order, product code first unless tests requested.
    let in_tier: HashSet<&str> = tier.iter().map(|s| s.id.as_str()).collect();
    let mut rest: Vec<(bool, usize, &Symbol)> = symbols
        .iter()
        .filter(|s| !in_tier.contains(s.id.as_str()))
        .enumerate()
        .map(|(i, s)| (!include_tests && is_deprioritized_seed_path(&s.file_path), i, s))
        .collect();
    rest.sort_by(|a, b| if a.0 == b.0 { a.1.cmp(&b.1) } else if a.0 { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Less });

    let ambiguous = kind != ResolutionKind::Fuzzy
        && kind != ResolutionKind::None
        && scored_tier.len() >= 2
        && scored_tier[0].0 == scored_tier[1].0
        && scored_tier[0].2.file_path != scored_tier[1].2.file_path;

    let mut candidates: Vec<Symbol> = scored_tier.into_iter().map(|(_, _, s)| s).collect();
    candidates.extend(rest.into_iter().map(|(_, _, s)| s.clone()));

    SymbolResolution { kind, candidates: redirect_export_alias(candidates), ambiguous, qualifier }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SeedResolveOptions {
    pub limit: Option<usize>,
    pub include_tests: Option<bool>,
}

/// Search + resolve a symbol-shaped query against the source host — the async entry every
/// command uses. A qualified query also searches the BARE symbol part; an alias-stub head
/// fetches its implementation so `redirect_export_alias` can land on product code.
pub async fn resolve_seed_symbol(
    code: &dyn CodeProvider,
    query: &str,
    opts: SeedResolveOptions,
) -> Result<SymbolResolution> {
    let limit = opts.limit.unwrap_or(20);
    let qualifier = parse_symbol_query(query);
    let mut pool = code.search_symbols(query, Some(limit)).await?;
    if let Some(q) = &qualifier {
        let extra = code.search_symbols(&q.symbol, Some(limit.max(30))).await?;
        let seen: HashSet<String> = pool.iter().map(|s| s.id.clone()).collect();
        pool.extend(extra.into_iter().filter(|s| !seen.contains(&s.id)));
    }
    let include_tests = opts.include_tests.unwrap_or(false);
    let mut resolution = resolve_symbol_query_with(query, pool.clone(), include_tests);
    let head = resolution.candidates.first().cloned();
    if let Some(head) = head {
        if let Some(alias_of) = head.alias_of.as_deref().filter(|a| !a.is_empty()) {
            let lower = alias_of.to_lowercase();
            if !pool.iter().any(|s| s.id != head.id && s.name.to_lowercase() == lower) {
                let impl_hits = code.search_symbols(alias_of, Some(limit.max(20))).await?;
                let seen: HashSet<String> = pool.iter().map(|s| s.id.clone()).collect();
                pool.extend(impl_hits.into_iter().filter(|s| !seen.contains(&s.id)));
                resolution = resolve_symbol_query_with(query, pool, include_tests);
            }
        }
    }
    Ok(resolution)
}

/// Rank seeds best-first. Stable for equal scores (preserves search order). When ANY real
/// candidate exists, deprioritized (test/example/codegen/type-decl) ones are hard-demoted
/// unless anchored (HOR-376 / HOR-430).
pub fn rank_seeds(
    seeds: &[Symbol],
    hint_tokens: Option<&[String]>,
    changed_files: Option<&HashSet<String>>,
    hint_has_code: bool,
    qualifier: Option<&SeedQualifier>,
    prefer_named: Option<&str>,
) -> Vec<RankedSeed> {
    struct Scored<'a> {
        symbol: &'a Symbol,
        score: f64,
        role: String,
        i: usize,
        deprio: bool,
        anchored: bool,
    }
    let mut scored: Vec<Scored> = seeds
        .iter()
        .enumerate()
        .map(|(i, symbol)| Scored {
            symbol,
            score: score_seed(symbol, i, hint_tokens, changed_files, hint_has_code, qualifier, prefer_named),
            role: seed_role(symbol),
            i,
            deprio: is_deprioritized_seed(symbol),
            anchored: is_anchored_exact_seed(symbol, qualifier, hint_has_code, prefer_named),
        })
        .collect();
    let has_real = scored.iter().any(|s| !s.deprio);
    if has_real {
        for s in &mut scored {
            if s.deprio && !s.anchored {
                s.score -= 1000.0;
            }
        }
    }
    scored.sort_by(|a, b| if a.score == b.score { a.i.cmp(&b.i) } else { crate::js::cmp_f64(b.score, a.score) });
    scored.into_iter().map(|s| RankedSeed { symbol: s.symbol.clone(), score: s.score, role: s.role }).collect()
}
