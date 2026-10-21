//! The ONE product/test path classifier.
//!
//! The source graph and change reports were polluted by test fixtures: architecture
//! showed fixture queues, blast-radius was dominated by `*.test.ts`, and change
//! reports counted docs edits as runtime risk. Every consumer classifies through
//! here; the Python source host mirrors these patterns in
//! `horus_source/core/classify.py` — keep the two lists in sync.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    Product,
    Test,
    Docs,
    Example,
    Config,
    Vendored,
}

/// Directory names that mark everything beneath them.
const TEST_DIRS: &[&str] = &[
    "test", "tests", "__tests__", "spec", "specs", "testdata", "fixtures", "__fixtures__",
    "__testfixtures__", "testfixtures", "__mocks__", "e2e",
];
// `www` and `site` are the conventional docs/marketing-site trees in OSS libraries.
const DOCS_DIRS: &[&str] = &["docs", "doc", "docs_src", "website", "www", "site"];
// Bench/demo/sandbox trees are exercised by external runners or exist as documentation.
const EXAMPLE_DIRS: &[&str] = &[
    "examples", "example", "samples", "sample", "demo", "demos", "bench", "benches", "benchmark",
    "benchmarks", "perf", "perf-measures", "runtime-tests", "sandbox", "playground", "tutorial",
    "tutorials",
];
// `.yarn` holds Yarn Berry's vendored blobs; `generated`/`__generated__` hold codegen output.
const VENDORED_DIRS: &[&str] = &[
    "node_modules", "vendor", "vendors", "vendored", "third_party", "third-party", "dist", "build",
    ".venv", "venv", ".yarn", "generated", "__generated__",
];

/// Test-file naming conventions across the indexed languages.
static TEST_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\.(test|spec|tst)\.[^/.]+$|^test_[^/]*\.[^/.]+$|_test\.(py|go|rs)$|^Test[A-Z][^/]*\.java$|Test\.java$|Spec\.(scala|kt)$|^conftest\.py$)").unwrap()
});

/// Config-ish files that are neither runtime code nor tests.
static CONFIG_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|\.)((eslint|prettier|babel|jest|vitest|tsup|vite|webpack|rollup)\.config\.[cm]?[jt]s$|tsconfig[^/]*\.json$|package\.json$|pnpm-(lock|workspace)\.yaml$|pyproject\.toml$|Cargo\.toml$|go\.(mod|sum)$|Dockerfile$|docker-compose[^/]*\.ya?ml$|\.github/)").unwrap()
});

// `.markdown`/`.mdown`/`.mkd` are the long-form Markdown extensions.
static DOCS_FILE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(md|mdx|markdown|mdown|mkd|rst|adoc|txt)$").unwrap());

/// Classify a repo-relative (or absolute) path. Product is the default — the
/// classifier only demotes what it can positively identify.
pub fn classify_path(path: &str) -> PathKind {
    let normalized = path.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or(&normalized);
    let lower = normalized.to_lowercase();
    let mut segments: Vec<&str> = lower.split('/').collect();
    segments.pop();

    if segments.iter().any(|s| VENDORED_DIRS.contains(s)) {
        return PathKind::Vendored;
    }
    if TEST_FILE_RE.is_match(base) {
        return PathKind::Test;
    }
    for seg in &segments {
        if TEST_DIRS.contains(seg) || seg.starts_with("test_") {
            return PathKind::Test;
        }
        if DOCS_DIRS.contains(seg) {
            return PathKind::Docs;
        }
        if EXAMPLE_DIRS.contains(seg) {
            return PathKind::Example;
        }
    }
    if DOCS_FILE_RE.is_match(base) {
        return PathKind::Docs;
    }
    if CONFIG_FILE_RE.is_match(&normalized) {
        return PathKind::Config;
    }
    PathKind::Product
}

/// True when the path is product code (the traversal/display default).
pub fn is_product_path(path: &str) -> bool {
    classify_path(path) == PathKind::Product
}

/// Bucket for change reports: `runtime` = product code shipped to production; the rest is context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeBucket {
    Runtime,
    Test,
    Docs,
    Config,
}

pub fn bucket_for_change(path: &str) -> ChangeBucket {
    match classify_path(path) {
        PathKind::Test => ChangeBucket::Test,
        PathKind::Docs | PathKind::Example => ChangeBucket::Docs,
        PathKind::Config | PathKind::Vendored => ChangeBucket::Config,
        PathKind::Product => ChangeBucket::Runtime,
    }
}
