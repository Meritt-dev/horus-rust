//! Port of `packages/cli/src/lib/own-packages.ts` — manifest-derived package names of the
//! CURRENT repo (dogfood cycle-2 N2). External-system detection must skip the repo's OWN
//! package, and the horus project label is often not the package name. Best-effort:
//! unreadable/missing manifests contribute nothing.

use std::path::Path;
use std::sync::LazyLock;

use indexmap::IndexSet;
use regex::Regex;

static TOML_NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^\s*name\s*=\s*["']([^"']+)["']"#).unwrap());
static GO_MODULE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^module\s+(\S+)").unwrap());

/// Detect this repo's package names from its manifests (+ the directory basename).
pub fn detect_own_packages(repo_root: &Path) -> Vec<String> {
    let mut names: IndexSet<String> = IndexSet::new();
    let read = |rel: &str| std::fs::read_to_string(repo_root.join(rel)).ok();

    // package.json — strip a scope (@org/name → name matches content markers).
    if let Some(pkg) = read("package.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&pkg) {
            if let Some(name) = v.get("name").and_then(|n| n.as_str()).filter(|n| !n.is_empty()) {
                names.insert(name.to_string());
                if let Some(bare) = name.rsplit('/').next().filter(|b| !b.is_empty()) {
                    names.insert(bare.to_string());
                }
            }
        }
    }

    // pyproject.toml — [project] name = "..." (PEP 621), or poetry's [tool.poetry] name.
    if let Some(py) = read("pyproject.toml") {
        if let Some(m) = TOML_NAME_RE.captures(&py) {
            names.insert(m[1].to_string());
        }
    }

    // go.mod — module github.com/org/name → name.
    if let Some(gomod) = read("go.mod") {
        if let Some(tail) = GO_MODULE_RE.captures(&gomod).and_then(|m| m[1].rsplit('/').next().map(String::from)) {
            if !tail.is_empty() {
                names.insert(tail);
            }
        }
    }

    // Cargo.toml — [package] name = "...".
    if let Some(cargo) = read("Cargo.toml") {
        if let Some(m) = TOML_NAME_RE.captures(&cargo) {
            names.insert(m[1].to_string());
        }
    }

    // The directory basename is a decent last-resort candidate (clone dir = package).
    if let Some(dir) = repo_root.file_name().and_then(|d| d.to_str()).filter(|d| !d.is_empty()) {
        names.insert(dir.to_string());
    }

    names.into_iter().collect()
}
