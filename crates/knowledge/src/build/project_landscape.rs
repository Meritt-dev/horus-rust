//! Project-landscape knowledge builder (HOR-293).
//!
//! The first-version `horus init` knowledge pass: derive a `RepositoryProfile`
//! for each repo from its dependency manifest (frameworks, languages, state
//! management, auth, data sources, integrations, scripts) — local-first, no
//! source-intelligence or network required. Deeper extraction layers on top
//! (see `source_graph`) and fills the other snapshot categories.
//!
//! Both Node (`package.json`) and Python (`pyproject.toml` / `setup.cfg` /
//! `setup.py` / `requirements.txt`) repos are supported. setup.py's
//! `install_requires` is parsed best-effort (HOR-418) and requirements.txt is
//! read as a flat dependency list (HOR-419). Provenance only ever cites a
//! manifest that actually exists on disk — never a phantom `package.json`
//! (HOR-407) — and only claims high-confidence "parsed" against a manifest whose
//! dependencies were actually extracted; otherwise it omits the filePath and
//! downgrades confidence rather than lie (HOR-418). A Python repo's dependencies
//! are mapped onto the same framework/datasource/integration tables so its
//! knowledge base is not left empty (HOR-408).

use crate::build::source_graph::{build_knowledge_from_source_graph, derive_external_integrations, SourceGraphExtract, SourceGraphMapOptions};
use crate::schema::*;
use anyhow::Result;
use indexmap::IndexSet;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageJson {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub dependencies: Option<Map<String, Value>>,
    #[serde(default)]
    pub dev_dependencies: Option<Map<String, Value>>,
    #[serde(default)]
    pub scripts: Option<Map<String, Value>>,
}

/// Read + parse a repo's package.json, or None if absent/unreadable.
pub fn read_package_json(repo_path: &Path) -> Option<PackageJson> {
    let text = fs::read_to_string(repo_path.join("package.json")).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    match value {
        // `JSON.parse` → null is falsy in TS, so a literal `null` counts as absent.
        Value::Null => None,
        Value::Object(_) => serde_json::from_value(value).ok().or(Some(PackageJson::default())),
        // Any other JSON scalar/array is truthy in TS: a package.json with no usable fields.
        _ => Some(PackageJson::default()),
    }
}

/// Read a UTF-8 file relative to the repo, or None if absent/unreadable.
fn read_text(repo_path: &Path, file: &str) -> Option<String> {
    fs::read_to_string(repo_path.join(file)).ok()
}

// ── JS/TS detection tables (dependency-name → label) ─────────────────────────
const FRAMEWORKS: &[(&str, &str)] = &[
    ("react", "React"),
    ("next", "Next.js"),
    ("vue", "Vue"),
    ("nuxt", "Nuxt"),
    ("@angular/core", "Angular"),
    ("svelte", "Svelte"),
    ("express", "Express"),
    ("fastify", "Fastify"),
    ("@nestjs/core", "NestJS"),
    ("koa", "Koa"),
    ("type-graphql", "TypeGraphQL"),
    ("@apollo/server", "Apollo Server"),
    ("graphql", "GraphQL"),
    ("commander", "Commander (CLI)"),
];
const STATE: &[(&str, &str)] = &[
    ("redux", "Redux"),
    ("@reduxjs/toolkit", "Redux Toolkit"),
    ("zustand", "Zustand"),
    ("jotai", "Jotai"),
    ("recoil", "Recoil"),
    ("pinia", "Pinia"),
    ("@tanstack/react-query", "React Query"),
    ("@apollo/client", "Apollo Client"),
];
const AUTH: &[(&str, &str)] = &[
    ("jsonwebtoken", "JWT"),
    ("passport", "Passport"),
    ("@clerk/nextjs", "Clerk"),
    ("@clerk/clerk-sdk-node", "Clerk"),
    ("next-auth", "NextAuth"),
    ("firebase", "Firebase Auth"),
    ("firebase-admin", "Firebase Admin"),
];
const DATA_SOURCES: &[(&str, &str)] = &[
    ("pg", "PostgreSQL"),
    ("postgres", "PostgreSQL"),
    ("drizzle-orm", "Drizzle (SQL)"),
    ("mongoose", "MongoDB"),
    ("mongodb", "MongoDB"),
    ("@prisma/client", "Prisma"),
    ("typeorm", "TypeORM"),
    ("redis", "Redis"),
    ("ioredis", "Redis"),
    ("@elastic/elasticsearch", "Elasticsearch"),
];
const INTEGRATIONS: &[(&str, &str)] = &[
    ("stripe", "Stripe"),
    ("shopify", "Shopify"),
    ("@shopify/shopify-api", "Shopify"),
    ("openai", "OpenAI"),
    ("@anthropic-ai/sdk", "Anthropic"),
    ("@aws-sdk/client-s3", "AWS S3"),
    ("twilio", "Twilio"),
    ("resend", "Resend"),
];

// ── Python detection tables (PEP 503-normalized dep name → label) ────────────
// Keys are normalized (lowercase; runs of `-`, `_`, `.` collapsed to `-`) so
// they match the output of pkg_name(); see normalizing in read_python_manifest().
const PY_FRAMEWORKS: &[(&str, &str)] = &[
    ("fastapi", "FastAPI"),
    ("django", "Django"),
    ("flask", "Flask"),
    ("starlette", "Starlette"),
    ("sanic", "Sanic"),
    ("tornado", "Tornado"),
    ("aiohttp", "aiohttp"),
    // task/job queues — no dedicated profile field, surfaced as frameworks.
    ("celery", "Celery (queue)"),
    ("dramatiq", "Dramatiq (queue)"),
    ("rq", "RQ (queue)"),
    ("arq", "arq (queue)"),
];
const PY_STATE: &[(&str, &str)] = &[("redis", "Redis")];
const PY_AUTH: &[(&str, &str)] = &[("pyjwt", "JWT"), ("python-jose", "JWT"), ("authlib", "Authlib")];
const PY_DATA_SOURCES: &[(&str, &str)] = &[
    ("sqlalchemy", "SQLAlchemy"),
    ("tortoise-orm", "Tortoise ORM"),
    ("peewee", "Peewee"),
    ("psycopg", "PostgreSQL"),
    ("psycopg2", "PostgreSQL"),
    ("psycopg2-binary", "PostgreSQL"),
    ("asyncpg", "PostgreSQL"),
    ("pymongo", "MongoDB"),
    ("motor", "MongoDB"),
];
const PY_INTEGRATIONS: &[(&str, &str)] = &[
    ("boto3", "AWS"),
    ("stripe", "Stripe"),
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic"),
    ("sendgrid", "SendGrid"),
];

/// Map a list of dependency names through a label table (deduped, order-stable).
fn detect_names<'a>(table: &[(&str, &'a str)], names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: IndexSet<&str> = IndexSet::new();
    for name in names {
        if let Some((_, label)) = table.iter().find(|(k, _)| *k == name) {
            out.insert(label);
        }
    }
    out.into_iter().map(str::to_string).collect()
}

/// Merge several label lists, preserving first-seen order and de-duping.
fn merge_labels(lists: &[Vec<String>]) -> Vec<String> {
    let mut out: IndexSet<String> = IndexSet::new();
    for list in lists {
        for label in list {
            out.insert(label.clone());
        }
    }
    out.into_iter().collect()
}

// ── Python manifest parsing ──────────────────────────────────────────────────

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

/// Strip a trailing `# comment` that is not inside a quoted string (best-effort).
fn strip_toml_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut quote = '\0';
    for (i, c) in line.char_indices() {
        if in_str {
            if c == quote {
                in_str = false;
            }
        } else if c == '"' || c == '\'' {
            in_str = true;
            quote = c;
        } else if c == '#' {
            return &line[..i];
        }
    }
    line
}

/// Reduce a PEP 508 requirement string (or a bare dependency name) to its
/// PEP 503-normalized project name: drop env markers / URLs / extras / version
/// specifiers, lowercase, and collapse runs of `-`, `_`, `.` to a single `-`.
fn pkg_name(spec: &str) -> String {
    static EXTRAS: OnceLock<Regex> = OnceLock::new();
    static HEAD: OnceLock<Regex> = OnceLock::new();
    static SEPS: OnceLock<Regex> = OnceLock::new();
    let s = spec.trim();
    if s.is_empty() {
        return String::new();
    }
    let s = s.split(';').next().unwrap_or(s); // environment markers
    let s = s.split('@').next().unwrap_or(s); // PEP 508 direct-reference URLs (`name @ url`)
    let s = re(&EXTRAS, r"\[[^\]]*\]").replace_all(s, ""); // extras, e.g. fastapi[all]
    let Some(m) = re(&HEAD, r"^[A-Za-z0-9._-]+").find(&s) else {
        return String::new();
    };
    re(&SEPS, r"[-_.]+").replace_all(&m.as_str().to_lowercase(), "-").into_owned()
}

#[derive(Debug, Clone, Default)]
struct PythonManifest {
    deps: Vec<String>,
    name: Option<String>,
    description: Option<String>,
}

/// `text.split(/\r?\n/)`.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l))
}

fn normalize_deps(deps: Vec<String>) -> Vec<String> {
    deps.iter().map(|d| pkg_name(d)).filter(|d| !d.is_empty()).collect()
}

/// Parse `[project].dependencies` (PEP 621) and Poetry dependency tables.
fn parse_pyproject(text: &str) -> PythonManifest {
    static SECTION: OnceLock<Regex> = OnceLock::new();
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    static QUOTED_ANY: OnceLock<Regex> = OnceLock::new();
    static NAME: OnceLock<Regex> = OnceLock::new();
    static DESC: OnceLock<Regex> = OnceLock::new();
    static DEPS_OPEN: OnceLock<Regex> = OnceLock::new();
    static POETRY_GROUP: OnceLock<Regex> = OnceLock::new();
    static KV: OnceLock<Regex> = OnceLock::new();

    let mut deps: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut section = String::new();
    let mut in_project_deps = false;

    let quoted = |s: &str| -> Vec<String> {
        re(&QUOTED, r#"["']([^"']+)["']"#)
            .find_iter(s)
            .map(|m| {
                let q = m.as_str();
                q[1..q.len() - 1].to_string()
            })
            .collect()
    };
    // The array terminates on a `]` that is NOT inside a quoted requirement
    // string (e.g. the `]` in `sqlalchemy[asyncio]` must not end the array).
    let closes_array = |s: &str| -> bool { re(&QUOTED_ANY, r#"["'][^"']*["']"#).replace_all(s, "").contains(']') };

    for raw in lines(text) {
        let trimmed = strip_toml_comment(raw).trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(sec) = re(&SECTION, r"^\[([^\]]+)\]\s*$").captures(trimmed) {
            let s = sec[1].trim();
            if !s.is_empty() {
                section = s.to_string();
                in_project_deps = false;
                continue;
            }
        }

        if section == "project" {
            if let Some(m) = re(&NAME, r#"^name\s*=\s*["']([^"']+)["']"#).captures(trimmed) {
                name.get_or_insert_with(|| m[1].to_string());
                continue;
            }
            if let Some(m) = re(&DESC, r#"^description\s*=\s*["']([^"']*)["']"#).captures(trimmed) {
                description.get_or_insert_with(|| m[1].to_string());
                continue;
            }
            if re(&DEPS_OPEN, r"^dependencies\s*=\s*\[").is_match(trimmed) {
                let rest = &trimmed[trimmed.find('[').unwrap_or(0)..];
                deps.extend(quoted(rest));
                in_project_deps = !closes_array(rest);
                continue;
            }
            if in_project_deps {
                deps.extend(quoted(trimmed));
                if closes_array(trimmed) {
                    in_project_deps = false;
                }
                continue;
            }
        }

        if section == "tool.poetry" {
            if let Some(m) = re(&NAME, r#"^name\s*=\s*["']([^"']+)["']"#).captures(trimmed) {
                name.get_or_insert_with(|| m[1].to_string());
            }
            if let Some(m) = re(&DESC, r#"^description\s*=\s*["']([^"']*)["']"#).captures(trimmed) {
                description.get_or_insert_with(|| m[1].to_string());
            }
            continue;
        }

        if section == "tool.poetry.dependencies"
            || section == "tool.poetry.dev-dependencies"
            || re(&POETRY_GROUP, r"^tool\.poetry\.group\..+\.dependencies$").is_match(&section)
        {
            if let Some(m) = re(&KV, r"^([A-Za-z0-9._-]+)\s*=").captures(trimmed) {
                let kv = &m[1];
                if kv.to_lowercase() != "python" {
                    deps.push(kv.to_string());
                }
            }
            continue;
        }
    }

    PythonManifest { deps: normalize_deps(deps), name, description }
}

/// Parse `install_requires` and `[metadata]` from a setup.cfg.
fn parse_setup_cfg(text: &str) -> PythonManifest {
    static SECTION: OnceLock<Regex> = OnceLock::new();
    static NAME: OnceLock<Regex> = OnceLock::new();
    static DESC: OnceLock<Regex> = OnceLock::new();
    static IR: OnceLock<Regex> = OnceLock::new();

    let mut deps: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut section = String::new();
    let mut in_install_requires = false;

    for line in lines(text) {
        let trimmed = line.trim();

        if let Some(sec) = re(&SECTION, r"^\[([^\]]+)\]\s*$").captures(trimmed) {
            let s = sec[1].to_string();
            if !s.is_empty() {
                section = s.trim().to_string();
                in_install_requires = false;
                continue;
            }
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        // Indented continuation lines belong to the active multi-line value.
        if in_install_requires && line.starts_with(|c: char| c.is_whitespace()) {
            deps.push(trimmed.to_string());
            continue;
        }
        in_install_requires = false;

        if section == "metadata" {
            if let Some(m) = re(&NAME, r"^name\s*=\s*(.+)$").captures(trimmed) {
                name.get_or_insert_with(|| m[1].trim().to_string());
            }
            if let Some(m) = re(&DESC, r"^description\s*=\s*(.+)$").captures(trimmed) {
                description.get_or_insert_with(|| m[1].trim().to_string());
            }
            continue;
        }
        if section == "options" {
            if let Some(m) = re(&IR, r"^install_requires\s*=\s*(.*)$").captures(trimmed) {
                in_install_requires = true;
                let ir = m[1].trim();
                if !ir.is_empty() {
                    deps.push(ir.to_string()); // rare same-line single dep
                }
            }
        }
    }

    PythonManifest { deps: normalize_deps(deps), name, description }
}

/// Best-effort parse of a setup.py's `install_requires=[...]` list (HOR-418).
/// setup.py is arbitrary Python, so this is intentionally narrow: it grabs the
/// first `install_requires = [ ... ]` literal array and extracts the quoted
/// requirement strings. Dynamically-computed dependency lists (e.g. built from a
/// variable or read from a file) yield nothing — the caller treats an empty
/// result as "not parsed" and refuses to stamp high-confidence provenance.
fn parse_setup_py(text: &str) -> PythonManifest {
    static OPEN: OnceLock<Regex> = OnceLock::new();
    let mut deps: Vec<String> = Vec::new();
    if let Some(open) = re(&OPEN, r"install_requires\s*=\s*\[").find(text) {
        // Scan the array literal quote-aware so a `]` inside a requirement string
        // (e.g. "sqlalchemy[asyncio]") doesn't prematurely terminate the array.
        let mut depth = 1;
        let mut in_str = false;
        let mut quote = '\0';
        let mut cur = String::new();
        for c in text[open.end()..].chars() {
            if depth == 0 {
                break;
            }
            if in_str {
                if c == quote {
                    in_str = false;
                    deps.push(std::mem::take(&mut cur));
                } else {
                    cur.push(c);
                }
            } else if c == '"' || c == '\'' {
                in_str = true;
                quote = c;
                cur.clear();
            } else if c == '[' {
                depth += 1;
            } else if c == ']' {
                depth -= 1;
            }
        }
    }
    PythonManifest { deps: normalize_deps(deps), ..Default::default() }
}

/// Parse a requirements.txt as a flat dependency list (HOR-419): one requirement
/// per line, skipping blanks, `#` comments, and pip directives / option flags
/// (`-r other.txt`, `-e .`, `--hash=...`). Each kept line is normalized via
/// pkg_name(), which also drops inline comments and version/extras specifiers.
fn parse_requirements_txt(text: &str) -> PythonManifest {
    let deps: Vec<String> = lines(text)
        .map(str::trim)
        .filter(|l| !(l.is_empty() || l.starts_with('#') || l.starts_with('-')))
        .map(str::to_string)
        .collect();
    PythonManifest { deps: normalize_deps(deps), ..Default::default() }
}

struct ManifestSet {
    pkg: Option<PackageJson>,
    has_package_json: bool,
    python: PythonManifest,
    has_python: bool,
    /// The single manifest file to cite as provenance, if any exists.
    file_path: Option<&'static str>,
    /// Confidence for the provenance stamp. `High` when the cited manifest's
    /// contents were genuinely parsed; downgraded to `Low` when a Python manifest
    /// exists but none of them yielded extractable dependencies (e.g. a setup.py
    /// that builds install_requires dynamically) — in that case file_path is also
    /// omitted so we never claim a high-confidence parse against an unread file
    /// (HOR-418).
    confidence: Confidence,
}

/// Read every dependency manifest present in a repo (Node + Python).
fn read_manifests(repo_path: &Path) -> ManifestSet {
    let pkg = read_package_json(repo_path);
    let has_package_json = pkg.is_some();

    let pyproject_text = read_text(repo_path, "pyproject.toml");
    let setup_cfg_text = read_text(repo_path, "setup.cfg");
    let setup_py_text = read_text(repo_path, "setup.py");
    let requirements_text = read_text(repo_path, "requirements.txt");

    let mut python = PythonManifest::default();
    // Track which Python manifests actually produced parseable content, so the
    // provenance only cites — at high confidence — a file we genuinely parsed.
    let mut parsed: HashSet<&'static str> = HashSet::new();
    let mut absorb = |file: &'static str, m: PythonManifest| {
        let meaningful = !m.deps.is_empty() || m.name.is_some() || m.description.is_some();
        python.deps.extend(m.deps);
        if python.name.is_none() {
            python.name = m.name;
        }
        if python.description.is_none() {
            python.description = m.description;
        }
        if meaningful {
            parsed.insert(file);
        }
    };
    if let Some(t) = &pyproject_text {
        absorb("pyproject.toml", parse_pyproject(t));
    }
    if let Some(t) = &setup_cfg_text {
        absorb("setup.cfg", parse_setup_cfg(t));
    }
    if let Some(t) = &setup_py_text {
        absorb("setup.py", parse_setup_py(t));
    }
    if let Some(t) = &requirements_text {
        absorb("requirements.txt", parse_requirements_txt(t));
    }

    let has_python = pyproject_text.is_some() || setup_cfg_text.is_some() || setup_py_text.is_some() || requirements_text.is_some();

    // Cite only a manifest that actually exists (HOR-407). package.json wins for
    // mixed repos; otherwise fall back to the first Python manifest we genuinely
    // parsed. If a Python manifest exists but none parsed, cite nothing and
    // downgrade confidence rather than claim a high-confidence parse (HOR-418).
    const PY_CHAIN: [&str; 4] = ["pyproject.toml", "setup.cfg", "setup.py", "requirements.txt"];
    let mut file_path: Option<&'static str> = None;
    let mut confidence = Confidence::High;
    if has_package_json {
        file_path = Some("package.json");
    } else if let Some(cited) = PY_CHAIN.iter().copied().find(|f| parsed.contains(f)) {
        file_path = Some(cited);
    } else if has_python {
        // Detected Python but extracted no dependencies — don't lie about it.
        confidence = Confidence::Low;
    }

    ManifestSet { pkg, has_package_json, python, has_python, file_path, confidence }
}

/// Languages a repo is written in, derived strictly from manifests that exist.
/// JS/TS are only claimed when a real package.json is present (HOR-407); Python
/// when any Python manifest is present. A repo with no manifest gets `[]`.
fn detect_languages(manifests: &ManifestSet, js_deps: &Map<String, Value>) -> Vec<String> {
    let mut langs: IndexSet<&str> = IndexSet::new();
    if manifests.has_package_json {
        if js_deps.contains_key("typescript") || js_deps.keys().any(|d| d.starts_with("@types/")) {
            langs.insert("TypeScript");
        } else {
            langs.insert("JavaScript");
        }
    }
    if manifests.has_python {
        langs.insert("Python");
    }
    langs.into_iter().map(str::to_string).collect()
}

fn infer_role(frameworks: &[String], data_sources: &[String]) -> Option<String> {
    const FE: [&str; 6] = ["React", "Next.js", "Vue", "Nuxt", "Angular", "Svelte"];
    const BE: [&str; 13] = [
        "Express",
        "Fastify",
        "NestJS",
        "Koa",
        "TypeGraphQL",
        "Apollo Server",
        // Python web frameworks.
        "FastAPI",
        "Django",
        "Flask",
        "Starlette",
        "Sanic",
        "Tornado",
        "aiohttp",
    ];
    let has_fe = frameworks.iter().any(|f| FE.contains(&f.as_str()));
    let has_be = frameworks.iter().any(|f| BE.contains(&f.as_str()));
    if frameworks.iter().any(|f| f == "Commander (CLI)") {
        return Some("cli".into());
    }
    if has_fe && has_be {
        return Some("fullstack".into());
    }
    if has_fe {
        return Some("frontend".into());
    }
    if has_be || !data_sources.is_empty() {
        return Some("backend".into());
    }
    None
}

const SCRIPT_KEYS: [&str; 6] = ["start", "dev", "build", "test", "lint", "migrate"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoInput {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    pub project: Option<String>,
    /// HEAD commit the snapshot is built at (recorded on provenance).
    pub git_sha: Option<String>,
    /// ISO timestamp for the snapshot (defaults to now).
    pub now: Option<String>,
    /// Source-intelligence graph pulled from the analysed repo (HOR-408). When
    /// present, its symbols/communities/processes populate the operations, types,
    /// enums, domainConcepts, dataFlows, and runtimeComponents categories — the
    /// rich analyse output the manifest-only pass used to drop. The host serves a
    /// single repo, so `repo` should name it (else the lone repo is assumed).
    pub source_graph: Option<SourceGraphExtract>,
}

/// `new Date().toISOString()` — millisecond-precision UTC.
pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Derive a single repository profile from its dependency manifest(s).
pub fn derive_repository_profile(repo: &RepoInput, opts: &BuildOptions) -> RepositoryProfile {
    let manifests = read_manifests(Path::new(&repo.path));
    let pkg = manifests.pkg.clone().unwrap_or_default();
    // `{ ...dependencies, ...devDependencies }` — insertion order, later keys overwrite in place.
    let mut js_deps: Map<String, Value> = Map::new();
    for (k, v) in pkg.dependencies.iter().flatten().chain(pkg.dev_dependencies.iter().flatten()) {
        js_deps.insert(k.clone(), v.clone());
    }
    let js_names: Vec<&str> = js_deps.keys().map(String::as_str).collect();
    let py_names: Vec<&str> = manifests.python.deps.iter().map(String::as_str).collect();

    let frameworks = merge_labels(&[detect_names(FRAMEWORKS, js_names.iter().copied()), detect_names(PY_FRAMEWORKS, py_names.iter().copied())]);
    let data_sources = merge_labels(&[detect_names(DATA_SOURCES, js_names.iter().copied()), detect_names(PY_DATA_SOURCES, py_names.iter().copied())]);
    let state_management = merge_labels(&[detect_names(STATE, js_names.iter().copied()), detect_names(PY_STATE, py_names.iter().copied())]);
    let auth = merge_labels(&[detect_names(AUTH, js_names.iter().copied()), detect_names(PY_AUTH, py_names.iter().copied())]);
    let integrations = merge_labels(&[detect_names(INTEGRATIONS, js_names.iter().copied()), detect_names(PY_INTEGRATIONS, py_names.iter().copied())]);

    let provenance = Provenance {
        source_type: SourceType::Parsed,
        confidence: Some(manifests.confidence),
        repo: Some(repo.name.clone()),
        // Only cite a manifest that exists; omit entirely otherwise (HOR-407).
        file_path: manifests.file_path.map(str::to_string),
        line_range: None,
        git_sha: opts.git_sha.clone(),
        generated_at: opts.now.clone(),
        last_seen: None,
        content_hash: None,
    };

    let role = infer_role(&frameworks, &data_sources);
    let languages = detect_languages(&manifests, &js_deps);
    let main_scripts = SCRIPT_KEYS
        .iter()
        .filter(|k| pkg.scripts.as_ref().is_some_and(|s| s.contains_key(**k)))
        .map(|k| k.to_string())
        .collect();

    RepositoryProfile {
        id: format!("repo:{}", repo.name),
        scope: Some(KnowledgeScope {
            project: opts.project.clone().filter(|p| !p.is_empty()),
            repository: Some(repo.name.clone()),
        }),
        provenance,
        key: repo.name.clone(),
        name: pkg.name.clone().or_else(|| manifests.python.name.clone()).unwrap_or_else(|| repo.name.clone()),
        path: Some(repo.path.clone()),
        role,
        summary: pkg.description.clone().or_else(|| manifests.python.description.clone()),
        frameworks,
        languages,
        state_management,
        auth,
        data_sources,
        main_scripts,
        integrations,
        deployment_notes: vec![],
        important_directories: vec![],
    }
}

/// Build a first-version project-knowledge snapshot (repository landscape) for one
/// or more repos. Repos with no readable manifest still get a minimal profile.
pub fn build_project_knowledge(repos: &[RepoInput], opts: &BuildOptions) -> Result<KnowledgeSnapshot> {
    let now = opts.now.clone().unwrap_or_else(now_iso);
    let per_repo = BuildOptions { now: Some(now.clone()), ..opts.clone() };
    let repositories: Vec<RepositoryProfile> = repos.iter().map(|r| derive_repository_profile(r, &per_repo)).collect();

    // Bridge the analysed source graph into the symbol-derived categories (HOR-408).
    // The host serves a single repo; if the caller didn't name it, fall back to the
    // lone configured repo so items carry a repository scope.
    let graph_repo: Option<String> = opts
        .source_graph
        .as_ref()
        .and_then(|g| g.repo.clone())
        .or_else(|| if repos.len() == 1 { repos.first().map(|r| r.name.clone()) } else { None });
    let from_graph = match &opts.source_graph {
        Some(graph) => build_knowledge_from_source_graph(
            graph,
            &SourceGraphMapOptions {
                project: opts.project.clone(),
                repo: graph_repo,
                git_sha: opts.git_sha.clone(),
                now: Some(now.clone()),
                max_per_category: None,
            },
        ),
        None => Default::default(),
    };

    let snapshot = KnowledgeSnapshot {
        schema_version: KNOWLEDGE_SCHEMA_VERSION,
        generated_at: now,
        project: opts.project.clone(),
        source_relationships: from_graph.source_relationships,
        // External integrations come from the manifest-derived repo profiles — the
        // data sources / third-party SDKs already detected for the landscape.
        external_integrations: derive_external_integrations(&repositories),
        repositories,
        operations: from_graph.operations,
        types: from_graph.types,
        enums: from_graph.enums,
        auth_rules: vec![],
        domain_concepts: from_graph.domain_concepts,
        frontend_patterns: vec![],
        data_flows: from_graph.data_flows,
        runtime_components: from_graph.runtime_components,
    };
    snapshot.validate()?;
    Ok(snapshot)
}
