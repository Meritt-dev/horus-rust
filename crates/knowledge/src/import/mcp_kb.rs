//! MCP knowledge-base importer (HOR-292).
//!
//! The first adapter that maps the prototype `knowledge-base.json` (GraphQL
//! operations, input/response types, enums, frontend patterns, domain concepts,
//! project profiles) into a Horus `KnowledgeSnapshot`. Imported items are tagged
//! `sourceType: 'imported'` with the KB's own `generatedAt` and a content hash as
//! provenance. Unknown/missing fields are skipped safely and reported as warnings,
//! never thrown.

use crate::build::project_landscape::now_iso;
use crate::schema::*;
use anyhow::{anyhow, Result};
use serde_json::{Map, Value};

pub const MCP_KB_SOURCE: &str = "mcp-kb-import";

#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// ISO timestamp for the produced snapshot (defaults to now).
    pub now: Option<String>,
    /// Content hash of the source file, recorded on every item's provenance.
    pub content_hash: Option<String>,
    /// Project name to scope the snapshot to.
    pub project: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportResult {
    pub snapshot: KnowledgeSnapshot,
    /// Non-fatal issues: skipped malformed items, ignored unknown top-level keys.
    pub warnings: Vec<String>,
    /// The detected KB schema version (string), if present.
    pub kb_version: Option<String>,
}

const KNOWN_KEYS: [&str; 11] = [
    "version",
    "generatedAt",
    "operations",
    "inputTypes",
    "responseTypes",
    "enums",
    "frontendPatterns",
    "domainConcepts",
    "projectProfiles",
    "maisonSdl",
    "dataFlows",
];

/// zod's `received` type name for an error message.
fn zod_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// A non-empty string, or None (`str()` in TS).
fn str_(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn str_array(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => vec![],
    }
}

/// The `looseField` zod object: each present key must have the right type, extra keys kept.
fn loose_field_ok(f: &Map<String, Value>) -> bool {
    let ok = |key: &str, pred: fn(&Value) -> bool| f.get(key).is_none_or(|v| v.is_null() || pred(v));
    ok("name", Value::is_string) && ok("type", Value::is_string) && ok("nullable", Value::is_boolean) && ok("description", Value::is_string)
}

fn map_fields(raw: Option<&Value>) -> Vec<Field> {
    let Some(Value::Array(items)) = raw else { return vec![] };
    let mut out = Vec::new();
    for f in items {
        let Value::Object(obj) = f else { continue };
        if !loose_field_ok(obj) {
            continue;
        }
        let (Some(name), Some(type_)) = (str_(obj.get("name")), str_(obj.get("type"))) else { continue };
        out.push(Field {
            name,
            type_,
            nullable: obj.get("nullable").and_then(Value::as_bool),
            description: str_(obj.get("description")),
        });
    }
    out
}

/// Validate the loose `MaisonKbSchema` shape; returns the first zod-style issue message.
fn check_kb_shape(raw: &Value) -> Result<&Map<String, Value>, String> {
    let Value::Object(kb) = raw else {
        return Err(format!("Expected object, received {}", zod_type(raw)));
    };
    if let Some(v) = kb.get("version") {
        if !(v.is_null() || v.is_string() || v.is_number()) {
            return Err("Invalid input".to_string());
        }
    }
    if let Some(v) = kb.get("generatedAt") {
        if !(v.is_null() || v.is_string()) {
            return Err(format!("Expected string, received {}", zod_type(v)));
        }
    }
    for key in ["operations", "inputTypes", "responseTypes", "enums", "frontendPatterns", "domainConcepts", "projectProfiles"] {
        match kb.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for item in items {
                    if !item.is_object() {
                        return Err(format!("Expected object, received {}", zod_type(item)));
                    }
                }
            }
            Some(v) => return Err(format!("Expected array, received {}", zod_type(v))),
        }
    }
    Ok(kb)
}

fn objects<'a>(kb: &'a Map<String, Value>, key: &str) -> Vec<&'a Map<String, Value>> {
    match kb.get(key) {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_object).collect(),
        _ => vec![],
    }
}

/// Import a parsed MCP knowledge-base into a `KnowledgeSnapshot`.
/// Pure: no file IO. Errors only when `raw` is not a KB-shaped object.
pub fn import_mcp_knowledge_base(raw: &Value, opts: &ImportOptions) -> Result<ImportResult> {
    let kb = check_kb_shape(raw).map_err(|m| anyhow!("Not an MCP knowledge-base: {m}"))?;
    let mut warnings: Vec<String> = Vec::new();

    // `String(kb.version)` when present and not null (an empty string stays, but still warns).
    let kb_version: Option<String> = match kb.get("version") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };
    if kb_version.as_deref().is_none_or(str::is_empty) {
        warnings.push("knowledge-base is missing a `version` field; importing without a schema version.".into());
    }

    // Report (don't fail on) unmapped top-level keys.
    for key in kb.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            warnings.push(format!("ignored unknown top-level key: `{key}`"));
        }
    }
    if kb.get("maisonSdl").is_some_and(Value::is_string) {
        warnings.push("`maisonSdl` is not mapped to a knowledge entity (kept out of the snapshot).".into());
    }

    let base_prov = Provenance {
        source_type: SourceType::Imported,
        confidence: None,
        repo: opts.project.clone(),
        file_path: None,
        line_range: None,
        git_sha: None,
        // Raw `kb.generatedAt` (an empty string is kept and fails datetime validation, as in TS).
        generated_at: kb.get("generatedAt").and_then(Value::as_str).map(str::to_string),
        last_seen: None,
        content_hash: opts.content_hash.clone(),
    };
    let prov = |file_path: Option<String>| Provenance { file_path, ..base_prov.clone() };
    let scope = opts.project.clone().filter(|p| !p.is_empty()).map(|project| KnowledgeScope { project: Some(project), repository: None });

    let mut skip = |cat: &str, why: &str| warnings.push(format!("skipped {cat}: {why}"));

    // ── operations ──
    let mut operations = Vec::new();
    for o in objects(kb, "operations") {
        let Some(name) = str_(o.get("name")) else {
            skip("operation", "missing `name`");
            continue;
        };
        let auth = o.get("auth").and_then(Value::as_object).map(|auth| OperationAuth {
            required: auth.get("required") == Some(&Value::Bool(true)),
            roles: str_array(auth.get("roles")),
            notes: str_(auth.get("notes")),
        });
        operations.push(Operation {
            id: format!("operation:{name}"),
            scope: scope.clone(),
            provenance: prov(str_(o.get("resolverFile"))),
            name,
            kind: str_(o.get("kind")).unwrap_or_else(|| "operation".into()),
            protocol: "graphql".into(),
            domain: str_(o.get("domain")),
            description: str_(o.get("description")),
            resolver_file: str_(o.get("resolverFile")),
            path: None,
            auth,
            args: map_fields(o.get("args")),
            return_type: str_(o.get("returnType")),
        });
    }

    // ── types (input + response) ──
    let mut types = Vec::new();
    for (key, kind) in [("inputTypes", "input"), ("responseTypes", "response")] {
        for t in objects(kb, key) {
            let Some(name) = str_(t.get("name")) else {
                skip(&format!("{kind} type"), "missing `name`");
                continue;
            };
            types.push(TypeDefinition {
                id: format!("type:{name}"),
                scope: scope.clone(),
                provenance: prov(str_(t.get("sourceFile"))),
                name,
                kind: str_(t.get("kind")).unwrap_or_else(|| kind.into()),
                fields: map_fields(t.get("fields")),
                source_file: str_(t.get("sourceFile")),
                description: str_(t.get("description")),
            });
        }
    }

    // ── enums ──
    let mut enums = Vec::new();
    for e in objects(kb, "enums") {
        let Some(name) = str_(e.get("name")) else {
            skip("enum", "missing `name`");
            continue;
        };
        enums.push(EnumDefinition {
            id: format!("enum:{name}"),
            scope: scope.clone(),
            provenance: prov(None),
            name,
            values: str_array(e.get("values")),
            description: str_(e.get("description")),
            source_file: None,
        });
    }

    // ── frontend patterns ──
    let mut frontend_patterns = Vec::new();
    for p in objects(kb, "frontendPatterns") {
        let Some(name) = str_(p.get("name")) else {
            skip("frontend pattern", "missing `name`");
            continue;
        };
        let kind = str_(p.get("kind")).unwrap_or_else(|| "pattern".into());
        frontend_patterns.push(FrontendPattern {
            id: format!("fe:{kind}:{name}"),
            scope: scope.clone(),
            provenance: prov(str_(p.get("filePath"))),
            kind,
            name,
            file_path: str_(p.get("filePath")),
            description: str_(p.get("description")),
        });
    }

    // ── domain concepts ──
    let mut domain_concepts = Vec::new();
    for c in objects(kb, "domainConcepts") {
        let Some(name) = str_(c.get("name")) else {
            skip("domain concept", "missing `name`");
            continue;
        };
        let slug = str_(c.get("slug"));
        domain_concepts.push(DomainConcept {
            id: format!("concept:{}", slug.as_deref().unwrap_or(&name)),
            scope: scope.clone(),
            provenance: prov(None),
            name,
            slug,
            summary: str_(c.get("summary")),
            details: str_(c.get("details")),
            related_operations: str_array(c.get("relatedOperations")),
            related_types: str_array(c.get("relatedTypes")),
        });
    }

    // ── project profiles → repository profiles ──
    let mut repositories = Vec::new();
    for p in objects(kb, "projectProfiles") {
        let Some(key) = str_(p.get("key")).or_else(|| str_(p.get("name"))) else {
            skip("project profile", "missing `key`/`name`");
            continue;
        };
        repositories.push(RepositoryProfile {
            id: format!("repo:{key}"),
            scope: scope.clone(),
            provenance: prov(None),
            name: str_(p.get("name")).unwrap_or_else(|| key.clone()),
            key,
            path: str_(p.get("path")),
            role: str_(p.get("role")),
            summary: str_(p.get("summary")),
            frameworks: str_array(p.get("frameworks")),
            languages: str_array(p.get("languages")),
            state_management: str_array(p.get("stateManagement")),
            auth: str_array(p.get("auth")),
            data_sources: str_array(p.get("dataSources")),
            main_scripts: str_array(p.get("mainScripts")),
            integrations: str_array(p.get("integrations")),
            deployment_notes: str_array(p.get("deploymentNotes")),
            important_directories: str_array(p.get("importantDirectories")),
        });
    }

    // Validate the assembled snapshot against the canonical schema.
    let snapshot = KnowledgeSnapshot {
        repositories,
        operations,
        types,
        enums,
        domain_concepts,
        frontend_patterns,
        ..KnowledgeSnapshot::empty(opts.now.clone().unwrap_or_else(now_iso), opts.project.clone())
    };
    snapshot.validate()?;

    Ok(ImportResult { snapshot, warnings, kb_version })
}
