//! Source-graph → knowledge bridge (HOR-408).
//!
//! `horus init` analyses a repo with the source-intelligence backend
//! (`horus-source analyze`), producing a rich code graph: functions, classes,
//! interfaces, type aliases, enums, semantic communities, and execution-flow
//! processes. The first-version knowledge pass (`build_project_knowledge`) only
//! ever derived the per-repo *landscape* from dependency manifests, so every
//! other knowledge category came out EMPTY even though the graph was full of
//! exactly that information — the analyse→KB bridge dropped it on the floor.
//!
//! This module is the missing bridge. It is PURE and local-first: it takes a
//! plain `SourceGraphExtract` (what the CLI pulls back over read-only Cypher from
//! the running host) and maps it onto the knowledge schema. The CLI owns the
//! Cypher, this owns the honest mapping.
//!
//! Honesty: every produced item is `sourceType: 'parsed'` and cites the file +
//! line range it was extracted from. Nothing is invented; categories with no
//! matching graph nodes stay empty rather than being padded.

use crate::schema::*;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// A code symbol pulled from the source graph (one Function/Class/Enum/... node).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceSymbolInput {
    /// Exact source-host identity; never resolve relationships by display name.
    pub id: Option<String>,
    /// Raw graph label, case-insensitive: function | method | class | interface | type_alias | enum.
    pub label: String,
    pub name: String,
    pub file_path: Option<String>,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
    /// Owning class for methods (graph `class_name`).
    pub class_name: Option<String>,
    pub signature: Option<String>,
    /// Source-graph `is_exported` flag (the symbol is part of the module's public surface).
    pub is_exported: Option<bool>,
    /// Source-graph `is_entry_point` flag (a runtime entry point — route, command, main).
    pub is_entry_point: Option<bool>,
    /// Enum member names, when the label is `enum` and they could be parsed.
    pub enum_values: Option<Vec<String>>,
}

/// A semantic community (cluster of related code) — the graph's own domain grouping.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceCommunityInput {
    pub id: Option<String>,
    pub name: String,
    pub summary: Option<String>,
}

/// One ordered step of an execution-flow process.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceProcessStepInput {
    pub component: String,
    pub detail: Option<String>,
}

/// A traced execution flow (a `Process` node + its ordered steps).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceProcessInput {
    pub id: Option<String>,
    pub name: String,
    pub steps: Option<Vec<SourceProcessStepInput>>,
}

/// A raw relationship edge between two source-host symbol ids.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceRelationshipInput {
    pub source: String,
    pub target: String,
    pub rel: SourceRel,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceRelationshipsInput {
    pub edges: Vec<SourceRelationshipInput>,
    pub truncated: bool,
}

/// Everything the CLI reads back from a repo's analysed source graph. All fields
/// are optional so a partial pull (e.g. a backend that can't answer one query)
/// still bridges whatever it does have.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceGraphExtract {
    pub relationships: Option<SourceRelationshipsInput>,
    pub symbols: Option<Vec<SourceSymbolInput>>,
    pub communities: Option<Vec<SourceCommunityInput>>,
    pub processes: Option<Vec<SourceProcessInput>>,
    /// Repository name the host serves — recorded on each item's scope/provenance.
    pub repo: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SourceGraphMapOptions {
    pub project: Option<String>,
    /// Repository the graph belongs to (overrides `extract.repo`).
    pub repo: Option<String>,
    pub git_sha: Option<String>,
    pub now: Option<String>,
    /// Defensive per-category cap so a pathologically large monorepo can't write a
    /// multi-hundred-MB knowledge base. Symbols are taken in graph order.
    pub max_per_category: Option<usize>,
}

/// Categories this bridge can populate from the source graph.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceGraphKnowledge {
    pub source_relationships: Option<SourceKnowledgeRelationships>,
    pub operations: Vec<Operation>,
    pub types: Vec<TypeDefinition>,
    pub enums: Vec<EnumDefinition>,
    pub domain_concepts: Vec<DomainConcept>,
    pub data_flows: Vec<DataFlow>,
    pub runtime_components: Vec<RuntimeComponent>,
}

const DEFAULT_MAX_PER_CATEGORY: usize = 5000;

/// Normalize a graph label to a lowercase, separator-free token so both the kùzu
/// table form (`TypeAlias`) and the model form (`type_alias`) collapse to the same
/// comparison key (`typealias`).
fn norm(label: &str) -> String {
    label
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !(c.is_whitespace() || *c == '_' || *c == '-'))
        .collect()
}

/// A non-empty, trimmed string, or None.
fn clean(s: Option<&str>) -> Option<&str> {
    let t = s?.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// Build per-item provenance: always `parsed`/`high`, citing the file + line
/// range the node was extracted from (omitting an empty line range so we never
/// cite a phantom `file:0`).
fn provenance_for(sym: &SourceSymbolInput, opts: &SourceGraphMapOptions, repo: Option<&str>) -> Provenance {
    let start = sym.start_line;
    let end = sym.end_line.or(sym.start_line);
    let range = match (start, end) {
        (Some(s), Some(e)) if s > 0 && e >= s => Some((s, e)),
        _ => None,
    };
    Provenance {
        source_type: SourceType::Parsed,
        confidence: Some(Confidence::High),
        repo: repo.map(str::to_string),
        // Keep the original (untrimmed) path once it's known to be non-blank — the TS does the same.
        file_path: clean(sym.file_path.as_deref()).map(|_| sym.file_path.clone().unwrap_or_default()),
        line_range: range,
        git_sha: opts.git_sha.clone().filter(|s| !s.is_empty()),
        generated_at: opts.now.clone().filter(|s| !s.is_empty()),
        last_seen: None,
        content_hash: None,
    }
}

/// Inferred-item provenance (communities, processes): no file span.
fn inferred_provenance(opts: &SourceGraphMapOptions, repo: Option<&str>) -> Provenance {
    Provenance {
        source_type: SourceType::Inferred,
        confidence: Some(Confidence::Medium),
        repo: repo.map(str::to_string),
        file_path: None,
        line_range: None,
        git_sha: opts.git_sha.clone().filter(|s| !s.is_empty()),
        generated_at: opts.now.clone().filter(|s| !s.is_empty()),
        last_seen: None,
        content_hash: None,
    }
}

/// Stable scope for every item (project + repository), omitting empty parts.
fn scope_for(opts: &SourceGraphMapOptions, repo: Option<&str>) -> Option<KnowledgeScope> {
    let project = opts.project.clone().filter(|p| !p.is_empty());
    let repository = repo.map(str::to_string);
    if project.is_none() && repository.is_none() {
        None
    } else {
        Some(KnowledgeScope { project, repository })
    }
}

fn id_for(kind: &str, sym: &SourceSymbolInput, display_name: &str) -> String {
    format!("{kind}:{}:{display_name}", sym.file_path.as_deref().unwrap_or(""))
}

/// Display name for a symbol: methods carry their owning class so `Service.create` reads unambiguously.
fn display_name_for(label: &str, name: &str, sym: &SourceSymbolInput) -> String {
    match (label, clean(sym.class_name.as_deref())) {
        ("method", Some(_)) => format!("{}.{name}", sym.class_name.as_deref().unwrap_or("")),
        _ => name.to_string(),
    }
}

/// Map a source-graph extract onto knowledge categories. Pure: deterministic in,
/// deterministic out. IDs are stable + collision-resistant (kind:file:name).
pub fn build_knowledge_from_source_graph(extract: &SourceGraphExtract, opts: &SourceGraphMapOptions) -> SourceGraphKnowledge {
    // `clean(opts.repo) ?? clean(extract.repo)` — trimmed.
    let repo: Option<&str> = clean(opts.repo.as_deref()).or_else(|| clean(extract.repo.as_deref()));
    let cap = opts.max_per_category.unwrap_or(DEFAULT_MAX_PER_CATEGORY);
    let scope = scope_for(opts, repo);

    let mut operations: Vec<Operation> = Vec::new();
    let mut types: Vec<TypeDefinition> = Vec::new();
    let mut enums: Vec<EnumDefinition> = Vec::new();
    let mut runtime_components: Vec<RuntimeComponent> = Vec::new();

    // De-dupe by id: the graph can carry overloads / re-declarations that hash to
    // the same kind:file:name. First write wins (graph order is stable).
    let mut seen_op: HashSet<String> = HashSet::new();
    let mut seen_ty: HashSet<String> = HashSet::new();
    let mut seen_en: HashSet<String> = HashSet::new();
    let mut seen_rt: HashSet<String> = HashSet::new();

    let symbols: &[SourceSymbolInput] = extract.symbols.as_deref().unwrap_or(&[]);
    for sym in symbols {
        let label = norm(&sym.label);
        let Some(name) = clean(Some(&sym.name)) else { continue };
        let prov = provenance_for(sym, opts, repo);
        let file = clean(sym.file_path.as_deref()).map(|_| sym.file_path.clone().unwrap_or_default());

        if label == "class" || label == "interface" || label == "typealias" {
            if types.len() >= cap {
                continue;
            }
            // class → object, interface → interface, type_alias → alias (kind is free-form).
            let kind = match label.as_str() {
                "typealias" => "alias",
                "interface" => "interface",
                _ => "object",
            };
            let id = id_for("type", sym, name);
            if !seen_ty.insert(id.clone()) {
                continue;
            }
            types.push(TypeDefinition {
                id,
                scope: scope.clone(),
                provenance: prov,
                name: name.to_string(),
                kind: kind.to_string(),
                fields: vec![],
                source_file: file,
                description: None,
            });
            continue;
        }

        if label == "enum" {
            if enums.len() >= cap {
                continue;
            }
            let id = id_for("enum", sym, name);
            if !seen_en.insert(id.clone()) {
                continue;
            }
            enums.push(EnumDefinition {
                id,
                scope: scope.clone(),
                provenance: prov,
                name: name.to_string(),
                values: sym
                    .enum_values
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect(),
                description: None,
                source_file: file,
            });
            continue;
        }

        if label == "function" || label == "method" {
            let display_name = display_name_for(&label, name, sym);

            if operations.len() < cap {
                let id = id_for("operation", sym, &display_name);
                if seen_op.insert(id.clone()) {
                    operations.push(Operation {
                        id,
                        scope: scope.clone(),
                        provenance: prov.clone(),
                        name: display_name.clone(),
                        kind: label.clone(), // function | method
                        protocol: "function".to_string(),
                        domain: None,
                        description: None,
                        resolver_file: file.clone(),
                        path: None,
                        auth: None,
                        args: vec![],
                        return_type: None,
                    });
                }
            }

            // Runtime entry points (a `main`, a route handler, a CLI command, a worker)
            // are the repo's runtime surface — surface them separately, honestly tagged.
            if sym.is_entry_point == Some(true) && runtime_components.len() < cap {
                let id = id_for("runtime", sym, &display_name);
                if seen_rt.insert(id.clone()) {
                    runtime_components.push(RuntimeComponent {
                        id,
                        scope: scope.clone(),
                        provenance: prov,
                        name: display_name,
                        type_: "function".to_string(),
                        description: None,
                        repo: repo.map(str::to_string),
                        entrypoints: file.into_iter().collect(),
                    });
                }
            }
        }
    }

    // Communities → domain concepts: the graph's own semantic grouping of code is
    // the closest honest analogue to a "domain concept" (inferred, not parsed).
    let mut domain_concepts: Vec<DomainConcept> = Vec::new();
    let mut seen_dc: HashSet<String> = HashSet::new();
    for c in extract.communities.as_deref().unwrap_or(&[]) {
        if domain_concepts.len() >= cap {
            break;
        }
        let Some(name) = clean(Some(&c.name)) else { continue };
        let id = format!("domain:{}", clean(c.id.as_deref()).unwrap_or(name));
        if !seen_dc.insert(id.clone()) {
            continue;
        }
        domain_concepts.push(DomainConcept {
            id,
            scope: scope.clone(),
            // A community is a derived clustering, not a parsed source span (honesty).
            provenance: inferred_provenance(opts, repo),
            name: name.to_string(),
            slug: None,
            summary: clean(c.summary.as_deref()).map(|_| c.summary.clone().unwrap_or_default()),
            details: None,
            related_operations: vec![],
            related_types: vec![],
        });
    }

    // Processes → data flows: a `Process` is a traced ordered path through the code.
    let mut data_flows: Vec<DataFlow> = Vec::new();
    let mut seen_flow: HashSet<String> = HashSet::new();
    for p in extract.processes.as_deref().unwrap_or(&[]) {
        if data_flows.len() >= cap {
            break;
        }
        let Some(name) = clean(Some(&p.name)) else { continue };
        let id = format!("flow:{}", clean(p.id.as_deref()).unwrap_or(name));
        if !seen_flow.insert(id.clone()) {
            continue;
        }
        data_flows.push(DataFlow {
            id,
            scope: scope.clone(),
            provenance: inferred_provenance(opts, repo),
            name: name.to_string(),
            description: None,
            steps: p
                .steps
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|s| {
                    let component = clean(Some(&s.component))?;
                    Some(DataFlowStep {
                        component: component.to_string(),
                        action: None,
                        detail: clean(s.detail.as_deref()).map(|_| s.detail.clone().unwrap_or_default()),
                    })
                })
                .collect(),
            sources: vec![],
            sinks: vec![],
        });
    }

    // Only project edges onto unambiguous, actually retained knowledge entities.
    // Overloads/re-declarations can collapse to one KB identity; never guess which
    // source node an edge meant in that case.
    let retained: HashSet<&str> = operations
        .iter()
        .map(|i| i.id.as_str())
        .chain(types.iter().map(|i| i.id.as_str()))
        .chain(enums.iter().map(|i| i.id.as_str()))
        .collect();
    let mut source_to_knowledge: HashMap<&str, String> = HashMap::new();
    let mut sources_by_knowledge: HashMap<String, HashSet<&str>> = HashMap::new();
    for sym in symbols {
        let (Some(source_id), Some(name)) = (clean(sym.id.as_deref()), clean(Some(&sym.name))) else { continue };
        let label = norm(&sym.label);
        let kind = match label.as_str() {
            "function" | "method" => "operation",
            "class" | "interface" | "typealias" => "type",
            "enum" => "enum",
            _ => continue,
        };
        let display_name = display_name_for(&label, name, sym);
        let id = id_for(kind, sym, &display_name);
        if !retained.contains(id.as_str()) {
            continue;
        }
        source_to_knowledge.insert(source_id, id.clone());
        sources_by_knowledge.entry(id).or_default().insert(source_id);
    }

    let mut source_relationships = extract.relationships.as_ref().map(|r| SourceKnowledgeRelationships {
        edges: Vec::new(),
        truncated: r.truncated,
    });
    let mut seen_relationships: HashSet<String> = HashSet::new();
    if let (Some(rels), Some(out)) = (extract.relationships.as_ref(), source_relationships.as_mut()) {
        for edge in &rels.edges {
            let from = source_to_knowledge.get(edge.source.as_str());
            let to = source_to_knowledge.get(edge.target.as_str());
            let unambiguous = |id: &String| sources_by_knowledge.get(id).map(|s| s.len()) == Some(1);
            let (Some(from), Some(to)) = (from, to) else {
                out.truncated = true;
                continue;
            };
            if !unambiguous(from) || !unambiguous(to) {
                out.truncated = true;
                continue;
            }
            // `JSON.stringify([rel, source, target])` → compact JSON array.
            let payload = serde_json::to_string(&[edge.rel.as_str(), edge.source.as_str(), edge.target.as_str()])
                .unwrap_or_default();
            let id = format!("source:{}", hex::encode(Sha256::digest(payload.as_bytes())));
            if !seen_relationships.insert(id.clone()) {
                continue;
            }
            if out.edges.len() >= MAX_SOURCE_RELATIONSHIP_EDGES {
                out.truncated = true;
                continue;
            }
            out.edges.push(SourceRelationshipEdge {
                id,
                from: from.clone(),
                to: to.clone(),
                rel: edge.rel,
                confidence: edge.confidence,
            });
        }
    }

    SourceGraphKnowledge {
        source_relationships,
        operations,
        types,
        enums,
        domain_concepts,
        data_flows,
        runtime_components,
    }
}

/// Derive external integrations from the per-repo landscape profiles (data
/// sources + third-party integrations the manifest analysis already detected).
/// These are genuine external systems the project talks to, so surfacing them as
/// `ExternalIntegration` items makes the runtime map non-empty without inventing
/// anything — provenance stays tied to the profile's manifest.
pub fn derive_external_integrations(profiles: &[RepositoryProfile]) -> Vec<ExternalIntegration> {
    // Insertion-ordered like the TS `Map`.
    let mut by_name: indexmap::IndexMap<String, ExternalIntegration> = indexmap::IndexMap::new();
    for profile in profiles {
        let repo = if profile.key.is_empty() { profile.name.as_str() } else { profile.key.as_str() };
        let mut add = |name: &str, kind: &str| {
            let clean0 = name.trim();
            if clean0.is_empty() {
                return;
            }
            let id = format!("integration:{clean0}");
            if let Some(existing) = by_name.get_mut(&id) {
                if !existing.used_by.iter().any(|u| u == repo) {
                    existing.used_by.push(repo.to_string());
                }
                return;
            }
            by_name.insert(
                id.clone(),
                ExternalIntegration {
                    id,
                    scope: profile.scope.clone(),
                    // Inherit the profile's manifest provenance — same source, same honesty.
                    provenance: Provenance { source_type: SourceType::Parsed, ..profile.provenance.clone() },
                    name: clean0.to_string(),
                    provider: None,
                    kind: Some(kind.to_string()),
                    description: None,
                    used_by: vec![repo.to_string()],
                },
            );
        };
        for ds in &profile.data_sources {
            add(ds, "db");
        }
        for integ in &profile.integrations {
            add(integ, "api");
        }
    }
    by_name.into_values().collect()
}
