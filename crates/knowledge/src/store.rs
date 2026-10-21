//! JSON-file knowledge store (HOR-291).
//!
//! The canonical v1 store is plain JSON under `.horus/index/` — human-readable,
//! git-diffable, no native deps, and queryable without embeddings (load + filter
//! in memory). A SQLite/vector layer (`index.db`) is a deferred v2 optimisation;
//! the store below is engine-agnostic so it can be added without changing callers.
//!
//! Files are written byte-identically to the TS store (`JSON.stringify(v, null, 2)`
//! plus a trailing newline) so the `knowledge-base.json` content hash recorded in
//! the manifest is the same whichever CLI produced it.

use crate::layout::{knowledge_dir, knowledge_path, KnowledgeFile};
use crate::schema::*;
use anyhow::{Context, Result};
use indexmap::IndexMap;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};


/// Options for [`JsonKnowledgeStore::write`].
#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    /// What produced this snapshot (recorded in the manifest).
    pub generator: Option<ToolRef>,
    /// Repos + their indexed HEAD commit.
    pub repositories: Option<Vec<ManifestRepository>>,
    /// Source-intelligence backend this snapshot references (e.g. source intelligence).
    pub source_intelligence: Option<ToolRef>,
    /// Git state the snapshot was built at (HOR-293).
    pub git: Option<ManifestGit>,
    /// Extra manifest file entries (e.g. an import source file + its content hash).
    pub extra_files: Option<Vec<ManifestFile>>,
}

/// `JSON.stringify(value, null, 2) + '\n'`.
pub fn to_json_file_string<T: Serialize>(value: &T) -> Result<String> {
    let mut s = horus_core::json::to_js_json_pretty(value)?;
    s.push('\n');
    Ok(s)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, to_json_file_string(value)?).with_context(|| format!("write {}", path.display()))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractsView<'a> {
    operations: &'a [Operation],
    types: &'a [TypeDefinition],
    enums: &'a [EnumDefinition],
    auth_rules: &'a [AuthRule],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DomainConceptsView<'a> {
    domain_concepts: &'a [DomainConcept],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DataFlowsView<'a> {
    data_flows: &'a [DataFlow],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeMapView<'a> {
    runtime_components: &'a [RuntimeComponent],
    external_integrations: &'a [ExternalIntegration],
}

/// JSON-backed knowledge store rooted at a repo directory
/// (`createJsonKnowledgeStore(root)`).
#[derive(Debug, Clone)]
pub struct JsonKnowledgeStore {
    root: PathBuf,
    manifest_path: PathBuf,
    base_path: PathBuf,
}

/// Create a JSON-backed knowledge store rooted at a repo directory.
pub fn create_json_knowledge_store(root: &Path) -> JsonKnowledgeStore {
    JsonKnowledgeStore::new(root)
}

impl JsonKnowledgeStore {
    pub fn new(root: &Path) -> Self {
        JsonKnowledgeStore {
            root: root.to_path_buf(),
            manifest_path: knowledge_path(root, KnowledgeFile::Manifest),
            base_path: knowledge_path(root, KnowledgeFile::KnowledgeBase),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<root>/.horus/index`.
    pub fn dir(&self) -> PathBuf {
        knowledge_dir(&self.root)
    }

    /// True if a knowledge index exists for this repo.
    pub fn exists(&self) -> bool {
        self.base_path.exists()
    }

    /// Read + validate the manifest, or `None` if absent.
    pub fn read_manifest(&self) -> Result<Option<KnowledgeManifest>> {
        if !self.manifest_path.exists() {
            return Ok(None);
        }
        let m: KnowledgeManifest = read_json(&self.manifest_path)?;
        m.validate()?;
        Ok(Some(m))
    }

    /// Read + validate the canonical snapshot, or `None` if absent.
    pub fn read_snapshot(&self) -> Result<Option<KnowledgeSnapshot>> {
        if !self.base_path.exists() {
            return Ok(None);
        }
        let s: KnowledgeSnapshot = read_json(&self.base_path)?;
        s.validate()?;
        Ok(Some(s))
    }

    /// Validate + persist a snapshot (canonical file, derived views, manifest).
    pub fn write(&self, snapshot: &KnowledgeSnapshot, opts: &WriteOptions) -> Result<KnowledgeManifest> {
        // Validate before touching disk so a bad snapshot never half-writes.
        snapshot.validate()?;
        let parsed = snapshot;

        let mut counts: IndexMap<String, u64> = IndexMap::new();
        for cat in KNOWLEDGE_CATEGORIES {
            counts.insert(cat.as_str().to_string(), parsed.category_len(cat) as u64);
        }

        // Content hash of the canonical snapshot (manifest integrity / freshness).
        let snapshot_json = to_json_file_string(parsed)?;
        let content_hash = hex::encode(Sha256::digest(snapshot_json.as_bytes()));

        // Canonical full snapshot.
        if let Some(dir) = self.base_path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&self.base_path, &snapshot_json)
            .with_context(|| format!("write {}", self.base_path.display()))?;

        // Derived, human-readable view files (subsets of the canonical snapshot).
        write_json(
            &knowledge_path(&self.root, KnowledgeFile::Contracts),
            &ContractsView {
                operations: &parsed.operations,
                types: &parsed.types,
                enums: &parsed.enums,
                auth_rules: &parsed.auth_rules,
            },
        )?;
        write_json(
            &knowledge_path(&self.root, KnowledgeFile::DomainConcepts),
            &DomainConceptsView { domain_concepts: &parsed.domain_concepts },
        )?;
        write_json(
            &knowledge_path(&self.root, KnowledgeFile::DataFlows),
            &DataFlowsView { data_flows: &parsed.data_flows },
        )?;
        write_json(
            &knowledge_path(&self.root, KnowledgeFile::RuntimeMap),
            &RuntimeMapView {
                runtime_components: &parsed.runtime_components,
                external_integrations: &parsed.external_integrations,
            },
        )?;

        let mut files = vec![
            ManifestFile { name: "knowledge-base.json".into(), category: None, item_count: None, content_hash: Some(content_hash) },
            ManifestFile { name: "contracts.json".into(), category: Some("contracts".into()), item_count: None, content_hash: None },
            ManifestFile { name: "domain-concepts.json".into(), category: Some("domainConcepts".into()), item_count: None, content_hash: None },
            ManifestFile { name: "data-flows.json".into(), category: Some("dataFlows".into()), item_count: None, content_hash: None },
            ManifestFile { name: "runtime-map.json".into(), category: Some("runtimeMap".into()), item_count: None, content_hash: None },
        ];
        files.extend(opts.extra_files.clone().unwrap_or_default());

        let manifest = KnowledgeManifest {
            schema_version: parsed.schema_version,
            generated_at: parsed.generated_at.clone(),
            generator: opts.generator.clone().unwrap_or(ToolRef { tool: "horus-cli".into(), version: None }),
            project: parsed.project.clone(),
            git: opts.git.clone(),
            repositories: opts.repositories.clone().unwrap_or_default(),
            files,
            counts,
            source_intelligence: opts.source_intelligence.clone(),
        };
        manifest.validate()?;
        write_json(&self.manifest_path, &manifest)?;
        Ok(manifest)
    }
}
