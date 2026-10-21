//! Knowledge-base import entrypoints (HOR-292).
//!
//! `import_knowledge_base_file` is the internal API behind
//! `horus knowledge import <file> --source maison-safqa-mcp`: it reads a JSON KB
//! from disk, hashes it, maps it into a `KnowledgeSnapshot`, and (when a repo
//! root is given) persists it to `.horus/index/` with a provenance manifest.

pub mod maison_safqa;

pub use maison_safqa::*;

use crate::schema::{KnowledgeManifest, ManifestFile, ToolRef};
use crate::store::{create_json_knowledge_store, WriteOptions};
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct ImportFileOptions {
    /// Repo root to persist the snapshot under `.horus/index/`. Omit to import in-memory only.
    pub root: Option<PathBuf>,
    /// Source label for provenance (defaults to `maison-safqa-mcp`).
    pub source: Option<String>,
    /// Project name to scope the snapshot to.
    pub project: Option<String>,
    /// ISO timestamp for the snapshot (defaults to now).
    pub now: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ImportFileResult {
    pub result: ImportResult,
    /// sha256 of the imported file.
    pub content_hash: String,
    /// Written manifest (only when `root` was provided).
    pub manifest: Option<KnowledgeManifest>,
}

/// Import a Maison Safqa MCP knowledge-base JSON file into the local index.
pub fn import_knowledge_base_file(file_path: &Path, opts: &ImportFileOptions) -> Result<ImportFileResult> {
    let source = opts.source.clone().unwrap_or_else(|| MAISON_SAFQA_SOURCE.to_string());
    let content = fs::read_to_string(file_path).with_context(|| format!("read {}", file_path.display()))?;
    let content_hash = hex::encode(Sha256::digest(content.as_bytes()));

    let raw: Value = serde_json::from_str(&content)
        .map_err(|err| anyhow!("Could not parse {} as JSON: {err}", file_path.display()))?;

    let result = import_maison_safqa_knowledge_base(
        &raw,
        &ImportOptions { now: opts.now.clone(), content_hash: Some(content_hash.clone()), project: opts.project.clone() },
    )?;

    let mut manifest = None;
    if let Some(root) = &opts.root {
        let store = create_json_knowledge_store(root);
        let base = file_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        manifest = Some(store.write(
            &result.snapshot,
            &WriteOptions {
                generator: Some(ToolRef { tool: source.clone(), version: result.kb_version.clone() }),
                source_intelligence: Some(ToolRef { tool: source.clone(), version: None }),
                extra_files: Some(vec![ManifestFile {
                    name: format!("{source}:{base}"),
                    category: Some("import-source".into()),
                    item_count: None,
                    content_hash: Some(content_hash.clone()),
                }]),
                ..Default::default()
            },
        )?);
    }

    Ok(ImportFileResult { result, content_hash, manifest })
}
