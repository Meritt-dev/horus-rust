//! On-disk layout for the local knowledge index (HOR-291).
//!
//! Lives under the repo's `.horus/` directory, alongside `source/` and
//! `config.json`:
//!
//! ```text
//!   .horus/index/
//!     manifest.json         # index entrypoint: versions, repos, counts, files
//!     knowledge-base.json   # CANONICAL full KnowledgeSnapshot
//!     contracts.json        # derived view: operations + types + enums + authRules
//!     domain-concepts.json  # derived view: domainConcepts
//!     data-flows.json       # derived view: dataFlows
//!     runtime-map.json      # derived view: runtimeComponents + externalIntegrations
//!     source-index.json     # optional pointer/summary into source intelligence
//!     index.db              # OPTIONAL (v2) SQLite for fast/semantic lookup
//! ```
//!
//! The split view files are human-readable, git-diffable projections for
//! debugging and partial reads; `knowledge-base.json` is the source of truth.

use std::path::{Path, PathBuf};

/// The repo-local Horus dir (mirrors `horus_core::discovery::HORUS_DIR`).
pub const HORUS_DIR: &str = horus_core::discovery::HORUS_DIR;
/// Sub-directory holding the knowledge index.
pub const KNOWLEDGE_DIR: &str = "index";

/// A known file inside the knowledge dir (`KNOWLEDGE_FILES` keys in TS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KnowledgeFile {
    Manifest,
    KnowledgeBase,
    Contracts,
    DomainConcepts,
    DataFlows,
    RuntimeMap,
    SourceIndex,
    /// Optional SQLite index (v2, not written in v1).
    Db,
}

impl KnowledgeFile {
    /// File name inside `.horus/index` (`KNOWLEDGE_FILES[file]`).
    pub fn file_name(self) -> &'static str {
        match self {
            KnowledgeFile::Manifest => "manifest.json",
            KnowledgeFile::KnowledgeBase => "knowledge-base.json",
            KnowledgeFile::Contracts => "contracts.json",
            KnowledgeFile::DomainConcepts => "domain-concepts.json",
            KnowledgeFile::DataFlows => "data-flows.json",
            KnowledgeFile::RuntimeMap => "runtime-map.json",
            KnowledgeFile::SourceIndex => "source-index.json",
            KnowledgeFile::Db => "index.db",
        }
    }
}

/// Absolute path to `<root>/.horus/index`.
pub fn knowledge_dir(root: &Path) -> PathBuf {
    root.join(HORUS_DIR).join(KNOWLEDGE_DIR)
}

/// Absolute path to a known file inside the knowledge dir.
pub fn knowledge_path(root: &Path, file: KnowledgeFile) -> PathBuf {
    knowledge_dir(root).join(file.file_name())
}
