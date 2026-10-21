//! Horus Memory M2 — the source-host-backed `MemoryVectorIndex`.
//!
//! Bridges to the single-RW-owner host over HTTP (`/api/memory/upsert|search|remove`) where
//! claims are embedded with the SAME nomic model/scheme/cache as code, so link-by-id is
//! semantically meaningful.
//!
//! DEPENDENCY NOTE: the engine crate depends on this crate, so the engine's seam cannot be
//! imported here. `MemoryVectorIndexLike` is a STRUCTURAL mirror of the engine's
//! `MemoryVectorIndex` — identical shapes — so the engine's `NoopVectorIndex` can be injected
//! as `fallback` and this type can be handed to the engine at the CLI wiring site.
//!
//! BEST-EFFORT INVARIANT (HARD RULE): every method swallows host failures.
//!   - `search` returns the host hits when present; on host-down / 404 / 503 / timeout, or
//!     when the index is empty, it delegates to the optional Jaccard `fallback` (else `[]`).
//!   - `upsert`/`remove` resolve silently on failure and mirror into the local `fallback`
//!     so a degraded (host-absent) read still has lexical candidates this process.
//! Memory add must NEVER block or fail because of the vector index.
//!
//! LOCAL-ONLY: this index talks only to the local source host; it never touches any
//! cloud-sync path. Vectors are a rebuildable derived index, not a system of record.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::client::SourceHttpClient;
use super::types::{SourceMemorySearchRequest, SourceMemoryUpsertRequest};

/// A scored candidate. Structural mirror of the engine's `VectorHit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryVectorHit {
    pub memory_id: String,
    pub score: f64,
}

/// Structural mirror of the engine's `MemoryVectorIndex` seam. Kept in lockstep with
/// the engine crate's `memory_store` — any drift there must be reflected here.
#[async_trait]
pub trait MemoryVectorIndexLike: Send + Sync {
    async fn upsert(&self, i: &SourceMemoryUpsertRequest) -> Result<()>;
    async fn search(&self, i: &SourceMemorySearchRequest) -> Result<Vec<MemoryVectorHit>>;
    async fn remove(&self, memory_id: &str) -> Result<()>;
}

#[derive(Default)]
pub struct SourceMemoryVectorIndexOptions {
    /// Optional local fallback (typically the engine `NoopVectorIndex`). When the host is
    /// unreachable or its index is empty, `search` delegates here; `upsert`/`remove` mirror
    /// into it so a degraded read still works within this process.
    pub fallback: Option<Arc<dyn MemoryVectorIndexLike>>,
}

pub struct SourceMemoryVectorIndex {
    client: SourceHttpClient,
    fallback: Option<Arc<dyn MemoryVectorIndexLike>>,
}

impl SourceMemoryVectorIndex {
    pub fn new(client: SourceHttpClient, opts: SourceMemoryVectorIndexOptions) -> Self {
        Self { client, fallback: opts.fallback }
    }

    async fn fallback_search(&self, i: &SourceMemorySearchRequest) -> Vec<MemoryVectorHit> {
        match &self.fallback {
            Some(fb) => fb.search(i).await.unwrap_or_default(),
            None => Vec::new(),
        }
    }
}

#[async_trait]
impl MemoryVectorIndexLike for SourceMemoryVectorIndex {
    async fn upsert(&self, i: &SourceMemoryUpsertRequest) -> Result<()> {
        // Mirror into the local fallback first (cheap, in-memory) so a host-down read still
        // has candidates, then push to the host. Both legs are best-effort / non-fatal.
        if let Some(fb) = &self.fallback {
            let _ = fb.upsert(i).await;
        }
        let _ = self.client.memory_upsert(i).await; // memory add must never block on indexing
        Ok(())
    }

    async fn search(&self, i: &SourceMemorySearchRequest) -> Result<Vec<MemoryVectorHit>> {
        match self.client.memory_search(i).await {
            // A non-empty host result wins. An empty result (index absent / not yet built)
            // degrades to the local Jaccard fallback so recall still gets candidates.
            Ok(hits) if !hits.is_empty() => Ok(hits
                .into_iter()
                .map(|h| MemoryVectorHit { memory_id: h.memory_id, score: h.score })
                .collect()),
            // Host down / 404 / 503 / timeout / empty — degrade to Jaccard (or empty).
            _ => Ok(self.fallback_search(i).await),
        }
    }

    async fn remove(&self, memory_id: &str) -> Result<()> {
        if let Some(fb) = &self.fallback {
            let _ = fb.remove(memory_id).await;
        }
        let _ = self.client.memory_remove(memory_id).await; // removal is best-effort
        Ok(())
    }
}
