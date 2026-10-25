//! Bridge between the engine `MemoryVectorIndex` and connectors `MemoryVectorIndexLike` seams:
//! structural mirrors (TS: one interface) with no shared impl, because the engine depends on connectors.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use horus_connectors::source::{MemoryVectorHit, MemoryVectorIndexLike, SourceMemorySearchRequest, SourceMemoryUpsertRequest};
use horus_engine::memory_store::{MemoryVectorIndex, NoopVectorIndex, VectorHit, VectorSearch, VectorUpsert};

/// Engine `NoopVectorIndex` exposed as the connectors fallback seam.
pub struct NoopAsLike(pub NoopVectorIndex);

#[async_trait]
impl MemoryVectorIndexLike for NoopAsLike {
    async fn upsert(&self, i: &SourceMemoryUpsertRequest) -> Result<()> {
        self.0
            .upsert(VectorUpsert { memory_id: i.memory_id.clone(), claim: i.claim.clone(), repo: i.repo.clone(), scope: i.scope.clone() })
            .await
    }
    async fn search(&self, i: &SourceMemorySearchRequest) -> Result<Vec<MemoryVectorHit>> {
        let hits = self.0.search(VectorSearch { query: i.query.clone(), repo: i.repo.clone(), limit: i.limit as f64 }).await?;
        Ok(hits.into_iter().map(|h| MemoryVectorHit { memory_id: h.memory_id, score: h.score }).collect())
    }
    async fn remove(&self, memory_id: &str) -> Result<()> {
        MemoryVectorIndex::remove(&self.0, memory_id).await
    }
}

/// A connectors index exposed as the engine recall seam.
pub struct LikeAsIndex(pub Arc<dyn MemoryVectorIndexLike>);

#[async_trait]
impl MemoryVectorIndex for LikeAsIndex {
    async fn upsert(&self, i: VectorUpsert) -> Result<()> {
        self.0.upsert(&SourceMemoryUpsertRequest { memory_id: i.memory_id, claim: i.claim, repo: i.repo, scope: i.scope }).await
    }
    async fn search(&self, i: VectorSearch) -> Result<Vec<VectorHit>> {
        let hits = self.0.search(&SourceMemorySearchRequest { query: i.query, repo: i.repo, limit: i.limit as i64 }).await?;
        Ok(hits.into_iter().map(|h| VectorHit { memory_id: h.memory_id, score: h.score }).collect())
    }
    async fn remove(&self, memory_id: &str) -> Result<()> {
        self.0.remove(memory_id).await
    }
}
