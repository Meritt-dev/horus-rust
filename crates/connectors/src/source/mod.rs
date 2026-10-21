//! Source-intelligence connector: HTTP client, `CodeProvider`, host lifecycle, memory
//! vector bridge. Mirrors `packages/connectors/src/source/index.ts`.

pub mod client;
pub mod lifecycle;
pub mod memory_index;
pub mod provider;
pub mod types;

pub use client::*;
pub use lifecycle::*;
pub use memory_index::*;
pub use provider::*;
pub use types::*;

use async_trait::async_trait;

/// Lets `compat::check_source_compatibility` read the backend version off the live client.
#[async_trait]
impl crate::compat::SourceVersionClient for SourceHttpClient {
    async fn version(&self) -> anyhow::Result<Option<String>> {
        Ok(SourceHttpClient::version(self).await)
    }
}
