//! Source-intelligence backend version pin check (`compat.ts`).

use anyhow::Result;
use async_trait::async_trait;
use horus_core::{PINNED_SOURCE_VERSION, SOURCE_PIN_ENFORCED};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCompatibility {
    /// Always serialized (`null` when the backend reported no version), matching TS.
    pub version: Option<String>,
    pub pinned: String,
    pub matches: bool,
}

/// The one method `check_source_compatibility` needs from `source::SourceHttpClient`.
#[async_trait]
pub trait SourceVersionClient: Send + Sync {
    async fn version(&self) -> Result<Option<String>>;
}

pub async fn check_source_compatibility<C: SourceVersionClient + ?Sized>(client: &C) -> Result<SourceCompatibility> {
    let version = client.version().await?;
    Ok(SourceCompatibility {
        pinned: PINNED_SOURCE_VERSION.to_string(),
        // An unenforced pin (unbundled dev run, pin = 'dev') matches any backend.
        matches: !SOURCE_PIN_ENFORCED || version.as_deref() == Some(PINNED_SOURCE_VERSION),
        version,
    })
}
