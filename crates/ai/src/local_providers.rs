//! HOR-74 — Local AI provider registry contract.
//!
//! Centralises provider IDs and typed shapes for local AI tools (Codex, Claude,
//! Kimi, Gemini, Cursor). No CLI execution, no token reading, no auth details
//! in the public contract. Implementations (detection, doctor) build on top.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Provider IDs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum LocalProviderId {
    Codex,
    Claude,
    Kimi,
    Gemini,
    Cursor,
}

pub const LOCAL_PROVIDER_IDS: &[LocalProviderId] = &[
    LocalProviderId::Codex,
    LocalProviderId::Claude,
    LocalProviderId::Kimi,
    LocalProviderId::Gemini,
    LocalProviderId::Cursor,
];

impl LocalProviderId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Kimi => "kimi",
            Self::Gemini => "gemini",
            Self::Cursor => "cursor",
        }
    }

    pub fn parse(id: &str) -> Option<Self> {
        LOCAL_PROVIDER_IDS.iter().copied().find(|p| p.as_str() == id)
    }
}

impl fmt::Display for LocalProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Descriptor — what the registry stores per provider
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalProviderDescriptor {
    pub id: LocalProviderId,
    /// Human-readable display name for CLI output.
    pub display_name: String,
}

// ---------------------------------------------------------------------------
// Detection / doctor result shapes
// ---------------------------------------------------------------------------

/// Coarse readiness state returned by a provider detector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LocalProviderStatus {
    Ready,
    Installed,
    Unavailable,
}

impl LocalProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Installed => "installed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Result shape for a single provider's detection/doctor check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalProviderResult {
    pub id: LocalProviderId,
    pub status: LocalProviderStatus,
    /// Optional human-readable detail (e.g., "binary not found on PATH").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LocalProviderRegistry {
    /// All registered providers in insertion order.
    pub providers: Vec<LocalProviderDescriptor>,
}

impl LocalProviderRegistry {
    /// Returns the descriptor for the given ID, or None if not registered.
    pub fn get(&self, id: LocalProviderId) -> Option<&LocalProviderDescriptor> {
        self.providers.iter().find(|d| d.id == id)
    }
}

// ---------------------------------------------------------------------------
// Lookup result — enum so callers handle missing providers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProviderLookupResult<'a> {
    Found(&'a LocalProviderDescriptor),
    NotFound(String),
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

fn default_descriptors() -> Vec<LocalProviderDescriptor> {
    let d = |id, name: &str| LocalProviderDescriptor { id, display_name: name.to_string() };
    vec![
        d(LocalProviderId::Codex, "OpenAI Codex CLI"),
        d(LocalProviderId::Claude, "Anthropic Claude"),
        d(LocalProviderId::Kimi, "Moonshot Kimi"),
        d(LocalProviderId::Gemini, "Google Gemini CLI"),
        d(LocalProviderId::Cursor, "Cursor"),
    ]
}

/// Build a LocalProviderRegistry from a list of descriptors.
/// Errors if two descriptors share the same ID.
/// Defaults to the five canonical providers when called with `None`.
pub fn create_local_provider_registry(
    descriptors: Option<Vec<LocalProviderDescriptor>>,
) -> anyhow::Result<LocalProviderRegistry> {
    let descriptors = descriptors.unwrap_or_else(default_descriptors);
    let mut list: Vec<LocalProviderDescriptor> = Vec::with_capacity(descriptors.len());
    for d in descriptors {
        if list.iter().any(|x| x.id == d.id) {
            anyhow::bail!("Duplicate provider ID: {}", d.id);
        }
        list.push(d);
    }
    Ok(LocalProviderRegistry { providers: list })
}

/// Look up a provider by string ID.
/// Returns an enum result so callers cannot silently ignore a miss.
pub fn lookup_local_provider<'a>(registry: &'a LocalProviderRegistry, id: &str) -> LocalProviderLookupResult<'a> {
    match LocalProviderId::parse(id).and_then(|p| registry.get(p)) {
        Some(provider) => LocalProviderLookupResult::Found(provider),
        None => LocalProviderLookupResult::NotFound(id.to_string()),
    }
}

/// Singleton registry containing all five canonical local providers.
pub static DEFAULT_LOCAL_PROVIDER_REGISTRY: LazyLock<LocalProviderRegistry> =
    LazyLock::new(|| create_local_provider_registry(None).expect("default descriptors are unique"));
