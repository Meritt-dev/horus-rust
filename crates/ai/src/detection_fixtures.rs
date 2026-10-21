//! HOR-75 — Synthetic detection fixtures for local AI providers.
//!
//! All fixtures are offline and deterministic — no PATH probing, no CLI calls,
//! no dependency on the developer's machine.
//!
//! Three fixture sets, one per status:
//!   DETECTION_FIXTURES_READY       — binary found and working
//!   DETECTION_FIXTURES_INSTALLED   — binary found on PATH but not configured
//!   DETECTION_FIXTURES_UNAVAILABLE — binary not found on PATH

use indexmap::IndexMap;
use std::sync::LazyLock;

use crate::local_providers::{LocalProviderId, LocalProviderResult, LocalProviderStatus, LOCAL_PROVIDER_IDS};

pub type DetectionFixtures = IndexMap<&'static str, LocalProviderResult>;

fn fixtures(status: LocalProviderStatus, detail: impl Fn(LocalProviderId) -> String) -> DetectionFixtures {
    LOCAL_PROVIDER_IDS
        .iter()
        .map(|&id| (id.as_str(), LocalProviderResult { id, status, detail: Some(detail(id)) }))
        .collect()
}

// ---------------------------------------------------------------------------
// ready — binary present and authenticated / usable
// ---------------------------------------------------------------------------

pub static DETECTION_FIXTURES_READY: LazyLock<DetectionFixtures> = LazyLock::new(|| {
    fixtures(LocalProviderStatus::Ready, |id| {
        let version = match id {
            LocalProviderId::Codex => "1.0.0",
            LocalProviderId::Claude => "0.1.0",
            LocalProviderId::Kimi => "1.0.0",
            LocalProviderId::Gemini => "0.1.10",
            LocalProviderId::Cursor => "1.0.0",
        };
        format!("{id} {version} — authenticated")
    })
});

// ---------------------------------------------------------------------------
// installed — binary present on PATH but not yet configured / authenticated
// ---------------------------------------------------------------------------

pub static DETECTION_FIXTURES_INSTALLED: LazyLock<DetectionFixtures> = LazyLock::new(|| {
    fixtures(LocalProviderStatus::Installed, |_| "binary found on PATH but no active session".to_string())
});

// ---------------------------------------------------------------------------
// unavailable — binary not found on PATH
// ---------------------------------------------------------------------------

pub static DETECTION_FIXTURES_UNAVAILABLE: LazyLock<DetectionFixtures> =
    LazyLock::new(|| fixtures(LocalProviderStatus::Unavailable, |id| format!("{id}: command not found")));
