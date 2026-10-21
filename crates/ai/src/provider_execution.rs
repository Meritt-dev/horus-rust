//! HOR-77 — Local provider execution contract and mocked adapter.
//!
//! Defines the typed boundary for running a prompt through a local AI provider
//! command. No real binaries are invoked here — real adapters build on top of
//! this contract. The mocked adapter covers success, failure, timeout, and
//! unsupported modes for deterministic CLI stubs.

use async_trait::async_trait;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::local_providers::LocalProviderId;

// ---------------------------------------------------------------------------
// Run input / output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRunInput {
    pub provider_id: LocalProviderId,
    /// The prompt to send to the provider.
    pub prompt: String,
    /// Execution timeout in milliseconds. Defaults to 30 000 ms in real adapters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Optional caller-supplied request ID for correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRunOutput {
    pub provider_id: LocalProviderId,
    /// The provider's text response.
    pub text: String,
    /// Wall-clock execution duration in milliseconds.
    pub duration_ms: u64,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderRunErrorCode {
    Unsupported,
    Timeout,
    ExecutionFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRunError {
    pub code: ProviderRunErrorCode,
    /// Human-readable message suitable for CLI output.
    pub message: String,
    pub provider_id: LocalProviderId,
}

// ---------------------------------------------------------------------------
// Result — enum so callers must handle both branches.
// Serializes as `{ "ok": true, "output": … }` / `{ "ok": false, "error": … }`.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderRunResult {
    Ok(ProviderRunOutput),
    Err(ProviderRunError),
}

impl Serialize for ProviderRunResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("ProviderRunResult", 2)?;
        match self {
            Self::Ok(output) => {
                s.serialize_field("ok", &true)?;
                s.serialize_field("output", output)?;
            }
            Self::Err(error) => {
                s.serialize_field("ok", &false)?;
                s.serialize_field("error", error)?;
            }
        }
        s.end()
    }
}

// ---------------------------------------------------------------------------
// Adapter interface — real adapters implement this
// ---------------------------------------------------------------------------

#[async_trait]
pub trait ProviderExecutionAdapter: Send + Sync {
    async fn run(&self, input: &ProviderRunInput) -> ProviderRunResult;
}

// ---------------------------------------------------------------------------
// Mocked adapter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MockProviderMode {
    Success,
    Failure,
    Timeout,
    Unsupported,
}

#[derive(Debug, Clone, Copy)]
pub struct MockedProviderAdapter {
    mode: MockProviderMode,
}

/// Build a deterministic adapter that returns a fixed result shape for the
/// given mode. Useful for CLI stubs — no binaries are invoked.
pub fn create_mocked_provider_adapter(mode: MockProviderMode) -> MockedProviderAdapter {
    MockedProviderAdapter { mode }
}

#[async_trait]
impl ProviderExecutionAdapter for MockedProviderAdapter {
    async fn run(&self, input: &ProviderRunInput) -> ProviderRunResult {
        let err = |code, message| ProviderRunResult::Err(ProviderRunError { code, message, provider_id: input.provider_id });
        match self.mode {
            MockProviderMode::Success => ProviderRunResult::Ok(ProviderRunOutput {
                provider_id: input.provider_id,
                text: format!("[mock] response to: {}", input.prompt.chars().take(60).collect::<String>()),
                duration_ms: 42,
            }),
            MockProviderMode::Failure => err(
                ProviderRunErrorCode::ExecutionFailed,
                format!("{}: process exited with non-zero code (mock)", input.provider_id),
            ),
            MockProviderMode::Timeout => err(
                ProviderRunErrorCode::Timeout,
                format!("{}: timed out after {}ms (mock)", input.provider_id, input.timeout_ms.unwrap_or(30000)),
            ),
            MockProviderMode::Unsupported => err(
                ProviderRunErrorCode::Unsupported,
                format!("provider \"{}\" is not supported by this adapter", input.provider_id),
            ),
        }
    }
}
