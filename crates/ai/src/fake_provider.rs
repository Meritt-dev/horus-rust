//! HOR-113 — Reusable fake NarrativeProvider for deterministic, network-free runs.
//!
//! Use `create_fake_narrative_provider` to wrap any pre-built NarrativeOutput into
//! a NarrativeProvider that satisfies the contract without making any network
//! calls. Used by the CLI's non-network paths.

use async_trait::async_trait;

use crate::contract::{NarrativeInput, NarrativeOutput, NarrativeProvider, NarrativeProviderOptions};
use crate::fixtures::FIXTURE_VALID_OUTPUT;

#[derive(Debug, Clone)]
pub struct FakeNarrativeProvider {
    output: NarrativeOutput,
}

/// Build a deterministic NarrativeProvider that always returns the given output.
/// Defaults to `FIXTURE_VALID_OUTPUT` when no output is supplied.
///
/// The output is returned as-is — validation is intentionally left to
/// `render_narrative` / `validate_narrative` so callers can exercise both the
/// success and validation-failure paths.
pub fn create_fake_narrative_provider(output: Option<NarrativeOutput>) -> FakeNarrativeProvider {
    FakeNarrativeProvider { output: output.unwrap_or_else(|| FIXTURE_VALID_OUTPUT.clone()) }
}

#[async_trait]
impl NarrativeProvider for FakeNarrativeProvider {
    fn name(&self) -> &str {
        "fake"
    }

    async fn render(
        &self,
        _input: &NarrativeInput,
        _opts: Option<&NarrativeProviderOptions>,
    ) -> anyhow::Result<NarrativeOutput> {
        Ok(self.output.clone())
    }
}
