//! horus-ai — AI narrative contract, citation validator, and provider interface.
//!
//! HOR-51: defines the data boundary between the deterministic investigation engine
//! and any AI narrative provider. The contract and validator are pure and usable
//! without API keys.
//!
//! AI never replaces deterministic scoring. It only annotates it.
//! See architecture.md §2.7 and docs/source-intelligence-boundary.md.

pub mod anthropic;
pub mod contract;
pub mod detection_fixtures;
pub mod fake_provider;
pub mod fixtures;
pub mod interpretation;
pub mod local_providers;
pub mod provider_execution;
pub mod redact;

pub use contract::{
    render_narrative, validate_narrative, AIHypothesisJudgment, AIRootCauseAssessment, HypothesisVerdict,
    NarrativeCauseItem, NarrativeCitation, NarrativeEvidenceItem, NarrativeFinding, NarrativeHypothesisItem,
    NarrativeInput, NarrativeOutput, NarrativeProvider, NarrativeProviderOptions, NarrativeValidationResult,
    RenderNarrativeOptions, RenderNarrativeResult, Uncertainty,
};

pub use fixtures::{
    FIXTURE_CONFIDENCE_INFLATION, FIXTURE_HALLUCINATED_SERVICE, FIXTURE_INPUT, FIXTURE_UNKNOWN_CITATION,
    FIXTURE_VALID_OUTPUT,
};

pub use anthropic::{extract_json, AnthropicNarrativeProvider, AnthropicProviderOptions, DEFAULT_ANTHROPIC_MODEL};
pub use fake_provider::{create_fake_narrative_provider, FakeNarrativeProvider};

pub use redact::{redact_narrative_input, redact_string};

pub use local_providers::{
    create_local_provider_registry, lookup_local_provider, LocalProviderDescriptor, LocalProviderId,
    LocalProviderLookupResult, LocalProviderRegistry, LocalProviderResult, LocalProviderStatus,
    DEFAULT_LOCAL_PROVIDER_REGISTRY, LOCAL_PROVIDER_IDS,
};

pub use detection_fixtures::{
    DetectionFixtures, DETECTION_FIXTURES_INSTALLED, DETECTION_FIXTURES_READY, DETECTION_FIXTURES_UNAVAILABLE,
};

pub use provider_execution::{
    create_mocked_provider_adapter, MockProviderMode, MockedProviderAdapter, ProviderExecutionAdapter,
    ProviderRunError, ProviderRunErrorCode, ProviderRunInput, ProviderRunOutput, ProviderRunResult,
};

// HOR-211 — shared command-level AI interpretation helper.
pub use interpretation::{
    build_interpretation_prompt, generate_interpretation, render_interpretation, InterpretationPromptKind,
    InterpretationProvider, InterpretationRequest, InterpretationResult, INTERPRETATION_GROUNDING_RULES,
};
