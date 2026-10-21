//! Port of `packages/cli/src/lib/ai-provider.ts` — shared AI provider resolution (HOR-215) and
//! the command-level `--ai` interpretation helper (HOR-211).
//!
//! Key/model resolution: saved config (`horus connect ai`) → ANTHROPIC_API_KEY env;
//! `--ai-model` wins over the saved model.

use std::path::Path;

use horus_ai::{
    generate_interpretation, AnthropicNarrativeProvider, AnthropicProviderOptions, InterpretationPromptKind,
    InterpretationRequest, InterpretationResult,
};
use horus_core::{load_config, resolve_ai_settings};
use serde_json::Value;

const DEFAULT_MODEL: &str = "claude-opus-4-8";

/// Resolved `{ apiKey, model }`. `model_override` (CLI `--ai-model`) wins.
fn resolve_ai_credentials(config: Option<&str>, model_override: Option<&str>) -> (Option<String>, String) {
    let (mut api_key, mut saved_model) = (None, None);
    if let Ok(cfg) = load_config(config.map(Path::new), None) {
        let ai = resolve_ai_settings(&cfg);
        api_key = ai.anthropic_api_key;
        saved_model = ai.model;
    }
    let api_key = api_key.or_else(|| std::env::var("ANTHROPIC_API_KEY").ok()).filter(|k| !k.is_empty());
    let model = model_override.map(str::to_string).or(saved_model).unwrap_or_else(|| DEFAULT_MODEL.to_string());
    (api_key, model)
}

/// Build the Anthropic narrative provider for `--ai` (investigate/replay/postmortem).
pub fn build_narrative_provider(config: Option<&str>, model_override: Option<&str>) -> (AnthropicNarrativeProvider, String) {
    let (api_key, model) = resolve_ai_credentials(config, model_override);
    let provider =
        AnthropicNarrativeProvider::new(AnthropicProviderOptions { api_key, model: Some(model.clone()), base_url: None });
    (provider, model)
}

/// Inputs to [`render_ai_interpretation`].
pub struct AiInterpretationOpts<'a> {
    pub command: &'a str,
    pub evidence: Value,
    pub prompt_kind: InterpretationPromptKind,
    pub output_contract: &'a str,
    pub user_intent: Option<String>,
    pub config: Option<&'a str>,
    pub model_override: Option<&'a str>,
}

/// Run a command-level AI interpretation over deterministic evidence. Never fails: a missing
/// provider or failed call yields `{ ok: false, warning }` so deterministic output stands.
/// Render the result with `horus_ai::render_interpretation`.
pub async fn render_ai_interpretation(opts: AiInterpretationOpts<'_>) -> InterpretationResult {
    let request = InterpretationRequest {
        command: opts.command.to_string(),
        user_intent: opts.user_intent.filter(|s| !s.is_empty()),
        evidence: opts.evidence,
        prompt_kind: opts.prompt_kind,
        output_contract: opts.output_contract.to_string(),
    };
    let (api_key, model) = resolve_ai_credentials(opts.config, opts.model_override);
    match api_key {
        // No configured provider — graceful "unavailable" result, no network call.
        None => generate_interpretation(&request, None, Some(&model)).await,
        Some(key) => {
            let provider = AnthropicNarrativeProvider::new(AnthropicProviderOptions {
                api_key: Some(key),
                model: Some(model.clone()),
                base_url: None,
            });
            generate_interpretation(&request, Some(&provider), Some(&model)).await
        }
    }
}

/// Print the interpretation block after a command's deterministic output (the shared TS tail:
/// `console.log('\n' + renderInterpretation(result))` + a yellow `[ai]` warning on stderr).
pub async fn print_ai_interpretation(opts: AiInterpretationOpts<'_>) {
    let result = render_ai_interpretation(opts).await;
    println!("\n{}", horus_ai::render_interpretation(&result));
    if !result.ok {
        eprintln!("{}", crate::lib::format::yellow(&format!("[ai] {}", result.warning.as_deref().unwrap_or(""))));
    }
}

