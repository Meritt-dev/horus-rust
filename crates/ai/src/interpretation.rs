//! HOR-211 — Shared command-level AI interpretation helper.
//!
//! Several Horus commands expose (or will expose) an optional `--ai` flag that
//! interprets the deterministic evidence the command already gathered:
//! `what-changed`, `timeline`, `blast-radius`, `architecture`, `onboard`,
//! `readiness`, `changes`, `logs`, `metrics`, `state`, `queues --live`, `score`.
//!
//! Without a shared helper, each command would re-implement provider resolution,
//! the grounding prompt, error handling, and the evidence/interpretation
//! separation. This module owns the command-level concerns that are NOT
//! investigation-specific:
//!
//!   - the grounded prompt (interpret, don't invent; cite only given evidence)
//!   - a minimal text-completion provider contract (`InterpretationProvider`)
//!   - graceful degradation when no provider is configured or the call fails
//!
//! It deliberately does NOT replace the investigation NarrativeProvider contract
//! (NarrativeInput → NarrativeOutput with citations); that remains the canonical
//! path for `investigate --ai`. `AnthropicNarrativeProvider` implements both:
//! `render` for the structured investigation narrative and `interpret` for
//! generic command interpretation.
//!
//! AI never creates evidence. It only interprets the evidence a command provides.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Command-specific prompt flavor. Determines the interpretation guidance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InterpretationPromptKind {
    ChangeRisk,
    TimelineNarrative,
    BlastRadius,
    SystemExplanation,
    Readiness,
    EvidenceSummary,
}

impl InterpretationPromptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChangeRisk => "change-risk",
            Self::TimelineNarrative => "timeline-narrative",
            Self::BlastRadius => "blast-radius",
            Self::SystemExplanation => "system-explanation",
            Self::Readiness => "readiness",
            Self::EvidenceSummary => "evidence-summary",
        }
    }

    fn guidance(self) -> &'static str {
        match self {
            Self::ChangeRisk => "Assess which changes carry the most risk and why, ranking by likely impact, grounded only in the evidence.",
            Self::TimelineNarrative => "Narrate the ordering of changes and evidence into phases; flag suspicious ordering and gaps in coverage.",
            Self::BlastRadius => "Explain severity, likely user impact, containment, and safe mitigations for the affected dependencies.",
            Self::SystemExplanation => "Explain how this system/subsystem works at onboarding quality, grounded in the evidence.",
            Self::Readiness => "Summarize readiness and risk, then prioritize what to do next before proceeding.",
            Self::EvidenceSummary => "Summarize what the evidence shows. Do not assert a root cause the evidence does not support.",
        }
    }
}

/// What a command passes to the helper after it has gathered deterministic evidence.
#[derive(Debug, Clone)]
pub struct InterpretationRequest {
    /// Command name, e.g. 'what-changed'. Used in the prompt and the rendered header.
    pub command: String,
    /// Optional user question/hint that scopes the interpretation.
    pub user_intent: Option<String>,
    /// Structured deterministic evidence the command produced. Prefer a structured
    /// value over pre-rendered terminal strings so the model sees facts, not formatting.
    pub evidence: Value,
    /// Command-specific prompt flavor.
    pub prompt_kind: InterpretationPromptKind,
    /// Command-specific description of the desired output shape/sections.
    pub output_contract: String,
}

/// Minimal text-completion contract for command-level interpretation. Kept separate
/// from `NarrativeProvider` (which is investigation-specific). A single provider can
/// implement both — `AnthropicNarrativeProvider` does.
#[async_trait]
pub trait InterpretationProvider: Send + Sync {
    fn name(&self) -> &str;
    /// Send a fully-built prompt and return the model's raw text response.
    async fn interpret(&self, prompt: &str) -> anyhow::Result<String>;
}

/// A renderable result or a graceful warning. Never fails back to the command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InterpretationResult {
    pub ok: bool,
    pub command: String,
    pub prompt_kind: InterpretationPromptKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Present when `ok`: the model's interpretation text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Present when `!ok`: a user-facing reason (provider unavailable / error / empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// The evidence-only grounding rules shared by every command-level `--ai` prompt.
pub const INTERPRETATION_GROUNDING_RULES: &[&str] = &[
    "You are interpreting Horus evidence, not gathering new evidence.",
    "Do not invent files, commits, services, queues, logs, metrics, dashboards, owners, or timestamps.",
    "Use only the evidence provided above — any fact not present in it is a hallucination.",
    "Clearly separate \"Evidence used\" from \"Interpretation\".",
    "State your confidence and call out any missing evidence that would change the conclusion.",
    "When suggesting next checks, prefer exact follow-up Horus commands.",
];

fn stringify_evidence(evidence: &Value) -> String {
    match evidence {
        Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
    }
}

/// Build the grounded command-level interpretation prompt. Exported so commands can
/// preview/snapshot it.
pub fn build_interpretation_prompt(req: &InterpretationRequest) -> String {
    let guidance = req.prompt_kind.guidance();
    let evidence_block = stringify_evidence(&req.evidence);
    let rules = INTERPRETATION_GROUNDING_RULES
        .iter()
        .map(|r| format!("- {r}"))
        .collect::<Vec<_>>()
        .join("\n");
    let intent = match &req.user_intent {
        Some(i) if !i.is_empty() => format!("\nUser intent: {i}\n"),
        _ => String::new(),
    };
    format!(
        "You are the Horus AI interpretation layer for the `{command}` command.
Task kind: {kind}. {guidance}
{intent}
Evidence used (this is the ONLY ground truth — interpret it, do not extend it):
{evidence_block}

Output contract:
{output_contract}

Rules:
{rules}
- End with a \"Confidence:\" line (low | medium | high) and a \"Next checks:\" list of concrete Horus commands.",
        command = req.command,
        kind = req.prompt_kind.as_str(),
        output_contract = req.output_contract,
    )
}

/// Run a command-level interpretation. Never fails: a missing provider, a provider
/// error, or an empty response all degrade to `{ ok: false, warning }` so the command
/// can still print its deterministic output and simply append the warning.
///
/// `provider` is the resolved interpretation provider, or `None` when none is
/// configured (yields the "provider unavailable" warning). `model` is an optional
/// model id to surface in the result/header.
pub async fn generate_interpretation(
    req: &InterpretationRequest,
    provider: Option<&dyn InterpretationProvider>,
    model: Option<&str>,
) -> InterpretationResult {
    let mut base = InterpretationResult {
        ok: false,
        command: req.command.clone(),
        prompt_kind: req.prompt_kind,
        provider: None,
        model: model.filter(|m| !m.is_empty()).map(str::to_string),
        text: None,
        warning: None,
    };
    let Some(provider) = provider else {
        base.warning =
            Some("No AI provider configured. Run `horus connect ai` or set ANTHROPIC_API_KEY to enable --ai.".into());
        return base;
    };
    base.provider = Some(provider.name().to_string());
    let prompt = build_interpretation_prompt(req);
    match provider.interpret(&prompt).await {
        Ok(raw) => {
            let text = raw.trim();
            if text.is_empty() {
                base.warning = Some("AI provider returned an empty response.".into());
                return base;
            }
            base.ok = true;
            base.text = Some(text.to_string());
            base
        }
        Err(err) => {
            base.warning = Some(format!("AI interpretation failed: {err}"));
            base
        }
    }
}

/// Render an interpretation result to a plain-text section (no terminal colors, so it
/// is reusable outside the CLI). The header keeps the AI output visually separate from
/// the deterministic command output; callers print this AFTER their own output.
pub fn render_interpretation(result: &InterpretationResult) -> String {
    let attribution = match (&result.model, &result.provider) {
        (Some(model), provider) => format!(" ({}, {model})", provider.as_deref().unwrap_or("ai")),
        (None, Some(provider)) => format!(" ({provider})"),
        (None, None) => String::new(),
    };
    let header = format!("── AI Interpretation{attribution} ──");
    if !result.ok {
        return format!(
            "{header}\n{}",
            result.warning.as_deref().unwrap_or("AI interpretation unavailable.")
        );
    }
    format!("{header}\n{}", result.text.as_deref().unwrap_or(""))
}
