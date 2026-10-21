//! HOR-51 — AI narrative contract and citation validator.
//!
//! Defines the data boundary between Horus's deterministic investigation engine
//! and any AI narrative provider. The contract enforces:
//!
//!   1. AI receives only a bounded, structured packet (no raw logs, no live queries).
//!   2. AI output is validated before it touches the report (citation + confidence guard).
//!   3. Provider failure falls back to a deterministic summary automatically.
//!
//! AI never replaces deterministic scoring. It only annotates it.
//! The caller (CLI / engine layer) builds the NarrativeInput from the full report —
//! horus-ai stays decoupled from horus-engine.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::redact::redact_narrative_input;

// ---------------------------------------------------------------------------
// Input packet — what the AI provider receives
// ---------------------------------------------------------------------------

/// A single evidence item in the narrative input packet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NarrativeEvidenceItem {
    pub id: String,
    pub kind: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Brief structured excerpt only — never raw unbounded log lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
}

/// A suspected cause in the narrative input packet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NarrativeCauseItem {
    pub label: String,
    pub score: f64,
    pub evidence_ids: Vec<String>,
}

/// Hypothesis verdict shared by the deterministic engine and the AI judgment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HypothesisVerdict {
    Supported,
    Weakened,
    Eliminated,
    Unconfirmed,
}

impl HypothesisVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Weakened => "weakened",
            Self::Eliminated => "eliminated",
            Self::Unconfirmed => "unconfirmed",
        }
    }

    pub fn parse(v: &str) -> Option<Self> {
        match v {
            "supported" => Some(Self::Supported),
            "weakened" => Some(Self::Weakened),
            "eliminated" => Some(Self::Eliminated),
            "unconfirmed" => Some(Self::Unconfirmed),
            _ => None,
        }
    }
}

/// A deterministic hypothesis passed to the AI for second-pass judgment (HOR-197).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NarrativeHypothesisItem {
    pub id: String,
    pub category: String,
    pub statement: String,
    /// Deterministic engine verdict before AI judgment.
    pub deterministic_verdict: HypothesisVerdict,
    /// Deterministic engine confidence (0–1).
    pub deterministic_confidence: f64,
    /// Evidence IDs that support this hypothesis deterministically.
    pub supporting_evidence_ids: Vec<String>,
}

/// A key finding from the engine, passed for context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NarrativeFinding {
    pub title: String,
    pub evidence_ids: Vec<String>,
}

/// Bounded, sanitised packet passed to a NarrativeProvider.
/// All evidence IDs here are the only valid citation targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NarrativeInput {
    /// Unique investigation ID.
    pub investigation_id: String,
    /// The original user hint.
    pub hint: String,
    /// Deterministic confidence ceiling from the investigation engine (0–1).
    pub report_confidence: f64,
    /// All evidence items available for citation.
    pub evidence: Vec<NarrativeEvidenceItem>,
    /// Services mentioned in the evidence (for hallucination detection).
    pub known_services: Vec<String>,
    /// Top suspected causes from the deterministic engine.
    pub suspected_causes: Vec<NarrativeCauseItem>,
    /// Deterministic summary from the engine (provider can enhance, not replace).
    pub deterministic_summary: String,
    /// Key findings from the engine for context.
    pub findings: Vec<NarrativeFinding>,
    /// Deterministic hypotheses for AI second-pass judgment (HOR-197).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypotheses: Option<Vec<NarrativeHypothesisItem>>,
}

// ---------------------------------------------------------------------------
// Output — what the AI provider returns
// ---------------------------------------------------------------------------

/// A single citation in the narrative output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NarrativeCitation {
    pub evidence_id: String,
    /// Why this evidence supports the claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// AI second-pass judgment on a single deterministic hypothesis (HOR-197).
/// The AI may agree with, refine, or disagree with the deterministic verdict.
/// Deterministic scoring remains authoritative; this is an annotation layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AIHypothesisJudgment {
    pub hypothesis_id: String,
    pub category: String,
    pub verdict: HypothesisVerdict,
    /// One-paragraph rationale grounded in cited evidence.
    pub rationale: String,
    /// Evidence IDs the AI cites to support this verdict. Must be from NarrativeInput.evidence.
    pub cited_evidence_ids: Vec<String>,
    /// AI confidence in this verdict (0–1). Must not exceed reportConfidence.
    pub confidence: f64,
}

/// AI-reported uncertainty level based on evidence quality.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Uncertainty {
    Low,
    Medium,
    High,
}

impl Uncertainty {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(v: &str) -> Option<Self> {
        match v {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// AI structured root cause assessment (HOR-197).
/// Complements the deterministic suspected causes with an evidence-grounded narrative.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AIRootCauseAssessment {
    /// One-paragraph root cause summary grounded in cited evidence.
    pub summary: String,
    /// ID of the hypothesis the AI considers the primary cause driver, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_hypothesis_id: Option<String>,
    /// Evidence IDs cited in this root cause assessment.
    pub cited_evidence_ids: Vec<String>,
    /// AI-reported uncertainty level based on evidence quality.
    pub uncertainty: Uncertainty,
}

/// The structured output a NarrativeProvider must return.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NarrativeOutput {
    /// What happened — a human-readable summary grounded in evidence.
    pub what: String,
    /// Why it happened — root cause narrative grounded in evidence.
    pub why: String,
    /// Recommended next actions.
    #[serde(default)]
    pub where_next: Vec<String>,
    /// All evidence IDs cited in the narrative. Must be a subset of NarrativeInput.evidence IDs.
    pub citations: Vec<NarrativeCitation>,
    /// Provider-reported confidence (0–1). Must not exceed reportConfidence.
    pub confidence: f64,
    /// Optional: services the narrative mentions. Used for hallucination check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mentioned_services: Option<Vec<String>>,
    /// Structured per-hypothesis AI judgments (HOR-197).
    /// Present when input.hypotheses was supplied. AI verdict and rationale for each hypothesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis_judgments: Option<Vec<AIHypothesisJudgment>>,
    /// Structured AI root cause assessment (HOR-197).
    /// Complements the deterministic suspected causes; never replaces them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_cause_assessment: Option<AIRootCauseAssessment>,
    /// True when this narrative could not be parsed as structured JSON and `why` holds the
    /// raw model prose (HOR-205/213). The renderer labels it as unstructured AI output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<bool>,
}

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub struct NarrativeProviderOptions {
    /// Hard ceiling on confidence the provider may claim. Defaults to input.reportConfidence.
    pub confidence_ceiling: Option<f64>,
}

/// Contract all AI narrative providers must implement.
#[async_trait]
pub trait NarrativeProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn render(
        &self,
        input: &NarrativeInput,
        opts: Option<&NarrativeProviderOptions>,
    ) -> anyhow::Result<NarrativeOutput>;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NarrativeValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// Validate a NarrativeOutput against the NarrativeInput it was derived from.
/// Enforces:
///   - all cited evidence IDs exist in the input
///   - confidence does not exceed reportConfidence
///   - no new services are introduced that are not in knownServices
///   - required sections (what, why, whereNext) are non-empty strings
pub fn validate_narrative(output: &NarrativeOutput, input: &NarrativeInput) -> NarrativeValidationResult {
    let mut errors: Vec<String> = Vec::new();
    let known_ids: HashSet<&str> = input.evidence.iter().map(|e| e.id.as_str()).collect();
    let known_services: HashSet<String> = input.known_services.iter().map(|s| s.to_lowercase()).collect();

    // Required sections
    if output.what.trim().is_empty() {
        errors.push("NarrativeOutput.what is required and must be non-empty".into());
    }
    if output.why.trim().is_empty() {
        errors.push("NarrativeOutput.why is required and must be non-empty".into());
    }
    // whereNext is recommended-actions context, not core narrative. A missing or empty
    // list must NOT invalidate an otherwise-useful narrative (HOR-213) — it is a plain
    // Vec here, so a missing field already deserializes to [].

    // Citation check — unknown IDs rejected
    for citation in &output.citations {
        if !known_ids.contains(citation.evidence_id.as_str()) {
            errors.push(format!(
                "Citation references unknown evidence ID \"{}\" — hallucinated citation",
                citation.evidence_id
            ));
        }
    }

    // Confidence guard — cannot exceed deterministic ceiling
    if output.confidence > input.report_confidence + 0.001 {
        errors.push(format!(
            "NarrativeOutput.confidence ({}) exceeds reportConfidence ceiling ({})",
            output.confidence, input.report_confidence
        ));
    }
    if output.confidence < 0.0 || output.confidence > 1.0 {
        errors.push(format!(
            "NarrativeOutput.confidence must be between 0 and 1 (got {})",
            output.confidence
        ));
    }

    // Service hallucination check — only when provider declares mentionedServices
    if let Some(services) = &output.mentioned_services {
        for svc in services {
            if !known_services.contains(&svc.to_lowercase()) {
                errors.push(format!(
                    "Narrative mentions service \"{svc}\" which is not in the known services list — possible hallucination"
                ));
            }
        }
    }

    // Hypothesis judgment validation (HOR-197). Verdicts are a closed enum in Rust, so the
    // TS "invalid verdict" error is unreachable here.
    if let Some(judgments) = &output.hypothesis_judgments {
        let known_hyp_ids: HashSet<&str> = input
            .hypotheses
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|h| h.id.as_str())
            .collect();
        for j in judgments {
            if input.hypotheses.is_some() && !known_hyp_ids.contains(j.hypothesis_id.as_str()) {
                errors.push(format!(
                    "hypothesisJudgment references unknown hypothesis ID \"{}\"",
                    j.hypothesis_id
                ));
            }
            if j.rationale.trim().is_empty() {
                errors.push(format!("hypothesisJudgment \"{}\" has empty rationale", j.hypothesis_id));
            }
            for eid in &j.cited_evidence_ids {
                if !known_ids.contains(eid.as_str()) {
                    errors.push(format!(
                        "hypothesisJudgment \"{}\" cites unknown evidence ID \"{eid}\"",
                        j.hypothesis_id
                    ));
                }
            }
            if j.confidence < 0.0 || j.confidence > 1.0 {
                errors.push(format!(
                    "hypothesisJudgment \"{}\" confidence must be between 0 and 1",
                    j.hypothesis_id
                ));
            }
        }
    }

    // Root cause assessment validation (HOR-197). Uncertainty is a closed enum in Rust.
    if let Some(rca) = &output.root_cause_assessment {
        if rca.summary.trim().is_empty() {
            errors.push("rootCauseAssessment.summary must be non-empty".into());
        }
        for eid in &rca.cited_evidence_ids {
            if !known_ids.contains(eid.as_str()) {
                errors.push(format!("rootCauseAssessment cites unknown evidence ID \"{eid}\""));
            }
        }
    }

    NarrativeValidationResult { valid: errors.is_empty(), errors }
}

// ---------------------------------------------------------------------------
// render_narrative — orchestrator with fallback
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct RenderNarrativeOptions<'a> {
    pub provider: Option<&'a dyn NarrativeProvider>,
    /// Override confidence ceiling passed to the provider. Defaults to input.reportConfidence.
    pub confidence_ceiling: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RenderNarrativeResult {
    pub output: NarrativeOutput,
    /// True when the provider was used and output passed validation.
    pub from_provider: bool,
    /// True when the provider produced usable narrative text that did not fully validate
    /// (or was unstructured) — render it as a labeled raw AI section rather than discarding
    /// it for the deterministic summary (HOR-213).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<bool>,
    /// Validation errors from provider output, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_errors: Option<Vec<String>>,
}

/// Render a narrative for an investigation.
///
/// If a provider is given, calls it and validates the output. On provider error
/// or validation failure, silently falls back to a deterministic narrative so the
/// investigation report is never blocked by AI unavailability.
pub async fn render_narrative(input: &NarrativeInput, opts: RenderNarrativeOptions<'_>) -> RenderNarrativeResult {
    let ceiling = opts.confidence_ceiling.unwrap_or(input.report_confidence);

    let Some(provider) = opts.provider else {
        return RenderNarrativeResult {
            output: deterministic_fallback(input),
            from_provider: false,
            degraded: None,
            validation_errors: None,
        };
    };

    // Redact sensitive values from the packet before it reaches the provider.
    let safe_input = redact_narrative_input(input);
    let provider_opts = NarrativeProviderOptions { confidence_ceiling: Some(ceiling) };
    match provider.render(&safe_input, Some(&provider_opts)).await {
        Ok(output) => {
            let validation = validate_narrative(&output, &safe_input);
            if validation.valid && output.degraded != Some(true) {
                return RenderNarrativeResult {
                    output,
                    from_provider: true,
                    degraded: None,
                    validation_errors: None,
                };
            }
            // Not fully structured-valid (e.g. a hallucinated citation) OR an unstructured raw
            // narrative — but the model still produced usable prose. Surface it as a labeled
            // degraded section instead of discarding it for the deterministic summary (HOR-213).
            let has_text = !output.what.trim().is_empty() || !output.why.trim().is_empty();
            if has_text {
                // Carry ONLY the narrative prose to the degraded result. The structured fields
                // (citations, mentionedServices, hypothesisJudgments, rootCauseAssessment) did not
                // fully validate, so they are dropped — nothing downstream can mistake an
                // unvalidated/hallucinated cause or over-ceiling confidence for a trusted one.
                let degraded_output = NarrativeOutput {
                    what: output.what,
                    why: output.why,
                    where_next: output.where_next,
                    citations: vec![],
                    confidence: output.confidence.min(ceiling),
                    mentioned_services: None,
                    hypothesis_judgments: None,
                    root_cause_assessment: None,
                    degraded: Some(true),
                };
                return RenderNarrativeResult {
                    output: degraded_output,
                    from_provider: false,
                    degraded: Some(true),
                    validation_errors: Some(validation.errors),
                };
            }
            RenderNarrativeResult {
                output: deterministic_fallback(input),
                from_provider: false,
                degraded: None,
                validation_errors: Some(validation.errors),
            }
        }
        Err(err) => RenderNarrativeResult {
            output: deterministic_fallback(input),
            from_provider: false,
            degraded: None,
            validation_errors: Some(vec![err.to_string()]),
        },
    }
}

/// Build a deterministic narrative from the investigation packet alone.
fn deterministic_fallback(input: &NarrativeInput) -> NarrativeOutput {
    let what = input.deterministic_summary.clone();
    let why = match input.suspected_causes.first() {
        // JS toFixed(0) rounds half away from zero for positives; f64::round matches.
        Some(top) => format!("Most likely cause: {} (score {}%).", top.label, (top.score * 100.0).round()),
        None => "Root cause could not be determined from available evidence.".to_string(),
    };
    let where_next = match input.findings.first() {
        Some(f) => vec![format!("Investigate: {}", f.title)],
        None => vec!["Collect more evidence and re-run investigation.".to_string()],
    };

    NarrativeOutput {
        what,
        why,
        where_next,
        citations: vec![],
        confidence: input.report_confidence,
        mentioned_services: None,
        hypothesis_judgments: None,
        root_cause_assessment: None,
        degraded: None,
    }
}
