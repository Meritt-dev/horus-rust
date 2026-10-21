//! HOR-61 — Anthropic narrative provider adapter.
//!
//! Implements NarrativeProvider using the Anthropic Messages API (via reqwest —
//! no SDK dependency). The adapter builds a structured prompt from the bounded
//! NarrativeInput packet and parses a JSON NarrativeOutput from the response.
//!
//! The adapter errors on API errors; the caller (render_narrative) catches those
//! and falls back to the deterministic summary — the investigation report is
//! never blocked by AI unavailability.

use async_trait::async_trait;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

use crate::contract::{
    AIHypothesisJudgment, AIRootCauseAssessment, HypothesisVerdict, NarrativeCitation, NarrativeInput,
    NarrativeOutput, NarrativeProvider, NarrativeProviderOptions, Uncertainty,
};
use crate::interpretation::InterpretationProvider;

pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-4-8";
pub const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";

#[derive(Debug, Clone, Default)]
pub struct AnthropicProviderOptions {
    /// Anthropic API key. Defaults to the ANTHROPIC_API_KEY env var.
    pub api_key: Option<String>,
    /// Model ID. Defaults to 'claude-opus-4-8'.
    pub model: Option<String>,
    /// Base URL override — useful for pointing at a mock server. Defaults to https://api.anthropic.com.
    pub base_url: Option<String>,
}

/// Anthropic-backed NarrativeProvider.
///
/// Reads the API key from opts.api_key or ANTHROPIC_API_KEY env var. Model
/// defaults to 'claude-opus-4-8' and can be overridden per-instance.
#[derive(Debug, Clone)]
pub struct AnthropicNarrativeProvider {
    api_key: String,
    model: String,
    base_url: String,
    client: reqwest::Client,
}

impl AnthropicNarrativeProvider {
    pub fn new(opts: AnthropicProviderOptions) -> Self {
        Self {
            api_key: opts
                .api_key
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                .unwrap_or_default(),
            model: opts.model.unwrap_or_else(|| DEFAULT_ANTHROPIC_MODEL.to_string()),
            base_url: opts.base_url.unwrap_or_else(|| DEFAULT_ANTHROPIC_BASE_URL.to_string()),
            client: reqwest::Client::new(),
        }
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    async fn call_api(&self, prompt: &str) -> anyhow::Result<String> {
        let response = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .header("content-type", "application/json")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": self.model,
                "max_tokens": 1024,
                "messages": [{ "role": "user", "content": prompt }],
            }))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!(
                "Anthropic API error: {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("")
            );
        }

        let data: Value = response.json().await?;
        let content = data
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("Anthropic API response missing content"))?;
        Ok(content
            .iter()
            .find(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .and_then(|b| b.get("text").and_then(Value::as_str))
            .unwrap_or("")
            .to_string())
    }
}

#[async_trait]
impl NarrativeProvider for AnthropicNarrativeProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    async fn render(
        &self,
        input: &NarrativeInput,
        opts: Option<&NarrativeProviderOptions>,
    ) -> anyhow::Result<NarrativeOutput> {
        let ceiling = opts
            .and_then(|o| o.confidence_ceiling)
            .unwrap_or(input.report_confidence);
        let prompt = build_prompt(input, ceiling);
        let raw = self.call_api(&prompt).await?;
        Ok(parse_output(&raw, input, ceiling))
    }
}

#[async_trait]
impl InterpretationProvider for AnthropicNarrativeProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    /// HOR-211 — generic command-level interpretation. Reuses the same Messages API
    /// call as render(), but with a caller-supplied command prompt (built by
    /// build_interpretation_prompt) instead of the investigation narrative prompt.
    /// Returns the raw model text; the shared helper handles parsing/rendering.
    async fn interpret(&self, prompt: &str) -> anyhow::Result<String> {
        self.call_api(prompt).await
    }
}

pub fn build_prompt(input: &NarrativeInput, ceiling: f64) -> String {
    let evidence_lines = input
        .evidence
        .iter()
        .map(|e| {
            let excerpt = e.excerpt.as_deref().filter(|x| !x.is_empty()).map(|x| format!(": {x}")).unwrap_or_default();
            format!("- [{}] ({}) {}{}", e.id, e.kind, e.title, excerpt)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let cause_lines = input
        .suspected_causes
        .iter()
        .map(|c| format!("- {} (score: {})", c.label, c.score))
        .collect::<Vec<_>>()
        .join("\n");

    let hypothesis_lines = input
        .hypotheses
        .as_deref()
        .filter(|h| !h.is_empty())
        .map(|hs| {
            hs.iter()
                .map(|h| {
                    format!(
                        "- [{}] ({}) [deterministic: {} @ {:.2}] {}",
                        h.id,
                        h.category,
                        h.deterministic_verdict.as_str(),
                        h.deterministic_confidence,
                        h.statement
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        });

    let hypothesis_judgment_schema = if hypothesis_lines.is_some() {
        format!(
            r#"  "hypothesisJudgments": [
    {{
      "hypothesisId": "<id from hypotheses list above>",
      "category": "<category from hypotheses list>",
      "verdict": "<supported|weakened|eliminated|unconfirmed>",
      "rationale": "<one paragraph grounded in evidence IDs>",
      "citedEvidenceIds": ["<evidence IDs from the list>"],
      "confidence": <0–{ceiling}>
    }}
  ],
  "rootCauseAssessment": {{
    "summary": "<one paragraph root cause grounded in evidence>",
    "primaryHypothesisId": "<id of the hypothesis you consider the primary driver, or omit>",
    "citedEvidenceIds": ["<evidence IDs from the list>"],
    "uncertainty": "<low|medium|high>"
  }},"#
        )
    } else {
        String::new()
    };

    let hypothesis_block = hypothesis_lines
        .map(|lines| format!("\nDeterministic hypotheses (provide a second-pass judgment for each):\n{lines}"))
        .unwrap_or_default();
    let known_services = input.known_services.join(", ");

    format!(
        r#"You are an incident analysis assistant. Analyze this investigation and return a JSON judgment.

Investigation hint: {hint}
Deterministic summary: {summary}

Evidence (only cite IDs listed here):
{evidence_lines}

Suspected causes:
{cause_lines}
{hypothesis_block}

Known services: {known_services}

Return ONLY valid JSON with this exact shape:
{{
  "what": "<what happened — one concise paragraph>",
  "why": "<root cause narrative grounded in the evidence above>",
  "whereNext": ["<action 1>", "<action 2>"],
  "citations": [{{"evidenceId": "<id from the evidence list>", "rationale": "<why this supports the claim>"}}],
  "confidence": <number between 0 and {ceiling}>,
  "mentionedServices": ["<service name from known list only>"],
{hypothesis_judgment_schema}
}}

Hard rules:
- confidence must not exceed {ceiling}
- only cite evidence IDs from the list above — any other ID is a hallucination
- only include services from: {known_services}
- hypothesisJudgments must only reference hypothesis IDs from the hypotheses list above
- verdict must be exactly one of: supported, weakened, eliminated, unconfirmed
- uncertainty must be exactly one of: low, medium, high
- output raw JSON only: no markdown code fences, no text before or after the JSON"#,
        hint = input.hint,
        summary = input.deterministic_summary,
    )
}

/// Pull every balanced top-level `{…}` object out of a string by brace-counting
/// while respecting string literals and escapes (a greedy regex would over/under-match
/// when prose contains stray braces). Returned longest-first, since the real payload
/// is almost always the largest object — a tiny `{ note }` before it parses and is
/// skipped in favour of the full report.
fn slice_balanced_objects(s: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    let mut in_str = false;
    let mut escaped = false;
    // Byte scan is safe: every delimiter is ASCII and never a UTF-8 continuation byte.
    for (i, ch) in s.bytes().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if ch == b'\\' {
                escaped = true;
            } else if ch == b'"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            b'"' => in_str = true,
            b'{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            b'}' => {
                if depth > 0 {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(st) = start {
                            out.push(&s[st..=i]);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out.sort_by_key(|o| std::cmp::Reverse(o.len()));
    out
}

static TRAILING_COMMA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r",(\s*[}\]])").unwrap());
static FENCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)```(?:json)?\s*(.*?)```").unwrap());
static FENCE_MARKER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)```(?:json)?").unwrap());

/// Remove trailing commas before `}`/`]` — the most common model JSON defect.
fn strip_trailing_commas(s: &str) -> String {
    TRAILING_COMMA.replace_all(s, "${1}").into_owned()
}

/// Best-effort structured extraction from a model response (HOR-205). Tries, in order:
/// direct parse, fenced ```json block, first balanced object, and a trailing-comma
/// repair of each. Returns the parsed object, or None when nothing parses.
pub fn extract_json(raw: &str) -> Option<Map<String, Value>> {
    let trimmed = raw.trim();
    let mut candidates: Vec<&str> = vec![trimmed];

    // Fenced code block: ```json … ``` or ``` … ```
    if let Some(inner) = FENCE.captures(trimmed).and_then(|c| c.get(1)) {
        let inner = inner.as_str().trim();
        if !inner.is_empty() {
            candidates.push(inner);
        }
    }

    // Balanced objects anywhere in the text (handles surrounding prose / stray braces).
    candidates.extend(slice_balanced_objects(trimmed));

    for c in candidates {
        for variant in [c.to_string(), strip_trailing_commas(c)] {
            if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&variant) {
                return Some(obj);
            }
        }
    }
    None
}

/// Build a NarrativeOutput from unparseable model text so a malformed JSON response
/// does not discard the AI narrative entirely (HOR-205). The raw prose becomes the
/// `why` narrative; citations/services are empty (nothing to validate against) and
/// confidence is capped, so it passes validation and reaches the user as degraded
/// AI output rather than silently falling back to the deterministic summary.
fn raw_narrative_fallback(raw: &str, input: &NarrativeInput, ceiling: f64) -> NarrativeOutput {
    let cleaned = FENCE_MARKER.replace_all(raw, "");
    let cleaned = cleaned.trim();
    NarrativeOutput {
        what: if input.deterministic_summary.is_empty() {
            "AI returned an unstructured response.".to_string()
        } else {
            input.deterministic_summary.clone()
        },
        why: cleaned.chars().take(4000).collect(),
        where_next: vec![],
        citations: vec![],
        confidence: input.report_confidence.min(ceiling),
        mentioned_services: None,
        hypothesis_judgments: None,
        root_cause_assessment: None,
        degraded: Some(true),
    }
}

/// JS `String(x)` for a JSON value: strings verbatim, everything else serialized.
fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn string_list(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(Value::as_array).map(|a| a.iter().map(value_to_string).collect())
}

fn str_field(obj: &Map<String, Value>, key: &str) -> String {
    obj.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn parse_output(raw: &str, input: &NarrativeInput, ceiling: f64) -> NarrativeOutput {
    let Some(parsed) = extract_json(raw) else {
        // Could not recover structured JSON — preserve the raw narrative instead of
        // failing (which would discard the entire AI response). Log enough to debug
        // without dumping the full text (which may echo user evidence).
        eprintln!(
            "[ai] structured JSON parse failed (response length {}); preserving raw narrative fallback",
            raw.encode_utf16().count()
        );
        return raw_narrative_fallback(raw, input, ceiling);
    };

    let confidence = parsed
        .get("confidence")
        .and_then(Value::as_f64)
        .unwrap_or(input.report_confidence)
        .min(ceiling);

    let citations: Vec<NarrativeCitation> = parsed
        .get("citations")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|c| NarrativeCitation {
                    evidence_id: c.get("evidenceId").map(value_to_string).unwrap_or_default(),
                    rationale: c.get("rationale").and_then(Value::as_str).map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default();

    let mut output = NarrativeOutput {
        what: str_field(&parsed, "what"),
        why: str_field(&parsed, "why"),
        where_next: string_list(parsed.get("whereNext")).unwrap_or_default(),
        citations,
        confidence,
        mentioned_services: string_list(parsed.get("mentionedServices")),
        hypothesis_judgments: None,
        root_cause_assessment: None,
        degraded: None,
    };

    // Parse structured hypothesis judgments (HOR-197)
    if let Some(judgments) = parsed.get("hypothesisJudgments").and_then(Value::as_array) {
        output.hypothesis_judgments = Some(
            judgments
                .iter()
                .map(|j| {
                    let empty = Map::new();
                    let j = j.as_object().unwrap_or(&empty);
                    AIHypothesisJudgment {
                        hypothesis_id: str_field(j, "hypothesisId"),
                        category: str_field(j, "category"),
                        verdict: j
                            .get("verdict")
                            .and_then(Value::as_str)
                            .and_then(HypothesisVerdict::parse)
                            .unwrap_or(HypothesisVerdict::Unconfirmed),
                        rationale: str_field(j, "rationale"),
                        cited_evidence_ids: string_list(j.get("citedEvidenceIds")).unwrap_or_default(),
                        confidence: j.get("confidence").and_then(Value::as_f64).unwrap_or(0.0).min(ceiling),
                    }
                })
                .collect(),
        );
    }

    // Parse structured root cause assessment (HOR-197)
    if let Some(rca) = parsed.get("rootCauseAssessment").and_then(Value::as_object) {
        output.root_cause_assessment = Some(AIRootCauseAssessment {
            summary: str_field(rca, "summary"),
            primary_hypothesis_id: rca.get("primaryHypothesisId").and_then(Value::as_str).map(str::to_string),
            cited_evidence_ids: string_list(rca.get("citedEvidenceIds")).unwrap_or_default(),
            uncertainty: rca
                .get("uncertainty")
                .and_then(Value::as_str)
                .and_then(Uncertainty::parse)
                .unwrap_or(Uncertainty::High),
        });
    }

    output
}
