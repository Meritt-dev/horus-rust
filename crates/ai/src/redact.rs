//! HOR-72 — Narrative input redaction guard.
//!
//! Scans free-text fields in a NarrativeInput for obvious secret patterns
//! (URL-embedded credentials, key=value pairs, Bearer tokens, AWS keys) and
//! replaces their values with `[REDACTED]` before the packet reaches any AI
//! provider. This is a lightweight guard, not a full DLP engine.
//!
//! Invariants:
//!   - Keys / field names are preserved so the narrative stays useful.
//!   - All other (non-text) fields are copied unchanged.
//!   - The input object is never mutated; a new object is returned.

use regex::Regex;
use std::sync::LazyLock;

use crate::contract::NarrativeInput;

// ---------------------------------------------------------------------------
// Patterns — ordered from most specific to least
// ---------------------------------------------------------------------------

static REDACT_RULES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let re = |s: &str| Regex::new(s).expect("static redaction regex");
    vec![
        // URL-embedded credentials: http(s)://user:pass@host
        (re(r"(?i)(https?://)[^:@\s]+:[^@\s]+@"), "${1}[REDACTED]@"),
        // Database / service connection strings with embedded credentials
        (
            re(r"(?i)((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?)://)[^:@\s]+:[^@\s]+@"),
            "${1}[REDACTED]@",
        ),
        // AWS Access Key IDs
        (re(r"AKIA[0-9A-Z]{16}"), "[REDACTED]"),
        // Bearer tokens
        (re(r"\bBearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [REDACTED]"),
        // Cookie / set-cookie header values
        (re(r#"(?i)((?:cookie|set-cookie)\s*[=:]\s*)[^\s"',;>]{4,}"#), "${1}[REDACTED]"),
        // key=value / key: value for common credential field names
        // Captures: password, passwd, pwd, token, api_key, apikey, secret, credential
        // Note: "auth" / "authorization" is intentionally excluded — Bearer pattern handles those.
        (
            re(r#"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|credential)[=:\s]+["']?[A-Za-z0-9._\-+/=@!#$%^&*]{4,}["']?"#),
            "${1}=[REDACTED]",
        ),
    ]
});

/// Apply all redaction rules to a single string. Returns the sanitised string.
pub fn redact_string(s: &str) -> String {
    let mut result = s.to_string();
    for (pattern, replacement) in REDACT_RULES.iter() {
        result = pattern.replace_all(&result, *replacement).into_owned();
    }
    result
}

/// Return a new NarrativeInput with sensitive values redacted from all free-text
/// fields. Structural fields (IDs, scores, enums, arrays of IDs) are copied as-is.
pub fn redact_narrative_input(input: &NarrativeInput) -> NarrativeInput {
    let mut out = input.clone();
    out.hint = redact_string(&input.hint);
    out.deterministic_summary = redact_string(&input.deterministic_summary);
    for e in &mut out.evidence {
        e.title = redact_string(&e.title);
        e.excerpt = e.excerpt.as_deref().map(redact_string);
    }
    for c in &mut out.suspected_causes {
        c.label = redact_string(&c.label);
    }
    for f in &mut out.findings {
        f.title = redact_string(&f.title);
    }
    out
}
