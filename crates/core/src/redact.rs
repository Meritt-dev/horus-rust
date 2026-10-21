//! Secret / PII redaction (HOR-325, promoted from connectors HOR-91).
//!
//! Two tiers of aggressiveness:
//!   - `redact_secrets`  — the conservative set (auth tokens, password/secret KV,
//!     cookies, connection-string creds, card numbers). Connection-string credential
//!     stripping is scheme-generic: known DB/broker schemes keep the '/'-permissive
//!     password class, the generic-scheme pattern excludes '/', ',' and ';' so
//!     `https://host/path@x` and comma-separated log tokens never false-positive.
//!   - `redact_content`  — the conservative set PLUS PII/credentials (emails, IPs,
//!     JWTs, cloud/provider keys, private keys). Used before free text leaves the machine.
//!
//! `redact_or_drop` adds a fail-closed guard: if a high-risk pattern still remains
//! afterward, the content is DROPPED rather than sent.

use regex::{Captures, Regex};
use std::sync::LazyLock;

enum Replacement {
    Str(&'static str),
    CardOrUuid,
}

type Pattern = (Regex, Replacement);

fn re(s: &str) -> Regex {
    Regex::new(s).expect("static redaction regex")
}

// Conservative, known-bad patterns — safe to apply to log evidence (HOR-91).
static BASE_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        (re(r#"(?i)(authorization\s*[=:]\s*)(bearer\s+)[^\s,"')]+"#), Replacement::Str("${1}${2}[REDACTED]")),
        (re(r#"(?i)(authorization\s*[=:]\s*)(basic\s+)[^\s,"')]+"#), Replacement::Str("${1}${2}[REDACTED]")),
        (
            re(r#"(?i)("?(?:password|passwd|secret|token|api[_-]key|apikey|x-api-key)"?\s*[=:]\s*)"?[^"',\s)>]+"#),
            Replacement::Str("${1}[REDACTED]"),
        ),
        (re(r#"(?i)((?:cookie|set-cookie)\s*[=:]\s*)[^\s"',;>]{4,}"#), Replacement::Str("${1}[REDACTED]")),
        // Known DB/broker schemes: password may contain raw '/' (HOR-91 behaviour preserved).
        (
            re(r"(?i)((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://)[^:@/\s]*:[^@\s]+@"),
            Replacement::Str("${1}[REDACTED]@"),
        ),
        // Scheme-generic URL userinfo (`scheme://user:pass@`, empty username allowed).
        (re(r"(?i)([a-z][a-z0-9+.-]*://)[^:@/\s,;]*:[^@/\s,;]+@"), Replacement::Str("${1}[REDACTED]@")),
        // Numeric UUID segments are incident/operation identities, not card numbers.
        (
            re(r"(?i)(\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b)|\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b"),
            Replacement::CardOrUuid,
        ),
    ]
});

// Aggressive PII/credential patterns — only for content that leaves the machine.
static EXTENDED_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        // PEM private key blocks (run first — multi-line, highest risk).
        (
            re(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----"),
            Replacement::Str("[REDACTED-PRIVATE-KEY]"),
        ),
        // JSON Web Tokens.
        (re(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), Replacement::Str("[REDACTED-JWT]")),
        // AWS access key ids.
        (re(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Replacement::Str("[REDACTED-AWS-KEY]")),
        // Google API keys.
        (re(r"\bAIza[0-9A-Za-z_-]{35}\b"), Replacement::Str("[REDACTED-GCP-KEY]")),
        // Slack tokens.
        (re(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Replacement::Str("[REDACTED-SLACK-TOKEN]")),
        // GitHub tokens.
        (re(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), Replacement::Str("[REDACTED-GH-TOKEN]")),
        // Emails.
        (re(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), Replacement::Str("[REDACTED-EMAIL]")),
        // IPv4 addresses.
        (re(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), Replacement::Str("[REDACTED-IP]")),
    ]
});

// If any of these survive redaction, something slipped — fail closed and drop.
static RESIDUAL_HIGH_RISK: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        re(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
        re(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        re(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ]
});

fn apply(patterns: &[Pattern], input: &str) -> String {
    let mut out = input.to_string();
    for (pattern, replacement) in patterns {
        out = match replacement {
            Replacement::Str(s) => pattern.replace_all(&out, *s).into_owned(),
            Replacement::CardOrUuid => pattern
                .replace_all(&out, |c: &Captures| {
                    c.get(1).map(|m| m.as_str().to_string()).unwrap_or_else(|| "[REDACTED-CARD]".to_string())
                })
                .into_owned(),
        };
    }
    out
}

/// Conservative scrub (auth/secret/card/conn-string). HOR-91 set, with the conn-string
/// pattern generalized to any URL scheme.
pub fn redact_secrets(input: &str) -> String {
    apply(&BASE_PATTERNS, input)
}

/// Redact a caught error's message — for connector health() details.
pub fn redact_error_message(err: &dyn std::fmt::Display) -> String {
    redact_secrets(&err.to_string())
}

/// Redact-then-cap an upstream response body before it is interpolated into an error.
/// `max` counts UTF-16 code units like JS `slice`; chars are close enough here.
pub fn redact_upstream_body(text: &str, max: Option<usize>) -> String {
    redact_secrets(text).chars().take(max.unwrap_or(200)).collect()
}

/// Aggressive scrub for content leaving the machine: secrets + PII + provider keys.
pub fn redact_content(input: &str) -> String {
    apply(&EXTENDED_PATTERNS, &apply(&BASE_PATTERNS, input))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    /// The redacted string, or None when dropped.
    pub value: Option<String>,
    /// True when content was dropped because a secret survived redaction.
    pub dropped: bool,
}

/// Fail-closed redaction: the scrubbed string, or `{ value: None, dropped: true }`
/// if a high-risk pattern remains afterward.
pub fn redact_or_drop(input: &str) -> RedactionResult {
    let value = redact_content(input);
    if RESIDUAL_HIGH_RISK.iter().any(|p| p.is_match(&value)) {
        return RedactionResult { value: None, dropped: true };
    }
    RedactionResult { value: Some(value), dropped: false }
}
