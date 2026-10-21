//! Outbound notify sink for `horus watch` (HOR-454). Port of `packages/cli/src/lib/notify-sink.ts`.
//!
//! When a watched auto-investigation clears the confidence threshold, its one-line headline is
//! dispatched to a generic HMAC-signed webhook and/or a Horus Cloud push. CLI/notify-layer only:
//! the engine never sees it. Dispatch is BEST-EFFORT and never fails — a failed send is
//! returned as a typed failure so the watch loop logs it and carries on.

use std::future::Future;
use std::time::Duration;

use horus_core::{redact_secrets, NotifyConfig};
use horus_engine::types::InvestigationReport;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The Claude result fields the notification needs (`validateClaudeResult(...).result`).
pub struct AiNotice<'a> {
    pub likely_cause: Option<&'a str>,
    pub evidence_ids: &'a [String],
    pub uncertainty: &'a str,
    pub next_checks: &'a [String],
}

/// A serde enum/struct field as its JSON string (e.g. `FixPrStatus::Open` → "open").
fn json_str<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        _ => String::new(),
    }
}

/// Bounded evidence and historical context for the unattended result notification.
pub fn notification_cause(report: &InvestigationReport, ai: Option<&AiNotice<'_>>, ai_failed: bool) -> String {
    let short = |v: &str| -> String {
        redact_secrets(v).split_whitespace().collect::<Vec<_>>().join(" ").chars().take(240).collect()
    };
    let evidence: Vec<String> = report
        .evidence
        .iter()
        .filter(|e| ai.map_or(true, |a| a.evidence_ids.contains(&e.id)))
        .take(3)
        .map(|e| format!("{}: {}", short(&e.id), short(&e.title)))
        .collect();
    let history: Vec<String> = report
        .startup_recall
        .as_deref()
        .unwrap_or_default()
        .iter()
        .take(3)
        .map(|m| {
            let v = serde_json::to_value(m).unwrap_or(Value::Null);
            let certainty = v.pointer("/outcome/certainty").and_then(Value::as_str).unwrap_or("inferred").to_string();
            let validation = v.get("validation").and_then(Value::as_str).unwrap_or("").to_string();
            format!("{} ({certainty}, {validation}): {}", short(&m.memory_id), short(&m.claim))
        })
        .collect();
    let headline = match ai {
        Some(a) => a.likely_cause.unwrap_or("Cause uncertain").to_string(),
        None => report.suspected_causes.first().map_or("Cause uncertain".into(), |c| c.title.clone()),
    };
    let mut parts = vec![
        format!("{}{}.", if ai_failed { "Engine-only (AI failed). " } else { "" }, short(&headline)),
        short(ai.map_or("Current cause remains unconfirmed.", |a| a.uncertainty)),
        format!("Current evidence: {}.", if evidence.is_empty() { "none cited".into() } else { evidence.join("; ") }),
    ];
    if !history.is_empty() {
        parts.push(format!("Historical context (not current proof): {}.", history.join("; ")));
    }
    parts.push(format!(
        "Diagnosis: {}.",
        report.diagnosis.as_ref().map_or("unresolved".into(), json_str)
    ));
    if let Some(pr) = &report.fix_pr {
        parts.push(match &pr.url {
            Some(url) if !url.is_empty() => format!("Fix PR ({}): {url}", json_str(&pr.status)),
            _ => format!("Fix PR: {}", short(&pr.summary)),
        });
    }
    let next = ai.and_then(|a| a.next_checks.first().map(String::as_str)).unwrap_or("Review current evidence and missing signals");
    parts.push(format!("Next: {}", short(next)));
    parts.retain(|p| !p.is_empty());
    parts.join(" ")
}

/// A finished headline ready to dispatch.
#[derive(Debug, Clone)]
pub struct NotifyHeadline {
    pub investigation_id: String,
    pub hint: String,
    pub cause: String,
    pub confidence: f64,
    pub notification_key: Option<String>,
    pub report_url: Option<String>,
}

/// Outcome of one sink dispatch — never thrown, always returned.
#[derive(Debug, Clone, Serialize)]
pub struct NotifyResult {
    /// `webhook` | `cloud`.
    pub target: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// JS `Math.round` (half up).
fn js_round(x: f64) -> f64 {
    (x + 0.5).floor()
}

/// The JSON payload posted to a webhook (Slack-compatible `text` + structured fields).
/// `undefined` optional keys are omitted, matching `JSON.stringify`.
pub fn build_webhook_payload(h: &NotifyHeadline) -> Value {
    let pct = format!("{}%", js_round(h.confidence * 100.0));
    let url = h.report_url.as_deref().filter(|u| !u.is_empty()).map(|u| format!("\n{u}")).unwrap_or_default();
    let mut m = Map::new();
    m.insert("text".into(), format!("🔭 Horus: {} → {} ({pct}){url}", h.hint, h.cause).into());
    m.insert("investigationId".into(), h.investigation_id.clone().into());
    m.insert("hint".into(), h.hint.clone().into());
    m.insert("cause".into(), h.cause.clone().into());
    m.insert("confidence".into(), json!(h.confidence));
    if let Some(k) = &h.notification_key {
        m.insert("notificationKey".into(), k.clone().into());
    }
    if let Some(u) = &h.report_url {
        m.insert("reportUrl".into(), u.clone().into());
    }
    Value::Object(m)
}

/// HMAC-SHA256 (RFC 2104) over sha2 — no extra crate for a dozen lines.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| k.iter().map(|x| x ^ b).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

/// Hex HMAC-SHA256 of the exact body under `secret` — the `X-Horus-Signature` value.
pub fn sign_payload(body: &str, secret: &str) -> String {
    let mac = hmac_sha256(secret.as_bytes(), body.as_bytes());
    format!("sha256={}", mac.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Dispatch when confidence clears the sink's threshold and a target is enabled.
pub fn should_notify(confidence: f64, notify: Option<&NotifyConfig>) -> bool {
    let Some(n) = notify else { return false };
    if n.webhook.is_none() && !n.cloud {
        return false;
    }
    confidence >= n.min_confidence
}

async fn post_webhook(url: &str, secret: Option<&str>, h: &NotifyHeadline, timeout_ms: u64) -> NotifyResult {
    let body = horus_core::json::to_js_json(&build_webhook_payload(h)).unwrap_or_default();
    let mut req = reqwest::Client::new()
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .header("content-type", "application/json");
    if let Some(k) = &h.notification_key {
        req = req.header("idempotency-key", k);
    }
    if let Some(s) = secret {
        req = req.header("x-horus-signature", sign_payload(&body, s));
    }
    match req.body(body).send().await {
        Ok(res) => {
            let status = res.status().as_u16();
            NotifyResult { target: "webhook", ok: res.status().is_success(), detail: format!("HTTP {status}") }
        }
        Err(e) => NotifyResult { target: "webhook", ok: false, detail: e.to_string() },
    }
}

/// What a dispatch needs from the finished report.
pub struct DispatchReport {
    pub id: String,
    pub confidence: f64,
    pub hint: String,
    pub cause: String,
    pub notification_key: Option<String>,
    pub report_url: Option<String>,
}

/// Dispatch a headline to every configured sink. One result per attempted target (empty when
/// nothing is configured or confidence is below threshold). Never fails. `cloud_push` is
/// injected by the caller, which already holds a cloud session.
pub async fn dispatch_notify<F, Fut>(
    report: DispatchReport,
    notify: Option<&NotifyConfig>,
    timeout_ms: Option<u64>,
    cloud_push: Option<F>,
) -> Vec<NotifyResult>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let Some(n) = notify else { return Vec::new() };
    if !should_notify(report.confidence, Some(n)) {
        return Vec::new();
    }
    let h = NotifyHeadline {
        investigation_id: report.id,
        hint: report.hint,
        cause: report.cause,
        confidence: report.confidence,
        notification_key: report.notification_key,
        report_url: report.report_url,
    };
    let mut results = Vec::new();
    if let Some(w) = &n.webhook {
        results.push(post_webhook(&w.url, w.secret.as_deref(), &h, timeout_ms.unwrap_or(5000)).await);
    }
    if let (true, Some(push)) = (n.cloud, cloud_push) {
        results.push(match push().await {
            Ok(()) => NotifyResult { target: "cloud", ok: true, detail: "pushed".into() },
            Err(e) => NotifyResult { target: "cloud", ok: false, detail: e.to_string() },
        });
    }
    results
}

/// No cloud push (the `cloud_push` slot's `None` type).
pub type NoPush = fn() -> std::future::Ready<anyhow::Result<()>>;
