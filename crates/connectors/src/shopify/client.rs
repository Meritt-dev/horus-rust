//! Read-only Shopify Admin GraphQL client.
//!
//! The Admin API is a single GraphQL endpoint. This client embeds NO queries: the caller
//! supplies the GraphQL document + variables and the client runs it verbatim against
//! `https://{store}/admin/api/{version}/graphql.json` with an `X-Shopify-Access-Token` header.
//!
//! Auth is a read-only Client-Credentials grant: `client_id` (access_id) + `client_secret`
//! (secret) are exchanged for a short-lived Admin API token at `/admin/oauth/access_token`,
//! cached with an expiry margin and refreshed on 401. When no `access_id` is configured the
//! `secret` is treated as a direct Admin API token (no grant).
//!
//! Safety: every request is bounded by an 8s timeout; GraphQL `THROTTLED` errors and HTTP
//! 429 are retried with bounded backoff. `graphql()` fails on a hard failure (its provider
//! degrades to []); `health()` returns a structured `{ ok, detail }` and never fails.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use horus_core::{redact_error_message, redact_secrets, redact_upstream_body, HealthStatus};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct ShopifyClientOpts {
    /// Store subdomain, e.g. "my-store" — `.myshopify.com` is added internally (a full domain also works).
    pub store: String,
    /// Admin API version segment, e.g. "2025-10". Normalized/defaulted when omitted/invalid.
    pub api_version: Option<String>,
    /// App client_id for the Client-Credentials grant. When absent, `secret` is used directly.
    pub access_id: Option<String>,
    /// App client_secret (or, when `access_id` is absent, a direct Admin API access token).
    pub secret: String,
    /// Base URL override. Defaults to `https://{store}`. Trailing slash trimmed.
    pub base_url: Option<String>,
}

/// Shopify Admin GraphQL throttle status (from `extensions.cost.throttleStatus`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShopifyThrottleStatus {
    #[serde(default)]
    pub maximum_available: f64,
    #[serde(default)]
    pub currently_available: f64,
    #[serde(default)]
    pub restore_rate: f64,
}

/// The `extensions.cost` block Shopify returns on every GraphQL response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShopifyCost {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_query_cost: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_query_cost: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttle_status: Option<ShopifyThrottleStatus>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ShopifyExtensions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<ShopifyCost>,
}

/// A GraphQL error — `message` plus any extra keys verbatim.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ShopifyGraphQLError {
    #[serde(default)]
    pub message: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A parsed Admin GraphQL response — `data`, GraphQL `errors`, and the cost extension.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ShopifyGraphQLResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ShopifyGraphQLError>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ShopifyExtensions>,
}

const REQUEST_TIMEOUT_MS: u64 = 8000;
const DEFAULT_API_VERSION: &str = "2025-10";
/// Refresh the CC token this many seconds before its stated expiry.
const TOKEN_REFRESH_MARGIN_S: f64 = 120.0;
/// Bounded retries for HTTP 429 / GraphQL THROTTLED.
const MAX_RETRIES: u32 = 2;
/// Cap a single backoff wait so a throttled store can't stall an investigation.
const MAX_BACKOFF_MS: f64 = 5000.0;

/// Normalize a store to its host: strip scheme/trailing slash, append `.myshopify.com` if bare.
pub fn normalize_store(raw: &str) -> String {
    let s = Regex::new(r"(?i)^https?://").unwrap().replace(raw.trim(), "");
    let s = s.trim_end_matches('/');
    if s.contains('.') { s.to_string() } else { format!("{s}.myshopify.com") }
}

/// Return `raw` if it is a valid `YYYY-MM` Admin API version, else the current default.
pub fn normalize_api_version(raw: Option<&str>) -> String {
    let v = raw.unwrap_or("").trim();
    if Regex::new(r"^20\d{2}-\d{2}$").unwrap().is_match(v) { v.to_string() } else { DEFAULT_API_VERSION.to_string() }
}

/// True when a GraphQL response carries a THROTTLED error (rate-limit backpressure).
pub fn is_throttled(result: &ShopifyGraphQLResult) -> bool {
    result.errors.iter().flatten().any(|e| {
        e.extra.get("extensions").and_then(|x| x.get("code")).and_then(Value::as_str) == Some("THROTTLED")
    })
}

struct CachedToken {
    token: String,
    expires_at: Instant,
}

pub struct ShopifyAdminClient {
    store: String,
    api_version: String,
    base_url: String,
    access_id: Option<String>,
    secret: String,
    token: Mutex<Option<CachedToken>>,
    http: reqwest::Client,
}

impl ShopifyAdminClient {
    pub fn new(opts: ShopifyClientOpts) -> Self {
        let store = normalize_store(&opts.store);
        let base_url = opts.base_url.unwrap_or_else(|| format!("https://{store}"));
        Self {
            base_url: base_url.strip_suffix('/').unwrap_or(&base_url).to_string(),
            store,
            api_version: normalize_api_version(opts.api_version.as_deref()),
            access_id: opts.access_id,
            secret: opts.secret,
            token: Mutex::new(None),
            http: reqwest::Client::new(),
        }
    }

    pub fn store(&self) -> &str {
        &self.store
    }

    /// Resolve a valid Admin API token. With an `access_id`, runs the Client-Credentials
    /// grant and caches the result until (expiry - margin); without one, returns `secret`
    /// as a direct token. Fails on a failed grant.
    async fn ensure_token(&self) -> anyhow::Result<String> {
        let Some(access_id) = self.access_id.as_deref().filter(|a| !a.is_empty()) else {
            return Ok(self.secret.clone());
        };
        if let Some(t) = self.token.lock().unwrap().as_ref() {
            if Instant::now() < t.expires_at {
                return Ok(t.token.clone());
            }
        }
        // Form-encoded body — matches Shopify's OAuth token endpoint. Shopify rejects a JSON
        // body on this endpoint for some app configs.
        let res = self
            .http
            .post(format!("{}/admin/oauth/access_token", self.base_url))
            .header("Accept", "application/json")
            .form(&[("client_id", access_id), ("client_secret", self.secret.as_str()), ("grant_type", "client_credentials")])
            .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS))
            .send()
            .await?;
        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            // Redact + cap: this body is the OAuth endpoint's response to a request carrying
            // client_id + client_secret — it can echo them back.
            anyhow::bail!("Shopify token exchange -> {status}: {}", redact_upstream_body(&text, None));
        }
        let json: Value = res.json().await?;
        let Some(token) = json.get("access_token").and_then(Value::as_str).filter(|t| !t.is_empty()) else {
            anyhow::bail!("Shopify token exchange returned no access_token");
        };
        let ttl = json.get("expires_in").and_then(Value::as_f64).unwrap_or(86_400.0);
        let expires_at = Instant::now() + Duration::from_secs_f64((ttl - TOKEN_REFRESH_MARGIN_S).max(0.0));
        *self.token.lock().unwrap() = Some(CachedToken { token: token.to_string(), expires_at });
        Ok(token.to_string())
    }

    /// Drop any cached token so the next request re-runs the grant (used after a 401).
    fn invalidate_token(&self) {
        *self.token.lock().unwrap() = None;
    }

    /// Run a GraphQL document verbatim against the Admin API and return the parsed result.
    /// Retries HTTP 429 / GraphQL THROTTLED with bounded backoff; refreshes the token once
    /// on 401. Fails on a non-retryable HTTP error.
    pub async fn graphql(&self, query: &str, variables: Option<&Map<String, Value>>) -> anyhow::Result<ShopifyGraphQLResult> {
        let url = format!("{}/admin/api/{}/graphql.json", self.base_url, self.api_version);
        let body = json!({ "query": query, "variables": variables.cloned().unwrap_or_default() });
        let mut http_retries = 0u32;
        let mut throttle_retries = 0u32;
        let mut refreshed_on_401 = false;

        loop {
            let token = self.ensure_token().await?;
            let res = self
                .http
                .post(&url)
                .header("X-Shopify-Access-Token", token)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&body)
                .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS))
                .send()
                .await?;

            let status = res.status().as_u16();
            if status == 401 && !refreshed_on_401 {
                refreshed_on_401 = true;
                self.invalidate_token();
                continue;
            }
            if status == 429 && http_retries < MAX_RETRIES {
                http_retries += 1;
                tokio::time::sleep(Duration::from_millis(retry_after_ms(&res, http_retries))).await;
                continue;
            }
            if !res.status().is_success() {
                let text = res.text().await.unwrap_or_default();
                anyhow::bail!("Shopify GraphQL -> {status}: {}", redact_upstream_body(&text, None));
            }

            let result: ShopifyGraphQLResult = res.json().await?;
            if is_throttled(&result) && throttle_retries < MAX_RETRIES {
                throttle_retries += 1;
                tokio::time::sleep(Duration::from_millis(throttle_backoff_ms(&result, throttle_retries))).await;
                continue;
            }
            return Ok(result);
        }
    }

    /// Liveness probe: run a minimal `{ shop { name } }` query — the connector's ONLY owned
    /// query, used purely for health / connect-time validation, NEVER for evidence. It
    /// validates both the auth AND that the token can actually read. Never fails.
    pub async fn health(&self) -> HealthStatus {
        match self.graphql("{ shop { name } }", None).await {
            Ok(result) => match result.errors.as_ref().and_then(|e| e.first()) {
                // GraphQL error text is upstream-controlled — redact before display.
                Some(first) => HealthStatus { ok: false, detail: redact_secrets(&first.message) },
                None => HealthStatus { ok: true, detail: format!("shopify reachable ({})", self.store) },
            },
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }
}

/// Milliseconds to wait after a 429, from the `Retry-After` header (seconds) or a backoff.
fn retry_after_ms(res: &reqwest::Response, attempt: u32) -> u64 {
    let secs = res
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.trim().parse::<f64>().ok())
        .filter(|s| s.is_finite());
    let ms = match secs {
        Some(s) => s * 1000.0,
        None => 500.0 * 2f64.powi(attempt as i32 - 1),
    };
    ms.clamp(0.0, MAX_BACKOFF_MS) as u64
}

/// Milliseconds to wait after a GraphQL THROTTLED, derived from how long the leaky bucket
/// needs to restore the requested cost (`requestedQueryCost / restoreRate`), else a backoff.
fn throttle_backoff_ms(result: &ShopifyGraphQLResult, attempt: u32) -> u64 {
    let cost = result.extensions.as_ref().and_then(|e| e.cost.as_ref());
    let requested = cost.and_then(|c| c.requested_query_cost).unwrap_or(0.0);
    let rate = cost.and_then(|c| c.throttle_status.as_ref()).map(|t| t.restore_rate).unwrap_or(0.0);
    let ms = if requested > 0.0 && rate > 0.0 { (requested / rate) * 1000.0 } else { 500.0 * 2f64.powi(attempt as i32 - 1) };
    ms.clamp(0.0, MAX_BACKOFF_MS) as u64
}
