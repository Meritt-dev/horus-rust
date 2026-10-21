//! Shared HTTP transport helper for horus-connectors.
//!
//! `fetch_with_retry` wraps reqwest with a per-attempt timeout and a bounded retry
//! loop for transient failures (429, 5xx, network errors). It NEVER errors on HTTP
//! status — non-ok responses are returned as-is so each client keeps its own
//! `!ok` error-message contract.
//!
//! READ-ONLY REQUESTS ONLY: every adopting connector hits read-only endpoints
//! (ES `_search`/`_count`, Grafana GETs, Sentry GETs, Axiom's read-only `_apl`
//! POST). Never point this at a mutating endpoint (e.g. Shopify's token-exchange
//! POST) without an idempotency decision — a retry would repeat the mutation.
//!
//! Timeouts are intentionally NOT retried — only 429/5xx/network errors are —
//! bounding worst-case latency at roughly one `timeout_ms` per call. A
//! flaky-but-slow endpoint that times out fails after a single attempt by design.
//! The TS caller `AbortSignal` has no reqwest equivalent: callers wrap the future
//! in `tokio::time::timeout` / `select!` instead (see DIVERGENCES.md).

use reqwest::{RequestBuilder, Response};
use std::time::Duration;

pub const DEFAULT_HTTP_TIMEOUT_MS: u64 = 8000;
pub const DEFAULT_HTTP_MAX_RETRIES: u32 = 2;
pub const DEFAULT_BACKOFF_BASE_MS: u64 = 300;
pub const DEFAULT_MAX_BACKOFF_MS: u64 = 5000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRequestOptions {
    /// Per-attempt timeout (default 8000ms).
    pub timeout_ms: Option<u64>,
    /// Extra attempts after the first (default 2 -> up to 3 attempts total).
    pub max_retries: Option<u32>,
    /// Exponential backoff base: delay = backoff_base_ms * 2^attempt (default 300ms).
    pub backoff_base_ms: Option<u64>,
    /// Upper clamp on any single backoff delay, incl. Retry-After (default 5000ms).
    pub max_backoff_ms: Option<u64>,
}

impl HttpRequestOptions {
    pub fn with_timeout_ms(timeout_ms: u64) -> Self {
        Self { timeout_ms: Some(timeout_ms), ..Default::default() }
    }
}

/// Delay before retrying a 429/5xx: the `Retry-After` header when it is a plain
/// number of seconds (HTTP-date values fall through), else exponential backoff.
/// Always clamped into [0, cap_ms].
fn retry_delay_ms(res: &Response, attempt: u32, base_ms: u64, cap_ms: u64) -> u64 {
    let header = res.headers().get("retry-after").and_then(|v| v.to_str().ok());
    let secs = header.and_then(|h| h.trim().parse::<f64>().ok()).filter(|s| s.is_finite());
    let ms = match secs {
        Some(s) => (s * 1000.0).max(0.0) as u64,
        None => base_ms.saturating_mul(1u64 << attempt.min(63)),
    };
    ms.min(cap_ms)
}

/// Request with a per-attempt timeout and bounded retries for 429/5xx/network
/// errors. Returns the Response for every completed request — even non-ok ones
/// (after exhausting retries on a retryable status, the LAST Response is
/// returned so the caller formats its own error). Timeouts are returned
/// immediately; the last network error is returned unchanged once retries are
/// exhausted.
///
/// `req` must be cloneable (`RequestBuilder::try_clone`) — i.e. a bytes/string
/// body, which every connector here uses.
pub async fn fetch_with_retry(req: RequestBuilder, opts: &HttpRequestOptions) -> Result<Response, reqwest::Error> {
    let timeout_ms = opts.timeout_ms.unwrap_or(DEFAULT_HTTP_TIMEOUT_MS);
    let max_retries = opts.max_retries.unwrap_or(DEFAULT_HTTP_MAX_RETRIES);
    let backoff_base_ms = opts.backoff_base_ms.unwrap_or(DEFAULT_BACKOFF_BASE_MS);
    let max_backoff_ms = opts.max_backoff_ms.unwrap_or(DEFAULT_MAX_BACKOFF_MS);

    let mut attempt: u32 = 0;
    loop {
        let this = req.try_clone().expect("fetch_with_retry: request body must be cloneable");
        let res = this.timeout(Duration::from_millis(timeout_ms)).send().await;
        let res = match res {
            Ok(r) => r,
            Err(err) => {
                // Timeout — never retried.
                if err.is_timeout() {
                    return Err(err);
                }
                // Network error — retry with exponential backoff while attempts remain.
                if attempt >= max_retries {
                    return Err(err);
                }
                let delay = backoff_base_ms.saturating_mul(1u64 << attempt.min(63)).min(max_backoff_ms);
                tokio::time::sleep(Duration::from_millis(delay)).await;
                attempt += 1;
                continue;
            }
        };

        let status = res.status().as_u16();
        // Every non-retryable status (2xx, 3xx, other 4xx) is the caller's to handle.
        if status != 429 && status < 500 {
            return Ok(res);
        }
        // Retryable status with attempts exhausted — return it for the caller to format.
        if attempt >= max_retries {
            return Ok(res);
        }
        let delay = retry_delay_ms(&res, attempt, backoff_base_ms, max_backoff_ms);
        drop(res);
        tokio::time::sleep(Duration::from_millis(delay)).await;
        attempt += 1;
    }
}
