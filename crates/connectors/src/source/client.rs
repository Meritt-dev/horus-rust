//! `SourceHttpClient` — REST transport to the running `horus-source host`. Request and
//! response shapes must match the TS client byte-for-byte because the Rust CLI runs
//! against the same live host (`http://127.0.0.1:8420`).

use std::time::Duration;

use indexmap::IndexMap;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use super::types::*;

/// Encode a graph node id for use as a URL PATH segment (HOR-445). Mirrors JS `encodeURI`
/// (keeps `/` and `:` literal — the backend's node ids are path-shaped, e.g.
/// `method:source/foo.ts:Bar.baz`) but additionally escapes `#` and `?`, the two structural
/// delimiters `encodeURI` leaves alone: a `#private` method id would otherwise truncate the
/// URL at the fragment and hit the wrong route (404).
pub fn encode_node_path(node_id: &str) -> String {
    // encodeURI reserved + unreserved set: A-Z a-z 0-9 ; , / ? : @ & = + $ - _ . ! ~ * ' ( ) #
    const KEEP: &[u8] = b";,/:@&=+$-_.!~*'()";
    let mut out = String::with_capacity(node_id.len());
    for b in node_id.bytes() {
        if b.is_ascii_alphanumeric() || KEEP.contains(&b) {
            out.push(b as char);
        } else {
            // `#` and `?` fall through here on purpose (%23 / %3F).
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// JS `encodeURIComponent` — everything except `A-Za-z0-9 - _ . ! ~ * ' ( )` is percent-encoded.
pub(crate) fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// `URLSearchParams` serialization (application/x-www-form-urlencoded: space → `+`,
/// `*-._` kept, everything else percent-encoded).
pub(crate) fn form_encode(pairs: &[(&str, &str)]) -> String {
    fn enc(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b' ' => out.push('+'),
                b if b.is_ascii_alphanumeric() || b"*-._".contains(&b) => out.push(b as char),
                b => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Non-2xx reply from the source host. Carries the status so callers can branch on 4xx
/// (graceful degradation, HOR-353) vs 5xx.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SourceHttpError {
    pub message: String,
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct SourceClientOptions {
    pub base_url: String,
    pub timeout_ms: Option<u64>,
    pub max_retries: Option<u32>,
}

impl SourceClientOptions {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), timeout_ms: None, max_retries: None }
    }
}

#[derive(Debug, Clone)]
pub struct SourceHttpClient {
    base_url: String,
    timeout: Duration,
    max_retries: u32,
    http: reqwest::Client,
}

/// Options for `impact` / `flows`.
#[derive(Debug, Clone, Copy, Default)]
pub struct IncludeTests {
    pub include_tests: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TraceOptions {
    pub max_depth: Option<i64>,
    pub relations: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct InsightsOptions {
    pub hub_limit: Option<i64>,
    pub bridge_limit: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct CodeRelationships {
    pub edges: Vec<SourceCodeRelationship>,
    pub truncated: bool,
}

impl SourceHttpClient {
    pub fn new(opts: SourceClientOptions) -> Self {
        Self {
            base_url: opts.base_url.trim_end_matches('/').to_string(),
            timeout: Duration::from_millis(opts.timeout_ms.unwrap_or(15_000)),
            max_retries: opts.max_retries.unwrap_or(2),
            http: reqwest::Client::new(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> anyhow::Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let body_str = match body {
            Some(b) => Some(serde_json::to_string(b)?),
            None => None,
        };

        let mut attempt = 0u32;
        loop {
            let mut req = self.http.request(method.clone(), &url).timeout(self.timeout);
            if let Some(ref b) = body_str {
                req = req.header("content-type", "application/json").body(b.clone());
            }
            match req.send().await {
                Ok(res) => {
                    let status = res.status().as_u16();
                    if status >= 500 {
                        let text = res.text().await.unwrap_or_default();
                        if attempt < self.max_retries {
                            tokio::time::sleep(Duration::from_millis(150 * 2u64.pow(attempt))).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(SourceHttpError {
                            message: format!("Source request failed: {} {} -> HTTP {}", method, path, status),
                            status,
                            body: text,
                        }
                        .into());
                    }
                    if !(200..300).contains(&status) {
                        // 4xx — never retry
                        let text = res.text().await.unwrap_or_default();
                        return Err(SourceHttpError {
                            message: format!("Source request failed: {} {} -> HTTP {}", method, path, status),
                            status,
                            body: text,
                        }
                        .into());
                    }
                    return res.json::<T>().await.map_err(fetch_error);
                }
                Err(err) => {
                    // Timeout (the TS AbortError) is never retried; network errors are.
                    if err.is_timeout() || attempt >= self.max_retries {
                        return Err(fetch_error(err));
                    }
                    tokio::time::sleep(Duration::from_millis(150 * 2u64.pow(attempt))).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        self.request::<T>(reqwest::Method::GET, path, None::<&Value>).await
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: &impl Serialize) -> anyhow::Result<T> {
        self.request::<T>(reqwest::Method::POST, path, Some(body)).await
    }

    /// `info.version` from `/openapi.json`, or `None` on any failure.
    pub async fn version(&self) -> Option<String> {
        let res = self
            .http
            .get(format!("{}/openapi.json", self.base_url))
            .timeout(self.timeout)
            .send()
            .await
            .ok()?;
        if !res.status().is_success() {
            return None;
        }
        let data: Value = res.json().await.ok()?;
        data.get("info")?.get("version")?.as_str().map(str::to_string)
    }

    pub async fn health(&self) -> SourceHealth {
        match self
            .http
            .get(format!("{}/api/health", self.base_url))
            .timeout(self.timeout)
            .send()
            .await
        {
            Ok(res) => SourceHealth { ok: res.status().is_success(), status: res.status().as_u16() },
            Err(_) => SourceHealth { ok: false, status: 0 },
        }
    }

    pub async fn host_info(&self) -> anyhow::Result<SourceHostInfo> {
        self.get("/api/host").await
    }

    pub async fn overview(&self) -> anyhow::Result<SourceOverview> {
        self.get("/api/overview").await
    }

    /// Reuse the canonical read-only SQL console; no new source-host endpoint.
    pub async fn code_relationships(&self, limit: Option<i64>) -> anyhow::Result<CodeRelationships> {
        let cap = limit.unwrap_or(20_000).clamp(1, 20_000) as usize;
        let result = self
            .cypher(&format!(
                "SELECT source, target, rel_type, confidence FROM edges \
                 WHERE rel_type IN ('calls', 'extends', 'implements', 'uses_type') \
                 ORDER BY source, target, rel_type LIMIT {}",
                cap + 1
            ))
            .await?;
        let mut edges = Vec::new();
        for row in result.rows.iter().take(cap) {
            let (Some(source), Some(target)) = (
                row.first().and_then(Value::as_str),
                row.get(1).and_then(Value::as_str),
            ) else {
                continue;
            };
            let rel = row.get(2).map(value_to_js_string).unwrap_or_default();
            if !["calls", "extends", "implements", "uses_type"].contains(&rel.as_str()) {
                continue;
            }
            let confidence = row
                .get(3)
                .and_then(Value::as_f64)
                .filter(|c| c.is_finite() && (0.0..=1.0).contains(c));
            edges.push(SourceCodeRelationship {
                source: source.to_string(),
                target: target.to_string(),
                rel,
                confidence,
            });
        }
        Ok(CodeRelationships { edges, truncated: result.rows.len() > cap })
    }

    pub async fn cypher(&self, query: &str) -> anyhow::Result<SourceCypherResult> {
        self.post("/api/cypher", &json!({ "query": query })).await
    }

    pub async fn search(&self, query: &str, limit: Option<i64>) -> anyhow::Result<Vec<SourceSearchResult>> {
        #[derive(serde::Deserialize)]
        struct Res {
            results: Vec<SourceSearchResult>,
        }
        let res: Res = self
            .post("/api/search", &json!({ "query": query, "limit": limit.unwrap_or(20) }))
            .await?;
        Ok(res.results)
    }

    /// Blast radius. Product-only by default; `include_tests` restores test/docs/example callers.
    pub async fn impact(
        &self,
        node_id: &str,
        depth: Option<i64>,
        opts: IncludeTests,
    ) -> anyhow::Result<SourceImpactResult> {
        let include_tests = if opts.include_tests { "&include_tests=true" } else { "" };
        self.get(&format!(
            "/api/impact/{}?depth={}{}",
            encode_node_path(node_id),
            depth.unwrap_or(3),
            include_tests
        ))
        .await
    }

    pub async fn diff(&self, base: &str, compare: &str) -> anyhow::Result<SourceDiffResult> {
        self.post("/api/diff", &json!({ "base": base, "compare": compare })).await
    }

    /// Shortest relationship path between two symbols across all semantic edges, in both
    /// directions. `relations` optionally narrows the edge kinds (e.g. `["calls"]`).
    pub async fn trace(
        &self,
        from_symbol: &str,
        to_symbol: &str,
        opts: &TraceOptions,
    ) -> anyhow::Result<SourceTraceResult> {
        let mut params: Vec<(&str, String)> =
            vec![("from", from_symbol.to_string()), ("to", to_symbol.to_string())];
        if let Some(d) = opts.max_depth {
            params.push(("max_depth", d.to_string()));
        }
        if let Some(rels) = opts.relations.as_ref().filter(|r| !r.is_empty()) {
            params.push(("relations", rels.join(",")));
        }
        let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.get(&format!("/api/trace?{}", form_encode(&pairs))).await
    }

    /// Graph-shape insights: hubs, surprising connections, suggested follow-up questions.
    pub async fn insights(&self, opts: InsightsOptions) -> anyhow::Result<SourceInsightsResult> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(h) = opts.hub_limit {
            params.push(("hub_limit", h.to_string()));
        }
        if let Some(b) = opts.bridge_limit {
            params.push(("bridge_limit", b.to_string()));
        }
        let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let qs = form_encode(&pairs);
        let path = if qs.is_empty() { "/api/insights".to_string() } else { format!("/api/insights?{qs}") };
        self.get(&path).await
    }

    pub async fn node_count(&self) -> anyhow::Result<i64> {
        Ok(self.overview().await?.total_nodes)
    }

    // -------------------------------------------------------------------------
    // Typed read-path endpoints (HOR-392): the host owns the queries and returns shaped
    // JSON, so the client never emits or escapes Cypher on the read path.
    // -------------------------------------------------------------------------

    /// Nodes whose full content contains ANY of `tokens` — full (untruncated) content.
    pub async fn content_search(&self, tokens: &[String], limit: Option<i64>) -> anyhow::Result<Vec<SourceContentHit>> {
        #[derive(serde::Deserialize)]
        struct Res {
            #[serde(default)]
            results: Vec<SourceContentHit>,
        }
        let res: Res = self
            .post("/api/content-search", &json!({ "tokens": tokens, "limit": limit.unwrap_or(500) }))
            .await?;
        Ok(res.results)
    }

    /// Exact-name symbol lookup (file label excluded), with line ranges.
    pub async fn exact_symbols(&self, name: &str, limit: Option<i64>) -> anyhow::Result<Vec<SourceExactSymbol>> {
        #[derive(serde::Deserialize)]
        struct Res {
            #[serde(default)]
            results: Vec<SourceExactSymbol>,
        }
        let res: Res = self
            .get(&format!(
                "/api/symbols/exact?name={}&limit={}",
                encode_uri_component(name),
                limit.unwrap_or(10)
            ))
            .await?;
        Ok(res.results)
    }

    /// Symbol nodes for the given comma-joinable lowercase labels (source-graph extraction).
    pub async fn symbols_by_label(&self, labels: &[String], limit: Option<i64>) -> anyhow::Result<Vec<SourceLabelSymbol>> {
        #[derive(serde::Deserialize)]
        struct Res {
            #[serde(default)]
            symbols: Vec<SourceLabelSymbol>,
        }
        let res: Res = self
            .get(&format!(
                "/api/symbols?labels={}&limit={}",
                encode_uri_component(&labels.join(",")),
                limit.unwrap_or(1000)
            ))
            .await?;
        Ok(res.symbols)
    }

    /// Batch-resolve node ids to their line ranges (CLI line hydration).
    pub async fn nodes_lines(&self, ids: &[String]) -> anyhow::Result<IndexMap<String, SourceNodeLine>> {
        #[derive(serde::Deserialize)]
        struct Res {
            #[serde(default)]
            lines: IndexMap<String, SourceNodeLine>,
        }
        let res: Res = self.post("/api/nodes/lines", &json!({ "ids": ids })).await?;
        Ok(res.lines)
    }

    /// Process flows a symbol participates in, with each flow's named ordered steps.
    pub async fn flows(&self, node_id: &str, opts: IncludeTests) -> anyhow::Result<SourceFlowsResult> {
        let include_tests = if opts.include_tests { "?include_tests=true" } else { "" };
        self.get(&format!("/api/flows/{}{}", encode_node_path(node_id), include_tests)).await
    }

    /// Method symbols of `class_name` defined in `file`, ordered by start line.
    pub async fn class_methods(&self, file: &str, class_name: &str) -> anyhow::Result<Vec<SourceNode>> {
        #[derive(serde::Deserialize)]
        struct Res {
            #[serde(default)]
            methods: Vec<SourceNode>,
        }
        let res: Res = self
            .get(&format!(
                "/api/class-methods?file={}&class={}",
                encode_uri_component(file),
                encode_uri_component(class_name)
            ))
            .await?;
        Ok(res.methods)
    }

    /// Extended node detail — node + content + callers/callees/typeRefs + imports + coupling + communities.
    pub async fn node(&self, node_id: &str) -> anyhow::Result<SourceNodeDetail> {
        self.get(&format!("/api/node/{}", encode_node_path(node_id))).await
    }

    pub async fn communities(&self) -> anyhow::Result<Vec<SourceCommunity>> {
        Ok(self.get::<SourceCommunitiesResult>("/api/communities").await?.communities)
    }

    pub async fn processes(&self) -> anyhow::Result<Vec<SourceProcess>> {
        Ok(self.get::<SourceProcessesResult>("/api/processes").await?.processes)
    }

    pub async fn dead_code(&self) -> anyhow::Result<SourceDeadCodeResult> {
        self.get("/api/dead-code").await
    }

    pub async fn coupling(&self) -> anyhow::Result<Vec<SourceCouplingPair>> {
        Ok(self.get::<SourceCouplingResult>("/api/coupling").await?.pairs)
    }

    /// Per-token distinct FILE paths whose content contains the token. `limit` is a PER-TOKEN
    /// budget so a common token can't crowd out rare ones.
    pub async fn files_containing(&self, tokens: &[String], limit: Option<i64>) -> anyhow::Result<IndexMap<String, Vec<String>>> {
        let res: SourceFilesContainingResult = self
            .post(
                "/api/content-search",
                &json!({ "tokens": tokens, "limit": limit.unwrap_or(500), "filesOnly": true }),
            )
            .await?;
        Ok(res.matches)
    }

    // -------------------------------------------------------------------------
    // Memory vector bridge (M2). Reuse `request` (retry/timeout/4xx) so a host-down /
    // 404 / 503 surfaces as an error the caller treats as best-effort.
    // -------------------------------------------------------------------------

    /// Index (or re-index) a single claim. Host returns 202/{ok} when accepted.
    pub async fn memory_upsert(&self, body: &SourceMemoryUpsertRequest) -> anyhow::Result<()> {
        let _: Value = self.post("/api/memory/upsert", body).await?;
        Ok(())
    }

    /// Vector-search claims in a repo. Returns the (possibly empty) hit list.
    pub async fn memory_search(&self, body: &SourceMemorySearchRequest) -> anyhow::Result<Vec<SourceMemorySearchHit>> {
        Ok(self.post::<SourceMemorySearchResult>("/api/memory/search", body).await?.results)
    }

    /// Drop a claim's vectors. Host returns {ok} when removed.
    pub async fn memory_remove(&self, memory_id: &str) -> anyhow::Result<()> {
        let _: Value = self.post("/api/memory/remove", &json!({ "memoryId": memory_id })).await?;
        Ok(())
    }
}

/// JS `String(v)` for the scalar cases the SQL console returns.
fn value_to_js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Node `fetch` error text, which callers print verbatim (`changes`, `--json` `detail`): an
/// aborted (timed-out) request reads `This operation was aborted`, a transport failure
/// `fetch failed`. Body decode errors keep serde's text (TS: `res.json()` SyntaxError).
fn fetch_error(err: reqwest::Error) -> anyhow::Error {
    if err.is_timeout() {
        anyhow::anyhow!("This operation was aborted")
    } else if err.is_decode() {
        err.into()
    } else {
        anyhow::anyhow!("fetch failed")
    }
}
