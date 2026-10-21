//! Redis runtime-state evidence provider (HOR-201).
//!
//! Reads cache/state/locks/rate-limit logical DBs read-only and produces summary
//! signals (key counts, top prefixes, lock/rate-limit presence) for the investigation
//! engine to fold as `redis-key` evidence. Counts/prefixes only — never key values.

use super::scan_client::{KeyPrefixSample, RedisScanClient, RedisScanClientOpts};
use crate::jsutil::now_iso;
use anyhow::{bail, Result};
use async_trait::async_trait;
use horus_core::RedisRole;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisStateScan {
    pub sample_limit: i64,
    pub patterns: Vec<String>,
}

/// One configured state DB to sample (URL already points at the base server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisStateDb {
    pub db: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub roles: Vec<RedisRole>,
    /// Base server URL — the DB index is selected via the `db` field.
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<RedisStateScan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisDbSummary {
    pub db: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub roles: Vec<RedisRole>,
    pub key_count: i64,
    pub prefixes: Vec<KeyPrefixSample>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisStateSignal {
    pub db: i64,
    pub title: String,
    pub payload: Value,
    /// Base relevance 0–1; the engine may boost it on hint-term overlap.
    pub relevance: f64,
    /// Lowercased text the engine can match hint terms against.
    pub match_text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisStateAnalysis {
    pub collected_at: String,
    pub databases: Vec<RedisDbSummary>,
    pub signals: Vec<RedisStateSignal>,
}

#[async_trait]
pub trait RedisStateProvider: Send + Sync {
    async fn analyze_redis_state(&self) -> Result<RedisStateAnalysis>;
    async fn close(&self);
}

static LOCK_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)lock").unwrap());
static RATELIMIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)rate.?limit|throttle").unwrap());

fn roles_str(roles: &[RedisRole]) -> Vec<&'static str> {
    roles.iter().map(|r| r.as_str()).collect()
}

pub struct RedisStateRuntimeProvider {
    dbs: Vec<RedisStateDb>,
}

impl RedisStateRuntimeProvider {
    pub fn new(dbs: Vec<RedisStateDb>) -> Self {
        Self { dbs }
    }

    async fn analyze_db(d: &RedisStateDb, client: &RedisScanClient, databases: &mut Vec<RedisDbSummary>, signals: &mut Vec<RedisStateSignal>) -> Result<()> {
        let key_count = client.db_size().await?;
        let (limit, patterns) = match &d.scan {
            Some(s) => (Some(s.sample_limit.max(0) as usize), Some(s.patterns.as_slice())),
            None => (Some(500), None),
        };
        let prefixes = client.sample_prefixes(limit, patterns).await?;
        databases.push(RedisDbSummary { db: d.db, name: d.name.clone(), roles: d.roles.clone(), key_count, prefixes: prefixes.clone() });
        if key_count == 0 {
            return Ok(());
        }

        let role_label = if d.roles.is_empty() { "state".to_string() } else { roles_str(&d.roles).join("/") };
        let top_prefixes: Vec<&KeyPrefixSample> = prefixes.iter().take(10).collect();
        let top_text = top_prefixes.iter().map(|p| p.prefix.as_str()).collect::<Vec<_>>().join(" ");

        // Summary signal — structural context for this DB.
        signals.push(RedisStateSignal {
            db: d.db,
            title: format!(
                "Redis DB {} ({role_label}): {key_count} key(s), top prefixes {}",
                d.db,
                top_prefixes.iter().take(4).map(|p| format!("{}:*", p.prefix)).collect::<Vec<_>>().join(", ")
            ),
            payload: json!({ "db": d.db, "roles": d.roles, "keyCount": key_count, "topPrefixes": top_prefixes }),
            relevance: 0.4,
            match_text: format!("{role_label} {top_text}").to_lowercase(),
        });

        // Role-specific signals — locks and rate-limits are common incident causes.
        let lock_prefixes: Vec<&KeyPrefixSample> = prefixes.iter().filter(|p| LOCK_RE.is_match(&p.prefix)).collect();
        if d.roles.contains(&RedisRole::Locks) || !lock_prefixes.is_empty() {
            let lock_keys: i64 = lock_prefixes.iter().map(|p| p.count).sum();
            if lock_keys > 0 {
                signals.push(RedisStateSignal {
                    db: d.db,
                    title: format!(
                        "Redis DB {}: {lock_keys} lock key(s) present ({})",
                        d.db,
                        lock_prefixes.iter().map(|p| format!("{}:*", p.prefix)).collect::<Vec<_>>().join(", ")
                    ),
                    payload: json!({ "db": d.db, "lockKeys": lock_keys, "lockPrefixes": lock_prefixes }),
                    relevance: 0.6,
                    match_text: format!("lock locks {}", lock_prefixes.iter().map(|p| p.prefix.as_str()).collect::<Vec<_>>().join(" "))
                        .to_lowercase(),
                });
            }
        }
        let rl_prefixes: Vec<&KeyPrefixSample> = prefixes.iter().filter(|p| RATELIMIT_RE.is_match(&p.prefix)).collect();
        if d.roles.contains(&RedisRole::RateLimit) || !rl_prefixes.is_empty() {
            let rl_keys: i64 = rl_prefixes.iter().map(|p| p.count).sum();
            if rl_keys > 0 {
                signals.push(RedisStateSignal {
                    db: d.db,
                    title: format!("Redis DB {}: {rl_keys} rate-limit key(s) present", d.db),
                    payload: json!({ "db": d.db, "rateLimitKeys": rl_keys, "prefixes": rl_prefixes }),
                    relevance: 0.6,
                    match_text: format!(
                        "rate limit throttle {}",
                        rl_prefixes.iter().map(|p| p.prefix.as_str()).collect::<Vec<_>>().join(" ")
                    )
                    .to_lowercase(),
                });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl RedisStateProvider for RedisStateRuntimeProvider {
    async fn analyze_redis_state(&self) -> Result<RedisStateAnalysis> {
        let collected_at = now_iso();
        let mut databases: Vec<RedisDbSummary> = Vec::new();
        let mut signals: Vec<RedisStateSignal> = Vec::new();
        let mut failures: Vec<String> = Vec::new();

        for d in &self.dbs {
            let client = RedisScanClient::new(RedisScanClientOpts { url: d.url.clone(), db: Some(d.db) })?;
            let health = client.health().await;
            if !health.ok {
                // Skip this DB but remember why — when EVERY configured DB fails we
                // throw below so the engine records a state gap instead of reading a
                // total Redis outage as a clean empty analysis.
                failures.push(format!("db {}: {}", d.db, health.detail));
                client.close().await;
                continue;
            }
            let result = Self::analyze_db(d, &client, &mut databases, &mut signals).await;
            client.close().await;
            result?;
        }

        if !self.dbs.is_empty() && databases.is_empty() && !failures.is_empty() {
            // health.detail is already redacted by the scan client.
            bail!("redis state collection failed: {}", failures.join("; "));
        }
        Ok(RedisStateAnalysis { collected_at, databases, signals })
    }

    async fn close(&self) {}
}
