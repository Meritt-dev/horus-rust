//! Redis multi-DB discovery (HOR-201) — scan logical DBs on a server to suggest how
//! each should be configured. Used by `horus connect redis`. Read-only and bounded:
//! every DB probe is a DBSIZE + a capped SCAN sample, never a full keyspace read.

use super::scan_client::{KeyPrefixSample, RedisScanClient, RedisScanClientOpts};
use anyhow::Result;
use horus_core::RedisRole;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisDbProbe {
    pub db: i64,
    pub reachable: bool,
    /// Error detail when unreachable (e.g. auth failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub key_count: i64,
    /// Top key prefixes sampled from this DB.
    pub prefixes: Vec<KeyPrefixSample>,
    /// BullMQ queue names detected via `{prefix}:*:meta`.
    pub bullmq_queues: Vec<String>,
    /// The BullMQ prefix that matched, when queues were found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bullmq_prefix: Option<String>,
    /// Roles suggested from the probe — a starting point for the user to confirm.
    pub suggested_roles: Vec<RedisRole>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeOpts {
    /// DB indices to scan. Default 0–15.
    pub db_range: Option<Vec<i64>>,
    /// Max keys sampled per DB. Default 500.
    pub sample_limit: Option<usize>,
    /// BullMQ prefix to look for. Default "bull".
    pub bullmq_prefix: Option<String>,
}

static RATELIMIT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"rate.?limit|throttle").unwrap());

/// Infer roles for a non-queue DB from its sampled key prefixes.
fn infer_state_roles(prefixes: &[KeyPrefixSample]) -> Vec<RedisRole> {
    let mut roles = vec![RedisRole::Cache, RedisRole::State];
    let mut add = |r: RedisRole| {
        if !roles.contains(&r) {
            roles.push(r);
        }
    };
    for KeyPrefixSample { prefix, .. } in prefixes {
        let p = prefix.to_lowercase();
        if p.contains("lock") {
            add(RedisRole::Locks);
        }
        if RATELIMIT_RE.is_match(&p) {
            add(RedisRole::RateLimit);
        }
        if p.contains("session") || p.contains("sess") {
            add(RedisRole::Session);
        }
        if p.contains("dedup") {
            add(RedisRole::Dedupe);
        }
    }
    roles
}

/// Probe each DB in range and suggest a role-tagged configuration.
pub async fn probe_redis_databases(base_url: &str, opts: ProbeOpts) -> Result<Vec<RedisDbProbe>> {
    let db_range = opts.db_range.unwrap_or_else(|| (0..16).collect());
    let sample_limit = opts.sample_limit.unwrap_or(500);
    let bullmq_prefix = opts.bullmq_prefix.unwrap_or_else(|| "bull".to_string());

    let mut probes: Vec<RedisDbProbe> = Vec::new();
    for db in db_range {
        let client = RedisScanClient::new(RedisScanClientOpts { url: base_url.to_string(), db: Some(db) })?;
        let result = probe_one(&client, db, sample_limit, &bullmq_prefix).await;
        client.close().await;
        let probe = result?;
        let reachable = probe.reachable;
        probes.push(probe);
        // Auth/connection failures are server-wide — stop scanning further DBs.
        if !reachable {
            break;
        }
    }
    Ok(probes)
}

async fn probe_one(client: &RedisScanClient, db: i64, sample_limit: usize, bullmq_prefix: &str) -> Result<RedisDbProbe> {
    let empty = RedisDbProbe {
        db,
        reachable: true,
        detail: None,
        key_count: 0,
        prefixes: vec![],
        bullmq_queues: vec![],
        bullmq_prefix: None,
        suggested_roles: vec![],
    };
    let health = client.health().await;
    if !health.ok {
        return Ok(RedisDbProbe { reachable: false, detail: Some(health.detail), ..empty });
    }
    let key_count = client.db_size().await?;
    if key_count == 0 {
        return Ok(empty);
    }
    let bullmq_queues = client.detect_bullmq_queues(Some(bullmq_prefix), None).await?;
    if !bullmq_queues.is_empty() {
        return Ok(RedisDbProbe {
            key_count,
            bullmq_queues,
            bullmq_prefix: Some(bullmq_prefix.to_string()),
            suggested_roles: vec![RedisRole::Bullmq, RedisRole::Queues],
            ..empty
        });
    }
    let prefixes = client.sample_prefixes(Some(sample_limit), None).await?;
    let suggested_roles = infer_state_roles(&prefixes);
    Ok(RedisDbProbe { key_count, prefixes, suggested_roles, ..empty })
}
