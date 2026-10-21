//! Redis server + per-DB status (HOR-201) — powers the multi-DB view in `horus status`.
//! Probes each configured logical DB read-only: a ping plus either a queue count
//! (bullmq DBs) or a key count (cache/state DBs).

use super::scan_client::{RedisScanClient, RedisScanClientOpts};
use anyhow::Result;
use horus_core::{redis_url_for_db, RedisRole, ResolvedEnvironment, REDIS_QUEUE_ROLES};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisDbStatus {
    pub db: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub roles: Vec<RedisRole>,
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Key count for state DBs (DBSIZE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_count: Option<i64>,
    /// Queue count for bullmq DBs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bullmq_prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedisServerStatus {
    /// True when at least one DB responded to PING.
    pub reachable: bool,
    /// True when a DB failed PING with an auth error (WRONGPASS/NOAUTH).
    pub auth_failed: bool,
    pub databases: Vec<RedisDbStatus>,
}

static AUTH_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)WRONGPASS|NOAUTH|invalid password").unwrap());

/// Probe the Redis server and each configured logical DB. Returns None when no Redis
/// connector (URL) is configured.
pub async fn redis_server_status(renv: &ResolvedEnvironment) -> Result<Option<RedisServerStatus>> {
    let Some(r) = renv.connectors.redis.as_ref() else { return Ok(None) };
    let Some(url) = r.url.as_deref().filter(|u| !u.is_empty()) else { return Ok(None) };

    let mut reachable = false;
    let mut auth_failed = false;
    let mut databases: Vec<RedisDbStatus> = Vec::new();

    for d in &r.databases {
        let client = RedisScanClient::new(RedisScanClientOpts { url: redis_url_for_db(url, d.db), db: Some(d.db) })?;
        let base = RedisDbStatus {
            db: d.db,
            name: d.name.clone(),
            roles: d.roles.clone(),
            reachable: false,
            detail: None,
            key_count: None,
            queue_count: None,
            bullmq_prefix: None,
        };
        let health = client.health().await;
        let is_queue = d.roles.iter().any(|role| REDIS_QUEUE_ROLES.contains(role));
        if !health.ok {
            if AUTH_RE.is_match(&health.detail) {
                auth_failed = true;
            }
            databases.push(RedisDbStatus { detail: Some(health.detail), ..base });
            client.close().await;
            continue;
        }
        reachable = true;
        let result = if is_queue {
            client.detect_bullmq_queues(Some(&d.bullmq_prefix), None).await.map(|queues| RedisDbStatus {
                reachable: true,
                queue_count: Some(queues.len() as i64),
                bullmq_prefix: Some(d.bullmq_prefix.clone()),
                ..base
            })
        } else {
            client.db_size().await.map(|key_count| RedisDbStatus { reachable: true, key_count: Some(key_count), ..base })
        };
        client.close().await;
        databases.push(result?);
    }

    Ok(Some(RedisServerStatus { reachable, auth_failed, databases }))
}
