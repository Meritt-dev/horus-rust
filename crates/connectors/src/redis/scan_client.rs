//! Generic Redis scan client (HOR-201).
//!
//! Redis in Horus is a general runtime-evidence connector, not only a BullMQ store:
//! a single server commonly holds queues in one logical DB and cache/locks/rate-limit/
//! session keys in others. This client inspects a single logical DB read-only — it never
//! mutates — and powers:
//!   - `horus connect redis` DB discovery (which DBs hold queues vs cache/state)
//!   - `horus status` per-DB display (key counts, queue counts)
//!   - investigation collectors sampling cache/state/locks/rate-limit DBs
//!
//! Queue *inspection* (job counts, failed breakdown) stays in BullMQRedisClient; this
//! client only counts/sample/detects.

use anyhow::Result;
use horus_core::{redact_error_message, HealthStatus};
use indexmap::IndexMap;
use redis::aio::MultiplexedConnection;
use redis::{AsyncConnectionConfig, Client, IntoConnectionInfo};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisScanClientOpts {
    /// Base server URL. The DB is selected via the `db` option, not the URL path.
    pub url: String,
    /// Logical DB index to operate on (default 0).
    pub db: Option<i64>,
}

/// A sampled key prefix and how many sampled keys shared it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPrefixSample {
    pub prefix: String,
    pub count: i64,
}

const SAMPLE_DEFAULT: usize = 500;
const SCAN_BATCH: usize = 200;
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// ioredis has no per-command timeout; we bound responses so a dropped tunnel can
/// never hang an investigation (the TS client bounds this via 3 quick reconnects).
pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// ioredis (`maxRetriesPerRequest: 1`) rejects a queued command with this once the first
/// reconnect fails — the text TS prints for an unreachable/refused/timed-out server.
pub(crate) const IOREDIS_MAX_RETRIES_MSG: &str =
    "Reached the max retries per request limit (which is 1). Refer to \"maxRetriesPerRequest\" option for details.";

/// The message ioredis would surface for the same failure: connection-level failures map to
/// the max-retries rejection; server replies keep Redis's raw `CODE detail` text (what an
/// ioredis `ReplyError` carries — `WRONGPASS …`, `NOAUTH …`, which `redis/status.rs` matches).
pub(crate) fn ioredis_message(e: &redis::RedisError) -> String {
    if e.is_io_error() || e.is_timeout() || e.is_connection_refusal() || e.is_connection_dropped() {
        return IOREDIS_MAX_RETRIES_MSG.to_string();
    }
    // redis-rs sends AUTH itself during connection setup and drops the server's reply. Redis 6+
    // answers a bad password with exactly this line, which ioredis surfaces verbatim.
    if e.kind() == redis::ErrorKind::AuthenticationFailed {
        return "WRONGPASS invalid username-password pair or user is disabled.".to_string();
    }
    match (e.code(), e.detail()) {
        (Some(code), Some(detail)) => format!("{code} {detail}"),
        (Some(code), None) => code.to_string(),
        _ => e.to_string(),
    }
}

pub(crate) fn ioredis_err(e: redis::RedisError) -> anyhow::Error {
    anyhow::anyhow!(ioredis_message(&e))
}

/// Lazily-connected multiplexed connection shared by the Redis-backed clients
/// (`lazyConnect: true` in ioredis). Errors never panic; they surface per call.
pub(crate) struct LazyRedis {
    client: Client,
    conn: Mutex<Option<MultiplexedConnection>>,
}

impl LazyRedis {
    /// `db = None` keeps the DB index from the URL path (BullMQ client); `Some(n)`
    /// overrides it (scan client — the URL is the base server).
    pub(crate) fn open(url: &str, db: Option<i64>) -> redis::RedisResult<Self> {
        // `rediss://` builds its rustls config with `ClientConfig::builder()`, which panics when
        // more than one crypto provider is compiled in (ring + tiberius's aws-lc-rs). Pin ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut info = url.into_connection_info()?;
        if let Some(db) = db {
            let settings = info.redis_settings().clone().set_db(db);
            info = info.set_redis_settings(settings);
        }
        Ok(Self { client: Client::open(info)?, conn: Mutex::new(None) })
    }

    pub(crate) async fn conn(&self) -> anyhow::Result<MultiplexedConnection> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let cfg = AsyncConnectionConfig::new()
            .set_connection_timeout(Some(CONNECT_TIMEOUT))
            .set_response_timeout(Some(RESPONSE_TIMEOUT));
        let c = self.client.get_multiplexed_async_connection_with_config(&cfg).await.map_err(ioredis_err)?;
        *guard = Some(c.clone());
        Ok(c)
    }

    pub(crate) async fn ping(&self) -> anyhow::Result<()> {
        let mut c = self.conn().await?;
        redis::cmd("PING").query_async::<()>(&mut c).await.map_err(ioredis_err)
    }

    /// One SCAN step; keys are returned lossily decoded (Redis keys are bytes).
    pub(crate) async fn scan(&self, cursor: u64, pattern: &str, count: usize) -> anyhow::Result<(u64, Vec<String>)> {
        let mut c = self.conn().await?;
        let (next, batch): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(count)
            .query_async(&mut c)
            .await
            .map_err(ioredis_err)?;
        Ok((next, batch.into_iter().map(|k| String::from_utf8_lossy(&k).into_owned()).collect()))
    }

    pub(crate) async fn close(&self) {
        // Dropping the multiplexed connection closes the socket (ioredis `disconnect()`).
        self.conn.lock().await.take();
    }
}

/// `key.slice(prefixLen, key.length - suffixLen)` for `{prefix}:{name}:meta`.
pub(crate) fn queue_name_from_meta_key(key: &str, prefix: &str) -> String {
    let start = prefix.len() + 1;
    let end = key.len().saturating_sub(":meta".len());
    key.get(start..end).unwrap_or("").to_string()
}

pub struct RedisScanClient {
    redis: LazyRedis,
    pub db: i64,
}

impl RedisScanClient {
    pub fn new(opts: RedisScanClientOpts) -> Result<Self> {
        let db = opts.db.unwrap_or(0);
        let redis = LazyRedis::open(&opts.url, Some(db)).map_err(|e| anyhow::anyhow!(redact_error_message(&e)))?;
        Ok(Self { redis, db })
    }

    /// Ping the server (also exercises AUTH).
    pub async fn health(&self) -> HealthStatus {
        match self.redis.ping().await {
            Ok(()) => HealthStatus { ok: true, detail: format!("Redis reachable (db {})", self.db) },
            // Redaction never alters WRONGPASS/NOAUTH/"invalid password" tokens, so
            // redis/status.rs auth-failure classification keeps working on this detail.
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }

    /// Total number of keys in this DB (DBSIZE).
    pub async fn db_size(&self) -> Result<i64> {
        let mut c = self.redis.conn().await?;
        redis::cmd("DBSIZE").query_async::<i64>(&mut c).await.map_err(ioredis_err)
    }

    /// Sample up to `limit` keys and group them by their leading segment (before the
    /// first ':'), returning the most common prefixes. Used to characterise a cache/
    /// state DB without reading values. Optional `patterns` restrict the scan.
    pub async fn sample_prefixes(&self, limit: Option<usize>, patterns: Option<&[String]>) -> Result<Vec<KeyPrefixSample>> {
        let limit = limit.unwrap_or(SAMPLE_DEFAULT);
        let mut counts: IndexMap<String, i64> = IndexMap::new();
        let mut sampled = 0usize;
        let star = vec!["*".to_string()];
        let scan_patterns = match patterns {
            Some(p) if !p.is_empty() => p,
            _ => &star,
        };
        'outer: for pattern in scan_patterns {
            let mut cursor = 0u64;
            loop {
                let (next, batch) = self.redis.scan(cursor, pattern, SCAN_BATCH).await?;
                cursor = next;
                for key in batch {
                    let prefix = match key.find(':') {
                        Some(i) => key[..i].to_string(),
                        None => key.clone(),
                    };
                    *counts.entry(prefix).or_insert(0) += 1;
                    sampled += 1;
                    if sampled >= limit {
                        break;
                    }
                }
                if cursor == 0 || sampled >= limit {
                    break;
                }
            }
            if sampled >= limit {
                break 'outer;
            }
        }
        let mut out: Vec<KeyPrefixSample> = counts.into_iter().map(|(prefix, count)| KeyPrefixSample { prefix, count }).collect();
        out.sort_by(|a, b| b.count.cmp(&a.count));
        Ok(out)
    }

    /// Detect BullMQ queue names in this DB by scanning `{prefix}:*:meta`. `:meta` exists
    /// for every instantiated queue (even idle ones), so this finds all queues, not just
    /// those with pending jobs. Returns at most `limit` names.
    pub async fn detect_bullmq_queues(&self, prefix: Option<&str>, limit: Option<usize>) -> Result<Vec<String>> {
        let prefix = prefix.unwrap_or("bull");
        let limit = limit.unwrap_or(200);
        let pattern = format!("{prefix}:*:meta");
        let mut names: Vec<String> = Vec::new();
        let mut cursor = 0u64;
        loop {
            let (next, batch) = self.redis.scan(cursor, &pattern, SCAN_BATCH).await?;
            cursor = next;
            for key in batch {
                names.push(queue_name_from_meta_key(&key, prefix));
                if names.len() >= limit {
                    return Ok(names);
                }
            }
            if cursor == 0 || names.len() >= limit {
                break;
            }
        }
        Ok(names)
    }

    pub async fn close(&self) {
        self.redis.close().await;
    }
}
