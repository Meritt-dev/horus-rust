//! Thin Redis client for reading BullMQ queue state (HOR-12).
//! Read-only — no mutations, no write surface exposed.

use crate::redis::scan_client::{ioredis_err, queue_name_from_meta_key, LazyRedis};
use anyhow::Result;
use horus_core::{redact_error_message, HealthStatus};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BullMQClientOpts {
    pub url: String,
    /// BullMQ key prefix — defaults to "bull".
    pub prefix: Option<String>,
}

/// BullMQ queue sub-structures addressable via `queue_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueKeySuffix {
    Wait,
    Active,
    Delayed,
    Failed,
    Completed,
    Paused,
}

impl QueueKeySuffix {
    fn as_str(self) -> &'static str {
        match self {
            QueueKeySuffix::Wait => "wait",
            QueueKeySuffix::Active => "active",
            QueueKeySuffix::Delayed => "delayed",
            QueueKeySuffix::Failed => "failed",
            QueueKeySuffix::Completed => "completed",
            QueueKeySuffix::Paused => "paused",
        }
    }
}

fn lossy(v: Vec<u8>) -> String {
    String::from_utf8_lossy(&v).into_owned()
}

pub struct BullMQRedisClient {
    redis: LazyRedis,
    pub prefix: String,
}

impl BullMQRedisClient {
    pub fn new(opts: BullMQClientOpts) -> Result<Self> {
        let prefix = opts.prefix.unwrap_or_else(|| "bull".to_string());
        // The DB index comes from the URL path (the factory already applied `redis_url_for_db`).
        let redis = LazyRedis::open(&opts.url, None).map_err(|e| anyhow::anyhow!(redact_error_message(&e)))?;
        Ok(Self { redis, prefix })
    }

    /// Redis key for a BullMQ queue sub-structure.
    pub fn queue_key(&self, name: &str, suffix: QueueKeySuffix) -> String {
        format!("{}:{name}:{}", self.prefix, suffix.as_str())
    }

    /// Redis key for a BullMQ job hash.
    pub fn job_key(&self, queue_name: &str, job_id: &str) -> String {
        format!("{}:{queue_name}:{job_id}", self.prefix)
    }

    pub async fn list_len(&self, key: &str) -> Result<i64> {
        let mut c = self.redis.conn().await?;
        redis::cmd("LLEN").arg(key).query_async::<i64>(&mut c).await.map_err(ioredis_err)
    }

    pub async fn sorted_set_card(&self, key: &str) -> Result<i64> {
        let mut c = self.redis.conn().await?;
        redis::cmd("ZCARD").arg(key).query_async::<i64>(&mut c).await.map_err(ioredis_err)
    }

    /// Returns None when the list is empty or the key does not exist.
    pub async fn list_index(&self, key: &str, index: i64) -> Result<Option<String>> {
        let mut c = self.redis.conn().await?;
        let v: Option<Vec<u8>> = redis::cmd("LINDEX").arg(key).arg(index).query_async(&mut c).await.map_err(ioredis_err)?;
        Ok(v.map(lossy))
    }

    /// Read specific fields from a BullMQ job hash.
    /// Returns a map with only the fields that exist in Redis.
    pub async fn job_fields(&self, queue_name: &str, job_id: &str, fields: &[&str]) -> Result<HashMap<String, String>> {
        let mut c = self.redis.conn().await?;
        let mut cmd = redis::cmd("HMGET");
        cmd.arg(self.job_key(queue_name, job_id));
        for f in fields {
            cmd.arg(*f);
        }
        let values: Vec<Option<Vec<u8>>> = cmd.query_async(&mut c).await.map_err(ioredis_err)?;
        let mut result = HashMap::new();
        for (i, f) in fields.iter().enumerate() {
            if let Some(Some(v)) = values.get(i) {
                result.insert(f.to_string(), lossy(v.clone()));
            }
        }
        Ok(result)
    }

    /// The most recent `count` members of a sorted set (rightmost = highest score).
    pub async fn sorted_set_tail(&self, key: &str, count: i64) -> Result<Vec<String>> {
        let mut c = self.redis.conn().await?;
        let v: Vec<Vec<u8>> = redis::cmd("ZRANGE").arg(key).arg(-count).arg(-1).query_async(&mut c).await.map_err(ioredis_err)?;
        Ok(v.into_iter().map(lossy).collect())
    }

    /// Fetch a single field from multiple job hashes in one pipeline round-trip.
    /// None entries mean the field was absent.
    pub async fn pipeline_hget(&self, queue_name: &str, job_ids: &[String], field: &str) -> Result<Vec<Option<String>>> {
        if job_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut c = self.redis.conn().await?;
        let mut pipe = redis::pipe();
        for job_id in job_ids {
            pipe.cmd("HGET").arg(self.job_key(queue_name, job_id)).arg(field);
        }
        let values: Vec<Option<Vec<u8>>> = pipe.query_async(&mut c).await.map_err(ioredis_err)?;
        Ok(values.into_iter().map(|v| v.map(lossy)).collect())
    }

    /// Discover queue names by scanning for BullMQ `:meta` keys.
    ///
    /// `:meta` is written when a Queue is instantiated and persists regardless of job
    /// state, so it finds idle queues too. Scanning `:wait` (the previous approach) only
    /// surfaced queues with pending jobs, so idle-but-real queues were invisible.
    /// Returns at most `limit` queue names.
    pub async fn discover_queues(&self, limit: Option<usize>) -> Result<Vec<String>> {
        let limit = limit.unwrap_or(50);
        let pattern = format!("{}:*:meta", self.prefix);
        let mut names: Vec<String> = Vec::new();
        let mut cursor = 0u64;
        loop {
            let (next, batch) = self.redis.scan(cursor, &pattern, 100).await?;
            cursor = next;
            for key in batch {
                names.push(queue_name_from_meta_key(&key, &self.prefix));
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

    pub async fn health(&self) -> HealthStatus {
        match self.redis.ping().await {
            Ok(()) => HealthStatus { ok: true, detail: format!("Redis reachable (prefix: {})", self.prefix) },
            // Redis errors can echo the credential-bearing connection URL.
            Err(err) => HealthStatus { ok: false, detail: redact_error_message(&err) },
        }
    }

    pub async fn close(&self) {
        self.redis.close().await;
    }
}
