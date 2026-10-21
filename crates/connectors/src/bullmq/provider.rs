//! Queue runtime evidence provider (HOR-12).
//!
//! Reads live BullMQ state from Redis and converts it into typed Evidence:
//! backlog depth, failed counts and error breakdown, delayed accumulation,
//! oldest-job age, and worker starvation. No raw Redis data reaches the engine.

use super::analyze::{queue_state_to_evidence, FailedBreakdown, QueueCounts, QueueRuntimeState};
use super::client::{BullMQRedisClient, QueueKeySuffix};
use crate::contract::Provider;
use crate::jsutil::{js_number_from_str, now_iso, now_ms};
use anyhow::Result;
use async_trait::async_trait;
use horus_core::{Evidence, HealthStatus, ProviderKind};
use indexmap::IndexMap;

#[async_trait]
pub trait QueueRuntimeProvider: Provider {
    async fn analyze_queues(&self, queue_names: Option<&[String]>) -> Result<QueueRuntimeState>;
    /// Discover queue names present in Redis (regardless of static topology).
    async fn discover_queues(&self) -> Result<Vec<String>>;
    fn to_evidence(&self, state: &QueueRuntimeState) -> Vec<Evidence>;
    async fn close(&self);
}

/// Number of recent failed jobs to sample for error-breakdown evidence.
const FAILED_SAMPLE: i64 = 20;

pub struct BullMQRuntimeProvider {
    client: BullMQRedisClient,
}

impl BullMQRuntimeProvider {
    pub fn new(client: BullMQRedisClient) -> Self {
        Self { client }
    }

    async fn inspect_queue(&self, name: &str) -> Result<QueueCounts> {
        let c = &self.client;
        let key = |s: QueueKeySuffix| c.queue_key(name, s);
        let (k_wait, k_active, k_failed, k_delayed, k_completed, k_paused) = (
            key(QueueKeySuffix::Wait),
            key(QueueKeySuffix::Active),
            key(QueueKeySuffix::Failed),
            key(QueueKeySuffix::Delayed),
            key(QueueKeySuffix::Completed),
            key(QueueKeySuffix::Paused),
        );
        let (waiting, active, failed, delayed, completed, paused) = tokio::try_join!(
            c.list_len(&k_wait),
            c.list_len(&k_active),
            c.sorted_set_card(&k_failed),
            c.sorted_set_card(&k_delayed),
            c.sorted_set_card(&k_completed),
            c.list_len(&k_paused),
        )?;

        let mut counts = QueueCounts {
            queue_name: name.to_string(),
            waiting,
            active,
            failed,
            delayed,
            completed,
            paused,
            is_paused: paused > 0,
            oldest_waiting_ms: None,
            failed_breakdown: None,
            newest_failed_age_ms: None,
        };

        // Oldest waiting job: BullMQ LPUSHes new jobs (index 0 = newest); workers
        // RPOPLPUSH from the tail, so the oldest unprocessed job is at index -1.
        if waiting > 0 {
            if let Some(oldest_job_id) = c.list_index(&c.queue_key(name, QueueKeySuffix::Wait), -1).await? {
                let fields = c.job_fields(name, &oldest_job_id, &["timestamp"]).await?;
                if let Some(ts) = fields.get("timestamp") {
                    if let Some(created) = js_number_from_str(ts).filter(|v| *v > 0.0) {
                        counts.oldest_waiting_ms = Some(now_ms() as f64 - created);
                    }
                }
            }
        }

        // Failed breakdown: sample the most recent failed jobs, group by error message.
        // Also read each job's `finishedOn` (epoch ms, set by BullMQ when a job fails)
        // so callers can tell a live failure from a stale one (HOR-217).
        if failed > 0 {
            let failed_job_ids = c.sorted_set_tail(&c.queue_key(name, QueueKeySuffix::Failed), FAILED_SAMPLE).await?;
            let (reasons, finished) =
                tokio::try_join!(c.pipeline_hget(name, &failed_job_ids, "failedReason"), c.pipeline_hget(name, &failed_job_ids, "finishedOn"))?;
            let now = now_ms() as f64;
            // Per-reason: count + the most recent finishedOn (epoch ms) seen for it.
            let mut by_reason: IndexMap<String, (i64, f64)> = IndexMap::new();
            let mut newest_finished_overall = 0.0f64;
            for i in 0..failed_job_ids.len() {
                let Some(r) = reasons.get(i).and_then(|r| r.as_deref()).filter(|r| !r.is_empty()) else { continue };
                // First line only — avoid folding distinct stack traces into one bucket
                let key: String = r.lines().next().unwrap_or("").trim().chars().take(120).collect();
                let fin = finished.get(i).and_then(|f| f.as_deref()).and_then(js_number_from_str);
                let fin = fin.filter(|f| f.is_finite() && *f > 0.0);
                let entry = by_reason.entry(key).or_insert((0, 0.0));
                entry.0 += 1;
                if let Some(f) = fin {
                    if f > entry.1 {
                        entry.1 = f;
                    }
                    if f > newest_finished_overall {
                        newest_finished_overall = f;
                    }
                }
            }
            let mut breakdown: Vec<FailedBreakdown> = by_reason
                .into_iter()
                .map(|(reason, (count, newest))| FailedBreakdown {
                    reason,
                    count,
                    last_failed_age_ms: if newest > 0.0 { Some((now - newest).max(0.0)) } else { None },
                })
                .collect();
            breakdown.sort_by(|a, b| b.count.cmp(&a.count)); // stable, like Array#sort
            counts.failed_breakdown = Some(breakdown);
            if newest_finished_overall > 0.0 {
                counts.newest_failed_age_ms = Some((now - newest_finished_overall).max(0.0));
            }
        }

        Ok(counts)
    }
}

#[async_trait]
impl Provider for BullMQRuntimeProvider {
    fn id(&self) -> &str {
        "bullmq"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Queue
    }
    async fn health(&self) -> HealthStatus {
        self.client.health().await
    }
}

#[async_trait]
impl QueueRuntimeProvider for BullMQRuntimeProvider {
    async fn analyze_queues(&self, queue_names: Option<&[String]>) -> Result<QueueRuntimeState> {
        let collected_at = now_iso();
        let names: Vec<String> = match queue_names {
            Some(n) if !n.is_empty() => n.to_vec(),
            _ => self.client.discover_queues(None).await?,
        };
        // `Promise.all` — inspect concurrently over the multiplexed connection, keep order.
        let queues = futures::future::try_join_all(names.iter().map(|name| self.inspect_queue(name))).await?;
        Ok(QueueRuntimeState { prefix: self.client.prefix.clone(), collected_at, queues })
    }

    /// Discover queue names present in Redis under the configured prefix.
    async fn discover_queues(&self) -> Result<Vec<String>> {
        self.client.discover_queues(None).await
    }

    fn to_evidence(&self, state: &QueueRuntimeState) -> Vec<Evidence> {
        queue_state_to_evidence(state, "queue.analyzeQueues", &state.collected_at)
    }

    async fn close(&self) {
        self.client.close().await;
    }
}
