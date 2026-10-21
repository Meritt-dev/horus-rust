//! Kafka / Azure Service Bus queue-evidence providers (`runtime-queue/provider.ts`).
//!
//! Service Bus reads management-plane counts via the local `az` CLI. Kafka reads topic
//! end offsets and consumer-group committed offsets through `kafka_admin` (the kafkajs
//! `admin()` subset the TS provider uses).

use super::kafka_admin::KafkaAdmin;
use crate::contract::Provider;
use crate::cloud_logs::native_cli::native_json;
use crate::jsutil::now_iso;
use anyhow::{bail, Result};
use async_trait::async_trait;
use horus_core::{
    redact_error_message, validate_azure_service_bus, validate_kafka, AzureServiceBusConfig, Evidence, EvidenceKind,
    EvidenceLinks, HealthStatus, Issues, KafkaConfig, ProviderKind, Provenance,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

#[async_trait]
pub trait QueueEvidenceProvider: Provider {
    async fn collect(&self) -> Result<Vec<Evidence>>;
}

fn evidence(source: &str, queue_name: &str, payload: Map<String, Value>) -> Evidence {
    let now = now_iso();
    let digest = hex::encode(Sha256::digest(queue_name.as_bytes()));
    let mut full = Map::new();
    full.insert("source".into(), Value::from(source));
    full.extend(payload);
    Evidence {
        id: format!("ev_{source}_{}", &digest[..16]),
        source: ProviderKind::Queue,
        kind: EvidenceKind::QueueState,
        title: format!("{source}: {queue_name} — read-only queue snapshot"),
        timestamp: Some(now.clone()),
        relevance: 0.45,
        payload: Value::Object(full),
        links: EvidenceLinks { queue_name: Some(queue_name.to_string()), ..Default::default() },
        provenance: Provenance { query: format!("{source}.metadata"), collected_at: now },
        priority: None,
        category: None,
        subject: None,
        is_new: None,
        ratio: None,
    }
}

fn first_issue(issues: &Issues, what: &str) -> Result<()> {
    if let Some(i) = issues.items.first() {
        bail!("{what} config: {}: {}", i.path, i.message);
    }
    Ok(())
}

/// Offsets only: never consumes messages, commits offsets, or creates topics.
pub struct KafkaQueueProvider {
    pub config: KafkaConfig,
}

impl KafkaQueueProvider {
    pub fn new(config: KafkaConfig) -> Result<Self> {
        let mut issues = Issues::default();
        validate_kafka(&mut issues, &config);
        first_issue(&issues, "kafka")?;
        Ok(Self { config })
    }
}

#[async_trait]
impl Provider for KafkaQueueProvider {
    fn id(&self) -> &str {
        "kafka"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Queue
    }
    async fn health(&self) -> HealthStatus {
        match self.collect().await {
            Ok(_) => HealthStatus { ok: true, detail: "Kafka topic and group offsets readable".to_string() },
            Err(e) => HealthStatus { ok: false, detail: redact_error_message(&e) },
        }
    }
}

#[async_trait]
impl QueueEvidenceProvider for KafkaQueueProvider {
    async fn collect(&self) -> Result<Vec<Evidence>> {
        let c = &self.config;
        // Dropping the admin closes every broker socket (kafkajs `admin.disconnect()` in `finally`).
        let mut admin = KafkaAdmin::connect(c).await?;
        let mut out = Vec::new();
        for topic in &c.topics {
            let ends = admin.fetch_topic_offsets(topic).await?;
            for group_id in &c.groups {
                let offsets = admin.fetch_offsets(group_id, topic).await?;
                let partitions: Vec<Value> = ends
                    .iter()
                    .map(|p| {
                        let committed = offsets.get(&p.partition);
                        json!({
                            "partition": p.partition,
                            "logEnd": p.high,
                            "committed": committed,
                            "lag": offset_lag(&p.high, committed.map(String::as_str)),
                        })
                    })
                    .collect();
                let mut payload = Map::new();
                payload.insert("topic".into(), Value::from(topic.as_str()));
                payload.insert("groupId".into(), Value::from(group_id.as_str()));
                payload.insert("partitions".into(), Value::Array(partitions));
                payload.insert(
                    "limitation".into(),
                    Value::from("Point-in-time committed offsets; unknown lag is not zero and does not prove worker starvation."),
                );
                out.push(evidence("kafka", &format!("{topic}/{group_id}"), payload));
            }
        }
        Ok(out)
    }
}

/// `high - committed` as a decimal string; None when either side isn't a non-negative integer.
pub fn offset_lag(high: &str, committed: Option<&str>) -> Option<String> {
    let committed = committed.filter(|c| !c.is_empty())?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(committed) || !digits(high) {
        return None;
    }
    let lag = high.parse::<u128>().ok()?.checked_sub(committed.parse::<u128>().ok()?)?;
    Some(lag.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SbCountDetails {
    active_message_count: i64,
    dead_letter_message_count: i64,
    scheduled_message_count: i64,
    transfer_message_count: Option<i64>,
    transfer_dead_letter_message_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SbProperties {
    status: String,
    count_details: SbCountDetails,
}

#[derive(Debug, Deserialize)]
struct SbQueue {
    properties: SbProperties,
}

/// Management-plane counts only: no peek-lock, receive, complete, or dead-letter writes.
pub struct ServiceBusQueueProvider {
    pub config: AzureServiceBusConfig,
}

impl ServiceBusQueueProvider {
    pub fn new(config: AzureServiceBusConfig) -> Result<Self> {
        let mut issues = Issues::default();
        validate_azure_service_bus(&mut issues, &config);
        first_issue(&issues, "azure-service-bus")?;
        Ok(Self { config })
    }
}

#[async_trait]
impl Provider for ServiceBusQueueProvider {
    fn id(&self) -> &str {
        "azure-service-bus"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Queue
    }
    async fn health(&self) -> HealthStatus {
        match self.collect().await {
            Ok(_) => HealthStatus { ok: true, detail: "Service Bus queue counts readable".to_string() },
            Err(e) => HealthStatus { ok: false, detail: redact_error_message(&e) },
        }
    }
}

#[async_trait]
impl QueueEvidenceProvider for ServiceBusQueueProvider {
    async fn collect(&self) -> Result<Vec<Evidence>> {
        let c = &self.config;
        let subscription = c.namespace_id.split('/').nth(2).unwrap_or_default().to_string();
        let mut out = Vec::new();
        for queue in &c.queues {
            let encoded: String = url::form_urlencoded::byte_serialize(queue.as_bytes()).collect();
            let url = format!("https://management.azure.com{}/queues/{encoded}?api-version=2024-01-01", c.namespace_id);
            let raw = native_json(&c.executable, &["rest", "--method", "get", "--url", &url, "--subscription", &subscription, "--output", "json"]).await?;
            let result: SbQueue = serde_json::from_value(raw)?;
            let p = result.properties;
            let d = p.count_details;
            let mut payload = Map::new();
            payload.insert("queue".into(), Value::from(queue.as_str()));
            payload.insert("status".into(), Value::from(p.status));
            payload.insert("activeMessageCount".into(), Value::from(d.active_message_count));
            payload.insert("deadLetterMessageCount".into(), Value::from(d.dead_letter_message_count));
            payload.insert("scheduledMessageCount".into(), Value::from(d.scheduled_message_count));
            if let Some(n) = d.transfer_message_count {
                payload.insert("transferMessageCount".into(), Value::from(n));
            }
            if let Some(n) = d.transfer_dead_letter_message_count {
                payload.insert("transferDeadLetterMessageCount".into(), Value::from(n));
            }
            for (k, v) in payload.iter() {
                if k.ends_with("Count") && v.as_i64().is_some_and(|n| n < 0) {
                    bail!("Service Bus count {k} must be non-negative");
                }
            }
            payload.insert("limitation".into(), Value::from("Broker counts do not measure active workers or establish starvation."));
            out.push(evidence(self.id(), queue, payload));
        }
        Ok(out)
    }
}
