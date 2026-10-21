//! `runtime-queue/` — Kafka and Azure Service Bus queue-evidence providers.

mod kafka_admin;
mod provider;

pub use provider::*;
