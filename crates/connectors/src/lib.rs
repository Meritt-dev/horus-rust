//! horus-connectors — provider contracts + implementations.
//! One Rust module per TypeScript directory/file in `packages/connectors/src`.

pub mod axiom;
pub mod bullmq;
pub mod cloud_logs;
pub mod compat;
pub mod contract;
pub mod duration;
pub mod elasticsearch;
pub mod factory;
pub mod firestore;
pub mod git;
pub mod grafana;
pub mod http;
pub mod jsutil;
pub mod lens;
pub mod mongodb;
pub mod postgres;
pub mod prometheus;
pub mod redis;
pub mod runtime_queue;
pub mod sentry;
pub mod shopify;
pub mod source;
#[cfg(feature = "sqlserver")]
pub mod sqlserver;
pub mod state;

pub use compat::*;
pub use contract::*;
pub use duration::*;
pub use factory::*;
pub use http::{fetch_with_retry, HttpRequestOptions, DEFAULT_HTTP_TIMEOUT_MS};

// --- agent C: state / queue / database connectors ---

pub use bullmq::*;
pub use firestore::*;
pub use mongodb::*;
pub use postgres::*;
pub use redis::*;
pub use runtime_queue::*;
#[cfg(feature = "sqlserver")]
pub use sqlserver::*;
pub use state::*;
