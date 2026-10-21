//! `redis/` — generic Redis scan client, DB discovery, status and the state provider.

mod discovery;
pub(crate) mod scan_client;
mod state_provider;
mod status;

pub use discovery::{probe_redis_databases, ProbeOpts, RedisDbProbe};
pub use scan_client::{KeyPrefixSample, RedisScanClient, RedisScanClientOpts};
pub use state_provider::{
    RedisDbSummary, RedisStateAnalysis, RedisStateDb, RedisStateProvider, RedisStateRuntimeProvider, RedisStateScan,
    RedisStateSignal,
};
pub use status::{redis_server_status, RedisDbStatus, RedisServerStatus};
