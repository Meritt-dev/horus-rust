//! `cloud-logs/` — Azure Monitor / CloudWatch / GCP Logging via native vendor CLIs.
pub mod native_cli;
pub mod provider;

pub use provider::*;
