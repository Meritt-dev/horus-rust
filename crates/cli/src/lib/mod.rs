//! Shared helpers: one module per TS file in `packages/cli/src/lib/`. Stubs until ported.
#![allow(dead_code)]

pub mod ai_provider;
pub mod bundled_backend;
pub mod capability_hint;
pub mod claude_investigation;
pub mod command_failure;
pub mod engine_code;
pub mod ensure_host;
pub mod feedback_nudge;
pub mod format;
pub mod freshness;
pub mod host_reaper;
pub mod incident_followups;
pub mod incident_repair;
pub mod investigation_runner;
pub mod notify_sink;
pub mod open_url;
pub mod own_packages;
pub mod related_incidents;
pub mod report_crash;
pub mod tty_selector;
pub mod update_notifier;
pub mod vector_index;
pub mod watch_service;
pub mod watch_store;
pub mod worker_activity;
pub mod cloud;
pub mod lens;
pub mod telemetry;
