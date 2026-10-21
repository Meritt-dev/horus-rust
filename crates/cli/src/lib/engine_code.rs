//! `createConnectors` (the one factory helper `horus_connectors::factory` does not export) plus
//! the small glue the read-only code commands share. The engine consumes the connectors
//! `CodeProvider` contract directly, so a `SourceCodeProvider` is passed straight through.

use anyhow::Result;
use horus_connectors::source::SourceCodeProvider;
use horus_core::{HorusConfig, ResolveOptions, ResolvedEnvironment};

use crate::commands::SilentExit;
use crate::lib::command_failure::fail_command;

/// `loadConfig(opts.config)`.
pub fn load_config(config: &Option<String>) -> Result<HorusConfig> {
    horus_core::load_config(config.as_deref().map(std::path::Path::new), None)
}

/// `resolveEnvironment(config, { project })`.
pub fn resolve_env(config: &HorusConfig, project: Option<&str>) -> Result<ResolvedEnvironment> {
    horus_core::resolve_environment(config, &ResolveOptions { project, env: None, cwd: None })
}

/// `return failCommand(err, json)` at a command's outer catch — except when the command
/// already reported its own failure (TS `return 1`), which exits quietly.
pub fn fail(err: anyhow::Error, json: bool) -> anyhow::Error {
    if err.downcast_ref::<SilentExit>().is_some() {
        return err;
    }
    fail_command(err, json)
}

pub use horus_connectors::code_for_repo;

// ported-from: @horus/connectors createConnectors
/// The code provider for the default (or single) project/env.
pub fn create_code(config: &HorusConfig) -> Result<SourceCodeProvider> {
    code_for_repo(config, None)
}

/// Map horus-db queue rows to the engine's queue-edge shape.
pub fn engine_edges(rows: Vec<horus_db::QueueEdge>) -> Vec<horus_engine::code_provider::QueueEdge> {
    rows.into_iter()
        .map(|e| horus_engine::code_provider::QueueEdge {
            queue_name: e.queue_name,
            producer_symbol: e.producer_symbol,
            producer_file: e.producer_file,
            worker_symbol: e.worker_symbol,
            worker_file: e.worker_file,
        })
        .collect()
}
