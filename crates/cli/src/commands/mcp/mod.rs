//! Port of `packages/cli/src/commands/mcp/` (`server.ts` is the `horus mcp` entry point).

pub mod cloud_tools;
pub mod server;
pub mod tools;

use anyhow::Result;

pub async fn run() -> Result<()> {
    server::run().await
}
