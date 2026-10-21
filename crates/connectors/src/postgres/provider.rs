//! Postgres `StateProvider` (`postgres/provider.ts`) — the shared database provider with id `postgres`.

use super::client::PostgresStateClient;
use crate::state::database_provider::{DatabaseStateOpts, DatabaseStateProvider};
use std::sync::Arc;

pub type PostgresStateProvider = DatabaseStateProvider;

impl DatabaseStateProvider {
    pub fn postgres(client: PostgresStateClient, opts: DatabaseStateOpts) -> PostgresStateProvider {
        DatabaseStateProvider::new("postgres", Arc::new(client), opts)
    }
}
