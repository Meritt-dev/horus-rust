//! `@horus/knowledge` — local project-knowledge index schema + store (HOR-291).
//!
//! The contract that `horus init` (HOR-293), the Maison Safqa import adapter
//! (HOR-292), `horus knowledge` (HOR-294), Horus MCP (HOR-295), and optional
//! cloud sync (HOR-296) all build against. Local-first; never requires Cloud.
//! One module per TypeScript file in `packages/knowledge/src`.

pub mod build;
pub mod import;
pub mod layout;
pub mod query;
pub mod schema;
pub mod store;

pub use build::*;
pub use import::*;
pub use layout::*;
pub use query::*;
pub use schema::*;
pub use store::*;
