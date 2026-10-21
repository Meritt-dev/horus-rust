//! Horus core: config schema, evidence model, secrets, discovery, redaction,
//! git helpers, CODEOWNERS, path classification and queue-edge hygiene.
//! One module per TypeScript file in `packages/core/src`.

pub mod codeowners;
pub mod config;
pub mod discovery;
pub mod evidence;
pub mod git;
pub mod json;
pub mod path_classify;
pub mod queue_hygiene;
pub mod redact;
pub mod runtime_connectors;
pub mod secrets;
pub mod version;

pub use codeowners::*;
pub use config::*;
pub use discovery::*;
pub use evidence::*;
pub use git::*;
pub use path_classify::*;
pub use queue_hygiene::*;
pub use redact::*;
pub use runtime_connectors::*;
pub use secrets::*;
pub use version::*;
