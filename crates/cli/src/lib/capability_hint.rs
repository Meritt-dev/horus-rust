//! Port of `packages/cli/src/lib/capability-hint.ts` — the D6 reindex nudge for class/interface
//! seeds against an index that predates inheritance-aware blast radius.

use horus_connectors::source::index_capability_stale;
use horus_core::EXPECTED_INDEX_CAPABILITY;

use crate::lib::cloud::session::repo_root_or_cwd;
use crate::lib::format::dim;

/// One string so blast-radius and explain stay byte-identical.
pub const CAPABILITY_HINT_TEXT: &str = "Index predates inheritance-aware blast radius — subclasses/implementors may be missing. Run `horus init --reindex` to complete them.";

/// True when the seed's node id denotes a class or interface (the only inheritance-bearing seeds).
pub fn is_inheritance_seed(seed_id: Option<&str>) -> bool {
    seed_id.is_some_and(|id| id.starts_with("class:") || id.starts_with("interface:"))
}

/// Print ONE dim reindex hint when the seed is a class/interface and the on-disk index's
/// capability stamp is below the current expectation. Never blocks; suppressed under --json;
/// a no-op when there is no local index/meta to be stale about.
pub fn print_capability_hint(seed_id: Option<&str>, json: bool) {
    if json || !is_inheritance_seed(seed_id) {
        return;
    }
    let root = repo_root_or_cwd(None);
    if !index_capability_stale(&root, EXPECTED_INDEX_CAPABILITY) {
        return;
    }
    println!("{}", dim(&format!("  {CAPABILITY_HINT_TEXT}")));
}
