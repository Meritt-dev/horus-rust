//! Version pins. The TS build injects `__HORUS_VERSION__` from `apps/horus/package.json`
//! and falls back to `'dev'`; here the build-time `HORUS_VERSION` env var plays that role.

/// Horus version string; `"dev"` when not injected at build time.
pub const HORUS_VERSION: &str = match option_env!("HORUS_VERSION") {
    Some(v) => v,
    None => "dev",
};

/// The exact source-intelligence backend version Horus is validated and pinned against.
/// The backend ships INSIDE the horus bundle, so the pin IS the horus version.
pub const PINNED_SOURCE_VERSION: &str = HORUS_VERSION;

/// Whether the pin is enforceable. In unbundled dev runs HORUS_VERSION is `dev`, which
/// matches no real backend — enforcing it would block every dev-mode host spawn and reuse.
pub const SOURCE_PIN_ENFORCED: bool = !const_str_eq(HORUS_VERSION, "dev");

/// The analysis-capability version this CLI expects an on-disk source index to carry (D6).
/// MUST be kept in lockstep with `INDEX_CAPABILITY_VERSION` in
/// `packages/source-py/src/horus_source/capabilities.py`.
pub const EXPECTED_INDEX_CAPABILITY: u32 = 2;

const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
