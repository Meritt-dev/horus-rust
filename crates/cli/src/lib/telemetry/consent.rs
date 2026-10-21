//! Consent resolution for usage telemetry (HOR-323). Port of
//! `packages/cli/src/lib/telemetry/consent.ts`.
//!
//! Most-restrictive-wins: (1) env hard opt-out — `DO_NOT_TRACK` or `HORUS_TELEMETRY=0|off|…`
//! (no file read); (2) CI collects nothing unless `HORUS_TELEMETRY` explicitly enables;
//! (3) stored decision (Tier A default on, Tier B default off). Tier B is only ever enabled via
//! `horus telemetry enable-content`, never via env.

use super::store::{read_telemetry_state, TelemetryState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentSource {
    Env,
    Ci,
    State,
    Default,
}

impl ConsentSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Ci => "ci",
            Self::State => "state",
            Self::Default => "default",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsentDecision {
    /// Anonymous usage metadata allowed.
    pub tier_a: bool,
    /// Redacted input/output content allowed.
    pub tier_b: bool,
    /// True when an env hard opt-out is in effect.
    pub forced_off: bool,
    pub source: ConsentSource,
    pub reason: String,
}

const OFF_VALUES: &[&str] = &["0", "false", "off", "no", "disable", "disabled"];
const ON_VALUES: &[&str] = &["1", "true", "on", "yes", "enable", "enabled", "all"];
const CI_ENV_VARS: &[&str] = &[
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "JENKINS_URL",
    "TEAMCITY_VERSION",
];

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn is_off(v: &str) -> bool {
    OFF_VALUES.contains(&v.trim().to_lowercase().as_str())
}

/// `DO_NOT_TRACK` is honored when set to anything other than empty/0/false.
fn do_not_track() -> bool {
    env("DO_NOT_TRACK").is_some_and(|v| !is_off(&v))
}

/// Parse `HORUS_TELEMETRY` into Some(true)=on / Some(false)=off, None when unset/unknown.
fn parse_env_flag() -> Option<bool> {
    let v = env("HORUS_TELEMETRY")?.trim().to_lowercase();
    if OFF_VALUES.contains(&v.as_str()) {
        Some(false)
    } else if ON_VALUES.contains(&v.as_str()) {
        Some(true)
    } else {
        None
    }
}

pub fn is_ci() -> bool {
    CI_ENV_VARS.iter().any(|k| env(k).is_some_and(|v| !is_off(&v)))
}

fn off(source: ConsentSource, reason: &str) -> ConsentDecision {
    ConsentDecision { tier_a: false, tier_b: false, forced_off: source == ConsentSource::Env, source, reason: reason.into() }
}

/// Resolve the effective consent decision. Reads `~/.horus/telemetry.json` unless `state` is
/// supplied (`Some(None)` = "no saved state").
pub fn resolve_consent(state: Option<Option<&TelemetryState>>) -> ConsentDecision {
    // 1. Hard opt-out via env wins over everything — decided before touching disk.
    if do_not_track() {
        return off(ConsentSource::Env, "DO_NOT_TRACK is set");
    }
    let env_flag = parse_env_flag();
    if env_flag == Some(false) {
        return off(ConsentSource::Env, "HORUS_TELEMETRY disables telemetry");
    }

    let loaded;
    let state = match state {
        Some(s) => s,
        None => {
            loaded = read_telemetry_state();
            loaded.as_ref()
        }
    };
    let stored_a = state.map_or(true, |s| s.tier_a.enabled);
    let stored_b = state.is_some_and(|s| s.tier_b.enabled);

    // 2. CI collects nothing unless explicitly enabled.
    if is_ci() && env_flag != Some(true) {
        return ConsentDecision {
            tier_a: false,
            tier_b: false,
            forced_off: false,
            source: ConsentSource::Ci,
            reason: "CI environment detected — telemetry off by default".into(),
        };
    }
    // 3. Explicit env enable turns the Tier A gate on; Tier B still needs opt-in.
    if env_flag == Some(true) {
        return ConsentDecision {
            tier_a: true,
            tier_b: stored_b,
            forced_off: false,
            source: ConsentSource::Env,
            reason: "HORUS_TELEMETRY enables usage metadata".into(),
        };
    }
    ConsentDecision {
        tier_a: stored_a,
        tier_b: stored_b,
        forced_off: false,
        source: if state.is_some() { ConsentSource::State } else { ConsentSource::Default },
        reason: if state.is_some() {
            "from ~/.horus/telemetry.json".into()
        } else {
            "default settings (no saved preference)".into()
        },
    }
}

/// Is anonymous usage metadata (Tier A) collection allowed right now.
pub fn is_telemetry_enabled() -> bool {
    resolve_consent(None).tier_a
}

/// Is redacted content (Tier B) sharing allowed right now.
pub fn is_content_sharing_enabled() -> bool {
    resolve_consent(None).tier_b
}
