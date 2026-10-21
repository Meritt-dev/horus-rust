//! HOR-386 — the shared, deterministic next-step router.
//!
//! PURE: no IO, no LLM, no command execution. Given a command + the conditions the
//! engine/surfaces already computed, returns an ordered `RouteStep[]`. Adding a route =
//! adding one table entry below. Suggests, never runs; never fabricates a command (every
//! `next_tool` is a REAL shipped `horus` command or MCP knowledge tool).

use crate::gaps::EvidenceGap;
pub use crate::types::{Intent, RouteStep};

/// The surface/command the router is producing next-steps for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouterCommand {
    Investigate,
    Explain,
    BlastRadius,
    Packet,
    Memory,
    Search,
    McpSearch,
    McpAsk,
    McpContract,
    McpDomain,
}

/// The facts the router decides over — every field is something a surface already computed.
#[derive(Debug, Clone)]
pub struct RouterConditions {
    pub command: RouterCommand,
    pub intent: Option<Intent>,
    pub empty: bool,
    pub low_confidence: bool,
    /// The highest-impact routable gap (callers pass the impact-sorted top).
    pub top_gap: Option<EvidenceGap>,
    /// `has_any_runtime_connector(flags)` — config already shows runtime intent.
    pub any_runtime_connector: bool,
    pub host_unreachable: bool,
    pub stale_index: bool,
    pub degraded_source_intelligence: bool,
    /// A performance hint with no metrics connector.
    pub metrics_null: bool,
    pub seed_name: Option<String>,
    pub query: Option<String>,
}

impl RouterConditions {
    pub fn new(command: RouterCommand) -> Self {
        Self {
            command,
            intent: None,
            empty: false,
            low_confidence: false,
            top_gap: None,
            any_runtime_connector: false,
            host_unreachable: false,
            stale_index: false,
            degraded_source_intelligence: false,
            metrics_null: false,
            seed_name: None,
            query: None,
        }
    }
}

fn step(next_tool: &str, args: &str, reason: &str) -> RouteStep {
    RouteStep { next_tool: next_tool.into(), args: args.into(), reason: reason.into() }
}

fn arg(s: &Option<String>) -> &str {
    s.as_deref().unwrap_or("")
}

struct RouteRule {
    id: &'static str,
    when: fn(&RouterConditions) -> bool,
    steps: fn(&RouterConditions) -> Vec<RouteStep>,
    /// Fires ONLY when no non-fallback rule produced a step.
    fallback: bool,
}

use RouterCommand as C;

/// The ordered routing table (priority top→bottom).
const RULES: &[RouteRule] = &[
    // 1 — any command: host down or index stale/degraded.
    RouteRule {
        id: "host-or-index-unhealthy",
        when: |c| c.host_unreachable || c.stale_index || c.degraded_source_intelligence,
        steps: |_| vec![step("init", "", "Source-intelligence host unreachable / index stale — run `horus init`.")],
        fallback: false,
    },
    // 2 — investigate with no seed matched.
    RouteRule {
        id: "investigate-empty",
        when: |c| c.command == C::Investigate && c.empty,
        steps: |c| vec![step("search", arg(&c.query), "No symbol matched — search the index for the right name.")],
        fallback: false,
    },
    // 3 — structural impact question → blast-radius.
    RouteRule {
        id: "investigate-source-impact",
        when: |c| c.command == C::Investigate && c.intent == Some(Intent::SourceImpact),
        steps: |c| {
            vec![step("blast-radius", arg(&c.seed_name), "Full upstream/downstream blast radius for the named symbol.")]
        },
        fallback: false,
    },
    // 4 — behavioral how-does-it-work question → explain.
    RouteRule {
        id: "investigate-explain",
        when: |c| c.command == C::Investigate && c.intent == Some(Intent::Explain),
        steps: |c| {
            vec![step(
                "explain",
                arg(&c.seed_name),
                "Reads as a how-does-it-work question — `explain` walks the behavior.",
            )]
        },
        fallback: false,
    },
    // 5 — perf hypothesis with no metrics backend, on a config that already uses runtime connectors.
    RouteRule {
        id: "investigate-metrics-null",
        when: |c| c.command == C::Investigate && c.metrics_null && c.any_runtime_connector,
        steps: |_| vec![step("connect", "grafana", "No metrics connector — connect Grafana to confirm the perf hypothesis.")],
        fallback: false,
    },
    // 6 — low confidence: route to the top evidence gap's colocated, real remedy.
    RouteRule {
        id: "investigate-low-confidence-top-gap",
        when: |c| {
            c.command == C::Investigate && c.low_confidence && c.top_gap.as_ref().is_some_and(|g| g.route_hint.is_some())
        },
        steps: |c| c.top_gap.as_ref().and_then(|g| g.route_hint.clone()).into_iter().collect(),
        fallback: false,
    },
    // 7 — explain with no symbol found → search.
    RouteRule {
        id: "explain-empty",
        when: |c| c.command == C::Explain && c.empty,
        steps: |c| vec![step("search", arg(&c.query), "No symbol found — search for the right name.")],
        fallback: false,
    },
    // 8 — blast-radius with no symbol found → search.
    RouteRule {
        id: "blast-radius-empty",
        when: |c| c.command == C::BlastRadius && c.empty,
        steps: |c| vec![step("search", arg(&c.query), "No symbol found — search for the right name.")],
        fallback: false,
    },
    // 9 — memory show with nothing stored → run an investigation.
    RouteRule {
        id: "memory-empty",
        when: |c| c.command == C::Memory && c.empty,
        steps: |c| vec![step("investigate", arg(&c.query), "No stored memory — run an investigation to populate it.")],
        fallback: false,
    },
    // 10 — MCP search/ask with 0 matches → broaden.
    RouteRule {
        id: "mcp-search-empty",
        when: |c| matches!(c.command, C::McpSearch | C::McpAsk) && c.empty,
        steps: |c| {
            vec![step("search_project_knowledge", arg(&c.query), "No indexed knowledge matched — broaden the search.")]
        },
        fallback: false,
    },
    // 11 — MCP contract/domain miss → search across knowledge.
    RouteRule {
        id: "mcp-contract-empty",
        when: |c| matches!(c.command, C::McpContract | C::McpDomain) && c.empty,
        steps: |c| vec![step("search_project_knowledge", arg(&c.query), "No exact match — search across knowledge.")],
        fallback: false,
    },
    // 12 (FALLBACK) — configured, immediately-useful follow-ups; never connector setup.
    RouteRule {
        id: "investigate-follow-ups-fallback",
        when: |c| c.command == C::Investigate && !c.empty && c.seed_name.as_deref().is_some_and(|s| !s.is_empty()),
        steps: |c| {
            let seed = arg(&c.seed_name);
            vec![
                step(
                    "explain",
                    seed,
                    &format!("Walk {seed}'s behavior, callers, and flows to verify the structural picture."),
                ),
                step(
                    "what-changed",
                    "",
                    "Diff the recent change window for this repo — changes are the most common cause source.",
                ),
            ]
        },
        fallback: true,
    },
];

/// Resolve next-steps: concatenate the steps of every matching non-fallback rule (table
/// order); fallbacks fire only when nothing else routed.
pub fn route(c: &RouterConditions) -> Vec<RouteStep> {
    let mut out: Vec<RouteStep> = RULES.iter().filter(|r| !r.fallback && (r.when)(c)).flat_map(|r| (r.steps)(c)).collect();
    if out.is_empty() {
        out = RULES.iter().filter(|r| r.fallback && (r.when)(c)).flat_map(|r| (r.steps)(c)).collect();
    }
    out
}

/// The rule ids in priority order.
pub fn route_rule_ids() -> Vec<&'static str> {
    RULES.iter().map(|r| r.id).collect()
}

/// The runnable `horus <tool> <args>` command string for a step.
pub fn format_route_command(step: &RouteStep) -> String {
    if step.args.is_empty() {
        format!("horus {}", step.next_tool)
    } else {
        format!("horus {} {}", step.next_tool, step.args)
    }
}

/// A one-line human suggestion: `"<reason> → run \`horus <tool> <args>\`"`.
pub fn format_route_step(step: &RouteStep) -> String {
    format!("{} → run `{}`", step.reason, format_route_command(step))
}
