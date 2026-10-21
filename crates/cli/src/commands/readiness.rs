//! Port of `packages/cli/src/commands/readiness.ts` — HOR-97 release readiness summary.
//!
//! Blocking checks (DB reachability, CLI binary) gate a non-zero exit; optional checks
//! (source intelligence, local config, connectors, indexed repo) only limit investigation
//! depth. Does not start services, run investigations, or probe live external connectors.

use std::path::Path;

use anyhow::Result;
use horus_ai::InterpretationPromptKind;
use horus_core::{discover_local_config, load_config, HORUS_VERSION, PINNED_SOURCE_VERSION};
use horus_db::check_embedded_db;
use serde::Serialize;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use crate::lib::format::{bold, dim, green, red, yellow};
use crate::lib::freshness::{read_index_meta, semantic_search_ready};

pub const READINESS_AI_CONTRACT: &str = "Provide a clearly separated AI readiness summary with:

Overall assessment
- Release/demo readiness in plain language (Ready / Partially ready / Not ready)
- One sentence explaining why

Blockers
- Each failing blocking check and what it means operationally
- Only reference checks that Horus found failing

Risks
- Non-blocking warnings that could limit investigation depth or demo quality
- Prioritize by likely impact

Recommended next action
- The single most impactful step to take right now
- Exact command or config change based on the checks above

Confidence / gaps
- Which checks Horus could verify vs. which require manual confirmation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
}

/// Field order mirrors the TS object literals (`label, status, blocking, detail, next?`).
#[derive(Debug, Clone, Serialize)]
struct Check {
    label: String,
    status: Status,
    /// true = must pass for release/demo; false = optional.
    blocking: bool,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,
}

fn check(label: &str, status: Status, blocking: bool, detail: impl Into<String>, next: Option<&str>) -> Check {
    Check { label: label.into(), status, blocking, detail: detail.into(), next: next.map(str::to_string) }
}

fn mark(s: Status) -> String {
    match s {
        Status::Pass => green("✓"),
        Status::Warn => yellow("~"),
        Status::Fail => red("✗"),
    }
}

pub async fn run(args: &ReadinessArgs) -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut checks: Vec<Check> = Vec::new();

    // ── CLI binary — always passes if the process is running ──
    checks.push(check("CLI", Status::Pass, true, format!("horus {HORUS_VERSION}"), None));

    // ── Global config (connector checks) ──
    let global_config = load_config(args.config.as_deref().map(Path::new), Some(&cwd)).ok();

    // ── Database (embedded local store) — BLOCKING ──
    let db = check_embedded_db().await;
    checks.push(if db.reachable {
        check("Database", Status::Pass, true, db.reachable_detail.clone(), None)
    } else {
        check("Database", Status::Fail, true, db.reachable_detail.clone(), Some("install via npm or Homebrew for local persistence"))
    });

    // ── Local config (.horus/config.json) — OPTIONAL ──
    checks.push(match discover_local_config(&cwd) {
        Some(p) => check("Local config", Status::Pass, false, p.display().to_string(), None),
        None => check(
            "Local config",
            Status::Warn,
            false,
            ".horus/config.json not found",
            Some("run `horus init` to create one for this repo"),
        ),
    });

    // ── Source-intelligence backend — OPTIONAL ──
    checks.push(match horus_connectors::source::get_source_version().await {
        None => check(
            "Source intelligence",
            Status::Warn,
            false,
            "not installed — source intelligence unavailable",
            Some("curl -fsSL https://horus.sh/install.sh | bash"),
        ),
        Some(v) if v != PINNED_SOURCE_VERSION => check(
            "Source intelligence",
            Status::Warn,
            false,
            format!("version mismatch (installed: {v}, required: {PINNED_SOURCE_VERSION})"),
            Some("horus update"),
        ),
        Some(v) => check("Source intelligence", Status::Pass, false, format!("{v} — ready"), None),
    });

    // ── Semantic search (index embeddings) — OPTIONAL (HOR-373/375) ──
    let index_meta = read_index_meta(&cwd);
    if let Some(meta) = &index_meta {
        checks.push(if semantic_search_ready(Some(meta)) {
            let n = meta.stats.as_ref().and_then(|s| s.get("embeddings")).copied().unwrap_or(0.0);
            check("Semantic search", Status::Pass, false, format!("{} embeddings", horus_engine::js::number_string(n)), None)
        } else {
            check(
                "Semantic search",
                Status::Warn,
                false,
                "index has 0 embeddings — running keyword/FTS only",
                Some("horus init   # rebuilds embeddings (a prior index was interrupted)"),
            )
        });
    }

    // ── Connector config (from global config) — OPTIONAL ──
    match &global_config {
        None => checks.push(check(
            "Global config",
            Status::Warn,
            false,
            "horus.config.js not found — connector and repo checks skipped",
            Some("run `horus init` in the repo to set it up"),
        )),
        Some(cfg) => {
            let any_repo = cfg.projects.iter().flat_map(|p| &p.repositories).any(|r| r.source.as_ref().is_some_and(|s| !s.host_url.is_empty()));
            let envs: Vec<_> = cfg.projects.iter().flat_map(|p| &p.environments).map(|e| &e.connectors).collect();
            let any = |f: fn(&horus_core::ConnectorsConfig) -> bool| envs.iter().any(|c| f(c));

            checks.push(if any_repo {
                check("Source host", Status::Pass, false, "configured", None)
            } else {
                check(
                    "Source host",
                    Status::Warn,
                    false,
                    "no source host URL in any project",
                    Some("set source.hostUrl in horus.config.js for this repository"),
                )
            });

            let rows: [(&str, bool, &str, &str); 8] = [
                ("Elasticsearch", any(|c| c.elasticsearch.is_some()), "not configured — no runtime log evidence", "run `horus connect elasticsearch`"),
                ("Grafana", any(|c| c.grafana.is_some()), "not configured — no metric evidence", "run `horus connect grafana`"),
                ("MongoDB", any(|c| c.mongodb.is_some()), "not configured — no database state evidence", "run `horus connect mongodb`"),
                ("Postgres", any(|c| c.postgres.is_some()), "not configured — no database state evidence", "run `horus connect postgres`"),
                ("Sentry", any(|c| c.sentry.is_some()), "not configured — no error-tracking evidence", "run `horus connect sentry`"),
                ("Axiom", any(|c| c.axiom.is_some()), "not configured — no runtime log evidence", "run `horus connect axiom`"),
                ("Shopify", any(|c| c.shopify.is_some()), "not configured — no Shopify Admin state evidence", "run `horus connect shopify`"),
                ("Redis", any(|c| c.redis.is_some()), "not configured — no queue state evidence", "run `horus connect redis`"),
            ];
            for (label, configured, detail, next) in rows {
                checks.push(if configured {
                    check(label, Status::Pass, false, "configured", None)
                } else {
                    check(label, Status::Warn, false, detail, Some(next))
                });
            }
        }
    }

    // ── Render ──
    let (blocking, optional): (Vec<&Check>, Vec<&Check>) = checks.iter().partition(|c| c.blocking);

    println!("{}", bold("\nHorus release readiness\n"));
    let print_group = |title: &str, group: &[&Check]| {
        println!("{}", bold(&format!("  {title}")));
        for c in group {
            println!("    {} {}  {}", mark(c.status), bold(&format!("{:<22}", c.label)), dim(&c.detail));
            if let Some(next) = &c.next {
                println!("      {}", dim(&format!("→ {next}")));
            }
        }
    };
    print_group("Blocking", &blocking);
    println!();
    print_group("Optional", &optional);
    println!();

    let blocking_fails = blocking.iter().filter(|c| c.status == Status::Fail).count();
    let optional_warns = optional.iter().filter(|c| c.status == Status::Warn).count();
    if blocking_fails == 0 {
        if optional_warns == 0 {
            println!("{}", green("  Ready for demo/release."));
        } else {
            println!(
                "{}",
                yellow(&format!(
                    "  Ready for a basic demo. {optional_warns} optional item(s) not configured — investigation evidence will be limited."
                ))
            );
        }
    } else {
        println!("{}", red(&format!("  Not ready. {blocking_fails} blocking item(s) must be resolved before demo/release.")));
        println!("{}", dim("  Re-run `horus readiness` after resolving the items above."));
    }
    println!();

    if args.ai {
        print_ai_interpretation(AiInterpretationOpts {
            command: "readiness",
            evidence: serde_json::to_value(&checks)?,
            prompt_kind: InterpretationPromptKind::Readiness,
            output_contract: READINESS_AI_CONTRACT,
            user_intent: None,
            config: args.config.as_deref(),
            model_override: args.ai_model.as_deref(),
        })
        .await;
    }

    if blocking_fails > 0 {
        return Err(SilentExit(1).into());
    }
    Ok(())
}
