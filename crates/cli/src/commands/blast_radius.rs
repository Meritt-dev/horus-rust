//! Port of `packages/cli/src/commands/blast-radius.ts`.

use anyhow::Result;
use horus_engine::blast_radius::{analyze_blast_radius, BlastRadiusDeps};
use horus_engine::code_provider::Provider;
use horus_engine::render_blast_radius::render_blast_radius;
use horus_engine::router::{format_route_step, route, RouterCommand, RouterConditions};
use horus_engine::seeds::ResolutionKind;
use serde_json::{json, Value};

use crate::cli::*;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use horus_ai::InterpretationPromptKind;
use crate::commands::SilentExit;
use crate::lib::capability_hint::print_capability_hint;
use crate::lib::engine_code::fail;
use crate::lib::engine_code::{create_code, engine_edges, load_config, resolve_env};
use crate::lib::format::{dim, red, yellow};

/// Dim note shown when this build ships without local persistence.
const DB_UNAVAILABLE_NOTE: &str = "local persistence unavailable in this build — async queue-boundary enrichment skipped (install via npm or Homebrew for it)";

pub const BLAST_RADIUS_AI_CONTRACT: &str = "Provide a clearly separated AI interpretation section with:

Evidence used
- The matched component(s), upstream dependencies, downstream callers, and async boundaries Horus found

Likely impact
- What users or operators would notice if this component fails
- Which services/flows are inside the blast radius and at direct risk
- Which services/flows appear outside the blast radius

Containment ideas
- Safe mitigations grounded only in the dependencies Horus found
- Rollback or disable suggestions only when supported by the evidence (prefix with \"verify before doing this\")
- Async boundaries to isolate (queues, workers, cron jobs, webhooks, external APIs)

Confidence
- High / Medium / Low with a one-line reason

Next checks
- Exact Horus commands or files to inspect next";

fn js(v: &impl serde::Serialize) -> String {
    horus_core::json::to_js_json_pretty(v).unwrap_or_default()
}

pub async fn run(args: &BlastRadiusArgs) -> Result<()> {
    run_inner(args).await.map_err(|e| fail(e, args.json))
}

async fn run_inner(args: &BlastRadiusArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    let code = create_code(&config)?;

    if !code.health().await.ok {
        // HOR-386 — host down: the router points at `horus init`.
        let steps = route(&RouterConditions { host_unreachable: true, ..RouterConditions::new(RouterCommand::BlastRadius) });
        if args.json {
            println!("{}", js(&json!({ "error": "Source-intelligence host unreachable", "nextSteps": steps })));
        } else {
            eprintln!("{}", red("Source-intelligence host unreachable — run: horus init"));
            for s in &steps {
                println!("{}{}", dim("  Suggested next: "), format_route_step(s));
            }
        }
        return Err(SilentExit(1).into());
    }

    let project = resolve_env(&config, None).ok().map(|r| r.project);

    // The db-unavailable case degrades to no async boundaries; any other db error surfaces.
    let db = horus_db::open_db().await?;
    let edges = match horus_db::list_queue_edges(&db, project.as_deref(), None).await {
        Ok(rows) => Some(engine_edges(rows)),
        Err(e) if horus_db::is_db_unavailable(&e) => None,
        Err(e) => {
            db.end().await;
            return Err(e);
        }
    };
    db.end().await;

    let depth = args.depth.map(|d| d as usize).unwrap_or(3);
    let Some(r) = analyze_blast_radius(&args.query, BlastRadiusDeps { code: &code, queue_edges: edges, project }, Some(depth), args.include_tests).await?
    else {
        // HOR-386 — no symbol matched: the router points at `horus search <query>`.
        let steps = route(&RouterConditions {
            empty: true,
            query: Some(args.query.clone()),
            ..RouterConditions::new(RouterCommand::BlastRadius)
        });
        if args.json {
            println!("{}", js(&json!({ "symbol": null, "nextSteps": steps })));
        } else {
            println!("No symbol found for: {}", args.query);
            println!("{}", dim("  Tip: use an exact class or function name, e.g. \"MyService\""));
            for s in &steps {
                println!("{}{}", dim("  Suggested next: "), format_route_step(s));
            }
        }
        return Err(SilentExit(1).into());
    };

    // The shared resolver's verdict, not a raw name comparison — an exact QUALIFIED match is
    // never reported as fuzzy.
    let fuzzy_notice = (r.resolution == ResolutionKind::Fuzzy)
        .then(|| format!("No exact match for \"{}\" — showing closest: \"{}\" (fuzzy match)", args.query, r.seed.name));
    let ambiguity_notice = (r.ambiguous && !r.alternatives.is_empty()).then(|| {
        format!(
            "{} equally-plausible matches for \"{}\" — disambiguate with \"Class.{}\" or \"path/to/file:{}\" (others: {})",
            r.alternatives.len() + 1,
            args.query,
            r.seed.name,
            r.seed.name,
            r.alternatives.iter().map(|s| s.file_path.as_str()).collect::<Vec<_>>().join(", ")
        )
    });

    if args.json {
        // stdout stays VALID JSON — the notices are structured fields.
        let mut obj = horus_core::json::to_js_value(&r)?;
        if let Value::Object(map) = &mut obj {
            if let Some(n) = &fuzzy_notice {
                map.insert("notice".into(), json!(n));
            }
            if let Some(n) = &ambiguity_notice {
                map.insert("ambiguityNotice".into(), json!(n));
            }
            if r.db_unavailable {
                map.insert("dbUnavailableNote".into(), json!(DB_UNAVAILABLE_NOTE));
            }
            // HOR-386 — the SAME router's structured next-steps; empty on the happy path.
            let steps = route(&RouterConditions {
                seed_name: Some(r.seed.name.clone()),
                query: Some(args.query.clone()),
                ..RouterConditions::new(RouterCommand::BlastRadius)
            });
            map.insert("nextSteps".into(), serde_json::to_value(steps)?);
        }
        println!("{}", js(&obj));
        return Ok(());
    }

    if let Some(n) = &fuzzy_notice {
        println!("{}", yellow(&format!("  {n}")));
    }
    if let Some(n) = &ambiguity_notice {
        println!("{}", dim(&format!("  {n}")));
    }
    println!("{}", render_blast_radius(&r));
    if r.db_unavailable {
        println!("{}", dim(&format!("  {DB_UNAVAILABLE_NOTE}")));
    }
    // D6: a class/interface seed against a pre-inheritance-traversal index — nudge a reindex.
    print_capability_hint(Some(&r.seed.id), args.json);
    if args.ai {
        print_ai_interpretation(AiInterpretationOpts {
            command: "blast-radius",
            user_intent: Some(format!("query: {}", args.query)),
            evidence: horus_core::json::to_js_value(&r)?,
            prompt_kind: InterpretationPromptKind::BlastRadius,
            output_contract: BLAST_RADIUS_AI_CONTRACT,
            config: args.config.as_deref(),
            model_override: args.ai_model.as_deref(),
        })
        .await;
    }
    Ok(())
}
