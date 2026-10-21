//! Port of `packages/cli/src/commands/explain.ts`.

use anyhow::Result;
use horus_core::{Flow, HorusConfig, ImpactResult, Symbol, SymbolContext};
use horus_engine::code_provider::{CodeProvider, Provider};
use horus_engine::render::symbol_display_name;
use horus_engine::router::{format_route_step, route, RouterCommand, RouterConditions};
use horus_engine::seeds::{resolve_seed_symbol, ResolutionKind, SeedResolveOptions};
use horus_engine::types::RouteStep;
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::capability_hint::print_capability_hint;
use crate::lib::engine_code::fail;
use crate::lib::engine_code::{code_for_repo, load_config, resolve_env};
use crate::lib::format::{bold, dim, red, yellow};

/// Print the router's suggestions as human "Suggested next:" lines (HOR-386).
fn print_suggested(steps: &[RouteStep]) {
    for s in steps {
        println!("{}{}", dim("  Suggested next: "), format_route_step(s));
    }
}

fn js(v: &impl serde::Serialize) -> String {
    horus_core::json::to_js_json_pretty(v).unwrap_or_default()
}

pub async fn run(args: &ExplainArgs) -> Result<()> {
    // Shared machine-JSON failure contract: a no-config/host failure yields the clean one-liner
    // on stderr and, under --json, one parseable object on stdout.
    explain(args).await.map_err(|e| fail(e, args.json))
}

async fn explain(args: &ExplainArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    let code = code_for_repo(&config, args.repo.as_deref())?;
    let query = args.query.as_str();

    if !code.health().await.ok {
        let steps = route(&RouterConditions { host_unreachable: true, ..RouterConditions::new(RouterCommand::Explain) });
        if args.json {
            println!("{}", js(&json!({ "error": "Source-intelligence host unreachable", "nextSteps": steps })));
        } else {
            eprintln!("{}", red("Source-intelligence host unreachable — run: horus init"));
            print_suggested(&steps);
        }
        return Err(SilentExit(1).into());
    }

    // THE canonical resolver (shared with search/blast-radius/investigate). SAME pool size as
    // blast-radius — differing pools made commands disagree. `--full` lifts the test demotion.
    let resolution = resolve_seed_symbol(&code, query, SeedResolveOptions { limit: Some(20), include_tests: Some(args.full) }).await?;
    let symbols = &resolution.candidates;
    let Some(top) = symbols.first() else {
        if is_queue_boundary(&config, query).await {
            println!("No symbol found for: {}", bold(query));
            println!("{}{}", dim(&format!("  \"{query}\" matches an async boundary — try: ")), bold(&format!("horus queues {query}")));
            return Err(SilentExit(1).into());
        }
        let steps = route(&RouterConditions { empty: true, query: Some(query.to_string()), ..RouterConditions::new(RouterCommand::Explain) });
        if args.json {
            println!("{}", js(&json!({ "symbol": null, "nextSteps": steps })));
        } else {
            println!("No symbol found for: {query}");
            println!("{}", dim("  Tip: use an exact class or function name, e.g. \"MyService\" or \"processOrder\""));
            print_suggested(&steps);
        }
        return Err(SilentExit(1).into());
    };

    // Exact includes qualified forms: `Reply.hijack` → Reply's hijack method is exact.
    let is_exact = matches!(resolution.kind, ResolutionKind::Exact | ResolutionKind::ExactQualified);
    let mut fuzzy_notice: Option<String> = None;
    if !is_exact {
        if is_queue_boundary(&config, query).await {
            if args.json {
                println!("{}", js(&json!({ "symbol": null, "queueBoundary": query })));
            } else {
                println!("No exact symbol match for: {}", bold(query));
                println!("{}{}", dim(&format!("  \"{query}\" matches an async boundary — try: ")), bold(&format!("horus queues {query}")));
            }
            return Err(SilentExit(1).into());
        }
        let notice = format!("No exact match for \"{query}\" — showing closest: \"{}\" (fuzzy match)", top.name);
        // stdout must be VALID JSON in --json mode — the notice becomes a structured field.
        if !args.json {
            println!("{}", yellow(&format!("  {notice}")));
        }
        fuzzy_notice = Some(notice);
    }
    let top_lower = top.name.to_lowercase();
    if resolution.ambiguous && !args.json {
        let n = resolution.candidates.iter().filter(|s| s.name.to_lowercase() == top_lower).count();
        println!(
            "{}",
            dim(&format!("  {n} equally-plausible matches — disambiguate with \"Class.{}\" or \"path/to/file:{}\"", top.name, top.name))
        );
    }

    // Disclose same-named collisions so the user can re-query another. A constructor named like
    // its class is not a "duplicate" (className == name, or the `...:Name.Name` id shape).
    let siblings: Vec<&Symbol> = symbols
        .iter()
        .filter(|s| {
            s.name.to_lowercase() == top_lower
                && s.id != top.id
                && s.class_name.as_deref() != Some(s.name.as_str())
                && !s.id.ends_with(&format!(":{}.{}", s.name, s.name))
        })
        .collect();

    // `--full` also lifts the product-only default: full output includes test callers.
    let include_tests = args.full.then_some(true);
    let depth = args.depth.map(|d| d as usize).unwrap_or(3);
    let (ctx, impact, flows) = tokio::try_join!(
        code.context(&top.id),
        code.impact(&top.id, Some(depth), include_tests),
        code.flows_for(&top.id, include_tests),
    )?;

    if args.json {
        let steps = route(&RouterConditions {
            seed_name: Some(top.name.clone()),
            query: Some(query.to_string()),
            ..RouterConditions::new(RouterCommand::Explain)
        });
        println!("{}", js(&explain_json(args.full, &ctx, &impact, &flows, &resolution, &siblings, fuzzy_notice.as_deref(), &steps)?));
        return Ok(());
    }

    render_report(top, &ctx, &impact, &flows, &siblings);
    // D6: nudge a reindex for a class/interface seed against a pre-inheritance index.
    print_capability_hint(Some(&top.id), args.json);
    Ok(())
}

/// Compact by default (dogfood: `explain Client --json` was enormous); `--full` restores all.
fn explain_json(
    full: bool,
    ctx: &SymbolContext,
    impact: &ImpactResult,
    flows: &[Flow],
    resolution: &horus_engine::seeds::SymbolResolution,
    siblings: &[&Symbol],
    fuzzy_notice: Option<&str>,
    next_steps: &[RouteStep],
) -> Result<Value> {
    let strip = |sym: &Symbol| -> Result<Value> {
        let mut v = horus_core::json::to_js_value(sym)?;
        if !full {
            if let Value::Object(m) = &mut v {
                for k in ["snippet", "sourceBody", "content"] {
                    m.shift_remove(k);
                }
            }
        }
        Ok(v)
    };
    let cap = |n: usize, len: usize| if full { len } else { n.min(len) };

    let impact_out = if full {
        horus_core::json::to_js_value(impact)?
    } else {
        let mut v = horus_core::json::to_js_value(impact)?;
        if let Some(Value::Array(depths)) = v.get_mut("byDepth") {
            for d in depths.iter_mut() {
                if let Some(Value::Array(syms)) = d.get_mut("symbols") {
                    let over = syms.len() > 25;
                    syms.truncate(25);
                    if over {
                        if let Value::Object(m) = d {
                            m.insert("truncated".into(), json!(true));
                        }
                    }
                }
            }
        }
        v
    };

    let mut out = Map::new();
    out.insert("symbol".into(), strip(&ctx.symbol)?);
    out.insert("resolution".into(), serde_json::to_value(resolution.kind)?);
    if resolution.ambiguous {
        out.insert("ambiguous".into(), json!(true));
    }
    if !siblings.is_empty() {
        let alts: Vec<Value> = siblings
            .iter()
            .take(10)
            .map(|s| {
                let mut m = Map::new();
                m.insert("name".into(), json!(s.name));
                m.insert("filePath".into(), json!(s.file_path));
                if let Some(c) = &s.class_name {
                    m.insert("className".into(), json!(c));
                }
                if let Some(l) = s.start_line {
                    m.insert("startLine".into(), json!(l));
                }
                Value::Object(m)
            })
            .collect();
        out.insert("alternatives".into(), Value::Array(alts));
        if siblings.len() > 10 {
            out.insert("alternativesTruncatedCount".into(), json!(siblings.len() - 10));
        }
    }
    if let Some(n) = fuzzy_notice {
        out.insert("notice".into(), json!(n));
    }
    out.insert("community".into(), serde_json::to_value(&ctx.community)?);
    if let Some(d) = ctx.is_dead {
        out.insert("isDead".into(), json!(d));
    }
    let callers: Result<Vec<Value>> = ctx.callers.iter().take(cap(20, ctx.callers.len())).map(&strip).collect();
    let callees: Result<Vec<Value>> = ctx.callees.iter().take(cap(20, ctx.callees.len())).map(&strip).collect();
    out.insert("callers".into(), Value::Array(callers?));
    out.insert("callees".into(), Value::Array(callees?));
    if !full && (ctx.callers.len() > 20 || ctx.callees.len() > 20) {
        out.insert("truncated".into(), json!("callers/callees capped at 20 — re-run with --full"));
    }
    out.insert("impact".into(), impact_out);
    out.insert("flows".into(), horus_core::json::to_js_value(&flows[..cap(10, flows.len())])?);
    // HOR-386 — structured next-steps from the SAME router; empty on the happy path.
    out.insert("nextSteps".into(), serde_json::to_value(next_steps)?);
    Ok(Value::Object(out))
}

async fn is_queue_boundary(config: &HorusConfig, query: &str) -> bool {
    // Scope to the active project so a same-named queue in another project doesn't produce a
    // false positive (HOR-207).
    let project = resolve_env(config, None).ok().map(|r| r.project);
    let Ok(db) = horus_db::open_db().await else { return false };
    let found = horus_db::list_queue_edges(&db, project.as_deref(), Some(query)).await.map(|e| !e.is_empty()).unwrap_or(false);
    db.end().await;
    found
}

fn render_report(top: &Symbol, ctx: &SymbolContext, impact: &ImpactResult, flows: &[Flow], siblings: &[&Symbol]) {
    let kind = match top.id.find(':') {
        Some(i) => &top.id[..i],
        None => top.id.as_str(),
    };

    let sym = &ctx.symbol;
    let mut location = sym.file_path.clone();
    if let Some(s) = sym.start_line.filter(|s| *s != 0) {
        location.push_str(&format!(":{s}"));
        if let Some(e) = sym.end_line.filter(|e| *e != 0) {
            location.push_str(&format!("-{e}"));
        }
    }

    let community = ctx.community.as_ref().map(|c| c.name.clone()).unwrap_or_else(|| dim("—"));

    let format_names = |list: &[Symbol]| -> String {
        // Qualify class members (e.g. constructor) with their owning class (HOR-214).
        let names: Vec<String> = list.iter().map(symbol_display_name).collect();
        if names.len() <= 10 {
            return names.join(", ");
        }
        format!("{} +{} more", names[..10].join(", "), names.len() - 10)
    };
    let caller_str = if ctx.callers.is_empty() { dim("none") } else { format_names(&ctx.callers) };
    let callee_str = if ctx.callees.is_empty() { dim("none") } else { format_names(&ctx.callees) };

    let all_impacted: Vec<&Symbol> = impact.by_depth.iter().flat_map(|d| d.symbols.iter()).collect();
    let impact_names = all_impacted.iter().take(8).map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ");
    let impact_suffix = if all_impacted.len() > 8 { format!(" +{} more", all_impacted.len() - 8) } else { String::new() };

    println!();
    println!("  {}       {}  {}", bold("Symbol:"), top.name, dim(&format!("(kind = {kind})")));
    if !siblings.is_empty() {
        let others = siblings.iter().map(|s| s.file_path.as_str()).collect::<Vec<_>>().join(", ");
        println!(
            "{}",
            dim(&format!("                {} symbols named '{}'; showing this one — others: {others}", siblings.len() + 1, top.name))
        );
    }
    println!("  {}     {location}", bold("Location:"));
    println!("  {}    {community}", bold("Community:"));
    println!("  {}  {caller_str}", bold(&format!("Callers ({}):", ctx.callers.len())));
    println!("  {}  {callee_str}", bold(&format!("Callees ({}):", ctx.callees.len())));
    let impact_tail = if impact_names.is_empty() { String::new() } else { format!("  {}", dim(&format!("{impact_names}{impact_suffix}"))) };
    println!("  {}       {} symbols affected{impact_tail}", bold("Impact:"), impact.affected);

    println!("  {}", bold("Related flows:"));
    if flows.is_empty() {
        println!("    {}", dim("none"));
    } else {
        for flow in flows {
            println!("    {}  {}", flow.name, dim(&format!("({} steps)", flow.steps.len())));
        }
    }

    if ctx.is_dead == Some(true) {
        println!("  {}    {}", bold("Dead code:"), red("yes"));
    }

    println!();
}
