//! Port of `packages/cli/src/commands/state.ts` — `horus state`: application-STATE evidence from
//! MongoDB (HOR-33). Read-only, allowlisted collections only. Counts, staleness and anomalous
//! status distributions — never raw documents.

use std::path::Path;

use anyhow::Result;
use horus_ai::InterpretationPromptKind;
use horus_connectors::{mongo_for_env, AnalyzeStateOpts, Provider, StateProvider};
use horus_core::json::{to_js_json_pretty, to_js_value};
use horus_core::{load_config, resolve_environment, ResolveOptions};
use serde_json::{json, Map, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use crate::lib::format::{bold, dim, red, yellow};

pub const STATE_AI_CONTRACT: &str = "Provide a clearly separated AI evidence narration with:

Evidence used
- Exact collection names, document counts, staleness hours, and anomalous status values Horus found

What stands out
- Collections with stale records or anomalous status distributions
- Any counts that seem unusually low or high

What this may indicate
- Use \"may suggest\", \"is consistent with\", or \"could indicate\" — never \"proves\"
- Do not infer private data or claim access to document contents

What is not proven
- Claims that require reading actual document content or non-allowlisted collections

Next checks
- Exact Horus commands or database queries to inspect next";

fn fail(msg: &str) -> anyhow::Error {
    eprintln!("{}", red(msg));
    SilentExit(1).into()
}

/// `s.padEnd(n).slice(0, n)` on chars.
fn pad_slice(s: &str, n: usize) -> String {
    format!("{s:<n$}").chars().take(n).collect()
}

pub async fn run(args: &StateArgs) -> Result<()> {
    match run_inner(args).await {
        Err(e) if e.downcast_ref::<SilentExit>().is_none() => Err(fail(&format!("{e:#}"))),
        other => other,
    }
}

async fn run_inner(args: &StateArgs) -> Result<()> {
    let config = load_config(args.config.as_deref().map(Path::new), None)?;
    let renv = resolve_environment(&config, &ResolveOptions { env: args.env.as_deref(), ..Default::default() })
        .map_err(|e| fail(&format!("{e:#}")))?;

    let Some(mongo) = mongo_for_env(&renv) else {
        return Err(fail(&format!(
            "No MongoDB connector configured for {}/{} (set the project's Mongo URL env var).",
            renv.project, renv.env
        )));
    };

    let health = mongo.health().await;
    if !health.ok {
        mongo.close().await;
        return Err(fail(&format!("MongoDB unreachable: {}", health.detail)));
    }

    let result = analyze_and_render(args, &renv, &mongo).await;
    mongo.close().await;
    result
}

async fn analyze_and_render(
    args: &StateArgs,
    renv: &horus_core::ResolvedEnvironment,
    mongo: &horus_connectors::MongoStateProvider,
) -> Result<()> {
    // `Number(opts.staleHours)`: a non-numeric value is NaN, passed through like TS.
    let stale_hours = args.stale_hours.as_deref().map(|s| s.trim().parse::<f64>().unwrap_or(f64::NAN));
    let analysis = mongo.analyze_state(AnalyzeStateOpts { stale_hours, legacy_hours: None }).await?;
    let auto = analysis.auto_discovered == Some(true);

    if args.json {
        let stale = analysis.collections.iter().filter(|c| c.is_stale == Some(true)).count();
        let anomalous: usize = analysis.collections.iter().map(|c| c.anomalies.len()).sum();
        let mut out = Map::new();
        out.insert("scope".into(), json!({ "project": renv.project, "env": renv.env, "database": analysis.database }));
        if let Some(a) = analysis.auto_discovered {
            out.insert("autoDiscovered".into(), json!(a));
        }
        out.insert("signals".into(), json!({ "stale": stale, "anomalous": anomalous }));
        out.insert("collections".into(), to_js_value(&analysis.collections)?);
        println!("{}", to_js_json_pretty(&Value::Object(out))?);
        return Ok(());
    }

    let discovery_note =
        if auto { dim(&format!(" ({} collections, auto-discovered)", analysis.collections.len())) } else { String::new() };
    println!(
        "{}{}{discovery_note}",
        bold("State analysis"),
        dim(&format!(" — {}/{} · db {}", renv.project, renv.env, analysis.database))
    );
    println!();

    let mut signals = 0usize;
    for c in &analysis.collections {
        let mut flags: Vec<String> = Vec::new();
        if c.is_stale == Some(true) {
            let age = horus_engine::js::int_string(horus_engine::js::math_round(c.age_hours.unwrap_or(0.0)));
            flags.push(yellow(&format!("stale (last {}, ~{age}h)", c.date_field.as_deref().unwrap_or("undefined"))));
        }
        for a in &c.anomalies {
            flags.push(red(&format!("{}× \"{}\"", a.count, a.value)));
            signals += 1;
        }
        if c.is_stale == Some(true) {
            signals += 1;
        }
        let head = format!("  {} {}", bold(&pad_slice(&c.collection, 18)), dim(&format!("{:>8} docs", c.count)));
        println!("{}", if flags.is_empty() { dim(&head) } else { format!("{head}   {}", flags.join("  ")) });
    }

    println!();
    if analysis.collections.is_empty() {
        println!(
            "{}{}",
            yellow("  No collections discovered in this database."),
            dim(" Verify the database name in your MongoDB connector config.")
        );
    } else {
        let scope = if auto { "collection(s)" } else { "allowlisted collection(s)" };
        let n = analysis.collections.len();
        if signals > 0 {
            println!("  {} state signal(s) across {n} {scope}", bold(&signals.to_string()));
        } else {
            println!("{}", dim(&format!("  No state anomalies across {n} {scope}.")));
        }
        if auto {
            println!("{}", dim("  Tip: add a \"collections\" list to your MongoDB connector config to restrict analysis."));
        }
    }

    if args.ai {
        print_ai_interpretation(AiInterpretationOpts {
            command: "state",
            evidence: to_js_value(&analysis)?,
            prompt_kind: InterpretationPromptKind::EvidenceSummary,
            output_contract: STATE_AI_CONTRACT,
            user_intent: None,
            config: args.config.as_deref(),
            model_override: args.ai_model.as_deref(),
        })
        .await;
    }
    Ok(())
}
