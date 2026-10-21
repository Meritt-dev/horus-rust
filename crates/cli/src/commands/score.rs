//! Port of `packages/cli/src/commands/score.ts`.

use anyhow::Result;
use horus_ai::InterpretationPromptKind;
use horus_db::{get_investigation, list_investigations_with_reports, open_db};
use horus_engine::migrate_report::migrate_report;
use horus_engine::render_score::{render_score, score_to_json};
use horus_engine::score::score_investigation;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use crate::lib::engine_code::{load_config, resolve_env};
use crate::lib::format::{format_date_time, red};

pub const SCORE_AI_CONTRACT: &str = "Provide a clearly separated AI score explanation with:

Why this scored this way
- Explain each weak dimension (low value, low weight contribution)
- Ground each explanation in what Horus found or failed to find

Biggest improvement lever
- The single dimension where better evidence would move the score most
- Exact investigation step or command to gather that evidence

Suggested improvements
- Specific ideas for how Horus could gather better evidence next time
- Be concrete: what connector, query, or signal is missing";

/// JS `Math.round` (half rounds up, toward +∞).
fn js_round(x: f64) -> f64 {
    (x + 0.5).floor()
}

pub async fn run(args: &ScoreArgs) -> Result<()> {
    let db = open_db().await?;
    let row = get_investigation(&db, &args.id).await;
    db.end().await;
    let Some(row) = row? else {
        eprintln!("{}", red(&format!("No investigation found: {}", args.id)));
        return Err(SilentExit(1).into());
    };
    let Some(report) = row.report else {
        eprintln!("{}", red(&format!("Investigation {} has no stored report.", args.id)));
        return Err(SilentExit(1).into());
    };
    let s = score_investigation(&migrate_report(serde_json::from_str(&report)?)?);

    if args.json {
        println!("{}", score_to_json(&s));
    } else {
        println!("{}", render_score(&s));
        if args.ai {
            print_ai_interpretation(AiInterpretationOpts {
                command: "score",
                evidence: horus_core::json::to_js_value(&s)?,
                prompt_kind: InterpretationPromptKind::EvidenceSummary,
                output_contract: SCORE_AI_CONTRACT,
                user_intent: Some(format!("investigation: {}", args.id)),
                config: args.config.as_deref(),
                model_override: args.ai_model.as_deref(),
            })
            .await;
        }
    }
    Ok(())
}

struct Scored {
    id: String,
    title: String,
    created_at: chrono::DateTime<chrono::Utc>,
    score: f64,
}

pub async fn run_scores(args: &ScoresArgs) -> Result<()> {
    let json = args.json;
    // Score THIS project's investigations only (dogfood N1 — shared-DB isolation).
    let project = load_config(&args.config).ok().and_then(|c| resolve_env(&c, None).ok()).map(|r| r.project);
    let scored: Result<Vec<Scored>> = async {
        let db = open_db().await?;
        let rows = list_investigations_with_reports(&db, i64::from(args.limit.unwrap_or(15)), project.as_deref()).await;
        db.end().await;
        let mut out = Vec::new();
        for r in rows? {
            let Some(report) = r.report else { continue };
            let score = score_investigation(&migrate_report(serde_json::from_str(&report)?)?).score;
            out.push(Scored { id: r.id, title: r.title, created_at: r.created_at, score });
        }
        Ok(out)
    }
    .await;
    let scored = match scored {
        Ok(s) => s,
        Err(err) => {
            // stdout must stay VALID JSON under --json; the human message goes to stderr.
            if json {
                let v = serde_json::json!({ "error": err.to_string(), "scores": [], "count": 0 });
                println!("{}", horus_core::json::to_js_json_pretty(&v)?);
            }
            eprintln!("{}", red(&err.to_string()));
            return Err(SilentExit(1).into());
        }
    };

    let avg = || js_round(scored.iter().map(|s| s.score).sum::<f64>() / scored.len() as f64);
    if json {
        let scores: Vec<_> = scored
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "createdAt": horus_db::format_ts(&s.created_at),
                    "score": s.score,
                    "title": s.title,
                })
            })
            .collect();
        let average = if scored.is_empty() { serde_json::Value::Null } else { serde_json::json!(avg()) };
        let v = serde_json::json!({ "scores": scores, "count": scored.len(), "average": average });
        println!("{}", horus_core::json::to_js_json_pretty(&v)?);
        return Ok(());
    }

    if scored.is_empty() {
        println!("No scored investigations yet.");
        return Ok(());
    }
    for s in &scored {
        println!(
            "  {:>3}/100  {}  {}  {}",
            horus_engine::js::number_string(s.score),
            format_date_time(&s.created_at),
            s.id,
            s.title
        );
    }
    println!("  avg {}/100 across {} investigation(s)", horus_engine::js::number_string(avg()), scored.len());
    Ok(())
}
