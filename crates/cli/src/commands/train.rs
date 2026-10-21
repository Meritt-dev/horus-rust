//! `horus train` (HOR-404 / HOR-442) — fit the LOCAL, per-tenant reranker over the outcome-label
//! corpus. Port of `packages/cli/src/commands/train.ts`.
//!
//! LOCAL and per-tenant: the corpus never leaves the client; the model is a few kB of logistic
//! weights in `~/.horus/reranker.json`. Honesty-gated: refuses below MIN_TRAIN_INVESTIGATIONS and
//! only writes a model that BEATS the hand-tuned baseline on the deterministic holdout. Read-only
//! on the label store.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;
use horus_core::load_config;
use horus_db::{dedupe_to_current_verdict, get_investigation, is_outcome_resolved, is_outcome_source, list_outcome_labels, open_db};
use horus_engine::js::to_fixed;
use horus_eval::{holdout_split, train_reranker, RankableCause, RerankInvestigation, RerankTrainResult, TrainOptions, MIN_TRAIN_INVESTIGATIONS};
use serde_json::Value;

use crate::cli::*;
use crate::commands::eval::read_slice;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red, yellow};

/// Where the local, per-tenant model lives (loaded by `horus investigate` when enabled).
pub fn reranker_model_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".horus").join("reranker.json")
}

/// The full ranked candidate set off a stored report blob, or None if missing/legacy.
fn candidates_from_report(blob: &Value) -> Option<Vec<RankableCause>> {
    serde_json::from_value(blob.get("suspectedCauses")?.clone()).ok()
}

fn pct(n: f64) -> String {
    format!("{}%", to_fixed(n * 100.0, 1))
}

pub async fn run(args: &TrainArgs) -> Result<()> {
    let query = read_slice(&args.source, args.days, args.limit)?;

    let corpus: Result<Vec<RerankInvestigation>> = async {
        let _config = load_config(args.config.as_deref().map(Path::new), None)?;
        let db = open_db().await?;
        let inner = async {
            // All local labels (no project filter) — a per-tenant reranker trains on the whole corpus.
            let labels = list_outcome_labels(&db, query).await?;
            let mut out = Vec::new();
            for label in dedupe_to_current_verdict(&labels) {
                let Some(id) = label.investigation_id.clone() else { continue };
                if !is_outcome_resolved(&label.resolved) || !is_outcome_source(&label.source) {
                    continue;
                }
                let report: Value = get_investigation(&db, &id)
                    .await?
                    .and_then(|r| r.report)
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Null);
                let Some(candidates) = candidates_from_report(&report) else { continue };
                // confirm's confirmedCause is Horus's own summary (circular) — drop it, like the corpus.
                let confirmed_cause = if label.source == "confirm" { None } else { label.confirmed_cause.clone() };
                out.push(RerankInvestigation { investigation_id: id, target: label.resolved.clone(), confirmed_cause, candidates });
            }
            anyhow::Ok(out)
        }
        .await;
        db.end().await;
        inner
    }
    .await;
    let investigations = match corpus {
        Ok(c) => c,
        Err(err) => {
            eprintln!("{}", red(&format!("Could not read the local corpus: {err}")));
            return Err(SilentExit(1).into());
        }
    };

    let split = holdout_split(investigations.iter().map(|i| i.investigation_id.as_str()), None);
    let holdout: HashSet<String> = split.holdout.into_iter().collect();
    let model = match train_reranker(&investigations, &holdout, TrainOptions::default()) {
        RerankTrainResult::Ok(m) => m,
        RerankTrainResult::Skip(skip) => {
            if skip.reason == "insufficient-corpus" {
                println!(
                    "{}",
                    yellow(&format!(
                        "Not enough labeled investigations to train yet (have {} with a known-correct cause; need ≥{MIN_TRAIN_INVESTIGATIONS}).",
                        skip.labeled_investigations
                    ))
                );
                println!("{}", dim("  Keep labeling outcomes with `horus feedback` — the reranker trains once the corpus is large enough."));
            } else {
                println!("{}", yellow(&format!("Cannot train a meaningful model yet: {}.", skip.detail)));
            }
            return Ok(());
        }
    };

    let h = &model.holdout;
    println!("{}", bold("\nReranker training (local, per-tenant)\n"));
    println!("  Holdout investigations:  {}", h.n);
    println!("  Baseline top-1 hit-rate: {}", pct(h.baseline_hit_rate));
    println!("  Reranked top-1 hit-rate: {}", pct(h.reranked_hit_rate));
    println!("  Delta:                   {}{}", if h.delta >= 0.0 { "+" } else { "" }, pct(h.delta));
    println!();

    if h.delta <= 0.0 {
        println!("{}", yellow("  The reranker did NOT beat the deterministic baseline — not saving a model."));
        println!("{}", dim("  Horus stays on its hand-tuned ranking. Re-run as more labels accumulate."));
        return Ok(());
    }

    let path = reranker_model_path();
    let written = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|_| std::fs::write(&path, horus_core::json::to_js_json_pretty(&model).unwrap_or_default() + "\n"));
    if let Err(err) = written {
        eprintln!("{}", red(&format!("Trained, but could not write the model: {err}")));
        return Err(SilentExit(1).into());
    }
    println!("{}", green(&format!("  ✓ Reranker beats baseline by +{} — saved to {}", pct(h.delta), path.display())));
    println!("{}", dim("  It ships OFF by default. Enable it with `HORUS_RERANK=1 horus investigate …`."));
    Ok(())
}
