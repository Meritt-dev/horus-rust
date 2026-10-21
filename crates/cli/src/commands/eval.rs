//! `horus eval` — the read-only accuracy harness (HOR-403). Port of
//! `packages/cli/src/commands/eval.ts`.
//!
//! READ-ONLY INVARIANT: nothing here writes the outcome_label store — this only reads labels +
//! joins investigation reports and writes its OWN artifact files. Project-scoped, fail-closed
//! (HOR-46), same read flags as `horus memory accuracy` (--source/--days/--limit/--repo).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{Duration, Utc};
use horus_core::{load_config, resolve_environment, HorusConfig, ResolveOptions};
use horus_db::{get_investigation, is_outcome_source, list_outcome_labels, open_db, DbHandle, OutcomeLabelQuery};
use horus_eval::{build_corpus, compute_baseline, feature_separation, serialize_corpus, CORPUS_VERSION};
use horus_engine::js::to_fixed;
use serde_json::{json, Value};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, cyan, dim, green, red, yellow};

pub async fn run(args: &EvalArgs) -> Result<()> {
    let r = match &args.command {
        EvalCommand::Build(a) => run_eval_build(a).await,
        EvalCommand::Baseline(a) => run_eval_baseline(a).await,
    };
    match r {
        Err(err) if err.downcast_ref::<SilentExit>().is_none() => {
            eprintln!("{}", red(&err.to_string()));
            Err(SilentExit(1).into())
        }
        other => other,
    }
}

/// HOR-46 fail-closed project resolution — an unresolved project is a hard error.
fn resolve_project(config: &HorusConfig, repo: Option<&str>) -> Result<String> {
    match resolve_environment(config, &ResolveOptions { project: repo, ..Default::default() }) {
        Ok(r) if !r.project.is_empty() => Ok(r.project),
        _ => {
            eprintln!("{}", red("Could not resolve a project — pass --repo <name> or run inside a repo."));
            Err(SilentExit(1).into())
        }
    }
}

/// Validate + normalize the shared read flags (--source/--days/--limit).
pub(crate) fn read_slice(source: &Option<String>, days: Option<u32>, limit: Option<u32>) -> Result<OutcomeLabelQuery> {
    if let Some(s) = source {
        if !is_outcome_source(s) {
            eprintln!("{}", red(&format!("Unknown --source \"{s}\" (one of: feedback, confirm).")));
            return Err(SilentExit(1).into());
        }
    }
    if days == Some(0) {
        eprintln!("{}", red("--days must be a positive number."));
        return Err(SilentExit(1).into());
    }
    Ok(OutcomeLabelQuery {
        source: source.clone(),
        since: days.map(|d| Utc::now() - Duration::milliseconds(i64::from(d) * 24 * 60 * 60 * 1000)),
        limit: limit.map(i64::from),
        ..Default::default()
    })
}

/// Each distinct, non-null investigationId's stored report, fetched once; the resolver is then a
/// pure lookup so `build_corpus` stays deterministic.
pub(crate) async fn load_reports(db: &DbHandle, ids: impl Iterator<Item = Option<String>>) -> Result<HashMap<String, Value>> {
    let mut map = HashMap::new();
    for id in ids.flatten() {
        if map.contains_key(&id) {
            continue;
        }
        let report = get_investigation(db, &id).await?.and_then(|r| r.report).and_then(|s| serde_json::from_str(&s).ok());
        map.insert(id, report.unwrap_or(Value::Null));
    }
    Ok(map)
}

fn resolver(map: &HashMap<String, Value>) -> impl Fn(&str) -> Option<Value> + '_ {
    move |id| map.get(id).filter(|v| !v.is_null()).cloned()
}

/// `horus eval build` — emit the corpus + manifest (read-only).
pub async fn run_eval_build(args: &EvalBuildArgs) -> Result<()> {
    let mut query = read_slice(&args.source, args.days, args.limit)?;
    let config = load_config(args.config.as_deref().map(Path::new), None)?;
    let project = resolve_project(&config, args.repo.as_deref())?;
    let version = args.version.clone().unwrap_or_else(|| CORPUS_VERSION.to_string());
    let cwd = std::env::current_dir()?;
    let out_dir: PathBuf = match &args.out {
        Some(o) => cwd.join(o),
        None => cwd.join(".horus").join("eval"),
    };

    let db = open_db().await?;
    query.project = Some(project.clone());
    let loaded = async {
        let labels = list_outcome_labels(&db, query).await?;
        let reports = load_reports(&db, labels.iter().map(|l| l.investigation_id.clone())).await?;
        anyhow::Ok((labels, reports))
    }
    .await;
    db.end().await;
    let (labels, reports) = loaded?;
    let build = build_corpus(&labels, &resolver(&reports));
    let artifact = serialize_corpus(&build, Some(&version));

    std::fs::create_dir_all(&out_dir)?;
    let corpus_path = out_dir.join(&artifact.filename);
    let manifest_path = out_dir.join(format!("corpus-{version}.manifest.json"));
    // Stamp the manifest (NOT the deterministic jsonl) with a generation time on write.
    let mut manifest = horus_core::json::to_js_value(&artifact.manifest)?;
    manifest["generatedAt"] = json!(horus_db::format_ts(&Utc::now()));
    manifest["project"] = json!(project);
    std::fs::write(&corpus_path, &artifact.jsonl)?;
    std::fs::write(&manifest_path, horus_core::json::to_js_json_pretty(&manifest)? + "\n")?;

    if args.json {
        let out = json!({
            "project": project,
            "corpusPath": corpus_path.display().to_string(),
            "manifestPath": manifest_path.display().to_string(),
            "manifest": manifest,
        });
        println!("{}", horus_core::json::to_js_json_pretty(&out)?);
    } else {
        println!("{}", bold(&format!("Eval corpus — {project}")));
        println!(
            "  Rows: {} {}",
            green(&build.rows.len().to_string()),
            dim(&format!(
                "(evaluated {}, quarantined {}, unjoinable {})",
                build.evaluated,
                build.quarantined.len(),
                build.unjoinable.len()
            ))
        );
        println!(
            "{}",
            dim(&format!(
                "  Class balance: {} yes, {} partly, {} no · source: {} feedback, {} confirm",
                build.class_balance.yes,
                build.class_balance.partly,
                build.class_balance.no,
                build.by_source.feedback,
                build.by_source.confirm
            ))
        );
        println!("  Corpus:   {}", cyan(&corpus_path.display().to_string()));
        println!("  Manifest: {}", cyan(&manifest_path.display().to_string()));
    }
    Ok(())
}

/// `horus eval baseline` — baseline hit-rate + feature-separation diagnostic (read-only).
pub async fn run_eval_baseline(args: &EvalBaselineArgs) -> Result<()> {
    let mut query = read_slice(&args.source, args.days, args.limit)?;
    let config = load_config(args.config.as_deref().map(Path::new), None)?;
    let project = resolve_project(&config, args.repo.as_deref())?;

    let db = open_db().await?;
    query.project = Some(project.clone());
    let loaded = async {
        let labels = list_outcome_labels(&db, query).await?;
        let reports = load_reports(&db, labels.iter().map(|l| l.investigation_id.clone())).await?;
        anyhow::Ok((labels, reports))
    }
    .await;
    db.end().await;
    let (labels, reports) = loaded?;
    // Baseline math mirrors `horus memory accuracy` exactly (shared summarize).
    let baseline = compute_baseline(&labels);
    let build = build_corpus(&labels, &resolver(&reports));
    let separation = feature_separation(&build.rows);

    if args.json {
        let out = json!({
            "project": project,
            "baseline": horus_core::json::to_js_value(&baseline)?,
            "separation": horus_core::json::to_js_value(&separation)?,
        });
        println!("{}", horus_core::json::to_js_json_pretty(&out)?);
        return Ok(());
    }

    let pct = |n: f64| format!("{}%", to_fixed(n * 100.0, 0));
    println!("{}", bold(&format!("Eval baseline — {project}")));
    if baseline.n == 0 {
        println!(
            "{}",
            dim("No outcome labels yet. Leave feedback (`horus feedback`) or confirm an investigation (`horus memory confirm`) to seed the eval set.")
        );
        return Ok(());
    }
    println!(
        "  Strict hit-rate: {} {}",
        green(&pct(baseline.strict_hit_rate)),
        dim(&format!("(weighted {}) over {} investigation(s)", pct(baseline.weighted_hit_rate), baseline.n))
    );
    let cb = &baseline.class_balance;
    println!(
        "  Class balance: {}, {}, {} · {}",
        green(&format!("{} yes", cb.yes)),
        yellow(&format!("{} partly", cb.partly)),
        red(&format!("{} no", cb.no)),
        dim(&format!("source: {} feedback, {} confirm", baseline.by_source.feedback, baseline.by_source.confirm))
    );
    if separation.factors.is_empty() {
        println!(
            "{}",
            dim("  Feature separation: no discriminative sample yet (needs feedback rows with yes AND no verdicts and a ranked cause).")
        );
    } else {
        println!("{}", dim(&format!("  Feature separation (yes vs no, {} row(s)):", separation.evaluated)));
        for f in separation.factors.iter().take(10) {
            println!(
                "{}",
                dim(&format!(
                    "    {}: Δ {} (yes {} vs no {}, effect {})",
                    f.factor,
                    to_fixed(f.separation, 3),
                    to_fixed(f.mean_yes, 3),
                    to_fixed(f.mean_no, 3),
                    to_fixed(f.effect_size, 2)
                ))
            );
        }
    }
    Ok(())
}
