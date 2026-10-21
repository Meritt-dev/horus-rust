//! HOR-26 — Draft an editable postmortem from a persisted investigation.
//! HOR-111 — `--output <path>` / `--force` Markdown export. HOR-15 — `--ai-summary`.
//! Port of `packages/cli/src/commands/postmortem.ts`. Read-only on the db; never touches the
//! source-intelligence host or connectors.

use std::path::{Component, PathBuf};

use anyhow::Result;
use horus_ai::{render_narrative, RenderNarrativeOptions};
use horus_db::{get_investigation, open_db};
use horus_engine::migrate_report::migrate_report;
use horus_engine::postmortem::generate_postmortem;
use horus_engine::types::InvestigationReport;

use crate::cli::*;
use crate::commands::replay::{build_narrative_input, narrative_output_to_stored_judgment};
use crate::commands::SilentExit;
use crate::lib::ai_provider::build_narrative_provider;
use crate::lib::format::{dim, green, red};

fn citations_line(ids: Vec<&str>) -> String {
    format!("\n**Cited evidence:** {}\n", ids.join(", "))
}

pub async fn run(args: &PostmortemArgs) -> Result<()> {
    let mut db = None;
    let result = async {
        let handle = open_db().await?;
        let row = get_investigation(&handle, &args.id).await;
        db = Some(handle);
        let Some(row) = row? else {
            println!("{}", red(&format!("No investigation found: {}", args.id)));
            return Err(SilentExit(1).into());
        };
        let Some(raw) = row.report else {
            println!("{}", red(&format!("Investigation {} has no stored report.", args.id)));
            return Err(SilentExit(1).into());
        };
        let report = migrate_report(serde_json::from_str(&raw)?)?;
        write_postmortem(args, report).await
    }
    .await;
    if let Some(h) = db {
        h.end().await;
    }
    match result {
        Err(err) if err.downcast_ref::<SilentExit>().is_none() => {
            println!("{}", red(&format!("postmortem failed: {err}")));
            Err(SilentExit(1).into())
        }
        other => other,
    }
}

async fn write_postmortem(args: &PostmortemArgs, mut report: InvestigationReport) -> Result<()> {
    let mut content = generate_postmortem(&report);

    if args.ai_summary {
        // Use the stored AI judgment when available (HOR-198); only call AI on --refresh-ai or none.
        match (&report.ai_judgment, args.refresh_ai) {
            (Some(j), false) => {
                content += "\n\n## AI Summary\n\n";
                content += &format!("_Stored AI judgment (provider: {}, generated: {})_\n\n", j.provider, j.generated_at);
                content += &format!("**What happened:** {}\n\n", j.what);
                content += &format!("**Why:** {}\n", j.why);
                if let Some(rca) = &j.root_cause_assessment {
                    content += &format!("\n**Root cause (AI):** {}\n", rca.summary);
                    content += &format!("_(uncertainty: {})_\n", rca.uncertainty);
                }
                if !j.where_next.is_empty() {
                    content += "\n**Next steps:**\n";
                    for step in &j.where_next {
                        content += &format!("- {step}\n");
                    }
                }
                if !j.citations.is_empty() {
                    content += &citations_line(j.citations.iter().map(|c| c.evidence_id.as_str()).collect());
                }
            }
            _ => {
                let input = build_narrative_input(&report)?;
                // Resolve the key/model saved via `horus connect ai` (env fallback), same as investigate (HOR-215).
                let (provider, _) = build_narrative_provider(args.config.as_deref(), args.ai_model.as_deref());
                let res =
                    render_narrative(&input, RenderNarrativeOptions { provider: Some(&provider), confidence_ceiling: None })
                        .await;
                let output = &res.output;
                if !res.from_provider && res.degraded == Some(true) {
                    // Usable AI prose that didn't fully validate — labeled unstructured section (HOR-213).
                    content += "\n\n## AI Summary (unstructured — not validated)\n\n";
                    if !output.what.trim().is_empty() {
                        content += &format!("**What happened:** {}\n\n", output.what.trim());
                    }
                    if !output.why.trim().is_empty() {
                        content += &format!("**Why:** {}\n", output.why.trim());
                    }
                } else if !res.from_provider {
                    // No usable AI text — provider threw; validation_errors[0] is the thrown message.
                    let reason = res.validation_errors.as_ref().and_then(|e| e.first()).map_or("provider error", String::as_str);
                    content += &format!("\n\n## AI Summary\n\n_AI summary unavailable: {reason}_\n");
                } else {
                    content += "\n\n## AI Summary\n\n";
                    content += &format!("**What happened:** {}\n\n", output.what);
                    content += &format!("**Why:** {}\n", output.why);
                    if let Some(rca) = &output.root_cause_assessment {
                        content += &format!("\n**Root cause (AI):** {}\n", rca.summary);
                        content += &format!("_(uncertainty: {})_\n", serde_json::to_value(rca.uncertainty)?.as_str().unwrap_or(""));
                    }
                    if !output.where_next.is_empty() {
                        content += "\n**Next steps:**\n";
                        for step in &output.where_next {
                            content += &format!("- {step}\n");
                        }
                    }
                    if !output.citations.is_empty() {
                        content += &citations_line(output.citations.iter().map(|c| c.evidence_id.as_str()).collect());
                    }
                    // Persist AI judgment for future use (HOR-198) — best effort, in-memory only (as TS).
                    report.ai_judgment = Some(narrative_output_to_stored_judgment(output, "anthropic")?);
                }
            }
        }
    }

    match &args.output {
        Some(out) => {
            let output_path = resolve_path(out);
            if output_path.exists() && !args.force {
                println!("{} {} already exists", red("✗"), output_path.display());
                println!("{}", dim("  pass --force to overwrite"));
                return Err(SilentExit(1).into());
            }
            if let Err(err) = std::fs::write(&output_path, &content) {
                println!("{}{}", red(&format!("✗ Could not write {}: ", output_path.display())), err);
                return Err(SilentExit(1).into());
            }
            println!("{} Saved postmortem to {}", green("✓"), output_path.display());
        }
        None => println!("{content}"),
    }
    Ok(())
}

/// Node `path.resolve`: absolute against cwd, `.`/`..` folded lexically.
fn resolve_path(p: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for c in std::env::current_dir().unwrap_or_default().join(p).components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}
