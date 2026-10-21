//! Port of `packages/cli/src/commands/changes.ts`.

use anyhow::Result;
use horus_ai::InterpretationPromptKind;
use horus_connectors::Provider;
use horus_engine::changes::{change_impact, ChangeImpactInput};
use horus_engine::render_changes::{change_impact_to_json, render_change_impact};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::ai_provider::{print_ai_interpretation, AiInterpretationOpts};
use crate::lib::engine_code::{create_code, fail, load_config};
use crate::lib::format::red;

pub const CHANGES_AI_CONTRACT: &str = "Provide a clearly separated AI change-impact review with:

Highest-risk changes
- Files, symbols, or flows most likely to matter for correctness or stability
- Explain why based on affected flows and change types (added/removed/modified)

Review focus
- What the reviewer should inspect first
- Specific symbols or files worth extra attention

Testing suggestions
- Specific smoke tests or checks based on affected flows
- Only reference flows and symbols Horus found

Confidence / gaps
- Where Horus evidence is strong (full flow coverage)
- What is missing (e.g. no affected flows found — no source index, or no matching flows)";

pub async fn run(args: &ChangesArgs) -> Result<()> {
    changes(args).await.map_err(|e| fail(e, args.json))
}

async fn changes(args: &ChangesArgs) -> Result<()> {
    let config = load_config(&args.config)?;
    let code = create_code(&config)?;
    if !code.health().await.ok {
        eprintln!("{}", red("Source-intelligence host unreachable — run: horus init"));
        return Err(SilentExit(1).into());
    }
    let report = change_impact(ChangeImpactInput { base: args.base.clone(), compare: args.compare.clone() }, &code).await?;

    if args.json {
        println!("{}", change_impact_to_json(&report, args.full));
    } else {
        println!("{}", render_change_impact(&report));
        if args.ai {
            print_ai_interpretation(AiInterpretationOpts {
                command: "changes",
                evidence: horus_core::json::to_js_value(&report)?,
                prompt_kind: InterpretationPromptKind::ChangeRisk,
                output_contract: CHANGES_AI_CONTRACT,
                user_intent: Some(format!("base: {}, compare: {}", args.base, args.compare.as_deref().unwrap_or("HEAD"))),
                config: args.config.as_deref(),
                model_override: args.ai_model.as_deref(),
            })
            .await;
        }
    }
    Ok(())
}
