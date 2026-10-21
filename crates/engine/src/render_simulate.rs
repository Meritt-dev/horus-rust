//! HOR-31 — Human-facing renderers for the simulation/training mode. Pure, no I/O.

use crate::js::to_fixed;
use crate::simulate::{Scenario, ScenarioEvaluation};
use crate::types::InvestigationReport;

/// Compact list of available scenarios — one entry per scenario with the symptom on a second line.
pub fn render_scenario_list(scenarios: &[Scenario]) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push("Available training scenarios".into());
    lines.push("".into());

    for s in scenarios {
        lines.push(format!("  {}  [{}]  {}", s.id, s.category, s.title));
        lines.push(format!("    {}", s.symptom));
    }

    lines.push("".into());
    lines.push("Run: horus simulate <id>".into());

    lines.join("\n")
}

/// The full training simulation: scenario context, Horus's findings, a signal-check
/// scorecard, and coaching tips.
pub fn render_simulation(scenario: &Scenario, report: &InvestigationReport, evaluation: &ScenarioEvaluation) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push(format!("# Training scenario: {}", scenario.title));
    lines.push("".into());

    lines.push("## Symptom".into());
    lines.push(scenario.symptom.clone());
    lines.push("".into());

    lines.push("Form your own hypothesis before reading on — then compare it with what Horus found.".into());
    lines.push("".into());

    let is_weak = evaluation.passed < evaluation.total;
    if is_weak {
        lines.push("> **Weak investigation** — Horus did not surface all expected signals for this scenario.".into());
        lines.push(
            "> This can happen when the hint resolves to a symbol that is not directly connected to the expected runtime/change evidence."
                .into(),
        );
        lines.push("".into());
    }

    lines.push("## Horus investigation".into());
    lines.push("".into());
    lines.push(report.summary.clone());
    lines.push("".into());

    lines.push("### Top hypotheses".into());
    let top: Vec<_> = report.hypotheses.iter().take(2).collect();
    if top.is_empty() {
        lines.push("(none)".into());
    } else {
        for h in top {
            lines.push(format!("- Verdict: {}", h.verdict.as_str()));
            lines.push(format!("  Confidence: {}", to_fixed(h.confidence, 2)));
            lines.push(format!("  Category: {}", h.category));
            lines.push(format!("  {}", h.statement));
        }
    }
    lines.push("".into());

    lines.push("## Did Horus surface the expected signals?".into());
    lines.push("".into());
    for check in &evaluation.checks {
        let mark = if check.ok { "[x]" } else { "[ ]" };
        lines.push(format!("{mark} {}", check.label));
    }
    lines.push("".into());
    lines.push(format!("Score: {}/{}", evaluation.passed, evaluation.total));
    lines.push("".into());

    lines.push("## Coaching".into());
    lines.push("".into());
    for tip in &scenario.coaching_tips {
        lines.push(format!("- {tip}"));
    }

    if scenario.category == "queue" {
        if let Some(c) = evaluation.checks.iter().find(|c| c.label == "Queue boundary crossing detected") {
            if !c.ok {
                lines.push("".into());
                lines.push("_No queue boundary was detected. The hint likely resolved to a symbol that is not directly connected to a known queue producer or worker. Try re-running with a hint that names a queue worker, producer, or the queue itself._".into());
            }
        }
    }

    if scenario.category == "change" {
        if let Some(c) = evaluation.checks.iter().find(|c| c.label == "Recent change evidence found") {
            if !c.ok {
                lines.push("".into());
                lines.push("_No recent change evidence was found. The deployment-regression scenario needs a diffable git range (`--since`) with commits touching the resolved symbol. Try a more specific hint or a different `--since` range._".into());
            }
        }
    }

    lines.join("\n")
}
