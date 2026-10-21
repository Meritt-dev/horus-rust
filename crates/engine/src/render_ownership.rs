//! Render helpers for OwnershipEstimate (HOR-20).

use crate::js::to_fixed;
use crate::ownership::OwnershipEstimate;

pub fn render_ownership(o: &OwnershipEstimate) -> String {
    let mut lines: Vec<String> = vec![];

    lines.push(format!("# Ownership: {}", o.query));
    lines.push("".into());

    let Some(file) = o.file.as_deref() else {
        lines.push(o.note.clone());
        if let Some(c) = o.candidates.as_ref().filter(|c| !c.is_empty()) {
            lines.push("".into());
            lines.push("Candidates:".into());
            for c in c {
                lines.push(format!("  {c}"));
            }
        }
        return lines.join("\n");
    };

    if let Some(sym) = &o.symbol {
        lines.push(format!("Symbol : {}", sym.name));
    }
    lines.push(format!("File   : {file}"));
    lines.push("".into());

    let pct = to_fixed(o.confidence * 100.0, 0);
    lines.push(format!(
        "Likely maintainer  : {} ({pct}% confidence)",
        o.likely_maintainer.as_deref().unwrap_or("(unknown)")
    ));
    lines.push(format!("Most active recently: {}", o.most_active_recent.as_deref().unwrap_or("(unknown)")));
    lines.push("".into());

    lines.push("Contributors:".into());
    for c in o.contributors.iter().take(8) {
        lines.push(format!("  {} × {} commits,  last {}", c.author, c.commits, c.last_date));
    }
    if o.contributors.len() > 8 {
        lines.push(format!("  … and {} more", o.contributors.len() - 8));
    }
    lines.push("".into());

    if !o.evidence.is_empty() {
        lines.push("Evidence:".into());
        for e in &o.evidence {
            lines.push(format!("  • {e}"));
        }
        lines.push("".into());
    }

    lines.push(format!("Note: {}", o.note));

    lines.join("\n")
}

pub fn ownership_to_json(o: &OwnershipEstimate) -> String {
    horus_core::json::to_js_json_pretty(o).unwrap_or_default()
}
