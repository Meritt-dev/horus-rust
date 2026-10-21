//! HOR-27 — Rendering for QualityScore.

use crate::js::{number_string, to_fixed};
use crate::score::QualityScore;

pub fn render_score(s: &QualityScore) -> String {
    let mut lines: Vec<String> = vec![];
    lines.push(format!("# Investigation quality: {}/100 ({})", number_string(s.score as f64), s.grade));
    for c in &s.components {
        lines.push(format!(
            "  {}: {}% (weight {}) — {}",
            c.dimension,
            to_fixed(c.value * 100.0, 0),
            number_string(c.weight),
            c.note
        ));
    }
    lines.push(s.summary.clone());
    lines.join("\n")
}

pub fn score_to_json(s: &QualityScore) -> String {
    horus_core::json::to_js_json_pretty(s).unwrap_or_default()
}
