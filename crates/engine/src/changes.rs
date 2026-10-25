//! HOR-8 change-impact primitive.
//! Computes which execution flows are affected by a set of code changes.

use crate::code_provider::{CodeProvider, DiffRange};
use crate::js::locale_compare;
use horus_core::{is_product_path, ChangeSet, Flow, ModifiedSymbol, Symbol};
use indexmap::{IndexMap, IndexSet};
use crate::memory_store::to_iso_string;
use horus_db::InvestigationWithReport;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AffectedFlow {
    pub flow_id: String,
    pub flow_name: String,
    pub changed_symbols: Vec<String>,
}

static DERIVED_ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(community|process|folder):").unwrap());

/// Derived/synthetic graph nodes (communities, processes, folder rollups, or anything with no
/// real file) must never be reported as structural changes.
fn is_derived_node(s: &Symbol) -> bool {
    DERIVED_ID_RE.is_match(&s.id) || s.file_path.trim().is_empty()
}

/// Is this flow rooted in a test/fixture file (its entry step)? Empty flows count as product.
fn flow_is_test_scoped(f: &Flow) -> bool {
    match f.steps.first().map(|s| s.file_path.as_str()) {
        Some(entry) if !entry.is_empty() => !is_product_path(entry),
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeImpactReport {
    pub base: String,
    pub compare: String,
    pub added: Vec<Symbol>,
    pub removed: Vec<Symbol>,
    pub modified: Vec<ModifiedSymbol>,
    pub affected_flows: Vec<AffectedFlow>,
    pub summary: String,
    /// Saved investigations whose code footprint this change touches (context only, never a verdict).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_incidents: Option<Vec<RelatedIncident>>,
}

/// A past investigation whose top code seeds include a symbol this change modifies or removes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedIncident {
    pub investigation_id: String,
    pub created_at: String,
    pub hint: String,
    pub top_cause: String,
    pub matched_symbols: Vec<String>,
}

/// Only causes Horus itself rated at least `likely`: their code links were ~2x as reliable as the rest.
const RELATED_INCIDENT_BANDS: &[&str] = &["highly-likely", "likely"];
const RELATED_INCIDENT_LIMIT: usize = 5;

static FOOTPRINT_ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(method|function):").unwrap());

fn value_string(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Past incidents whose footprint (top-3 method/function seeds) this change touches, newest first.
/// Validated on 409 commits / 200 investigations: such links point at the code later changed for the
/// incident about twice as often as chance, but do NOT predict the next incident — so this is review
/// context ("code behind incident X"), never a risk score or merge gate.
pub fn incidents_touching_changes(modified: &[ModifiedSymbol], removed: &[Symbol], saved: &[InvestigationWithReport]) -> Vec<RelatedIncident> {
    let changed: HashSet<&str> = modified
        .iter()
        .flat_map(|m| [m.before.id.as_str(), m.after.id.as_str()])
        .chain(removed.iter().map(|s| s.id.as_str()))
        .collect();
    let mut rows: Vec<&InvestigationWithReport> = saved.iter().collect();
    rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let mut out: Vec<RelatedIncident> = Vec::new();
    for row in rows {
        let Some(report) = row.report.as_deref().and_then(|r| serde_json::from_str::<Value>(r).ok()) else { continue };
        let Some(cause) = report.pointer("/suspectedCauses/0") else { continue };
        if !RELATED_INCIDENT_BANDS.contains(&value_string(cause.get("band")).as_str()) {
            continue;
        }
        let matched: Vec<String> = report
            .get("seeds")
            .and_then(Value::as_array)
            .map(|seeds| seeds.iter().take(3).map(|s| value_string(s.get("id"))).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .filter(|id| FOOTPRINT_ID_RE.is_match(id) && changed.contains(id.as_str()))
            .collect();
        if matched.is_empty() {
            continue;
        }
        let hint = value_string(report.pointer("/input/hint"));
        // Re-runs of the same question add nothing; the newest one wins (rows are newest first).
        if out.iter().any(|o| o.hint.trim().to_lowercase() == hint.trim().to_lowercase()) {
            continue;
        }
        out.push(RelatedIncident {
            investigation_id: row.id.clone(),
            created_at: to_iso_string(&row.created_at),
            hint,
            top_cause: value_string(cause.get("title")),
            matched_symbols: matched,
        });
        if out.len() == RELATED_INCIDENT_LIMIT {
            break;
        }
    }
    out
}

pub struct ChangeImpactInput {
    pub base: String,
    pub compare: Option<String>,
}

pub async fn change_impact(input: ChangeImpactInput, code: &dyn CodeProvider) -> anyhow::Result<ChangeImpactReport> {
    let compare = input.compare.unwrap_or_else(|| "HEAD".to_string());

    // Identical refs cannot differ — short-circuit before the source index gets a
    // chance to fabricate structural changes from derived nodes (`changes HEAD HEAD`).
    if input.base == compare {
        return Ok(ChangeImpactReport {
            base: input.base,
            summary: format!("base and compare are the same ref ({compare}) — no changes."),
            compare,
            added: vec![],
            removed: vec![],
            modified: vec![],
            affected_flows: vec![],
            related_incidents: None,
        });
    }

    let raw: ChangeSet = code.detect_changes(&DiffRange { base: input.base.clone(), compare: compare.clone() }).await?;
    // Defensive: derived/synthetic nodes are index artifacts, not code changes.
    let changes = ChangeSet {
        added: raw.added.into_iter().filter(|s| !is_derived_node(s)).collect(),
        removed: raw.removed.into_iter().filter(|s| !is_derived_node(s)).collect(),
        modified: raw.modified.into_iter().filter(|m| !is_derived_node(&m.after) && !is_derived_node(&m.before)).collect(),
    };

    // All "present-day" changed symbols — added + modified afters; cap at 25 to bound
    // source-intelligence calls; skip file-label ids for flow mapping.
    let capped: Vec<&Symbol> = changes
        .added
        .iter()
        .chain(changes.modified.iter().map(|m| &m.after))
        .filter(|s| !s.id.starts_with("file:"))
        .take(25)
        .collect();

    // For each changed symbol, fetch flows (treat errors as no flows)
    let mut flows_per_symbol: Vec<Vec<Flow>> = Vec::with_capacity(capped.len());
    for s in &capped {
        flows_per_symbol.push(code.flows_for(&s.id, None).await.unwrap_or_default());
    }

    let mut flow_map: IndexMap<String, (String, IndexSet<String>)> = IndexMap::new();
    for (sym, flows) in capped.iter().zip(flows_per_symbol.iter()) {
        let sym_is_test_scoped = !is_product_path(&sym.file_path);
        for flow in flows {
            // Test-derived flows only count when the changed symbol itself is test-scoped —
            // a product change "affecting" 40 test flows is noise, not blast radius.
            if flow_is_test_scoped(flow) && !sym_is_test_scoped {
                continue;
            }
            match flow_map.get_mut(&flow.id) {
                Some(existing) => {
                    existing.1.insert(sym.name.clone());
                }
                None => {
                    let mut set = IndexSet::new();
                    set.insert(sym.name.clone());
                    flow_map.insert(flow.id.clone(), (flow.name.clone(), set));
                }
            }
        }
    }

    // Rank by how much of the change lands in the flow (most changed symbols first),
    // name as the deterministic tie-break.
    let mut affected_flows: Vec<AffectedFlow> = flow_map
        .into_iter()
        .map(|(flow_id, (flow_name, changed))| AffectedFlow { flow_id, flow_name, changed_symbols: changed.into_iter().collect() })
        .collect();
    affected_flows.sort_by(|a, b| {
        b.changed_symbols
            .len()
            .cmp(&a.changed_symbols.len())
            .then_with(|| locale_compare(&a.flow_name, &b.flow_name))
    });

    let summary = format!(
        "{} added, {} modified, {} removed between {}..{compare}; {} execution flow(s) affected.",
        changes.added.len(),
        changes.modified.len(),
        changes.removed.len(),
        input.base,
        affected_flows.len(),
    );

    Ok(ChangeImpactReport {
        base: input.base,
        compare,
        added: changes.added,
        removed: changes.removed,
        modified: changes.modified,
        affected_flows,
        summary,
        related_incidents: None,
    })
}
