//! Lightweight, embedding-free query over a `KnowledgeSnapshot` (HOR-291/HOR-292).
//!
//! Enough for `horus knowledge search/contracts` (HOR-294) and to prove imported
//! knowledge is findable by name and keyword: case-insensitive substring matching
//! across each item's id, name, and a few descriptive fields. No index needed —
//! snapshots are small and load fully into memory.
//!
//! Items are searched as their JSON object form (what zod handed the TS code), so
//! field lookup, ranking (category order, then item order) and limits are identical.

use crate::schema::{KnowledgeCategory, KnowledgeSnapshot, KNOWLEDGE_CATEGORIES};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct KnowledgeMatch {
    pub category: KnowledgeCategory,
    pub id: String,
    /// Best display name for the item.
    pub name: String,
    /// The matched item as a JSON object.
    pub item: Value,
}

/// A snapshot category as JSON objects (one per item), in snapshot order.
pub fn category_items(snapshot: &KnowledgeSnapshot, category: KnowledgeCategory) -> Vec<Value> {
    fn conv<T: serde::Serialize>(items: &[T]) -> Vec<Value> {
        items.iter().map(|i| serde_json::to_value(i).unwrap_or(Value::Null)).collect()
    }
    match category {
        KnowledgeCategory::Repositories => conv(&snapshot.repositories),
        KnowledgeCategory::Operations => conv(&snapshot.operations),
        KnowledgeCategory::Types => conv(&snapshot.types),
        KnowledgeCategory::Enums => conv(&snapshot.enums),
        KnowledgeCategory::AuthRules => conv(&snapshot.auth_rules),
        KnowledgeCategory::DomainConcepts => conv(&snapshot.domain_concepts),
        KnowledgeCategory::FrontendPatterns => conv(&snapshot.frontend_patterns),
        KnowledgeCategory::DataFlows => conv(&snapshot.data_flows),
        KnowledgeCategory::RuntimeComponents => conv(&snapshot.runtime_components),
        KnowledgeCategory::ExternalIntegrations => conv(&snapshot.external_integrations),
    }
}

const TEXT_KEYS: [&str; 11] = [
    "id", "name", "key", "slug", "kind", "domain", "role", "summary", "description", "details", "returnType",
];
const LIST_KEYS: [&str; 5] = ["values", "relatedOperations", "relatedTypes", "frameworks", "integrations"];

/// The text fields searched per item, in addition to id + name.
fn searchable_text(item: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    for key in TEXT_KEYS {
        if let Some(Value::String(v)) = item.get(key) {
            parts.push(v.clone());
        }
    }
    for key in LIST_KEYS {
        if let Some(Value::Array(v)) = item.get(key) {
            let strs: Vec<&str> = v.iter().filter_map(|x| x.as_str()).collect();
            parts.push(strs.join(" "));
        }
    }
    parts.join(" ").to_lowercase()
}

fn display_name(item: &Value) -> String {
    for key in ["name", "key", "id"] {
        if let Some(Value::String(v)) = item.get(key) {
            if !v.is_empty() {
                return v.clone();
            }
        }
    }
    String::new()
}

fn item_id(item: &Value) -> String {
    // `String(item.id)` — ids are always strings in a validated snapshot.
    match item.get("id") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "undefined".to_string(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    /// Restrict to specific categories.
    pub categories: Option<Vec<KnowledgeCategory>>,
    /// Max matches to return (`0`/`None` = unlimited, like a falsy JS limit).
    pub limit: Option<usize>,
}

/// Search a snapshot by keyword across all (or selected) categories.
pub fn search_snapshot(snapshot: &KnowledgeSnapshot, query: &str, opts: &SearchOptions) -> Vec<KnowledgeMatch> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return vec![];
    }
    let cats: Vec<KnowledgeCategory> = opts.categories.clone().unwrap_or_else(|| KNOWLEDGE_CATEGORIES.to_vec());
    let limit = opts.limit.unwrap_or(0);
    let mut matches = Vec::new();

    for category in cats {
        for item in category_items(snapshot, category) {
            if searchable_text(&item).contains(&q) {
                matches.push(KnowledgeMatch { category, id: item_id(&item), name: display_name(&item), item });
                if limit > 0 && matches.len() >= limit {
                    return matches;
                }
            }
        }
    }
    matches
}

/// Find a single item across categories by exact (case-insensitive) name or id.
pub fn find_by_name(snapshot: &KnowledgeSnapshot, name: &str) -> Option<KnowledgeMatch> {
    let target = name.trim().to_lowercase();
    for category in KNOWLEDGE_CATEGORIES {
        for item in category_items(snapshot, category) {
            let n = item.get("name").and_then(Value::as_str).map(str::to_lowercase).unwrap_or_default();
            let id = item.get("id").and_then(Value::as_str).map(str::to_lowercase).unwrap_or_default();
            if n == target || id == target {
                return Some(KnowledgeMatch { category, id: item_id(&item), name: display_name(&item), item });
            }
        }
    }
    None
}
