//! The Evidence model — the universal currency between providers, the engine, and the
//! LLM. Everything the AI sees is a typed, attributable `Evidence`; no raw provider
//! blobs reach the model. See architecture.md §2.5.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Which kind of system produced a piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    /// source intelligence
    Code,
    /// Elasticsearch
    Logs,
    /// Prometheus
    Metrics,
    /// Redis / MongoDB
    State,
    /// BullMQ
    Queue,
    /// Git
    History,
}

/// Investigation-priority tier, assigned by the normalization layer (never by
/// providers). Reflects attention the investigator should give this item — NOT
/// operational impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidencePriority {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Broad functional category for grouping and filtering across providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceCategory {
    Queue,
    Database,
    Cache,
    Logs,
    Code,
    Deployment,
    Metrics,
    Other,
}

/// The shape of a single evidence item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Log,
    Metric,
    Symbol,
    Flow,
    Commit,
    QueueState,
    QueueEdge,
    RedisKey,
    /// application/DB state (MongoDB)
    State,
    Impact,
}

/// The entity an evidence item pertains to. Assigned by the NORMALIZATION layer;
/// a field is present only when a real value is known, never fabricated.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

/// Graph back-references that let a human (or the engine) jump to the source.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceLinks {
    // Field order = TS literal order (`{ symbolId, file, line }` for code evidence; Sentry/logs
    // assign `file` then `line`), so serialized key order matches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Not in the TS interface, but set by the Elasticsearch normalizer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_name: Option<String>,
}

/// Reproducibility: the query that produced an evidence item and when.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub query: String,
    pub collected_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    /// Stable, citable id, e.g. `ev_log_01H...`. The AI must reference these.
    pub id: String,
    pub source: ProviderKind,
    pub kind: EvidenceKind,
    /// Human-readable one-line summary.
    pub title: String,
    // Field order = the key order TS objects end up with: the engine's `mkEv` literal
    // (`id…relevance, payload, links, provenance`), then `timestamp`, `isNew`, `ratio` as it
    // assigns them, then `normalizeEvidence`'s `category`, `priority`, `subject`.
    /// Engine-assigned relevance, 0–1.
    pub relevance: f64,
    /// Typed per `kind`; opaque to the engine, structured for the renderer/AI.
    pub payload: Value,
    pub links: EvidenceLinks,
    pub provenance: Provenance,
    /// ISO timestamp, for timeline alignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Recurrence signal: true when this error/event signature has never been seen before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_new: Option<bool>,
    /// Recurrence signal: current-window count divided by baseline (≥ 3.0 = spike).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratio: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<EvidenceCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<EvidencePriority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<EvidenceSubject>,
}

/// A resolved code symbol, as returned by the code provider.
///
/// JSON key order follows how the symbol was BUILT, like the TS object literals: `id, name,
/// filePath` always lead, then the optional fields in [`Symbol::key_order`] (falling back to
/// declaration order). The source provider builds symbols in several orders (exact search hits
/// put `score` right after `filePath`; graph-serialized nodes put `className` before
/// `signature`), so the order is carried on the value and survives a JSON round-trip.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Symbol {
    pub id: String,
    pub name: String,
    pub file_path: String,
    pub start_line: Option<i64>,
    pub end_line: Option<i64>,
    pub signature: Option<String>,
    pub language: Option<String>,
    pub class_name: Option<String>,
    /// Search relevance (0–1) carried from the source provider, when available.
    pub score: Option<f64>,
    /// B2: the NAME of the implementation symbol this export-alias stub points at.
    pub alias_of: Option<String>,
    /// Serialization order of the optional fields (never part of equality).
    pub key_order: SymbolKeyOrder,
}

/// An optional [`Symbol`] field, for [`SymbolKeyOrder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolField {
    StartLine,
    EndLine,
    Signature,
    Language,
    ClassName,
    Score,
    AliasOf,
}

impl SymbolField {
    const DECLARATION_ORDER: [SymbolField; 7] = [
        SymbolField::StartLine,
        SymbolField::EndLine,
        SymbolField::Signature,
        SymbolField::Language,
        SymbolField::ClassName,
        SymbolField::Score,
        SymbolField::AliasOf,
    ];

    fn key(self) -> &'static str {
        match self {
            SymbolField::StartLine => "startLine",
            SymbolField::EndLine => "endLine",
            SymbolField::Signature => "signature",
            SymbolField::Language => "language",
            SymbolField::ClassName => "className",
            SymbolField::Score => "score",
            SymbolField::AliasOf => "aliasOf",
        }
    }

    fn from_key(k: &str) -> Option<SymbolField> {
        SymbolField::DECLARATION_ORDER.into_iter().find(|f| f.key() == k)
    }
}

/// Key order of a symbol's optional fields. Empty = declaration order. Fields not listed are
/// emitted after the listed ones, in declaration order. Equality ignores it.
#[derive(Debug, Clone, Default)]
pub struct SymbolKeyOrder(pub Vec<SymbolField>);

impl PartialEq for SymbolKeyOrder {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl SymbolKeyOrder {
    pub fn of(fields: &[SymbolField]) -> Self {
        SymbolKeyOrder(fields.to_vec())
    }
    /// JS property assignment: a key that is new goes last; an existing key keeps its slot.
    pub fn touch(&mut self, f: SymbolField) {
        if !self.0.contains(&f) {
            self.0.push(f);
        }
    }
}

impl Serialize for Symbol {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("filePath", &self.file_path)?;
        let listed = self.key_order.0.iter().copied();
        let rest = SymbolField::DECLARATION_ORDER.into_iter().filter(|f| !self.key_order.0.contains(f));
        for f in listed.chain(rest) {
            match f {
                SymbolField::StartLine => {
                    if let Some(v) = self.start_line {
                        map.serialize_entry(f.key(), &v)?;
                    }
                }
                SymbolField::EndLine => {
                    if let Some(v) = self.end_line {
                        map.serialize_entry(f.key(), &v)?;
                    }
                }
                SymbolField::Signature => {
                    if let Some(v) = &self.signature {
                        map.serialize_entry(f.key(), v)?;
                    }
                }
                SymbolField::Language => {
                    if let Some(v) = &self.language {
                        map.serialize_entry(f.key(), v)?;
                    }
                }
                SymbolField::ClassName => {
                    if let Some(v) = &self.class_name {
                        map.serialize_entry(f.key(), v)?;
                    }
                }
                SymbolField::Score => {
                    if let Some(v) = self.score {
                        map.serialize_entry(f.key(), &v)?;
                    }
                }
                SymbolField::AliasOf => {
                    if let Some(v) = &self.alias_of {
                        map.serialize_entry(f.key(), v)?;
                    }
                }
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Symbol {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let raw = indexmap::IndexMap::<String, Value>::deserialize(deserializer)?;
        let req = |k: &'static str| -> Result<String, D::Error> {
            match raw.get(k) {
                Some(Value::String(s)) => Ok(s.clone()),
                Some(other) => Err(D::Error::custom(format!("invalid type for `{k}`: {other}"))),
                None => Err(D::Error::missing_field(k)),
            }
        };
        let opt_str = |k: &str| raw.get(k).and_then(Value::as_str).map(str::to_string);
        let opt_int = |k: &str| raw.get(k).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)));
        Ok(Symbol {
            id: req("id")?,
            name: req("name")?,
            file_path: req("filePath")?,
            start_line: opt_int("startLine"),
            end_line: opt_int("endLine"),
            signature: opt_str("signature"),
            language: opt_str("language"),
            class_name: opt_str("className"),
            score: raw.get("score").and_then(Value::as_f64),
            alias_of: opt_str("aliasOf"),
            key_order: SymbolKeyOrder(
                raw.iter().filter(|(_, v)| !v.is_null()).filter_map(|(k, _)| SymbolField::from_key(k)).collect(),
            ),
        })
    }
}

/// A reference to a source-intelligence community cluster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommunityRef {
    pub id: String,
    pub name: String,
}

/// A file that co-changes frequently with another (git coupling).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoupledFile {
    pub file: String,
    pub co_changes: i64,
}

/// Raw result from a Cypher query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CypherResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImpactDepth {
    pub depth: i64,
    pub symbols: Vec<Symbol>,
}

/// Result of an impact analysis rooted at a symbol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactResult {
    pub target: Symbol,
    pub affected: i64,
    pub by_depth: Vec<ImpactDepth>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModifiedSymbol {
    pub before: Symbol,
    pub after: Symbol,
}

/// Added/removed/modified symbols between two refs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChangeSet {
    pub added: Vec<Symbol>,
    pub removed: Vec<Symbol>,
    pub modified: Vec<ModifiedSymbol>,
}

/// Callers + callees of a symbol, enriched with source-intelligence graph neighbours.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolContext {
    pub symbol: Symbol,
    /// Short excerpt of the symbol's source (display).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// The symbol's FULL source body, for analysis that must scan the whole function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_body: Option<String>,
    pub callers: Vec<Symbol>,
    pub callees: Vec<Symbol>,
    /// File paths the symbol's defining file imports.
    pub imports: Vec<String>,
    /// TypeAlias/Interface the symbol uses.
    pub uses_type: Vec<Symbol>,
    /// Always serialized (`null` when absent), matching the TS `CommunityRef | null`.
    pub community: Option<CommunityRef>,
    /// git-coupled files
    pub coupled_with: Vec<CoupledFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_dead: Option<bool>,
}

/// A pre-computed multi-hop execution flow (source-intelligence `Process` node).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub id: String,
    pub name: String,
    pub steps: Vec<Symbol>,
}

/// Status of a provider, surfaced by `horus status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthStatus {
    pub ok: bool,
    pub detail: String,
}
