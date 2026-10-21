//! `SourceCodeProvider` — the code-graph `CodeProvider` backed by a running `horus-source host`.
//!
//! The read path goes through the host's TYPED endpoints (HOR-392): exact-name lookup,
//! batch line hydration, the extended node-detail endpoint, and the flows endpoint. The
//! CLI never emits or escapes raw Cypher — `cypher()` remains ONLY as a passthrough for
//! the user-facing SQL-console path.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use async_trait::async_trait;
use horus_core::{SymbolField, SymbolKeyOrder, 
    ChangeSet, CommunityRef, CoupledFile, CypherResult, Flow, HealthStatus, ImpactDepth,
    ImpactResult, ModifiedSymbol, ProviderKind, Symbol, SymbolContext,
};
use serde_json::Value;

use super::client::{IncludeTests, SourceHttpClient, SourceHttpError};
use super::types::SourceNode;
use crate::contract::{
    CodeCommunity, CodeOverview, CodeProcess, CodeProcessStep, CodeProvider, CouplingPair,
    DeadCodeSummary, DiffRange, Provider,
};

pub struct SourceCodeProvider {
    client: SourceHttpClient,
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() { None } else { Some(s.to_string()) }
}

fn positive(n: i64) -> Option<i64> {
    if n > 0 { Some(n) } else { None }
}

/// JS `String(v)` for the loosely-typed id/name values the host returns.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

impl SourceCodeProvider {
    pub fn new(client: SourceHttpClient) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &SourceHttpClient {
        &self.client
    }

    // --- helpers -------------------------------------------------------------

    fn node_to_symbol(n: &SourceNode) -> Symbol {
        Symbol {
            id: n.id.clone(),
            name: n.name.clone(),
            file_path: n.file_path.clone(),
            start_line: Some(n.start_line),
            end_line: Some(n.end_line),
            signature: Some(n.signature.clone()),
            language: Some(n.language.clone()),
            class_name: Some(n.class_name.clone()),
            score: None,
            alias_of: n.alias_of.clone().filter(|a| !a.is_empty()), // B2: export-alias redirect target
            key_order: SymbolKeyOrder::default(),
        }
    }

    /// Map a serialized graph node to a `Symbol`, coercing the host's `0` line sentinel to None.
    fn serialized_to_symbol(n: &SourceNode) -> Symbol {
        Symbol {
            id: n.id.clone(),
            name: n.name.clone(),
            file_path: n.file_path.clone(),
            start_line: positive(n.start_line),
            end_line: positive(n.end_line),
            class_name: non_empty(&n.class_name),
            signature: non_empty(&n.signature),
            language: non_empty(&n.language),
            score: None,
            alias_of: n.alias_of.clone().filter(|a| !a.is_empty()), // B2
            key_order: SymbolKeyOrder::of(&[SymbolField::StartLine, SymbolField::EndLine, SymbolField::ClassName, SymbolField::Signature, SymbolField::Language, SymbolField::AliasOf]),
        }
    }

    /// Graceful degradation (HOR-353): a 4xx for THIS repo's graph shape must not abort the
    /// whole investigation. The caller passes a default the slice degrades to.
    fn degrade<T>(r: Result<T>, fallback: T) -> Result<T> {
        match r {
            Ok(v) => Ok(v),
            Err(err) => match err.downcast_ref::<SourceHttpError>() {
                Some(e) if (400..500).contains(&e.status) => Ok(fallback),
                _ => Err(err),
            },
        }
    }

    /// Attach start/end line ranges to symbols via a single batched id lookup.
    async fn hydrate_lines(&self, mut symbols: Vec<Symbol>) -> Result<Vec<Symbol>> {
        let ids: Vec<String> = symbols.iter().map(|s| s.id.clone()).filter(|id| !id.is_empty()).collect();
        if ids.is_empty() {
            return Ok(symbols);
        }
        let lines = Self::degrade(self.client.nodes_lines(&ids).await, Default::default())?;
        for s in symbols.iter_mut() {
            if let Some(l) = lines.get(&s.id) {
                if l.start_line > 0 {
                    s.start_line = Some(l.start_line);
                    s.key_order.touch(SymbolField::StartLine);
                }
                if l.end_line > 0 {
                    s.end_line = Some(l.end_line);
                    s.key_order.touch(SymbolField::EndLine);
                }
            }
        }
        Ok(symbols)
    }
}

#[async_trait]
impl Provider for SourceCodeProvider {
    fn id(&self) -> &str {
        "source"
    }
    fn kind(&self) -> ProviderKind {
        ProviderKind::Code
    }
    async fn health(&self) -> HealthStatus {
        let h = self.client.health().await;
        HealthStatus {
            ok: h.ok,
            detail: if h.ok {
                format!("Source intelligence host responded {}", h.status)
            } else {
                "Source intelligence host unreachable".to_string()
            },
        }
    }
}

#[async_trait]
impl CodeProvider for SourceCodeProvider {
    async fn search_symbols(&self, query: &str, limit: Option<usize>) -> Result<Vec<Symbol>> {
        let limit = limit.unwrap_or(10);
        // Phase 1: deterministic exact-name lookup via the typed endpoint. Vector search can
        // rank unrelated symbols above exact-name hits when embedding similarity is
        // misleading (HOR-164). An exact-name hit is always authoritative.
        // Phase 2: semantic search — run in parallel with Phase 1.
        let (exact_res, semantic_res) = tokio::join!(
            self.client.exact_symbols(query, Some(limit as i64)),
            self.client.search(query, Some(limit as i64)),
        );
        let exact_hits = Self::degrade(exact_res, Vec::new())?;
        let semantic_res = semantic_res?;

        let exact_symbols: Vec<Symbol> = exact_hits
            .iter()
            .map(|h| Symbol {
                id: h.node_id.clone(),
                name: h.name.clone(),
                file_path: h.file_path.clone(),
                score: Some(1.0), // an exact-name hit is authoritative
                start_line: positive(h.start_line),
                end_line: positive(h.end_line),
                alias_of: h.alias_of.clone().filter(|a| !a.is_empty()), // B2/HOR-465
                key_order: SymbolKeyOrder::of(&[SymbolField::Score, SymbolField::StartLine, SymbolField::EndLine, SymbolField::AliasOf]),
                ..Default::default()
            })
            .collect();

        let exact_ids: HashSet<&str> = exact_symbols.iter().map(|s| s.id.as_str()).collect();
        let ql = query.to_lowercase();

        // Re-rank semantic results: partial name matches above pure embedding-only matches,
        // File-label results below all symbol matches. Within a band, PUBLIC declarations
        // outrank private internals (dogfood cycle-2 N9: hybrid scores are near-flat, so the
        // underscore prefix is the only discriminating signal available here).
        let mut semantic: Vec<(f64, &super::types::SourceSearchResult)> = semantic_res
            .iter()
            .filter(|r| !exact_ids.contains(r.node_id.as_str()))
            .map(|r| {
                let nl = r.name.to_lowercase();
                let is_file = r.label == "File";
                let name_match = nl.contains(&ql) || ql.contains(&nl);
                let mut rank = 0.0;
                if !is_file && name_match {
                    rank = 2.0;
                } else if is_file && name_match {
                    rank = 1.0;
                }
                if r.name.starts_with('_') || r.name.starts_with('#') {
                    rank -= 1.0; // private convention
                }
                let label = r.label.to_lowercase();
                if label == "class" || label == "interface" {
                    rank += 0.5; // declarations lead
                }
                (rank, r)
            })
            .collect();
        semantic.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.1.score.partial_cmp(&a.1.score).unwrap_or(std::cmp::Ordering::Equal))
        });

        let mut combined = exact_symbols;
        combined.extend(semantic.into_iter().map(|(_, r)| Symbol {
            id: r.node_id.clone(),
            name: r.name.clone(),
            file_path: r.file_path.clone(),
            score: Some(r.score),
            key_order: SymbolKeyOrder::of(&[SymbolField::Score]),
            ..Default::default()
        }));
        combined.truncate(limit);

        // Hydrate start/end lines from the graph (HOR-211). Exact hits already carry lines,
        // but semantic results return only id/name/file — without this they render as `file:0`.
        self.hydrate_lines(combined).await
    }

    async fn context(&self, symbol_id: &str) -> Result<SymbolContext> {
        // One round-trip: the extended node-detail endpoint returns the node + content +
        // callers/callees/typeRefs + file imports + git coupling + communities (HOR-392).
        let detail = Self::degrade(self.client.node(symbol_id).await.map(Some), None)?;

        let Some(detail) = detail else {
            // 4xx / unknown node — degrade to an empty-but-honest context.
            return Ok(SymbolContext {
                symbol: Symbol { id: symbol_id.to_string(), ..Default::default() },
                snippet: None,
                source_body: None,
                callers: vec![],
                callees: vec![],
                imports: vec![],
                uses_type: vec![],
                community: None,
                coupled_with: vec![],
                is_dead: Some(false),
            });
        };

        let n = &detail.node;
        let symbol = Symbol {
            id: if n.id.is_empty() { symbol_id.to_string() } else { n.id.clone() },
            name: n.name.clone(),
            file_path: n.file_path.clone(),
            start_line: positive(n.start_line),
            end_line: positive(n.end_line),
            signature: non_empty(&n.signature),
            class_name: non_empty(&n.class_name),
            language: non_empty(&n.language),
            score: None,
            alias_of: None,
            key_order: SymbolKeyOrder::of(&[SymbolField::StartLine, SymbolField::EndLine, SymbolField::Signature, SymbolField::ClassName, SymbolField::Language]),
        };

        let content = n.content.as_deref();
        let snippet = content.map(|c| c.chars().take(600).collect::<String>());
        // Full body for analysis that must scan the whole function (e.g. detecting runtime
        // error codes RAISED FROM the seed, whose literal often sits near the end — past the
        // snippet cutoff). Bounded generously so very large symbols don't bloat memory.
        let source_body = content.map(|c| c.chars().take(20_000).collect::<String>());

        let callees = detail.callees.iter().map(|c| Self::serialized_to_symbol(&c.node)).collect();
        let callers = detail.callers.iter().map(|c| Self::serialized_to_symbol(&c.node)).collect();
        let uses_type = detail.type_refs.iter().map(Self::serialized_to_symbol).collect();

        let community = detail
            .communities
            .first()
            .map(|c| CommunityRef { id: js_string(&c.id), name: js_string(&c.name) });

        let imports = detail.imports.iter().map(js_string).collect();
        let coupled_with = detail
            .coupled_with
            .iter()
            .map(|c| CoupledFile { file: c.file.clone(), co_changes: c.co_changes })
            .collect();

        Ok(SymbolContext {
            symbol,
            snippet,
            source_body,
            callers,
            callees,
            imports,
            uses_type,
            community,
            coupled_with,
            is_dead: Some(n.is_dead),
        })
    }

    async fn impact(&self, symbol_id: &str, depth: Option<usize>, include_tests: Option<bool>) -> Result<ImpactResult> {
        let r = self
            .client
            .impact(
                symbol_id,
                Some(depth.unwrap_or(3) as i64),
                IncludeTests { include_tests: include_tests.unwrap_or(false) },
            )
            .await?;
        let mut by_depth: Vec<ImpactDepth> = r
            .depths
            .iter()
            .map(|(d, nodes)| ImpactDepth {
                depth: d.parse::<f64>().map(|f| f as i64).unwrap_or(0),
                symbols: nodes.iter().map(Self::node_to_symbol).collect(),
            })
            .collect();
        by_depth.sort_by_key(|d| d.depth);
        Ok(ImpactResult { target: Self::node_to_symbol(&r.target), affected: r.affected, by_depth })
    }

    async fn flows_for(&self, symbol_id: &str, include_tests: Option<bool>) -> Result<Vec<Flow>> {
        // The typed flows endpoint returns the processes a symbol is a step in, plus the
        // merged ordered steps (each step carries its name/file). The host merges steps across
        // a symbol's processes, so each Flow shares that ordered step list.
        let res = Self::degrade(
            self.client
                .flows(symbol_id, IncludeTests { include_tests: include_tests.unwrap_or(false) })
                .await,
            Default::default(),
        )?;
        let steps: Vec<Symbol> = res
            .steps
            .iter()
            .map(|s| Symbol {
                id: s.node_id.clone(),
                name: s.name.clone(),
                file_path: s.file_path.clone(),
                start_line: positive(s.start_line),
                ..Default::default()
            })
            .collect();
        Ok(res
            .processes
            .iter()
            .map(|p| Flow { id: p.id.clone(), name: p.name.clone(), steps: steps.clone() })
            .collect())
    }

    /// Method symbols of a class (typed /api/class-methods). Used for class-seed walkthroughs.
    async fn class_methods(&self, file: &str, class_name: &str) -> Result<Option<Vec<Symbol>>> {
        let methods = Self::degrade(self.client.class_methods(file, class_name).await, Vec::new())?;
        Ok(Some(
            methods
                .iter()
                .map(Self::serialized_to_symbol)
                .filter(|s| !s.id.is_empty() && !s.name.is_empty())
                .collect(),
        ))
    }

    async fn detect_changes(&self, diff: &DiffRange) -> Result<ChangeSet> {
        let d = self.client.diff(&diff.base, &diff.compare).await?;
        Ok(ChangeSet {
            added: d.added.iter().map(Self::node_to_symbol).collect(),
            removed: d.removed.iter().map(Self::node_to_symbol).collect(),
            modified: d
                .modified
                .iter()
                .map(|m| ModifiedSymbol {
                    before: Self::node_to_symbol(&m.before),
                    after: Self::node_to_symbol(&m.after),
                })
                .collect(),
        })
    }

    async fn cypher(&self, query: &str) -> Result<CypherResult> {
        let r = self.client.cypher(query).await?;
        Ok(CypherResult { columns: r.columns, rows: r.rows, row_count: r.row_count })
    }

    // Typed read-path passthroughs for architecture discovery — see CodeProvider contract.

    async fn overview(&self) -> Result<Option<CodeOverview>> {
        let o = self.client.overview().await?;
        Ok(Some(CodeOverview { nodes_by_label: o.nodes_by_label.into_iter().collect() }))
    }

    async fn communities(&self) -> Result<Option<Vec<CodeCommunity>>> {
        Ok(Some(
            self.client
                .communities()
                .await?
                .into_iter()
                .map(|c| CodeCommunity { name: c.name, member_count: c.member_count, members: Some(c.members) })
                .collect(),
        ))
    }

    async fn processes(&self) -> Result<Option<Vec<CodeProcess>>> {
        Ok(Some(
            self.client
                .processes()
                .await?
                .into_iter()
                .map(|p| CodeProcess {
                    name: p.name,
                    step_count: Some(p.step_count),
                    steps: Some(p.steps.into_iter().map(|s| CodeProcessStep { node_id: s.node_id }).collect()),
                })
                .collect(),
        ))
    }

    async fn dead_code(&self) -> Result<Option<DeadCodeSummary>> {
        Ok(Some(DeadCodeSummary { total: self.client.dead_code().await?.total }))
    }

    async fn coupling(&self) -> Result<Option<Vec<CouplingPair>>> {
        Ok(Some(
            self.client
                .coupling()
                .await?
                .into_iter()
                .map(|p| CouplingPair { co_changes: p.co_changes })
                .collect(),
        ))
    }

    async fn files_containing(&self, tokens: &[String], limit: Option<usize>) -> Result<Option<HashMap<String, Vec<String>>>> {
        let m = self.client.files_containing(tokens, limit.map(|l| l as i64)).await?;
        Ok(Some(m.into_iter().collect()))
    }
}
