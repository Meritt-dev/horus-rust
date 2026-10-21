//! HOR-14 — Investigation Graph.
//!
//! Models the infrastructure topology implicit in normalized Evidence: queues,
//! services, workers, collections, deployments as nodes; emits/consumes/observed_in/…
//! as edges. Implication scores identify which nodes sit on the suspected-cause path.

use std::collections::HashSet;

use horus_core::{Evidence, EvidenceKind, EvidencePriority};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::js;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeType {
    Service,
    Queue,
    Worker,
    Database,
    Collection,
    Deployment,
    Symbol,
    File,
    Flow,
    Evidence,
    ExternalSystem,
    Unknown,
}

impl GraphNodeType {
    pub fn as_str(self) -> &'static str {
        match self {
            GraphNodeType::Service => "service",
            GraphNodeType::Queue => "queue",
            GraphNodeType::Worker => "worker",
            GraphNodeType::Database => "database",
            GraphNodeType::Collection => "collection",
            GraphNodeType::Deployment => "deployment",
            GraphNodeType::Symbol => "symbol",
            GraphNodeType::File => "file",
            GraphNodeType::Flow => "flow",
            GraphNodeType::Evidence => "evidence",
            GraphNodeType::ExternalSystem => "external_system",
            GraphNodeType::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GraphEdgeType {
    #[serde(rename = "emits")]
    Emits,
    #[serde(rename = "consumes")]
    Consumes,
    #[serde(rename = "writes_to")]
    WritesTo,
    #[serde(rename = "reads_from")]
    ReadsFrom,
    #[serde(rename = "depends_on")]
    DependsOn,
    #[serde(rename = "caused_by")]
    CausedBy,
    #[serde(rename = "correlated_with")]
    CorrelatedWith,
    #[serde(rename = "observed_in")]
    ObservedIn,
    #[serde(rename = "in-file")]
    InFile,
    #[serde(rename = "symbol-in-flow")]
    SymbolInFlow,
    #[serde(rename = "metric-from")]
    MetricFrom,
}

impl GraphEdgeType {
    pub fn as_str(self) -> &'static str {
        match self {
            GraphEdgeType::Emits => "emits",
            GraphEdgeType::Consumes => "consumes",
            GraphEdgeType::WritesTo => "writes_to",
            GraphEdgeType::ReadsFrom => "reads_from",
            GraphEdgeType::DependsOn => "depends_on",
            GraphEdgeType::CausedBy => "caused_by",
            GraphEdgeType::CorrelatedWith => "correlated_with",
            GraphEdgeType::ObservedIn => "observed_in",
            GraphEdgeType::InFile => "in-file",
            GraphEdgeType::SymbolInFlow => "symbol-in-flow",
            GraphEdgeType::MetricFrom => "metric-from",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    /// Stable content-derived id, e.g. `"queue:payments"`, `"service:api"`.
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: GraphNodeType,
    pub label: String,
    pub evidence_ids: Vec<String>,
    /// True when high-relevance evidence is attached to this node or a direct neighbour.
    pub implicated: bool,
    /// 0–1; max relevance of directly-attached evidence, propagated one hop.
    pub implication_score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    /// `"{from}--{type}-->{to}"`.
    pub id: String,
    #[serde(rename = "type")]
    pub edge_type: GraphEdgeType,
    pub from: String,
    pub to: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InvestigationGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

type NodeMap = IndexMap<String, GraphNode>;
type EdgeMap = IndexMap<String, GraphEdge>;

fn upsert_node(nodes: &mut NodeMap, id: &str, node_type: GraphNodeType, label: &str, evidence_id: Option<&str>) {
    let node = nodes.entry(id.to_string()).or_insert_with(|| GraphNode {
        id: id.to_string(),
        node_type,
        label: label.to_string(),
        evidence_ids: vec![],
        implicated: false,
        implication_score: 0.0,
    });
    if let Some(eid) = evidence_id {
        if !node.evidence_ids.iter().any(|e| e == eid) {
            node.evidence_ids.push(eid.to_string());
        }
    }
}

fn add_edge(edges: &mut EdgeMap, edge_type: GraphEdgeType, from: &str, to: &str, evidence_id: Option<&str>) {
    let id = format!("{from}--{}-->{to}", edge_type.as_str());
    let edge = edges.entry(id.clone()).or_insert_with(|| GraphEdge {
        id,
        edge_type,
        from: from.to_string(),
        to: to.to_string(),
        evidence_ids: vec![],
    });
    if let Some(eid) = evidence_id {
        if !edge.evidence_ids.iter().any(|e| e == eid) {
            edge.evidence_ids.push(eid.to_string());
        }
    }
}

/// Non-empty string at `key` of an object payload (JS truthiness on a string field).
fn str_field<'a>(p: &'a Value, key: &str) -> Option<&'a str> {
    p.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn process_evidence(ev: &Evidence, nodes: &mut NodeMap, edges: &mut EdgeMap) {
    let ev_id = format!("ev:{}", ev.id);
    upsert_node(nodes, &ev_id, GraphNodeType::Evidence, &ev.title, Some(&ev.id));
    let p = &ev.payload;

    match ev.kind {
        EvidenceKind::QueueEdge => {
            // `p.queueName ?? ev.links.queueName` then truthiness check.
            let q_name = p
                .get("queueName")
                .and_then(Value::as_str)
                .or(ev.links.queue_name.as_deref())
                .filter(|s| !s.is_empty());
            let Some(q_name) = q_name else { return };
            let queue_id = format!("queue:{q_name}");
            upsert_node(nodes, &queue_id, GraphNodeType::Queue, q_name, Some(&ev.id));
            add_edge(edges, GraphEdgeType::ObservedIn, &ev_id, &queue_id, Some(&ev.id));
            if let Some(producer) = str_field(p, "producerSymbol") {
                let producer_id = format!("service:{producer}");
                upsert_node(nodes, &producer_id, GraphNodeType::Service, producer, Some(&ev.id));
                add_edge(edges, GraphEdgeType::Emits, &producer_id, &queue_id, Some(&ev.id));
            }
            if let Some(worker) = str_field(p, "workerSymbol") {
                let worker_id = format!("worker:{worker}");
                upsert_node(nodes, &worker_id, GraphNodeType::Worker, worker, Some(&ev.id));
                add_edge(edges, GraphEdgeType::Consumes, &queue_id, &worker_id, Some(&ev.id));
            }
        }
        EvidenceKind::QueueState => {
            let q_name = p
                .get("queueName")
                .and_then(Value::as_str)
                .or(ev.links.queue_name.as_deref())
                .filter(|s| !s.is_empty());
            let Some(q_name) = q_name else { return };
            let queue_id = format!("queue:{q_name}");
            upsert_node(nodes, &queue_id, GraphNodeType::Queue, q_name, Some(&ev.id));
            add_edge(edges, GraphEdgeType::ObservedIn, &ev_id, &queue_id, Some(&ev.id));
        }
        EvidenceKind::Log => {
            if let Some(services) = p.get("services").and_then(Value::as_array) {
                for svc in services.iter().filter_map(Value::as_str) {
                    let service_id = format!("service:{svc}");
                    upsert_node(nodes, &service_id, GraphNodeType::Service, svc, Some(&ev.id));
                    add_edge(edges, GraphEdgeType::ObservedIn, &ev_id, &service_id, Some(&ev.id));
                }
            }
        }
        EvidenceKind::State => {
            let Some(collection) = str_field(p, "collection") else { return };
            let collection_id = format!("collection:{collection}");
            upsert_node(nodes, &collection_id, GraphNodeType::Collection, collection, Some(&ev.id));
            add_edge(edges, GraphEdgeType::ObservedIn, &ev_id, &collection_id, Some(&ev.id));
        }
        EvidenceKind::Commit => {
            let deploy_id = format!("deployment:{}", ev.id);
            upsert_node(nodes, &deploy_id, GraphNodeType::Deployment, &ev.title, Some(&ev.id));
            add_edge(edges, GraphEdgeType::ObservedIn, &ev_id, &deploy_id, Some(&ev.id));
        }
        EvidenceKind::Symbol => {
            let sym = p.get("symbol");
            let name = sym.and_then(|s| s.get("name")).and_then(Value::as_str).unwrap_or("");
            if name.is_empty() {
                return;
            }
            let symbol_id = format!("symbol:{name}");
            upsert_node(nodes, &symbol_id, GraphNodeType::Symbol, name, Some(&ev.id));
            add_edge(edges, GraphEdgeType::ObservedIn, &ev_id, &symbol_id, Some(&ev.id));
            // `sym.filePath ?? p.filePath ?? ev.links.file` — nullish chain, then truthiness.
            let file_path = sym
                .and_then(|s| s.get("filePath"))
                .and_then(Value::as_str)
                .or_else(|| p.get("filePath").and_then(Value::as_str))
                .or(ev.links.file.as_deref())
                .filter(|s| !s.is_empty());
            if let Some(file_path) = file_path {
                let file_id = format!("file:{file_path}");
                upsert_node(nodes, &file_id, GraphNodeType::File, file_path, Some(&ev.id));
                add_edge(edges, GraphEdgeType::InFile, &symbol_id, &file_id, Some(&ev.id));
            }
        }
        EvidenceKind::Flow => {
            let name = p.get("name").and_then(Value::as_str).unwrap_or(&ev.title);
            let flow_key = p.get("flowId").and_then(Value::as_str).unwrap_or(name);
            let flow_node_id = format!("flow:{flow_key}");
            upsert_node(nodes, &flow_node_id, GraphNodeType::Flow, name, Some(&ev.id));
            add_edge(edges, GraphEdgeType::ObservedIn, &ev_id, &flow_node_id, Some(&ev.id));
            if let Some(steps) = p.get("steps").and_then(Value::as_array) {
                for step_name in steps.iter().filter_map(Value::as_str) {
                    if step_name.is_empty() {
                        continue;
                    }
                    let step_symbol_id = format!("symbol:{step_name}");
                    upsert_node(nodes, &step_symbol_id, GraphNodeType::Symbol, step_name, None);
                    add_edge(edges, GraphEdgeType::SymbolInFlow, &step_symbol_id, &flow_node_id, Some(&ev.id));
                }
            }
        }
        EvidenceKind::Metric => {
            let labels = p.get("labels");
            // Try common label keys to identify the emitting service.
            let svc = ["service", "job", "instance"]
                .iter()
                .find_map(|k| labels.and_then(|l| l.get(*k)).and_then(Value::as_str))
                .filter(|s| !s.is_empty());
            if let Some(svc) = svc {
                let service_id = format!("service:{svc}");
                upsert_node(nodes, &service_id, GraphNodeType::Service, svc, Some(&ev.id));
                add_edge(edges, GraphEdgeType::MetricFrom, &ev_id, &service_id, Some(&ev.id));
            }
        }
        // impact, redis-key: evidence node only, no infra derived
        EvidenceKind::Impact | EvidenceKind::RedisKey => {}
    }
}

// ── Implication scoring ───────────────────────────────────────────────────────

/// Fraction of a node's implication score to propagate to direct neighbours.
const PROPAGATION_FACTOR: f64 = 0.7;
/// Minimum implication score for a node to be marked `implicated: true`.
const IMPLICATION_THRESHOLD: f64 = 0.6;

fn is_structural_kind(k: EvidenceKind) -> bool {
    matches!(k, EvidenceKind::Symbol | EvidenceKind::Flow | EvidenceKind::Impact | EvidenceKind::QueueEdge)
}

/// When evidence has been normalized, `priority === 'info'` is authoritative;
/// otherwise fall back to the structural-kind set.
fn is_excluded_from_implication(ev: &Evidence) -> bool {
    match ev.priority {
        Some(p) => p == EvidencePriority::Info,
        None => is_structural_kind(ev.kind),
    }
}

fn is_code_topology(t: GraphNodeType) -> bool {
    matches!(t, GraphNodeType::Symbol | GraphNodeType::File | GraphNodeType::Flow)
}

fn score_implication(nodes: &mut NodeMap, edges: &EdgeMap, evidence: &[Evidence]) {
    let ev_by_id: IndexMap<&str, &Evidence> = evidence.iter().map(|e| (e.id.as_str(), e)).collect();

    // Pass 1: base score = max relevance of non-structural, directly-attached evidence.
    for node in nodes.values_mut() {
        if node.node_type == GraphNodeType::Evidence || is_code_topology(node.node_type) {
            continue;
        }
        node.implication_score = node.evidence_ids.iter().fold(0.0, |max, eid| {
            match ev_by_id.get(eid.as_str()) {
                Some(ev) if !is_excluded_from_implication(ev) => max.max(ev.relevance),
                _ => max,
            }
        });
    }

    // Pass 2: propagate one hop between runtime infrastructure nodes (bidirectional).
    let mut adj: IndexMap<String, IndexSet<String>> = IndexMap::new();
    for edge in edges.values() {
        if matches!(
            edge.edge_type,
            GraphEdgeType::ObservedIn | GraphEdgeType::InFile | GraphEdgeType::SymbolInFlow | GraphEdgeType::MetricFrom
        ) {
            continue;
        }
        let (Some(f), Some(t)) = (nodes.get(&edge.from), nodes.get(&edge.to)) else { continue };
        let skip = |t: GraphNodeType| t == GraphNodeType::Evidence || is_code_topology(t);
        if skip(f.node_type) || skip(t.node_type) {
            continue;
        }
        adj.entry(edge.from.clone()).or_default().insert(edge.to.clone());
        adj.entry(edge.to.clone()).or_default().insert(edge.from.clone());
    }

    // Collect all propagated scores before applying any — exactly one hop.
    let mut to_propagate: IndexMap<String, f64> = IndexMap::new();
    for (node_id, neighbours) in &adj {
        let Some(node) = nodes.get(node_id) else { continue };
        let propagated = node.implication_score * PROPAGATION_FACTOR;
        if propagated <= 0.0 {
            continue;
        }
        for nid in neighbours {
            let current = to_propagate.get(nid).copied().unwrap_or(0.0);
            if propagated > current {
                to_propagate.insert(nid.clone(), propagated);
            }
        }
    }
    for (nid, score) in to_propagate {
        if let Some(node) = nodes.get_mut(&nid) {
            if score > node.implication_score {
                node.implication_score = score;
            }
        }
    }

    // Pass 3: set implicated flag based on final score (code topology never implicated).
    for node in nodes.values_mut() {
        if node.node_type == GraphNodeType::Evidence || is_code_topology(node.node_type) {
            continue;
        }
        node.implicated = node.implication_score >= IMPLICATION_THRESHOLD;
    }
}

/// Sort nodes and edges by id and sort evidenceIds within each, for determinism.
fn finalize(nodes: NodeMap, edges: EdgeMap) -> InvestigationGraph {
    let mut sorted_nodes: Vec<GraphNode> = nodes.into_values().collect();
    sorted_nodes.sort_by(|a, b| js::locale_compare(&a.id, &b.id));
    for n in &mut sorted_nodes {
        n.evidence_ids.sort();
    }
    let mut sorted_edges: Vec<GraphEdge> = edges.into_values().collect();
    sorted_edges.sort_by(|a, b| js::locale_compare(&a.id, &b.id));
    for e in &mut sorted_edges {
        e.evidence_ids.sort();
    }
    InvestigationGraph { nodes: sorted_nodes, edges: sorted_edges }
}

/// Build a deterministic investigation graph from normalized evidence.
/// Evidence items are processed in id order to guarantee stable output.
pub fn build_graph(evidence: &[Evidence]) -> InvestigationGraph {
    let mut nodes: NodeMap = IndexMap::new();
    let mut edges: EdgeMap = IndexMap::new();

    let mut sorted: Vec<&Evidence> = evidence.iter().collect();
    sorted.sort_by(|a, b| js::locale_compare(&a.id, &b.id));
    for ev in sorted {
        process_evidence(ev, &mut nodes, &mut edges);
    }

    score_implication(&mut nodes, &edges, evidence);
    finalize(nodes, edges)
}

/// Max implication score among **implicated** infrastructure nodes touching any of `evidence_ids`.
pub fn max_implication_score(graph: &InvestigationGraph, evidence_ids: &[String]) -> f64 {
    let id_set: HashSet<&str> = evidence_ids.iter().map(String::as_str).collect();
    graph.nodes.iter().fold(0.0, |max, node| {
        if node.node_type == GraphNodeType::Evidence || !node.implicated {
            return max;
        }
        if node.evidence_ids.iter().any(|eid| id_set.contains(eid.as_str())) {
            max.max(node.implication_score)
        } else {
            max
        }
    })
}

/// IDs of all **implicated** infrastructure nodes whose evidence overlaps the supplied set.
pub fn implicated_node_ids(graph: &InvestigationGraph, evidence_ids: &[String]) -> Vec<String> {
    let id_set: HashSet<&str> = evidence_ids.iter().map(String::as_str).collect();
    graph
        .nodes
        .iter()
        .filter(|n| {
            n.node_type != GraphNodeType::Evidence
                && n.implicated
                && n.evidence_ids.iter().any(|eid| id_set.contains(eid.as_str()))
        })
        .map(|n| n.id.clone())
        .collect()
}

/// All evidence IDs attached to **implicated** nodes of the given type (first-seen order).
pub fn implicated_evidence_ids_by_node_type(graph: &InvestigationGraph, node_type: GraphNodeType) -> Vec<String> {
    let mut ids: Vec<String> = vec![];
    for node in &graph.nodes {
        if node.node_type != node_type || !node.implicated {
            continue;
        }
        for eid in &node.evidence_ids {
            if !ids.contains(eid) {
                ids.push(eid.clone());
            }
        }
    }
    ids
}
