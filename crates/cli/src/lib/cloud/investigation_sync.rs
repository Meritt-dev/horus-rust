//! Reusable cloud write-path library (HOR-239). Port of
//! `packages/cli/src/lib/cloud/investigation-sync.ts`: persist and retrieve a Horus
//! investigation through the Horus Cloud API. The CLI never touches cloud Postgres directly.
//!
//! Reports are handled as `serde_json::Value` (the verbatim persisted JSON) so the uploaded
//! `content` and its sha256 idempotency key are byte-identical to what the TS CLI sends.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use horus_core::{redact_secrets, HORUS_VERSION};
use horus_db::{get_latest_outcome_label, is_outcome_resolved, is_outcome_source, DbHandle, OutcomeLabel};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::api::{
    AgentRunBody, CitationEdgeInput, CitationNode, CloudClient, CloudError, CreateEvidenceBody,
    CreateInvestigationBody, EvidenceRecord, InvestigationOutcome, InvestigationRecord, ProvenanceEvidenceInput,
    UpdateInvestigationBody,
};
use super::context_store::CloudConfig;
use crate::lib::worker_activity::{worker_run_logs, RunLogResult, WorkerActivity};

// A Horus report snapshot is stored as a `note` evidence with the full report serialized into
// `content` (mirrored in `payload`); `payload.kind` marks it as our snapshot.
const REPORT_EVIDENCE_TYPE: &str = "note";
const REPORT_EVIDENCE_SOURCE: &str = "cli";
const REPORT_EVIDENCE_TITLE: &str = "Investigation report snapshot";
const REPORT_EVIDENCE_KIND: &str = "horus:report";
const REPORT_CONTENT_FORMAT: &str = "application/json";
/// `payload.kind` marker for a per-item evidence row (vs the `horus:report` blob).
const EVIDENCE_ITEM_KIND: &str = "horus:evidence";

/// Map an engine `EvidenceKind` onto the coarse cloud evidence-table `type` enum. Unknown → `note`.
fn cloud_evidence_type(kind: &str) -> &'static str {
    match kind {
        "log" => "log",
        "metric" | "queue-state" | "queue-edge" | "redis-key" | "state" => "runtime_evidence",
        "symbol" | "flow" | "impact" => "code_snippet",
        "commit" => "file_reference",
        _ => "note",
    }
}

#[derive(Debug, Clone)]
pub struct CloudInvestigationRefs {
    pub agent_run_id: Option<String>,
    pub project_id: String,
    pub investigation_id: String,
}

fn idempotency_key(report_id: &str, suffix: &str) -> String {
    format!("{report_id}:{suffix}")
}

fn key_matches(key: &str, words: &[&str]) -> bool {
    let k = key.to_ascii_lowercase();
    words.contains(&k.as_str())
}

/// Apply secret redaction recursively to exported records; vectors and credentials are excluded.
pub fn redact_cloud_value(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact_secrets(s)),
        Value::Array(a) => Value::Array(a.iter().map(redact_cloud_value).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(k, _)| !key_matches(k, &["embedding", "embeddings", "vector", "vectors"]))
                .map(|(k, v)| {
                    let secret = key_matches(
                        k,
                        &[
                            "password", "secret", "token", "authorization", "apikey", "api_key", "api-key",
                            "accesstoken", "access_token", "access-token",
                        ],
                    );
                    (k.clone(), if secret { Value::String("[REDACTED]".into()) } else { redact_cloud_value(v) })
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn js_json(v: &Value) -> String {
    horus_core::json::to_js_json(v).unwrap_or_default()
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |acc, k| acc.get(*k))?.as_str()
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// Materialize the report's evidence as per-item cloud evidence rows (Stage 1). `filePath` /
/// `symbolName` resolve from the evidence links (and the seed symbol table) ONLY when a real
/// value exists — never fabricated. Pure.
pub fn build_evidence_items(report: &Value) -> Vec<ProvenanceEvidenceInput> {
    let mut symbol_name: HashMap<&str, &str> = HashMap::new();
    let mut symbol_file: HashMap<&str, &str> = HashMap::new();
    for s in arr(report, "seeds") {
        let Some(id) = s.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) else { continue };
        if let Some(n) = s.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            symbol_name.insert(id, n);
        }
        if let Some(f) = s.get("filePath").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            symbol_file.insert(id, f);
        }
    }
    let report_id = report.get("id").and_then(Value::as_str).unwrap_or_default();
    arr(report, "evidence")
        .iter()
        .map(|ev| {
            let id = ev.get("id").and_then(Value::as_str).unwrap_or_default();
            let kind = ev.get("kind").and_then(Value::as_str).unwrap_or_default();
            let symbol_id = str_at(ev, &["links", "symbolId"]);
            let file_path = str_at(ev, &["links", "file"]).or_else(|| symbol_id.and_then(|s| symbol_file.get(s).copied()));
            ProvenanceEvidenceInput {
                kind_bucket: cloud_evidence_type(kind).into(),
                source: ev.get("source").and_then(Value::as_str).unwrap_or_default().into(),
                title: ev.get("title").and_then(Value::as_str).unwrap_or_default().into(),
                content: js_json(ev),
                content_format: REPORT_CONTENT_FORMAT.into(),
                payload: Some(serde_json::json!({ "kind": EVIDENCE_ITEM_KIND, "engineRef": id })),
                idempotency_key: Some(idempotency_key(report_id, &format!("ev:{id}"))),
                engine_ref: id.into(),
                service: str_at(ev, &["subject", "service"]).map(str::to_string),
                environment: str_at(ev, &["subject", "environment"]).map(str::to_string),
                provenance: ev.get("provenance").filter(|p| !p.is_null()).cloned(),
                file_path: file_path.map(str::to_string),
                symbol_name: symbol_id.and_then(|s| symbol_name.get(s)).map(|s| s.to_string()),
                kind: kind.into(),
            }
        })
        .collect()
}

fn node(kind: &str, reference: &str, label: &str) -> CitationNode {
    CitationNode {
        kind: kind.into(),
        reference: reference.into(),
        label: label.into(),
        confidence: None,
        band: None,
        verdict: None,
        subject: None,
    }
}

fn truthy_object(v: Option<&Value>) -> Option<Value> {
    v.filter(|s| !s.is_null() && *s != &Value::Bool(false)).cloned()
}

/// Build the citation graph (Stage 1): cause → evidence (`derives`), hypothesis → evidence
/// (`supports`), finding → evidence (`cites`), each rooted at the investigation node. Edges only
/// from real evidence ids; contradicting hypothesis edges are CUT (no backing data yet). Pure.
pub fn build_citation_edges(report: &Value, investigation_id: &str) -> Vec<CitationEdgeInput> {
    let by_id: HashMap<&str, &Value> =
        arr(report, "evidence").iter().filter_map(|e| Some((e.get("id")?.as_str()?, e))).collect();
    let subject = truthy_object(report.get("subject"));
    let mut edges = Vec::new();

    let hint = js_slice(str_at(report, &["input", "hint"]).unwrap_or_default(), 200);
    let mut investigation_node = node("investigation", investigation_id, if hint.is_empty() { "Investigation" } else { &hint });
    investigation_node.confidence = report.get("confidence").and_then(Value::as_f64);
    investigation_node.subject = subject.clone();

    let evidence_node = |engine_ref: &str| -> Option<CitationNode> {
        let ev = by_id.get(engine_ref)?;
        let mut n = node("evidence", ev.get("id")?.as_str()?, ev.get("title").and_then(Value::as_str).unwrap_or_default());
        n.subject = truthy_object(ev.get("subject"));
        Some(n)
    };
    let ids = |v: &Value, key: &str| -> Vec<String> {
        arr(v, key).iter().filter_map(|x| x.as_str().map(str::to_string)).collect()
    };

    for c in arr(report, "suspectedCauses") {
        let mut cause = node("cause", c.get("id").and_then(Value::as_str).unwrap_or_default(), c.get("title").and_then(Value::as_str).unwrap_or_default());
        cause.confidence = c.get("confidence").and_then(Value::as_f64);
        cause.band = c.get("band").and_then(Value::as_str).map(str::to_string);
        cause.subject = subject.clone();
        let mut cited = false;
        for ev_id in ids(c, "sourceEvidenceIds") {
            if let Some(en) = evidence_node(&ev_id) {
                edges.push(CitationEdgeInput { from: cause.clone(), to: en, role: "derives".into() });
                cited = true;
            }
        }
        if cited {
            edges.push(CitationEdgeInput { from: investigation_node.clone(), to: cause, role: "derives".into() });
        }
    }

    for h in arr(report, "hypotheses") {
        let mut hyp = node("hypothesis", h.get("id").and_then(Value::as_str).unwrap_or_default(), h.get("statement").and_then(Value::as_str).unwrap_or_default());
        hyp.confidence = h.get("confidence").and_then(Value::as_f64);
        hyp.verdict = h.get("verdict").and_then(Value::as_str).map(str::to_string);
        hyp.subject = subject.clone();
        let mut cited = false;
        for ev_id in ids(h, "supportingEvidenceIds") {
            if let Some(en) = evidence_node(&ev_id) {
                edges.push(CitationEdgeInput { from: hyp.clone(), to: en, role: "supports".into() });
                cited = true;
            }
        }
        // CUT: contradicting hypothesis edges are not emitted (no backing data yet).
        if cited {
            edges.push(CitationEdgeInput { from: investigation_node.clone(), to: hyp, role: "explains".into() });
        }
    }

    let report_id = report.get("id").and_then(Value::as_str).unwrap_or_default();
    for (i, f) in arr(report, "findings").iter().enumerate() {
        let mut finding = node("finding", &format!("{report_id}:finding:{i}"), f.get("title").and_then(Value::as_str).unwrap_or_default());
        finding.confidence = f.get("confidence").and_then(Value::as_f64);
        finding.subject = subject.clone();
        let mut cited = false;
        for ev_id in ids(f, "evidenceIds") {
            if let Some(en) = evidence_node(&ev_id) {
                edges.push(CitationEdgeInput { from: finding.clone(), to: en, role: "cites".into() });
                cited = true;
            }
        }
        if cited {
            edges.push(CitationEdgeInput { from: investigation_node.clone(), to: finding, role: "cites".into() });
        }
    }
    edges
}

/// JS `s.slice(0, n)` (UTF-16 code units).
fn js_slice(s: &str, n: usize) -> String {
    String::from_utf16_lossy(&s.encode_utf16().take(n).collect::<Vec<_>>())
}

/// Resolve evidence-node refs from engine `ev_…` ids to cloud ids. An edge whose evidence
/// endpoint does not resolve is CUT — never a fake link. Pure.
pub fn resolve_citation_edges(edges: Vec<CitationEdgeInput>, id_map: &HashMap<String, String>) -> Vec<CitationEdgeInput> {
    let resolve = |mut n: CitationNode| -> Option<CitationNode> {
        if n.kind != "evidence" {
            return Some(n);
        }
        n.reference = id_map.get(&n.reference)?.clone();
        Some(n)
    };
    edges
        .into_iter()
        .filter_map(|e| Some(CitationEdgeInput { from: resolve(e.from)?, to: resolve(e.to)?, role: e.role }))
        .collect()
}

/// Stage 1 dual-write: per-item evidence rows + citation edges, batched. Best-effort — the
/// report blob stays the source of truth, so a cloud/network failure is swallowed.
async fn write_investigation_provenance(
    client: &CloudClient,
    project_id: &str,
    investigation_id: &str,
    report: &Value,
) -> Result<()> {
    let run = async {
        let items = build_evidence_items(report);
        if items.is_empty() {
            return Ok::<(), CloudError>(());
        }
        let created = client.create_evidence_batch(project_id, investigation_id, &items).await?;
        let id_map: HashMap<String, String> = created
            .evidence
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| Some((r.engine_ref.filter(|s| !s.is_empty())?, r.id.filter(|s| !s.is_empty())?)))
            .collect();
        let edges = resolve_citation_edges(build_citation_edges(report, investigation_id), &id_map);
        if !edges.is_empty() {
            client.create_citations(project_id, investigation_id, &edges).await?;
        }
        Ok(())
    };
    match run.await {
        Ok(()) => Ok(()),
        // Older cloud (404) or transient failure: keep the upload green. Re-throw only
        // genuinely unexpected (non-cloud) errors so real bugs still surface.
        Err(e) if e.is_cloud() => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Map an eval-store outcome label (HOR-390) onto the frozen-contract `outcome` payload. None for
/// no label — and for a label failing the validate-on-read firewall. Pure.
pub fn to_investigation_outcome(label: Option<&OutcomeLabel>) -> Option<InvestigationOutcome> {
    let label = label?;
    if !is_outcome_resolved(&label.resolved) || !is_outcome_source(&label.source) {
        return None;
    }
    let trimmed = |s: &Option<String>| s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    Some(InvestigationOutcome {
        resolved: label.resolved.clone(),
        note: trimmed(&label.note),
        confirmed_cause: trimmed(&label.confirmed_cause),
        source: label.source.clone(),
        labeled_at: label.at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    })
}

/// Best-effort: a missing/unreachable store (or bad row) yields None so the sync never fails on it.
async fn resolve_outcome_for_sync(db: Option<&DbHandle>, investigation_id: &str) -> Option<InvestigationOutcome> {
    let label = get_latest_outcome_label(db?, investigation_id).await.ok()?;
    to_investigation_outcome(label.as_ref())
}

#[derive(Default)]
pub struct UploadOpts<'a> {
    pub db: Option<&'a DbHandle>,
    /// `(startedAt, endedAt)`.
    pub run_timing: Option<(String, String)>,
    pub run_activity: Option<&'a [WorkerActivity]>,
}

/// Upload the results of a locally-run investigation to Horus Cloud: create the investigation,
/// attach the full report snapshot as evidence, and record the CLI execution as an AgentRun.
/// With `opts.db`, the current human outcome label rides the create payload (frozen contract).
pub async fn upload_investigation_to_cloud(
    client: &CloudClient,
    cfg: &CloudConfig,
    report: &Value,
    opts: UploadOpts<'_>,
) -> Result<CloudInvestigationRefs> {
    let project = cfg.project.as_ref().ok_or_else(|| anyhow!("Cloud config is missing a linked project."))?;
    let report = redact_cloud_value(report);
    let project_id = project.id.as_str();
    let repository_ids = cfg.repository.as_ref().and_then(|r| r.id.clone()).filter(|s| !s.is_empty()).map(|id| vec![id]);
    let report_id = report.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
    let hint = str_at(&report, &["input", "hint"]).unwrap_or_default().to_string();

    let outcome = resolve_outcome_for_sync(opts.db, &report_id).await;
    let title = js_slice(&hint, 500);
    let investigation: InvestigationRecord = client
        .create_investigation(
            project_id,
            &CreateInvestigationBody {
                title: if title.is_empty() { "Untitled investigation".into() } else { title },
                hint: Some(hint.clone()),
                repository_ids,
                idempotency_key: Some(idempotency_key(&report_id, "investigation")),
                outcome,
            },
        )
        .await?;

    let content = js_json(&report);
    let digest = hex::encode(Sha256::digest(content.as_bytes()));
    client
        .create_evidence(
            project_id,
            &investigation.id,
            &CreateEvidenceBody {
                kind: REPORT_EVIDENCE_TYPE.into(),
                source: REPORT_EVIDENCE_SOURCE.into(),
                title: REPORT_EVIDENCE_TITLE.into(),
                content,
                content_format: REPORT_CONTENT_FORMAT.into(),
                payload: Some(serde_json::json!({ "kind": REPORT_EVIDENCE_KIND, "report": report })),
                idempotency_key: Some(idempotency_key(&report_id, &format!("report:{digest}"))),
            },
        )
        .await?;

    // Stage 1 dual-write: additive, best-effort provenance graph.
    write_investigation_provenance(client, project_id, &investigation.id, &report).await?;

    let unattended = report.get("unattended").filter(|u| u.is_object());
    let agent = match unattended {
        Some(u) if u.get("engineOnly").and_then(Value::as_bool) == Some(true) => "Horus background worker · engine only",
        Some(_) => "Horus background worker",
        None => "Horus CLI",
    };
    let model = unattended
        .filter(|u| u.get("status").and_then(Value::as_str) == Some("completed"))
        .and_then(|u| u.get("model")?.as_str())
        .map(str::to_string);
    let logs = opts.run_activity.map(|events| {
        let judgment: Option<RunLogResult> =
            report.get("aiJudgment").and_then(|j| serde_json::from_value(j.clone()).ok());
        worker_run_logs(events, judgment.as_ref())
    });
    let metadata = AgentRunBody {
        agent: Some(agent.into()),
        model,
        started_at: opts.run_timing.as_ref().map(|t| t.0.clone()),
        ended_at: opts.run_timing.as_ref().map(|t| t.1.clone()),
        logs_format: logs.as_ref().map(|l| l.logs_format.clone()),
        logs: logs.map(|l| l.logs),
        cli_version: Some(HORUS_VERSION.into()),
        summary: report.get("summary").and_then(Value::as_str).map(str::to_string),
        ..Default::default()
    };
    let run = client
        .create_agent_run(
            project_id,
            &investigation.id,
            &AgentRunBody {
                repository_id: cfg.repository.as_ref().and_then(|r| r.id.clone()),
                status: Some("completed".into()),
                idempotency_key: Some(idempotency_key(&report_id, "run")),
                ..metadata.clone()
            },
        )
        .await?;
    // Memory sync may have created this stable run before inference completed; enrich it.
    if unattended.is_some() || opts.run_timing.is_some() || opts.run_activity.is_some() {
        client
            .update_agent_run(project_id, &investigation.id, &run.id, &metadata)
            .await?;
    }
    client
        .update_investigation(project_id, &investigation.id, &UpdateInvestigationBody { status: Some("completed".into()), ..Default::default() })
        .await?;

    Ok(CloudInvestigationRefs { project_id: project_id.into(), investigation_id: investigation.id, agent_run_id: Some(run.id) })
}

fn parse_ms(s: &str) -> f64 {
    chrono::DateTime::parse_from_rfc3339(s).map(|t| t.timestamp_millis() as f64).unwrap_or(f64::NAN)
}

fn find_report_evidence(evidence: Vec<EvidenceRecord>) -> Option<Value> {
    let mut sorted = evidence;
    // Newest first (a NaN date compares equal, like the JS comparator returning NaN).
    sorted.sort_by(|a, b| parse_ms(&b.created_at).partial_cmp(&parse_ms(&a.created_at)).unwrap_or(std::cmp::Ordering::Equal));
    let record = sorted.into_iter().find(|e| {
        e.source == REPORT_EVIDENCE_SOURCE && e.payload.get("kind").and_then(Value::as_str) == Some(REPORT_EVIDENCE_KIND)
    })?;
    // Prefer the structured payload mirror; fall back to the serialized content.
    match record.payload.get("report").filter(|r| !r.is_null() && *r != &Value::Bool(false)) {
        Some(r) => Some(r.clone()),
        None => serde_json::from_str(&record.content).ok(),
    }
}

/// Fetch a cloud investigation and reconstruct the saved report from its evidence. None when no
/// report snapshot is attached.
pub async fn fetch_investigation_report_from_cloud(
    client: &CloudClient,
    cfg: &CloudConfig,
    investigation_id: &str,
) -> Result<Option<Value>> {
    let project = cfg.project.as_ref().ok_or_else(|| anyhow!("Cloud config is missing a linked project."))?;
    client.get_investigation(&project.id, investigation_id).await?;
    let evidence = client.list_evidence(&project.id, investigation_id).await?;
    Ok(find_report_evidence(evidence))
}

pub async fn list_cloud_investigations(client: &CloudClient, cfg: &CloudConfig) -> Result<Vec<InvestigationRecord>> {
    let project = cfg.project.as_ref().ok_or_else(|| anyhow!("Cloud config is missing a linked project."))?;
    Ok(client.list_investigations(&project.id).await?.investigations)
}
