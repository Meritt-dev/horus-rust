//! IncidentBench runner: chronological replay of incident histories through the real startup-recall
//! and auto-capture paths, scored against independent relevance labels. Port of the TS
//! `scripts/incident-bench.ts`; method and case format in `docs/incident-bench.md`.
//!
//!   HORUS_BENCH_CASES=<dir of *.json cases> cargo run -q -p horus-engine --example incident_bench
//!
//! With `vectors`, a fixed index replays the local embedding lane exactly; without, keyword-only.
//! Every memory write goes to a fresh disposable SQLite file; nothing touches saved user storage.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use horus_db::create_local_db;
use horus_engine::auto_investigation_memory::{capture_investigation_memory, CaptureAction};
use horus_engine::memory::{create_local_memory_store, LocalMemoryStoreOpts};
use horus_engine::memory_db::SqliteMemoryStorage;
use horus_engine::memory_recall::{index_incident_hint, recall_startup_incidents, StartupRecallOpts};
use horus_engine::memory_store::{AuditActor, AuditCtx, MemoryStore, MemoryVectorIndex, VectorHit, VectorSearch, VectorUpsert};
use horus_engine::types::InvestigationReport;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct BenchCase {
    codebase: String,
    investigations: Vec<Row>,
    labels: BTreeMap<String, Vec<Vec<String>>>,
    vectors: Option<HashMap<String, Vectors>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Row {
    id: String,
    created_at: DateTime<Utc>,
    report: Value,
}

#[derive(Deserialize)]
struct Vectors {
    q: Vec<f64>,
    d: Vec<f64>,
}

/// Replays the host's memory index from precomputed vectors: cosine of query vs stored hint vectors.
struct FixedVectorIndex<'a> {
    vectors: &'a HashMap<String, Vectors>,
    rows: Mutex<Vec<(String, String, &'a [f64])>>,
}

#[async_trait]
impl MemoryVectorIndex for FixedVectorIndex<'_> {
    async fn upsert(&self, i: VectorUpsert) -> Result<()> {
        if let Some(v) = self.vectors.get(&i.claim) {
            let mut rows = self.rows.lock().unwrap();
            rows.retain(|(id, _, _)| *id != i.memory_id);
            rows.push((i.memory_id, i.repo, &v.d));
        }
        Ok(())
    }
    async fn search(&self, i: VectorSearch) -> Result<Vec<VectorHit>> {
        let Some(q) = self.vectors.get(&i.query).map(|v| &v.q) else { return Ok(vec![]) };
        let cos = |a: &[f64], b: &[f64]| {
            let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
            dot / (a.iter().map(|x| x * x).sum::<f64>() * b.iter().map(|x| x * x).sum::<f64>()).sqrt()
        };
        let mut hits: Vec<VectorHit> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, repo, _)| *repo == i.repo)
            .map(|(id, _, d)| VectorHit { memory_id: id.clone(), score: cos(q, d) })
            .collect();
        hits.sort_by(|a, b| b.score.total_cmp(&a.score));
        hits.truncate(i.limit as usize);
        Ok(hits)
    }
    async fn remove(&self, memory_id: &str) -> Result<()> {
        self.rows.lock().unwrap().retain(|(id, _, _)| id != memory_id);
        Ok(())
    }
}

/// The case `report` is the minimal projection auto-capture reads; fill the rest of the typed shape.
fn full_report(id: &str, projection: &Value) -> Result<InvestigationReport> {
    let mut report = json!({
        "id": id, "summary": "", "seeds": [], "evidence": [],
        "timeline": { "events": [], "boundaryCrossings": [] },
        "correlation": { "groups": [], "chains": [], "missing": [] },
        "findings": [], "suspectedCauses": [], "hypotheses": [], "similarIncidents": [],
        "gapAnalysis": { "gaps": [], "blindSpots": [], "confidenceCeiling": 1 },
        "graph": { "nodes": [], "edges": [] },
        "confidence": 0, "nextActions": [],
    });
    merge(&mut report, projection.as_object().context("report must be an object")?);
    let fill = |list: &mut Value, prefix: &str, defaults: Value| {
        for (n, el) in list.as_array_mut().into_iter().flatten().enumerate() {
            let mut full = defaults.clone();
            full["id"] = json!(format!("{prefix}{n}"));
            merge(&mut full, &el.as_object().cloned().unwrap_or_default());
            *el = full;
        }
    };
    fill(&mut report["hypotheses"], "h", json!({ "category": "", "statement": "", "confidence": 0, "supportingEvidenceIds": [],
        "contradictingEvidenceIds": [], "missingEvidence": [], "priorConfidence": 0, "verdict": "unconfirmed",
        "supportingPresent": 0, "contradictingPresent": 0, "rationale": "" }));
    // Case files are tool-neutral; any band Horus does not emit is below `possible`.
    for cause in report["suspectedCauses"].as_array_mut().into_iter().flatten() {
        if !matches!(cause["band"].as_str(), Some("highly-likely" | "likely" | "possible" | "observation")) {
            cause["band"] = json!("observation");
        }
    }
    fill(&mut report["timeline"]["boundaryCrossings"], "b", json!({ "queueName": "", "evidenceId": "" }));
    fill(&mut report["suspectedCauses"], "c", json!({ "title": "", "category": "", "sourceEvidenceIds": [], "affectedNodeIds": [],
        "baseScore": 0, "finalScore": 0, "confidence": 0, "band": "observation", "explanations": [] }));
    serde_json::from_value(report).with_context(|| format!("report {id} does not fit InvestigationReport"))
}

fn merge(into: &mut Value, from: &serde_json::Map<String, Value>) {
    for (k, v) in from {
        match (into.get_mut(k), v) {
            (Some(Value::Object(_)), Value::Object(inner)) => merge(&mut into[k], inner),
            _ => into[k] = v.clone(),
        }
    }
}

struct Replay {
    /// (investigation id, recalled report-id groups) in chronological order.
    recalled: Vec<(String, Vec<Vec<String>>)>,
    at: HashMap<String, DateTime<Utc>>,
}

async fn replay(bench: &BenchCase, with_vectors: bool) -> Result<Replay> {
    let dir = std::env::temp_dir().join(format!("horus-bench-{}", uuid::Uuid::new_v4()));
    let db = create_local_db(Some(dir.join("bench.db"))).await?;
    let store = create_local_memory_store(Arc::new(SqliteMemoryStorage::new(db.clone())), LocalMemoryStoreOpts::default());
    let fixed = bench.vectors.as_ref().filter(|_| with_vectors).map(|vectors| FixedVectorIndex { vectors, rows: Mutex::new(vec![]) });
    let index = fixed.as_ref().map(|f| f as &dyn MemoryVectorIndex);
    let audit = AuditCtx { actor: AuditActor::system(), note: Some("IncidentBench replay in isolated storage".into()) };
    let mut rows: Vec<&Row> = bench.investigations.iter().collect();
    rows.sort_by_key(|r| r.created_at);
    let mut out = Replay { recalled: vec![], at: rows.iter().map(|r| (r.id.clone(), r.created_at)).collect() };
    let result: Result<()> = async {
        for row in rows {
            let report = full_report(&row.id, &row.report)?;
            let now = row.created_at;
            let matches = recall_startup_incidents(&store, &report.input, StartupRecallOpts { now: Some(now), index, ..Default::default() }).await?;
            let mut groups = vec![];
            for m in matches {
                let ids = store
                    .get(&m.memory_id)
                    .await?
                    .and_then(|item| item.payload)
                    .and_then(|p| p.get("investigationIds").and_then(Value::as_array).cloned())
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                    .unwrap_or_else(|| vec![m.incident_id.clone().unwrap_or_default()]);
                groups.push(ids);
            }
            out.recalled.push((row.id.clone(), groups));
            let captured = capture_investigation_memory(&store, Some(&row.id), &report, now, &audit).await?;
            if let Some(memory_id) = captured.memory_id {
                if captured.action == CaptureAction::Created {
                    // Backdate to the replayed moment so later steps see it as already existing.
                    let (id, at) = (memory_id.clone(), horus_engine::memory_store::to_iso_string(&now));
                    db.with_conn(move |c| Ok(c.execute("UPDATE memory_item SET created_at = ?1 WHERE id = ?2", (at, id))?)).await?;
                }
                if let (Some(index), Some(repo)) = (index, report.input.repo.as_deref()) {
                    index_incident_hint(index, repo, &memory_id, &report.input.hint).await;
                }
            }
        }
        Ok(())
    }
    .await;
    db.end().await;
    let _ = std::fs::remove_dir_all(&dir);
    result.map(|_| out)
}

#[derive(Default, Clone, Copy)]
struct Score {
    repeats: usize,
    found: usize,
    unrelated: usize,
    clean: usize,
}

/// found = repeats whose related earlier incident is recalled; clean = unrelated incidents with no recall.
fn score(bench: &BenchCase, families: &[Vec<String>], run: &Replay) -> Result<Score> {
    let fam: HashMap<&str, usize> = families.iter().enumerate().flat_map(|(k, ids)| ids.iter().map(move |id| (id.as_str(), k))).collect();
    let mut s = Score::default();
    for (id, groups) in &run.recalled {
        let Some(&k) = fam.get(id.as_str()) else { bail!("{}: unlabelled investigation {id}", bench.codebase) };
        let relevant: HashSet<&str> =
            fam.iter().filter(|(other, kk)| **kk == k && run.at[**other] < run.at[id]).map(|(other, _)| *other).collect();
        let hit = groups.iter().any(|ids| ids.iter().any(|x| relevant.contains(x.as_str())));
        if relevant.is_empty() {
            s.unrelated += 1;
            s.clean += usize::from(groups.is_empty());
        } else {
            s.repeats += 1;
            s.found += usize::from(hit);
        }
    }
    Ok(s)
}

#[tokio::main]
async fn main() -> Result<()> {
    let dir = std::env::var("HORUS_BENCH_CASES").context("Set HORUS_BENCH_CASES to a directory of IncidentBench case files.")?;
    let mut files: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut results = vec![];
    let mut pooled: BTreeMap<String, Score> = BTreeMap::new();
    for file in files {
        let bench: BenchCase = serde_json::from_str(&std::fs::read_to_string(&file)?).with_context(|| format!("{}", file.display()))?;
        let modes: &[&str] = if bench.vectors.is_some() { &["embedding", "keyword-only"] } else { &["keyword-only"] };
        for mode in modes {
            let run = replay(&bench, *mode == "embedding").await?;
            for (label_set, families) in &bench.labels {
                let s = score(&bench, families, &run)?;
                results.push(json!({ "codebase": bench.codebase, "mode": mode, "labelSet": label_set,
                    "repeats": s.repeats, "found": s.found, "unrelated": s.unrelated, "clean": s.clean }));
                let p = pooled.entry(format!("{mode}/{label_set}")).or_default();
                p.repeats += s.repeats;
                p.found += s.found;
                p.unrelated += s.unrelated;
                p.clean += s.clean;
            }
        }
    }
    let rate = |n: usize, d: usize| if d == 0 { Value::Null } else { json!(n as f64 / d as f64) };
    let summary: Vec<Value> = pooled
        .iter()
        .map(|(key, p)| json!({ "key": key, "repeats": p.repeats, "found": p.found, "unrelated": p.unrelated, "clean": p.clean,
            "foundRate": rate(p.found, p.repeats), "cleanRate": rate(p.clean, p.unrelated) }))
        .collect();
    let out = serde_json::to_string_pretty(&json!({ "benchmark": "IncidentBench", "version": 0, "task": "startup-recall",
        "results": results, "pooled": summary }))?;
    if let Ok(path) = std::env::var("HORUS_BENCH_OUT") {
        std::fs::write(path, &out)?;
    }
    println!("{out}");
    Ok(())
}
