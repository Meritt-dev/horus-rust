//! Port of `packages/cli/src/commands/memory.ts` — the `horus memory` command group.
//!
//! `memory show <scope>` is the read-only synthesis of incident memory + the code-knowledge graph
//! for a scope, plus the PERSISTED authored memory items. The write/read leaves (`add`/`confirm`/
//! `forget`/`pin`/`list`/`link`/`unlink`/`detect`) are thin handlers over the local MemoryStore.
//! Each resolves the project fail-closed (HOR-46): an unresolved project is a hard error.
//!
//! HONESTY INVARIANT (spec §8): authored memory is CONTEXT ONLY — never read by scoring.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use horus_connectors::memory_index_for_env;
use horus_connectors::source::MemoryVectorIndexLike;
use horus_core::{find_repo_root, HorusConfig};
use horus_db::{
    get_investigation, get_latest_outcome_label, is_outcome_source, list_outcome_labels, list_queue_edges, open_db,
    record_outcome_label, summarize_outcome_labels, DbHandle, OutcomeLabel, OutcomeLabelInput, OutcomeLabelQuery,
};
use horus_engine::js::to_fixed;
use horus_engine::memory::{create_local_memory_store, derive_signature, derive_tags, LocalMemoryStoreOpts, LocalStore};
use horus_engine::memory_db::SqliteMemoryStorage;
use horus_engine::memory_detect::{detect_memory_edges, DetectMemoryDeps, DetectMemoryOpts, OutcomeResolver, OutcomeVerdict, ProposedEdge, Resolved};
use horus_engine::memory_recall::{read_incident_disposition, recall_memory, Certainty, RecallOptions, RecallQuery, RecalledMemory};
use horus_engine::memory_store::{
    AddLinkOpts, AuditActor, AuditActorKind, AuditCtx, LinkDetection, LocalMemoryStore, MemoryItem, MemoryOrigin, MemoryQuery,
    MemoryRel, MemoryStatus, MemoryStore, MemoryVectorIndex, NewMemoryItem, NewMemoryLink, NoopVectorIndex, PromoteProvenance,
    RemoveLinkOpts, RemoveLinkSpec, VectorUpsert,
};
use horus_engine::memory_view::{build_memory_view, MemoryViewDeps};
use horus_engine::render_memory::{memory_view_to_json, render_memory_view};
use horus_engine::router::{format_route_step, route, RouterCommand, RouterConditions};
use horus_engine::types::InvestigationReport;
use serde_json::{json, Value};

use crate::lib::vector_index::{LikeAsIndex, NoopAsLike};
use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::cloud::api::{CloudError, TeamMemoryItem, TeamMemoryListQuery, TeamMemoryPromoteInput};
use crate::lib::cloud::context_store::{is_cloud_active, read_cloud_config};
use crate::lib::cloud::memory_sync::{memory_sync_context, sync_linked_memory, MemorySyncOptions, MemorySyncStatus};
use crate::lib::cloud::session::{authed_client, repo_root_or_cwd};
use crate::lib::engine_code::{create_code, engine_edges, load_config, resolve_env};
use crate::lib::format::{bold, dim, green, red, yellow};

const MEMORY_KINDS: [&str; 6] = ["code-fact", "contract", "decision", "pitfall", "incident-pattern", "confirmed-outcome"];
const MEMORY_RELS: [&str; 3] = ["supersedes", "contradicts", "recurs-with"];
const DEFAULT_ADD_CONFIDENCE: f64 = 0.75;
const DEFAULT_CONFIRM_CONFIDENCE: f64 = 0.8;
const ALL_STATUSES: [MemoryStatus; 6] = [
    MemoryStatus::Fresh,
    MemoryStatus::PossiblyStale,
    MemoryStatus::Contradicted,
    MemoryStatus::Deprecated,
    MemoryStatus::Pinned,
    MemoryStatus::Forgotten,
];

pub async fn run(args: &MemoryArgs) -> Result<()> {
    let code = match &args.command {
        MemoryCommand::Show(a) => show(a).await,
        MemoryCommand::Add(a) => add(a).await,
        MemoryCommand::Confirm(a) => confirm(a).await,
        MemoryCommand::Forget(a) => forget(a).await,
        MemoryCommand::Pin(a) => set_status_leaf(a, MemoryStatus::Pinned, "Pinned").await,
        MemoryCommand::List(a) => list(a).await,
        MemoryCommand::Link(a) => link(a).await,
        MemoryCommand::Unlink(a) => unlink(a).await,
        MemoryCommand::Detect(a) => detect(a).await,
        MemoryCommand::Accuracy(a) => accuracy(a).await,
        MemoryCommand::Sync(a) => sync(a).await,
        MemoryCommand::Promote(a) => promote(a).await,
        MemoryCommand::Pull(a) => pull(a).await,
    };
    if code == 0 { Ok(()) } else { Err(SilentExit(code).into()) }
}

/// The TS outer `catch (err) { console.error(red(msg)); return 1; }`.
fn report(r: Result<u8>) -> u8 {
    r.unwrap_or_else(|err| {
        eprintln!("{}", red(&err.to_string()));
        1
    })
}

fn print_json(v: &Value) {
    println!("{}", horus_core::json::to_js_json_pretty(v).unwrap_or_default());
}

fn iso(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn audit(kind: AuditActorKind, note: Option<String>) -> AuditCtx {
    AuditCtx { actor: AuditActor { kind, id: None, name: None }, note }
}

/// Resolve the project (HOR-46 fail-closed): prints + returns None when unresolvable.
fn resolve_project(config: &HorusConfig, repo: Option<&str>) -> Option<String> {
    match resolve_env(config, repo).ok().map(|r| r.project).filter(|p| !p.is_empty()) {
        Some(p) => Some(p),
        None => {
            eprintln!("{}", red("Could not resolve a project — pass --repo <name> or run inside a repo."));
            None
        }
    }
}

fn project_root(config: &HorusConfig, project: &str) -> String {
    resolve_env(config, Some(project)).map(|r| r.path).unwrap_or_default()
}

fn local_store(db: &DbHandle, config: &HorusConfig, project: &str) -> LocalStore {
    let root = project_root(config, project);
    let sync_scope = memory_sync_context(Path::new(&root), project, None).map(|c| c.scope);
    create_local_memory_store(Arc::new(SqliteMemoryStorage::new(db.clone())), LocalMemoryStoreOpts { sync_scope })
}

/// `withStore` opening half: open the DB, run the startup (pull-only) sync, build the store.
async fn open_store(config: &HorusConfig, project: &str) -> Result<(DbHandle, LocalStore, String)> {
    let db = open_db().await?;
    let root = project_root(config, project);
    let _ = sync_linked_memory(&db, Path::new(&root), project, MemorySyncOptions { startup: true, ..Default::default() }).await;
    let store = local_store(&db, config, project);
    Ok((db, store, root))
}

fn sync_line(state: &MemorySyncStatus) -> String {
    format!(
        "Memory: {}; {} pending{}",
        state.state,
        state.pending,
        state.error.as_deref().map(|e| format!(" — {e}")).unwrap_or_default()
    )
}

/// `withStore` closing half (TS `finally`): sync + report, then close the pool.
async fn close_store(db: DbHandle, root: &str, project: &str) {
    if let Ok(state) = sync_linked_memory(&db, Path::new(root), project, MemorySyncOptions::default()).await {
        eprintln!("{}", sync_line(&state));
    }
    db.end().await;
}

// ── Vector index (M2): Source-when-available, Jaccard-Noop fallback ──────────────────────────────

/// Never fails: an unresolvable env falls back to the Jaccard Noop index.
fn build_vector_index(config: &HorusConfig, project: &str) -> LikeAsIndex {
    let fallback: Arc<dyn MemoryVectorIndexLike> = Arc::new(NoopAsLike(NoopVectorIndex::new()));
    match resolve_env(config, Some(project)) {
        Ok(renv) => LikeAsIndex(memory_index_for_env(&renv, Some(fallback.clone())).unwrap_or(fallback)),
        Err(_) => LikeAsIndex(fallback),
    }
}

/// Best-effort vector upsert — never blocks or fails the command.
async fn best_effort_upsert(index: &LikeAsIndex, memory_id: &str, claim: &str, repo: &str, scope: &str) {
    let _ = index
        .upsert(VectorUpsert { memory_id: memory_id.into(), claim: claim.into(), repo: repo.into(), scope: scope.into() })
        .await;
}

/// Parse `--evidence` values ("kind:ref" or bare "ref").
fn parse_evidence(values: &[String], captured_at: &str) -> Value {
    Value::Array(
        values
            .iter()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(|v| match v.find(':') {
                Some(idx) if idx > 0 => {
                    json!({ "kind": v[..idx].trim(), "ref": v[idx + 1..].trim(), "capturedAt": captured_at })
                }
                _ => json!({ "kind": "note", "ref": v, "capturedAt": captured_at }),
            })
            .collect(),
    )
}

/// JS `Number(s)`: blank → 0, otherwise a full numeric parse or NaN.
fn js_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() { 0.0 } else { t.parse().unwrap_or(f64::NAN) }
}

fn label_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// Project a recalled item into a machine-stable JSON object.
fn recalled_to_json(r: &RecalledMemory) -> Value {
    json!({
        "id": r.item.id,
        "kind": r.item.kind,
        "claim": r.item.claim,
        "scope": r.item.scope,
        "source": r.item.source,
        "storedStatus": r.item.status,
        "effectiveStatus": r.freshness.status,
        "confidence": r.item.confidence,
        "visibility": r.item.visibility,
        "origin": r.item.origin,
        "authorName": r.item.author_name,
        "evidence": r.item.evidence,
        "freshness": {
            "label": r.freshness.label,
            "ageDays": r.freshness.age_days,
            "verified": r.freshness.verified,
            "driftDetected": r.freshness.drift_detected,
        },
        "createdAt": iso(&r.item.created_at),
        "lastVerifiedAt": r.item.last_verified_at.as_ref().map(iso),
    })
}

/// Render the persisted authored items as a Markdown section.
fn render_stored_items(items: &[RecalledMemory]) -> String {
    let mut lines = vec!["## Stored memory items".to_string(), String::new()];
    if items.is_empty() {
        lines.push("_none on record_".into());
        return lines.join("\n");
    }
    for r in items {
        let conf = format!("{}%", to_fixed(r.item.confidence * 100.0, 0));
        let drift = if r.freshness.drift_detected { ", drift-detected" } else { "" };
        lines.push(format!("- [{}] {}", r.item.id, r.item.claim));
        lines.push(format!(
            "  - {} · scope: {} · {}{drift} · confidence: {conf}",
            r.item.kind,
            r.item.scope,
            label_str(&r.freshness.label)
        ));
        if r.item.origin == "cloud" {
            let who = match r.item.author_name.as_deref().filter(|a| !a.is_empty()) {
                Some(a) => format!("teammate {a}"),
                None => "a teammate".into(),
            };
            lines.push(format!("  - {}", dim(&format!("shared by {who} (team)"))));
        }
    }
    lines.join("\n")
}

/// Incident-family recall keys from a stored report; a partial/legacy report yields none.
fn derive_incident_keys(report: Option<&str>) -> (Option<String>, Option<Vec<String>>) {
    match report.and_then(|r| serde_json::from_str::<InvestigationReport>(r).ok()) {
        Some(full) => (Some(derive_signature(&full)), Some(derive_tags(&full))),
        None => (None, None),
    }
}

fn report_value(report: Option<&str>) -> Value {
    report.and_then(|r| serde_json::from_str(r).ok()).unwrap_or(Value::Null)
}

fn report_hint(report: &Value, title: &str) -> String {
    report.pointer("/input/hint").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| title.to_string())
}

// ── memory show <scope> ──────────────────────────────────────────────────────────────────────────

async fn show(a: &MemoryShowArgs) -> u8 {
    report(async {
        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return Ok(1) };
        let code = create_code(&config)?;
        let cwd = std::env::current_dir().unwrap_or_default();
        let repo_path = find_repo_root(&cwd).unwrap_or(cwd);
        let db = open_db().await?;
        let res: Result<u8> = async {
            let storage = SqliteMemoryStorage::new(db.clone());
            let queue_edges = list_queue_edges(&db, Some(&project), None).await.map(engine_edges).unwrap_or_default();
            let view = build_memory_view(
                &a.scope,
                MemoryViewDeps {
                    code: &code,
                    db: &storage,
                    queue_edges,
                    repo_path: repo_path.to_string_lossy().into_owned(),
                    project: project.clone(),
                },
            )
            .await;
            let store = local_store(&db, &config, &project);
            let vector_index = build_vector_index(&config, &project);
            let stored = recall_memory(
                &store,
                RecallQuery { query: MemoryQuery { repo: project.clone(), ..Default::default() }, text: Some(a.scope.clone()) },
                RecallOptions { limit: Some(50.0), vector_index: Some(&vector_index), ..Default::default() },
            )
            .await?;
            let next_steps = route(&RouterConditions {
                empty: stored.is_empty(),
                query: Some(a.scope.clone()),
                ..RouterConditions::new(RouterCommand::Memory)
            });
            if a.json {
                let mut parsed: Value = serde_json::from_str(&memory_view_to_json(&view))?;
                if let Value::Object(map) = &mut parsed {
                    map.insert("storedItems".into(), Value::Array(stored.iter().map(recalled_to_json).collect()));
                    map.insert("nextSteps".into(), serde_json::to_value(&next_steps)?);
                }
                print_json(&parsed);
            } else {
                println!("{}", render_memory_view(&view));
                println!();
                println!("{}", render_stored_items(&stored));
                for s in &next_steps {
                    println!("{}{}", dim("  Suggested next: "), format_route_step(s));
                }
            }
            Ok(0)
        }
        .await;
        db.end().await;
        res
    }
    .await)
}

// ── memory add <claim> ───────────────────────────────────────────────────────────────────────────

async fn add(a: &MemoryAddArgs) -> u8 {
    report(async {
        let text = a.claim.trim().to_string();
        if text.is_empty() {
            eprintln!("{}", red("A non-empty claim is required."));
            return Ok(1);
        }
        let disposition = match &a.outcome_file {
            Some(path) => read_incident_disposition(Some(&serde_json::from_str::<Value>(&std::fs::read_to_string(path)?)?)),
            None => None,
        };
        if a.outcome_file.is_some()
            && !disposition.as_ref().is_some_and(|d| {
                d.certainty == Certainty::Inferred
                    && !d.source_investigation.trim().is_empty()
                    && d.source_refs.iter().any(|r| !r.trim().is_empty())
            })
        {
            return Err(anyhow!("Outcome file requires an inferred disposition with sourceInvestigation and sourceRefs; use memory confirm for an attested outcome."));
        }
        let kind = a.kind.clone().unwrap_or_else(|| if disposition.is_some() { "incident-pattern".into() } else { "code-fact".into() });
        if disposition.is_some() && (kind != "incident-pattern" || a.scope != "repo") {
            return Err(anyhow!("An inferred disposition requires --kind incident-pattern and --scope repo."));
        }
        if !MEMORY_KINDS.contains(&kind.as_str()) {
            eprintln!(
                "{}",
                red(&format!("Unknown --kind \"{}\" (one of: {}).", a.kind.as_deref().unwrap_or("undefined"), MEMORY_KINDS.join(", ")))
            );
            return Ok(1);
        }
        let mut confidence = DEFAULT_ADD_CONFIDENCE;
        if let Some(c) = &a.confidence {
            let n = js_number(c);
            if !n.is_finite() || !(0.0..=1.0).contains(&n) {
                eprintln!("{}", red("--confidence must be a number between 0 and 1."));
                return Ok(1);
            }
            confidence = n;
        }

        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return Ok(1) };
        let scope = if a.scope.trim().is_empty() { "repo".to_string() } else { a.scope.trim().to_string() };
        let now = iso(&Utc::now());
        let mut item = NewMemoryItem {
            kind,
            claim: text.clone(),
            scope: scope.clone(),
            source: "human".into(),
            evidence: Some(parse_evidence(&a.evidence, &now)),
            confidence,
            repo: project.clone(),
            ..Default::default()
        };

        let (db, store, root) = open_store(&config, &project).await?;
        let res: Result<u8> = async {
            if let Some(d) = &disposition {
                let inv = get_investigation(&db, &d.source_investigation).await?;
                let Some(inv) = inv.filter(|i| i.project.as_deref() == Some(project.as_str())) else {
                    return Err(anyhow!("Investigation not found in this project: {}", d.source_investigation));
                };
                let (signature, tags) = derive_incident_keys(inv.report.as_deref());
                let rv = report_value(inv.report.as_deref());
                item.signature = signature;
                item.tags = tags;
                item.claim = format!("Inferred {}: {text}", label_str(&d.disposition));
                item.source = "derived".into();
                item.visibility = Some("private".into());
                item.payload = Some(json!({ "investigationId": inv.id, "hint": report_hint(&rv, &inv.title), "outcome": d }));
            }
            let created = store.add(item.clone(), &audit(AuditActorKind::User, None)).await?;
            if let Some(d) = &disposition {
                store
                    .add_link(
                        NewMemoryLink {
                            from_memory_id: created.id.clone(),
                            rel: "about-incident".into(),
                            to_kind: "incident".into(),
                            to_ref: d.source_investigation.clone(),
                            ..Default::default()
                        },
                        None,
                    )
                    .await?;
            }
            if a.json {
                print_json(&json!({ "ok": true, "id": created.id, "kind": created.kind, "scope": created.scope }));
            } else {
                println!("{}", green(&format!("Added memory item {} ({}, scope: {}).", created.id, created.kind, created.scope)));
            }
            best_effort_upsert(&build_vector_index(&config, &project), &created.id, &item.claim, &project, &scope).await;
            Ok(0)
        }
        .await;
        close_store(db, &root, &project).await;
        res
    }
    .await)
}

// ── memory confirm <investigationId> ─────────────────────────────────────────────────────────────

async fn confirm(a: &MemoryConfirmArgs) -> u8 {
    report(async {
        let id = a.investigation_id.trim().to_string();
        if id.is_empty() {
            eprintln!("{}", red("An investigation id is required."));
            return Ok(1);
        }
        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return Ok(1) };
        let db = open_db().await?;
        let res: Result<u8> = async {
            let inv = get_investigation(&db, &id).await?;
            let Some(inv) = inv.filter(|i| i.project.as_deref().is_none_or(|p| p.is_empty() || p == project)) else {
                eprintln!("{}", red(&format!("Investigation not found: {id}")));
                return Ok(1);
            };
            let rv = report_value(inv.report.as_deref());
            let summary = rv.get("summary").and_then(Value::as_str).unwrap_or("").trim().to_string();
            let outcome = if !summary.is_empty() {
                summary
            } else if !inv.summary.as_deref().unwrap_or("").trim().is_empty() {
                inv.summary.as_deref().unwrap_or("").trim().to_string()
            } else {
                inv.title.trim().to_string()
            };
            let claim = format!("Confirmed outcome for \"{}\": {outcome}", inv.title);
            let confidence = rv.get("confidence").and_then(Value::as_f64).filter(|c| c.is_finite()).unwrap_or(DEFAULT_CONFIRM_CONFIDENCE);
            let (signature, tags) = derive_incident_keys(inv.report.as_deref());
            let store = local_store(&db, &config, &project);
            let mut item = NewMemoryItem {
                kind: "confirmed-outcome".into(),
                claim: claim.clone(),
                scope: "repo".into(),
                source: "confirmed-outcome".into(),
                evidence: Some(json!([])),
                confidence,
                repo: project.clone(),
                visibility: Some("private".into()),
                signature,
                tags,
                ..Default::default()
            };
            if let Some(path) = &a.outcome_file {
                let d = read_incident_disposition(Some(&serde_json::from_str::<Value>(&std::fs::read_to_string(path)?)?))
                    .filter(|d| d.certainty == Certainty::Confirmed && d.source_investigation == id)
                    .ok_or_else(|| anyhow!("Outcome file requires a confirmed disposition, this investigation id, attester, verifiedAt and sourceRefs"))?;
                item.claim = format!(
                    "Attested {} for {}: {}{}",
                    label_str(&d.disposition),
                    inv.title,
                    d.actual_cause.as_deref().unwrap_or("Cause not established"),
                    d.resolution.as_deref().filter(|r| !r.is_empty()).map(|r| format!("; {r}")).unwrap_or_default()
                );
                item.last_verified_at = d
                    .verified_at
                    .as_deref()
                    .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                    .map(|v| v.with_timezone(&Utc));
                item.payload = Some(json!({ "investigationId": id, "hint": report_hint(&rv, &inv.title), "outcome": d }));
            }
            let created = store
                .add(item, &audit(AuditActorKind::User, Some(a.note.clone().unwrap_or_else(|| format!("confirmed from investigation {id}")))))
                .await?;
            store
                .add_link(
                    NewMemoryLink {
                        from_memory_id: created.id.clone(),
                        rel: "about-incident".into(),
                        to_kind: "incident".into(),
                        to_ref: id.clone(),
                        ..Default::default()
                    },
                    None,
                )
                .await?;
            if a.outcome_file.is_none() {
                record_outcome_label(
                    &db,
                    OutcomeLabelInput {
                        investigation_id: id.clone(),
                        resolved: "yes".into(),
                        source: "confirm".into(),
                        confirmed_cause: Some(outcome.clone()),
                        project: Some(project.clone()),
                        note: a.note.clone(),
                        ..Default::default()
                    },
                )
                .await?;
            }
            if a.json {
                print_json(&json!({ "ok": true, "id": created.id, "investigationId": id, "visibility": created.visibility }));
            } else {
                println!("{}", green(&format!("Confirmed outcome stored as {} (private) and linked to investigation {id}.", created.id)));
            }
            best_effort_upsert(&build_vector_index(&config, &project), &created.id, &claim, &project, "repo").await;
            let root = project_root(&config, &project);
            let sync = sync_linked_memory(&db, Path::new(&root), &project, MemorySyncOptions::default()).await?;
            eprintln!("{}", sync_line(&sync));
            Ok(0)
        }
        .await;
        db.end().await;
        res
    }
    .await)
}

// ── memory forget / pin ──────────────────────────────────────────────────────────────────────────

async fn set_status_leaf(a: &MemoryIdNoteArgs, status: MemoryStatus, verb: &str) -> u8 {
    report(async {
        let mem_id = a.id.trim().to_string();
        if mem_id.is_empty() {
            eprintln!("{}", red("A memory item id is required."));
            return Ok(1);
        }
        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, None) else { return Ok(1) };
        let (db, store, root) = open_store(&config, &project).await?;
        let res: Result<u8> = async {
            store.set_status(&mem_id, status, &audit(AuditActorKind::User, a.note.clone())).await?;
            if a.json {
                print_json(&json!({ "ok": true, "id": mem_id, "status": status.as_str() }));
            } else {
                println!("{}", green(&format!("{verb} {mem_id} (status: {}).", status.as_str())));
            }
            Ok(0)
        }
        .await;
        close_store(db, &root, &project).await;
        res
    }
    .await)
}

async fn forget(a: &MemoryIdNoteArgs) -> u8 {
    let code = set_status_leaf(a, MemoryStatus::Forgotten, "Forgot").await;
    if code == 0 {
        // Best-effort drop of the DERIVED vector; resolve the project QUIETLY.
        if let Ok(config) = load_config(&a.config) {
            if let Some(project) = resolve_env(&config, None).ok().map(|r| r.project).filter(|p| !p.is_empty()) {
                let _ = build_vector_index(&config, &project).remove(a.id.trim()).await;
            }
        }
    }
    code
}

// ── memory list ──────────────────────────────────────────────────────────────────────────────────

async fn list(a: &MemoryListArgs) -> u8 {
    report(async {
        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return Ok(1) };
        let (db, store, root) = open_store(&config, &project).await?;
        let res: Result<u8> = async {
            let status = if a.all { Some(ALL_STATUSES.to_vec()) } else { None };
            let vector_index = build_vector_index(&config, &project);
            let items = recall_memory(
                &store,
                RecallQuery { query: MemoryQuery { repo: project.clone(), status, ..Default::default() }, text: None },
                RecallOptions { limit: Some(200.0), vector_index: Some(&vector_index), ..Default::default() },
            )
            .await?;
            if a.json {
                print_json(&json!({ "project": project, "items": items.iter().map(recalled_to_json).collect::<Vec<_>>() }));
            } else {
                println!("{}", render_stored_items(&items));
            }
            Ok(0)
        }
        .await;
        close_store(db, &root, &project).await;
        res
    }
    .await)
}

// ── memory link / unlink / detect ────────────────────────────────────────────────────────────────

fn parse_rel(rel: &str) -> Option<MemoryRel> {
    match rel {
        "supersedes" => Some(MemoryRel::Supersedes),
        "contradicts" => Some(MemoryRel::Contradicts),
        "recurs-with" => Some(MemoryRel::RecursWith),
        _ => {
            eprintln!("{}", red(&format!("--rel must be one of: {}.", MEMORY_RELS.join(", "))));
            None
        }
    }
}

async fn link(a: &MemoryEdgeArgs) -> u8 {
    report(async {
        let (from, to) = (a.a.trim().to_string(), a.b.trim().to_string());
        if from.is_empty() || to.is_empty() {
            eprintln!("{}", red("Two memory item ids are required: `memory link <a> <b> --rel <rel>`."));
            return Ok(1);
        }
        let Some(rel) = parse_rel(&a.rel) else { return Ok(1) };
        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return Ok(1) };
        let (db, store, root) = open_store(&config, &project).await?;
        let res: Result<u8> = async {
            let l = store
                .add_link(
                    NewMemoryLink { from_memory_id: from, rel: rel.as_str().into(), to_kind: "memory".into(), to_ref: to, ..Default::default() },
                    Some(AddLinkOpts {
                        detection: Some(LinkDetection::Manual),
                        audit: Some(audit(AuditActorKind::User, a.note.clone())),
                        detail: None,
                    }),
                )
                .await?;
            if a.json {
                print_json(&json!({ "ok": true, "id": l.id, "rel": l.rel, "from": l.from_memory_id, "to": l.to_ref }));
            } else {
                println!("{}", green(&format!("Linked {} {} {} ({}).", l.from_memory_id, bold(&l.rel), l.to_ref, l.id)));
            }
            Ok(0)
        }
        .await;
        close_store(db, &root, &project).await;
        res
    }
    .await)
}

async fn unlink(a: &MemoryEdgeArgs) -> u8 {
    report(async {
        let (from, to) = (a.a.trim().to_string(), a.b.trim().to_string());
        if from.is_empty() || to.is_empty() {
            eprintln!("{}", red("Two memory item ids are required: `memory unlink <a> <b> --rel <rel>`."));
            return Ok(1);
        }
        let Some(rel) = parse_rel(&a.rel) else { return Ok(1) };
        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return Ok(1) };
        let (db, store, root) = open_store(&config, &project).await?;
        let res: Result<u8> = async {
            let removed = store
                .remove_link(
                    RemoveLinkSpec { from_memory_id: from.clone(), rel, to_ref: to.clone() },
                    Some(RemoveLinkOpts { audit: Some(audit(AuditActorKind::User, a.note.clone())) }),
                )
                .await?;
            if a.json {
                print_json(&json!({ "ok": true, "removed": removed, "rel": rel.as_str(), "from": from, "to": to }));
            } else if removed == 0 {
                println!("{}", dim(&format!("No {} link from {from} to {to} — nothing removed.", rel.as_str())));
            } else {
                println!("{}", green(&format!("Unlinked {from} {} {to} ({removed} edge removed).", bold(rel.as_str()))));
            }
            Ok(0)
        }
        .await;
        close_store(db, &root, &project).await;
        res
    }
    .await)
}

fn render_proposal(p: &ProposedEdge) -> String {
    format!(
        "  {} {} {} {} {}",
        dim(&format!("[{}]", label_str(&p.detection))),
        p.from_memory_id,
        bold(p.rel.as_str()),
        p.to_memory_id,
        dim(&format!("— {}", p.reason))
    )
}

/// CONTEXT-ONLY join: the latest outcome verdict for an investigation (never feeds scoring).
struct DbOutcomes(DbHandle);

#[async_trait]
impl OutcomeResolver for DbOutcomes {
    async fn outcome_for(&self, investigation_id: &str) -> Result<Option<OutcomeVerdict>> {
        let Some(label) = get_latest_outcome_label(&self.0, investigation_id).await? else { return Ok(None) };
        let resolved = match label.resolved.as_str() {
            "yes" => Resolved::Yes,
            "partly" => Resolved::Partly,
            _ => Resolved::No,
        };
        Ok(Some(OutcomeVerdict { investigation_id: investigation_id.into(), resolved, confirmed_cause: label.confirmed_cause }))
    }
}

async fn detect(a: &MemoryDetectArgs) -> u8 {
    report(async {
        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return Ok(1) };
        let vector_index = build_vector_index(&config, &project);
        let (db, store, root) = open_store(&config, &project).await?;
        let res: Result<u8> = async {
            let outcomes = DbOutcomes(db.clone());
            let proposals = detect_memory_edges(
                &store,
                DetectMemoryOpts { repo: project.clone(), limit: a.limit.map(f64::from) },
                DetectMemoryDeps { vector_index: Some(&vector_index), outcome_for: Some(&outcomes) },
            )
            .await?;
            if a.dry_run {
                if a.json {
                    print_json(&json!({ "ok": true, "dryRun": true, "proposed": proposals.len(), "applied": 0, "edges": proposals }));
                } else if proposals.is_empty() {
                    println!("{}", dim("No memory→memory edges proposed."));
                } else {
                    println!("{}", bold(&format!("Proposed {} edge(s) {}:", proposals.len(), dim("(dry run — nothing written)"))));
                    for p in &proposals {
                        println!("{}", render_proposal(p));
                    }
                    println!("{}", dim("Re-run without --dry-run to persist these edges."));
                }
                return Ok(0);
            }
            let mut applied = 0usize;
            for p in &proposals {
                let detection = serde_json::from_value::<LinkDetection>(serde_json::to_value(p.detection)?)?;
                store
                    .add_link(
                        NewMemoryLink {
                            id: p.id.clone(),
                            from_memory_id: p.from_memory_id.clone(),
                            rel: p.rel.as_str().into(),
                            to_kind: "memory".into(),
                            to_ref: p.to_memory_id.clone(),
                            ..Default::default()
                        },
                        Some(AddLinkOpts {
                            detection: Some(detection),
                            audit: Some(audit(AuditActorKind::System, Some(p.reason.clone()))),
                            detail: p.detail.clone(),
                        }),
                    )
                    .await?;
                applied += 1;
                if !a.json {
                    println!("{}{}", green("✓"), render_proposal(p));
                }
            }
            if a.json {
                print_json(&json!({ "ok": true, "dryRun": false, "proposed": proposals.len(), "applied": applied, "edges": proposals }));
            } else if applied == 0 {
                println!("{}", dim("No memory→memory edges proposed."));
            } else {
                println!("{}", green(&format!("Applied {applied} detected edge(s).")));
            }
            Ok(0)
        }
        .await;
        close_store(db, &root, &project).await;
        res
    }
    .await)
}

// ── memory sync / promote / pull (cloud) ─────────────────────────────────────────────────────────

fn cloud_fail(json: bool, msg: &str) -> u8 {
    if json {
        print_json(&json!({ "ok": false, "error": msg }));
    } else {
        eprintln!("{}", red(msg));
    }
    1
}

const NOT_LINKED: &str = "This repo isn't linked to a cloud project. Run `horus cloud link` first.";
const NOT_LOGGED_IN: &str = "Not logged in. Run `horus login` first.";

async fn sync(a: &MemorySyncArgs) -> u8 {
    let json = a.json;
    if a.limit == Some(0) {
        return cloud_fail(json, "--limit must be a positive integer");
    }
    let root = repo_root_or_cwd(None);
    let cfg = read_cloud_config(&root);
    let Some(cloud_project) = cfg.as_ref().filter(|c| is_cloud_active(Some(c))).and_then(|c| c.project.clone()) else {
        return cloud_fail(json, NOT_LINKED);
    };
    if authed_client().is_none() {
        return cloud_fail(json, NOT_LOGGED_IN);
    }
    let config = match load_config(&a.config) {
        Ok(c) => c,
        Err(err) => return cloud_fail(json, &err.to_string()),
    };
    let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return 1 };
    let db = match open_db().await {
        Ok(db) => db,
        Err(err) => return cloud_fail(json, &err.to_string()),
    };
    let res: Result<u8> = async {
        if a.dry_run {
            let items = local_store(&db, &config, &project)
                .query(MemoryQuery {
                    repo: project.clone(),
                    origin: Some(MemoryOrigin::Local),
                    status: Some(ALL_STATUSES.to_vec()),
                    ..Default::default()
                })
                .await?;
            println!("{}", horus_core::json::to_js_json(&json!({ "dryRun": true, "eligible": items.len(), "target": cloud_project.id }))?);
            return Ok(0);
        }
        let state = sync_linked_memory(
            &db,
            &root,
            &project,
            MemorySyncOptions {
                resolve: a.resolve.clone(),
                choice: a.choice.clone(),
                restore: a.restore.clone(),
                limit: a.limit.map(|l| l as usize),
                ..Default::default()
            },
        )
        .await?;
        if json {
            println!("{}", horus_core::json::to_js_json_pretty(&state)?);
        } else {
            println!(
                "Memory: {}; {}/{} synced, {} pending, {} excluded, {} failed{}",
                state.state,
                state.synced,
                state.eligible,
                state.pending,
                state.excluded,
                state.failed,
                state.error.as_deref().map(|e| format!(" — {e}")).unwrap_or_default()
            );
        }
        Ok(if state.failed > 0 || state.error.as_deref().is_some_and(|e| !e.is_empty()) { 1 } else { 0 })
    }
    .await;
    db.end().await;
    res.unwrap_or_else(|err| cloud_fail(json, &err.to_string()))
}

/// PRIVACY CHOKE POINT: a positive allowlist — `payload` is NEVER serialized.
fn to_promote_input(item: &MemoryItem) -> TeamMemoryPromoteInput {
    TeamMemoryPromoteInput {
        origin_client_id: item.id.clone(),
        kind: item.kind.clone(),
        claim: item.claim.clone(),
        scope: item.scope.clone(),
        source: item.source.clone(),
        status: Some(item.status.clone()),
        confidence: Some(Some(item.confidence)),
        content_hash: Some(item.last_verified_hash.clone()),
        provenance: Some(serde_json::Map::new()),
    }
}

async fn promote(a: &MemoryPromoteArgs) -> u8 {
    let json = a.json;
    let mem_id = a.id.trim().to_string();
    if mem_id.is_empty() {
        return cloud_fail(json, "A memory item id is required.");
    }
    let root = repo_root_or_cwd(None);
    let cfg = read_cloud_config(&root);
    let Some(cloud_project) = cfg.as_ref().filter(|c| is_cloud_active(Some(c))).and_then(|c| c.project.clone()) else {
        return cloud_fail(json, NOT_LINKED);
    };
    let Some(session) = authed_client() else { return cloud_fail(json, NOT_LOGGED_IN) };
    let config = match load_config(&a.config) {
        Ok(c) => c,
        Err(err) => return cloud_fail(json, &err.to_string()),
    };
    let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return 1 };
    let db = match open_db().await {
        Ok(db) => db,
        Err(err) => return cloud_fail(json, &err.to_string()),
    };
    let res: Result<u8> = async {
        let store = local_store(&db, &config, &project);
        let Some(row) = store.get(&mem_id).await? else { return Ok(cloud_fail(json, &format!("Memory item not found: {mem_id}"))) };
        if row.kind == "confirmed-outcome" || row.source == "confirmed-outcome" {
            return Ok(cloud_fail(json, "Refusing to promote a confirmed-outcome item — it stays private (spec §5.2)."));
        }
        if row.origin == "cloud" {
            if json {
                print_json(&json!({ "ok": true, "id": mem_id, "alreadyTeam": true }));
            } else {
                println!("{}", dim(&format!("{mem_id} is already a team item — nothing to promote.")));
            }
            return Ok(0);
        }
        let res = session.client.promote_team_memory(&cloud_project.id, &[to_promote_input(&row)]).await?;
        let Some(promoted) = res.items.iter().find(|it| it.origin_client_id == mem_id) else {
            return Ok(cloud_fail(
                json,
                &format!(
                    "The server did not promote {mem_id} (skipped {}/{}). Local state unchanged.",
                    horus_engine::js::number_string(res.skipped),
                    horus_engine::js::number_string(res.total)
                ),
            ));
        };
        let updated = store
            .mark_promoted(
                &mem_id,
                PromoteProvenance { cloud_id: promoted.id.clone(), author_name: promoted.author_name.clone() },
                &audit(AuditActorKind::User, Some(format!("promoted to team {}", cloud_project.slug))),
            )
            .await?;
        if json {
            print_json(&json!({ "ok": true, "id": mem_id, "cloudId": promoted.id, "visibility": updated.visibility, "origin": updated.origin }));
        } else {
            println!("{}", green(&format!("Promoted {mem_id} to team memory ({}) — now visible to teammates.", cloud_project.slug)));
        }
        Ok(0)
    }
    .await;
    db.end().await;
    res.unwrap_or_else(|err| cloud_fail(json, &err.to_string()))
}

const TEAM_PULL_PAGE_LIMIT: u32 = 200;
const TEAM_PULL_MAX_PAGES: usize = 10_000;

fn format_age(ms: f64) -> String {
    let mins = (ms / 60_000.0).floor() as i64;
    if mins < 1 {
        return "just now".into();
    }
    if mins < 60 {
        return format!("{mins}m ago");
    }
    let hrs = mins / 60;
    if hrs < 24 {
        return format!("{hrs}h ago");
    }
    format!("{}d ago", hrs / 24)
}

async fn pull(a: &MemoryPullArgs) -> u8 {
    let json = a.json;
    let root = repo_root_or_cwd(None);
    let cfg = read_cloud_config(&root);
    let Some(cloud_project) = cfg.as_ref().filter(|c| is_cloud_active(Some(c))).and_then(|c| c.project.clone()) else {
        return cloud_fail(json, NOT_LINKED);
    };
    let Some(session) = authed_client() else { return cloud_fail(json, NOT_LOGGED_IN) };
    let config = match load_config(&a.config) {
        Ok(c) => c,
        Err(err) => return cloud_fail(json, &err.to_string()),
    };
    let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return 1 };
    let db = match open_db().await {
        Ok(db) => db,
        Err(err) => return cloud_fail(json, &err.to_string()),
    };
    let res: Result<u8> = async {
        let store = local_store(&db, &config, &project);
        let vector_index = build_vector_index(&config, &project);

        // 1. FULL pull (since='0'), paginated; offline serves the stale cache.
        let mut items: Vec<TeamMemoryItem> = vec![];
        let mut since = "0".to_string();
        for _ in 0..TEAM_PULL_MAX_PAGES {
            let page = session
                .client
                .list_team_memory_since(
                    &cloud_project.id,
                    &TeamMemoryListQuery { since: since.clone(), limit: Some(TEAM_PULL_PAGE_LIMIT), include_deleted: true, search: None },
                )
                .await;
            let page = match page {
                Ok(p) => p,
                Err(CloudError::Offline(_)) => {
                    let cached = store.query(MemoryQuery { repo: project.clone(), origin: Some(MemoryOrigin::Cloud), ..Default::default() }).await?;
                    let newest = cached.iter().map(|c| c.pulled_at.map(|t| t.timestamp_millis()).unwrap_or(0)).max().unwrap_or(0);
                    let note = if newest > 0 {
                        format!("stale — last pulled {}", format_age((Utc::now().timestamp_millis() - newest) as f64))
                    } else {
                        "stale — never pulled".into()
                    };
                    if json {
                        print_json(&json!({ "ok": true, "offline": true, "stale": true, "cached": cached.len(), "note": note }));
                    } else {
                        println!("{}", yellow(&format!("Offline — serving {} cached team item(s) ({note}).", cached.len())));
                    }
                    return Ok(0);
                }
                Err(err) => return Err(err.into()),
            };
            items.extend(page.items);
            match page.next_cursor.filter(|c| page.has_more && !c.is_empty()) {
                Some(next) => since = next,
                None => break,
            }
        }

        // 2. Apply: upsert live items as cache rows + re-embed locally; tombstones drop.
        let mut keep_ids: Vec<String> = vec![];
        let mut upserted = 0usize;
        for it in &items {
            if it.deleted_at.as_deref().is_some_and(|d| !d.is_empty()) {
                let _ = vector_index.remove(&it.origin_client_id).await;
                continue;
            }
            let row = NewMemoryItem {
                id: it.origin_client_id.clone(),
                kind: it.kind.clone(),
                claim: it.claim.clone(),
                scope: it.scope.clone(),
                source: it.source.clone(),
                status: Some(if it.status.is_empty() { "fresh".into() } else { it.status.clone() }),
                confidence: it.confidence.unwrap_or(0.0),
                evidence: Some(json!([])),
                repo: project.clone(),
                visibility: Some("team".into()),
                cloud_id: Some(it.id.clone()),
                author_name: it.author_name.clone(),
                ..Default::default()
            };
            store.upsert_cached(row, &audit(AuditActorKind::System, Some("memory pull".into()))).await?;
            best_effort_upsert(&vector_index, &it.origin_client_id, &it.claim, &project, &it.scope).await;
            keep_ids.push(it.origin_client_id.clone());
            upserted += 1;
        }

        // 3. Reconcile — ONLY after a fully-successful pull.
        let removed = store.reconcile_cache(&project, &keep_ids).await?;
        if json {
            print_json(&json!({ "ok": true, "project": project, "pulled": upserted, "removed": removed, "total": items.len() }));
        } else {
            println!(
                "{}",
                green(&format!(
                    "Pulled {upserted} team memory item(s){}.",
                    if removed > 0 { format!(", dropped {removed} stale") } else { String::new() }
                ))
            );
            println!("{}", dim("Team items are read-only locally — re-promote to change one. Vectors stay local."));
        }
        Ok(0)
    }
    .await;
    db.end().await;
    res.unwrap_or_else(|err| cloud_fail(json, &err.to_string()))
}

// ── memory accuracy ──────────────────────────────────────────────────────────────────────────────

const DEFAULT_ACCURACY_WINDOW_DAYS: u32 = 30;
const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;

fn outcome_label_to_json(l: &OutcomeLabel) -> Value {
    json!({
        "id": l.id,
        "investigationId": l.investigation_id,
        "resolved": l.resolved,
        "source": l.source,
        "confirmedCause": l.confirmed_cause,
        "note": l.note,
        "project": l.project,
        "at": iso(&l.at),
    })
}

async fn accuracy(a: &MemoryAccuracyArgs) -> u8 {
    report(async {
        if let Some(s) = a.source.as_deref().filter(|s| !is_outcome_source(s)) {
            eprintln!("{}", red(&format!("Unknown --source \"{s}\" (one of: feedback, confirm).")));
            return Ok(1);
        }
        let now_ms = Utc::now().timestamp_millis();
        let (since, window): (Option<DateTime<Utc>>, String) = if a.all {
            (None, "all time".into())
        } else if let Some(s) = &a.since {
            let ms = horus_engine::js::date_parse(s);
            if ms.is_nan() {
                eprintln!("{}", red("--since must be a parseable date (e.g. 2026-06-01 or an ISO timestamp)."));
                return Ok(1);
            }
            let parsed = DateTime::from_timestamp_millis(ms as i64).unwrap_or_default();
            let day: String = iso(&parsed).chars().take(10).collect();
            (Some(parsed), format!("since {day}"))
        } else if let Some(days) = a.days {
            if days == 0 {
                eprintln!("{}", red("--days must be a positive number."));
                return Ok(1);
            }
            (DateTime::from_timestamp_millis(now_ms - days as i64 * MS_PER_DAY), format!("last {days} day(s)"))
        } else {
            (
                DateTime::from_timestamp_millis(now_ms - DEFAULT_ACCURACY_WINDOW_DAYS as i64 * MS_PER_DAY),
                format!("last {DEFAULT_ACCURACY_WINDOW_DAYS} day(s) (default — pass --all for full history)"),
            )
        };

        let config = load_config(&a.config)?;
        let Some(project) = resolve_project(&config, a.repo.as_deref()) else { return Ok(1) };
        let db = open_db().await?;
        let res: Result<u8> = async {
            let labels = list_outcome_labels(
                &db,
                OutcomeLabelQuery {
                    project: Some(project.clone()),
                    source: a.source.clone(),
                    since,
                    limit: a.limit.map(i64::from),
                    ..Default::default()
                },
            )
            .await?;
            let summary = summarize_outcome_labels(&labels);
            if a.json {
                print_json(&json!({
                    "project": project,
                    "source": a.source,
                    "since": since.as_ref().map(iso),
                    "window": window,
                    "summary": summary,
                    "labels": labels.iter().map(outcome_label_to_json).collect::<Vec<_>>(),
                }));
            } else {
                let pct = |n: f64| format!("{}%", to_fixed(n * 100.0, 0));
                println!("{}{}", bold(&format!("Investigation accuracy — {project}")), dim(&format!("  ·  window: {window}")));
                if summary.evaluated == 0 {
                    println!(
                        "{}",
                        dim(&format!(
                            "No outcome labels in this window ({window}). Confirm an investigation (`horus memory confirm <id>`) or leave feedback (`horus feedback <id> --resolved yes|partly|no`) to add to the eval set{}",
                            if a.all { "." } else { ", or pass --all to include older labels." }
                        ))
                    );
                } else {
                    println!(
                        "  Pointed at the cause: {} {}",
                        green(&pct(summary.accuracy)),
                        dim(&format!("(weighted {}) over {} investigation(s)", pct(summary.weighted_score), summary.evaluated))
                    );
                    println!(
                        "  Verdicts: {}, {}, {}",
                        green(&format!("{} yes", summary.counts.yes)),
                        yellow(&format!("{} partly", summary.counts.partly)),
                        red(&format!("{} no", summary.counts.no))
                    );
                    println!(
                        "{}",
                        dim(&format!(
                            "  Source: {} confirm, {} feedback · {} total attestation(s)",
                            summary.by_source.confirm, summary.by_source.feedback, summary.attestations
                        ))
                    );
                }
            }
            Ok(0)
        }
        .await;
        db.end().await;
        res
    }
    .await)
}
