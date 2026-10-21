//! HOR-384 — `horus packet`: a compact, honesty-framed projection of an investigation for an
//! agent's context window. Port of `packages/cli/src/commands/packet.ts`.
//!
//! Two input modes, auto-detected: a saved investigation id (UUID) → load the persisted report
//! (no re-query) and project it; a hint → run a fresh investigation, then project it.
//! Remembered context is recalled best-effort from the local memory store — it NEVER blocks
//! packet delivery and is CONTEXT ONLY (never live evidence, never scoring).

use std::path::Path;
use std::sync::{Arc, LazyLock};

use anyhow::Result;
use horus_connectors::git::provider::collect_repo_state;
use horus_db::{get_investigation, open_db, DbHandle};
use horus_engine::memory::{create_local_memory_store, LocalMemoryStoreOpts};
use horus_engine::memory_db::SqliteMemoryStorage;
use horus_connectors::memory_index_for_env;
use horus_connectors::source::{MemoryVectorHit, MemoryVectorIndexLike, SourceMemorySearchRequest, SourceMemoryUpsertRequest};
use horus_core::ResolvedEnvironment;
use horus_engine::memory_recall::{recall_memory, RecallCodeProvider, RecallOptions, RecallQuery};
use horus_engine::memory_store::{MemoryQuery, MemoryVectorIndex, NoopVectorIndex, VectorHit, VectorSearch, VectorUpsert};
use horus_engine::migrate_report::migrate_report;
use horus_engine::packet::{
    build_packet, packet_to_json, render_packet_markdown, AgentPreset, PacketFreshness, PacketOptions, RepoIdentity,
    RuntimeWindow,
};
use horus_engine::types::InvestigationReport;
use regex::Regex;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::cloud::session::repo_root_or_cwd;
use crate::lib::format::{dim, red};
use crate::lib::investigation_runner::{
    build_investigation_context, dispose_investigation_context, js_number, run_one_investigation, BuildContextOptions,
    InvestigationContext, RunInvestigationInput,
};
use crate::lib::freshness::{commits_since, compute_freshness, read_index_meta, semantic_search_ready, FreshnessEvidence, FreshnessOpts};

/// Standard UUID (the id `engine.investigate()` mints).
static UUID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap());

/// Valid `--for` presets, in TS Set order.
const PRESETS: [(&str, AgentPreset); 3] =
    [("claude", AgentPreset::Claude), ("cursor", AgentPreset::Cursor), ("generic", AgentPreset::Generic)];

/// Cap on remembered-context items recalled for a packet (build_packet caps the surfaced subset).
const PACKET_MEMORY_LIMIT: f64 = 8.0;

/// Freshness inputs for the honesty header, plus the semantic-search-readiness flag (which is
/// NOT part of `compute_freshness().caveats` and must be passed explicitly).
async fn compute_packet_freshness(repo_root: &Path, report: &InvestigationReport) -> Result<PacketFreshness> {
    let meta = read_index_meta(repo_root);
    let commits = match meta.as_ref().and_then(|m| m.last_indexed_at.as_deref()).filter(|s| !s.is_empty()) {
        Some(at) => commits_since(repo_root, at).await,
        None => None,
    };
    let evidence: Vec<FreshnessEvidence> = report
        .evidence
        .iter()
        .map(|e| FreshnessEvidence {
            source: serde_json::to_value(&e.source).ok().and_then(|v| v.as_str().map(str::to_string)),
            timestamp: e.timestamp.clone(),
        })
        .collect();
    let now = horus_db::format_ts(&chrono::Utc::now());
    let f = compute_freshness(FreshnessOpts {
        repo_root,
        evidence: &evidence,
        now_iso: &now,
        meta: Some(meta.clone()),
        commits_since_index: commits,
        any_runtime_connector: Some(report.source_status.as_ref().is_some_and(|s| s.sources.iter().any(|x| x.configured))),
    });
    Ok(PacketFreshness {
        index_stale: Some(f.index_stale),
        commits_since_index: Some(f.commits_since_index),
        runtime_window: Some(f.runtime_window.map(|w| RuntimeWindow { from_iso: w.from_iso, to_iso: w.to_iso })),
        caveats: Some(f.caveats),
        semantic_search_ready: Some(semantic_search_ready(meta.as_ref())),
    })
}

/// Free-text relevance query for recall: hint, path scope, first seed, headline cause title.
fn packet_memory_query(report: &InvestigationReport, project: &str) -> RecallQuery {
    let parts = [
        Some(report.input.hint.as_str()),
        report.input.scope.as_deref(),
        report.seeds.first().map(|s| s.name.as_str()),
        report.suspected_causes.first().map(|c| c.title.as_str()),
    ];
    let text = parts.into_iter().flatten().filter(|p| !p.trim().is_empty()).collect::<Vec<_>>().join(" ");
    RecallQuery { query: MemoryQuery { repo: project.to_string(), ..Default::default() }, text: Some(text) }
}

/// Recall relevant remembered context. BEST-EFFORT and fail-closed (HOR-46): no project → no
/// memory; any store/recall error → no memory. No live source host on the saved-id path, so
/// drift detection is skipped.
async fn recall_packet_memory(db: &DbHandle, project: Option<&str>, report: &InvestigationReport) -> Vec<horus_engine::memory_recall::RecalledMemory> {
    let Some(project) = project.filter(|p| !p.trim().is_empty()) else { return Vec::new() };
    let store = create_local_memory_store(Arc::new(SqliteMemoryStorage::new(db.clone())), LocalMemoryStoreOpts::default());
    recall_memory(
        &store,
        packet_memory_query(report, project),
        RecallOptions { limit: Some(PACKET_MEMORY_LIMIT), ..Default::default() },
    )
    .await
    .unwrap_or_default()
}

/// Repo identity — WHICH checkout produced the evidence. Best-effort git (null fields on failure).
async fn collect_packet_repo(name: Option<&str>, repo_path: &Path) -> RepoIdentity {
    let state = collect_repo_state(repo_path).await;
    RepoIdentity {
        name: name.filter(|n| !n.trim().is_empty()).map(str::to_string),
        branch: state.as_ref().and_then(|s| s.branch.clone()),
        commit: state.as_ref().and_then(|s| s.head_sha.clone()),
    }
}

fn emit_packet(report: &InvestigationReport, json: bool, opts: PacketOptions) -> Result<()> {
    let packet = build_packet(report, opts);
    if json {
        println!("{}", horus_core::json::to_js_json_pretty(&packet_to_json(&packet))?);
    } else {
        println!("{}", render_packet_markdown(&packet));
    }
    Ok(())
}

fn report_failure(err: &anyhow::Error, fallback: &str) {
    let msg = err.to_string();
    eprintln!("{}", red(if msg.trim().is_empty() { fallback } else { &msg }));
    if std::env::var_os("HORUS_DEBUG").is_some() {
        eprintln!("{}", dim(&format!("{err:?}")));
    }
}

pub async fn run(args: &PacketArgs) -> Result<()> {
    // `--for` is presentation-only; validate up front so an agent gets a clear error.
    let mut preset = None;
    if let Some(f) = &args.r#for {
        let Some((_, p)) = PRESETS.iter().find(|(n, _)| n == f) else {
            let names: Vec<&str> = PRESETS.iter().map(|(n, _)| *n).collect();
            eprintln!("{}", red(&format!("Unknown --for preset \"{f}\". Expected one of: {}.", names.join(", "))));
            return Err(SilentExit(1).into());
        };
        preset = Some(*p);
    }

    // ── Saved-id path: load the persisted report, no re-query ───────────────────
    if UUID_RE.is_match(&args.hint_or_id) {
        let db = open_db().await?;
        let result = saved_packet(&db, args, preset).await;
        db.end().await;
        return match result {
            Err(err) if err.downcast_ref::<SilentExit>().is_none() => {
                report_failure(&err, "Failed to load investigation.");
                Err(SilentExit(1).into())
            }
            other => other,
        };
    }

    // ── Hint path: run a fresh investigation, then project it ────────────────────
    match hint_packet(args, preset).await {
        Err(err) if err.downcast_ref::<SilentExit>().is_none() => {
            report_failure(&err, "Packet generation failed (unknown error).");
            Err(SilentExit(1).into())
        }
        other => other,
    }
}

async fn saved_packet(db: &DbHandle, args: &PacketArgs, preset: Option<AgentPreset>) -> Result<()> {
    let id = &args.hint_or_id;
    let Some(row) = get_investigation(db, id).await? else {
        eprintln!("{}", red(&format!("No investigation found: {id}")));
        return Err(SilentExit(1).into());
    };
    let Some(raw) = row.report else {
        eprintln!("{}", red(&format!("Investigation {id} has no stored report (run a newer investigation).")));
        return Err(SilentExit(1).into());
    };
    let report = migrate_report(serde_json::from_str(&raw)?)?;
    let repo_root = repo_root_or_cwd(None);
    let freshness = compute_packet_freshness(&repo_root, &report).await?;
    let repo = collect_packet_repo(report.input.repo.as_deref(), &repo_root).await;
    let memory = recall_packet_memory(db, report.input.repo.as_deref(), &report).await;
    emit_packet(
        &report,
        args.json,
        PacketOptions { preset, freshness: Some(freshness), memory: Some(memory), repo: Some(repo), ..Default::default() },
    )
}

async fn hint_packet(args: &PacketArgs, preset: Option<AgentPreset>) -> Result<()> {
    let config = horus_core::load_config(args.config.as_deref().map(Path::new), None)?;
    let renv = match horus_core::resolve_environment(
        &config,
        &horus_core::ResolveOptions { env: args.env.as_deref(), ..Default::default() },
    ) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{}", red(&err.to_string()));
            return Err(SilentExit(1).into());
        }
    };
    let repo_root = repo_root_or_cwd(Some(Path::new(&renv.path)));

    let ctx = match build_investigation_context(
        renv,
        BuildContextOptions { database_url: &config.database.url, service: args.service.clone(), ..Default::default() },
    )
    .await
    {
        Ok(c) => c,
        Err(err) => {
            // No source-intelligence connector configured — same hard requirement as `investigate`.
            eprintln!("{}", red(&err.to_string()));
            return Err(SilentExit(1).into());
        }
    };
    let result = hint_packet_with(args, preset, &ctx, &repo_root).await;
    // Close EVERY connector + the DB.
    dispose_investigation_context(ctx).await;
    result
}

async fn hint_packet_with(
    args: &PacketArgs,
    preset: Option<AgentPreset>,
    ctx: &InvestigationContext,
    repo_root: &Path,
) -> Result<()> {
    let timeout_sec = {
        let flag = args.timeout.as_deref().map(js_number).unwrap_or(0.0);
        let env = std::env::var("HORUS_INVESTIGATE_TIMEOUT_S").map(|v| js_number(&v)).unwrap_or(f64::NAN);
        let truthy = |n: f64| !n.is_nan() && n != 0.0;
        if truthy(flag) { flag } else if truthy(env) { env } else { 120.0 }
    };
    let report = run_one_investigation(
        RunInvestigationInput {
            hint: args.hint_or_id.clone(),
            scope: args.scope.clone(),
            since: args.since.clone(),
            service: args.service.clone(),
            ..Default::default()
        },
        ctx,
        Some((timeout_sec * 1000.0) as u64),
    )
    .await?;
    let freshness = compute_packet_freshness(repo_root, &report).await?;
    let project = ctx.renv.project.clone();
    let repo = collect_packet_repo(Some(&project), repo_root).await;

    // Remembered context: same DB + project, with the Source-when-available vector index for
    // relevance and the live code provider for read-time drift detection. Best-effort.
    let memory = if project.trim().is_empty() {
        Vec::new()
    } else {
        let store =
            create_local_memory_store(Arc::new(SqliteMemoryStorage::new(ctx.db.clone())), LocalMemoryStoreOpts::default());
        let index = packet_vector_index(&ctx.renv);
        let code = ctx.code.as_ref().map(BorrowedRecall);
        recall_memory(
            &store,
            packet_memory_query(&report, &project),
            RecallOptions {
                limit: Some(PACKET_MEMORY_LIMIT),
                vector_index: Some(&index),
                code: code.as_ref().map(|c| c as &dyn RecallCodeProvider),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_default()
    };
    emit_packet(
        &report,
        args.json,
        PacketOptions { preset, freshness: Some(freshness), memory: Some(memory), repo: Some(repo), ..Default::default() },
    )
}

// ── Vector-index bridge ───────────────────────────────────────────────────────────────────────
// needs upstreaming: the engine `MemoryVectorIndex` and connectors `MemoryVectorIndexLike` are
// structural mirrors (TS: one interface) with no adapter between them.

/// Engine `NoopVectorIndex` exposed as the connectors fallback seam.
struct NoopAsLike(NoopVectorIndex);

#[async_trait::async_trait]
impl MemoryVectorIndexLike for NoopAsLike {
    async fn upsert(&self, i: &SourceMemoryUpsertRequest) -> Result<()> {
        self.0
            .upsert(VectorUpsert { memory_id: i.memory_id.clone(), claim: i.claim.clone(), repo: i.repo.clone(), scope: i.scope.clone() })
            .await
    }
    async fn search(&self, i: &SourceMemorySearchRequest) -> Result<Vec<MemoryVectorHit>> {
        let hits = self.0.search(VectorSearch { query: i.query.clone(), repo: i.repo.clone(), limit: i.limit as f64 }).await?;
        Ok(hits.into_iter().map(|h| MemoryVectorHit { memory_id: h.memory_id, score: h.score }).collect())
    }
    async fn remove(&self, memory_id: &str) -> Result<()> {
        MemoryVectorIndex::remove(&self.0, memory_id).await
    }
}

/// A connectors index exposed as the engine recall seam.
struct LikeAsIndex(Arc<dyn MemoryVectorIndexLike>);

#[async_trait::async_trait]
impl MemoryVectorIndex for LikeAsIndex {
    async fn upsert(&self, i: VectorUpsert) -> Result<()> {
        self.0.upsert(&SourceMemoryUpsertRequest { memory_id: i.memory_id, claim: i.claim, repo: i.repo, scope: i.scope }).await
    }
    async fn search(&self, i: VectorSearch) -> Result<Vec<VectorHit>> {
        let hits = self.0.search(&SourceMemorySearchRequest { query: i.query, repo: i.repo, limit: i.limit as i64 }).await?;
        Ok(hits.into_iter().map(|h| VectorHit { memory_id: h.memory_id, score: h.score }).collect())
    }
    async fn remove(&self, memory_id: &str) -> Result<()> {
        self.0.remove(memory_id).await
    }
}

/// `CodeProviderRecallAdapter` over a borrowed provider (the engine adapter needs an owned `Arc`).
struct BorrowedRecall<'a>(&'a horus_connectors::source::SourceCodeProvider);

#[async_trait::async_trait]
impl RecallCodeProvider for BorrowedRecall<'_> {
    async fn get_node_content(&self, node_id: &str) -> Option<String> {
        use horus_engine::code_provider::CodeProvider;
        self.0.context(node_id).await.ok().and_then(|c| c.source_body.or(c.snippet))
    }
}

/// Source-when-available vector index for an env (nomic embeddings on the local host), composed
/// over a deterministic Jaccard `NoopVectorIndex` fallback. LOCAL-ONLY; never fails.
fn packet_vector_index(renv: &ResolvedEnvironment) -> LikeAsIndex {
    let fallback: Arc<dyn MemoryVectorIndexLike> = Arc::new(NoopAsLike(NoopVectorIndex::new()));
    LikeAsIndex(memory_index_for_env(renv, Some(fallback.clone())).unwrap_or(fallback))
}
