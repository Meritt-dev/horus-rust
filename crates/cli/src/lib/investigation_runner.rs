//! Shared investigation runner (HOR-CLI). Port of `packages/cli/src/lib/investigation-runner.ts`.
//!
//! Turns a resolved environment into a live engine call: resolve every connector, self-heal a
//! down source-intelligence host, degrade to runtime-only when it stays down, open the local DB,
//! call `investigate()` under a deadline, and tear every handle back down. Both
//! `horus investigate` and `horus watch` use it — do NOT duplicate this flow, extend it.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use horus_connectors::axiom::AxiomProvider;
use horus_connectors::bullmq::BullMQRuntimeProvider;
use horus_connectors::cloud_logs::{CloudLogsProvider, StructuredLogSource};
use horus_connectors::elasticsearch::{ElasticsearchLogsProvider, LogsProvider};
use horus_connectors::grafana::MetricsProvider;
use horus_connectors::lens::LensProvider;
use horus_connectors::mongodb::MongoStateProvider;
use horus_connectors::redis::RedisStateRuntimeProvider;
use horus_connectors::runtime_queue::QueueEvidenceProvider;
use horus_connectors::sentry::SentryProvider;
use horus_connectors::shopify::ShopifyProvider;
use horus_connectors::source::{SourceClientOptions, SourceCodeProvider, SourceHttpClient, SourceMemoryVectorIndex, SourceMemoryVectorIndexOptions};
use horus_connectors::state::{DatabaseStateProvider, StateProvider};
use horus_connectors::{
    additional_queues_for_env, additional_state_for_env, axiom_for_env, cloud_logs_for_env, code_for_env, code_for_url,
    lens_for_cloud, logs_for_env, metrics_for_env, mongo_for_env, postgres_for_env, queue_for_env, redis_state_for_env,
    sentry_for_env, shopify_for_env, Provider,
};
use horus_core::{redact_secrets, ResolvedEnvironment, ShopifyQuerySpec};
use horus_db::{get_investigation, open_db, DbHandle};
use horus_engine::gaps::ConnectorFlags;
use horus_engine::memory::{create_local_memory_store, LocalMemoryStoreOpts};
use horus_engine::memory_db::SqliteMemoryStorage;
use horus_engine::memory_recall::StartupIncident;
use horus_engine::score_cause::CauseCandidate;
use horus_engine::types::{IncidentContext, InvestigationInput, InvestigationReport};
use horus_engine::{investigate, EngineDeps};
use horus_eval::reranker::{apply_reranker, is_reranker_model, RerankerModel};
use serde_json::Value;

use crate::lib::cloud::auth_store::read_auth;
use crate::lib::cloud::context_store::read_cloud_config;
use crate::lib::cloud::memory_sync::{memory_sync_context, sync_linked_memory, MemorySyncOptions};
use crate::lib::vector_index::LikeAsIndex;
use crate::lib::ensure_host::resolve_source_host_url;
use crate::lib::format::{bold, yellow};
use crate::lib::freshness::{read_index_meta, STALE_INDEX_MS};

/// JS `Number(s)` for CLI/env numeric strings: trimmed, `""` → 0, invalid → NaN.
pub fn js_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    let radix = |p: &str, r: u32| u64::from_str_radix(p, r).map(|n| n as f64).unwrap_or(f64::NAN);
    match t.get(..2).map(str::to_ascii_lowercase).as_deref() {
        Some("0x") => return radix(&t[2..], 16),
        Some("0o") => return radix(&t[2..], 8),
        Some("0b") => return radix(&t[2..], 2),
        _ => {}
    }
    match t.trim_start_matches(['+', '-']) {
        "Infinity" => return if t.starts_with('-') { f64::NEG_INFINITY } else { f64::INFINITY },
        x if x.chars().any(|c| c.is_ascii_alphabetic() && c != 'e' && c != 'E') => return f64::NAN,
        _ => {}
    }
    t.parse().unwrap_or(f64::NAN)
}

/// Explain the startup match before current evidence is gathered.
pub fn format_startup_incident(item: &StartupIncident) -> String {
    let item = serde_json::to_value(item).unwrap_or(Value::Null);
    let s = |v: &Value| v.as_str().map(str::to_string);
    let refs: Vec<String> = item["reportRefs"]
        .as_object()
        .map(|m| m.iter().map(|(local, cloud)| format!("{local} (Cloud {})", cloud.as_str().unwrap_or(""))).collect())
        .unwrap_or_default();
    let matching: Vec<String> = item["matchingFields"].as_array().map(|a| a.iter().filter_map(|x| s(x)).collect()).unwrap_or_default();
    let outcome = &item["outcome"];
    let reports = if !refs.is_empty() {
        refs.join(", ")
    } else {
        s(&outcome["sourceInvestigation"]).filter(|x| !x.is_empty()).unwrap_or_else(|| "unavailable".into())
    };
    redact_secrets(&format!(
        "Prior incident {} [{}; {}]: {}\n  Matched: {}; last verified: {}.\n  Reports: {}; historical outcome: {}.\n  First check: {}. Historical match; current outcome unconfirmed.",
        s(&item["incidentId"]).or_else(|| s(&item["memoryId"])).unwrap_or_default(),
        s(&item["environment"]).unwrap_or_default(),
        s(&outcome["certainty"]).unwrap_or_else(|| "inferred".into()),
        s(&item["claim"]).unwrap_or_default(),
        if matching.is_empty() { "unspecified".to_string() } else { matching.join(", ") },
        s(&item["lastVerifiedAt"]).unwrap_or_else(|| "never".into()),
        reports,
        s(&outcome["disposition"]).unwrap_or_else(|| "unknown".into()),
        item["checks"][0].as_str().unwrap_or("Review current evidence"),
    ))
}

/// Everything a single `investigate()` call needs: the resolved env, the live connectors, the
/// open DB handle, and whether the run is degraded to runtime-only (no source host). Built once
/// by [`build_investigation_context`]; reused for many investigations by a watcher.
pub struct InvestigationContext {
    pub renv: ResolvedEnvironment,
    pub db: DbHandle,
    /// True when the source-intelligence host was unreachable and could not be self-healed.
    pub runtime_only: bool,
    pub code: Option<SourceCodeProvider>,
    pub logs: Option<ElasticsearchLogsProvider>,
    pub mongo: Option<MongoStateProvider>,
    pub postgres: Option<DatabaseStateProvider>,
    pub sentry: Option<SentryProvider>,
    /// Native Lens (Horus Cloud) provider — only when logged in + repo cloud-linked (HOR-470).
    pub lens: Option<LensProvider>,
    pub axiom: Option<AxiomProvider>,
    pub cloud_logs: Vec<CloudLogsProvider>,
    pub additional_state: Vec<DatabaseStateProvider>,
    pub additional_queues: Vec<Box<dyn QueueEvidenceProvider>>,
    pub shopify: Option<ShopifyProvider>,
    pub queue: Option<BullMQRuntimeProvider>,
    pub redis_state: Option<RedisStateRuntimeProvider>,
    pub metrics: Option<Box<dyn MetricsProvider>>,
    /// Default service scope: CLI flag > ES connector's serviceName > None.
    pub service: Option<String>,
    /// Local memory vector index on the verified source host; None in runtime-only mode.
    pub recall_index: Option<LikeAsIndex>,
}

#[derive(Default)]
pub struct BuildContextOptions<'a> {
    /// Database URL for the investigation store (config.database.url — ignored: always embedded).
    pub database_url: &'a str,
    pub unattended: bool,
    /// Explicit service scope; falls back to the ES connector's configured serviceName.
    pub service: Option<String>,
    /// Sink for human-readable status/warning lines (default: stderr).
    pub log: Option<&'a (dyn Fn(&str) + Send + Sync)>,
}

/// Build a reusable investigation context for a resolved environment: resolve a source
/// `CodeProvider`, self-heal a down host (HOR-319 layer 1) + verify it serves THIS repo
/// (HOR-421), degrade to RUNTIME-ONLY when it stays down (layer 2), resolve every runtime
/// connector, and open the local DB. Errors when no source-intelligence connector (and no
/// runtime connector) is configured — the same hard requirement `investigate` enforces.
pub async fn build_investigation_context(renv: ResolvedEnvironment, opts: BuildContextOptions<'_>) -> Result<InvestigationContext> {
    let stderr = |l: &str| eprintln!("{l}");
    let log: &dyn Fn(&str) = match opts.log {
        Some(l) => l,
        None => &stderr,
    };

    let mut code = code_for_env(&renv);
    let any_runtime = serde_json::to_value(&renv.connectors)?.as_object().is_some_and(|m| m.values().any(|v| !v.is_null()));
    if code.is_none() && !opts.unattended && !any_runtime {
        bail!("No source-intelligence connector configured for project \"{}\" / env \"{}\".", renv.project, renv.env);
    }

    // `code_for_env` only returns a provider when the repo has a configured sourceHostUrl.
    let source_url = renv.repositories.first().and_then(|r| r.source_host_url.clone()).filter(|u| !u.is_empty());
    let mut host_url = source_url.clone();
    let runtime_only = match (&source_url, opts.unattended) {
        (Some(url), false) => {
            // Self-heal + identity guard: the resolved URL may differ from the configured one when
            // this repo's own host had to be started on a free port — rebuild the provider.
            let resolved = resolve_source_host_url(Path::new(&renv.path), url, None, log).await;
            if let Some(h) = resolved.host_url.as_deref().filter(|h| resolved.ok && *h != url) {
                code = Some(code_for_url(h));
                host_url = Some(h.to_string());
            }
            !resolved.ok
        }
        _ => match &code {
            Some(c) => !c.health().await.ok,
            None => true,
        },
    };

    // HOR-319 layer 2: logs/metrics/state/queues are independent of the source host.
    if runtime_only {
        log(&yellow(&format!(
            "Proceeding in runtime-only mode — no source intelligence. Run {} for a full (code-aware) investigation.",
            bold("horus init")
        )));
    }

    // Native Lens (HOR-470): lights up iff logged into Horus Cloud AND the repo is cloud-linked
    // with a workspace id. Degrades silently to None otherwise.
    let lens = match (read_auth(), read_cloud_config(Path::new(&renv.path))) {
        (Some(auth), Some(cfg)) => cfg
            .workspace
            .as_ref()
            .filter(|w| !w.id.is_empty())
            .map(|w| lens_for_cloud(&auth.api_base_url, &auth.token, &w.id)),
        _ => None,
    };
    let service = opts.service.clone().or_else(|| renv.connectors.elasticsearch.as_ref().and_then(|e| e.service_name.clone()));

    Ok(InvestigationContext {
        logs: logs_for_env(&renv)?,
        mongo: mongo_for_env(&renv),
        postgres: postgres_for_env(&renv),
        sentry: sentry_for_env(&renv),
        lens,
        axiom: axiom_for_env(&renv),
        cloud_logs: cloud_logs_for_env(&renv)?,
        additional_state: additional_state_for_env(&renv)?,
        additional_queues: additional_queues_for_env(&renv)?,
        shopify: shopify_for_env(&renv),
        queue: queue_for_env(&renv)?,
        redis_state: redis_state_for_env(&renv),
        metrics: metrics_for_env(&renv)?,
        db: open_db().await?,
        // Runtime-only degrade: no source provider, so the engine skips seed resolution.
        code: if runtime_only { None } else { code },
        // Short timeout: recall similarity is optional context and must not delay the investigation.
        // No Jaccard fallback: its overlap scores are not embedding similarities.
        recall_index: host_url.filter(|_| !runtime_only).map(|url| {
            let client = SourceHttpClient::new(SourceClientOptions { base_url: url, timeout_ms: Some(3000), max_retries: None });
            LikeAsIndex(Arc::new(SourceMemoryVectorIndex::new(client, SourceMemoryVectorIndexOptions::default())))
        }),
        runtime_only,
        service,
        renv,
    })
}

/// Per-investigation overrides — the hint plus optional scoping/window flags.
#[derive(Debug, Clone, Default)]
pub struct RunInvestigationInput {
    pub report_id: Option<String>,
    pub incident: Option<IncidentContext>,
    pub hint: String,
    /// Git ref/range for change-impact (e.g. HEAD~5).
    pub since: Option<String>,
    /// Runtime-log window as a duration (e.g. 30d, 24h), independent of `since`.
    pub logs_since: Option<String>,
    /// Service scope override; defaults to the context's resolved service.
    pub service: Option<String>,
    /// Path scope for seed resolution (e.g. packages/core) — HOR-356.
    pub scope: Option<String>,
    /// Shopify Admin GraphQL queries supplied at invocation (`--shopify-query`); None falls back
    /// to the connector's config-declared defaults.
    pub shopify_queries: Option<Vec<ShopifyQuerySpec>>,
}

/// HOR-404: load the LOCAL reranker model, or None. OFF by default — active only when
/// `HORUS_RERANK` is truthy AND a saved model beat the baseline on its holdout (delta > 0).
/// Fail-closed: any error → None → deterministic ranking.
pub fn load_reranker() -> Option<RerankerModel> {
    let flag = std::env::var("HORUS_RERANK").ok()?;
    if flag.is_empty() || flag == "0" || flag.eq_ignore_ascii_case("false") {
        return None;
    }
    let path = dirs::home_dir()?.join(".horus").join("reranker.json");
    let blob: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    if !is_reranker_model(&blob) {
        return None;
    }
    let model: RerankerModel = serde_json::from_value(blob).ok()?;
    // Never apply a model that didn't beat the baseline.
    if !(model.holdout.delta > 0.0) {
        return None;
    }
    Some(model)
}

/// `memorySyncContext(root, repo)?.scope` — the cloud sync scope for a linked + signed-in repo.
fn memory_sync_scope(root: &Path, repo: &str) -> Option<String> {
    memory_sync_context(root, repo, None).map(|c| c.scope)
}

/// Run a single investigation against a prepared context and persist it (the engine writes the
/// report into the local DB, so it lands in incident memory and `horus ask`). Bounded by
/// `timeout_ms` so an unreachable/slow connector can never hang the call.
pub async fn run_one_investigation(
    input: RunInvestigationInput,
    ctx: &InvestigationContext,
    timeout_ms: Option<u64>,
) -> Result<InvestigationReport> {
    run_one_investigation_with(input, ctx, timeout_ms, None).await
}

/// [`run_one_investigation`] with the watcher's `onActivity('recall' | 'collect')` hook.
pub async fn run_one_investigation_with(
    input: RunInvestigationInput,
    ctx: &InvestigationContext,
    timeout_ms: Option<u64>,
    on_activity: Option<&(dyn Fn(&str) + Send + Sync)>,
) -> Result<InvestigationReport> {
    let renv = &ctx.renv;
    let root = Path::new(&renv.path);
    if let Some(id) = &input.report_id {
        if let Some(saved) = get_investigation(&ctx.db, id).await? {
            let report: Option<InvestigationReport> = saved.report.as_deref().map(serde_json::from_str).transpose()?;
            match report {
                Some(r) if saved.project.as_deref() == Some(renv.project.as_str())
                    && r.input.environment.as_deref() == Some(renv.env.as_str()) =>
                {
                    return Ok(r)
                }
                _ => bail!("Saved report identity/scope mismatch"),
            }
        }
    }

    // The engine's `Reranker` is a 'static trait object, so the closure owns the model.
    let rerank_fn = load_reranker().map(|model| move |causes: &[CauseCandidate]| apply_reranker(&model, causes));
    if let Some(f) = on_activity {
        f("recall");
    }
    let startup = MemorySyncOptions { startup: true, ..Default::default() };
    if let Err(error) = sync_linked_memory(&ctx.db, root, &renv.project, startup).await {
        eprintln!("Memory refresh unavailable: {error}");
    }

    // Stale-index freshness feeds next-step routing: a behind index makes `horus init` a real step.
    let stale_index = read_index_meta(root)
        .and_then(|m| m.last_indexed_at)
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(&at).ok())
        .is_some_and(|at| chrono::Utc::now().timestamp_millis() - at.timestamp_millis() > STALE_INDEX_MS);

    let scope = memory_sync_scope(root, &renv.project);
    let store = create_local_memory_store(
        Arc::new(SqliteMemoryStorage::new(ctx.db.clone())),
        LocalMemoryStoreOpts { sync_scope: scope.clone() },
    );
    let on_startup = move |items: &[StartupIncident]| {
        if items.is_empty() {
            eprintln!("Prior incidents: no relevant match.");
        }
        for item in items {
            eprintln!("{}", format_startup_incident(item));
        }
        if let Some(f) = on_activity {
            f("collect");
        }
    };

    let c = &renv.connectors;
    // CONFIGURED = the connector STANZA exists — never resolved-URL truthiness.
    let flags = ConnectorFlags {
        elasticsearch: Some(c.elasticsearch.is_some()),
        grafana: Some(c.grafana.is_some()),
        prometheus: Some(c.prometheus.is_some()),
        additional_state: Some(c.firestore.is_some() || c.sqlserver.is_some()),
        mongodb: Some(c.mongodb.is_some()),
        postgres: Some(c.postgres.is_some()),
        sentry: Some(c.sentry.is_some()),
        // Lens is NATIVE (no stanza) — "configured" == provider present.
        lens: Some(ctx.lens.is_some()),
        axiom: Some(c.axiom.is_some()),
        shopify: Some(c.shopify.is_some()),
        redis: Some(c.redis.is_some()),
        queue: Some(ctx.queue.is_some() || !ctx.additional_queues.is_empty()),
        ..Default::default()
    };

    let mut deps = EngineDeps::new(&ctx.db);
    deps.memory_scope = scope;
    deps.on_startup_recall = Some(&on_startup);
    deps.recall_index = ctx.recall_index.as_ref().map(|i| i as &dyn horus_engine::memory_store::MemoryVectorIndex);
    deps.code = ctx.code.as_ref().map(|c| c as &dyn horus_engine::code_provider::CodeProvider);
    deps.rerank = rerank_fn.as_ref().map(|f| f as &horus_engine::Reranker);
    deps.logs = ctx.logs.as_ref().map(|l| l as &dyn LogsProvider);
    deps.mongo = ctx.mongo.as_ref().map(|m| m as &dyn StateProvider);
    deps.postgres = ctx.postgres.as_ref().map(|p| p as &dyn StateProvider);
    deps.sentry = ctx.sentry.as_ref();
    deps.lens = ctx.lens.as_ref();
    deps.axiom = ctx.axiom.as_ref();
    deps.cloud_logs = ctx.cloud_logs.iter().map(|p| p as &dyn StructuredLogSource).collect();
    deps.additional_state = ctx.additional_state.iter().map(|p| p as &dyn StateProvider).collect();
    deps.additional_queues = ctx.additional_queues.iter().map(|q| q.as_ref()).collect();
    deps.shopify = ctx.shopify.as_ref();
    deps.queue = ctx.queue.as_ref().map(|q| q as &dyn horus_connectors::bullmq::QueueRuntimeProvider);
    deps.redis_state = ctx.redis_state.as_ref().map(|r| r as &dyn horus_connectors::redis::RedisStateProvider);
    deps.metrics = ctx.metrics.as_deref();
    deps.repo_path = Some(renv.path.clone());
    deps.connectors = Some(flags);
    deps.stale_index = stale_index;
    deps.store = Some(&store);

    let investigation = investigate(
        InvestigationInput {
            report_id: input.report_id,
            incident: input.incident,
            hint: input.hint,
            agent_session: ["HORUS_AGENT_SESSION", "CLAUDE_CODE_SESSION_ID"]
                .iter()
                .find_map(|k| std::env::var(k).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            repo: Some(renv.project.clone()),
            since: input.since,
            logs_since: input.logs_since,
            service: input.service.or_else(|| ctx.service.clone()),
            environment: Some(renv.env.clone()),
            scope: input.scope,
            duration_dimension: None,
            // Invocation-time Shopify queries override the connector's config defaults.
            shopify_queries: input.shopify_queries,
        },
        deps,
    );

    let timeout_ms = timeout_ms.unwrap_or_else(|| {
        let n = js_number(&std::env::var("HORUS_INVESTIGATE_TIMEOUT_S").unwrap_or_default());
        (if n.is_nan() || n == 0.0 { 120.0 } else { n } * 1000.0) as u64
    });
    let report = with_deadline(investigation, timeout_ms).await?;
    match sync_linked_memory(&ctx.db, root, &renv.project, MemorySyncOptions::default()).await {
        Ok(sync) => eprintln!(
            "Memory: {}; {} pending{}",
            sync.state,
            sync.pending,
            sync.error.map(|e| format!(" — {e}")).unwrap_or_default()
        ),
        Err(error) => eprintln!("Memory is not durably saved: {error}"),
    }
    Ok(report)
}

/// Close EVERY connector + the DB. Each close is best-effort; never throws past shutdown.
pub async fn dispose_investigation_context(ctx: InvestigationContext) {
    ctx.db.end().await;
    for p in &ctx.additional_state {
        p.close().await;
    }
    if let Some(m) = &ctx.mongo {
        m.close().await;
    }
    if let Some(p) = &ctx.postgres {
        p.close().await;
    }
    if let Some(r) = &ctx.redis_state {
        horus_connectors::redis::RedisStateProvider::close(r).await;
    }
    if let Some(q) = &ctx.queue {
        horus_connectors::bullmq::QueueRuntimeProvider::close(q).await;
    }
}

/// Resolve `fut`, or fail after `ms` with a clear, actionable message. The underlying work is
/// dropped — a hung connector (dropped tunnel / slow source host) can never hang the CLI.
pub async fn with_deadline<T>(fut: impl Future<Output = Result<T>>, ms: u64) -> Result<T> {
    match tokio::time::timeout(Duration::from_millis(ms), fut).await {
        Ok(r) => r,
        Err(_) => bail!(
            "Investigation exceeded {}s and was aborted. A runtime connector is likely unreachable (e.g. a dropped SSH tunnel / port-forward) or the source-intelligence host is slow. Re-run, or raise --timeout <seconds>.",
            (ms as f64 / 1000.0 + 0.5).floor()
        ),
    }
}
