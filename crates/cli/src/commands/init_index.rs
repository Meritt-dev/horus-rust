//! The indexing flow behind `horus init`. Port of `packages/cli/src/commands/init-index.ts`:
//! build the queue map (HOR-6) and the one-command setup (HOR-37) — auto-detect the repo,
//! ensure horus-source is hosting it, stitch the queue boundaries, and (for new repos)
//! write/register a `.horus/config.json`.
//!
//! Host model: horus-source runs at most ONE host per repo (single-writer store lock), but
//! different repos run their own hosts on their own ports concurrently. So the flow NEVER
//! starts a second host for a repo that already has one — it reuses it (from the resolved
//! config, or from `.horus/source/host.json`).

use std::path::{Component, Path, PathBuf};

use anyhow::Result;
use horus_connectors::check_source_compatibility;
use horus_connectors::source::client::{SourceClientOptions, SourceHttpClient};
use horus_connectors::source::lifecycle::{
    analyze_repo, assert_source_version_pinned, find_free_port, index_embeddings_pending, index_needs_reanalyze,
    is_analyzed, is_host_healthy, kill_spawned_host, read_source_host_url, reconcile_spawned_host, source_available,
    start_host, wait_for_own_host,
};
use horus_core::{
    collect_local_changes, discover_local_config, ensure_project_gitignore, find_repo_root, get_current_branch,
    get_head_sha, load_config, read_local_config, register_project, write_local_config, HorusConfig, LocalChangeResult,
    LocalConfigFile, PINNED_SOURCE_VERSION,
};
use horus_knowledge::{
    build_project_knowledge, create_json_knowledge_store, import_knowledge_base_file, BuildOptions, ImportFileOptions,
    ManifestGit, ManifestRepository, RepoInput, SourceCommunityInput, SourceGraphExtract, SourceProcessInput,
    SourceProcessStepInput, SourceRel, SourceRelationshipInput, SourceRelationshipsInput, SourceSymbolInput, ToolRef,
    WriteOptions,
};
use serde_json::{json, Map, Value};

use crate::lib::ensure_host::parse_host_port;
use crate::lib::format::{bold, dim, green, red, yellow};

/// Node `path.resolve`: absolute against cwd, lexically normalised, no symlink resolution.
pub(crate) fn resolve_path(p: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for c in std::env::current_dir().unwrap_or_default().join(p).components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn client(host_url: &str) -> SourceHttpClient {
    SourceHttpClient::new(SourceClientOptions::new(host_url))
}

async fn stitch_queue_map(host_url: &str, label: &str) -> Result<()> {
    let source = client(host_url);
    let db = horus_db::open_db().await?;
    match horus_stitcher::stitch(&source, &db, Some(label)).await {
        Ok(summary) => println!(
            "{}Stitched {} queue edge(s) across {} queue(s) — {} producer(s), {} worker(s).",
            dim(&format!("[{label}]  ")),
            summary.edges,
            summary.queues,
            summary.producers,
            summary.workers
        ),
        // HOR-392: a content-search / DB failure DEGRADES the queue-map pass, never aborts init.
        Err(err) => println!(
            "{}Queue map skipped (degraded): {err}. Stitched 0 queue edge(s).",
            dim(&format!("[{label}]  "))
        ),
    }
    db.end().await;
    Ok(())
}

/// Whether the host at `host_url` serves `root` (not another repo on the same port).
/// Best-effort: a host that can't report its repo does NOT block reuse.
async fn host_serves_repo(host_url: &str, root: &Path) -> bool {
    match client(host_url).host_info().await {
        Ok(info) => resolve_path(&info.repo_path) == resolve_path(&root.to_string_lossy()),
        Err(_) => true,
    }
}

/// A project in the config whose repository path matches `root`: `(project, hostUrl)`.
fn find_configured_repo(config: &HorusConfig, root: &Path) -> Option<(String, Option<String>)> {
    let target = resolve_path(&root.to_string_lossy());
    for p in &config.projects {
        for r in &p.repositories {
            if resolve_path(&r.path) == target {
                let host = r.source.as_ref().map(|s| s.host_url.clone()).filter(|h| !h.is_empty());
                return Some((p.name.clone(), host));
            }
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct IndexOptions {
    pub config: Option<String>,
    pub env: Option<String>,
    /// Repository root (default: nearest git root, else cwd).
    pub path: Option<String>,
    /// Build a full project-knowledge snapshot (default mode).
    pub full: bool,
    /// Pre-push-safe mode: only changed files, avoid heavy re-indexing.
    pub changed: bool,
    /// Speed hint, used with --changed (accepted for parity; TS reads it nowhere either).
    #[allow(dead_code)]
    pub fast: bool,
    /// Import an MCP knowledge-base JSON instead of deriving from source.
    pub import_kb: Option<String>,
    /// Force a FULL source re-analysis: stop the host, remove `.horus/source`, rebuild.
    pub reindex: bool,
}

/// Cap per-category pulls so a huge monorepo can't bloat the KB or stall init.
const SOURCE_GRAPH_PULL_LIMIT: i64 = 5000;
/// Source-graph labels (lowercase NodeLabel values) the KB ingests.
const SOURCE_SYMBOL_LABELS: &[&str] = &["class", "interface", "type_alias", "function", "method", "enum"];

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Read the analysed source graph back from the host over the TYPED endpoints (HOR-392) into
/// a `SourceGraphExtract` (HOR-408). Every slice degrades to "no rows" on failure; None only
/// when nothing at all could be read.
async fn extract_source_graph(host_url: &str, repo: &str) -> Option<SourceGraphExtract> {
    let client = client(host_url);
    let labels: Vec<String> = SOURCE_SYMBOL_LABELS.iter().map(|s| s.to_string()).collect();
    let symbol_rows = client.symbols_by_label(&labels, Some(SOURCE_GRAPH_PULL_LIMIT * 2)).await.unwrap_or_default();
    let symbols: Vec<SourceSymbolInput> = symbol_rows
        .iter()
        .map(|r| SourceSymbolInput {
            id: Some(r.id.clone()),
            label: r.label.clone(),
            name: r.name.clone(),
            file_path: non_empty(&r.file_path),
            start_line: (r.start_line > 0).then_some(r.start_line as u64),
            end_line: (r.end_line > 0).then_some(r.end_line as u64),
            class_name: non_empty(&r.class_name),
            signature: non_empty(&r.signature),
            is_exported: Some(r.is_exported),
            is_entry_point: Some(r.is_entry_point),
            enum_values: None,
        })
        .collect();

    // Resolve process step ids → symbol names/files (steps carry only ids).
    let name_by_id: std::collections::HashMap<&str, (&str, Option<String>)> = symbol_rows
        .iter()
        .filter(|r| !r.id.is_empty())
        .map(|r| (r.id.as_str(), (r.name.as_str(), non_empty(&r.file_path))))
        .collect();

    let communities: Vec<SourceCommunityInput> = client
        .communities()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| SourceCommunityInput { id: non_empty(&c.id), name: c.name, summary: None })
        .collect();

    let processes: Vec<SourceProcessInput> = client
        .processes()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|p| SourceProcessInput {
            id: None,
            name: p.name,
            steps: Some(
                p.steps
                    .iter()
                    .filter_map(|s| {
                        let resolved = name_by_id.get(s.node_id.as_str());
                        let component = resolved.map_or(s.node_id.as_str(), |r| r.0);
                        if component.is_empty() {
                            return None;
                        }
                        Some(SourceProcessStepInput {
                            component: component.to_string(),
                            detail: resolved.and_then(|r| r.1.clone()),
                        })
                    })
                    .collect(),
            ),
        })
        .collect();

    if symbols.is_empty() && communities.is_empty() && processes.is_empty() {
        return None;
    }
    // Optional additive metadata — absence is distinct from a confirmed empty graph.
    let relationships = client.code_relationships(None).await.ok().map(|r| SourceRelationshipsInput {
        edges: r
            .edges
            .into_iter()
            .filter_map(|e| {
                let rel: SourceRel = serde_json::from_value(Value::String(e.rel)).ok()?;
                Some(SourceRelationshipInput { source: e.source, target: e.target, rel, confidence: e.confidence })
            })
            .collect(),
        truncated: r.truncated,
    });
    Some(SourceGraphExtract {
        relationships,
        symbols: Some(symbols),
        communities: Some(communities),
        processes: Some(processes),
        repo: Some(repo.to_string()),
    })
}

/// Additive project-knowledge pass (HOR-293). Best-effort: never fails init.
async fn build_knowledge_index(
    root: &Path,
    config: Option<&HorusConfig>,
    label: &str,
    configured_project: Option<&str>,
    opts: &IndexOptions,
    host_url: Option<&str>,
) {
    if let Err(err) = build_knowledge_index_inner(root, config, label, configured_project, opts, host_url).await {
        // Knowledge building must never break `horus init`.
        println!("{}", dim(&format!("  project knowledge skipped: {err}")));
    }
}

async fn build_knowledge_index_inner(
    root: &Path,
    config: Option<&HorusConfig>,
    label: &str,
    configured_project: Option<&str>,
    opts: &IndexOptions,
    host_url: Option<&str>,
) -> Result<()> {
    let git_sha = get_head_sha(Some(root));
    let branch = get_current_branch(Some(root));

    // Import mode: a provided KB is the knowledge source (HOR-292).
    if let Some(kb) = &opts.import_kb {
        let res = import_knowledge_base_file(
            &resolve_path(kb),
            &ImportFileOptions { root: Some(root.to_path_buf()), project: Some(label.to_string()), ..Default::default() },
        )?;
        let total: u64 = res.manifest.as_ref().map_or(0, |m| m.counts.values().sum());
        println!("{}", dim(&format!("  project knowledge: imported {total} item(s) from {kb}")));
        if !res.result.warnings.is_empty() {
            println!("{}", dim(&format!("  ({} import warning(s))", res.result.warnings.len())));
        }
        return Ok(());
    }

    if opts.changed && !opts.full {
        // Pre-push-safe: note what changed, keep the build to the cheap landscape pass.
        let n = match collect_local_changes(Some(root), None) {
            LocalChangeResult::LocalChanges { changed_files, .. } => changed_files.len(),
            _ => 0,
        };
        println!(
            "{}",
            dim(&format!(
                "  project knowledge: fast refresh ({n} changed file(s)) — the source graph is NOT reanalyzed (use `horus init --reindex` for that)"
            ))
        );
    }

    // Repos to profile: the configured project's repos, else the current repo root.
    let mut repos: Vec<RepoInput> = Vec::new();
    if let (Some(config), Some(cp)) = (config, configured_project) {
        if let Some(proj) = config.projects.iter().find(|p| p.name == cp) {
            for r in &proj.repositories {
                repos.push(RepoInput { name: r.name.clone(), path: resolve_path(&r.path).to_string_lossy().into_owned() });
            }
        }
    }
    if repos.is_empty() {
        repos.push(RepoInput { name: label.to_string(), path: root.to_string_lossy().into_owned() });
    }

    // Bridge the analysed source graph into the KB (HOR-408), attributed to the repo whose root
    // we indexed. Best-effort.
    let mut source_graph = None;
    if let Some(host_url) = host_url {
        let target = resolve_path(&root.to_string_lossy());
        let graph_repo =
            repos.iter().find(|r| resolve_path(&r.path) == target).map_or(label.to_string(), |r| r.name.clone());
        source_graph = extract_source_graph(host_url, &graph_repo).await;
    }

    let snapshot = build_project_knowledge(
        &repos,
        &BuildOptions { project: Some(label.to_string()), git_sha: git_sha.clone(), now: None, source_graph },
    )?;
    create_json_knowledge_store(root).write(
        &snapshot,
        &WriteOptions {
            generator: Some(ToolRef { tool: "horus-cli".into(), version: None }),
            git: Some(ManifestGit { sha: git_sha.clone(), branch }),
            repositories: Some(
                repos
                    .iter()
                    .map(|r| ManifestRepository { name: r.name.clone(), path: Some(r.path.clone()), head_sha: git_sha.clone() })
                    .collect(),
            ),
            source_intelligence: config
                .map(|_| ToolRef { tool: "source".into(), version: Some(PINNED_SOURCE_VERSION.into()) }),
            extra_files: None,
        },
    )?;
    let mut counts: Vec<String> = Vec::new();
    let mut push = |n: usize, what: &str| {
        if n > 0 {
            counts.push(format!("{n} {what}"));
        }
    };
    push(snapshot.repositories.len(), "repo(s)");
    push(snapshot.operations.len(), "operation(s)");
    push(snapshot.types.len(), "type(s)");
    push(snapshot.domain_concepts.len(), "concept(s)");
    push(snapshot.data_flows.len(), "flow(s)");
    if let Some(rel) = &snapshot.source_relationships {
        counts.push(format!(
            "{} source relationship(s){}",
            rel.edges.len(),
            if rel.truncated { " (truncated)" } else { "" }
        ));
    }
    println!("{}", dim(&format!("  project knowledge: {} → .horus/index/", counts.join(", "))));
    Ok(())
}

pub async fn run_index(opts: &IndexOptions) -> u8 {
    match run_index_inner(opts).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", red(&err.to_string()));
            1
        }
    }
}

async fn run_index_inner(opts: &IndexOptions) -> Result<u8> {
    let cwd = std::env::current_dir()?;
    let root = match &opts.path {
        Some(p) => resolve_path(p),
        None => find_repo_root(&cwd).unwrap_or(cwd),
    };
    let root_s = root.to_string_lossy().into_owned();
    // Ignore `.horus/` up front — before the slow, abortable analyze/spawn work — so a failed
    // init still leaves a clean tree (dogfood 0.21.1). Idempotent.
    ensure_project_gitignore(&root);

    // Try to resolve a config (central or .horus). Non-fatal if absent.
    let config = load_config(opts.config.as_deref().map(Path::new), None).ok();

    // Is this repo already a configured project (matched by PATH)? Then reuse its host and do
    // NOT write a local .horus (that would shadow the project's runtime connectors).
    let (configured_project, configured_host) = match config.as_ref().and_then(|c| find_configured_repo(c, &root)) {
        Some((p, h)) => (Some(p), h),
        None => (None, None),
    };
    let is_configured = configured_project.is_some();
    let name = configured_project
        .clone()
        .unwrap_or_else(|| root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    let label = name.clone();

    let mut host_url: Option<String> = None;
    let mut drifted_host: Option<(String, Option<String>)> = None;
    if opts.reindex {
        // Full re-analysis: stop the host (it holds the store lock) and remove `.horus/source`.
        println!("{}", dim("  --reindex: stopping the host and removing .horus/source for a full re-analysis…"));
        kill_spawned_host(&root).await;
        let _ = std::fs::remove_dir_all(root.join(".horus").join("source"));
    }
    let candidates: Vec<Option<String>> =
        if opts.reindex { vec![] } else { vec![configured_host.clone(), read_source_host_url(&root)] };
    for candidate in candidates.into_iter().flatten() {
        // Reuse only a healthy host that actually serves THIS repo…
        if is_host_healthy(&candidate).await && host_serves_repo(&candidate, &root).await {
            // …AND runs the pinned backend; a drifted host is restarted instead.
            let compat = check_source_compatibility(&client(&candidate)).await?;
            if compat.version.is_some() && !compat.matches {
                drifted_host = Some((candidate, compat.version));
                continue;
            }
            host_url = Some(candidate);
            break;
        }
    }

    if host_url.is_none() {
        if let Some((url, version)) = &drifted_host {
            // The old host holds the single-writer lock — stop it before spawning a pinned one.
            println!(
                "{}",
                yellow(&format!(
                    "Host at {url} runs backend v{} (pinned {PINNED_SOURCE_VERSION}) — restarting it with the pinned backend",
                    version.as_deref().unwrap_or("")
                ))
            );
            kill_spawned_host(&root).await;
        }
    }

    if let Some(h) = &host_url {
        println!("{}", dim(&format!("Reusing source-intelligence host for {label} at {h}")));
    } else {
        // No host running for this repo — set one up.
        println!("{}{}", bold(&format!("Indexing {label}")), dim(&format!("  ({root_s})")));
        if !source_available().await {
            eprintln!(
                "{}",
                red("horus-source not found on PATH. Install it: curl -fsSL https://horus.sh/install.sh | bash")
            );
            return Ok(1);
        }
        // Refuse to analyze or host with a drifted backend (corrupts the graph identically on
        // every rebuild).
        if let Err(err) = assert_source_version_pinned().await {
            eprintln!("{}", red(&format!("  {err}")));
            return Ok(1);
        }
        // Re-analyze when there is no index OR the existing one is stale/legacy (HOR-433).
        let stale_reason = if is_analyzed(&root) { index_needs_reanalyze(&root) } else { None };
        if !is_analyzed(&root) || stale_reason.is_some() {
            println!(
                "{}",
                dim(&match &stale_reason {
                    Some(r) => format!("  existing index is stale ({r}) — re-analyzing with source-intelligence backend…"),
                    None => "  analyzing with source-intelligence backend (first time — this can take a while)…".into(),
                })
            );
            if let Err(err) = analyze_repo(&root).await {
                eprintln!("{}", red(&format!("  source analysis failed: {err}")));
                return Ok(1);
            }
            // Analyze runs with --defer-embeddings: structural-complete/embeddings-pending is
            // healthy. Only a missing or broken structural index is fatal.
            let incomplete =
                if is_analyzed(&root) { index_needs_reanalyze(&root) } else { Some("no index was produced".into()) };
            if let Some(why) = incomplete {
                eprintln!(
                    "{}",
                    red(&format!(
                        "  source analysis did not finish ({why}) — the structural index is missing or broken. Re-run `horus init` to rebuild it."
                    ))
                );
                return Ok(1);
            }
        } else {
            println!("{}", dim("  already analyzed"));
        }
        // Prefer this repo's OWN prior port so a re-index keeps a STABLE port and never grabs
        // another repo's. find_free_port is check-then-release (TOCTOU), so retry on a fresh
        // port when the host doesn't come up (HOR-357).
        let prior_port = parse_host_port(configured_host.as_deref().unwrap_or(""))
            .or_else(|| parse_host_port(&read_source_host_url(&root).unwrap_or_default()));
        // Any host still recorded is stale/unhealthy — reap it so the new host can take the
        // lock (HOR-372).
        kill_spawned_host(&root).await;
        const MAX_PORT_ATTEMPTS: usize = 4;
        let mut started = false;
        for attempt in 0..MAX_PORT_ATTEMPTS {
            let port = match (attempt, prior_port) {
                (0, Some(p)) => match find_free_port(Some(p), Some(p)).await {
                    Ok(p) => p,
                    Err(_) => find_free_port(None, None).await?,
                },
                _ => find_free_port(None, None).await?,
            };
            let requested = format!("http://127.0.0.1:{port}");
            println!(
                "{}",
                dim(&if attempt == 0 {
                    format!("  starting source-intelligence host on port {port}…")
                } else {
                    format!("  port contended — retrying on {port}…")
                })
            );
            start_host(&root, port)?;
            // HOR-409: resolve to the port the backend ACTUALLY bound and only accept a host
            // that verifies it serves THIS repo.
            if let Some(own) = wait_for_own_host(&root, &requested, None).await {
                reconcile_spawned_host(&root, i64::from(parse_host_port(&own).unwrap_or(port)));
                host_url = Some(own);
                started = true;
                break;
            }
            // Didn't come up — kill the spawn before retrying so it can't keep the lock (HOR-372).
            kill_spawned_host(&root).await;
        }
        if !started {
            eprintln!(
                "{}",
                red(&format!("  Source-intelligence host did not become healthy — see {root_s}/.horus/source-host.log"))
            );
            return Ok(1);
        }
    }

    let Some(host_url) = host_url else { return Ok(1) };

    // Final contamination guard (HOR-409 / HOR-421): never read a known-foreign host's graph.
    if !host_serves_repo(&host_url, &root).await {
        eprintln!(
            "{}",
            red(&format!(
                "  Source-intelligence host at {host_url} is serving a DIFFERENT repository — refusing to index foreign code. Retry, or stop the stale host: horus stop"
            ))
        );
        return Ok(1);
    }

    // Symbol-only degraded-mode notice (B1.4), from the durable meta.
    if index_embeddings_pending(&root) {
        println!("{}", dim("  index ready (semantic search warming up)"));
    }

    // Queue map — best-effort (HOR-392); stitch_queue_map self-degrades, this guards open_db.
    if let Err(err) = stitch_queue_map(&host_url, &label).await {
        println!(
            "{}Queue map skipped (degraded): {err}. Stitched 0 queue edge(s).",
            dim(&format!("[{label}]  "))
        );
    }

    build_knowledge_index(&root, config.as_ref(), &label, configured_project.as_deref(), opts, Some(&host_url)).await;

    // "Set up" = a discoverable local config, computed from the repo itself (not from whether
    // we spawned): a reused host used to fall through without ever writing one.
    let has_local_config = discover_local_config(&root).is_some();
    if !is_configured && !has_local_config {
        let file = LocalConfigFile {
            version: 1,
            project: json!({
                "name": name,
                "repositories": [{ "name": name, "path": root_s, "source": { "hostUrl": host_url } }],
                "environments": [{ "name": opts.env.as_deref().unwrap_or("production"), "readOnly": true, "connectors": {} }],
            }),
            database: None,
            ai: None,
            extra: Map::new(),
        };
        let config_path = write_local_config(&root, &file)?;
        register_project(&name, &root_s, &config_path.to_string_lossy())?;
        ensure_project_gitignore(&root);
        println!("{} Indexed {} — host {host_url}", green("✓"), bold(&name));
        println!("{}", dim(&format!("  {}", config_path.display())));
        println!("{}", dim("  investigate: horus investigate \"<hint>\"  (from this repo)"));
    } else if Some(&host_url) != configured_host.as_ref() {
        // The live host differs from the configured one (never persisted, or a replacement on a
        // new port) — persist it so status/doctor/investigate target the running host.
        if let Some(existing) = discover_local_config(&root) {
            let mut file = read_local_config(&existing)?;
            if let Some(first) =
                file.project.get_mut("repositories").and_then(Value::as_array_mut).and_then(|r| r.first_mut())
            {
                if let Some(obj) = first.as_object_mut() {
                    obj.insert("source".into(), json!({ "hostUrl": host_url }));
                }
            }
            write_local_config(&root, &file)?;
            register_project(&label, &root_s, &existing.to_string_lossy())?;
            ensure_project_gitignore(&root);
            println!("{} Indexed {} — source host registered at {host_url}", green("✓"), bold(&label));
            println!("{}", dim(&format!("  {}", existing.display())));
        } else {
            println!("{} Indexed {} {}", green("✓"), bold(&label), dim("(queue map refreshed)"));
        }
    } else {
        println!("{} Indexed {} {}", green("✓"), bold(&label), dim("(queue map refreshed)"));
    }
    Ok(0)
}
