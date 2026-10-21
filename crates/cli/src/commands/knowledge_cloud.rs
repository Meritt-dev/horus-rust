//! `horus knowledge push|pull` and `horus knowledge status --cloud` (HOR-296). Port of
//! `packages/cli/src/commands/knowledge-cloud.ts`.
//!
//! OPTIONAL cloud sync for the local knowledge index — gated behind authenticated, cloud-linked
//! mode. Uploads are content-hash idempotent. Redaction controls come from `.horus/config.json`
//! (`knowledge.redact`) and are applied before the snapshot leaves the machine.

use std::path::{Path, PathBuf};

use anyhow::Result;
use horus_knowledge::{create_json_knowledge_store, validate_snapshot, KnowledgeManifest, KnowledgeSnapshot, ManifestGit, ToolRef, WriteOptions};
use serde_json::Value;

use crate::cli::*;
use crate::commands::context::{exit, report_cloud_error};
use crate::lib::cloud::api::{CloudClient, PushKnowledgeSnapshotBody};
use crate::lib::cloud::context_store::{is_cloud_active, read_cloud_config};
use crate::lib::cloud::session::{authed_client, repo_root_or_cwd};
use crate::lib::format::{bold, dim, green, red, yellow};

// ── Redaction ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default)]
pub struct KnowledgeRedactConfig {
    /// Strip provenance.filePath and provenance.lineRange from every item before upload.
    pub drop_provenance_paths: bool,
    /// Strip descriptive text bodies and detail lists — upload structure + provenance only.
    pub summaries_only: bool,
}

/// JS truthiness of a JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// Read `knowledge.redact` from `.horus/config.json`, defaults when absent.
pub fn read_knowledge_redact_config(root: &Path) -> KnowledgeRedactConfig {
    let Ok(raw) = std::fs::read_to_string(root.join(".horus").join("config.json")) else { return Default::default() };
    let Ok(raw) = serde_json::from_str::<Value>(&raw) else { return Default::default() };
    let redact = raw.get("knowledge").and_then(|k| k.get("redact"));
    KnowledgeRedactConfig {
        drop_provenance_paths: truthy(redact.and_then(|r| r.get("dropProvenancePaths"))),
        summaries_only: truthy(redact.and_then(|r| r.get("summariesOnly"))),
    }
}

const ITEM_CATEGORIES: &[&str] = &[
    "repositories", "operations", "types", "enums", "authRules", "domainConcepts", "frontendPatterns", "dataFlows",
    "runtimeComponents", "externalIntegrations",
];
const VERBOSE_FIELDS: &[&str] = &["summary", "details", "description", "notes", "deploymentNotes"];
const DETAIL_FIELDS: &[&str] = &[
    "args", "fields", "steps", "sources", "sinks", "usedBy", "relatedOperations", "relatedTypes", "entrypoints",
    "frameworks", "languages", "stateManagement", "dataSources", "mainScripts", "integrations", "importantDirectories",
    "resolverFile", "returnType", "auth", "appliesTo",
];

/// Apply redaction controls to a (serialized) snapshot before upload. Unchanged when no
/// control is active.
pub fn apply_knowledge_redaction(mut snapshot: Value, redact: KnowledgeRedactConfig) -> Value {
    if !redact.drop_provenance_paths && !redact.summaries_only {
        return snapshot;
    }
    for cat in ITEM_CATEGORIES {
        let Some(items) = snapshot.get_mut(*cat).and_then(Value::as_array_mut) else { continue };
        for item in items.iter_mut() {
            let Some(obj) = item.as_object_mut() else { continue };
            if redact.drop_provenance_paths {
                if let Some(p) = obj.get_mut("provenance").and_then(Value::as_object_mut) {
                    p.shift_remove("filePath");
                    p.shift_remove("lineRange");
                }
            }
            if redact.summaries_only {
                for f in VERBOSE_FIELDS.iter().chain(DETAIL_FIELDS) {
                    obj.shift_remove(*f);
                }
            }
        }
    }
    snapshot
}

struct CloudTarget {
    client: CloudClient,
    project_id: String,
    project_slug: String,
    root: PathBuf,
}

/// The authenticated client + linked cloud project, or a gated message (Err = exit code).
fn resolve_cloud_target() -> Result<CloudTarget, u8> {
    let root = repo_root_or_cwd(None);
    let Some(session) = authed_client() else {
        eprintln!(
            "{} Cloud sync is optional — run {} to enable it. Local knowledge still works.",
            red("Not logged in."),
            bold("horus login")
        );
        return Err(1);
    };
    let Some(project) = read_cloud_config(&root).filter(|c| is_cloud_active(Some(c))).and_then(|c| c.project) else {
        eprintln!(
            "{} Run {} first.",
            red("This repo is not linked to a cloud project."),
            bold("horus context use <org>/<workspace>/<project>")
        );
        return Err(1);
    };
    Ok(CloudTarget { client: session.client, project_id: project.id, project_slug: project.slug, root })
}

struct LocalIndex {
    hash: Option<String>,
    snapshot: Option<KnowledgeSnapshot>,
    manifest: Option<KnowledgeManifest>,
}

fn local_content_hash(root: &Path) -> LocalIndex {
    let store = create_json_knowledge_store(root);
    if !store.exists() {
        return LocalIndex { hash: None, snapshot: None, manifest: None };
    }
    let manifest = store.read_manifest().ok().flatten();
    let snapshot = store.read_snapshot().ok().flatten();
    let hash = manifest
        .as_ref()
        .and_then(|m| m.files.iter().find(|f| f.name == "knowledge-base.json"))
        .and_then(|f| f.content_hash.clone());
    LocalIndex { hash, snapshot, manifest }
}

/// First 8 UTF-16 units (hashes are ASCII).
fn short(s: &str) -> String {
    s.chars().take(8).collect()
}

pub async fn run_knowledge_push(dry_run: bool) -> Result<u8> {
    let root0 = repo_root_or_cwd(None);
    let local = local_content_hash(&root0);
    let (Some(hash), Some(snapshot), Some(manifest)) = (local.hash, local.snapshot, local.manifest) else {
        eprintln!("{} Run {} first.", red("No local knowledge index to push."), bold("horus init"));
        return Ok(1);
    };
    let t = match resolve_cloud_target() {
        Ok(t) => t,
        Err(code) => return Ok(code),
    };
    // Apply redaction controls before anything leaves the machine.
    let redact = read_knowledge_redact_config(&root0);
    let upload_snapshot = apply_knowledge_redaction(horus_core::json::to_js_value(&snapshot)?, redact);

    // Content-hash dedup: skip when the cloud already has this exact snapshot.
    match t.client.get_latest_knowledge_snapshot(&t.project_id).await {
        Ok(latest) if latest.content_hash == hash => {
            println!("{}{}", green("Cloud is already up to date"), dim(&format!(" ({}).", short(&hash))));
            return Ok(0);
        }
        Ok(_) => {}
        Err(e) if e.status() == Some(404) => {} // no snapshot yet; continue to push
        Err(e) => return Ok(report_cloud_error(&e.into())),
    }

    let total: u64 = manifest.counts.values().sum();
    if dry_run {
        let labels: Vec<&str> = [
            redact.drop_provenance_paths.then_some("dropProvenancePaths"),
            redact.summaries_only.then_some("summariesOnly"),
        ]
        .into_iter()
        .flatten()
        .collect();
        let redact_label = if labels.is_empty() { String::new() } else { format!(" [redact: {}]", labels.join(", ")) };
        println!(
            "{}",
            dim(&format!(
                "[dry-run] would push snapshot {} ({total} item(s), schema v{}) to project {}{redact_label}.",
                short(&hash),
                manifest.schema_version,
                t.project_slug
            ))
        );
        return Ok(0);
    }
    let body = PushKnowledgeSnapshotBody {
        schema_version: manifest.schema_version,
        content_hash: hash.clone(),
        git_sha: manifest.git.as_ref().and_then(|g| g.sha.clone()),
        branch: manifest.git.as_ref().and_then(|g| g.branch.clone()),
        generated_at: manifest.generated_at.clone(),
        counts: Some(manifest.counts.clone()),
        snapshot: upload_snapshot,
        manifest: horus_core::json::to_js_value(&manifest)?,
        idempotency_key: Some(hash),
    };
    match t.client.push_knowledge_snapshot(&t.project_id, &body).await {
        Ok(rec) => {
            println!(
                "{}{}",
                green("✓ pushed knowledge snapshot"),
                dim(&format!(" {} → {} ({total} item(s))", short(&rec.content_hash), t.project_slug))
            );
            Ok(0)
        }
        Err(e) => Ok(report_cloud_error(&e.into())),
    }
}

pub async fn run_knowledge_pull(force: bool) -> Result<u8> {
    let t = match resolve_cloud_target() {
        Ok(t) => t,
        Err(code) => return Ok(code),
    };
    let latest = match t.client.get_latest_knowledge_snapshot(&t.project_id).await {
        Ok(l) => l,
        Err(e) if e.status() == Some(404) => {
            println!(
                "{} Push one with {}.",
                yellow("No cloud knowledge snapshot for this project yet."),
                bold("horus knowledge push")
            );
            return Ok(0);
        }
        Err(e) => return Ok(report_cloud_error(&e.into())),
    };
    let Some(raw_snapshot) = latest.snapshot.clone().filter(|s| !s.is_null()) else {
        eprintln!("{}", red("Cloud returned a snapshot record with no body."));
        return Ok(1);
    };
    let local = local_content_hash(&t.root);
    if local.hash.as_deref() == Some(latest.content_hash.as_str()) {
        println!("{}{}", green("Local index already matches cloud"), dim(&format!(" ({}).", short(&latest.content_hash))));
        return Ok(0);
    }
    if local.hash.is_some() && !force {
        eprintln!(
            "{} Re-run with {} to overwrite local with the cloud copy.",
            yellow("Local index differs from the cloud snapshot."),
            bold("--force")
        );
        return Ok(1);
    }
    let snapshot: KnowledgeSnapshot = match serde_json::from_value::<KnowledgeSnapshot>(raw_snapshot) {
        Ok(s) => match validate_snapshot(&s).into_iter().next() {
            None => s,
            Some(issue) => {
                eprintln!("{}", red(&format!("Cloud snapshot failed validation: {issue}")));
                return Ok(1);
            }
        },
        Err(e) => {
            eprintln!("{}", red(&format!("Cloud snapshot failed validation: {e}")));
            return Ok(1);
        }
    };
    create_json_knowledge_store(&t.root).write(
        &snapshot,
        &WriteOptions {
            generator: Some(ToolRef { tool: "horus-cloud-pull".into(), version: None }),
            git: Some(ManifestGit { sha: latest.git_sha.clone(), branch: latest.branch.clone() }),
            ..Default::default()
        },
    )?;
    println!(
        "{}{}",
        green("✓ pulled knowledge snapshot"),
        dim(&format!(" {} ← {}", short(&latest.content_hash), t.project_slug))
    );
    Ok(0)
}

/// The `--cloud` addendum to `horus knowledge status`: compares local vs cloud.
pub async fn run_knowledge_cloud_status() -> Result<u8> {
    let root = repo_root_or_cwd(None);
    let Some(session) = authed_client() else {
        println!("{}", dim("Cloud: not logged in (`horus login` to enable optional cloud sync)."));
        return Ok(0);
    };
    let Some(project) = read_cloud_config(&root).filter(|c| is_cloud_active(Some(c))).and_then(|c| c.project) else {
        println!("{}", dim("Cloud: this repo is not linked to a cloud project."));
        return Ok(0);
    };
    match session.client.get_latest_knowledge_snapshot(&project.id).await {
        Ok(latest) => {
            let local_hash = local_content_hash(&root).hash;
            let in_sync = local_hash.as_deref() == Some(latest.content_hash.as_str());
            println!("{}", bold("Cloud knowledge snapshot"));
            println!("  project:    {}", project.slug);
            println!(
                "  cloud:      {} @ {} ({})",
                short(&latest.content_hash),
                short(latest.git_sha.as_deref().unwrap_or("—")),
                latest.generated_at
            );
            println!("  local:      {}", short(local_hash.as_deref().unwrap_or("—")));
            println!(
                "{}",
                if in_sync {
                    green("  ✓ local matches cloud")
                } else {
                    yellow("  ⚠ local differs — run `horus knowledge push` or `horus knowledge pull`")
                }
            );
            Ok(0)
        }
        Err(e) if e.status() == Some(404) => {
            println!("{}", dim("Cloud: no knowledge snapshot pushed for this project yet."));
            Ok(0)
        }
        Err(e) => Ok(report_cloud_error(&e.into())),
    }
}

pub async fn run(args: &KnowledgeArgs) -> Result<()> {
    let code = match &args.command {
        KnowledgeCommand::Push(a) => run_knowledge_push(a.dry_run).await?,
        KnowledgeCommand::Pull(a) => run_knowledge_pull(a.force).await?,
        _ => unreachable!("only knowledge push/pull dispatch here"),
    };
    exit(code)
}
