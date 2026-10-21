//! Local-project discovery + registry (HOR-37).
//!
//! Horus is driven git-style: a repo carries a `.horus/config.json`, discovered by
//! walking up from the working directory — the config/cwd IS the project identity.
//! The global registry at `~/.horus/registry.json` only backs the informational
//! `projects`/`hosts` listings; it is NOT a targeting mechanism.

use crate::secrets::{decrypt_secret, encrypt_secret, write_file_0600, EncryptedSecret, MasterKey, SecretError};
use anyhow::{anyhow, Context, Result};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const HORUS_DIR: &str = ".horus";
pub const LOCAL_CONFIG_FILE: &str = "config.json";

/// Absolute path to a repo's local config file.
pub fn local_config_path(root: &Path) -> PathBuf {
    root.join(HORUS_DIR).join(LOCAL_CONFIG_FILE)
}

fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Walk up from `start` for a `.horus/config.json`; returns its absolute path or None.
pub fn discover_local_config(start: &Path) -> Option<PathBuf> {
    let mut dir = absolute(start);
    loop {
        let candidate = local_config_path(&dir);
        if candidate.exists() {
            return Some(candidate);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

/// Walk up from `start` for a `.git` entry → repo root; else None.
pub fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut dir = absolute(start);
    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }
        dir = dir.parent()?.to_path_buf();
    }
}

// ---------------------------------------------------------------------------
// Global registry (~/.horus/registry.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEntry {
    pub root: String,
    pub config_path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub projects: IndexMap<String, RegistryEntry>,
}

pub fn registry_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(HORUS_DIR).join("registry.json")
}

/// Display-only read: degrades to an empty registry when missing or unreadable.
pub fn read_registry() -> Registry {
    read_registry_for_update().unwrap_or_default()
}

/// Read for a read-modify-WRITE cycle. An EXISTING-but-unreadable registry errors:
/// treating a corrupt file as empty and writing it back would WIPE every registered
/// project on an ordinary `horus init`.
fn read_registry_for_update() -> Result<Registry> {
    let p = registry_path();
    if !p.exists() {
        return Ok(Registry::default());
    }
    Ok(serde_json::from_str(&std::fs::read_to_string(&p)?)?)
}

/// Atomic write (tmp + rename): a crash mid-write must never leave a torn registry.
pub fn write_registry(reg: &Registry) -> Result<()> {
    let p = registry_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = PathBuf::from(format!("{}.tmp-{}", p.display(), std::process::id()));
    std::fs::write(&tmp, format!("{}\n", serde_json::to_string_pretty(reg)?))?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// Merge one project into the registry. BEST-EFFORT and strictly ADDITIVE: a corrupt
/// registry is preserved for recovery (returns `Ok(false)`), never clobbered.
pub fn register_project(name: &str, root: &str, config_path: &str) -> Result<bool> {
    let Ok(mut reg) = read_registry_for_update() else { return Ok(false) };
    reg.projects.insert(name.to_string(), RegistryEntry { root: root.to_string(), config_path: config_path.to_string() });
    write_registry(&reg)?;
    Ok(true)
}

pub fn lookup_project(name: &str) -> Option<RegistryEntry> {
    read_registry().projects.get(name).cloned()
}

// ---------------------------------------------------------------------------
// Local config file shape
// ---------------------------------------------------------------------------

/// Deprecated `database` block — ignored; local persistence is embedded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseUrl {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalConfigFile {
    pub version: i64,
    /// A single ProjectConfig-shaped object (name, repositories[], environments[]).
    pub project: Value,
    /// Deprecated — ignored. Kept so a file that still sets it round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseUrl>,
    /// Optional AI narrative settings (provider + Anthropic key/model) — HOR-206.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai: Option<Value>,
    /// Unknown keys, preserved across read-modify-write like the TS `JSON.parse` cast.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn write_json_0600(p: &Path, v: &impl Serialize) -> Result<()> {
    write_file_0600(p, format!("{}\n", serde_json::to_string_pretty(v)?).as_bytes())
        .with_context(|| format!("write {}", p.display()))
}

/// Write a `.horus/config.json` under `root` and return its absolute path.
pub fn write_local_config(root: &Path, file: &LocalConfigFile) -> Result<PathBuf> {
    let dir = root.join(HORUS_DIR);
    std::fs::create_dir_all(&dir)?;
    let p = dir.join(LOCAL_CONFIG_FILE);
    write_json_0600(&p, file)?;
    Ok(p)
}

/// Append `entry` to `.horus/.gitignore` unless already present.
fn ensure_horus_dir_gitignore_entry(root: &Path, entry: &str) -> Result<()> {
    let dir = root.join(HORUS_DIR);
    std::fs::create_dir_all(&dir)?;
    let gitignore = dir.join(".gitignore");
    if gitignore.exists() {
        let existing = std::fs::read_to_string(&gitignore)?;
        if existing.split('\n').any(|l| l.trim() == entry) {
            return Ok(());
        }
        std::fs::write(&gitignore, format!("{}\n{entry}\n", existing.trim_end()))?;
    } else {
        std::fs::write(&gitignore, format!("{entry}\n"))?;
    }
    Ok(())
}

/// Ensure `.horus/config.json` is listed in `.horus/.gitignore`. Called by `horus connect`
/// when literal credential values are written into the config.
pub fn ensure_credential_gitignore(root: &Path) -> Result<()> {
    ensure_horus_dir_gitignore_entry(root, LOCAL_CONFIG_FILE)
}

/// Node's `fs.readFileSync(path, 'utf8')` error text: `<CODE>: <description>, <syscall>[ '<path>']`
/// (libuv wording), e.g. `ENOENT: no such file or directory, open '/x.json'`. Other errors
/// keep the OS message.
pub fn read_file_utf8(path: &Path) -> Result<String> {
    use std::io::{ErrorKind, Read};
    let node_err = |e: std::io::Error, syscall: String| {
        let (code, desc) = match e.kind() {
            ErrorKind::NotFound => ("ENOENT", "no such file or directory"),
            ErrorKind::PermissionDenied => ("EACCES", "permission denied"),
            ErrorKind::IsADirectory => ("EISDIR", "illegal operation on a directory"),
            ErrorKind::NotADirectory => ("ENOTDIR", "not a directory"),
            _ => return anyhow!("{e}, {syscall}"),
        };
        anyhow!("{code}: {desc}, {syscall}")
    };
    let mut file = std::fs::File::open(path).map_err(|e| node_err(e, format!("open '{}'", path.display())))?;
    let mut text = String::new();
    // A directory opens fine on unix; the read fails (`EISDIR: …, read`, no path — like Node).
    file.read_to_string(&mut text).map_err(|e| node_err(e, "read".into()))?;
    Ok(text)
}

pub fn read_local_config(path: &Path) -> Result<LocalConfigFile> {
    let text = read_file_utf8(path)?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

// ---------------------------------------------------------------------------
// Local secrets (HOR-212) — API keys live OUTSIDE config.json. Always gitignored.
// ---------------------------------------------------------------------------

pub const LOCAL_SECRETS_FILE: &str = "secrets.local.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnthropicSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

/// env name → connector type → field name → encrypted envelope (kept as raw JSON so a
/// malformed blob is skipped, not fatal).
pub type ConnectorSecretBlobs = IndexMap<String, IndexMap<String, IndexMap<String, Value>>>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LocalSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anthropic: Option<AnthropicSecrets>,
    /// Connector credentials, AES-256-GCM encrypted (HOR-452).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connectors: Option<ConnectorSecretBlobs>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Absolute path to a repo's local secrets file.
pub fn local_secrets_path(root: &Path) -> PathBuf {
    root.join(HORUS_DIR).join(LOCAL_SECRETS_FILE)
}

/// Read `.horus/secrets.local.json`, or empty when absent/unreadable.
pub fn read_local_secrets(root: &Path) -> LocalSecrets {
    std::fs::read_to_string(local_secrets_path(root)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Write `.horus/secrets.local.json` (mode 0600) and ensure it is gitignored.
pub fn write_local_secrets(root: &Path, secrets: &LocalSecrets) -> Result<PathBuf> {
    let dir = root.join(HORUS_DIR);
    std::fs::create_dir_all(&dir)?;
    let p = local_secrets_path(root);
    write_json_0600(&p, secrets)?;
    // Belt-and-suspenders: explicitly ignore the secrets file (in addition to `.horus/`).
    ensure_horus_dir_gitignore_entry(root, LOCAL_SECRETS_FILE)?;
    Ok(p)
}

// ---------------------------------------------------------------------------
// Encrypted connector secrets (HOR-452)
// ---------------------------------------------------------------------------

/// Encrypt + store one connector secret field into `.horus/secrets.local.json`.
pub fn write_connector_secret(
    root: &Path,
    env_name: &str,
    connector: &str,
    field: &str,
    plaintext: &str,
    key: Option<&MasterKey>,
) -> Result<()> {
    let mut secrets = read_local_secrets(root);
    let blob = encrypt_secret(plaintext, key)?;
    secrets
        .connectors
        .get_or_insert_with(IndexMap::new)
        .entry(env_name.to_string())
        .or_default()
        .entry(connector.to_string())
        .or_default()
        .insert(field.to_string(), serde_json::to_value(blob)?);
    write_local_secrets(root, &secrets)?;
    // Harden: also ensure the repo ignores `.horus/` in case it was never onboarded.
    ensure_project_gitignore(root);
    Ok(())
}

/// Remove all stored secrets for one connector in an environment (e.g. on disconnect).
pub fn delete_connector_secrets(root: &Path, env_name: &str, connector: &str) -> Result<()> {
    let mut secrets = read_local_secrets(root);
    let removed = secrets
        .connectors
        .as_mut()
        .and_then(|c| c.get_mut(env_name))
        .is_some_and(|by_connector| by_connector.shift_remove(connector).is_some());
    if removed {
        write_local_secrets(root, &secrets)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecryptedConnectorSecrets {
    /// env → connector → field → plaintext value.
    pub values: IndexMap<String, IndexMap<String, IndexMap<String, String>>>,
    /// Non-fatal decrypt problems (missing/wrong key) for the caller to surface.
    pub warnings: Vec<String>,
}

/// Read + decrypt every connector secret. Best-effort: a blob that cannot be decrypted
/// is skipped with a warning so the rest of config loading still works.
pub fn decrypt_connector_secrets(root: &Path) -> DecryptedConnectorSecrets {
    let mut out = DecryptedConnectorSecrets::default();
    let Some(stored) = read_local_secrets(root).connectors else { return out };
    for (env, by_connector) in stored {
        for (connector, by_field) in by_connector {
            for (field, blob) in by_field {
                let Some(blob) = EncryptedSecret::from_value(&blob) else { continue };
                match decrypt_secret(&blob, None) {
                    Ok(plain) => {
                        out.values.entry(env.clone()).or_default().entry(connector.clone()).or_default().insert(field, plain);
                    }
                    Err(err) => {
                        let reason = match err {
                            SecretError::MasterKeyUnavailable(_) => "no master key".to_string(),
                            other => other.to_string(),
                        };
                        out.warnings.push(format!("{env}/{connector}.{field}: {reason}"));
                    }
                }
            }
        }
    }
    out
}

/// True when a gitignore/exclude file's text carries a `.horus` ignore line.
fn has_horus_ignore_entry(text: &str) -> bool {
    text.split('\n').map(str::trim).any(|l| matches!(l, ".horus" | ".horus/" | "/.horus" | "/.horus/"))
}

static GITDIR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^gitdir:\s*(.+?)\s*$").unwrap());

/// Resolve the repo-local `.git/info/exclude` path for `root`, following a `.git` FILE
/// (worktree/submodule `gitdir: <path>`) to its real git dir.
fn git_info_exclude_path(root: &Path) -> Option<PathBuf> {
    let git_path = root.join(".git");
    let meta = std::fs::metadata(&git_path).ok()?;
    let git_dir = if meta.is_dir() {
        git_path
    } else {
        let text = std::fs::read_to_string(&git_path).ok()?;
        let resolved = GITDIR_RE.captures(&text)?.get(1)?.as_str().to_string();
        if resolved.starts_with('/') { PathBuf::from(resolved) } else { root.join(resolved) }
    };
    Some(git_dir.join("info").join("exclude"))
}

/// Read-only check: is `.horus/` ignored for this repo? Checks `.git/info/exclude` AND a
/// legacy tracked `.gitignore` entry. True for a non-git directory. Used by `horus doctor`.
pub fn is_horus_gitignored(root: &Path) -> bool {
    if !root.join(".git").exists() {
        return true;
    }
    let excluded = git_info_exclude_path(root)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|t| has_horus_ignore_entry(&t));
    excluded || std::fs::read_to_string(root.join(".gitignore")).is_ok_and(|t| has_horus_ignore_entry(&t))
}

/// Ensure the repo ignores `.horus/` — through the repo-LOCAL exclude file
/// (`.git/info/exclude`), NEVER the tracked `.gitignore`: writing a tracked file dirties
/// the working tree and Horus's own what-changed detection then reports its setup edit
/// as evidence. Best-effort: a read-only `.git/info` never fails a connect/init.
pub fn ensure_project_gitignore(root: &Path) {
    let Some(exclude_path) = git_info_exclude_path(root) else { return };
    let entry = ".horus/";
    let _ = (|| -> std::io::Result<()> {
        if let Some(info_dir) = exclude_path.parent() {
            std::fs::create_dir_all(info_dir)?;
        }
        let existing = std::fs::read_to_string(&exclude_path).unwrap_or_default();
        if has_horus_ignore_entry(&existing) {
            return Ok(());
        }
        let prefix = if existing.trim().is_empty() { String::new() } else { format!("{}\n", existing.trim_end()) };
        std::fs::write(&exclude_path, format!("{prefix}{entry}\n"))
    })();
}

/// Patch a single connector's config in an existing `.horus/config.json`. If `env_name`
/// is omitted, targets the first environment. Merges `patch` into any existing block.
pub fn patch_local_connector(
    config_path: &Path,
    connector_type: &str,
    patch: Map<String, Value>,
    env_name: Option<&str>,
) -> Result<()> {
    let mut file = read_local_config(config_path)?;
    let envs = file
        .project
        .get_mut("environments")
        .and_then(Value::as_array_mut)
        .filter(|e| !e.is_empty())
        .ok_or_else(|| anyhow!("No environments found in config."))?;
    let first_name = envs[0].get("name").and_then(Value::as_str).unwrap_or_default().to_string();
    let env = match env_name {
        Some(name) => envs.iter_mut().find(|e| e.get("name").and_then(Value::as_str) == Some(name)),
        None => envs.first_mut(),
    }
    .ok_or_else(|| anyhow!("Environment \"{}\" not found in config.", env_name.unwrap_or(&first_name)))?;

    let env_obj = env.as_object_mut().ok_or_else(|| anyhow!("Environment entry is not an object."))?;
    if !env_obj.get("connectors").is_some_and(Value::is_object) {
        env_obj.insert("connectors".to_string(), Value::Object(Map::new()));
    }
    let connectors = env_obj.get_mut("connectors").and_then(Value::as_object_mut).expect("connectors object");
    let mut merged = connectors.get(connector_type).and_then(Value::as_object).cloned().unwrap_or_default();
    merged.extend(patch);
    connectors.insert(connector_type.to_string(), Value::Object(merged));

    let root = config_path.to_string_lossy().replacen(&format!("/{HORUS_DIR}/{LOCAL_CONFIG_FILE}"), "", 1);
    write_local_config(Path::new(&root), &file)?;
    Ok(())
}
