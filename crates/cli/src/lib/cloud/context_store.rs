//! Repo cloud-context store: `<repo>/.horus/cloud.json`. Port of
//! `packages/cli/src/lib/cloud/context-store.ts`.
//!
//! Holds IDs + slugs only — never the token. It is a CACHE of *which* Cloud project this repo
//! syncs to, not a connection or an auth boundary (HOR-298): the CLI engine still uses its
//! embedded local database for all local execution state.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::paths::cloud_config_path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ref {
    pub id: String,
    pub slug: String,
}

/// @deprecated A project IS the repository now (HOR-280); retained so legacy configs parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudConfig {
    /// Where this repo's investigations are stored: `"local"` | `"cloud"`.
    pub context: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<Ref>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<Ref>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<Ref>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RepositoryRef>,
    /// Unknown keys, preserved like the TS `JSON.parse` cast.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub fn read_cloud_config(root: &Path) -> Option<CloudConfig> {
    let raw = std::fs::read_to_string(cloud_config_path(root)).ok()?;
    let parsed: CloudConfig = serde_json::from_str(&raw).ok()?;
    if parsed.context != "local" && parsed.context != "cloud" {
        return None;
    }
    Some(parsed)
}

pub fn write_cloud_config(root: &Path, cfg: &CloudConfig) -> Result<()> {
    let p = cloud_config_path(root);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(p, serde_json::to_string_pretty(cfg)? + "\n")?;
    Ok(())
}

pub fn clear_cloud_config(root: &Path) {
    let _ = std::fs::remove_file(cloud_config_path(root));
}

/// True when the repo is actively storing investigations in the cloud.
pub fn is_cloud_active(cfg: Option<&CloudConfig>) -> bool {
    matches!(cfg, Some(c) if c.context == "cloud" && c.project.is_some())
}
