//! Multi-repository helpers (HOR-28): fan-out queries to every configured source-intelligence
//! host. Failures are captured as `reachable: false` rather than aborting the whole fan-out.

use crate::code_provider::{fetch_host_repo_path, RepoProvider};
use crate::seeds::resolve_symbol_query;
use futures::future::join_all;
use horus_core::Symbol;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoSearchResult {
    pub repo: String,
    pub host_url: String,
    pub reachable: bool,
    pub symbols: Vec<Symbol>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoHealth {
    pub repo: String,
    pub path: String,
    pub host_url: String,
    pub reachable: bool,
    pub detail: String,
}

/// `path.resolve(p)` equivalent for the identity check: absolute + lexically normalised.
fn resolve_path(p: &str) -> PathBuf {
    let path = Path::new(p);
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map(|d| d.join(path)).unwrap_or_else(|_| path.to_path_buf())
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    out
}

/// Check the source-intelligence host health for every configured repository concurrently,
/// using the injectable identity probe `served_path` (GET /api/host repoPath).
pub async fn repos_health_with<F, Fut>(providers: &[RepoProvider], served_path: F) -> Vec<RepoHealth>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Option<String>>,
{
    let served_path = &served_path;
    join_all(providers.iter().map(|provider| async move {
        let h = provider.code.health().await;
        // Identity check: the shared default port means "healthy" can be a FOREIGN repo's host.
        if h.ok {
            if let Some(served) = served_path(provider.host_url.clone()).await {
                if resolve_path(&served) != resolve_path(&provider.path) {
                    return RepoHealth {
                        repo: provider.name.clone(),
                        path: provider.path.clone(),
                        host_url: provider.host_url.clone(),
                        reachable: false,
                        detail: format!("foreign host on port — serves {served}"),
                    };
                }
            }
        }
        RepoHealth {
            repo: provider.name.clone(),
            path: provider.path.clone(),
            host_url: provider.host_url.clone(),
            reachable: h.ok,
            detail: h.detail,
        }
    }))
    .await
}

/// `repos_health_with` using the live `/api/host` probe.
pub async fn repos_health(providers: &[RepoProvider]) -> Vec<RepoHealth> {
    repos_health_with(providers, |url| async move { fetch_host_repo_path(&url).await }).await
}

/// Search symbols across ALL configured repositories concurrently. Unreachable hosts yield an
/// empty `symbols` array and `reachable: false` rather than failing.
pub async fn search_across_repos(query: &str, providers: &[RepoProvider], limit: Option<usize>) -> Vec<RepoSearchResult> {
    let limit = limit.unwrap_or(8);
    join_all(providers.iter().map(|provider| async move {
        let unreachable = || RepoSearchResult {
            repo: provider.name.clone(),
            host_url: provider.host_url.clone(),
            reachable: false,
            symbols: vec![],
        };
        let h = provider.code.health().await;
        // Shared-resolver semantics (same as explain/blast-radius/investigate): exact matches
        // lead — qualified ones first — and product code outranks tests.
        let symbols = if h.ok {
            match provider.code.search_symbols(query, Some(limit)).await {
                Ok(found) => resolve_symbol_query(query, found).candidates,
                Err(_) => return unreachable(),
            }
        } else {
            vec![]
        };
        RepoSearchResult { repo: provider.name.clone(), host_url: provider.host_url.clone(), reachable: h.ok, symbols }
    }))
    .await
}
