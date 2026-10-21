//! `horus report [hint]` (HOR-439) — file a bug / capability gap against Horus.
//! Port of `packages/cli/src/commands/report-issue.ts`.
//!
//! Builds a PRE-FILLED GitHub issue URL on meritt-dev/horus and best-effort opens it in the
//! browser. NO auth, NO API call. The URL is ALWAYS printed (headless boxes). The builder is
//! shared with the `report_issue` MCP tool so both produce byte-identical output.

use anyhow::Result;
use horus_core::{HORUS_VERSION, PINNED_SOURCE_VERSION};
use serde::Serialize;

use crate::cli::*;
use crate::lib::format::{bold, cyan, dim};
use crate::lib::open_url::open_browser;

const ISSUE_BASE: &str = "https://github.com/meritt-dev/horus/issues/new";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueEnvironment {
    pub horus_version: String,
    pub source_version: String,
    pub platform: String,
    /// TS reports `process.version`; the Rust build reports its runtime instead (see DIVERGENCES).
    pub node_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltIssue {
    pub url: String,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub environment: IssueEnvironment,
}

#[derive(Debug, Clone, Default)]
pub struct IssueOpts<'a> {
    pub title: Option<&'a str>,
    pub body: Option<&'a str>,
    pub labels: Option<&'a str>,
    pub hint: Option<&'a str>,
}

/// Node `process.platform` names.
fn platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

/// Snapshot the runtime environment that rides on every reported issue.
pub fn issue_environment() -> IssueEnvironment {
    IssueEnvironment {
        horus_version: HORUS_VERSION.into(),
        source_version: PINNED_SOURCE_VERSION.into(),
        platform: platform().into(),
        node_version: "n/a (rust build)".into(),
    }
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// Build the pre-filled GitHub issue (title, markdown body with an Environment block, labels,
/// encoded new-issue URL). Pure.
pub fn build_issue(opts: &IssueOpts<'_>) -> BuiltIssue {
    let environment = issue_environment();
    let hint = non_empty(opts.hint);
    let title_full = match (non_empty(opts.title), hint) {
        (Some(t), _) => t.to_string(),
        (None, Some(h)) => format!("Bug/gap: {h}"),
        (None, None) => "Horus bug / capability gap".to_string(),
    };
    // ponytail: JS slices UTF-16 units; chars differ only for astral-plane text.
    let title: String = title_full.chars().take(256).collect();
    let labels: Vec<String> = opts
        .labels
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();

    let mut sections: Vec<String> = vec!["### What happened / what is missing".into()];
    sections.push(non_empty(opts.body).unwrap_or("<!-- Describe the bug or the capability gap you hit. -->").into());
    if let Some(h) = hint {
        sections.push("### Context".into());
        sections.push(h.into());
    }
    sections.push("### Environment".into());
    sections.push(format!(
        "- Horus version: {}\n- Source intelligence: {}\n- OS: {}\n- Node: {}",
        environment.horus_version, environment.source_version, environment.platform, environment.node_version
    ));
    let body = sections.join("\n\n");

    let mut url = url::Url::parse(ISSUE_BASE).expect("static URL");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("title", &title);
        q.append_pair("body", &body);
        if !labels.is_empty() {
            q.append_pair("labels", &labels.join(","));
        }
    }
    BuiltIssue { url: url.to_string(), title, body, labels, environment }
}

pub async fn run(args: &ReportArgs) -> Result<()> {
    let issue = build_issue(&IssueOpts {
        title: args.title.as_deref(),
        body: args.body.as_deref(),
        labels: args.labels.as_deref(),
        hint: args.hint.as_deref(),
    });

    open_browser(&issue.url);

    println!();
    println!("  {} — pre-filled on {}:", bold("File a Horus issue"), cyan("meritt-dev/horus"));
    println!();
    println!("    {}", cyan(&issue.url));
    println!();
    println!("{}", dim("  Your browser should open it; if not, open the URL above. (No data is sent automatically.)"));
    Ok(())
}
