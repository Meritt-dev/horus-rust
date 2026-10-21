//! Horus MCP cloud tools — the Lens work queue over MCP. Port of
//! `packages/cli/src/commands/mcp/cloud-tools.ts`. Cloud-backed and async; all fetch+shape is
//! delegated to `lib/lens/reports.rs` (same core as `horus lens`). Light up only when logged
//! in + cloud-linked; otherwise `ok:false` with a one-line remedy. Read-only.

use std::path::Path;

use futures::future::BoxFuture;
use serde_json::{Map, Value};

use super::tools::{Prop, ToolResult};
use crate::lib::lens::reports::{detail_json, get_lens_report_detail, list_lens_reports, LensDetail, LensListOpts};

pub struct CloudTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input: &'static [Prop],
    pub handler: for<'a> fn(&'a Map<String, Value>, &'a Path) -> BoxFuture<'a, anyhow::Result<ToolResult>>,
}

fn as_string(args: &Map<String, Value>, k: &str) -> Option<String> {
    args.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

fn list<'a>(args: &'a Map<String, Value>, root: &'a Path) -> BoxFuture<'a, anyhow::Result<ToolResult>> {
    Box::pin(async move {
        let opts = LensListOpts {
            status: as_string(args, "status"),
            all: args.get("all") == Some(&Value::Bool(true)),
            limit: args.get("limit").and_then(Value::as_f64).filter(|n| n.is_finite()),
            since: as_string(args, "since"),
            site_id: None,
        };
        Ok(match list_lens_reports(root, &opts).await? {
            Err(u) => ToolResult::fail(format!("Lens work queue unavailable — {}", u.remedy)),
            Ok(result) => {
                let n = result.reports.len();
                ToolResult {
                    ok: true,
                    summary: if n == 0 {
                        "No client-reported Lens issues.".into()
                    } else {
                        format!("{n} client-reported issue(s) across {} site(s). Use get_lens_report <id> for the code seed.", result.sites)
                    },
                    data: Some(serde_json::to_value(&result)?),
                    suggested_next_tools: None,
                }
            }
        })
    })
}

fn get<'a>(args: &'a Map<String, Value>, root: &'a Path) -> BoxFuture<'a, anyhow::Result<ToolResult>> {
    Box::pin(async move {
        let Some(report_id) = as_string(args, "reportId") else { return Ok(ToolResult::fail("reportId is required.")) };
        Ok(match get_lens_report_detail(root, &report_id, as_string(args, "site").as_deref()).await? {
            LensDetail::Unavailable(u) => ToolResult::fail(format!("Lens work queue unavailable — {}", u.remedy)),
            LensDetail::NotFound { .. } => ToolResult::fail(format!("No Lens report {report_id} in this workspace.")),
            LensDetail::Found(detail) => {
                let data = detail_json(&detail)?;
                let seed = match &detail.seed {
                    Some(s) => format!(" Seed: {}{}", s.file, s.line.map(|l| format!(":{l}")).unwrap_or_default()),
                    None => " No code seed (no parseable stack frame).".into(),
                };
                let field = |k: &str| data.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                ToolResult {
                    ok: true,
                    summary: format!("Lens report {} [{}].{seed}", field("id"), field("status")),
                    data: Some(data),
                    suggested_next_tools: None,
                }
            }
        })
    })
}

/// The Lens work-queue MCP tools (cloud-backed; bound to a repo root at call time).
pub const CLOUD_TOOLS: &[CloudTool] = &[
    CloudTool {
        name: "list_lens_reports",
        description: "List client-reported Lens issues (bug reports users filed from the running app) as a work queue — newest first, across the workspace. Use this to find real user-reported problems to fix, independent of any investigation. Needs the CLI logged in (`horus login`) and the repo cloud-linked (`horus cloud link`); returns a remedy otherwise. Each row: id, status, route, comment, errorCount. Call get_lens_report for the code seed (file:line) to fix.",
        input: &[
            ("status", "string", Some("Filter by report status (default: submitted)."), false),
            ("all", "boolean", Some("Include every status (drop the default submitted filter)."), false),
            ("limit", "integer", Some("Max reports, 1–200 (default 50)."), false),
            ("since", "string", Some("Only reports created on/after this ISO date."), false),
        ],
        handler: list,
    },
    CloudTool {
        name: "get_lens_report",
        description: "Fetch one Lens report in full: comment, route, release/gitSha, failing requests, top error message, and the code seed (file:line:symbol — the raise site to fix). Needs login + cloud link.",
        input: &[
            ("reportId", "string", Some("The Lens report id (e.g. rep_abc123)."), true),
            ("site", "string", Some("The report's Lens site id (skips the cross-site scan)."), false),
        ],
        handler: get,
    },
];
