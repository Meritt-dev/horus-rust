//! Horus MCP server (HOR-295) — stdio transport exposing Horus to coding agents.
//! Port of `packages/cli/src/commands/mcp/server.ts`.
//!
//! The TS server uses `@modelcontextprotocol/sdk`; there is no MCP SDK in this workspace, so the
//! stdio JSON-RPC 2.0 protocol (newline-delimited) is implemented directly: `initialize`,
//! `ping`, `tools/list`, `tools/call` (DIVERGENCES.md).

use std::path::{Path, PathBuf};

use anyhow::Result;
use horus_core::find_repo_root;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::cloud_tools::CLOUD_TOOLS;
use super::tools::{Prop, ToolResult, KNOWLEDGE_TOOLS};

const SERVER_INSTRUCTIONS: &str = "Horus exposes THIS project to coding agents. Before grepping or reading the whole repo to answer project-level questions (what owns a feature, which operation/type/enum/auth rule applies, which frontend pattern exists, which worker/queue handles a job), call the Horus knowledge tools first — they read a local index; every result carries provenance and a staleness flag, so if the index is stale, suggest re-running `horus init`. To act on real client-reported problems, call list_lens_reports for the backlog of issues users filed from the app, then get_lens_report for the code seed (file:line) to fix — these are cloud-backed and need `horus login` + `horus cloud link`.";

/// Latest protocol revision this server speaks; a client's requested version is echoed back.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// zod shape → JSON Schema, as the SDK emits it for `registerTool({ inputSchema })`.
fn input_schema(props: &[Prop]) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for (name, ty, desc, req) in props {
        let mut p = Map::new();
        p.insert("type".into(), json!(ty));
        if let Some(d) = desc {
            p.insert("description".into(), json!(d));
        }
        properties.insert((*name).into(), Value::Object(p));
        if *req {
            required.push(json!(name));
        }
    }
    let mut schema = Map::new();
    schema.insert("type".into(), json!("object"));
    schema.insert("properties".into(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".into(), Value::Array(required));
    }
    schema.insert("additionalProperties".into(), json!(false));
    schema.insert("$schema".into(), json!("http://json-schema.org/draft-07/schema#"));
    Value::Object(schema)
}

/// SDK input validation: required keys present and every supplied key well-typed.
fn validate_args(props: &[Prop], args: &Map<String, Value>) -> Result<(), String> {
    for (name, ty, _, req) in props {
        match args.get(*name) {
            None | Some(Value::Null) if *req => return Err(format!("{name}: Required")),
            None => {}
            Some(v) => {
                let ok = match *ty {
                    "string" => v.is_string(),
                    "boolean" => v.is_boolean(),
                    "integer" => v.as_f64().is_some_and(|n| n.fract() == 0.0),
                    _ => true,
                };
                if !ok {
                    return Err(format!("{name}: Expected {ty}"));
                }
            }
        }
    }
    Ok(())
}

fn tool_list() -> Value {
    let mut tools: Vec<Value> = KNOWLEDGE_TOOLS
        .iter()
        .map(|t| json!({ "name": t.name, "description": t.description, "inputSchema": input_schema(t.input) }))
        .collect();
    tools.extend(
        CLOUD_TOOLS.iter().map(|t| json!({ "name": t.name, "description": t.description, "inputSchema": input_schema(t.input) })),
    );
    json!({ "tools": tools })
}

fn render(res: &ToolResult, with_suggestions: bool) -> Value {
    let data = horus_core::json::to_js_json_pretty(res.data.as_ref().unwrap_or(&Value::Null)).unwrap_or_default();
    let steps = res.suggested_next_tools.as_deref().unwrap_or_default();
    // HOR-386 — surface the router's next-tool suggestions as text AND structuredContent.
    let suggestion_text = if with_suggestions && !steps.is_empty() {
        let lines: Vec<String> = steps
            .iter()
            .map(|s| format!("- {}{} — {}", s.next_tool, if s.args.is_empty() { String::new() } else { format!(" {}", s.args) }, s.reason))
            .collect();
        format!("\n\nSuggested next tools:\n{}", lines.join("\n"))
    } else {
        String::new()
    };
    let mut out = Map::new();
    out.insert("content".into(), json!([{ "type": "text", "text": format!("{}\n\n{data}{suggestion_text}", res.summary) }]));
    if with_suggestions && !steps.is_empty() {
        out.insert("structuredContent".into(), json!({ "suggestedNextTools": steps }));
    }
    out.insert("isError".into(), json!(!res.ok));
    Value::Object(out)
}

fn error_result(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

/// `Err((code, message))` becomes a JSON-RPC error response.
async fn call_tool(params: &Value, root: &Path) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").and_then(Value::as_object).cloned().unwrap_or_default();
    if let Some(t) = KNOWLEDGE_TOOLS.iter().find(|t| t.name == name) {
        validate_args(t.input, &args).map_err(|e| (-32602, format!("Invalid arguments for tool {name}: {e}")))?;
        return Ok(render(&(t.handler)(&args, root), true));
    }
    if let Some(t) = CLOUD_TOOLS.iter().find(|t| t.name == name) {
        validate_args(t.input, &args).map_err(|e| (-32602, format!("Invalid arguments for tool {name}: {e}")))?;
        // A thrown handler error becomes an isError tool result, as in the SDK.
        return Ok(match (t.handler)(&args, root).await {
            Ok(res) => render(&res, false),
            Err(e) => error_result(&e.to_string()),
        });
    }
    Err((-32602, format!("Tool {name} not found")))
}

async fn handle(msg: &Value, root: &Path) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    // Notifications (no id) never get a response.
    let id = id?;
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => {
            let requested = msg.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSION);
            Ok(json!({
                "protocolVersion": requested,
                "capabilities": { "tools": { "listChanged": true } },
                "serverInfo": { "name": "horus", "version": "0.1.0" },
                "instructions": SERVER_INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tool_list()),
        "tools/call" => call_tool(msg.get("params").unwrap_or(&Value::Null), root).await,
        _ => Err((-32601, "Method not found".into())),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    })
}

/// Serve MCP over stdio until stdin closes.
pub async fn run_mcp_server(root: Option<PathBuf>) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let root = root.or_else(|| find_repo_root(&cwd)).unwrap_or(cwd);
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&msg, &root).await,
            Err(e) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": format!("Parse error: {e}") } })),
        };
        if let Some(r) = response {
            stdout.write_all((horus_core::json::to_js_json(&r)? + "\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

pub async fn run() -> Result<()> {
    run_mcp_server(None).await
}
