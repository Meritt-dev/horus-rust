//! Port of `packages/cli/src/commands/trace.ts`.

use anyhow::Result;
use horus_connectors::source::{SourceClientOptions, SourceHttpClient, SourceTraceResult, TraceOptions};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::engine_code::{fail, load_config};
use crate::lib::ensure_host::{ensure_host_reason_hint, ensure_own_source_host};
use crate::lib::format::{dim, red};

/// Visual confidence indicator mirroring the source host's MCP renderer.
fn confidence_tag(confidence: f64) -> &'static str {
    if confidence >= 0.9 {
        ""
    } else if confidence >= 0.5 {
        " (~)"
    } else {
        " (?)"
    }
}

/// Build the `A --calls--> B <--imports-- C` arrow chain from the structured result.
pub fn render_trace(result: &SourceTraceResult) -> String {
    if !result.found {
        let mut lines = vec![result.error.clone().unwrap_or_else(|| "No path found.".into())];
        for n in result.notes.iter().flatten() {
            lines.push(dim(&format!("  {n}")));
        }
        return lines.join("\n");
    }
    let path = result.path.as_deref().unwrap_or_default();
    let segments = result.segments.as_deref().unwrap_or_default();
    let name_at = |i: usize| path.get(i).map_or("?", |n| n.name.as_str());
    let mut chain = vec![name_at(0).to_string()];
    for (i, seg) in segments.iter().enumerate() {
        let tag = confidence_tag(seg.confidence);
        let next = name_at(i + 1);
        chain.push(if seg.direction == "out" {
            format!("--{}{tag}--> {next}", seg.rel_type)
        } else {
            format!("<--{}{tag}-- {next}", seg.rel_type)
        });
    }
    let hops = result.hops.unwrap_or(segments.len() as i64);
    let mut out = vec![format!("Trace: {} ({hops} hop{})", chain.join(" "), if hops == 1 { "" } else { "s" }), String::new()];
    for (i, n) in path.iter().enumerate() {
        let mut label = n.label.clone();
        if let Some(f) = label.get(..1) {
            label = f.to_uppercase() + &label[1..];
        }
        out.push(format!("  {}. {} ({label}) — {}:{}", i + 1, n.name, n.file_path, n.start_line));
    }
    for n in result.notes.iter().flatten() {
        out.push(String::new());
        out.push(dim(n));
    }
    out.join("\n")
}

pub async fn run(args: &TraceArgs) -> Result<()> {
    trace(args).await.map_err(|e| fail(e, args.json))
}

async fn trace(args: &TraceArgs) -> Result<()> {
    load_config(&args.config)?;
    let host = ensure_own_source_host(&std::env::current_dir()?, None).await;
    let Some(host_url) = host.host_url.clone().filter(|_| host.ok) else {
        let hint = ensure_host_reason_hint(host.reason);
        if args.json {
            let v = serde_json::json!({ "error": "Source-intelligence host unavailable", "hint": hint });
            println!("{}", horus_core::json::to_js_json_pretty(&v)?);
        } else {
            eprintln!("{}", red("Source-intelligence host unavailable"));
            eprintln!("{}", dim(&format!("  {hint}")));
        }
        return Err(SilentExit(1).into());
    };

    let client = SourceHttpClient::new(SourceClientOptions::new(host_url));
    let relations = args.relations.as_ref().map(|r| {
        r.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect::<Vec<_>>()
    });
    let result = client
        .trace(&args.from, &args.to, &TraceOptions { max_depth: args.max_depth.map(i64::from), relations })
        .await?;

    if args.json {
        println!("{}", horus_core::json::to_js_json_pretty(&result)?);
    } else {
        println!("{}", render_trace(&result));
    }
    // A resolution failure or unreachable target is a non-zero exit so scripts can react.
    if result.found {
        Ok(())
    } else {
        Err(SilentExit(1).into())
    }
}
