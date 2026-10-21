//! Port of `packages/cli/src/commands/insights.ts`.

use anyhow::Result;
use horus_connectors::source::{InsightsOptions, SourceClientOptions, SourceHttpClient, SourceInsightsResult};

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::engine_code::fail;
use crate::lib::engine_code::load_config;
use crate::lib::ensure_host::{ensure_host_reason_hint, ensure_own_source_host};
use crate::lib::format::{bold, dim, red};

/// Render the graph-insights report as human-readable text.
pub fn render_insights(r: &SourceInsightsResult) -> String {
    let mut out: Vec<String> = vec![];

    out.push(format!("{}{}", bold("Hubs"), dim(" — most-connected symbols")));
    if r.hubs.is_empty() {
        out.push(dim("  none (empty or unindexed graph)"));
    } else {
        for h in &r.hubs {
            let mut chars = h.label.chars();
            let label: String = match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => String::new(),
            };
            out.push(format!(
                "  {:>3}  {} {}",
                h.degree,
                h.name,
                dim(&format!("({label}) — {}:{}", h.file_path, h.start_line))
            ));
        }
    }

    out.push(String::new());
    out.push(format!("{}{}", bold("Surprising connections"), dim(" — edges bridging communities")));
    if r.bridges.is_empty() {
        out.push(dim("  none detected (run community detection first)"));
    } else {
        for b in &r.bridges {
            out.push(format!(
                "  {} --{}--> {}  {}",
                b.source,
                b.rel_type,
                b.target,
                dim(&format!("[{} → {}]", b.source_community, b.target_community))
            ));
        }
    }

    if !r.questions.is_empty() {
        out.push(String::new());
        out.push(bold("Suggested questions"));
        for q in &r.questions {
            out.push(format!("  {} {q}", dim("•")));
        }
    }

    out.join("\n")
}

pub async fn run(args: &InsightsArgs) -> Result<()> {
    run_inner(args).await.map_err(|e| fail(e, args.json))
}

async fn run_inner(args: &InsightsArgs) -> Result<()> {
    load_config(&args.config)?;
    let cwd = std::env::current_dir()?;
    let host = ensure_own_source_host(&cwd, None).await;
    let Some(host_url) = host.host_url.clone().filter(|_| host.ok) else {
        let hint = ensure_host_reason_hint(host.reason);
        if args.json {
            let obj = serde_json::json!({ "error": "Source-intelligence host unavailable", "hint": hint });
            println!("{}", horus_core::json::to_js_json_pretty(&obj)?);
        } else {
            eprintln!("{}", red("Source-intelligence host unavailable"));
            eprintln!("{}", dim(&format!("  {hint}")));
        }
        return Err(SilentExit(1).into());
    };

    let opts = InsightsOptions { hub_limit: args.hubs.map(i64::from), bridge_limit: args.bridges.map(i64::from) };
    if args.json {
        // `JSON.stringify(result)` of the host's own payload: fetch it raw so every field the
        // host returns survives in its own order (the typed struct would drop/reorder keys).
        let mut params: Vec<String> = vec![];
        if let Some(h) = opts.hub_limit {
            params.push(format!("hub_limit={h}"));
        }
        if let Some(b) = opts.bridge_limit {
            params.push(format!("bridge_limit={b}"));
        }
        let qs = if params.is_empty() { String::new() } else { format!("?{}", params.join("&")) };
        let res = reqwest::get(format!("{host_url}/api/insights{qs}")).await?.error_for_status()?;
        let v: serde_json::Value = res.json().await?;
        println!("{}", horus_core::json::to_js_json_pretty(&v)?);
        return Ok(());
    }

    let client = SourceHttpClient::new(SourceClientOptions::new(host_url));
    let result = client.insights(opts).await?;
    println!("{}", render_insights(&result));
    Ok(())
}
