//! `horus lens` — the client-reported issue work queue (HOR-CLI). Port of
//! `packages/cli/src/commands/lens.ts`. Thin adapter over `lib/lens/reports.rs`; needs
//! `horus login` + `horus cloud link`, and under --json always emits valid JSON.

use anyhow::Result;
use chrono::{DateTime, Utc};
use horus_core::json::to_js_json_pretty;

use crate::cli::*;
use crate::commands::context::exit;
use crate::lib::cloud::session::repo_root_or_cwd;
use crate::lib::format::{bold, cyan, dim, format_date_time, green, red, yellow};
use crate::lib::lens::reports::{get_lens_report_detail, list_lens_reports, LensDetail, LensListOpts, LensReportRow};

fn truncate(s: Option<&str>, n: usize) -> String {
    let Some(s) = s.filter(|s| !s.is_empty()) else { return String::new() };
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let units: Vec<u16> = flat.encode_utf16().collect();
    if units.len() > n {
        format!("{}…", String::from_utf16_lossy(&units[..n - 1]))
    } else {
        flat
    }
}

/// `formatDateTime(new Date(s))`; an unparseable date prints `Invalid Date` like JS.
fn fmt_date(s: &str) -> String {
    match DateTime::parse_from_rfc3339(s) {
        Ok(t) => format_date_time(&t.with_timezone(&Utc)),
        Err(_) => "Invalid Date".into(),
    }
}

fn js_num(n: f64) -> String {
    horus_core::json::to_js_json(&n).unwrap_or_else(|_| n.to_string())
}

fn print_row(r: &LensReportRow) {
    let ts = fmt_date(&r.created_at);
    let status = dim(&format!("[{}]", if r.status.is_empty() { "?" } else { &r.status }));
    let route = r.route.as_deref().map_or_else(|| dim("(no route)"), cyan);
    let errs = if r.error_count > 0.0 { red(&format!("{}err", js_num(r.error_count))) } else { dim("0err") };
    let comment = truncate(r.comment.as_deref(), 60);
    let comment = if comment.is_empty() { dim("(no comment)") } else { comment };
    println!("{}  {ts}  {status}  {route}  {comment}  {errs}", r.id);
}

pub async fn run_lens_list(opts: &LensListArgs) -> Result<u8> {
    let json = opts.json;
    let root = repo_root_or_cwd(None);
    let list_opts = LensListOpts {
        status: opts.status.clone(),
        all: opts.all,
        limit: opts.limit.map(f64::from),
        since: opts.since.clone(),
        site_id: opts.site.clone(),
    };
    let result = match list_lens_reports(&root, &list_opts).await {
        Ok(r) => r,
        Err(err) => {
            let message = err.to_string();
            if json {
                println!("{}", to_js_json_pretty(&serde_json::json!({ "reports": [], "count": 0, "notes": [message] }))?);
            }
            eprintln!("{}", red(&message));
            return Ok(1);
        }
    };
    let result = match result {
        Ok(r) => r,
        Err(u) => {
            if json {
                println!("{}", to_js_json_pretty(&serde_json::json!({ "reports": [], "count": 0, "notes": [u.remedy] }))?);
            } else {
                println!("{}", yellow(&format!("Lens work queue unavailable — {}", u.remedy)));
            }
            return Ok(if json { 0 } else { 1 });
        }
    };
    if json {
        let mut out = serde_json::json!({ "reports": result.reports, "count": result.reports.len(), "sites": result.sites });
        if let Some(n) = &result.notes {
            out["notes"] = serde_json::json!(n);
        }
        println!("{}", to_js_json_pretty(&out)?);
        return Ok(0);
    }
    if result.reports.is_empty() {
        println!("No client reports. Clients file them from the app via Horus Lens.");
        return Ok(0);
    }
    for r in &result.reports {
        print_row(r);
    }
    println!("{}", dim(&format!("\n{} report(s) · detail: horus lens show <id>", result.reports.len())));
    for n in result.notes.iter().flatten() {
        println!("{}", dim(n));
    }
    Ok(0)
}

pub async fn run_lens_show(args: &LensShowArgs) -> Result<u8> {
    let json = args.json;
    let root = repo_root_or_cwd(None);
    let detail = match get_lens_report_detail(&root, &args.report_id, args.site.as_deref()).await {
        Ok(d) => d,
        Err(err) => {
            let message = err.to_string();
            if json {
                println!("{}", to_js_json_pretty(&serde_json::json!({ "error": message }))?);
            }
            eprintln!("{}", red(&message));
            return Ok(1);
        }
    };
    let detail = match detail {
        LensDetail::Found(d) => d,
        LensDetail::Unavailable(u) => {
            if json {
                println!("{}", to_js_json_pretty(&serde_json::json!({ "error": u.remedy }))?);
            } else {
                println!("{}", yellow(&format!("Lens work queue unavailable — {}", u.remedy)));
            }
            return Ok(if json { 0 } else { 1 });
        }
        LensDetail::NotFound { .. } => {
            let msg = format!("No Lens report {} in this workspace.", args.report_id);
            if json {
                println!("{}", to_js_json_pretty(&serde_json::json!({ "error": msg, "notFound": true }))?);
            } else {
                println!("{}", yellow(&msg));
            }
            return Ok(1);
        }
    };
    if json {
        println!("{}", to_js_json_pretty(&*detail)?);
        return Ok(0);
    }
    let s = &detail.signal;
    println!("{}  {}", bold(&format!("Lens report {}", s.id)), dim(&format!("[{}]", s.status)));
    if let Some(c) = s.comment.as_deref().filter(|c| !c.is_empty()) {
        println!("  {}   {}", bold("comment"), truncate(Some(c), 200));
    }
    if let Some(r) = s.route.as_deref().filter(|r| !r.is_empty()) {
        println!("  {}     {}", bold("route"), cyan(r));
    }
    println!("  {}     {}", bold("filed"), fmt_date(&s.created_at));
    if let Some(r) = s.release.as_deref().filter(|r| !r.is_empty()) {
        println!("  {}   {r}", bold("release"));
    }
    if let Some(g) = s.git_sha.as_deref().filter(|g| !g.is_empty()) {
        println!("  {}    {g}", bold("gitSha"));
    }
    if let Some(e) = s.top_error_message.as_deref().filter(|e| !e.is_empty()) {
        println!("  {}     {}", bold("error"), red(&truncate(Some(e), 160)));
    }
    if let Some(seed) = &detail.seed {
        let loc = format!("{}{}", seed.file, seed.line.map(|l| format!(":{l}")).unwrap_or_default());
        let sym = seed.symbol.as_deref().map(|s| dim(&format!(" ({s})"))).unwrap_or_default();
        println!("  {}      {}{sym}  {}", bold("seed"), green(&loc), dim("← raise site to fix"));
    }
    if !s.failing_requests.is_empty() {
        println!("  {}", bold("failing"));
        for req in &s.failing_requests {
            let status = req.status.map_or_else(|| "?".to_string(), |s| s.to_string());
            println!("    {} {} {}", req.method, req.url, red(&status));
        }
    }
    Ok(0)
}

pub async fn run(args: &LensArgs) -> Result<()> {
    let code = match &args.command {
        Some(LensCommand::Show(a)) => run_lens_show(a).await?,
        Some(LensCommand::List(a)) => run_lens_list(a).await?,
        None => run_lens_list(&args.list).await?,
    };
    exit(code)
}
