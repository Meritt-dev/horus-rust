//! Port of `packages/cli/src/lib/format.ts` (`format_date_time`), plus the colour gate and the
//! picocolors subset the commands use (`bold`/`dim`/…) — picocolors has no Rust equivalent, so
//! the same escape sequences live here, disabled under `NO_COLOR` / `FORCE_COLOR=0` / non-TTY.

use std::io::IsTerminal;

use chrono::{DateTime, Local, Utc};

/// `NO_COLOR` (any value) and `FORCE_COLOR=0` disable colour; any other `FORCE_COLOR` forces
/// it on; otherwise colour follows whether stdout is a TTY.
pub fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match std::env::var("FORCE_COLOR") {
        Ok(v) if v == "0" => false,
        Ok(_) => true,
        Err(_) => std::io::stdout().is_terminal(),
    }
}

fn paint(open: &str, close: &str, s: &str) -> String {
    if color_enabled() {
        format!("\x1b[{open}m{s}\x1b[{close}m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    paint("1", "22", s)
}
pub fn dim(s: &str) -> String {
    paint("2", "22", s)
}
pub fn red(s: &str) -> String {
    paint("31", "39", s)
}
pub fn green(s: &str) -> String {
    paint("32", "39", s)
}
pub fn yellow(s: &str) -> String {
    paint("33", "39", s)
}
pub fn cyan(s: &str) -> String {
    paint("36", "39", s)
}

/// Human-readable date for CLI lists: local time with an explicit UTC offset so users can
/// reason about when an investigation happened without converting from ISO-8601.
/// Example: `2026-06-16 14:49 (UTC+03:00)`.
pub fn format_date_time(date: &DateTime<Utc>) -> String {
    let local = date.with_timezone(&Local);
    let offset = local.offset().local_minus_utc() / 60;
    let sign = if offset >= 0 { '+' } else { '-' };
    format!(
        "{} (UTC{}{:02}:{:02})",
        local.format("%Y-%m-%d %H:%M"),
        sign,
        offset.abs() / 60,
        offset.abs() % 60
    )
}
