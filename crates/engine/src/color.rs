//! Tiny ANSI colour helper mirroring `picocolors` detection semantics:
//! no colour when `NO_COLOR` is set, `FORCE_COLOR=0`, `--no-color`, or stdout is
//! not a TTY (or `TERM=dumb`); colour when `FORCE_COLOR` (non-zero), `--color`,
//! or `CI` is set. Detection runs once per process.

use std::io::IsTerminal;
use std::sync::OnceLock;

fn detect() -> bool {
    let env = |k: &str| std::env::var(k).ok();
    let argv: Vec<String> = std::env::args().collect();
    if env("NO_COLOR").is_some() || argv.iter().any(|a| a == "--no-color") {
        return false;
    }
    if let Some(v) = env("FORCE_COLOR") {
        return v != "0";
    }
    if argv.iter().any(|a| a == "--color") || env("CI").is_some() || cfg!(windows) {
        return true;
    }
    std::io::stdout().is_terminal() && env("TERM").as_deref() != Some("dumb")
}

/// Whether colour output is enabled for this process.
pub fn is_color_supported() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(detect)
}

/// picocolors `formatter`: wraps `s` in open/close codes and re-opens after any
/// embedded close so nested colours survive.
fn wrap(open: &str, close: &str, replace: &str, s: &str) -> String {
    if !is_color_supported() {
        return s.to_string();
    }
    let body = match s.find(close) {
        Some(_) => s.replace(close, replace),
        None => s.to_string(),
    };
    format!("{open}{body}{close}")
}

macro_rules! style {
    ($name:ident, $open:literal, $close:literal, $replace:literal) => {
        pub fn $name(s: &str) -> String {
            wrap($open, $close, $replace, s)
        }
    };
}

style!(reset, "\x1b[0m", "\x1b[0m", "\x1b[0m");
style!(bold, "\x1b[1m", "\x1b[22m", "\x1b[22m\x1b[1m");
style!(dim, "\x1b[2m", "\x1b[22m", "\x1b[22m\x1b[2m");
style!(italic, "\x1b[3m", "\x1b[23m", "\x1b[23m");
style!(underline, "\x1b[4m", "\x1b[24m", "\x1b[24m");
style!(inverse, "\x1b[7m", "\x1b[27m", "\x1b[27m");
style!(hidden, "\x1b[8m", "\x1b[28m", "\x1b[28m");
style!(strikethrough, "\x1b[9m", "\x1b[29m", "\x1b[29m");
style!(black, "\x1b[30m", "\x1b[39m", "\x1b[39m");
style!(red, "\x1b[31m", "\x1b[39m", "\x1b[39m");
style!(green, "\x1b[32m", "\x1b[39m", "\x1b[39m");
style!(yellow, "\x1b[33m", "\x1b[39m", "\x1b[39m");
style!(blue, "\x1b[34m", "\x1b[39m", "\x1b[39m");
style!(magenta, "\x1b[35m", "\x1b[39m", "\x1b[39m");
style!(cyan, "\x1b[36m", "\x1b[39m", "\x1b[39m");
style!(white, "\x1b[37m", "\x1b[39m", "\x1b[39m");
style!(gray, "\x1b[90m", "\x1b[39m", "\x1b[39m");
style!(bg_black, "\x1b[40m", "\x1b[49m", "\x1b[49m");
style!(bg_red, "\x1b[41m", "\x1b[49m", "\x1b[49m");
style!(bg_green, "\x1b[42m", "\x1b[49m", "\x1b[49m");
style!(bg_yellow, "\x1b[43m", "\x1b[49m", "\x1b[49m");
style!(bg_blue, "\x1b[44m", "\x1b[49m", "\x1b[49m");
style!(bg_magenta, "\x1b[45m", "\x1b[49m", "\x1b[49m");
style!(bg_cyan, "\x1b[46m", "\x1b[49m", "\x1b[49m");
style!(bg_white, "\x1b[47m", "\x1b[49m", "\x1b[49m");
