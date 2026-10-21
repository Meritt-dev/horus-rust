//! Commander.js (v12.1.0) compatibility layer over the clap `Command` tree: help rendering,
//! usage errors and exit codes, byte-identical to the TS CLI. clap stays the source of truth for
//! the arg definitions and does the real parse; this module only replays commander's argv walk
//! (`Command._parseCommand` / `parseOptions`) to decide what commander would print and exit with,
//! and which excess operands commander would silently ignore (`allowExcessArguments` defaults to
//! true in v12, clap would reject them).
//!
//! Model mapping (clap → commander):
//! - a command with subcommands and `subcommand_required` has no action handler, so it gets
//!   commander's implicit `help [command]` subcommand and prints help on stderr (exit 1) when run
//!   bare;
//! - `args_conflicts_with_subcommands` marks a commander default subcommand (`{ isDefault: true }`):
//!   the first subcommand; the parent's flattened args belong to it, not the parent;
//! - clap's generated `help` arg / subcommand stand in for commander's help option / command.

use std::collections::VecDeque;
use std::io::IsTerminal;
use std::sync::OnceLock;

use clap::{Arg, ArgAction, Command};
use regex::Regex;

/// What commander would print and the exit code, when it would not run an action.
pub struct Exit {
    pub stdout: String,
    pub stderr: String,
    pub code: u8,
}

// ---------------------------------------------------------------------------------------------
// text helpers (JS string semantics: lengths are UTF-16 code units)
// ---------------------------------------------------------------------------------------------

fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn pad_end(s: &str, width: usize) -> String {
    let n = js_len(s);
    format!("{s}{}", " ".repeat(width.saturating_sub(n)))
}

// JS `\s` minus nothing: tab, LF, VT, FF, CR, space, NBSP, Unicode spaces, line/para separators, BOM.
const JS_SPACE: &str = r"\t\n\x0B\x0C\r \u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}";

/// Port of commander `Help.wrap(str, width, indent, minColumnWidth = 40)`.
fn wrap(s: &str, width: usize, indent: usize) -> String {
    static MANUAL: OnceLock<Regex> = OnceLock::new();
    let manual = MANUAL.get_or_init(|| {
        Regex::new(r"\n[ \x0C\t\x0B\u{a0}\u{1680}\u{2000}-\u{200a}\u{202f}\u{205f}\u{3000}\u{feff}]+")
            .unwrap()
    });
    if manual.is_match(s) {
        return s.to_string();
    }
    let column_width = width as isize - indent as isize;
    if column_width < 40 {
        return s.to_string();
    }
    let split = s.char_indices().nth(indent).map_or(s.len(), |(i, _)| i);
    let (leading, rest) = s.split_at(split);
    let column_text = rest.replacen("\r\n", "\n", 1);
    let breaks = format!(r"{JS_SPACE}\u{{200B}}");
    let re = Regex::new(&format!(
        r"\n|[^\n\r\u{{2028}}\u{{2029}}]{{1,{}}}([{breaks}]|$)|[^{breaks}]+?([{breaks}]|$)",
        column_width - 1
    ))
    .unwrap();
    let indent_str = " ".repeat(indent);
    let lines: Vec<String> = re
        .find_iter(&column_text)
        .enumerate()
        .map(|(i, m)| {
            let line = m.as_str();
            if line == "\n" {
                return String::new();
            }
            let pre = if i > 0 { indent_str.as_str() } else { "" };
            format!("{pre}{}", line.trim_end())
        })
        .collect();
    format!("{leading}{}", lines.join("\n"))
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

// ---------------------------------------------------------------------------------------------
// clap → commander model
// ---------------------------------------------------------------------------------------------

fn is_help_arg(a: &Arg) -> bool {
    matches!(a.get_action(), ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong)
}

fn subcommands(cmd: &Command) -> Vec<&Command> {
    cmd.get_subcommands().filter(|c| c.get_name() != "help").collect()
}

/// Commander `{ isDefault: true }` subcommand.
fn default_sub(cmd: &Command) -> Option<&Command> {
    if cmd.is_args_conflicts_with_subcommands_set() {
        subcommands(cmd).into_iter().next()
    } else {
        None
    }
}

fn has_action(cmd: &Command) -> bool {
    subcommands(cmd).is_empty()
        || !(cmd.is_subcommand_required_set() || cmd.is_args_conflicts_with_subcommands_set())
}

/// Commander's implicit `help [command]`: commands present and no action handler.
fn has_help_command(cmd: &Command) -> bool {
    !subcommands(cmd).is_empty() && !has_action(cmd)
}

/// Commander `cmd.options` (registration order; excludes the help option).
fn options(cmd: &Command) -> Vec<&Arg> {
    if default_sub(cmd).is_some() {
        return vec![];
    }
    cmd.get_arguments().filter(|a| !a.is_positional() && !is_help_arg(a)).collect()
}

fn positionals(cmd: &Command) -> Vec<&Arg> {
    cmd.get_positionals().collect()
}

#[derive(PartialEq)]
enum Takes {
    Nothing,
    Required,
    Optional,
}

fn takes(a: &Arg) -> Takes {
    if !matches!(a.get_action(), ArgAction::Set | ArgAction::Append) {
        return Takes::Nothing;
    }
    match a.get_num_args() {
        Some(r) if r.max_values() == 0 => Takes::Nothing,
        Some(r) if r.min_values() == 0 => Takes::Optional,
        _ => Takes::Required,
    }
}

fn is_variadic(a: &Arg) -> bool {
    a.get_num_args().is_some_and(|r| r.max_values() > 1)
}

fn value_name(a: &Arg) -> String {
    a.get_value_names()
        .map(|v| v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| a.get_id().to_string())
}

/// Commander `option.flags`, e.g. `-c, --config <path>`.
fn option_flags(a: &Arg) -> String {
    let mut names = vec![];
    if let Some(s) = a.get_short() {
        names.push(format!("-{s}"));
    }
    if let Some(l) = a.get_long() {
        names.push(format!("--{l}"));
    }
    let mut flags = names.join(", ");
    let dots = if is_variadic(a) { "..." } else { "" };
    match takes(a) {
        Takes::Required => flags.push_str(&format!(" <{}{dots}>", value_name(a))),
        Takes::Optional => flags.push_str(&format!(" [{}{dots}]", value_name(a))),
        Takes::Nothing => {}
    }
    flags
}

fn choices(a: &Arg) -> Vec<String> {
    a.get_possible_values().iter().map(|p| p.get_name().to_string()).collect()
}

fn numeric(a: &Arg) -> bool {
    use std::any::TypeId;
    let t = a.get_value_parser().type_id();
    [
        TypeId::of::<u8>(),
        TypeId::of::<u16>(),
        TypeId::of::<u32>(),
        TypeId::of::<u64>(),
        TypeId::of::<usize>(),
        TypeId::of::<i32>(),
        TypeId::of::<i64>(),
        TypeId::of::<f32>(),
        TypeId::of::<f64>(),
    ]
    .iter()
    .any(|id| t == *id)
}

/// `(default: "x")` text: JSON of the default, unquoted when the TS side defaults to a number.
fn default_desc(a: &Arg) -> Option<String> {
    if a.is_hide_default_value_set() {
        return None;
    }
    let d = a.get_default_values();
    let list = is_variadic(a) || matches!(a.get_action(), ArgAction::Append);
    if d.is_empty() {
        // Repeatable TS options are collectors seeded with `[]`, which commander displays.
        return list.then(|| "[]".to_string());
    }
    let vals: Vec<String> = d
        .iter()
        .map(|v| {
            let v = v.to_string_lossy();
            if numeric(a) { v.into_owned() } else { json_str(&v) }
        })
        .collect();
    Some(if list {
        format!("[{}]", vals.join(","))
    } else {
        vals.join(",")
    })
}

fn help_text(a: &Arg) -> String {
    a.get_long_help().or(a.get_help()).map(|h| h.to_string()).unwrap_or_default()
}

/// Commander `Help.optionDescription`.
fn option_description(a: &Arg) -> String {
    let mut extra = vec![];
    let ch = choices(a);
    if !ch.is_empty() && !a.is_hide_possible_values_set() {
        extra.push(format!(
            "choices: {}",
            ch.iter().map(|c| json_str(c)).collect::<Vec<_>>().join(", ")
        ));
    }
    if takes(a) != Takes::Nothing {
        if let Some(d) = default_desc(a) {
            extra.push(format!("default: {d}"));
        }
    }
    let desc = help_text(a);
    if extra.is_empty() { desc } else { format!("{desc} ({})", extra.join(", ")) }
}

/// Commander `Help.argumentDescription`.
fn argument_description(a: &Arg) -> String {
    let mut extra = vec![];
    let ch = choices(a);
    if !ch.is_empty() && !a.is_hide_possible_values_set() {
        extra.push(format!(
            "choices: {}",
            ch.iter().map(|c| json_str(c)).collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(d) = default_desc(a) {
        extra.push(format!("default: {d}"));
    }
    let desc = help_text(a);
    match (extra.is_empty(), desc.is_empty()) {
        (true, _) => desc,
        (false, true) => format!("({})", extra.join(", ")),
        (false, false) => format!("{desc} ({})", extra.join(", ")),
    }
}

/// Commander `humanReadableArgName`.
fn arg_usage(a: &Arg) -> String {
    let name = format!("{}{}", value_name(a), if is_variadic(a) { "..." } else { "" });
    if a.is_required_set() { format!("<{name}>") } else { format!("[{name}]") }
}

fn about(cmd: &Command) -> String {
    cmd.get_long_about().or(cmd.get_about()).map(|s| s.to_string()).unwrap_or_default()
}

/// Commander `Help.subcommandTerm`.
fn subcommand_term(cmd: &Command) -> String {
    let mut t = cmd.get_name().to_string();
    if let Some(alias) = cmd.get_visible_aliases().next() {
        t.push('|');
        t.push_str(alias);
    }
    if !options(cmd).is_empty() {
        t.push_str(" [options]");
    }
    let args: Vec<String> = positionals(cmd).iter().map(|a| arg_usage(a)).collect();
    if !args.is_empty() {
        t.push(' ');
        t.push_str(&args.join(" "));
    }
    t
}

// ---------------------------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------------------------

const HELP_FLAGS: &str = "-h, --help";
const HELP_DESC: &str = "display help for command";

/// Commander `helpWidth`: the stream's columns when it is a TTY, else 80.
fn help_width(error: bool) -> usize {
    let tty = if error { std::io::stderr().is_terminal() } else { std::io::stdout().is_terminal() };
    if !tty {
        return 80;
    }
    // ponytail: shells out to `stty size` instead of an ioctl dependency; only runs on a TTY.
    std::fs::File::open("/dev/tty")
        .ok()
        .and_then(|tty| std::process::Command::new("stty").arg("size").stdin(tty).output().ok())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().nth(1).and_then(|c| c.parse().ok()))
        .unwrap_or(80)
}

/// Commander `Help.formatHelp` plus `addHelpText('after', …)`. `path` is the ancestor chain
/// (root first) ending with `cmd`.
fn format_help(path: &[&Command], error: bool) -> String {
    let cmd = *path.last().unwrap();
    let width = help_width(error);

    let mut usage_parts = vec!["[options]".to_string()];
    if !subcommands(cmd).is_empty() {
        usage_parts.push("[command]".into());
    }
    usage_parts.extend(positionals(cmd).iter().map(|a| arg_usage(a)));
    let names: Vec<&str> = path.iter().map(|c| c.get_name()).collect();

    let arguments: Vec<(String, String)> = {
        let ps = positionals(cmd);
        if ps.iter().any(|a| !help_text(a).is_empty()) {
            ps.iter().map(|a| (value_name(a), argument_description(a))).collect()
        } else {
            vec![]
        }
    };
    let mut opts: Vec<(String, String)> = options(cmd)
        .into_iter()
        .filter(|a| !a.is_hide_set())
        .map(|a| (option_flags(a), option_description(a)))
        .collect();
    opts.push((HELP_FLAGS.into(), HELP_DESC.into()));
    let mut commands: Vec<(String, String)> = subcommands(cmd)
        .into_iter()
        .filter(|c| !c.is_hide_set())
        .map(|c| (subcommand_term(c), about(c)))
        .collect();
    if has_help_command(cmd) {
        commands.push(("help [command]".into(), HELP_DESC.into()));
    }

    let term_width = arguments
        .iter()
        .chain(&opts)
        .chain(&commands)
        .map(|(t, _)| js_len(t))
        .max()
        .unwrap_or(0);
    let item = |(term, desc): &(String, String)| -> String {
        if desc.is_empty() {
            return term.clone();
        }
        let full = format!("{}{desc}", pad_end(term, term_width + 2));
        wrap(&full, width.saturating_sub(2), term_width + 2)
    };
    let list = |items: &[(String, String)]| -> String {
        let joined = items.iter().map(item).collect::<Vec<_>>().join("\n");
        joined.split('\n').map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n")
    };

    let mut out = vec![format!("Usage: {} {}", names.join(" "), usage_parts.join(" ")), String::new()];
    let desc = about(cmd);
    if !desc.is_empty() {
        out.push(wrap(&desc, width, 0));
        out.push(String::new());
    }
    for (title, items) in [("Arguments:", &arguments), ("Options:", &opts), ("Commands:", &commands)] {
        if !items.is_empty() {
            out.push(title.into());
            out.push(list(items));
            out.push(String::new());
        }
    }
    let mut text = out.join("\n");
    if let Some(after) = cmd.get_after_long_help().or(cmd.get_after_help()) {
        let after = after.to_string();
        if !after.is_empty() {
            text.push_str(&after);
            text.push('\n');
        }
    }
    text
}

fn help(path: &[&Command], error: bool) -> Exit {
    let text = format_help(path, error);
    if error {
        Exit { stdout: String::new(), stderr: text, code: 1 }
    } else {
        Exit { stdout: text, stderr: String::new(), code: 0 }
    }
}

fn error(message: String) -> Exit {
    Exit { stdout: String::new(), stderr: format!("{message}\n"), code: 1 }
}

// ---------------------------------------------------------------------------------------------
// suggestions (port of commander `suggestSimilar.js`)
// ---------------------------------------------------------------------------------------------

const MAX_DISTANCE: usize = 3;

fn edit_distance(a: &[u16], b: &[u16]) -> usize {
    if a.len().abs_diff(b.len()) > MAX_DISTANCE {
        return a.len().max(b.len());
    }
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for j in 0..=b.len() {
        d[0][j] = j;
    }
    for j in 1..=b.len() {
        for i in 1..=a.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// JS `localeCompare` for the ASCII command/flag names involved: case-insensitive first, then
/// lowercase before uppercase (ICU root collation), punctuation before letters.
fn locale_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let key = |s: &str| -> Vec<(u8, u8)> {
        s.bytes()
            .map(|c| {
                let class = if c.is_ascii_alphanumeric() { 1 } else { 0 };
                (class, c.to_ascii_lowercase())
            })
            .collect()
    };
    key(a).cmp(&key(b)).then_with(|| {
        // tertiary: lowercase sorts before uppercase
        let t = |s: &str| s.bytes().map(|c| c.is_ascii_uppercase()).collect::<Vec<_>>();
        t(a).cmp(&t(b))
    })
}

fn suggest_similar(word: &str, candidates: &[String]) -> String {
    let mut uniq: Vec<String> = vec![];
    for c in candidates {
        if !uniq.contains(c) {
            uniq.push(c.clone());
        }
    }
    let searching_options = word.starts_with("--");
    let (word, cands): (&str, Vec<String>) = if searching_options {
        (&word[2..], uniq.iter().map(|c| c.get(2..).unwrap_or("").to_string()).collect())
    } else {
        (word, uniq)
    };
    let w: Vec<u16> = word.encode_utf16().collect();
    let mut similar: Vec<String> = vec![];
    let mut best = MAX_DISTANCE;
    for c in cands {
        let cu: Vec<u16> = c.encode_utf16().collect();
        if cu.len() <= 1 {
            continue;
        }
        let distance = edit_distance(&w, &cu);
        let length = w.len().max(cu.len());
        let similarity = (length as f64 - distance as f64) / length as f64;
        if similarity > 0.4 {
            if distance < best {
                best = distance;
                similar = vec![c];
            } else if distance == best {
                similar.push(c);
            }
        }
    }
    similar.sort_by(|a, b| locale_cmp(a, b));
    if searching_options {
        similar = similar.into_iter().map(|c| format!("--{c}")).collect();
    }
    match similar.len() {
        0 => String::new(),
        1 => format!("\n(Did you mean {}?)", similar[0]),
        _ => format!("\n(Did you mean one of {}?)", similar.join(", ")),
    }
}

// ---------------------------------------------------------------------------------------------
// argv walk (port of commander `_parseCommand` / `parseOptions`)
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Tok {
    /// index into the argv passed to [`preflight`]
    i: usize,
    s: String,
}

fn maybe_option(s: &str) -> bool {
    s.len() > 1 && s.starts_with('-')
}

fn find_option<'a>(cmd: &'a Command, flag: &str) -> Option<&'a Arg> {
    options(cmd).into_iter().find(|a| {
        a.get_short().is_some_and(|s| flag == format!("-{s}"))
            || a.get_long().is_some_and(|l| flag == format!("--{l}"))
    })
}

fn is_help_flag(s: &str) -> bool {
    s == "-h" || s == "--help"
}

struct Walk<'a> {
    version: String,
    path: Vec<&'a Command>,
}

impl<'a> Walk<'a> {
    fn cmd(&self) -> &'a Command {
        self.path.last().unwrap()
    }

    /// Commander option event: version exits, choices are validated.
    fn option_value(&self, a: &Arg, value: Option<&str>) -> Result<(), Exit> {
        if matches!(a.get_action(), ArgAction::Version) {
            return Err(Exit { stdout: format!("{}\n", self.version), stderr: String::new(), code: 0 });
        }
        let ch = choices(a);
        if let Some(v) = value {
            if !ch.is_empty() && !ch.iter().any(|c| c == v) {
                return Err(error(format!(
                    "error: option '{}' argument '{v}' is invalid. Allowed choices are {}.",
                    option_flags(a),
                    ch.join(", ")
                )));
            }
        }
        Ok(())
    }

    /// Returns (operands, unknown, option ids seen).
    fn parse_options(&self, argv: Vec<Tok>) -> Result<(Vec<Tok>, Vec<Tok>, Vec<String>), Exit> {
        let cmd = self.cmd();
        let (mut operands, mut unknown, mut seen) = (vec![], vec![], vec![]);
        let mut to_unknown = false;
        let mut args: VecDeque<Tok> = argv.into();
        let mut active_variadic = false;
        while let Some(arg) = args.pop_front() {
            let dest = if to_unknown { &mut unknown } else { &mut operands };
            if arg.s == "--" {
                if to_unknown {
                    dest.push(arg);
                }
                dest.extend(args.drain(..));
                break;
            }
            if active_variadic && !maybe_option(&arg.s) {
                continue;
            }
            active_variadic = false;

            if maybe_option(&arg.s) {
                if let Some(opt) = find_option(cmd, &arg.s) {
                    match takes(opt) {
                        Takes::Required => {
                            let Some(v) = args.pop_front() else {
                                return Err(error(format!(
                                    "error: option '{}' argument missing",
                                    option_flags(opt)
                                )));
                            };
                            self.option_value(opt, Some(&v.s))?;
                        }
                        Takes::Optional => {
                            let v = match args.front() {
                                Some(n) if !maybe_option(&n.s) => args.pop_front(),
                                _ => None,
                            };
                            self.option_value(opt, v.as_ref().map(|t| t.s.as_str()))?;
                        }
                        Takes::Nothing => self.option_value(opt, None)?,
                    }
                    active_variadic = is_variadic(opt);
                    seen.push(opt.get_id().to_string());
                    continue;
                }
            }

            // combo short flags: `-abc` / `-n5`
            let chars: Vec<char> = arg.s.chars().collect();
            if chars.len() > 2 && chars[0] == '-' && chars[1] != '-' {
                if let Some(opt) = find_option(cmd, &format!("-{}", chars[1])) {
                    let rest: String = chars[2..].iter().collect();
                    if takes(opt) != Takes::Nothing {
                        self.option_value(opt, Some(&rest))?;
                    } else {
                        self.option_value(opt, None)?;
                        args.push_front(Tok { i: arg.i, s: format!("-{rest}") });
                    }
                    seen.push(opt.get_id().to_string());
                    continue;
                }
            }

            // `--flag=value`
            if arg.s.starts_with("--") {
                if let Some(eq) = arg.s.find('=').filter(|&eq| eq > 2) {
                    if let Some(opt) = find_option(cmd, &arg.s[..eq]) {
                        if takes(opt) != Takes::Nothing {
                            self.option_value(opt, Some(&arg.s[eq + 1..]))?;
                            seen.push(opt.get_id().to_string());
                            continue;
                        }
                    }
                }
            }

            if maybe_option(&arg.s) {
                to_unknown = true;
            }
            if to_unknown { unknown.push(arg) } else { operands.push(arg) }
        }
        Ok((operands, unknown, seen))
    }

    fn find_sub(&self, name: &str) -> Option<&'a Command> {
        subcommands(self.cmd())
            .into_iter()
            .find(|c| c.get_name() == name || c.get_all_aliases().any(|a| a == name))
    }

    fn unknown_option(&self, flag: &str) -> Exit {
        let mut suggestion = String::new();
        if flag.starts_with("--") {
            let mut cands = vec![];
            for c in self.path.iter().rev() {
                cands.extend(
                    options(c).into_iter().filter(|a| !a.is_hide_set()).filter_map(|a| a.get_long()).map(|l| format!("--{l}")),
                );
                cands.push("--help".into());
            }
            suggestion = suggest_similar(flag, &cands);
        }
        error(format!("error: unknown option '{flag}'{suggestion}"))
    }

    fn unknown_command(&self, name: &str) -> Exit {
        let cmd = self.cmd();
        let mut cands = vec![];
        for c in subcommands(cmd).into_iter().filter(|c| !c.is_hide_set()) {
            cands.push(c.get_name().to_string());
            if let Some(a) = c.get_visible_aliases().next() {
                cands.push(a.to_string());
            }
        }
        if has_help_command(cmd) {
            cands.push("help".into());
        }
        error(format!("error: unknown command '{name}'{}", suggest_similar(name, &cands)))
    }

    /// Commander `_parseCommand`. `Ok(drop)` = commander would run the action; `drop` are the
    /// argv indices of excess operands it ignores.
    fn parse_command(&mut self, mut operands: Vec<Tok>, unknown: Vec<Tok>) -> Result<Vec<usize>, Exit> {
        let cmd = self.cmd();
        let (ops, unknown, seen) = self.parse_options(unknown)?;
        operands.extend(ops);
        let no_args = operands.is_empty() && unknown.is_empty();

        if let Some(first) = operands.first() {
            if let Some(sub) = self.find_sub(&first.s) {
                self.path.push(sub);
                return self.parse_command(operands[1..].to_vec(), unknown);
            }
            if has_help_command(cmd) && first.s == "help" {
                return Err(match operands.get(1) {
                    None => help(&self.path, false),
                    Some(name) => match self.find_sub(&name.s) {
                        Some(sub) => {
                            self.path.push(sub);
                            help(&self.path, false)
                        }
                        None => help(&self.path, true),
                    },
                });
            }
        }
        let help_requested = unknown.iter().any(|t| is_help_flag(&t.s));
        if let Some(sub) = default_sub(cmd) {
            if help_requested {
                return Err(help(&self.path, false));
            }
            self.path.push(sub);
            return self.parse_command(operands, unknown);
        }
        let action = has_action(cmd);
        if !subcommands(cmd).is_empty() && no_args && !action {
            return Err(help(&self.path, true));
        }
        if help_requested {
            return Err(help(&self.path, false));
        }
        for a in options(cmd) {
            if a.is_required_set() && !seen.iter().any(|s| s == a.get_id().as_str()) {
                return Err(error(format!("error: required option '{}' not specified", option_flags(a))));
            }
        }
        if action {
            if let Some(u) = unknown.first() {
                return Err(self.unknown_option(&u.s));
            }
            let ps = positionals(cmd);
            for (i, p) in ps.iter().enumerate() {
                if p.is_required_set() && operands.get(i).is_none() {
                    return Err(error(format!("error: missing required argument '{}'", value_name(p))));
                }
            }
            if ps.last().is_some_and(|p| is_variadic(p)) {
                return Ok(vec![]);
            }
            return Ok(operands.iter().skip(ps.len()).map(|t| t.i).collect());
        }
        if let Some(first) = operands.first() {
            return Err(self.unknown_command(&first.s));
        }
        match unknown.first() {
            Some(u) => Err(self.unknown_option(&u.s)),
            None => Err(help(&self.path, true)),
        }
    }
}

/// Replay commander's parse of `args` (argv without the program name). `Err` carries exactly what
/// commander prints and its exit code; `Ok` lists indices of excess operands to drop before clap.
pub fn preflight(root: &Command, version: &str, args: &[String]) -> Result<Vec<usize>, Exit> {
    let toks: Vec<Tok> = args.iter().enumerate().map(|(i, s)| Tok { i, s: s.clone() }).collect();
    let mut walk = Walk { version: version.to_string(), path: vec![root] };
    walk.parse_command(vec![], toks)
}

/// Fallback for a clap error after commander would have accepted the argv (clap validates value
/// types commander passes through): commander's `error: …` first line, exit 1.
pub fn clap_error(err: &clap::Error) -> Exit {
    let rendered = err.render().to_string();
    let first = rendered.lines().next().unwrap_or("error: invalid arguments").to_string();
    error(first)
}
