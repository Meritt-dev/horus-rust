//! Minimal interactive TTY selector for `horus connect`. Port of
//! `packages/cli/src/lib/tty-selector.ts`: a searchable multi-select checkbox prompt and its
//! single-select analogue. Raw mode is toggled via `stty` on `/dev/tty` (no termios/libc
//! dependency in the workspace).

use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::process::{Command, Stdio};

use crate::lib::format::{bold, cyan, dim, green};

/// The prompt was cancelled (Ctrl+C / Esc on an empty filter).
#[derive(Debug)]
pub struct ExitPromptError(pub String);

impl std::fmt::Display for ExitPromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ExitPromptError {}

impl Default for ExitPromptError {
    fn default() -> Self {
        Self("Prompt was cancelled".into())
    }
}

/// Why a selector returned no value: cancelled by the user, or could not run at all.
#[derive(Debug)]
pub enum SelectError {
    Exit(ExitPromptError),
    Other(String),
}

/// True when stdin is an interactive TTY (and `--no-input` / HORUS_NO_INPUT is not set).
pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::env::var_os("HORUS_NO_INPUT").is_none()
}

fn stty(args: &[&str]) -> Option<String> {
    let tty = File::open("/dev/tty").ok()?;
    let out = Command::new("stty").args(args).stdin(Stdio::from(tty)).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Raw-mode guard: restores the saved terminal settings on drop.
pub struct RawMode(Option<String>);

impl RawMode {
    pub fn enter() -> Self {
        let saved = stty(&["-g"]);
        let _ = stty(&["raw", "-echo"]);
        Self(saved)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        match &self.0 {
            Some(s) => {
                let _ = stty(&[s.as_str()]);
            }
            None => {
                let _ = stty(&["sane"]);
            }
        }
    }
}

/// One keypress chunk from stdin (raw mode delivers an escape sequence in one read).
pub fn read_key() -> Option<String> {
    let mut buf = [0u8; 16];
    let n = std::io::stdin().read(&mut buf).ok()?;
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn out(s: &str) {
    let mut o = std::io::stdout();
    let _ = o.write_all(s.as_bytes());
    let _ = o.flush();
}

/// Shared list state + keyboard handling for both selectors.
struct ListState<'a> {
    choices: &'a [String],
    page_size: usize,
    filter: String,
    cursor: usize,
    filtered: Vec<&'a String>,
    visible_offset: usize,
    last_render_lines: usize,
}

impl<'a> ListState<'a> {
    fn new(choices: &'a [String], page_size: usize) -> Self {
        let mut s = Self {
            choices,
            page_size,
            filter: String::new(),
            cursor: 0,
            filtered: vec![],
            visible_offset: 0,
            last_render_lines: 0,
        };
        s.update_filtered();
        s
    }

    fn update_filtered(&mut self) {
        let f = self.filter.to_lowercase();
        self.filtered = self.choices.iter().filter(|c| f.is_empty() || c.to_lowercase().contains(&f)).collect();
        self.cursor = self.cursor.min(self.filtered.len().saturating_sub(1));
        self.update_visible_offset();
    }

    fn update_visible_offset(&mut self) {
        if self.cursor < self.visible_offset {
            self.visible_offset = self.cursor;
        } else if self.cursor >= self.visible_offset + self.page_size {
            self.visible_offset = self.cursor + 1 - self.page_size;
        }
        let max_offset = self.filtered.len().saturating_sub(self.page_size);
        self.visible_offset = self.visible_offset.min(max_offset);
    }

    fn clear(&self) {
        out("\x1B[?25l"); // hide cursor
        if self.last_render_lines > 0 {
            out(&format!("\x1B[{}A", self.last_render_lines)); // move up
            out("\x1B[0J"); // clear to end
        }
    }

    /// Raw mode needs `\r\n`; the TS stream writer translates `\n` itself.
    fn write_lines(&mut self, lines: &[String]) {
        out(&lines.join("\r\n"));
        // Cursor ends on the last line; moving up N-1 returns to the header line.
        self.last_render_lines = lines.len().saturating_sub(1);
        out("\r");
    }

    /// Apply a navigation/filter key. Returns false when the key is not one of those.
    fn handle_common(&mut self, s: &str) -> bool {
        match s {
            "\x7F" | "\x08" => {
                if self.filter.pop().is_some() {
                    self.cursor = 0;
                    self.update_filtered();
                }
            }
            "\x1B[A" => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.update_visible_offset();
                }
            }
            "\x1B[B" => {
                if self.cursor + 1 < self.filtered.len() {
                    self.cursor += 1;
                    self.update_visible_offset();
                }
            }
            _ if s.len() == 1 && (32..=126).contains(&s.as_bytes()[0]) => {
                self.filter.push_str(s);
                self.cursor = 0;
                self.update_filtered();
            }
            _ => return false,
        }
        true
    }

    fn status(&self, selected: Option<usize>) -> String {
        let mut parts = vec![];
        if let Some(n) = selected {
            parts.push(format!("{n} selected"));
        }
        parts.push(format!("{}/{} matches", self.filtered.len(), self.choices.len()));
        if !self.filter.is_empty() {
            parts.push(format!("filter: {}", self.filter));
        }
        dim(&format!("  {}", parts.join(" · ")))
    }
}

/// Searchable multi-select checkbox prompt (↑/↓ navigate, space toggle, enter confirm, type
/// to filter, esc clears filter / cancels, ctrl+c cancels).
pub fn checkbox_search(message: &str, choices: &[String], page_size: Option<usize>) -> Result<Vec<String>, SelectError> {
    if !is_interactive() {
        return Err(SelectError::Other("checkboxSearch requires an interactive TTY".into()));
    }
    if choices.is_empty() {
        return Ok(vec![]);
    }
    let mut st = ListState::new(choices, page_size.unwrap_or(10));
    // Insertion-ordered like the TS Set.
    let mut selected: Vec<String> = Vec::new();
    let raw = RawMode::enter();
    let render = |st: &mut ListState, selected: &Vec<String>| {
        st.clear();
        let mut lines = vec![format!(
            "? {} {}",
            bold(message),
            dim("(↑↓ navigate • space toggle • enter confirm • type filter)")
        )];
        let end = (st.visible_offset + st.page_size).min(st.filtered.len());
        for idx in st.visible_offset..end {
            let choice = st.filtered[idx];
            let is_cursor = idx == st.cursor;
            let marker = if selected.contains(choice) { green("●") } else { " ".into() };
            let label = if is_cursor { cyan(choice) } else { choice.clone() };
            let pointer = if is_cursor { cyan("❯") } else { " ".into() };
            lines.push(format!("  {pointer} [{marker}] {label}"));
        }
        if st.filtered.is_empty() {
            lines.push(dim("  No matches"));
        }
        lines.push(st.status(Some(selected.len())));
        st.write_lines(&lines);
    };
    render(&mut st, &selected);
    let result = loop {
        let Some(s) = read_key() else { break Err(SelectError::Exit(ExitPromptError::default())) };
        match s.as_str() {
            "\x03" => break Err(SelectError::Exit(ExitPromptError::default())),
            "\x1B" => {
                if st.filter.is_empty() {
                    break Err(SelectError::Exit(ExitPromptError::default()));
                }
                st.filter.clear();
                st.cursor = 0;
                st.update_filtered();
            }
            "\r" | "\n" => break Ok(selected.clone()),
            " " => {
                if let Some(choice) = st.filtered.get(st.cursor) {
                    match selected.iter().position(|c| c == *choice) {
                        Some(i) => {
                            selected.remove(i);
                        }
                        None => selected.push((*choice).clone()),
                    }
                }
            }
            other => {
                if !st.handle_common(other) {
                    continue;
                }
            }
        }
        render(&mut st, &selected);
    };
    drop(raw);
    out("\x1B[?25h"); // show cursor
    if let Ok(values) = &result {
        let summary = if values.is_empty() { dim("none") } else { values.join(", ") };
        out(&format!("\n? {} {summary}\n", bold(message)));
    }
    result
}

/// Searchable single-select prompt — the single-choice analogue of [`checkbox_search`].
pub fn select_search(message: &str, choices: &[String], page_size: Option<usize>) -> Result<String, SelectError> {
    if !is_interactive() {
        return Err(SelectError::Other("selectSearch requires an interactive TTY".into()));
    }
    if choices.is_empty() {
        return Err(SelectError::Exit(ExitPromptError("No choices to select from".into())));
    }
    let mut st = ListState::new(choices, page_size.unwrap_or(10));
    let raw = RawMode::enter();
    let render = |st: &mut ListState| {
        st.clear();
        let mut lines = vec![format!("? {} {}", bold(message), dim("(↑↓ navigate • enter confirm • type filter)"))];
        let end = (st.visible_offset + st.page_size).min(st.filtered.len());
        for idx in st.visible_offset..end {
            let choice = st.filtered[idx];
            let is_cursor = idx == st.cursor;
            let pointer = if is_cursor { cyan("❯") } else { " ".into() };
            let label = if is_cursor { cyan(choice) } else { choice.clone() };
            lines.push(format!("  {pointer} {label}"));
        }
        if st.filtered.is_empty() {
            lines.push(dim("  No matches"));
        }
        lines.push(st.status(None));
        st.write_lines(&lines);
    };
    render(&mut st);
    let result = loop {
        let Some(s) = read_key() else { break Err(SelectError::Exit(ExitPromptError::default())) };
        match s.as_str() {
            "\x03" => break Err(SelectError::Exit(ExitPromptError::default())),
            "\x1B" => {
                if st.filter.is_empty() {
                    break Err(SelectError::Exit(ExitPromptError::default()));
                }
                st.filter.clear();
                st.cursor = 0;
                st.update_filtered();
            }
            "\r" | "\n" => match st.filtered.get(st.cursor) {
                Some(c) => break Ok((*c).clone()),
                None => continue,
            },
            other => {
                if !st.handle_common(other) {
                    continue;
                }
            }
        }
        render(&mut st);
    };
    drop(raw);
    out("\x1B[?25h");
    if let Ok(v) = &result {
        out(&format!("\n? {} {v}\n", bold(message)));
    }
    result
}
