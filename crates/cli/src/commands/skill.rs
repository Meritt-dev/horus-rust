//! `horus skill` — install / print / locate the Horus agent skill.
//! Port of `packages/cli/src/commands/skill.ts`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;

use crate::cli::*;
use crate::commands::SilentExit;
use crate::lib::format::{bold, dim, green, red, yellow};

pub const SUPPORTED_TARGETS: &[&str] = &["claude", "codex", "gemini", "cursor", "generic"];

pub fn is_valid_target(target: &str) -> bool {
    SUPPORTED_TARGETS.contains(&target)
}

fn base_dir(global: bool, cwd: Option<&Path>) -> PathBuf {
    if global {
        dirs::home_dir().unwrap_or_default()
    } else {
        cwd.map(Path::to_path_buf).unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
    }
}

/// Legacy flat-file path used by early Horus Claude skill installers.
pub fn get_legacy_claude_skill_path(global: bool, cwd: Option<&Path>) -> PathBuf {
    base_dir(global, cwd).join(".claude").join("skills").join("horus.md")
}

pub fn get_skill_install_path(target: &str, global: bool, cwd: Option<&Path>) -> PathBuf {
    let base = base_dir(global, cwd);
    match target {
        "claude" => base.join(".claude").join("skills").join("horus").join("SKILL.md"),
        "gemini" if global => base.join(".gemini").join("GEMINI.md"),
        "gemini" => base.join("GEMINI.md"),
        "cursor" if global => base.join(".cursorrules"),
        "cursor" => base.join(".cursor").join("rules").join("horus.mdc"),
        "codex" if global => base.join(".codex").join("AGENTS.md"),
        "codex" => base.join("AGENTS.md"),
        _ => base.join(".horus").join("skills").join(format!("horus-{target}.md")),
    }
}

const BASE_SKILL: &str = r##"# Horus: grounded investigation

Horus is a **read-only** evidence layer over a repo's production runtime (logs, metrics,
queues, application state), source intelligence (symbols, call graph, ownership, blast
radius) and git history. Use it instead of assuming; skip it for formatting edits and
obvious local refactors. It never writes to production systems, only to its own local
state (`.horus/`, saved investigations, feedback).

## Cheapest path to an answer

Stop at the first step that answers.

1. Reuse: `horus investigations --json -n 5`. If one matches, use its id with
   `horus packet <id> --json` or `horus ask <id>`. Neither re-queries.
2. Symbol, path, owner, impact or change questions: one Source reasoning command, not
   an investigation.
3. New incident: `horus packet "<symptom, service, error text>" --for claude --json`
   runs one investigation and returns a short briefing with caveats and recalled prior
   incidents. Read the memory section first.
4. Only if the packet is not enough: `horus investigate --json "<hint>"`, then
   `horus ask <id>`.

## Output

- Add `--json` to parse a result. `replay` takes `--format json`; `postmortem`,
  `feedback` and `report` have no JSON mode.
- JSON from `investigate`, `explain`, `changes`, `timeline` and `what-changed` is
  **compact by default**. Add `--full` only for raw payloads, commit lists or graph edges.
  `horus replay <id> --format json` is always full; use `horus packet <id> --json`.
- `investigate`, `packet`, `explain`, `blast-radius` and `memory show` return
  `nextSteps`. Prefer them to guessing; they are advisory and some name an MCP tool.
- Do not add `--ai`: it spends model tokens on a narrative you can write.

## Setup and health

Run `horus init` (**idempotent**) and retry once if `.horus/config.json` is missing,
`horus doctor --json` reports source intelligence missing, or the host is unreachable or
the index stale; `horus init --reindex` if the call graph still looks wrong.
`horus status --json` shows connector health. `horus connect <type>` adds a source
(`--help` lists types). Never invent credentials or hand-edit them into config; ask the
user.

## Investigation loop

`investigate` and `packet "<hint>"` save the run and return its id. Reuse it.

```bash
horus investigate --json "<hint>" --service <name> --scope <path> --since <git-ref> --logs-since 24h
horus ask <id> "what evidence is missing?"
horus score <id> --json
horus postmortem <id>          # editable Markdown draft
```

`horus ask` requires an investigation ID and a directive:

```bash
horus ask <id> "what evidence contradicts <hypothesis>?"   # correct
horus ask "<question>"                                      # WRONG: no investigation ID
```

`ask` is deterministic, not a chat model. It answers what is missing, what contradicts a
topic, why confidence is not higher, "focus on <topic>" and "where is X defined?".
Anything else gets "cannot be answered from the saved evidence".

Stop and report when the top cause has direct evidence and an exact source location,
when `nextSteps` is empty or repeats what you ran, or when the remaining gaps need a
connector or credential you lack. Do not run more than three refinement rounds without
new evidence.

## Empty or degraded results

- **Horus returns nothing**: retry once with a qualified name, `horus search`, a wider
  window (`--logs-since 7d`) or `--service`, then report the gap.
- Degraded or missing connector: use what was collected, name the gap, run the remedy
  in `nextSteps`.
- `explain` fuzzy match: the symbol was not found. Say so. Report low confidence as low.

## Runtime evidence

Use these only for a signal the packet lacked.

```bash
horus logs [service] --since 24h --json   # Elasticsearch or cloud logs; --grep, --where k=v
horus metrics "<hint>" --since 6h --json  # Grafana
horus queues --live --json                # Redis/BullMQ, Kafka, Service Bus
horus state --json                        # MongoDB only
```

## Source reasoning

```bash
horus search "<words>" --json          # find symbols across configured repos
horus explain <symbol> --json          # location, callers/callees, impact
horus trace <from> <to> --json         # shortest code path between two symbols
horus blast-radius <symbol> --json     # upstream/downstream reach, criticality
horus owner <symbol> --json            # likely owner from git history
horus changes <base> [compare] --json  # changed symbols, flows, past incidents in that code
horus what-changed --json              # changed files by status, past incidents
horus memory show <scope> --json       # past investigations, weak spots
```

Qualified names resolve precisely across `search`, `explain`, `investigate` and
`blast-radius`: `horus explain PaymentService.charge`. Product code ranks above tests;
add `--include-tests` to `blast-radius` or `--full` to `explain`.

## Logic and behavior questions

For "does this worker retry failed jobs?", answer from source. `explain` takes a symbol,
not a sentence: `horus search`, `horus explain`, then `horus trace`. Horus locates code;
it does not prove behavior. Read the cited file:line before answering.

## Client-reported issues (Lens)

`horus lens --json` lists submitted client reports (`--all` for every status).
`horus lens show <reportId> --json` adds a `seed` (`file:line:symbol` raise site, or
null). Needs `horus login` and `horus cloud link`; otherwise it returns a remedy.

## Change and fix workflow

1. Before editing: `horus blast-radius <symbol> --json` and `horus owner <symbol> --json`.
2. Edit with normal file tools.
3. After editing: re-run `horus blast-radius <changed-symbol> --json`, and
   `horus changes <base> --json` once committed. `horus ask` cannot judge a fix; after
   it ships, run a fresh `horus investigate` on the original hint.
4. Run the project's own tests, typecheck and lint.

## Close the loop

Once the outcome is confirmed, record it once; never guess. The id defaults to the
latest investigation:

```bash
horus feedback <id> --resolved yes|partly|no [--cause "<confirmed cause>"]
```

If Horus was wrong or lacked a capability, `horus report "<what>"` prints a pre-filled
GitHub issue URL (and tries to open it) and sends nothing. Include the URL in your report.

## Running unattended

Do not wait for a human: run `horus init` if needed, follow the cheapest path and
`nextSteps`, apply the stop rules, report. Only credentials need a human.

## Contract

- Horus evidence is grounded but **not infallible**. Say when it is missing, stale,
  ambient, or not linked to the symptom.
- **Do not invent runtime evidence**. If **Horus returns nothing**, say so. Never
  **hallucinate** a result.
- Prefer Horus's exact source locations. If they conflict with the source, report it.
- **Never use Horus to mutate production**. It does not replace tests or reading source.
- Report: conclusion; investigation id; evidence with exact locations; gaps;
  **blast radius** or risk; next action.
"##;

const NOTES_CLAUDE: &str = r##"## Claude Code notes

This skill is loaded automatically when present at:

```bash
.claude/skills/horus/SKILL.md
```

Useful starting points:

```bash
horus investigations
horus doctor
horus onboard [area]
horus status
```
"##;

const NOTES_GEMINI: &str = r##"## Gemini CLI notes

This context file is loaded automatically by Gemini CLI when present at:

```bash
GEMINI.md
```

Useful starting points:

```bash
horus investigations
horus doctor
horus onboard [area]
horus status
```
"##;

const NOTES_CURSOR: &str = r##"## Cursor notes

This rule is loaded automatically when present at `.cursor/rules/horus.mdc`.

Useful starting points:

```bash
horus investigations
horus doctor
horus onboard [area]
horus status
```
"##;

const NOTES_CODEX: &str = r##"## Codex notes

This file is loaded automatically by Codex CLI as project instructions when present at `AGENTS.md`.

Useful starting points:

```bash
horus investigations
horus doctor
horus onboard [area]
horus status
```
"##;

fn skill_frontmatter(target: &str) -> String {
    let description = "Grounded production-incident investigation with Horus — a read-only evidence layer over logs, metrics, queues, application state, and source intelligence. Use when debugging incidents, outages, regressions, or flaky/slow behavior; when asked what changed, what broke, who owns code, or the blast radius of a change; and to verify fixes against runtime evidence.";
    match target {
        "claude" => format!("---\nname: horus\ndescription: {description}\n---\n\n"),
        "cursor" => format!("---\ndescription: {description}\nglobs: *\nalwaysApply: true\n---\n\n"),
        _ => String::new(),
    }
}

fn provider_notes(target: &str) -> &'static str {
    match target {
        "claude" => NOTES_CLAUDE,
        "gemini" => NOTES_GEMINI,
        "cursor" => NOTES_CURSOR,
        "codex" => NOTES_CODEX,
        _ => "",
    }
}

pub fn generate_skill_content(target: &str) -> String {
    format!("{}{BASE_SKILL}\n{}", skill_frontmatter(target), provider_notes(target))
}

/// `[y/N]` prompt; false when stdin is not a TTY (or `--no-input` / `HORUS_NO_INPUT`).
fn confirm(message: &str) -> bool {
    if !std::io::stdin().is_terminal() || std::env::var_os("HORUS_NO_INPUT").is_some() {
        return false;
    }
    print!("{message} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }
    let a = answer.trim().to_ascii_lowercase();
    a == "y" || a == "yes"
}

fn unknown_target(target: &str) -> u8 {
    println!("{} Unknown target: {}", red("✗"), bold(target));
    println!("{}", dim(&format!("  Supported targets: {}", SUPPORTED_TARGETS.join(", "))));
    1
}

pub fn run_skill_install(target: &str, force: bool, global: bool, cwd: Option<&Path>) -> u8 {
    if !is_valid_target(target) {
        return unknown_target(target);
    }
    let out_path = get_skill_install_path(target, global, cwd);
    let content = generate_skill_content(target);

    // Migrate the legacy flat Claude skill file to the directory layout.
    if target == "claude" {
        let legacy = get_legacy_claude_skill_path(global, cwd);
        if legacy.exists() {
            if !force
                && !confirm(&format!(
                    "Found old flat skill file at {}. Replace it with the new directory layout?",
                    legacy.display()
                ))
            {
                println!("{} Migration cancelled; existing skill left untouched.", yellow("!"));
                println!("{}", dim("  Pass --force to replace without prompting."));
                return 1;
            }
            if let Err(e) = std::fs::remove_file(&legacy) {
                println!("{} Could not remove legacy skill file {}: {e}", red("✗"), legacy.display());
                return 1;
            }
            println!("{} Replaced old flat skill file: {}", yellow("!"), legacy.display());
        }
    }

    if out_path.exists() && !force {
        println!("{} {} already exists", red("✗"), out_path.display());
        println!("{}", dim("  pass --force to overwrite"));
        return 1;
    }

    let written = out_path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|_| std::fs::write(&out_path, &content));
    if let Err(e) = written {
        println!("{} Could not write {}: {e}", red("✗"), out_path.display());
        return 1;
    }

    println!("{} Horus skill installed → {}", green("✓"), out_path.display());
    match target {
        "claude" => {
            println!("{}", dim("  Claude Code will load this skill automatically."));
            println!("{}", dim("  Invoke it with: /horus"));
        }
        "gemini" => println!("{}", dim("  Gemini CLI will load this context file automatically.")),
        "cursor" => println!("{}", dim("  Cursor will load this rule automatically.")),
        "codex" => println!("{}", dim("  Codex CLI will load this file automatically.")),
        _ => println!("{}", dim(&format!("  Copy or reference this file in your {target} agent instructions."))),
    }
    0
}

pub fn run_skill_print(target: &str) -> u8 {
    if !is_valid_target(target) {
        return unknown_target(target);
    }
    print!("{}", generate_skill_content(target));
    let _ = std::io::stdout().flush();
    0
}

pub fn run_skill_path(target: &str, global: bool, cwd: Option<&Path>) -> u8 {
    if !is_valid_target(target) {
        return unknown_target(target);
    }
    println!("{}", get_skill_install_path(target, global, cwd).display());
    0
}

#[allow(dead_code)]
static SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r#"(?i)"password"\s*:"#,
        r#"(?i)"apiKey"\s*:"#,
        r#"(?i)"api_key"\s*:"#,
        r"(?i)bearer\s+[a-z0-9._-]{20,}",
        r"(?i)mongodb\+srv://[^@]+@",
        r"(?i)redis://:[^@]+@",
        r"(?i)postgresql://[^:]+:[^@]+@",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// Verify the installed skill contains no secrets from .horus/config.json.
#[allow(dead_code)]
pub fn skill_content_leaks_secrets(content: &str) -> bool {
    SECRET_PATTERNS.iter().any(|p| p.is_match(content))
}

pub async fn run(args: &SkillArgs) -> Result<()> {
    let code = match &args.command {
        SkillCommand::Install(a) => run_skill_install(&a.target, a.force, a.global, None),
        SkillCommand::Print { target } => run_skill_print(target),
        SkillCommand::Path(a) => run_skill_path(&a.target, a.global, None),
    };
    if code != 0 {
        return Err(SilentExit(code).into());
    }
    Ok(())
}
