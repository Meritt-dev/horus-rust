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

const BASE_SKILL: &str = r##"# Horus — grounded investigation

Horus is a read-only evidence layer over a repo's production runtime (logs, metrics,
queues, application state), source intelligence (symbols, call graph, ownership, blast
radius), and git history. Use it before answering from assumption about runtime
behavior, what changed, who owns code, blast radius, or whether code paths are actually
connected. It never mutates anything.

Add `--json` to any command (`--format json` for `investigate` and `replay`) when you
need to parse the result — output is stable and **compact by default**; add `--full`
for the uncapped structure. Every JSON result carries a `nextSteps` array of
deterministic follow-up commands; run those rather than guessing.

## When to invoke

Invoke Horus when the task involves: an incident / outage / regression / slow / flaky /
inconsistent behavior; "what changed" or "what caused this"; ownership of a component,
service, queue, worker, route, or module; blast radius or impact of a change; queues,
workers, Redis/BullMQ, logs, metrics, MongoDB/Postgres state; where business logic
lives; whether a flag / enum / status / branch is handled; whether code paths are truly
connected or only coincidentally similar; or verifying a fix. Skip it for trivial
syntax/formatting edits and obvious local refactors where blast radius doesn't matter.

## Setup (once per repo)

If there is no `.horus/config.json` (or `horus doctor` reports source intelligence
missing), run the single onboarding command — idempotent, safe to re-run:

```bash
horus init
```

It checks prerequisites, writes the config, starts the source-intelligence host,
indexes the code, and stitches the queue map. Add runtime sources with
`horus connect <type>` (elasticsearch / mongodb / postgres / sentry / axiom / shopify /
grafana / redis; credentials encrypted at rest — never hand-edit them into config). The
source backend ships inside the Horus bundle and installs automatically.

## Primary entry points

```bash
horus status --json                            # config + connector health matrix
horus investigate --format json "<hint>"       # deterministic, ranked, evidence-backed report
horus packet "<hint>" --for claude --json      # compact, honesty-framed briefing for your context
```

`investigate` returns a saved id. Reuse it — never restart from scratch:

```bash
horus investigations --json                    # list saved ids
horus replay <id> --format json                # re-render a saved report, no re-query
horus ask <id> "what evidence is missing?"     # refine against already-collected evidence
horus postmortem <id>                          # draft an editable postmortem
horus score <id> --json                        # quality score for the investigation
```

`horus ask` requires an investigation ID and a directive:

```bash
horus ask <id> "what evidence contradicts <hypothesis>?"   # correct
horus ask "<question>"                                      # WRONG — missing id
```

## Runtime evidence

```bash
horus logs [service] --json
horus state --json
horus metrics "<hint>" --json
horus queues --live --json
```

## Client-reported issues (Lens work queue)

Lens reports are bug reports clients filed from the running app. They feed
`investigate` as evidence, but you can also work the backlog DIRECTLY — every reported
issue, not just the ones relevant to one incident:

```bash
horus lens --json                 # list every client report, newest first
horus lens --status open -n 100   # filter + widen the window
horus lens show <reportId> --json # full detail incl. the code seed (file:line to fix)
```

`show` resolves the top stack frame of the report's first error into a `seed`
(`file:line:symbol` — the raise site), alongside the comment, route, release/gitSha, and
failing requests. Native/cloud-backed: needs `horus login` + `horus cloud link`;
degrades cleanly (a remedy, valid JSON) otherwise. Same reports are exposed to MCP as
`list_lens_reports` / `get_lens_report`.

## Source reasoning

```bash
horus explain <symbol> --json          # location, callers/callees, impact, resolution kind
horus blast-radius <symbol> --json     # upstream/downstream reach + criticality
horus owner <symbol> --json            # likely owner from git history, with confidence
horus changes <base> [compare] --json  # changed symbols + affected execution flows
horus what-changed --json              # git truth: files by status, +/- lines, runtime/test/docs/config buckets
horus timeline --json
```

Qualified names resolve precisely and identically across `search`, `explain`,
`investigate`, and `blast-radius` — prefer them to disambiguate a method from a
same-named helper or test: `horus explain PaymentService.charge`, `horus blast-radius
Reply.hijack`. Product code is preferred over tests/examples by default; add
`--include-tests` (or `--full`) when you need test callers too.

## Logic and behavior questions

For "do we auto-draft products when brandType===MANUAL?", "where is this status
handled?", "does this worker retry failed jobs?", "is this queue idempotent?" — resolve
from source, not assumptions:

```bash
horus explain "<symbol-or-behavior>" --json
horus investigate --format json "<behavior question>"
horus ask <id> "what source evidence proves or disproves this behavior?"
```

## Change and fix workflow

1. Before editing: `horus investigate` / `horus blast-radius <symbol>` to ground in
   evidence, ownership, and blast radius.
2. Edit with normal filesystem tools.
3. After editing: re-check `horus blast-radius <changed-symbol>`, then
   `horus ask <id> "does the proposed fix address the collected evidence?"`.
4. Run the project's own tests / typecheck / lint — Horus does not replace them.

## Close the loop

After you ACT on an investigation and know the outcome, record whether Horus pointed at
the real cause (non-interactive, safe unattended; report once, after you confirm — never
guess):

```bash
horus feedback <id> --resolved yes      # pointed at the real cause
horus feedback <id> --resolved partly   # useful lead, not the whole cause
horus feedback <id> --resolved no       # missed the cause
# optionally add --manual-estimate-min <minutes>
```

If Horus itself is wrong, crashes, or lacks a capability you needed, file it — you see
its failure modes firsthand, the highest-leverage way to improve it:

```bash
horus report "<what was wrong or missing>"
```

## Contract

- Horus evidence is grounded but **not infallible**. State when it is missing, stale,
  ambient, or not structurally linked to the symptom.
- **Do not invent runtime evidence** Horus did not collect. If **Horus returns nothing**,
  say so explicitly — never **hallucinate** a result.
- Prefer Horus's exact source locations over guesses. If Horus conflicts with direct
  source inspection, report the discrepancy.
- Horus is **read-only** evidence collection. **Never use Horus to mutate production**
  systems, and do not use it as a substitute for tests, typechecks, or source inspection.
- Report back: conclusion; Horus evidence + exact source locations; gaps / weak / stale
  evidence; **blast radius** or risk; recommended next action.
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
