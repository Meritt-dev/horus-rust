# Horus

[Horus](https://horus.sh), the incident-investigation CLI. From 0.24.0 this Rust implementation **is** `horus`: the npm package `@merittdev/horus`, the Homebrew formula `horus` and the GitHub release binaries all ship it.
It traces a production symptom through the code (via the source-intelligence backend) and your runtime systems:
- logs
- metrics
- queues
- databases
- error trackers
- past incidents in local memory (synced with Horus Cloud when the repo is linked)

It then ranks the likely causes and states its confidence plainly.

It is a command-for-command port of the TypeScript `horus` 0.23.0 ([Meritt-dev/horus](https://github.com/Meritt-dev/horus)): same commands, flags, help text, output and exit codes, now as a single native binary.

New in 0.24.3:
- **Hybrid startup recall.** An investigation opens with matching past incidents, scored by exact code-shaped terms plus local embedding similarity against every hint an incident was seen under. `HORUS_STARTUP_RECALL=off` disables it.
- **Past incidents in this code.** `horus changes` and `horus what-changed` list earlier investigations whose top code seeds (a method or function behind a cause rated likely or highly likely) the change modifies or removes (`relatedIncidents` in JSON). Context, not a gate.
- **IncidentBench**, an open benchmark for startup recall: [docs/incident-bench.md](docs/incident-bench.md).
- Investigations record the calling agent session from `HORUS_AGENT_SESSION` or `CLAUDE_CODE_SESSION_ID`.

## Install

```sh
npm i -g @merittdev/horus                       # npm (macOS / Linux, arm64 / x64)
brew install meritt-dev/tap/horus               # Homebrew
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Meritt-dev/horus-rust/releases/latest/download/horus-cli-installer.sh | sh
horus update --force                            # after the curl installer: installs the bundled backend
```

The npm and Homebrew packages bundle the matching source-intelligence backend wheel. `horus init` installs it with [uv](https://docs.astral.sh/uv/).

## Upgrading from the TypeScript horus (≤ 0.23.0)

- **npm:** `npm i -g @merittdev/horus@latest` (or `horus update`) replaces the TS build with this one. Node is still required for npm itself, not for Horus.
- **Homebrew:** `brew upgrade horus`. The formula no longer depends on `node`.
- **Config and secrets** in `~/.horus` and `.horus/config.json` are read as-is.
- **Local history.** The TS CLI kept investigations and memory in a PGlite store at `~/.horus/horus.db`. This build uses SQLite at `~/.horus/horus-rust.db`. Copy the history over once (needs `node`/`npx`; the TS store is only read):

  ```sh
  horus db migrate-from-ts
  ```

  Until you do, `horus` prints a one-line reminder while the new store is empty. Re-running the migration is safe.

## Use

```sh
cd your-service
horus init                       # index the repo, start the source host, write .horus/config.json
horus connect elasticsearch …    # add runtime connectors (see `horus connect --help`)
horus doctor
horus investigate "checkout requests timing out since the last deploy"
```

`horus --help` lists every command.

## How it compares to the TypeScript CLI

We ran side-by-side benchmarks against 12 real repositories ([docs/BENCHMARK.md](docs/BENCHMARK.md)):
- **Startup:** 5 ms vs 158 ms cold start.
- **Memory:** 10 MB vs 153 MB idle; 140–175 MB vs about 1 GB for a full investigation.
- **Speed:** 2.5–11.8× faster per project.
- **Output parity:** 98–100% mean match on the 11 other repos; 66/76 identical cases on the main project (the rest differ only by local history, live data or clock).

The intended differences are listed in [DIVERGENCES.md](DIVERGENCES.md). The main ones:
- **Local database.** History lives in `~/.horus/horus-rust.db` (SQLite), not the TS CLI's PGlite `~/.horus/horus.db`; `horus db migrate-from-ts` copies it over. Horus Cloud memory syncs into both.
- **JS/TS config files.** `horus.config.{js,ts}` is loaded through an installed `node`. `.horus/config.json` needs nothing extra.
- **Cloud writes switch.** `HORUS_RUST_CLOUD_WRITE=0` keeps a run local: no Cloud writes and no telemetry.

## Build from source

```sh
HORUS_VERSION=0.24.3 cargo build --release -p horus-cli   # → target/release/horus
```

Cross-platform release builds are covered in [PORTING.md](PORTING.md), and cutting a release in [docs/RELEASE.md](docs/RELEASE.md).

The workspace mirrors the TS monorepo crate-for-package:
- `core`
- `connectors`
- `db`
- `stitcher`
- `engine`
- `ai`
- `knowledge`
- `eval`
- `cli`

## License

MIT
