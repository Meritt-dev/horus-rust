# horus-rs

A Rust port of [Horus](https://github.com/Meritt-dev/horus), the incident-investigation CLI.
It traces a production symptom through the code (via the source-intelligence backend) and your runtime systems:
- logs
- metrics
- queues
- databases
- error trackers
- Horus Cloud memory

It then ranks the likely causes and states its confidence plainly.

`horus-rs` is a command-for-command port of `horus` 0.23.0: same commands, flags, help text, output and exit codes. It ships as a single native binary and runs alongside the TypeScript `horus`.

## Install

```sh
npm i -g @merittdev/horus-rs                    # npm (macOS / Linux, arm64 / x64)
brew install meritt-dev/tap/horus-rs            # Homebrew
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Meritt-dev/horus-rust/releases/latest/download/horus-cli-installer.sh | sh
horus-rs update --force                         # after the curl installer: installs the bundled backend
```

The npm and Homebrew packages bundle the matching source-intelligence backend wheel. `horus-rs init` installs it with [uv](https://docs.astral.sh/uv/).

## Use

```sh
cd your-service
horus-rs init                       # index the repo, start the source host, write .horus/config.json
horus-rs connect elasticsearch …    # add runtime connectors (see `horus-rs connect --help`)
horus-rs doctor
horus-rs investigate "checkout requests timing out since the last deploy"
```

The commands are the same as `horus`; `horus-rs --help` lists them all.

## How it compares to the TypeScript CLI

We ran side-by-side benchmarks against 12 real repositories ([docs/BENCHMARK.md](docs/BENCHMARK.md)):
- **Startup:** 5 ms vs 158 ms cold start.
- **Memory:** 10 MB vs 153 MB idle; 140–175 MB vs about 1 GB for a full investigation.
- **Speed:** 2.5–11.8× faster per project.
- **Output parity:** 98–100% mean match.

The intended differences are listed in [DIVERGENCES.md](DIVERGENCES.md). The main ones:
- **Local database.** History lives in `~/.horus/horus-rust.db` (SQLite). The TS CLI's PGlite DB is not shared; Horus Cloud memory syncs into both.
- **JS/TS config files.** `horus.config.{js,ts}` is loaded through an installed `node`. `.horus/config.json` needs nothing extra.
- **Cloud writes switch.** `HORUS_RUST_CLOUD_WRITE=0` keeps a run local: no Cloud writes and no telemetry.

## Build from source

```sh
HORUS_VERSION=0.23.0 cargo build --release -p horus-cli   # → target/release/horus-rs
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
