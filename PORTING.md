# Horus → Rust port conventions

Source of truth: `../horus-master` (TypeScript monorepo at the latest `master`).
This workspace mirrors it crate-for-package:

| TS package           | Rust crate            | Notes |
| -------------------- | --------------------- | ----- |
| `packages/core`      | `crates/core`         | config schema (serde + manual validation replaces zod), evidence model, secrets, discovery, redact, git, codeowners |
| `packages/connectors`| `crates/connectors`   | reqwest for HTTP providers; `mongodb`, `redis`, `tokio-postgres` crates for state providers |
| `packages/db`        | `crates/db`           | pglite has no Rust equivalent → embedded SQLite via `rusqlite` at `~/.horus/horus-rust.db` (never touch `horus.db`) |
| `packages/stitcher`  | `crates/stitcher`     | queue producer/consumer extraction |
| `packages/engine`    | `crates/engine`       | deterministic pipeline: must produce byte-comparable JSON to the TS engine for the same evidence |
| `packages/ai`        | `crates/ai`           | Anthropic narrative layer; never creates evidence |
| `packages/knowledge` | `crates/knowledge`    | local knowledge index |
| `packages/eval`      | `crates/eval`         | |
| `packages/cli` + `apps/horus` | `crates/cli` (bin `horus`) | clap replaces commander; same command names, flags and output text |

## Rules

- Port behaviour, not structure: one Rust module per TS file, same names in snake_case. Keep comments that explain *why*.
- **No test files.** Do not write `#[cfg(test)]`, `tests/`, or e2e tests in this port (explicit user instruction). Verification is `cargo build` + the side-by-side benchmark in `bench/`.
- JSON output shapes (report JSON, `--json` flags, saved investigation files) must match the TS output field-for-field, same key order (`serde_json` with `preserve_order`, structs declare fields in TS order). The benchmark diffs them.
- Human-readable output: match the TS text as closely as practical; exact ANSI/colour parity is not required.
- Config files: read the same `.horus/config.json`, `.horus/secrets.local.json`, `~/.horus/*` files the TS CLI reads. Never write to files the TS CLI owns except where the command's purpose is to write them (e.g. `connect`, `init`).
- Secrets: identical envelope (`aes-256-gcm`, scrypt passphrase KDF, same fixed salt, `kid` = first 16 hex of sha256(key)), same macOS keychain service/account via the `security` CLI, same key-file fallback.
- Errors: `anyhow::Result` at command boundaries, `thiserror` enums only where the TS code branches on error kinds.
- Async: tokio. Blocking subprocess calls (`git`, `security`) may stay blocking inside `spawn_blocking`.
- Dependencies: use `[workspace.dependencies]`; add a new crate only when the stdlib or an existing dependency cannot do it.
- When a TS feature cannot be ported faithfully (e.g. pglite, MCP SDK), implement the nearest equivalent and record the divergence in `DIVERGENCES.md`.

## Multi-agent etiquette (several agents port in parallel)

- You own only the files listed in your brief. Re-read `lib.rs` / `Cargo.toml` immediately before editing them and make the smallest additive edit (add one `pub mod` / one dependency line); if the edit fails because the file changed, re-read and retry.
- Never edit another crate. If you need something from `horus-core` that is missing, add a private helper in your own crate and list it in your final report under "needs upstreaming".
- `horus-connectors` layout: `contract.rs` (Provider traits + shared types), `http.rs`, `duration.rs`, `compat.rs`, `factory.rs`, then one module directory per TS directory (`elasticsearch/`, `grafana/`, …) with `mod.rs` mirroring the TS `index.ts` barrel.
- Build gate before you report: `cargo build -p <your crate>` passes.

## Building release binaries

Toolchain: stable Rust pinned to the host's `rustc --version` (1.96.0 at time of writing). The Linux
builds run in Docker and keep their output in a named volume, so the host `target/` and `target-bench/`
stay untouched. `CARGO_BUILD_JOBS=4` keeps peak memory low on an 8 GB Docker VM.

**macOS arm64 (host)**

```sh
HORUS_VERSION=0.23.0 cargo build --release -p horus-cli      # → target/release/horus-rs
```

**Linux arm64 (native on Apple Silicon Docker, ~5 min cold)**

```sh
docker volume create horus-rust-linux-target; docker volume create horus-rust-cargo-registry
docker run --rm --platform linux/arm64 \
  -v "$PWD":/src:ro -v horus-rust-linux-target:/target -v horus-rust-cargo-registry:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS=4 -e HORUS_VERSION=0.23.0 -w /src \
  rust:1.96.0-bookworm cargo build --release --locked -p horus-cli
# binary: /target/release/horus-rs in the volume
```

**Linux amd64 (cross-compiled with Debian's gcc cross toolchain, ~5 min cold; no emulation needed)**

```sh
docker run --rm --platform linux/arm64 \
  -v "$PWD":/src:ro -v horus-rust-linux-target:/target -v horus-rust-cargo-registry:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS=4 -e HORUS_VERSION=0.23.0 \
  -e CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
  -e CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc -e AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar \
  -w /src rust:1.96.0-bookworm sh -c '
    apt-get -qq update && apt-get -qq install -y gcc-x86-64-linux-gnu libc6-dev-amd64-cross &&
    rustup target add x86_64-unknown-linux-gnu &&
    cargo build --release --locked -p horus-cli --target x86_64-unknown-linux-gnu'
# binary: /target/x86_64-unknown-linux-gnu/release/horus-rs in the volume
```

Copy a binary out: `docker run --rm -v horus-rust-linux-target:/target -v "$PWD/out":/out debian:bookworm-slim cp /target/release/horus-rs /out/`.

**Linux runtime requirements:** glibc ≥ 2.34 (dynamically links only `libc`, `libm`, `libgcc_s`; TLS is
rustls and SQLite is bundled). Install `procps` for `ps`/`kill`, which host and worker process management
shells out to, and `git` for repo detection and freshness checks. The master key comes from
`HORUS_SECRET_KEY`, then `secret-tool` (libsecret), then `~/.horus/keyring/master.key` (0600).
