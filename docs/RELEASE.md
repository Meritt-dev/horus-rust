# Releasing the Rust CLI

The Rust CLI ships ALONGSIDE the TS one: the executable is `horus-rs`, npm is `@merittdev/horus-rs`,
and the Homebrew formula is `horus-rs`. None of them touch `@merittdev/horus`, the `horus` formula or
the TS `horus` on PATH. Only the file name differs: help and messages still say `horus …`
(clap `bin_name = "horus"`), because command parity with TS is the point.

One tag builds native `horus-rs` binaries for four targets and ships them through GitHub Releases,
a shell installer, Homebrew, npm and (optionally) cargo-binstall. Every archive carries `horus`
plus `horus_source.whl`, the source-intelligence backend wheel, pinned to the same version
(`PINNED_SOURCE_VERSION == HORUS_VERSION`). `horus init` / `horus update` install the wheel with
`uv tool install`.

| Target | Runner (CI) | Notes |
| ------ | ----------- | ----- |
| `aarch64-apple-darwin` | `macos-14` | |
| `x86_64-apple-darwin` | `macos-14` (cross) | macOS SDK covers both arches |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` | static, no glibc requirement |
| `x86_64-unknown-linux-musl` | `ubuntu-22.04` | static, no glibc requirement |

Linux builds are musl and fully static (checked: `file` → "statically linked", `ldd` → "not a
dynamic executable"). rustls, bundled SQLite, aws-lc-sys and the Kafka client all build there, so
the glibc ≥ 2.34 floor of the gnu builds in PORTING.md does not apply to release binaries. They still
need `ps`/`kill` (procps) and `git` at runtime.

## Pieces

| File | Role |
| ---- | ---- |
| `dist-workspace.toml` | [dist](https://opensource.axo.dev/cargo-dist/) config: targets, installers, tap, custom jobs |
| `Cargo.toml` `[workspace.package] repository` | the GitHub repo that hosts releases; dist, binstall, `horus update` and the update notifier all read it |
| `crates/cli/Cargo.toml` `[package.metadata.dist]` | opts the CLI into dist (crates are `publish = false`) and adds `horus_source.whl` to every archive |
| `.github/build-setup.yml` | dist inserts these steps before every build: sets `HORUS_VERSION` from the tag, checks out `Meritt-dev/horus` at the same tag, stamps `packages/source-py` to that version and runs `scripts/release/build-source-wheel.sh`, stages the wheel at `crates/cli/horus_source.whl` |
| `.github/workflows/release.yml` | **generated** by `dist generate`; do not edit by hand |
| `.github/workflows/publish-npm.yml` | custom publish job: archives → npm packages → `npm publish` |
| `.github/workflows/notarize-macos.yml` | custom post-announce job: submits the signed darwin binaries to Apple notarization |
| `release/npm/build.mjs`, `release/npm/horus-rs.js` | npm package generator and launcher shim |

After changing `dist-workspace.toml` or `.github/build-setup.yml`, run `dist generate` and commit
the regenerated `release.yml`. `dist plan` shows what a tag would build.

## Channels

| Channel | Install | What lands on disk | `horus update` does |
| ------- | ------- | ------------------ | ------------------- |
| GitHub release | download `horus-cli-<target>.tar.gz` | whatever the user extracts | self-replace (below) |
| Shell installer | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Meritt-dev/horus-rust/releases/latest/download/horus-cli-installer.sh \| sh` | `horus-rs` in `$XDG_BIN_HOME`, else `~/.local/bin`; **no wheel** (dist installers copy binaries only) | self-replace from the archive; that also puts the wheel beside the binary |
| Homebrew | `brew install meritt-dev/tap/horus-rs` | `bin/horus-rs` → Cellar, wheel in `share/horus-rs/` | `brew upgrade horus-rs`, then the new binary pins the backend |
| npm | `npm i -g @merittdev/horus-rs` | launcher + one `@merittdev/horus-rs-<os>-<cpu>` with `bin/horus-rs` and `bin/horus_source.whl` | `npm install -g --prefix <same prefix> @merittdev/horus-rs@latest`, then the new binary pins the backend |
| cargo-binstall | `cargo binstall --git https://github.com/Meritt-dev/horus-rust horus-cli` | `horus-rs` in `~/.cargo/bin`; no wheel | self-replace from the archive |
| Source build | `cargo install --git … horus-cli` | `horus` only, version `dev` unless `HORUS_VERSION` is set | self-replace refuses `dev` (unparseable version) |

The executable path decides the channel (`crates/cli/src/commands/update.rs`, `detect_channel`):
`…/lib/node_modules/<pkg>-<os>-<cpu>/bin/horus-rs` is npm, `…/Cellar/<formula>/…` is Homebrew, and
anything else is standalone. Standalone self-replace downloads `horus-cli-<target>.tar.gz`,
checks it against its `.sha256`, unpacks it with `tar`, swaps the binary (with rollback) and
writes the wheel beside it.

**No wheel (shell installer, binstall, source build).** `resolve_bundled_wheel` looks beside the
resolved binary and in `../share/horus-rs/`. When neither has it, `horus init` writes the config,
skips indexing and prints the installer hint. Fix it with `horus update --force`, which fetches
this release's archive and writes the wheel beside the binary. A source build can't carry the
wheel and runs with `HORUS_VERSION=dev`, so it can't enforce the backend pin. Install the backend
yourself (`uv tool install` on a `horus_source` wheel built from `Meritt-dev/horus`).

### npm layout (esbuild/biome pattern)

`node release/npm/build.mjs --archives <dir> --version X.Y.Z --out <dir>` writes:

- `@merittdev/horus-rs-darwin-arm64`, `-darwin-x64`, `-linux-arm64`, `-linux-x64`: each holds
  `bin/horus-rs` and `bin/horus_source.whl`, with `os`/`cpu` set so npm installs only the matching one.
- `@merittdev/horus-rs`: the `horus-rs` bin is `bin/horus-rs.js`, which resolves
  `<its own name>-<process.platform>-<process.arch>`, spawns `bin/horus-rs` with inherited stdio,
  forwards SIGINT/SIGTERM/SIGHUP/SIGQUIT and exits with the child's code (or re-raises its signal).
  The platform packages are `optionalDependencies` pinned to the same version. No postinstall,
  no download.

The npm name is set in one place: `NPM_NAME` in `release/npm/build.mjs`, which the
`HORUS_NPM_NAME` env var overrides. The launcher and `horus update` both derive everything else
from the installed package names.

The publish job publishes the platform packages first and the launcher last. It skips any
version already on npm, so a re-run resumes.

## One-time setup

Secrets in the release repo (Settings → Secrets and variables → Actions):

| Secret | Needed for | When absent |
| ------ | ---------- | ----------- |
| `NPM_TOKEN` | npm automation token with publish rights on the `@merittdev` scope | the npm job prints a notice and skips |
| `HOMEBREW_TAP_TOKEN` | PAT with Contents: write on `Meritt-dev/homebrew-tap` | dist's `publish-homebrew-formula` job fails, but the GitHub release is already published by then |
| `CODESIGN_CERTIFICATE` | base64 of the Developer ID Application `.p12` | dist warns and leaves the binaries ad-hoc signed |
| `CODESIGN_CERTIFICATE_PASSWORD` | password of that `.p12` | as above |
| `CODESIGN_IDENTITY` | e.g. `Developer ID Application: Meritt Dev (TEAMID)` | as above |
| `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` | `notarytool` (app-specific password) | the notarize job prints a notice and skips |

**Wheel source.** `Meritt-dev/horus` is public, so the checkout needs no token. It checks out the
release tag itself: `v0.23.0` exists there and points at `bcdc5f0`, the `gitHead` of npm
`@merittdev/horus@0.23.0`. The wheel step stamps `packages/source-py` from 0.20.0 to the release
version, exactly as TS `release.yml` does. Set the repo variable `HORUS_SOURCE_REF` to build from
another ref (a tag or SHA). This is needed if a Rust release has no matching TS tag.

Notarization doesn't modify the archives. A bare Mach-O can't be stapled, so Gatekeeper fetches
the ticket online. curl, npm and Homebrew formulae don't set the quarantine bit, so unsigned
binaries still run. Signing matters mainly for browser downloads and MDM-managed Macs. The first
signed release should confirm that dist signs with the hardened runtime and a timestamp, which
notarization requires.

## Cutting a release

1. Bump `[workspace.package] version` in `Cargo.toml` to match the TS release (the wheel tag must
   exist in `Meritt-dev/horus`), then commit.
2. `dist plan` locally. It should list four archives, `horus-cli-installer.sh`, `horus-rs.rb` and
   `sha256.sum`.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag must equal the workspace version; dist
   checks this in its plan job.
4. `release.yml` runs plan → build (four runners, wheel built on each) → global installers → host
   (GitHub release) → Homebrew formula push + npm publish → announce → notarize.

Local dry run (no credentials, nothing published):

```sh
cp <horus>/packages/source-py/dist/horus_source.whl crates/cli/   # from build-source-wheel.sh
HORUS_VERSION=0.23.0 dist build --artifacts=local --target=aarch64-apple-darwin
node release/npm/build.mjs --archives target/distrib --version 0.23.0 --out /tmp/npm --allow-missing
(cd /tmp/npm/horus-darwin-arm64 && npm pack) && (cd /tmp/npm/horus && npm pack)
npm i -g --prefix /tmp/horus-npm-test --offline /tmp/npm/*/*.tgz && /tmp/horus-npm-test/bin/horus-rs --version
```

For a Linux musl archive, run the same `dist build` in `rust:1.96.0-bookworm` with `musl-tools`
installed (see PORTING.md for the Docker volume layout).

## Installing beside the TS CLI

Nothing migrates. `npm i -g @merittdev/horus-rs` or `brew install meritt-dev/tap/horus-rs` adds a
`horus-rs` command. `horus` stays the TS CLI. Both read the same `~/.horus` config and secrets.
Rust keeps its own `~/.horus/horus-rust.db` (DIVERGENCES.md), so they can run side by side.
Never run both at the same time against the same repo's watch service.

## Open decisions

- **Release repo.** `repository` in the workspace `Cargo.toml` is `Meritt-dev/horus-rust`, a
  placeholder: this repo has no remote yet. Using `Meritt-dev/horus` would collide with the TS
  `vX.Y.Z` tags.
- **Archive and installer names.** dist names them after the Cargo package:
  `horus-cli-<target>.tar.gz` and `horus-cli-installer.sh`. They don't collide with TS's
  `horus-vX.Y.Z-*` assets. Renaming the package to `horus-rs` would make every name match the
  binary; `cargo build -p horus-cli` and the binstall/update asset names would change with it.
- **crates.io.** `horus` and `horus-cli` are taken by an unrelated project. All crates are
  `publish = false`, and cargo-binstall works from the GitHub release via `--git`. Publishing
  means renaming the CLI package (e.g. `horus-rs`), then publishing the eight internal crates
  under free names in dependency order: core → ai, connectors, db, knowledge → stitcher, engine
  → eval → cli. Every internal crate becomes a public API. A crates.io source build still has
  no wheel (see "No wheel" above).
- **Notarization.** Wired but unproven until a Developer ID certificate exists.
