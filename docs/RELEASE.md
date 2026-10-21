# Releasing Horus

From 0.24.0 this Rust implementation **is** `horus`. It replaces the TypeScript CLI, which published up
to 0.23.0, on every channel: npm `@merittdev/horus`, the Homebrew formula `horus` in
`Meritt-dev/homebrew-tap`, and the curl installer. The executable is `horus`.

**The TS repo must stay out of publishing.** `Meritt-dev/horus`'s `Release` and `NPM Publish` workflows
are disabled. If anyone re-enables them, they would publish `@merittdev/horus` and overwrite
`Formula/horus.rb` with the TS build. Keep them disabled, or strip their npm and Homebrew steps.
`Meritt-dev/horus` stays the source of the backend wheel (see "Wheel source").

One tag builds native binaries for four targets and ships them through GitHub Releases, a shell
installer, Homebrew, npm and (optionally) cargo-binstall. Every archive carries `horus` plus
`horus_source.whl`, the source-intelligence backend wheel, stamped to the CLI version
(`PINNED_SOURCE_VERSION == HORUS_VERSION`). `horus init` / `horus update` install the wheel with
`uv tool install`.

| Target | Runner (CI) | Notes |
| ------ | ----------- | ----- |
| `aarch64-apple-darwin` | `macos-14` | |
| `x86_64-apple-darwin` | `macos-14` (cross) | macOS SDK covers both arches |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` | static, no glibc requirement |
| `x86_64-unknown-linux-musl` | `ubuntu-22.04` | static, no glibc requirement |

Linux builds are musl and fully static (checked: `file` → "statically linked", `ldd` → "not a
dynamic executable"; both musl builds passed in CI on the v0.23.0 attempt). They still need
`ps`/`kill` (procps) and `git` at runtime.

## Pieces

| File | Role |
| ---- | ---- |
| `dist-workspace.toml` | [dist](https://opensource.axo.dev/cargo-dist/) config: targets, installers, tap, custom jobs |
| `Cargo.toml` `[workspace.package]` | `version` (= the release tag) and `repository` (the repo that hosts releases; dist, binstall, `horus update` and the update notifier read it) |
| `crates/cli/Cargo.toml` `[package.metadata.dist]` | opts the CLI into dist (crates are `publish = false`) and adds `horus_source.whl` to every archive |
| `.github/build-setup.yml` | dist inserts these steps before every build: sets `HORUS_VERSION` from the tag, checks out `Meritt-dev/horus` at `HORUS_SOURCE_REF`, stamps `packages/source-py` to `HORUS_VERSION`, runs `scripts/release/build-source-wheel.sh`, and stages the wheel at `crates/cli/horus_source.whl` |
| `.github/workflows/release.yml` | **generated** by `dist generate`; do not edit by hand |
| `.github/workflows/publish-homebrew.yml` | custom publish job: pushes `Formula/horus.rb` to the tap with a deploy key |
| `.github/workflows/publish-npm.yml` | custom publish job: archives → npm packages → `npm publish` |
| `.github/workflows/notarize-macos.yml` | custom post-announce job: submits the signed darwin binaries to Apple notarization |
| `release/npm/build.mjs`, `release/npm/horus.js` | npm package generator and launcher shim |

After changing `dist-workspace.toml` or `.github/build-setup.yml`, run `dist generate` and commit
the regenerated `release.yml`. `dist plan` shows what a tag would build.

## Channels

| Channel | Install | What lands on disk | `horus update` does |
| ------- | ------- | ------------------ | ------------------- |
| GitHub release | download `horus-cli-<target>.tar.gz` | whatever the user extracts | self-replace (below) |
| Shell installer | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Meritt-dev/horus-rust/releases/latest/download/horus-cli-installer.sh \| sh` | `horus` in `$XDG_BIN_HOME`, else `~/.local/bin`; **no wheel** (dist installers copy binaries only) | self-replace from the archive; that also puts the wheel beside the binary |
| Homebrew | `brew install meritt-dev/tap/horus` | `bin/horus` → Cellar, wheel in `share/horus/` | `brew upgrade horus`, then the new binary pins the backend |
| npm | `npm i -g @merittdev/horus` | launcher + one `@merittdev/horus-<os>-<cpu>` with `bin/horus` and `bin/horus_source.whl` | `npm install -g --prefix <same prefix> @merittdev/horus@latest`, then the new binary pins the backend |
| cargo-binstall | `cargo binstall --git https://github.com/Meritt-dev/horus-rust horus-cli` | `horus` in `~/.cargo/bin`; no wheel | self-replace from the archive |
| Source build | `cargo install --git … horus-cli` | `horus` only, version `dev` unless `HORUS_VERSION` is set | self-replace refuses `dev` (unparseable version) |

The executable path decides the channel (`crates/cli/src/commands/update.rs`, `detect_channel`):
`…/lib/node_modules/<pkg>-<os>-<cpu>/bin/horus` is npm, and `…/Cellar/<formula>/…` is Homebrew.
Anything else is standalone. The pre-0.24 side-by-side layouts (`@merittdev/horus-rs-*`,
`Cellar/horus-rs`) are still recognised: they upgrade to `@merittdev/horus`, or
`brew install meritt-dev/tap/horus`. For npm and Homebrew installs, the update notice also names
the package-manager command. Standalone self-replace downloads `horus-cli-<target>.tar.gz`,
checks it against its `.sha256`, unpacks it with `tar`, swaps the binary (with rollback) and
writes the wheel beside it.

Archive and installer names keep dist's package-derived `horus-cli-` prefix. The Cargo package
is `horus-cli`; renaming it would change `cargo build -p horus-cli` everywhere, along with the
binstall and update asset names, for a cosmetic gain.

**No wheel (shell installer, binstall, source build).** `resolve_bundled_wheel` looks beside the
resolved binary and in `../share/<exe name>/`. When neither has it, `horus init` writes the
config, skips indexing and prints the installer hint. Fix it with `horus update --force`, which
fetches this release's archive and writes the wheel beside the binary. A source build can't
carry the wheel and runs with `HORUS_VERSION=dev`, so it can't enforce the backend pin. Install
the backend yourself (`uv tool install` on a `horus_source` wheel built from `Meritt-dev/horus`).

### npm layout (esbuild/biome pattern)

`node release/npm/build.mjs --archives <dir> --version X.Y.Z --out <dir>` writes:

- `@merittdev/horus-darwin-arm64`, `-darwin-x64`, `-linux-arm64`, `-linux-x64`: each holds
  `bin/horus` and `bin/horus_source.whl`, with `os`/`cpu` set so npm installs only the matching
  one. All four names were free on npm before 0.24.0.
- `@merittdev/horus`: the `horus` bin is `bin/horus.js`, which resolves
  `<its own name>-<process.platform>-<process.arch>`, spawns `bin/horus` with inherited stdio,
  forwards SIGINT/SIGTERM/SIGHUP/SIGQUIT and exits with the child's code (or re-raises its signal).
  The platform packages are `optionalDependencies` pinned to the same version. No postinstall,
  no download.

The npm name is set in one place: `NPM_NAME` in `release/npm/build.mjs`, which the
`HORUS_NPM_NAME` env var overrides. The publish job publishes the platform packages first and
the launcher last. It skips any version already on npm, so a re-run resumes.

## One-time setup

Secrets and variables in the release repo (Settings → Secrets and variables → Actions):

| Name | Kind | Needed for | When absent |
| ---- | ---- | ---------- | ----------- |
| `HOMEBREW_TAP_DEPLOY_KEY` | secret | write deploy key on `Meritt-dev/homebrew-tap` | the Homebrew job prints a notice and skips |
| npm trusted publisher | npm package setting | each of `@merittdev/horus` and the four `@merittdev/horus-<platform>` packages trusts GitHub Actions `Meritt-dev/horus-rust` → `release.yml` (no token, no OTP; the account enforces 2FA on publishing, so tokens get `EOTP`) | the npm job fails with `ENEEDAUTH`/`E404`; publish the release by hand with `npm publish <tgz>` (2FA) and add the trust |
| `HORUS_SOURCE_REF` | variable | `Meritt-dev/horus` ref the wheel is built from | defaults to `v0.23.0` |
| `CODESIGN_CERTIFICATE`, `CODESIGN_CERTIFICATE_PASSWORD`, `CODESIGN_IDENTITY` | secrets | Developer ID signing (base64 `.p12`, its password, e.g. `Developer ID Application: Meritt Dev (TEAMID)`) | unused while `macos-sign = false` |
| `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` | secrets | `notarytool` (app-specific password) | the notarize job prints a notice and skips (it also needs `CODESIGN_IDENTITY`) |

**macOS signing is off** (`macos-sign = false`). dist 0.33 does not skip signing when the
`CODESIGN_*` secrets are empty. It fails the macOS builds (`SecKeychainItemImport … failed to
import certificate`; this broke the v0.23.0 run). Once the three `CODESIGN_*` secrets exist, set
`macos-sign = true` in `dist-workspace.toml` and run `dist generate`. Until then the binaries keep
the linker's ad-hoc signature. curl, npm and Homebrew don't set the quarantine bit, so they run
as-is.

Notarization doesn't modify the archives. A bare Mach-O can't be stapled, so Gatekeeper fetches
the ticket online. The first signed release should confirm that dist signs with the hardened
runtime and a timestamp, which notarization requires.

**Wheel source.** `Meritt-dev/horus` is public, so the checkout needs no token. The backend is
versioned on its own: the checkout uses `vars.HORUS_SOURCE_REF`, falling back to `v0.23.0`
(`bcdc5f0`, the commit npm `@merittdev/horus@0.23.0` was built from). The wheel step then stamps
`packages/source-py` to `HORUS_VERSION` (e.g. 0.20.0 → 0.24.0), so the bundled wheel always
equals `PINNED_SOURCE_VERSION`. When the backend changes, tag it in `Meritt-dev/horus` and point
`HORUS_SOURCE_REF` at the tag.

## Cutting a release

1. Bump `[workspace.package] version` in `Cargo.toml`, then commit.
2. `dist plan` locally. It should list four archives, `horus-cli-installer.sh`, `horus.rb` and
   `sha256.sum`.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag must equal the workspace version; dist
   checks this in its plan job.
4. `release.yml` runs plan → build (four runners, wheel built on each) → global installers → host
   (GitHub release) → Homebrew formula push + npm publish → announce → notarize.

Local dry run (no credentials, nothing published):

```sh
cp <horus>/packages/source-py/dist/horus_source.whl crates/cli/   # from build-source-wheel.sh, stamped
HORUS_VERSION=0.24.0 dist build --artifacts=local --target=aarch64-apple-darwin
node release/npm/build.mjs --archives target/distrib --version 0.24.0 --out /tmp/npm --allow-missing
(cd /tmp/npm/horus-darwin-arm64 && npm pack) && (cd /tmp/npm/horus && npm pack)
npm i -g --prefix /tmp/horus-npm-test --offline /tmp/npm/*/*.tgz && /tmp/horus-npm-test/bin/horus --version
```

For a Linux musl archive, run the same `dist build` in `rust:1.96.0-bookworm` with `musl-tools`
installed (see PORTING.md for the Docker volume layout).

## Upgrading from the TypeScript horus (≤ 0.23.0)

- **npm:** `npm i -g @merittdev/horus@latest` (or the TS `horus update`, which self-replaces from
  `Meritt-dev/horus` releases and therefore stays on TS; use npm). It swaps the TS bundle for the
  launcher and native binary.
- **Homebrew:** `brew upgrade horus` once the tap's `horus.rb` is the Rust formula. It drops
  `depends_on "node"`.
- **Config and secrets** (`~/.horus`, `.horus/config.json`, encrypted `secrets.local.json`) are
  read as-is.
- **Local history.** TS kept investigations, scores, memory and sync state in PGlite at
  `~/.horus/horus.db`. This build uses SQLite at `~/.horus/horus-rust.db`. Bring it over once:

  ```sh
  horus db migrate-from-ts            # --from <dir> for a non-default location
  ```

  1. It refuses while a live TS process holds `horus.db.lock` (the same lock protocol TS uses).
  2. Under that lock it copies the data dir to a temp dir, so the original is only read.
  3. It serves the copy with `npx @electric-sql/pglite-socket@0.2.6` (paired with pglite 0.5.3,
     the TS build's) on a free loopback port.
  4. It imports all 20 tables (registry, investigations and their evidence, findings and
     hypotheses, incident memory, outcome labels, memory items, links and audit, queue edges,
     provider cache, memory-sync state, watch jobs), upserting by primary key. Memory-sync
     triggers are held off, so sync generations arrive unchanged and nothing is re-pushed to Cloud.
  5. It stops the server, deletes the copy and prints rows per table.

  Rows whose parent no longer exists are skipped and counted. PGlite stores can hold such rows
  despite their FK constraints; SQLite with foreign keys on cannot. Re-running is safe. It needs
  `node`/`npx` and prints a clear message when they're missing. While `horus-rust.db` has no
  investigations and `horus.db` exists, interactive commands print a one-line dim reminder on
  stderr.

  Verified on a copy of a real TS store (608 investigations). Every table matched the source
  count minus the orphans the source query confirmed (e.g. evidence 17632 → 16720 with 912
  orphans). `sum(sync_generation)` was 1023 on both sides, `horus memory list` showed "Synced;
  0 pending", and a second run changed nothing.

## Open decisions

- **crates.io.** `horus` and `horus-cli` are taken by an unrelated project. All crates are
  `publish = false`, and cargo-binstall works from the GitHub release via `--git`. Publishing
  means renaming the CLI package, then publishing the eight internal crates under free names in
  dependency order: core → ai, connectors, db, knowledge → stitcher, engine → eval → cli. A
  crates.io source build still has no wheel (see "No wheel" above).
- **Notarization.** Wired but unproven until a Developer ID certificate exists.

## npm trusted publishing (one-time, per package)

`@merittdev` requires 2FA on publishing, so CI can't publish with a token. Instead each package
trusts this repo's release workflow (needs npm ≥ 11.10 for `npm trust`; run with 2FA):

```sh
for p in @merittdev/horus @merittdev/horus-darwin-arm64 @merittdev/horus-darwin-x64 \
         @merittdev/horus-linux-arm64 @merittdev/horus-linux-x64; do
  npx -y npm@latest trust github "$p" --file release.yml --repo Meritt-dev/horus-rust --allow-publish -y
done
```

A new platform package (e.g. another target) has to be published once by hand before it can be trusted.
