# Benchmark: Horus TypeScript vs Rust

These are side-by-side runs of the TypeScript CLI (`horus` 0.23.0) and this port (`horus-rs` 0.23.0), measured on a MacBook (Apple silicon) in October 2026.

## Method

- **Projects:** 12 real repositories. One is a full production setup (Elasticsearch, Grafana, MongoDB, Redis, Shopify). Others use Elasticsearch, Postgres, Sentry or Axiom, and the rest are code-only.
- **Commands:** about 80 command cases for the main project, plus about 30 for each of the others. They cover health checks, queues, logs, state, metrics, code intelligence, project knowledge, saved investigations, full `investigate` runs, and the release smoke and acceptance checks.
- **Read-only:** every case runs TS, then Rust, from the same directory against the same live systems. Cloud writes are blocked on both sides.
- **Live data:** cases that read live data are also compared from a paired run where both CLIs start in the same instant, so they query the same window.
- **Parity:** text output is compared line by line after masking timestamps, ids and durations. JSON is compared value by value, including key order. stderr and exit codes are compared too.
- **Resources:** wall time is the best successful run. CPU and peak memory come from `/usr/bin/time -l`.
- **Harness:** `bench/run.mjs`.

## Results

| | TypeScript | Rust |
|---|---:|---:|
| Exit-code parity, main project | — | 79/80 (the one exception was a TS-side database fault) |
| Identical output, main project | — | 66/76 compared cases; the other 10 differ only by local history, live data or clock |
| Exit-code parity, 11 other repos | — | 100% |
| Mean output match, 11 other repos | — | 98–100% |
| Release smoke + acceptance expectations | 32/41 | 32/41 (identical passes and failures) |
| Cold start (`--version`, median) | 158 ms | 5 ms |
| Idle peak memory | 153 MB | 10 MB |
| Typical command peak memory | 170–950 MB | 15–90 MB |
| Full investigation peak memory | 950–1,280 MB | 140–175 MB |
| Speedup, geometric mean per project | — | 2.5×–11.8× |
| Shipped artifact | 26 MB bundle + 112 MB Node runtime | about 32 MB single binary |

Rust is faster wherever the work is local: startup, code intelligence, the knowledge index, saved reports, and the analysis engine (4–35×). It's about equal where both CLIs mostly wait on a remote system, such as large MongoDB scans and source-host diffs. Full investigations run 1.1–1.3× faster.

## Known differences

All of these are listed in `DIVERGENCES.md`.

- **Separate local database.** Rust uses SQLite at `~/.horus/horus-rust.db`; TS uses PGlite at `~/.horus/horus.db`. Cloud-synced memory flows into both, but local-only history does not.
- **JS/TS config files.** `horus.config.{js,ts}` is loaded through an installed `node`. `.horus/config.json` needs nothing extra.
- **Crash output.** JavaScript stack frames on an uncaught error cannot be reproduced.
- **Cloud writes switch.** `HORUS_RUST_CLOUD_WRITE=0` turns off cloud writes and telemetry. The benchmark uses it.
