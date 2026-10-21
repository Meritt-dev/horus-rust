#!/usr/bin/env node
// Side-by-side benchmark: TypeScript horus vs Rust horus on real projects.
//
// Usage: node bench/run.mjs [--project <dir>] [--ts <bin>] [--rs <bin>] [--only <a,b>] [--skip <a,b>]
//                           [--group <name>] [--runs N] [--timeout ms] [--config <file>] [--concurrency]
// Writes bench/out/<timestamp>/{results.json,REPORT.md,<case>/{ts,rs}.{out,err}}
//
// What is measured, per case and per side:
//   wall time (best successful run + every run), CPU user+sys, peak RSS (via /usr/bin/time -l),
//   exit code, output parity (text Dice / JSON structure), and — for release use cases —
//   pass/fail of the same expectations the repo's release scripts assert.
// Plus: footprint (binary/runtime size), cold start, and concurrent throughput.
//
// Safety: every command is read-only against production systems. TS cloud writes are blocked by a
// fetch preload (no-cloud-writes.cjs); Rust blocks them with HORUS_RUST_CLOUD_WRITE=0.
// Each run gets its own process group so a timeout kills the whole tree (a hung TS run once held the
// TS DB lock for 30 min).
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync, statSync, mkdtempSync, rmSync, readdirSync, readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
};
// Machine-specific setup (project paths, real symbols, hints, acceptance cases) lives in the
// gitignored bench/projects.local.json; bench/projects.example.json shows the shape.
const LOCAL_FILE = join(here, 'projects.local.json');
const LOCAL = existsSync(LOCAL_FILE) ? JSON.parse(readFileSync(LOCAL_FILE, 'utf8')) : {};
const TS_ROOT = LOCAL.tsRoot ?? process.env.HORUS_TS_ROOT ?? join(here, '..', '..', 'horus');
const PROJECT = resolve(opt('--project', LOCAL.mainProject ?? process.cwd()));
const MAIN = { sym: 'App', sym2: 'AppService', area: 'app', hint: 'recent errors', hint2: 'jobs retrying', metricsHint: 'latency', question: 'how does the main flow work', ...LOCAL.main };
const TS_BIN = opt('--ts', `node ${TS_ROOT}/apps/horus/dist/index.cjs`);
const RS_BIN = opt('--rs', join(here, '..', 'target-bench', 'release', 'horus-rs'));
const ONLY = opt('--only', null);
const SKIP = opt('--skip', null);
const GROUP = opt('--group', null);
const RUNS = Number(opt('--runs', '1'));
const TIMEOUT_MS = Number(opt('--timeout', '240000'));
const NO_CLOUD_WRITES = join(here, 'no-cloud-writes.cjs');

// HOR-83 regression input from scripts/acceptance/release-smoke.sh (JS config must load, no babel.cjs crash).
const smokeDir = mkdtempSync(join(tmpdir(), 'horus-bench-smoke-'));
const SMOKE_CONFIG = join(smokeDir, 'horus.config.js');
writeFileSync(
  SMOKE_CONFIG,
  `export default {
  database: { url: "postgresql://localhost:5432/horus" },
  projects: [{
    name: "smoke-test",
    repositories: [{ name: "smoke-test", path: "/tmp/smoke-test" }],
    environments: [{ name: "production", connectors: {} }],
  }],
};
`,
);

// ── checks (release acceptance) ───────────────────────────────────────────────────────────────
const has = (s, ci = false) => ({ kind: 'contains', value: s, ci });
const lacks = (s) => ({ kind: 'absent', value: s });
const noLine = (re) => ({ kind: 'noLine', value: re });
const exit0 = { kind: 'exit0' };
const nonzero = { kind: 'nonzero' };

// ── case matrix ─────────────────────────────────────────────────────────────────────────────
// group: cli | engine | knowledge | saved | release-smoke | release-acceptance
// json: structural diff; live: compare outputs from a simultaneous paired run; compare:false: timing only.
const CASES = [
  // CLI command matrix (the main project, real connectors)
  { group: 'cli', name: 'version', argv: ['--version'] },
  { group: 'cli', name: 'doctor', argv: ['doctor'] },
  { group: 'cli', name: 'doctor-json', argv: ['doctor', '--json'], json: true },
  { group: 'cli', name: 'status', argv: ['status'], live: true },
  { group: 'cli', name: 'status-json', argv: ['status', '--json'], json: true, live: true },
  { group: 'cli', name: 'readiness', argv: ['readiness'] },
  { group: 'cli', name: 'projects', argv: ['projects'] },
  { group: 'cli', name: 'repos', argv: ['repos'] },
  { group: 'cli', name: 'hosts', argv: ['hosts'] },
  { group: 'cli', name: 'investigations', argv: ['investigations'] },
  { group: 'cli', name: 'queues', argv: ['queues'] },
  { group: 'cli', name: 'queues-json', argv: ['queues', '--json'], json: true },
  { group: 'cli', name: 'queues-live', argv: ['queues', '--live'], live: true },
  { group: 'cli', name: 'queues-live-json', argv: ['queues', '--live', '--json'], json: true, live: true },
  { group: 'cli', name: 'logs', argv: ['logs', '--since', '24h'], live: true },
  { group: 'cli', name: 'logs-json', argv: ['logs', '--since', '24h', '--json'], json: true, live: true },
  { group: 'cli', name: 'state', argv: ['state'], live: true },
  { group: 'cli', name: 'state-json', argv: ['state', '--json'], json: true, live: true },
  { group: 'cli', name: 'metrics', argv: ['metrics', MAIN.metricsHint], live: true },
  { group: 'cli', name: 'what-changed', argv: ['what-changed'] },
  { group: 'cli', name: 'what-changed-json', argv: ['what-changed', '--json'], json: true },
  { group: 'cli', name: 'timeline', argv: ['timeline'] },
  { group: 'cli', name: 'architecture', argv: ['architecture'] },
  { group: 'cli', name: 'architecture-json', argv: ['architecture', '--json'], json: true },
  { group: 'cli', name: 'insights', argv: ['insights'] },
  { group: 'cli', name: 'explain', argv: ['explain', MAIN.sym] },
  { group: 'cli', name: 'explain-json', argv: ['explain', MAIN.sym, '--json'], json: true },
  { group: 'cli', name: 'blast-radius', argv: ['blast-radius', MAIN.sym] },
  { group: 'cli', name: 'owner', argv: ['owner', MAIN.sym] },
  { group: 'cli', name: 'owner-json', argv: ['owner', MAIN.sym, '--json'], json: true },
  { group: 'cli', name: 'search', argv: ['search', MAIN.sym] },
  { group: 'cli', name: 'search-json', argv: ['search', MAIN.sym, '--json'], json: true },
  { group: 'cli', name: 'trace', argv: ['trace', MAIN.sym, MAIN.sym2] },
  { group: 'cli', name: 'changes', argv: ['changes', 'HEAD~5', 'HEAD'] },
  { group: 'cli', name: 'changes-json', argv: ['changes', 'HEAD~5', 'HEAD', '--json'], json: true },
  { group: 'cli', name: 'onboard', argv: ['onboard', MAIN.area] },
  { group: 'cli', name: 'providers-doctor', argv: ['providers', 'doctor'] },
  { group: 'cli', name: 'secrets-status', argv: ['secrets', 'status'] },
  { group: 'cli', name: 'telemetry-status', argv: ['telemetry', 'status'] },
  { group: 'cli', name: 'context-show', argv: ['context', 'show'] },
  { group: 'cli', name: 'lens', argv: ['lens'] },
  { group: 'cli', name: 'memory-show', argv: ['memory', 'show'] },
  { group: 'cli', name: 'memory-list', argv: ['memory', 'list'] },
  { group: 'cli', name: 'memory-accuracy', argv: ['memory', 'accuracy'] },
  { group: 'cli', name: 'investigate-text', argv: ['investigate', MAIN.hint, '--timeout', '180'], heavy: true },
  { group: 'cli', name: 'investigate-json', argv: ['investigate', MAIN.hint, '--json', '--timeout', '180'], json: true, heavy: true },
  { group: 'cli', name: 'investigate-md', argv: ['investigate', MAIN.hint2, '--format', 'markdown', '--timeout', '180'], heavy: true },

  // Offline engine: the full investigation pipeline on built-in synthetic incidents (deterministic, no network).
  { group: 'engine', name: 'simulate-list', argv: ['simulate'] },
  ...['queue-backlog', 'external-api-outage', 'deployment-regression', 'database-slowdown', 'cache-failure'].map((s) => ({
    group: 'engine',
    name: `simulate-${s}`,
    argv: ['simulate', s],
  })),

  // Project knowledge index (.horus/index, ~12 MB) — offline.
  { group: 'knowledge', name: 'knowledge-status', argv: ['knowledge', 'status'] },
  { group: 'knowledge', name: 'knowledge-validate', argv: ['knowledge', 'validate'] },
  { group: 'knowledge', name: 'knowledge-search', argv: ['knowledge', 'search', 'product'] },
  { group: 'knowledge', name: 'knowledge-contracts', argv: ['knowledge', 'contracts', 'Product'] },
  { group: 'knowledge', name: 'knowledge-trace', argv: ['knowledge', 'trace', 'order'] },
  { group: 'knowledge', name: 'knowledge-ask', argv: ['knowledge', 'ask', MAIN.question] },

  // Saved-investigation workloads: each CLI re-reads its OWN latest saved report (separate DBs), so these
  // are timing + exit comparisons, not output parity.
  ...['replay', 'score', 'postmortem', 'packet'].map((c) => ({ group: 'saved', name: `${c}-last`, argv: [c, '@last'], compare: false })),

  // Release use case 1 — scripts/acceptance/release-smoke.sh: the CLI contract every release must pass.
  { group: 'release-smoke', name: 'smoke-version', argv: ['--version'], checks: [exit0, has('horus'), has('0.'), has('0.23.0')] },
  {
    group: 'release-smoke',
    name: 'smoke-help',
    argv: ['--help'],
    checks: [exit0, has('investigate'), has('init'), has('connect'), has('Usage: horus'), noLine('^  setup'), noLine('^  index')],
  },
  ...[['setup', '--help'], ['index', '--help'], ['setup'], ['index'], ['generate-config'], ['help', 'setup'], ['help', 'index']].map((a) => ({
    group: 'release-smoke',
    name: `smoke-removed-${a.join('-')}`,
    argv: a,
    checks: [nonzero],
  })),
  ...['investigate', 'connect', 'hosts', 'stop'].map((c) => ({ group: 'release-smoke', name: `smoke-${c}-help`, argv: [c, '--help'], checks: [exit0] })),
  { group: 'release-smoke', name: 'smoke-doctor', argv: ['doctor'], checks: [has('Horus readiness check'), has('CLI version')] },
  { group: 'release-smoke', name: 'smoke-config-js', argv: ['doctor', '--config', SMOKE_CONFIG], checks: [lacks('babel.cjs'), has('CLI version')] },

  // Release use cases with real expectations (e.g. scripts/acceptance/zoho-sync-delay.sh) need a real
  // project and incident, so they come from projects.local.json: [{ name, cwd?, argv, json?, checks }].
  ...(LOCAL.acceptance ?? []).map((a) => ({ group: 'release-acceptance', heavy: true, ...a })),
];

// ── other projects (multi-project sweep) — keyed by absolute path in projects.local.json ───────
// One real symbol pair, an area word and an investigate hint per repo; `runtime` adds the live cases.
const PROJECT_CASES = LOCAL.projects ?? {};
const projectCases = ({ sym, sym2, area, hint, runtime }) => [
  ...[
    ['doctor'], ['doctor', '--json'], ['status'], ['status', '--json'], ['readiness'], ['repos'], ['hosts'],
    ['architecture'], ['architecture', '--json'], ['insights'], ['what-changed'], ['timeline'],
    ['changes', 'HEAD~5', 'HEAD'], ['changes', 'HEAD~5', 'HEAD', '--json'], ['knowledge', 'status'], ['knowledge', 'search', area],
    ['queues'], ['queues', '--json'], ['memory', 'show', area], ['onboard', area],
    ['explain', sym], ['explain', sym, '--json'], ['blast-radius', sym], ['owner', sym], ['search', sym], ['trace', sym2, sym],
  ].map((argv) => ({ group: 'cli', name: argv.filter((a) => a !== 'HEAD~5' && a !== 'HEAD').join('-').replace(/^-+|--/g, ''), argv, json: argv.includes('--json') })),
  ...(runtime
    ? [['logs', '--since', '24h'], ['logs', '--since', '24h', '--json'], ['state'], ['state', '--json'], ['queues', '--live'], ['metrics', area]].map((argv) => ({
        group: 'runtime', name: argv.filter((a) => a !== '--since' && a !== '24h').join('-').replace(/--/g, ''), argv, json: argv.includes('--json'), live: true,
      }))
    : []),
  { group: 'investigate', name: 'investigate-json', argv: ['investigate', hint, '--json', '--timeout', '180'], json: true, heavy: true },
];
if (PROJECT_CASES[PROJECT]) CASES.splice(0, CASES.length, ...projectCases(PROJECT_CASES[PROJECT]));
// --config <file>: a config outside the repo (e.g. pointing the repo at its OWN source host when the
// registered port is held by another repo's host). Appended to every command that accepts it.
const CFG = opt('--config', null);
if (CFG) for (const c of CASES) if (!['hosts', 'knowledge', '--version', '--help'].includes(c.argv[0])) c.argv = [...c.argv, '--config', CFG];

const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const OUT = join(here, 'out', stamp);
mkdirSync(OUT, { recursive: true });

// ── process running ───────────────────────────────────────────────────────────────────────────
function envFor(cmd) {
  const nodeOptions = cmd === 'node' ? `${process.env.NODE_OPTIONS ?? ''} --require ${NO_CLOUD_WRITES}`.trim() : process.env.NODE_OPTIONS;
  return { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0', HORUS_TELEMETRY: '0', NODE_OPTIONS: nodeOptions, HORUS_RUST_CLOUD_WRITE: '0' };
}

// /usr/bin/time -l appends its report to stderr; split it off and parse it.
const TIME_RE = /\n?\s*([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys\n[\s\S]*$/;
function parseTime(err) {
  const m = err.match(TIME_RE);
  if (!m) return { err, cpuMs: NaN, rssMb: NaN };
  const rss = err.slice(m.index).match(/(\d+)\s+maximum resident set size/);
  return {
    err: err.slice(0, m.index),
    cpuMs: (Number(m[2]) + Number(m[3])) * 1000,
    rssMb: rss ? Number(rss[1]) / 1024 / 1024 : NaN, // macOS reports bytes
  };
}

function run(bin, argv, cwd = PROJECT) {
  const [cmd, ...pre] = bin.split(' ');
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const child = spawn('/usr/bin/time', ['-l', cmd, ...pre, ...argv], { cwd, env: envFor(cmd), detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '', timedOut = false;
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    const timer = setTimeout(() => {
      timedOut = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    }, TIMEOUT_MS);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      const t = parseTime(err);
      resolve({ ms, code: timedOut ? null : code, signal, out, err: t.err, cpuMs: t.cpuMs, rssMb: t.rssMb, timedOut });
    });
  });
}

const busy = (r) => /HORUS_DB_BUSY/.test(r.err);

async function best(bin, argv, cwd, n) {
  const runs = [];
  for (let i = 0; i < n; i++) {
    let r = await run(bin, argv, cwd);
    // Another Horus process briefly held the TS DB lock: contention, not a result. Retry.
    for (let k = 0; k < 5 && busy(r); k++) r = await run(bin, argv, cwd);
    runs.push(r);
  }
  // Fastest of the runs sharing the most common exit code — a fast failure never wins.
  const counts = new Map();
  for (const r of runs) counts.set(r.code, (counts.get(r.code) ?? 0) + 1);
  const mode = [...counts.entries()].sort((a, b) => b[1] - a[1] || (a[0] === 0 ? -1 : 1))[0][0];
  const b = runs.filter((r) => r.code === mode).reduce((x, y) => (y.ms < x.ms ? y : x));
  return { ...b, allMs: runs.map((r) => Math.round(r.ms)), allCpu: runs.map((r) => Math.round(r.cpuMs)), allRss: runs.map((r) => r.rssMb) };
}

// `@last` → the side's own most recent saved investigation id.
const lastIds = {};
async function lastId(bin) {
  if (!(bin in lastIds)) {
    const r = await run(bin, ['investigations', '--json']);
    let id = null;
    try {
      const j = JSON.parse(r.out);
      const list = Array.isArray(j) ? j : (j.investigations ?? j.items ?? []);
      id = list.find((x) => !x.cloud && !x.source?.includes?.('cloud'))?.id ?? list[0]?.id ?? null;
    } catch {}
    lastIds[bin] = id;
  }
  return lastIds[bin];
}
const resolveArgv = (bin, argv) => Promise.all(argv.map((a) => (a === '@last' ? lastId(bin) : a)));

// ── comparison ──────────────────────────────────────────────────────────────────────────────
const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');
const VOLATILE = /\b(\d{4}-\d{2}-\d{2}T[\d:.]+Z?|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d+(\.\d+)?\s?(ms|s)\b)/g;
// Intended divergence: the Rust port uses its own DB file (DIVERGENCES.md).
const sameDb = (s) => s.replaceAll('horus-rust.db', 'horus.db');
const normText = (s) => sameDb(strip(s)).split('\n').map((l) => l.replace(VOLATILE, '<v>').trimEnd()).filter(Boolean);

function textSimilarity(a, b) {
  const A = normText(a), B = normText(b);
  if (!A.length && !B.length) return 1;
  const setB = new Map();
  for (const l of B) setB.set(l, (setB.get(l) ?? 0) + 1);
  let common = 0;
  for (const l of A) if (setB.get(l) > 0) { common++; setB.set(l, setB.get(l) - 1); }
  return (2 * common) / (A.length + B.length);
}

function jsonDiff(a, b, path = '', acc = { missing: [], extra: [], changed: [], order: [], same: 0 }) {
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) acc.changed.push(`${path}.length ${a.length}→${b.length}`);
    for (let i = 0; i < Math.min(a.length, b.length); i++) jsonDiff(a[i], b[i], `${path}[${i}]`, acc);
    return acc;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const ka = Object.keys(a), kb = Object.keys(b);
    const shared = ka.filter((k) => k in b), sharedB = kb.filter((k) => k in a);
    if (shared.join() !== sharedB.join()) acc.order.push(path || '.');
    for (const k of ka) if (!(k in b)) acc.missing.push(`${path}.${k}`); else jsonDiff(a[k], b[k], `${path}.${k}`, acc);
    for (const k of kb) if (!(k in a)) acc.extra.push(`${path}.${k}`);
    return acc;
  }
  if (a === b) acc.same++;
  else if (typeof a === 'string' && typeof b === 'string' && a.replace(VOLATILE, '') === b.replace(VOLATILE, '')) acc.same++;
  else acc.changed.push(`${path}: ${JSON.stringify(a)?.slice(0, 60)} → ${JSON.stringify(b)?.slice(0, 60)}`);
  return acc;
}
const tryJson = (s) => { try { return JSON.parse(s); } catch { return undefined; } };

function compare(c, tsOut, rsOut) {
  if (c.compare === false) return { kind: 'none' };
  if (c.json) {
    const a = tryJson(tsOut), b = tryJson(sameDb(rsOut));
    if (a === undefined || b === undefined) return { kind: 'json', parse: { ts: a !== undefined, rs: b !== undefined } };
    const d = jsonDiff(a, b);
    const total = d.same + d.changed.length + d.missing.length + d.extra.length;
    return {
      kind: 'json', parse: { ts: true, rs: true }, score: total ? d.same / total : 1,
      counts: { same: d.same, changed: d.changed.length, missing: d.missing.length, extra: d.extra.length, keyOrder: d.order.length },
      missing: d.missing.slice(0, 50), extra: d.extra.slice(0, 50), changed: d.changed.slice(0, 50), order: d.order.slice(0, 20),
    };
  }
  return { kind: 'text', score: textSimilarity(tsOut, rsOut), identical: normText(tsOut).join('\n') === normText(rsOut).join('\n') };
}

function evalChecks(checks, r) {
  const text = strip(`${r.out}\n${r.err}`);
  return checks.map((ch) => {
    let pass;
    if (ch.kind === 'exit0') pass = r.code === 0;
    else if (ch.kind === 'nonzero') pass = r.code !== 0 && r.code !== null;
    else if (ch.kind === 'contains') pass = ch.ci ? text.toLowerCase().includes(ch.value.toLowerCase()) : text.includes(ch.value);
    else if (ch.kind === 'absent') pass = !text.includes(ch.value);
    else if (ch.kind === 'noLine') pass = !new RegExp(ch.value, 'm').test(text);
    return { desc: `${ch.kind}${ch.value ? ` ${JSON.stringify(ch.value)}` : ''}`, pass };
  });
}

// ── run cases ───────────────────────────────────────────────────────────────────────────────
const rsBuilt = existsSync(RS_BIN);
const results = [];
for (const c of CASES) {
  if (ONLY && !ONLY.split(',').some((o) => c.name.includes(o))) continue;
  if (SKIP && SKIP.split(',').some((o) => c.name.includes(o))) continue;
  if (GROUP && c.group !== GROUP) continue;
  process.stderr.write(`▶ [${c.group}] ${c.name} … `);
  const dir = join(OUT, c.name);
  mkdirSync(dir, { recursive: true });
  const n = c.heavy ? 1 : RUNS; // investigate cases take minutes against live prod: one run each
  const tsArgv = await resolveArgv(TS_BIN, c.argv);
  const ts = await best(TS_BIN, tsArgv, c.cwd ?? PROJECT, n);
  const rsArgv = rsBuilt ? await resolveArgv(RS_BIN, c.argv) : c.argv;
  const rs = rsBuilt ? await best(RS_BIN, rsArgv, c.cwd ?? PROJECT, n) : { ms: NaN, code: null, out: '', err: 'rust binary not built', allMs: [] };
  for (const [side, r] of [['ts', ts], ['rs', rs]]) {
    writeFileSync(join(dir, `${side}.out`), r.out);
    writeFileSync(join(dir, `${side}.err`), r.err);
  }
  let tsOut = ts.out, rsOut = rs.out;
  if (c.live && rsBuilt) {
    // Live data: start both at the same instant so they query the same time window (timings stay sequential).
    const [pts, prs] = await Promise.all([run(TS_BIN, c.argv, c.cwd ?? PROJECT), run(RS_BIN, c.argv, c.cwd ?? PROJECT)]);
    writeFileSync(join(dir, 'ts.paired.out'), pts.out);
    writeFileSync(join(dir, 'rs.paired.out'), prs.out);
    tsOut = pts.out; rsOut = prs.out;
  }
  const cmp = compare(c, tsOut, rsOut);
  // stderr carries warnings and errors (unknown command, degraded connectors): part of 1:1 too.
  if (c.compare !== false) cmp.errScore = textSimilarity(ts.err, rs.err);
  const checks = c.checks ? { ts: evalChecks(c.checks, ts), rs: evalChecks(c.checks, rs) } : undefined;
  const pick = (r) => ({ ms: r.ms, allMs: r.allMs, cpuMs: r.cpuMs, allCpu: r.allCpu, rssMb: r.rssMb, code: r.code, timedOut: r.timedOut, cloudBlocked: /Cannot reach Horus Cloud|Cloud request failed/.test(r.err ?? '') });
  const row = { group: c.group, name: c.name, argv: c.argv, cwd: c.cwd ?? PROJECT, live: !!c.live, ts: pick(ts), rs: pick(rs), cmp, checks };
  results.push(row);
  const chk = checks ? ` | checks ts ${checks.ts.filter((x) => x.pass).length}/${checks.ts.length} rs ${checks.rs.filter((x) => x.pass).length}/${checks.rs.length}` : '';
  process.stderr.write(`ts ${ts.code} ${ts.ms.toFixed(0)}ms | rs ${rs.code} ${isNaN(rs.ms) ? '-' : rs.ms.toFixed(0) + 'ms'} | match ${cmp.score === undefined ? 'n/a' : (cmp.score * 100).toFixed(0) + '%'}${chk}\n`);
}

// ── footprint, cold start, concurrency (only on a full run) ───────────────────────────────────
const extras = {};
if (!ONLY && !GROUP && rsBuilt && !PROJECT_CASES[PROJECT]) {
  process.stderr.write('▶ footprint / cold start / concurrency …\n');
  const duKb = (p) => {
    let total = 0;
    const walk = (q) => { const s = statSync(q); if (s.isDirectory()) for (const e of readdirSync(q)) walk(join(q, e)); else total += s.size; };
    try { walk(p); } catch {}
    return total / 1024;
  };
  extras.footprint = {
    rustBinaryMb: statSync(RS_BIN).size / 1024 / 1024,
    tsBundleMb: duKb(join(TS_ROOT, 'apps/horus/dist')) / 1024,
    nodeRuntimeMb: statSync(process.execPath).size / 1024 / 1024,
  };
  const cold = async (bin) => {
    const ms = [], rss = [];
    for (let i = 0; i < 20; i++) { const r = await run(bin, ['--version']); ms.push(r.ms); rss.push(r.rssMb); }
    ms.sort((a, b) => a - b);
    return { medianMs: ms[9], p95Ms: ms[18], minMs: ms[0], rssMb: Math.max(...rss) };
  };
  extras.coldStart = { ts: await cold(TS_BIN), rs: await cold(RS_BIN) };
  const burst = async (bin, argv, n) => {
    const t0 = process.hrtime.bigint();
    const rs = await Promise.all(Array.from({ length: n }, () => run(bin, argv)));
    return { wallMs: Number(process.hrtime.bigint() - t0) / 1e6, ok: rs.filter((r) => r.code === 0).length, n, peakRssSumMb: rs.reduce((s, r) => s + (r.rssMb || 0), 0) };
  };
  // Only commands that never open the local DB: concurrent TS processes on one PGlite data dir
  // can corrupt it (seen once during benchmarking).
  extras.concurrency = [];
  // N simultaneous TS processes: opt-in (--concurrency), since the sweep rule is one TS command at a time.
  if (args.includes('--concurrency')) for (const [label, argv, n] of [['search ×8', ['search', MAIN.sym], 8], ['knowledge search ×8', ['knowledge', 'search', 'product'], 8]]) {
    extras.concurrency.push({ label, ts: await burst(TS_BIN, argv, n), rs: await burst(RS_BIN, argv, n) });
  }
}
rmSync(smokeDir, { recursive: true, force: true });

writeFileSync(join(OUT, 'results.json'), JSON.stringify({ tsBin: TS_BIN, rsBin: RS_BIN, runs: RUNS, generatedAt: new Date().toISOString(), results, extras }, null, 2));

// ── report ──────────────────────────────────────────────────────────────────────────────────
const pct = (x) => (x === undefined ? 'n/a' : `${(x * 100).toFixed(0)}%`);
const msf = (x) => (x === undefined || isNaN(x) ? '-' : x >= 10000 ? `${(x / 1000).toFixed(1)} s` : `${x.toFixed(0)} ms`);
const mb = (x) => (x === undefined || isNaN(x) ? '-' : `${x.toFixed(0)} MB`);
const ratio = (a, b) => (isNaN(a) || isNaN(b) || !b ? '-' : `${(a / b).toFixed(1)}×`);
const med = (a) => { const b = [...a].filter((x) => !isNaN(x)).sort((x, y) => x - y); return b.length ? b[Math.floor((b.length - 1) / 2)] : NaN; };
const geo = (xs) => { const v = xs.filter((x) => x > 0 && isFinite(x)); return v.length ? Math.exp(v.reduce((s, x) => s + Math.log(x), 0) / v.length) : NaN; };
const spread = (a) => (a?.length > 1 ? `±${(((Math.max(...a) - Math.min(...a)) / 2 / med(a)) * 100).toFixed(0)}%` : '-');
// By design: TS fails a run whose Cloud upload is blocked (exit 1); the Rust port keeps it local (exit 0).
const cloudBlockedOnly = (r) => r.ts.code === 1 && r.rs.code === 0 && r.ts.cloudBlocked;
const exitSame = (r) => r.ts.code === r.rs.code || cloudBlockedOnly(r);
const exitOk = (r) => (r.ts.code === r.rs.code ? '✓' : cloudBlockedOnly(r) ? '✓ (TS upload blocked)' : `✗ ${r.ts.code}/${r.rs.code}`);
const passes = (l) => `${l.filter((x) => x.pass).length}/${l.length}`;

const md = [];
md.push('# Horus TS vs Rust — side-by-side benchmark', '');
md.push(`TS: \`${TS_BIN}\`  `, `Rust: \`${RS_BIN}\`  `, `Runs per case: best of ${RUNS} (investigate/acceptance: 1)  `, `Generated: ${new Date().toISOString()}`, '');
md.push(
  '**Method.** Every case runs TS then Rust from the same directory against the same production connectors (read-only).',
  'Time = best successful wall-clock run; CPU = user+sys and RSS = peak resident memory, both from `/usr/bin/time -l`.',
  'Live-data cases (*) compare outputs from a paired run where both CLIs start in the same instant (same query window).',
  'Text match = line-multiset Dice after stripping ANSI, timestamps, UUIDs, durations and the intended `horus-rust.db` path; JSON match = share of identical leaf values.',
  'Cloud writes are blocked on both sides (TS: `bench/no-cloud-writes.cjs`; Rust: `HORUS_RUST_CLOUD_WRITE=0`), so nothing uploads to Horus Cloud.',
  '',
);

// summary by group
md.push('## Summary', '', '| Group | Cases | Exit parity | Identical output | Mean match | Mean stderr match | Geo-mean speedup | CPU ratio TS/Rust | Peak RSS TS → Rust |', '|---|---:|---:|---:|---:|---:|---:|---:|---|');
const groups = [...new Set(results.map((r) => r.group))];
for (const g of groups) {
  const rs = results.filter((r) => r.group === g && !isNaN(r.rs.ms));
  if (!rs.length) continue;
  const scored = rs.filter((r) => r.cmp.score !== undefined);
  const ident = rs.filter((r) => r.cmp.identical || r.cmp.score === 1).length;
  md.push(
    `| ${g} | ${rs.length} | ${rs.filter(exitSame).length}/${rs.length} | ${scored.length ? `${ident}/${scored.length}` : '-'} | ${scored.length ? pct(scored.reduce((s, r) => s + r.cmp.score, 0) / scored.length) : '-'} | ${scored.length ? pct(scored.reduce((s, r) => s + (r.cmp.errScore ?? 0), 0) / scored.length) : '-'} | ${ratio(geo(rs.map((r) => r.ts.ms / r.rs.ms)), 1)} | ${ratio(geo(rs.map((r) => r.ts.cpuMs / r.rs.cpuMs)), 1)} | ${mb(med(rs.map((r) => r.ts.rssMb)))} → ${mb(med(rs.map((r) => r.rs.rssMb)))} (median) |`,
  );
}

// release use cases
const rel = results.filter((r) => r.checks);
if (rel.length) {
  md.push('', '## Release use cases', '', '| Suite | Case | TS | Rust | Failing expectations |', '|---|---|---:|---:|---|');
  for (const r of rel) {
    const fails = r.checks.ts.map((t, i) => [t, r.checks.rs[i]]).filter(([t, s]) => !t.pass || !s.pass).map(([t, s]) => `${t.desc} (ts ${t.pass ? '✓' : '✗'} rs ${s.pass ? '✓' : '✗'})`);
    md.push(`| ${r.group} | ${r.name} | ${passes(r.checks.ts)} | ${passes(r.checks.rs)} | ${fails.join('; ') || '—'} |`);
  }
  const tot = (side) => rel.reduce((s, r) => s + r.checks[side].filter((x) => x.pass).length, 0);
  const all = rel.reduce((s, r) => s + r.checks.ts.length, 0);
  md.push('', `**Expectations passed:** TS ${tot('ts')}/${all} · Rust ${tot('rs')}/${all}`);
}

// per-case table
md.push('', '## All cases', '', '| Group | Case | Exit | TS time | Rust time | Speedup | TS CPU | Rust CPU | TS RSS | Rust RSS | Output match | stderr match |', '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|');
for (const r of results) {
  md.push(`| ${r.group} | ${r.name}${r.live ? ' *' : ''} | ${exitOk(r)} | ${msf(r.ts.ms)} | ${msf(r.rs.ms)} | ${ratio(r.ts.ms, r.rs.ms)} | ${msf(r.ts.cpuMs)} | ${msf(r.rs.cpuMs)} | ${mb(r.ts.rssMb)} | ${mb(r.rs.rssMb)} | ${r.cmp.kind === 'none' ? 'n/a (own DB)' : pct(r.cmp.score)} | ${pct(r.cmp.errScore)} |`);
}

if (extras.footprint) {
  const f = extras.footprint, cs = extras.coldStart;
  md.push('', '## Footprint and cold start', '', '| Metric | TS | Rust |', '|---|---:|---:|');
  md.push(`| Shipped artifact | ${f.tsBundleMb.toFixed(1)} MB bundle + ${f.nodeRuntimeMb.toFixed(0)} MB Node runtime | ${f.rustBinaryMb.toFixed(1)} MB single binary |`);
  md.push(`| Cold start \`--version\` median (20 runs) | ${msf(cs.ts.medianMs)} | ${msf(cs.rs.medianMs)} |`);
  md.push(`| Cold start p95 | ${msf(cs.ts.p95Ms)} | ${msf(cs.rs.p95Ms)} |`);
  md.push(`| Baseline peak RSS | ${mb(cs.ts.rssMb)} | ${mb(cs.rs.rssMb)} |`);
  md.push('', '## Concurrency (N simultaneous invocations)', '', '| Workload | TS wall | Rust wall | TS ok | Rust ok | TS Σ peak RSS | Rust Σ peak RSS |', '|---|---:|---:|---:|---:|---:|---:|');
  for (const c of extras.concurrency) md.push(`| ${c.label} | ${msf(c.ts.wallMs)} | ${msf(c.rs.wallMs)} | ${c.ts.ok}/${c.ts.n} | ${c.rs.ok}/${c.rs.n} | ${mb(c.ts.peakRssSumMb)} | ${mb(c.rs.peakRssSumMb)} |`);
}

md.push('', '## Timing detail', '', 'Every measured run (ms). Spread = half the min–max range relative to the median.', '');
md.push('| Case | TS runs | TS spread | Rust runs | Rust spread | Median speedup |', '|---|---|---:|---|---:|---:|');
for (const r of results) md.push(`| ${r.name} | ${(r.ts.allMs ?? []).join(', ')} | ${spread(r.ts.allMs)} | ${(r.rs.allMs ?? []).join(', ')} | ${spread(r.rs.allMs)} | ${ratio(med(r.ts.allMs ?? []), med(r.rs.allMs ?? []))} |`);

md.push('', '## JSON structural differences', '');
for (const r of results.filter((r) => r.cmp.kind === 'json')) {
  md.push(`### ${r.name}`, '');
  if (!r.cmp.parse?.ts || !r.cmp.parse?.rs) { md.push(`- parse: ts=${r.cmp.parse?.ts} rs=${r.cmp.parse?.rs}`, ''); continue; }
  const k = r.cmp.counts;
  md.push(`- same ${k.same} · changed ${k.changed} · missing-in-rust ${k.missing} · extra-in-rust ${k.extra} · objects with different key order ${k.keyOrder}`);
  for (const key of ['missing', 'extra', 'changed', 'order']) if (r.cmp[key].length) { md.push(`- ${key}:`); for (const x of r.cmp[key].slice(0, 15)) md.push(`  - \`${x}\``); }
  md.push('');
}
md.push('Raw stdout/stderr per case live next to this file.');
writeFileSync(join(OUT, 'REPORT.md'), md.join('\n'));
process.stderr.write(`\nreport: ${join(OUT, 'REPORT.md')}\n`);
