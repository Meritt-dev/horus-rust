#!/usr/bin/env node
// Turn dist's release archives into npm packages: one per platform (bin/horus +
// bin/horus_source.whl, with os/cpu set) and one launcher with them as optionalDependencies.
//
//   node release/npm/build.mjs --archives <dir with horus-cli-*.tar.gz> --version 0.23.0 --out <dir>
//
// The npm name is decided HERE (or by HORUS_NPM_NAME). From 0.24.0 the Rust build IS
// '@merittdev/horus' (it replaced the TS package, which published up to 0.23.0).
// See docs/RELEASE.md.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';

const NPM_NAME = process.env.HORUS_NPM_NAME || '@merittdev/horus';
const BIN = 'horus';

// npm platform suffix (process.platform-process.arch) → dist target triple.
const PLATFORMS = {
  'darwin-arm64': 'aarch64-apple-darwin',
  'darwin-x64': 'x86_64-apple-darwin',
  'linux-arm64': 'aarch64-unknown-linux-musl',
  'linux-x64': 'x86_64-unknown-linux-musl',
};

const { values } = parseArgs({
  options: {
    archives: { type: 'string' },
    version: { type: 'string' },
    out: { type: 'string' },
    // Local dry runs only build some targets; CI must have all four.
    'allow-missing': { type: 'boolean', default: false },
  },
});
const { archives, out } = values;
const version = values.version?.replace(/^v/, '');
if (!archives || !version || !out) {
  console.error('usage: build.mjs --archives <dir> --version <x.y.z> --out <dir> [--allow-missing]');
  process.exit(2);
}

const here = path.dirname(new URL(import.meta.url).pathname);
const common = {
  version,
  description: 'Local-first, source-aware production-incident investigation engine',
  license: 'MIT',
  homepage: 'https://horus.sh',
  repository: { type: 'git', url: 'https://github.com/meritt-dev/horus' },
};
const write = (dir, json) => {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), `${JSON.stringify(json, null, 2)}\n`);
};

fs.rmSync(out, { recursive: true, force: true });
const built = [];
for (const [suffix, target] of Object.entries(PLATFORMS)) {
  const archive = path.join(archives, `horus-cli-${target}.tar.gz`);
  if (!fs.existsSync(archive)) {
    if (values['allow-missing']) {
      console.warn(`skip ${suffix}: ${archive} not found`);
      continue;
    }
    throw new Error(`missing ${archive}`);
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'horus-npm-'));
  execFileSync('tar', ['-xzf', archive, '-C', tmp]);
  const src = path.join(tmp, `horus-cli-${target}`);
  const dir = path.join(out, `${BIN}-${suffix}`);
  fs.mkdirSync(path.join(dir, 'bin'), { recursive: true });
  for (const f of [BIN, 'horus_source.whl']) {
    if (!fs.existsSync(path.join(src, f))) throw new Error(`${archive} has no ${f}`);
    fs.copyFileSync(path.join(src, f), path.join(dir, 'bin', f));
  }
  fs.chmodSync(path.join(dir, 'bin', BIN), 0o755);
  fs.rmSync(tmp, { recursive: true, force: true });
  const [platform, cpu] = suffix.split('-');
  write(dir, {
    name: `${NPM_NAME}-${suffix}`,
    ...common,
    os: [platform],
    cpu: [cpu],
    files: ['bin'],
    preferUnplugged: true,
    publishConfig: { access: 'public' },
  });
  built.push(dir);
}

const launcher = path.join(out, BIN);
fs.mkdirSync(path.join(launcher, 'bin'), { recursive: true });
fs.copyFileSync(path.join(here, `${BIN}.js`), path.join(launcher, 'bin', `${BIN}.js`));
fs.chmodSync(path.join(launcher, 'bin', `${BIN}.js`), 0o755);
write(launcher, {
  name: NPM_NAME,
  ...common,
  bin: { [BIN]: `bin/${BIN}.js` },
  files: ['bin'],
  engines: { node: '>=18' },
  optionalDependencies: Object.fromEntries(Object.keys(PLATFORMS).map((s) => [`${NPM_NAME}-${s}`, version])),
  publishConfig: { access: 'public' },
});

// Publish order: platform packages first, the launcher last.
console.log([...built, launcher].join('\n'));
