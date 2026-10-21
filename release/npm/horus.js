#!/usr/bin/env node
// Launcher for the native Horus binary (esbuild/biome pattern). npm installs exactly one
// platform package through optionalDependencies; this shim runs its `bin/horus`, inheriting
// stdio and forwarding signals and the exit status. No postinstall, no download.
'use strict';
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const launcher = require('../package.json').name;
const pkg = `${launcher}-${process.platform}-${process.arch}`;

let binary;
try {
  binary = path.join(path.dirname(require.resolve(`${pkg}/package.json`)), 'bin', 'horus');
} catch {
  const supported = Object.keys(require('../package.json').optionalDependencies || {}).join(', ');
  console.error(
    `horus: no native binary for ${process.platform}-${process.arch} (expected the optional package ${pkg}).\n` +
      `Supported: ${supported}.\n` +
      'If you installed with --omit=optional or --no-optional, reinstall without it.',
  );
  process.exit(1);
}

// Some npm versions drop the executable bit from non-`bin` files.
try {
  fs.accessSync(binary, fs.constants.X_OK);
} catch {
  fs.chmodSync(binary, 0o755);
}

const child = spawn(binary, process.argv.slice(2), { stdio: 'inherit' });
const forward = (signal) => child.kill(signal);
const signals = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'];
for (const s of signals) process.on(s, forward);
child.on('error', (err) => {
  console.error(`horus: failed to start ${binary}: ${err.message}`);
  process.exit(1);
});
child.on('exit', (code, signal) => {
  for (const s of signals) process.off(s, forward);
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 1);
});
