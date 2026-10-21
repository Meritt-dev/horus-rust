// Preloaded into the TS CLI during benchmarks (NODE_OPTIONS=--require).
// Refuses non-GET requests to Horus Cloud as a network failure, so TS degrades the
// same way it does offline. Mirrors the Rust port's HORUS_RUST_CLOUD_WRITE gate:
// benchmark investigations never upload to the shared workspace; cloud reads still work.
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { homedir } = require('node:os');

const hosts = new Set(['api.horus.sh']);
try {
  const auth = JSON.parse(readFileSync(join(process.env.HORUS_HOME ?? join(homedir(), '.horus'), 'auth.json'), 'utf8'));
  if (auth.apiBaseUrl) hosts.add(new URL(auth.apiBaseUrl).host);
} catch {}

const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
  const method = (init?.method ?? (typeof input === 'object' && 'method' in input ? input.method : 'GET')).toUpperCase();
  if (hosts.has(url.host) && method !== 'GET') {
    throw new TypeError('fetch failed', { cause: new Error(`benchmark: Horus Cloud writes blocked (${method} ${url.pathname})`) });
  }
  return realFetch(input, init);
};

