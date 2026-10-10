#!/usr/bin/env node
// Smoke-test a running Tokker Worker: the harness built-ins (/__health,
// /__ready, /__surface) and the 404 fallback. Start the Worker first
// (`npx wrangler dev --local` from the repo root), then run
// `node tools/smoke.mjs [base-url]`. SMOKE_URL or the first argument set the
// base URL (default http://127.0.0.1:8787); prints one PASS/FAIL line per
// check and exits 1 if any check fails.

const BASE = process.env.SMOKE_URL || process.argv[2] || 'http://127.0.0.1:8787';

let failed = false;

/** Run one check: name plus an async function answering {ok, detail}. */
async function check(name, fn) {
  try {
    const { ok, detail } = await fn();
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
    if (!ok) failed = true;
  } catch (err) {
    console.log(`FAIL ${name} — ${err.message}`);
    failed = true;
  }
}

/** GET a path, returning the response and its text (empty on a read error). */
async function get(path) {
  const res = await fetch(BASE + path, { redirect: 'manual' });
  const body = await res.text().catch(() => '');
  return { res, body };
}

/** {ok, detail} for a plain status expectation. */
function atStatus(res, want, body) {
  const ok = want(res.status);
  return { ok, detail: `status ${res.status}${ok ? '' : `: ${body.slice(0, 200)}`}` };
}

await check('/__health answers 2xx', async () => {
  const { res, body } = await get('/__health');
  return atStatus(res, (s) => s >= 200 && s < 300, body);
});

// Locally the D1 binding is wired, so /__ready's SELECT 1 answers 200.
await check('/__ready answers 2xx (SELECT 1 through the DB port)', async () => {
  const { res, body } = await get('/__ready');
  return atStatus(res, (s) => s >= 200 && s < 300, body);
});

await check('/__surface answers 2xx JSON', async () => {
  const { res, body } = await get('/__surface');
  let json = null;
  try {
    json = JSON.parse(body);
  } catch {
    // left null; the detail below says so
  }
  const ok = res.status >= 200 && res.status < 300 && json !== null;
  return { ok, detail: `status ${res.status}, ${json === null ? 'body is not JSON' : 'JSON'}` };
});

await check('unknown path answers 404', async () => {
  const { res, body } = await get('/__smoke-not-a-route');
  return atStatus(res, (s) => s === 404, body);
});

process.exit(failed ? 1 : 0);
