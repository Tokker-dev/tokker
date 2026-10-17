import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, expect, test } from 'vitest';
import { annotate, classify, staleness } from './freshness.mjs';
import { validateDocuments } from './validate.mjs';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const tmpDir = mkdtempSync(join(tmpdir(), 'tokker-build-test-'));
const rules = JSON.parse(readFileSync(new URL('../data/rules/freshness.json', import.meta.url), 'utf-8'));
const vectors = JSON.parse(readFileSync(new URL('../tests/vectors/staleness.json', import.meta.url), 'utf-8'));

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

test('every shared vector matches the build implementation (the Worker runs the same file)', () => {
  expect(vectors.vectors.length).toBeGreaterThan(0);
  for (const v of vectors.vectors) {
    const got = staleness(
      { rowType: v.row_type, volatility: v.volatility, lastVerifiedAt: v.last_verified_at, today: v.today },
      rules
    );
    expect(got, v.name).toEqual(v.expect);
  }
});

test('classify picks the first matching rule; row type beats volatility', () => {
  expect(classify('api_offer', 'high', rules)).toBe('volatile_api');
  expect(classify('api_offer', 'medium', rules)).toBe('standard_api');
  expect(classify('api_offer', 'low', rules)).toBe('standard_api');
  expect(classify('subscription', 'high', rules)).toBe('subscription');
  expect(() => classify('plan', 'high', rules)).toThrow(/no freshness rule/);
  expect(() => staleness({ rowType: 'api_offer', volatility: 'high', lastVerifiedAt: '2026-10-05', today: '2026-10-05' }, { classes: {}, rules: [] })).toThrow(
    /no freshness rule/
  );
});

test('a malformed date is an error, not a silently fresh row', () => {
  const stale = { rowType: 'api_offer', volatility: 'high', today: '2026-10-05' };
  expect(() => staleness({ ...stale, lastVerifiedAt: 'not-a-date' }, rules)).toThrow(/not an ISO date/);
  expect(() => staleness({ ...stale, lastVerifiedAt: '2026-02-30' }, rules)).toThrow(/not a real calendar date/);
  expect(() => staleness({ ...stale, lastVerifiedAt: '2026-10-05', today: '2026-13-01' }, rules)).toThrow(
    /not a real calendar date/
  );
});

function makeRow(overrides = {}) {
  return {
    id: 'testco/test-model',
    last_verified_at: '2026-10-05',
    fetch_recipe: { volatility: 'high' },
    provenance: {},
    ...overrides,
  };
}

function makeDoc(apiOffers = [], subscriptions = []) {
  return { api_offers: apiOffers, subscriptions };
}

test('per-field staleness flags an older override once it, too, passes the SLA', () => {
  const doc = makeDoc([
    makeRow({
      id: 'testco/old-field',
      provenance: { fields: { input_per_mtok: { fetched_at: '2026-09-01' } } },
    }),
  ]);
  const built = annotate(doc, { today: '2026-10-05' });
  expect(built.api_offers[0].stale_fields).toEqual({ input_per_mtok: '2026-09-05' });
});

test('a "default" fields entry, an older-but-fresh one and a newer one are never flagged', () => {
  const doc = makeDoc([
    makeRow({
      id: 'testco/default-field',
      provenance: { fields: { input_per_mtok: 'default' } },
    }),
    makeRow({
      id: 'testco/fresh-field',
      provenance: { fields: { input_per_mtok: { fetched_at: '2026-10-03' } } }, // older than the row, within the SLA
    }),
  ]);
  const built = annotate(doc, { today: '2026-10-05' });
  for (const row of built.api_offers) expect(row.stale_fields).toBeUndefined();
});

test('an override newer than the row is not flagged even when the row itself is stale', () => {
  const doc = makeDoc([
    makeRow({
      id: 'testco/newer-field',
      last_verified_at: '2026-09-01',
      provenance: { fields: { input_per_mtok: { fetched_at: '2026-09-28' } } },
    }),
  ]);
  const built = annotate(doc, { today: '2026-10-05' });
  expect(built.api_offers[0].stale).toBe(true);
  expect(built.api_offers[0].stale_fields).toBeUndefined();
});

test('annotate sets counts.stale, the five oldest rows (ties by id) and leaves the input alone', () => {
  const doc = makeDoc(
    [
      makeRow({ id: 'testco/b', last_verified_at: '2026-10-02' }),
      makeRow({ id: 'testco/a', last_verified_at: '2026-10-01' }),
      makeRow({ id: 'testco/d', last_verified_at: '2026-10-02' }),
      makeRow({ id: 'testco/c', last_verified_at: '2026-09-25', fetch_recipe: { volatility: 'medium' } }),
    ],
    [makeRow({ id: 'testco/plan', last_verified_at: '2026-08-01', fetch_recipe: { volatility: 'high' } })]
  );
  const built = annotate(doc, { today: '2026-10-05' });
  // plan: subscription class (14d) despite high volatility, stale; a: volatile 4d, stale;
  // c: standard 10d, exactly at SLA, fresh; b and d: 3d, fresh.
  expect(built.counts.stale).toBe(2);
  expect(built.freshness.as_of).toBe('2026-10-05');
  expect(built.freshness.oldest).toEqual([
    { id: 'testco/plan', row_type: 'subscription', last_verified_at: '2026-08-01', stale: true, stale_since: '2026-08-16' },
    { id: 'testco/c', row_type: 'api_offer', last_verified_at: '2026-09-25', stale: false, stale_since: null },
    { id: 'testco/a', row_type: 'api_offer', last_verified_at: '2026-10-01', stale: true, stale_since: '2026-10-05' },
    { id: 'testco/b', row_type: 'api_offer', last_verified_at: '2026-10-02', stale: false, stale_since: null },
    { id: 'testco/d', row_type: 'api_offer', last_verified_at: '2026-10-02', stale: false, stale_since: null },
  ]);
  expect(doc.api_offers[0].stale).toBeUndefined();
  expect(doc.freshness).toBeUndefined();
});

test('the annotated real dataset passes the schema', () => {
  const source = JSON.parse(readFileSync(new URL('../data/pricing.json', import.meta.url), 'utf-8'));
  const built = annotate(source, { today: '2026-10-10' });
  expect(validateDocuments([{ file: 'dist/pricing.json', doc: built }])).toEqual([]);
  // Every row was verified 2026-10-05, so only the volatile API rows (3-day SLA)
  // are past it five days later; subscriptions (14d) and standard rows (10d) are not.
  const volatile = source.api_offers.filter((row) => row.fetch_recipe.volatility === 'high').length;
  expect(built.counts.stale).toBe(volatile);
  expect(built.freshness.oldest).toHaveLength(5);
});

test('the build CLI writes its output and prints one summary line', () => {
  const out = join(tmpDir, 'pricing.json');
  const r = spawnSync(process.execPath, ['tools/build.mjs', '--as-of', '2026-10-10', '--out', out], {
    cwd: repoRoot,
    encoding: 'utf-8',
  });
  expect(r.status, `stderr: ${r.stderr}`).toBe(0);
  expect(r.stdout.trim().split('\n')).toHaveLength(1);
  const built = JSON.parse(readFileSync(out, 'utf-8'));
  expect(built.freshness.as_of).toBe('2026-10-10');
  expect(built.counts.stale).toBeGreaterThan(0);
});

test('the build rejects a bad --as-of and unknown arguments', () => {
  for (const args of [['--as-of', 'tomorrow'], ['--wat']]) {
    const r = spawnSync(process.execPath, ['tools/build.mjs', ...args], { cwd: repoRoot, encoding: 'utf-8' });
    expect(r.status).toBe(1);
    expect(r.stderr).not.toBe('');
  }
});
