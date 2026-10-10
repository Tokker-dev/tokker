import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, expect, test } from 'vitest';
import {
  checkPr,
  loadRules,
  loadRows,
  type Finding,
  type LoadedFile,
  type Row,
  type RowSet,
} from './check-pr.ts';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const DATE = '2026-10-10';
const tmpDir = mkdtempSync(join(tmpdir(), 'tokker-check-pr-test-'));

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

// --- fixtures ---------------------------------------------------------------

function offer(over: Row = {}): Row {
  return {
    id: 'testco/test-model',
    provider_id: 'testco',
    model_slug: 'test-model',
    model_name: 'Test Model',
    currency: 'USD',
    input_per_mtok: 3,
    output_per_mtok: 15,
    cached_input_per_mtok: 0.3,
    cache_write_per_mtok: 3.75,
    last_verified_at: DATE,
    provenance: {
      default: {
        source: 'https://docs.testco.example/pricing',
        fetched_at: DATE,
        method: 'docs_markdown',
        confidence: 'official_docs',
      },
      fields: { input_per_mtok: 'default' },
    },
    ...over,
  };
}

function plan(over: Row = {}): Row {
  return {
    id: 'testco/pro',
    vendor_id: 'testco',
    product: 'TestBot',
    plan_name: 'Pro',
    currency: 'USD',
    price_month: 20,
    price_year: 200,
    limits_published: [
      { window: '5h_rolling', unit: 'tokens', amount: 'unknown', quote: 'usage caps apply' },
    ],
    last_verified_at: DATE,
    provenance: {
      default: {
        source: 'https://docs.testco.example/plans',
        fetched_at: DATE,
        method: 'html_static',
        confidence: 'official_page',
      },
      fields: { price_month: 'default' },
    },
    ...over,
  };
}

function rowSet(offers: Row[] = [], plans: Row[] = []): RowSet {
  const toMap = (rows: Row[]): Map<string, Row> => new Map(rows.map((r) => [r.id as string, r]));
  return { offers: toMap(offers), plans: toMap(plans) };
}

const TEST_HOSTS = { testco: ['testco.example'] };

/** checkPr pinned to the fixture date, with testco's host registered unless
 * the test overrides it. */
function check(base: RowSet, head: RowSet, opts: Record<string, unknown> = {}) {
  return checkPr(base, head, { date: DATE, providerHosts: TEST_HOSTS, ...opts });
}

const triples = (findings: Finding[]) =>
  findings.map((f) => ({ rule: f.rule, id: f.id, field: f.field }));

/** Exactly one finding of the given rule/id/field in `kind`, none in the other. */
function expectExactlyOne(
  result: { violations: Finding[]; flags: Finding[] },
  kind: 'violations' | 'flags',
  rule: string,
  id: string,
  field?: string
) {
  expect(triples(result[kind])).toEqual([{ rule, id, field }]);
  expect(result[kind === 'violations' ? 'flags' : 'violations']).toEqual([]);
}

// --- rules ------------------------------------------------------------------

test('identical sides are clean', () => {
  const rows = rowSet([offer()], [plan()]);
  expect(check(rows, rows)).toEqual({ violations: [], flags: [] });
});

test('a clean price change with fresh provenance has no violations and no flags', () => {
  const result = check(rowSet([offer()]), rowSet([offer({ input_per_mtok: 3.5 })]));
  expect(result).toEqual({ violations: [], flags: [] });
});

test('a brand-new row with fresh provenance is clean', () => {
  expect(check(rowSet(), rowSet([offer()]))).toEqual({ violations: [], flags: [] });
});

test('id.removed: a dropped row without a successor fails', () => {
  expectExactlyOne(check(rowSet([offer()]), rowSet([])), 'violations', 'id.removed', 'testco/test-model');
});

test('id.removed: a successor with supersedes excuses the removal', () => {
  const head = rowSet([
    offer({ id: 'testco/test-model-v2', model_slug: 'test-model-v2', supersedes: 'testco/test-model' }),
  ]);
  expect(check(rowSet([offer()]), head)).toEqual({ violations: [], flags: [] });
});

test('id.removed: a retired row may be removed', () => {
  expect(check(rowSet([offer({ retired_at: '2026-09-01' })]), rowSet())).toEqual({
    violations: [],
    flags: [],
  });
});

test('retiring a row in place (adding retired_at) is bookkeeping and needs no fresh provenance', () => {
  // stale last_verified_at would fail if adding retired_at counted as a change
  const base = offer({ last_verified_at: '2026-01-01' });
  const head = offer({ last_verified_at: '2026-01-01', retired_at: '2026-09-01' });
  expect(check(rowSet([base]), rowSet([head]))).toEqual({ violations: [], flags: [] });
});

test('id.reused: changing an identity field fails and names the field', () => {
  const result = check(rowSet([offer()]), rowSet([offer({ model_name: 'Renamed Model' })]));
  expectExactlyOne(result, 'violations', 'id.reused', 'testco/test-model', 'model_name');
});

test('id.reused: reactivating a retired row with new content fails', () => {
  const head = offer({ retired_at: '2026-09-01', input_per_mtok: 4 });
  const result = check(rowSet([offer({ retired_at: '2026-09-01' })]), rowSet([head]));
  expectExactlyOne(result, 'violations', 'id.reused', 'testco/test-model');
});

test('id.reused: an id superseded in the base must not come back changed', () => {
  const successor = offer({
    id: 'testco/test-model-v2',
    model_slug: 'test-model-v2',
    supersedes: 'testco/test-model',
  });
  const result = check(rowSet([offer(), successor]), rowSet([offer({ input_per_mtok: 4 }), successor]));
  expectExactlyOne(result, 'violations', 'id.reused', 'testco/test-model');
});

test('bounds.negative: a negative price fails and names the field', () => {
  const result = check(rowSet([offer()]), rowSet([offer({ input_per_mtok: -1, cached_input_per_mtok: null })]));
  expectExactlyOne(result, 'violations', 'bounds.negative', 'testco/test-model', 'input_per_mtok');
});

test('bounds.move: more than 10x up or down fails; exactly 10x passes', () => {
  // keep output (and other prices) put so only the move rule can fire
  const up = check(
    rowSet([offer({ output_per_mtok: 50 })]),
    rowSet([offer({ output_per_mtok: 50, input_per_mtok: 31 })])
  );
  expectExactlyOne(up, 'violations', 'bounds.move', 'testco/test-model', 'input_per_mtok');

  const down = check(
    rowSet([offer({ output_per_mtok: 1, cached_input_per_mtok: 0.05 })]),
    rowSet([offer({ output_per_mtok: 1, cached_input_per_mtok: 0.05, input_per_mtok: 0.2 })])
  );
  expectExactlyOne(down, 'violations', 'bounds.move', 'testco/test-model', 'input_per_mtok');

  const exact = check(
    rowSet([offer({ output_per_mtok: 50 })]),
    rowSet([offer({ output_per_mtok: 50, input_per_mtok: 30 })])
  );
  expect(exact.violations).toEqual([]);

  // 3 -> 0.3 and 0.3 -> 3 are decimal-exact 10x moves; float rounding of the
  // ratio must not turn them into violations
  const floatDown = check(
    rowSet([offer({ output_per_mtok: 50, input_per_mtok: 3, cached_input_per_mtok: 0.05 })]),
    rowSet([offer({ output_per_mtok: 50, input_per_mtok: 0.3, cached_input_per_mtok: 0.05 })])
  );
  const floatUp = check(
    rowSet([offer({ output_per_mtok: 50, input_per_mtok: 0.3, cached_input_per_mtok: 0.05 })]),
    rowSet([offer({ output_per_mtok: 50, input_per_mtok: 3, cached_input_per_mtok: 0.05 })])
  );
  expect(floatDown.violations).toEqual([]);
  expect(floatUp.violations).toEqual([]);
});

test('bounds.inverted: input above output fails unless the provider is registered', () => {
  const inverted = offer({ input_per_mtok: 20, output_per_mtok: 10 });
  expectExactlyOne(
    check(rowSet([offer()]), rowSet([inverted])),
    'violations',
    'bounds.inverted',
    'testco/test-model',
    'input_per_mtok'
  );
  const excused = check(rowSet([offer()]), rowSet([inverted]), {
    invertedProviders: new Set(['testco']),
  });
  expect(excused).toEqual({ violations: [], flags: [] });
});

test('bounds.currency: a currency change fails and carries both values', () => {
  const result = check(rowSet([offer()]), rowSet([offer({ currency: 'EUR' })]));
  expect(result.violations.length).toBe(1);
  expect(result.violations[0]).toMatchObject({
    rule: 'bounds.currency',
    id: 'testco/test-model',
    field: 'currency',
    base: 'USD',
    head: 'EUR',
  });
});

test('bounds.cache: a cache-hit price above the input price fails', () => {
  // cached 1 -> 5 is a 5x move, so only the cache rule can fire
  const result = check(
    rowSet([offer({ cached_input_per_mtok: 1 })]),
    rowSet([offer({ cached_input_per_mtok: 5 })])
  );
  expectExactlyOne(result, 'violations', 'bounds.cache', 'testco/test-model', 'cached_input_per_mtok');
});

test('provenance.fetched_at: a named stale entry fails and reports the entry key', () => {
  const head = offer({
    input_per_mtok: 3.5,
    provenance: {
      default: {
        source: 'https://docs.testco.example/pricing',
        fetched_at: DATE,
        method: 'docs_markdown',
        confidence: 'official_docs',
      },
      recheck: {
        source: 'https://docs.testco.example/pricing',
        fetched_at: '2026-10-01',
        method: 'docs_markdown',
        confidence: 'official_docs',
      },
      fields: { input_per_mtok: 'recheck' },
    },
  });
  expectExactlyOne(
    check(rowSet([offer()]), rowSet([head])),
    'violations',
    'provenance.fetched_at',
    'testco/test-model',
    'recheck'
  );
});

test('provenance.fetched_at: a missing referenced entry fails as missing', () => {
  const head = offer({
    input_per_mtok: 3.5,
    provenance: {
      default: {
        source: 'https://docs.testco.example/pricing',
        fetched_at: DATE,
        method: 'docs_markdown',
        confidence: 'official_docs',
      },
      fields: { input_per_mtok: 'recheck' },
    },
  });
  const result = check(rowSet([offer()]), rowSet([head]));
  expectExactlyOne(result, 'violations', 'provenance.fetched_at', 'testco/test-model', 'recheck');
  expect(result.violations[0].message).toContain('missing');
});

test('provenance findings are reported once per provenance entry, not per field', () => {
  const head = offer({
    input_per_mtok: 3.5,
    output_per_mtok: 16,
    last_verified_at: '2026-10-01',
    provenance: {
      default: {
        source: 'https://docs.testco.example/pricing',
        fetched_at: '2026-10-01',
        method: 'docs_markdown',
        confidence: 'official_docs',
      },
      fields: {},
    },
  });
  const result = check(rowSet([offer()]), rowSet([head]));
  expect(result.violations).toHaveLength(2); // one fetched_at for both fields + one last_verified_at
  const fetched = result.violations.find((v) => v.rule === 'provenance.fetched_at');
  expect(fetched?.field).toBe('default');
  expect(fetched?.message).toContain('input_per_mtok, output_per_mtok');
});

test('provenance.last_verified_at: stale or missing fails once per row', () => {
  const stale = check(rowSet([offer()]), rowSet([offer({ input_per_mtok: 3.5, last_verified_at: '2026-10-01' })]));
  expectExactlyOne(stale, 'violations', 'provenance.last_verified_at', 'testco/test-model', 'last_verified_at');

  const missing = check(rowSet(), rowSet([offer({ last_verified_at: undefined })]));
  expect(triples(missing.violations)).toContainEqual({
    rule: 'provenance.last_verified_at',
    id: 'testco/test-model',
    field: 'last_verified_at',
  });
});

test('provenance.host: unregistered fails; registered exact or subdomain passes; secondary is exempt', () => {
  const changed = rowSet([offer({ input_per_mtok: 3.5 })]);
  const source = (url: string, confidence: string): Row =>
    offer({
      input_per_mtok: 3.5,
      provenance: {
        default: { source: url, fetched_at: DATE, method: 'docs_markdown', confidence },
        fields: {},
      },
    });

  expectExactlyOne(
    check(rowSet([offer()]), changed, { providerHosts: {} }),
    'violations',
    'provenance.host',
    'testco/test-model',
    'default'
  );

  expect(
    check(rowSet([offer()]), changed, { providerHosts: { testco: ['docs.testco.example'] } }).violations
  ).toEqual([]);
  expect(check(rowSet([offer()]), changed, { providerHosts: { testco: ['testco.example'] } }).violations).toEqual([]);

  const secondary = rowSet([source('https://someone-else.example/pricing', 'secondary')]);
  expect(check(rowSet([offer()]), secondary, { providerHosts: {} })).toEqual({
    violations: [],
    flags: [],
  });
});

test('untouched legacy rows are never failed, even if they break current rules', () => {
  const legacy = offer({ input_per_mtok: -5, provider_id: 'legacy-co', id: 'legacy-co/old', model_slug: 'old' });
  expect(check(rowSet([legacy]), rowSet([legacy]), { providerHosts: {} })).toEqual({
    violations: [],
    flags: [],
  });
});

test('limits.window and limits.unit changes are data:review flags, not violations', () => {
  const headPlan = plan({
    limits_published: [{ window: 'weekly', unit: 'prompts', amount: 'unknown', quote: 'x' }],
  });
  const result = check(rowSet([], [plan()]), rowSet([], [headPlan]));
  expect(result.violations).toEqual([]);
  expect(result.flags.map((f) => ({ rule: f.rule, id: f.id, field: f.field, label: f.label }))).toEqual([
    { rule: 'limits.window', id: 'testco/pro', field: 'limits_published', label: 'data:review' },
    { rule: 'limits.unit', id: 'testco/pro', field: 'limits_published', label: 'data:review' },
  ]);
});

test('loadRows prefers the shard layout and classifies arrays by directory', () => {
  const a = offer({ id: 'shard-a/m1', model_slug: 'm1' });
  const b = offer({ id: 'shard-b/m2', model_slug: 'm2' });
  const rows = loadRows([
    { path: 'data/pricing.json', json: { api_offers: [offer()] } },
    { path: 'data/offers/shard-a.json', json: { offers: [a] } },
    { path: 'data/offers/shard-b.json', json: [b] },
    { path: 'data/plans/shard-c.json', json: [plan()] },
  ]);
  expect([...rows.offers.keys()].sort()).toEqual(['shard-a/m1', 'shard-b/m2']);
  expect([...rows.plans.keys()]).toEqual(['testco/pro']);
});

test('loadRules reads the two known rule files and lowercases hosts', () => {
  const rules = loadRules([
    { path: 'data/rules/inverted-pricing.json', json: { providers: ['oddco'] } },
    { path: 'data/rules/provider-hosts.json', json: { hosts: { OddCo: ['ODD.example'] } } },
    { path: 'data/rules/unknown.json', json: { hosts: { nope: ['x'] } } },
  ]);
  expect(rules.invertedProviders).toEqual(new Set(['oddco']));
  expect(rules.providerHosts).toEqual({ OddCo: ['odd.example'] });
});

// --- CLI --------------------------------------------------------------------

function writeDataDir(
  root: string,
  rows: { offers?: Row[]; plans?: Row[] },
  rules?: Record<string, unknown>
): string {
  const dataDir = join(root, 'data');
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(
    join(dataDir, 'pricing.json'),
    JSON.stringify({ api_offers: rows.offers ?? [], subscriptions: rows.plans ?? [] })
  );
  if (rules) {
    mkdirSync(join(dataDir, 'rules'), { recursive: true });
    for (const [name, json] of Object.entries(rules)) {
      writeFileSync(join(dataDir, 'rules', name), JSON.stringify(json));
    }
  }
  return dataDir;
}

function cli(args: string[]) {
  return spawnSync(process.execPath, ['tools/check-pr.ts', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

const TEST_RULES = {
  'provider-hosts.json': { hosts: { testco: ['testco.example'] } },
  'inverted-pricing.json': { providers: [] },
};

test('CLI: --base-dir/--head-dir with --json reports the stale-provenance violation and the limit flag', () => {
  const baseRoot = join(tmpDir, 'cli-base');
  const headRoot = join(tmpDir, 'cli-head');
  writeDataDir(baseRoot, { offers: [offer()], plans: [plan()] });
  writeDataDir(
    headRoot,
    {
      offers: [offer({ input_per_mtok: 4, last_verified_at: '2026-10-01' })],
      plans: [plan({ limits_published: [{ window: 'weekly', unit: 'tokens', amount: 'unknown', quote: 'x' }] })],
    },
    TEST_RULES
  );
  const r = cli([
    '--base-dir', baseRoot, // repo-root style: contains data/
    '--head-dir', join(headRoot, 'data'), // data-dir style: pricing.json inside
    '--date', DATE,
    '--json',
  ]);
  expect(r.stderr).toBe('');
  expect(r.status).toBe(1);
  const out = JSON.parse(r.stdout);
  expect(out.ok).toBe(false);
  expect(out.date).toBe(DATE);
  expect(out.base).toBe(baseRoot);
  expect(triples(out.violations)).toEqual([
    { rule: 'provenance.last_verified_at', id: 'testco/test-model', field: 'last_verified_at' },
  ]);
  expect(triples(out.flags)).toEqual([{ rule: 'limits.window', id: 'testco/pro', field: 'limits_published' }]);
});

test('CLI: text mode prints violations to stderr; clean runs print counts and exit 0', () => {
  const baseRoot = join(tmpDir, 'cli-text-base');
  const headBad = join(tmpDir, 'cli-text-head-bad');
  const headClean = join(tmpDir, 'cli-text-head-clean');
  writeDataDir(baseRoot, { offers: [offer()] });
  writeDataDir(headBad, { offers: [offer({ input_per_mtok: -2, cached_input_per_mtok: null })] }, TEST_RULES);
  writeDataDir(headClean, { offers: [offer({ input_per_mtok: 3.5 })] }, TEST_RULES);

  const bad = cli(['--base-dir', baseRoot, '--head-dir', headBad, '--date', DATE]);
  expect(bad.status).toBe(1);
  expect(bad.stderr).toContain('bounds.negative testco/test-model.input_per_mtok:');
  expect(bad.stderr).toContain('1 violation(s)');

  const good = cli(['--base-dir', baseRoot, '--head-dir', headClean, '--date', DATE]);
  expect(good.status).toBe(0);
  expect(good.stdout.trim()).toBe('ok: 1 offers, 0 plans checked');
  expect(good.stderr).toBe('');
});

test('CLI: a bad ref or unknown argument exits 1 with a check-pr: message', () => {
  const badRef = cli(['--base', 'no-such-ref', '--date', DATE]);
  expect(badRef.status).toBe(1);
  expect(badRef.stderr).toContain('check-pr:');
  const badArg = cli(['--nope']);
  expect(badArg.status).toBe(1);
  expect(badArg.stderr).toContain("unknown argument '--nope'");
});

// --- the real dataset -------------------------------------------------------

const REAL_RULES: LoadedFile[] = ['inverted-pricing.json', 'provider-hosts.json'].map((name) => ({
  path: `data/rules/${name}`,
  json: JSON.parse(readFileSync(join(repoRoot, 'data', 'rules', name), 'utf8')),
}));

test('full dataset: base = head = data/pricing.json with the real rules is clean', () => {
  const file: LoadedFile = {
    path: 'data/pricing.json',
    json: JSON.parse(readFileSync(join(repoRoot, 'data', 'pricing.json'), 'utf8')),
  };
  const rows = loadRows([file]);
  const rules = loadRules(REAL_RULES);
  const result = checkPr(rows, rows, {
    date: DATE,
    invertedProviders: rules.invertedProviders,
    providerHosts: rules.providerHosts,
  });
  expect(result).toEqual({ violations: [], flags: [] });
  expect(rows.offers.size).toBe(480);
  expect(rows.plans.size).toBe(103);
});

test('full dataset: the CLI against HEAD runs clean in under 10s', () => {
  const started = Date.now();
  const r = cli(['--base', 'HEAD', '--json']);
  const elapsed = Date.now() - started;
  expect(r.status, `stderr: ${r.stderr}`).toBe(0);
  expect(r.stderr).toBe('');
  const out = JSON.parse(r.stdout);
  expect(out.ok).toBe(true);
  expect(out.violations).toEqual([]);
  expect(out.flags).toEqual([]);
  expect(elapsed).toBeLessThan(10_000);
});
