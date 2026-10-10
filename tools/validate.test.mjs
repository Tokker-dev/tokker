import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, expect, test } from 'vitest';
import {
  ESTIMATE_PROFILES,
  formatError,
  pointerToJsonPath,
  run,
  validateDocuments,
} from './validate.mjs';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const tmpDir = mkdtempSync(join(tmpdir(), 'tokker-validate-test-'));

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function recipe() {
  return {
    method: 'docs_markdown',
    endpoint: 'https://testco.example/pricing.md',
    selector_hint: "table under '## Pricing'",
    volatility: 'low',
  };
}

function makeOffer() {
  return {
    id: 'testco/test-model',
    provider_id: 'testco',
    provider_name: 'TestCo',
    provider_type: 'first_party',
    provider_country: 'US',
    model_slug: 'test-model',
    model_name: 'Test Model',
    model_creator: 'testco',
    open_weights: false,
    currency: 'USD',
    input_per_mtok: 3,
    output_per_mtok: 15,
    cached_input_per_mtok: 0.3,
    cache_write_per_mtok: 3.75,
    batch_discount_pct: 50,
    offpeak: null,
    tiered_pricing: null,
    context_window: 200000,
    max_output: 64000,
    free_tier: null,
    region_notes: null,
    source: 'https://testco.example/pricing',
    checked: '2026-10-05',
    confidence: 'official_docs',
    notes: null,
    fetch_recipe: recipe(),
    usd: {
      input_per_mtok: 3,
      output_per_mtok: 15,
      cached_input_per_mtok: 0.3,
      cache_write_per_mtok: 3.75,
      blended_3to1: 6,
    },
    last_verified_at: '2026-10-05',
    provenance: {
      default: {
        source: 'https://testco.example/pricing',
        fetched_at: '2026-10-05',
        method: 'docs_markdown',
        confidence: 'official_docs',
      },
      fields: { input_per_mtok: 'default' },
    },
  };
}

function makePlan() {
  return {
    id: 'testco/pro',
    vendor_id: 'testco',
    vendor_name: 'TestCo',
    product: 'TestBot',
    plan_name: 'Pro',
    category: 'chat',
    currency: 'USD',
    price_month: 20,
    price_year: 200,
    models_included: ['test-model'],
    limits_published: [
      { window: '5h_rolling', unit: 'tokens', amount: 'unknown', quote: 'usage caps apply' },
    ],
    fair_use: null,
    est_tokens_per_month: 300000000,
    est_usd_per_mtok_at_full_use: 0.07,
    estimate_assumption: 'STANDARD: 120 windows/month x 21,500 tokens/window.',
    source: 'https://testco.example/plans',
    checked: '2026-10-05',
    confidence: 'official_page',
    notes: null,
    fetch_recipe: recipe(),
    usd: { price_month: 20, price_year: 200 },
    last_verified_at: '2026-10-05',
    provenance: {
      default: {
        source: 'https://testco.example/plans',
        fetched_at: '2026-10-05',
        method: 'html_static',
        confidence: 'official_page',
      },
      fields: { price_month: 'default' },
    },
  };
}

function makeDoc() {
  return {
    schema_version: '1.0.0',
    dataset: 'test',
    generated_at: '2026-10-05T07:01:34Z',
    license: 'CC BY 4.0 (proposed)',
    conventions: { unknown: "string 'unknown' = not published; null = not applicable" },
    fx: {
      base: 'USD',
      date: '2026-10-02',
      source: 'https://api.frankfurter.app/latest?from=USD',
      rates: { EUR: 0.89, JPY: 157.67 },
    },
    counts: { api_providers: 1, api_offers: 1, subscription_vendors: 1, subscriptions: 1, sources: 1 },
    providers: [
      { id: 'testco', name: 'TestCo', type: 'first_party', country: 'US', api_offer_count: 1, subscription_count: 1 },
    ],
    api_offers: [makeOffer()],
    subscriptions: [makePlan()],
    derived: {
      cheapest_provider_per_model: {
        'test-model': { offers: 1, cheapest_offer: 'testco/test-model', blended_3to1_usd: 6 },
      },
    },
    sources: [
      {
        provider_id: 'testco',
        url: 'https://testco.example/pricing',
        fetch_recipe: recipe(),
        fetch_ok: true,
        notes: 'primary pricing source',
        part: 'api_western.json',
      },
    ],
    research_notes: { 'api_western.json': 'checked 2026-10-05' },
  };
}

function errorsOf(doc) {
  return validateDocuments([{ file: 'fixture.json', doc }]);
}

test('the valid fixture passes', () => {
  expect(errorsOf(makeDoc())).toEqual([]);
});

test('data/pricing.json passes via the CLI (explicit file)', () => {
  const r = spawnSync(process.execPath, ['tools/validate.mjs', 'data/pricing.json'], {
    cwd: repoRoot,
    encoding: 'utf-8',
  });
  expect(r.status, `stderr: ${r.stderr}`).toBe(0);
  expect(r.stdout.trim()).toBe('ok data/pricing.json');
});

test('a named shard passes via the CLI and prints only that file', () => {
  const r = spawnSync(process.execPath, ['tools/validate.mjs', 'data/offers/anthropic.json'], {
    cwd: repoRoot,
    encoding: 'utf-8',
  });
  expect(r.status, `stderr: ${r.stderr}`).toBe(0);
  expect(r.stdout.trim()).toBe('ok data/offers/anthropic.json');
});

test('the default invocation validates every fragment plus the generated document', () => {
  const fragments = [
    ...readdirSync(join(repoRoot, 'data/offers'))
      .filter((name) => name.endsWith('.json'))
      .map((name) => `data/offers/${name}`),
    ...readdirSync(join(repoRoot, 'data/plans'))
      .filter((name) => name.endsWith('.json'))
      .map((name) => `data/plans/${name}`),
    'data/fx.json',
    'data/meta.json',
    'data/providers.json',
    'data/sources.json',
  ].sort();
  const expected = [...fragments, 'data/pricing.json'];

  const r = spawnSync(process.execPath, ['tools/validate.mjs'], {
    cwd: repoRoot,
    encoding: 'utf-8',
  });
  expect(r.status, `stderr: ${r.stderr}`).toBe(0);
  expect(r.stdout.trim().split('\n')).toEqual(expected.map((file) => `ok ${file}`));
});

test('a number and the string "unknown" both pass where number|"unknown" is allowed', () => {
  const withNumber = makeDoc();
  withNumber.api_offers[0].input_per_mtok = 3;
  expect(errorsOf(withNumber)).toEqual([]);

  const withUnknown = makeDoc();
  withUnknown.api_offers[0].input_per_mtok = 'unknown';
  expect(errorsOf(withUnknown)).toEqual([]);
});

test('a missing provenance fails and names the row path', () => {
  const doc = makeDoc();
  delete doc.api_offers[0].provenance;
  const errors = errorsOf(doc);
  expect(errors.length).toBeGreaterThan(0);
  const hit = errors.find((e) => e.path === '$.api_offers[0].provenance');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("required property 'provenance' is missing");
});

test('a duplicate id fails and names the path of the duplicate', () => {
  const doc = makeDoc();
  doc.subscriptions[0].id = doc.api_offers[0].id;
  const errors = errorsOf(doc);
  const hit = errors.find((e) => e.path === '$.subscriptions[0].id');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("duplicate row id 'testco/test-model'");
  expect(hit.message).toContain('first occurrence at fixture.json $.api_offers[0].id');
});

test('a duplicate id across two files points at the second file', () => {
  const first = makeDoc();
  const second = makeDoc();
  second.subscriptions[0].id = first.api_offers[0].id;
  const errors = validateDocuments([
    { file: 'a.json', doc: first },
    { file: 'b.json', doc: second },
  ]);
  const hit = errors.find((e) => e.file === 'b.json' && e.path === '$.subscriptions[0].id');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("duplicate row id 'testco/test-model'");
  expect(hit.message).toContain('first occurrence at a.json $.api_offers[0].id');
});

test('a bad enum fails and names its path', () => {
  const doc = makeDoc();
  doc.providers[0].type = 'reseller';
  const errors = errorsOf(doc);
  const hit = errors.find((e) => e.path === '$.providers[0].type');
  expect(hit).toBeDefined();
  expect(hit.message).toContain('"first_party"');
});

test('a fetch_recipe without (or with a blank) endpoint fails', () => {
  const missing = makeDoc();
  delete missing.api_offers[0].fetch_recipe.endpoint;
  const schemaHit = errorsOf(missing).find(
    (e) => e.path === '$.api_offers[0].fetch_recipe.endpoint'
  );
  expect(schemaHit).toBeDefined();
  expect(schemaHit.message).toContain("required property 'endpoint' is missing");

  const blank = makeDoc();
  blank.subscriptions[0].fetch_recipe.endpoint = '   ';
  const checkHit = errorsOf(blank).find(
    (e) => e.path === '$.subscriptions[0].fetch_recipe.endpoint'
  );
  expect(checkHit).toBeDefined();
  expect(checkHit.message).toContain('\\S');
});

test('a numeric estimate without an assumption profile fails', () => {
  const doc = makeDoc();
  doc.subscriptions[0].estimate_assumption = 'trust me';
  const errors = errorsOf(doc);
  const hit = errors.find((e) => e.path === '$.subscriptions[0].estimate_assumption');
  expect(hit).toBeDefined();
  for (const profile of ESTIMATE_PROFILES) expect(hit.message).toContain(profile);
});

test('errors format as file:jsonpath: message', () => {
  const doc = makeDoc();
  delete doc.api_offers[0].provenance;
  const [error] = errorsOf(doc);
  expect(formatError(error)).toBe(`${error.file}:${error.path}: ${error.message}`);
  expect(formatError(error)).toContain('fixture.json:$.api_offers[0].provenance:');
});

test('an unreadable or invalid JSON file is reported as file:$: and exits 1', () => {
  const bad = join(tmpDir, 'bad.json');
  writeFileSync(bad, '{nope');
  const r = spawnSync(process.execPath, ['tools/validate.mjs', bad], {
    cwd: repoRoot,
    encoding: 'utf-8',
  });
  expect(r.status).toBe(1);
  expect(r.stderr).toContain(`${bad}:$:`);
});

test('pointerToJsonPath renders array indexes, identifiers and odd keys', () => {
  expect(pointerToJsonPath('')).toBe('$');
  expect(pointerToJsonPath('/api_offers/12/provenance/default')).toBe(
    '$.api_offers[12].provenance.default'
  );
  expect(pointerToJsonPath('/weird key')).toBe('$["weird key"]');
});

// -- fragment validation (files classified by their data/ path) --------------

const canonicalText = (doc) => JSON.stringify(doc, null, 2) + '\n';

/** Write a file under the tmp data dir laid out like data/, return its path. */
function writeFragment(relPath, text) {
  const path = join(tmpDir, relPath);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  return path;
}

/** Run the validator in-process on paths; capture output. */
function runTool(paths) {
  const logs = [];
  const errs = [];
  const code = run(paths, { log: (line) => logs.push(line), error: (line) => errs.push(line) });
  return { code, logs, errs: errs.join('\n') };
}

function offerShard(providerId = 'testco', mutateRow = (row) => row) {
  return { provider_id: providerId, offers: [mutateRow(makeOffer())] };
}

function planShard() {
  return { vendor_id: 'testco', plans: [makePlan()] };
}

test('an unsorted offers shard fails at the offending row', () => {
  const shard = offerShard('testco', (row) => row);
  shard.offers.push({ ...makeOffer(), id: 'testco/aaa-model', model_slug: 'aaa-model' });
  const path = writeFragment('data/offers/testco.json', canonicalText(shard));
  const { code, errs } = runTool([path]);
  expect(code).toBe(1);
  expect(errs).toContain(
    `${path}:$.offers[1].id: ids must be strictly ascending (sorted, unique): ` +
      `'testco/aaa-model' does not follow 'testco/test-model'`
  );
});

test('a shard whose provider_id disagrees with the file name or its rows fails', () => {
  const wrongWrapper = writeFragment(
    'data/offers/testco.json',
    canonicalText({ provider_id: 'other', offers: [] })
  );
  const wrongRow = writeFragment(
    'data/offers/testco2.json',
    canonicalText(offerShard('testco2', (row) => ({ ...row, provider_id: 'testco' })))
  );
  const { code, errs } = runTool([wrongWrapper, wrongRow]);
  expect(code).toBe(1);
  expect(errs).toContain(`${wrongWrapper}:$.provider_id: 'other' does not match the file name 'testco'`);
  expect(errs).toContain(
    `${wrongRow}:$.offers[0].provider_id: 'testco' does not match the fragment provider_id 'testco2'`
  );
});

test('a duplicate id across two offer shards is caught across the pool', () => {
  const first = writeFragment('data/offers/testco.json', canonicalText(offerShard()));
  const second = writeFragment(
    'data/offers/testco2.json',
    canonicalText(offerShard('testco2', (row) => ({ ...row, provider_id: 'testco2' })))
  );
  const { code, errs } = runTool([first, second]);
  expect(code).toBe(1);
  expect(errs).toContain(
    `${second}:$.offers[0].id: duplicate row id 'testco/test-model' (first occurrence at ${first} $.offers[0].id)`
  );
});

test('a fragment with non-canonical formatting fails (missing newline, 4-space indent)', () => {
  const noNewline = writeFragment('data/offers/testco.json', JSON.stringify(offerShard(), null, 2));
  const wideIndent = writeFragment(
    'data/offers/testco2.json',
    JSON.stringify(offerShard('testco2', (row) => ({ ...row, provider_id: 'testco2', id: 'testco2/test-model' })), null, 4) + '\n'
  );
  const { code, errs } = runTool([noNewline, wideIndent]);
  expect(code).toBe(1);
  expect(errs).toContain(`${noNewline}:$: file is not in canonical form`);
  expect(errs).toContain(`${wideIndent}:$: file is not in canonical form`);
});

test('a bad row inside a shard is reported under the shard path and array name', () => {
  const shard = offerShard();
  delete shard.offers[0].provenance;
  const path = writeFragment('data/offers/testco.json', canonicalText(shard));
  const { code, errs } = runTool([path]);
  expect(code).toBe(1);
  expect(errs).toContain(
    `${path}:$.offers[0].provenance: required property 'provenance' is missing`
  );
});

test('a duplicate (provider_id, part, url) in sources.json fails', () => {
  const source = makeDoc().sources[0];
  const path = writeFragment('data/sources.json', canonicalText([source, { ...source }]));
  const { code, errs } = runTool([path]);
  expect(code).toBe(1);
  expect(errs).toContain(
    `${path}:$[1]: duplicate source (provider_id, part, url) ('testco', 'api_western.json', 'https://testco.example/pricing'); first occurrence at $[0]`
  );
});

test('an unsorted providers.json fails', () => {
  const provider = makeDoc().providers[0];
  const path = writeFragment(
    'data/providers.json',
    canonicalText([provider, { ...provider, id: 'aaa', name: 'AAA' }])
  );
  const { code, errs } = runTool([path]);
  expect(code).toBe(1);
  expect(errs).toContain(
    `${path}:$[1].id: ids must be strictly ascending (sorted, unique): 'aaa' does not follow 'testco'`
  );
});

test('a meta.json with a bad research_notes key fails', () => {
  const meta = {
    schema_version: '1.0.0',
    dataset: 'test',
    license: 'CC BY 4.0 (proposed)',
    conventions: {},
    research_notes: { '/bad key!': 'notes' },
  };
  const path = writeFragment('data/meta.json', canonicalText(meta));
  const { code, errs } = runTool([path]);
  expect(code).toBe(1);
  expect(errs).toContain(
    `${path}:$.research_notes: must be a string matching ^[A-Za-z0-9][A-Za-z0-9._-]*$`
  );
});

test('a plans shard row with a numeric estimate and no profile fails under $.plans', () => {
  const shard = planShard();
  shard.plans[0].estimate_assumption = 'trust me';
  const path = writeFragment('data/plans/testco.json', canonicalText(shard));
  const { code, errs } = runTool([path]);
  expect(code).toBe(1);
  expect(errs).toContain(`${path}:$.plans[0].estimate_assumption: a numeric est_tokens_per_month/`);
});

test('a valid fragment set passes in one pool and prints each file', () => {
  const doc = makeDoc();
  const paths = [
    writeFragment('data/offers/testco.json', canonicalText(offerShard())),
    writeFragment('data/plans/testco.json', canonicalText(planShard())),
    writeFragment('data/providers.json', canonicalText(doc.providers)),
    writeFragment('data/sources.json', canonicalText(doc.sources)),
    writeFragment('data/fx.json', canonicalText(doc.fx)),
    writeFragment(
      'data/meta.json',
      canonicalText({
        schema_version: doc.schema_version,
        dataset: doc.dataset,
        license: doc.license,
        conventions: doc.conventions,
        research_notes: doc.research_notes,
      })
    ),
  ];
  const { code, logs, errs } = runTool(paths);
  expect(errs).toBe('');
  expect(code).toBe(0);
  expect(logs).toEqual(paths.map((p) => `ok ${p}`));
});
