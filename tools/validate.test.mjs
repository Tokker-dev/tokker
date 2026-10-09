import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, expect, test } from 'vitest';
import {
  ESTIMATE_PROFILES,
  formatError,
  pointerToJsonPath,
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

test('data/pricing.json passes via the CLI (explicit and default file)', () => {
  for (const args of [['data/pricing.json'], []]) {
    const r = spawnSync(process.execPath, ['tools/validate.mjs', ...args], {
      cwd: repoRoot,
      encoding: 'utf-8',
    });
    expect(r.status, `stderr: ${r.stderr}`).toBe(0);
    expect(r.stdout.trim()).toBe('ok data/pricing.json');
  }
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
