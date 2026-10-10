import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from 'vitest';
import {
  assembleDataset,
  computeCheapestProviderPerModel,
  deriveGeneratedAt,
  loadFragments,
  serializeJson,
  toCsvApi,
  toCsvSubscriptions,
} from './build.ts';
import { validateDocuments } from './validate.mjs';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const dataDir = join(repoRoot, 'data');
const readRepoFile = (relPath) => readFileSync(join(repoRoot, relPath), 'utf-8');

test('the committed generated files are byte-equal to a fresh build', () => {
  const doc = assembleDataset(loadFragments(dataDir));
  expect(serializeJson(doc)).toBe(readRepoFile('data/pricing.json'));
  expect(toCsvApi(doc.api_offers)).toBe(readRepoFile('data/pricing_api.csv'));
  expect(toCsvSubscriptions(doc.subscriptions)).toBe(readRepoFile('data/pricing_subscriptions.csv'));
});

test('building twice yields byte-identical output', () => {
  const first = serializeJson(assembleDataset(loadFragments(dataDir)));
  const second = serializeJson(assembleDataset(loadFragments(dataDir)));
  expect(first).toBe(second);
});

test('the assembled dataset passes schema validation with zero errors', () => {
  const doc = assembleDataset(loadFragments(dataDir));
  const schema = JSON.parse(readRepoFile('schema/pricing.v1.json'));
  expect(validateDocuments([{ file: 'data/pricing.json (assembled)', doc }], schema)).toEqual([]);
});

test('counts match the assembled arrays they are computed from', () => {
  const doc = assembleDataset(loadFragments(dataDir));
  expect(doc.counts).toEqual({
    api_providers: new Set(doc.api_offers.map((row) => row.provider_id)).size,
    api_offers: doc.api_offers.length,
    subscription_vendors: new Set(doc.subscriptions.map((row) => row.vendor_id)).size,
    subscriptions: doc.subscriptions.length,
    sources: doc.sources.length,
  });
});

test('generated_at is the max last_verified_at, date-only normalised to T00:00:00Z', () => {
  expect(deriveGeneratedAt([{ last_verified_at: '2026-10-05' }])).toBe('2026-10-05T00:00:00Z');
  expect(deriveGeneratedAt([{ last_verified_at: '2026-10-05' }, { last_verified_at: '2026-10-06T07:01:34Z' }])).toBe(
    '2026-10-06T07:01:34Z'
  );
  // a date-only value beats a full timestamp from the previous evening
  expect(deriveGeneratedAt([{ last_verified_at: '2026-10-05T23:00:00Z' }, { last_verified_at: '2026-10-06' }])).toBe(
    '2026-10-06T00:00:00Z'
  );

  const doc = assembleDataset(syntheticFragments([{ ...syntheticOffer(), last_verified_at: '2026-10-06' }]));
  expect(doc.generated_at).toBe('2026-10-06T00:00:00Z');
});

function syntheticOffer(overrides = {}) {
  return {
    id: 't/m',
    provider_id: 't',
    model_slug: 'm',
    usd: { blended_3to1: 6 },
    last_verified_at: '2026-10-05',
    ...overrides,
  };
}

function syntheticFragments(offers) {
  return {
    meta: {
      schema_version: '1.0.0',
      dataset: 'test',
      license: 'CC BY 4.0 (proposed)',
      conventions: {},
      research_notes: {},
    },
    fx: { base: 'USD', date: '2026-10-02', source: 'https://fx.example/latest?from=USD', rates: {} },
    providers: [],
    offers: [{ provider_id: 't', offers }],
    plans: [{ vendor_id: 't', plans: [] }],
    sources: [],
  };
}

function csvOffer() {
  return {
    id: 't/m',
    provider_id: 't',
    provider_name: 'T',
    provider_type: 'first_party',
    provider_country: 'US',
    model_slug: 'm',
    model_name: 'M',
    model_creator: 't',
    open_weights: true,
    currency: 'USD',
    input_per_mtok: 3,
    output_per_mtok: 15,
    cached_input_per_mtok: 0.3,
    cache_write_per_mtok: null,
    usd: {
      input_per_mtok: 3,
      output_per_mtok: 15,
      cached_input_per_mtok: 0.3,
      cache_write_per_mtok: 9, // dropped: no usd_cache_write column
      fx_rate_date: '2026-10-02', // dropped
      blended_3to1: 6,
    },
    batch_discount_pct: 'unknown',
    offpeak: null,
    tiered_pricing: null,
    context_window: 200000,
    max_output: 64000,
    free_tier: null,
    region_notes: null,
    fetch_recipe: {
      method: 'docs_markdown',
      endpoint: 'https://x.example/p, q',
      selector_hint: 'drop me', // dropped
      volatility: 'low',
    },
    source: 'https://x.example/p',
    checked: '2026-10-05',
    confidence: 'official_docs',
    notes: 'said "3"',
  };
}

test('toCsvApi emits the exact header, CRLF endings and flattened cells', () => {
  const csv = toCsvApi([csvOffer()]);
  expect(csv.endsWith('\r\n')).toBe(true);
  const lines = csv.split('\r\n');
  expect(lines).toHaveLength(3); // header, one row, empty tail after the final CRLF
  expect(lines[0]).toBe(
    'id,provider_id,provider_name,provider_type,provider_country,model_slug,model_name,model_creator,' +
      'open_weights,currency,input_per_mtok,output_per_mtok,cached_input_per_mtok,cache_write_per_mtok,' +
      'usd_input,usd_output,usd_cached_input,usd_blended_3to1,batch_discount_pct,offpeak,tiered_pricing,' +
      'context_window,max_output,free_tier,region_notes,fetch_method,fetch_endpoint,volatility,source,' +
      'checked,confidence,notes'
  );
  expect(lines[1]).toBe(
    't/m,t,T,first_party,US,m,M,t,True,USD,3,15,0.3,,3,15,0.3,6,unknown,,,200000,64000,,,docs_markdown,' +
      '"https://x.example/p, q",low,https://x.example/p,2026-10-05,official_docs,"said ""3"""'
  );
  expect(lines[2]).toBe('');
  // the documented drops stay dropped
  expect(lines[1]).not.toContain('9');
  expect(lines[1]).not.toContain('fx_rate_date');
  expect(lines[1]).not.toContain('drop me');
});

function csvPlan() {
  return {
    id: 't/pro',
    vendor_id: 't',
    vendor_name: 'T',
    product: 'P',
    plan_name: 'Pro',
    category: 'chat',
    currency: 'USD',
    price_month: 20,
    price_year: 200,
    usd: { price_month: 20, price_year: 200 },
    models_included: ['a', 'b'],
    limits_published: [
      { window: '5h_rolling', unit: 'tokens', amount: 'unknown', quote: 'usage caps, apply' },
      { window: 'monthly', unit: 'requests', amount: 100, quote: 'no hard cap' },
    ],
    fair_use: null,
    est_tokens_per_month: 300000000,
    est_usd_per_mtok_at_full_use: 0.07,
    estimate_assumption: 'standard',
    fetch_recipe: {
      method: 'html_static',
      endpoint: 'https://x.example/plans-endpoint', // dropped: no fetch_endpoint column
      selector_hint: 'drop me',
      volatility: 'low',
    },
    source: 'https://x.example/plans-page',
    checked: '2026-10-05',
    confidence: 'official_page',
    notes: null,
  };
}

test('toCsvSubscriptions emits the exact header, joins models and renders limits', () => {
  const csv = toCsvSubscriptions([csvPlan()]);
  expect(csv.endsWith('\r\n')).toBe(true);
  const lines = csv.split('\r\n');
  expect(lines).toHaveLength(3);
  expect(lines[0]).toBe(
    'id,vendor_id,vendor_name,product,plan_name,category,currency,price_month,price_year,usd_price_month,' +
      'models_included,limits_published,fair_use,est_tokens_per_month,est_usd_per_mtok_at_full_use,' +
      'estimate_assumption,fetch_method,volatility,source,checked,confidence,notes'
  );
  expect(lines[1]).toBe(
    't/pro,t,T,P,Pro,chat,USD,20,200,20,a; b,' +
      '"5h_rolling:unknown tokens (""usage caps, apply"") | monthly:100 requests (""no hard cap"")",' +
      ',300000000,0.07,standard,html_static,low,https://x.example/plans-page,2026-10-05,official_page,'
  );
  expect(lines[2]).toBe('');
  expect(lines[1]).not.toContain('plans-endpoint');
  expect(lines[1]).not.toContain('drop me');
});

test('derived: >=2 numeric rows per model, min blended wins, ties by smallest id, keys sorted', () => {
  const offers = [
    syntheticOffer({ id: 'p/a', model_slug: 'a', usd: { blended_3to1: 2 } }),
    syntheticOffer({ id: 'q/a', model_slug: 'a', usd: { blended_3to1: 1 } }),
    syntheticOffer({ id: 'b/m', model_slug: 'm', usd: { blended_3to1: 6 } }),
    syntheticOffer({ id: 'c/m', model_slug: 'm', usd: { blended_3to1: 4 } }),
    syntheticOffer({ id: 'd/m', model_slug: 'm', usd: { blended_3to1: 4 } }), // tie with c: c wins
    syntheticOffer({ id: 'e/m', model_slug: 'm', usd: { blended_3to1: 'unknown' } }), // not rankable
    syntheticOffer({ id: 'f/m', model_slug: 'm', usd: { blended_3to1: null } }), // not rankable
    syntheticOffer({ id: 'g/solo', model_slug: 'solo', usd: { blended_3to1: 1 } }), // one rankable row
    syntheticOffer({ id: 'h/nu', model_slug: 'nu', usd: null }), // nothing rankable
  ];

  const derived = computeCheapestProviderPerModel(offers);
  expect(derived).toEqual({
    a: { offers: 2, cheapest_offer: 'q/a', blended_3to1_usd: 1 },
    m: { offers: 3, cheapest_offer: 'c/m', blended_3to1_usd: 4 },
  });
  expect(Object.keys(derived)).toEqual(['a', 'm']); // sorted; solo/nu groups dropped

  // the same rule through the public entry point
  const doc = assembleDataset(syntheticFragments(offers));
  expect(doc.derived).toEqual({ cheapest_provider_per_model: derived });
});
