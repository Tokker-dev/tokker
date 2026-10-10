import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, test } from 'vitest';

import {
  buildDocument,
  collectNumberLexemes,
  csvUsdColumns,
  offerUsd,
  serializeDocument,
  subscriptionUsd,
  updateCsvUsd,
} from './build.mjs';

function makeFx(overrides = {}) {
  return {
    base: 'USD',
    date: '2026-10-02',
    source: 'https://api.frankfurter.app/latest?from=USD',
    rates: { CHF: 0.82664, EUR: 0.89087, TST: 0.919 },
    ...overrides,
  };
}

let nextId = 0;
function makeOffer(overrides = {}) {
  nextId += 1;
  return {
    id: overrides.id ?? `prov${nextId}/test-model`,
    model_slug: 'test-model',
    currency: 'USD',
    input_per_mtok: 3,
    output_per_mtok: 15,
    cached_input_per_mtok: 0.3,
    cache_write_per_mtok: 3.75,
    ...overrides,
  };
}

function makePlan(overrides = {}) {
  nextId += 1;
  return {
    id: overrides.id ?? `vendor${nextId}/pro`,
    currency: 'USD',
    price_month: 20,
    price_year: 200,
    ...overrides,
  };
}

test('buildDocument recomputes usd blocks and stamps fx_rate_date on non-base rows only', () => {
  const doc = {
    fx: { base: 'USD', date: 'old', source: 'old', rates: {} },
    api_offers: [
      makeOffer(),
      makeOffer({ currency: 'CHF', input_per_mtok: 2, output_per_mtok: 8, cached_input_per_mtok: 0.04, cache_write_per_mtok: null }),
    ],
    subscriptions: [makePlan(), makePlan({ currency: 'CHF', price_month: 30, price_year: null })],
    derived: { cheapest_provider_per_model: {} },
  };
  buildDocument(doc, makeFx());

  expect(doc.api_offers[0].usd).toEqual({
    input_per_mtok: 3,
    output_per_mtok: 15,
    cached_input_per_mtok: 0.3,
    cache_write_per_mtok: 3.75,
    blended_3to1: 6,
  });
  expect(doc.api_offers[1].usd).toEqual({
    input_per_mtok: 2.41943, // 2 / 0.82664
    output_per_mtok: 9.67773,
    cached_input_per_mtok: 0.0483887,
    cache_write_per_mtok: null,
    fx_rate_date: '2026-10-02',
    blended_3to1: 4.23401, // (3*2 + 8) / 4 / 0.82664, unrounded blend
  });
  expect(doc.subscriptions[0].usd).toEqual({ price_month: 20, price_year: 200 });
  expect(doc.subscriptions[1].usd).toEqual({ price_month: 36.2915, fx_rate_date: '2026-10-02', price_year: null });
  expect(doc.fx).toEqual(makeFx());
  expect(doc.fx).not.toBe(makeFx()); // a copy, the caller's object is untouched
});

test('blended_3to1 converts the unrounded native blend, rounding once', () => {
  const row = makeOffer({ currency: 'TST', input_per_mtok: 1.1, output_per_mtok: 2.9 });
  // (3*1.1 + 2.9)/4 = 1.55 native; / 0.919 = 1.686616... -> 1.68662. Blending the
  // already-rounded usd values would give 1.68661.
  expect(offerUsd(row, makeFx()).blended_3to1).toBe(1.68662);
});

test('null and "unknown" natives stay null in usd; unknown input/output kill the blend', () => {
  const row = makeOffer({
    input_per_mtok: 'unknown',
    output_per_mtok: 'unknown',
    cached_input_per_mtok: 'unknown',
    cache_write_per_mtok: 'unknown',
  });
  expect(offerUsd(row, makeFx())).toEqual({
    input_per_mtok: null,
    output_per_mtok: null,
    cached_input_per_mtok: null,
    cache_write_per_mtok: null,
    blended_3to1: null,
  });
  expect(subscriptionUsd(makePlan({ price_month: 'unknown', price_year: null }), makeFx())).toEqual({
    price_month: null,
    price_year: null,
  });
});

test('an unsupported currency throws instead of guessing a rate', () => {
  expect(() => buildDocument({ api_offers: [makeOffer({ currency: 'XYZ' })], subscriptions: [] }, makeFx()))
    .toThrowError(/XYZ.*docs\/fx\.md/);
});

test('changing one rate in fx changes exactly the usd blocks of rows in that currency', () => {
  const makeDoc = () => ({
    api_offers: [
      makeOffer({ id: 'usd/test-model' }),
      makeOffer({ id: 'chf/test-model', currency: 'CHF' }),
      makeOffer({ id: 'eur/test-model', currency: 'EUR' }),
    ],
    subscriptions: [makePlan({ id: 'usd/pro' }), makePlan({ id: 'chf/pro', currency: 'CHF' })],
    derived: { cheapest_provider_per_model: {} },
  });
  const before = buildDocument(makeDoc(), makeFx());
  const after = buildDocument(makeDoc(), makeFx({ rates: { CHF: 0.8, EUR: 0.89087, TST: 0.919 } }));

  for (const row of [...before.api_offers, ...before.subscriptions]) {
    const changed = row.currency === 'CHF';
    const counterpart = [...after.api_offers, ...after.subscriptions].find((r) => r.id === row.id);
    expect(JSON.stringify(counterpart.usd) !== JSON.stringify(row.usd), row.id).toBe(changed);
  }
});

test('the derived cheapest-provider ranking follows the rebuilt blends', () => {
  const doc = {
    api_offers: [
      // tie on blend: the smaller row id wins
      makeOffer({ id: 'b-prov/m1', model_slug: 'm1' }),
      makeOffer({ id: 'a-prov/m1', model_slug: 'm1' }),
      // p2 wins on blend (6.00019 vs 6.1); rows without a blend never rank
      makeOffer({ id: 'p1/m2', model_slug: 'm2', input_per_mtok: 4.88, output_per_mtok: 9.76 }),
      makeOffer({ id: 'p2/m2', model_slug: 'm2', currency: 'CHF', input_per_mtok: 3.968, output_per_mtok: 7.936 }),
      makeOffer({ id: 'p3/m2', model_slug: 'm2', input_per_mtok: 'unknown', output_per_mtok: 'unknown' }),
      // two ranked rows but no derived entry yet: build adds one
      makeOffer({ id: 'q1/m3', model_slug: 'm3', input_per_mtok: 1, output_per_mtok: 1 }),
      makeOffer({ id: 'q2/m3', model_slug: 'm3', input_per_mtok: 2, output_per_mtok: 2 }),
      // a single-row model gets no entry
      makeOffer({ id: 'solo/m4', model_slug: 'm4' }),
    ],
    subscriptions: [],
    derived: {
      cheapest_provider_per_model: {
        m1: { offers: 1, cheapest_offer: 'stale/m1', blended_3to1_usd: 99 },
        m2: { offers: 9, cheapest_offer: 'stale/m2', blended_3to1_usd: 99 },
      },
    },
  };
  buildDocument(doc, makeFx());

  expect(doc.derived.cheapest_provider_per_model.m1).toEqual({
    offers: 2,
    cheapest_offer: 'a-prov/m1',
    blended_3to1_usd: 6,
  });
  expect(doc.derived.cheapest_provider_per_model.m2).toEqual({
    offers: 2,
    cheapest_offer: 'p2/m2',
    blended_3to1_usd: 6.00019, // 4.96 native blend / 0.82664
  });
  expect(doc.derived.cheapest_provider_per_model.m3).toEqual({
    offers: 2,
    cheapest_offer: 'q1/m3',
    blended_3to1_usd: 1,
  });
  expect(doc.derived.cheapest_provider_per_model.m4).toBeUndefined();

  // a rate move that flips the ranking moves the entry: p2's blend becomes
  // 4.96 / 0.8 = 6.2 and p1's 6.1 takes over
  buildDocument(doc, makeFx({ rates: { CHF: 0.8, EUR: 0.89087, TST: 0.919 } }));
  expect(doc.derived.cheapest_provider_per_model.m2).toEqual({
    offers: 2,
    cheapest_offer: 'p1/m2',
    blended_3to1_usd: 6.1,
  });
});

// --- acceptance over the committed dataset ---------------------------------

const repoPricing = JSON.parse(readFileSync(fileURLToPath(new URL('../data/pricing.json', import.meta.url)), 'utf-8'));
const repoFx = JSON.parse(readFileSync(fileURLToPath(new URL('../data/fx.json', import.meta.url)), 'utf-8'));

test('data: bumping one fx rate changes exactly that currency\'s rows, and nothing else', () => {
  const bumpedFx = JSON.parse(JSON.stringify(repoFx));
  bumpedFx.rates.CHF = 0.83;
  const before = buildDocument(JSON.parse(JSON.stringify(repoPricing)), repoFx);
  const after = buildDocument(JSON.parse(JSON.stringify(repoPricing)), bumpedFx);

  const chfRowIds = new Set(
    [...before.api_offers, ...before.subscriptions].filter((row) => row.currency === 'CHF').map((row) => row.id)
  );
  expect(chfRowIds.size).toBeGreaterThan(0);
  const changedIds = new Set();
  for (const [i, row] of before.api_offers.entries()) {
    if (JSON.stringify(row.usd) !== JSON.stringify(after.api_offers[i].usd)) changedIds.add(row.id);
  }
  for (const [i, row] of before.subscriptions.entries()) {
    if (JSON.stringify(row.usd) !== JSON.stringify(after.subscriptions[i].usd)) changedIds.add(row.id);
  }
  expect([...changedIds].sort()).toEqual([...chfRowIds].sort());

  // the ranking itself is untouched by this bump: same winners, same entry set
  expect(Object.keys(after.derived.cheapest_provider_per_model).sort()).toEqual(
    Object.keys(before.derived.cheapest_provider_per_model).sort()
  );
  for (const [slug, entry] of Object.entries(before.derived.cheapest_provider_per_model)) {
    expect(after.derived.cheapest_provider_per_model[slug].cheapest_offer).toBe(entry.cheapest_offer);
    expect(after.derived.cheapest_provider_per_model[slug].offers).toBe(entry.offers);
  }
});

// --- formatting: committed text stays byte-stable ---------------------------

test('serializeDocument round-trips the committed pricing.json byte for byte', () => {
  const text = readFileSync(fileURLToPath(new URL('../data/pricing.json', import.meta.url)), 'utf-8');
  const doc = JSON.parse(text);
  expect(serializeDocument(doc, collectNumberLexemes(text, doc))).toBe(text);
});

test('serializeDocument keeps unchanged numbers as written and prints changed ones plainly', () => {
  const text = '{\n  "a": 20.0,\n  "b": [\n    1.50,\n    2\n  ],\n  "c": "20.0"\n}';
  const doc = JSON.parse(text);
  const lexemes = collectNumberLexemes(text, doc);
  expect(serializeDocument(doc, lexemes)).toBe(text);

  const changed = JSON.parse(text);
  changed.a = 21;
  changed.b[0] = 3;
  expect(serializeDocument(changed, lexemes)).toBe('{\n  "a": 21,\n  "b": [\n    3,\n    2\n  ],\n  "c": "20.0"\n}');
});

// --- CSV exports -------------------------------------------------------------

const CSV = [
  'id,provider_name,currency,input_per_mtok,usd_input,usd_output,usd_cached_input,usd_blended_3to1,notes',
  'p/m1,Acme,USD,10,10.0,50.0,0.25,20.0,"plain, quoted"',
  'p/m2,Acme,CHF,2,2.41943,9.67773,0.0483887,4.23401,"say ""hi"""',
  'p/m3,Acme,USD,,,,,,"n/a, unknown"',
].join('\r\n');

test('updateCsvUsd changes only the usd cells of the named rows, byte for byte', () => {
  const updates = new Map([
    [
      'p/m2',
      csvUsdColumns('api', { usd: { input_per_mtok: 2.5, output_per_mtok: 9.67773, cached_input_per_mtok: 0.0483887, blended_3to1: null } }),
    ],
    [
      'p/m3',
      csvUsdColumns('api', { usd: { input_per_mtok: 12.5, output_per_mtok: null, cached_input_per_mtok: null, blended_3to1: 12.5 } }),
    ],
  ]);
  const out = updateCsvUsd(CSV, updates);
  expect(out).toBe(
    [
      'id,provider_name,currency,input_per_mtok,usd_input,usd_output,usd_cached_input,usd_blended_3to1,notes',
      'p/m1,Acme,USD,10,10.0,50.0,0.25,20.0,"plain, quoted"', // untouched row, untouched bytes
      'p/m2,Acme,CHF,2,2.5,9.67773,0.0483887,,"say ""hi"""', // null blends to an empty cell
      'p/m3,Acme,USD,,12.5,,,12.5,"n/a, unknown"',
    ].join('\r\n')
  );
});

test('updateCsvUsd keeps the written form of cells whose value did not change', () => {
  const updates = new Map([
    ['p/m1', csvUsdColumns('api', { usd: { input_per_mtok: 10, output_per_mtok: 50, cached_input_per_mtok: 0.25, blended_3to1: 25 } })],
  ]);
  const out = updateCsvUsd(CSV, updates);
  expect(out).toContain('p/m1,Acme,USD,10,10.0,50.0,0.25,25,'); // 10.0 kept, 25 printed plainly
});

test('updateCsvUsd writes a 0 over an empty cell (empty means null, not 0)', () => {
  const updates = new Map([
    ['p/m3', csvUsdColumns('api', { usd: { input_per_mtok: 0, output_per_mtok: null, cached_input_per_mtok: null, blended_3to1: 0 } })],
  ]);
  const out = updateCsvUsd(CSV, updates);
  expect(out).toContain('p/m3,Acme,USD,,0,,,0,');
});

test('updateCsvUsd without updates returns the text untouched, CRLF and all', () => {
  expect(updateCsvUsd(CSV, new Map())).toBe(CSV);
});

test('updateCsvUsd handles a file whose last line is CRLF-terminated', () => {
  const out = updateCsvUsd(CSV + '\r\n', new Map([['p/m2', csvUsdColumns('api', { usd: { input_per_mtok: 2.5, output_per_mtok: 9.67773, cached_input_per_mtok: 0.0483887, blended_3to1: null } })]]));
  expect(out.endsWith('"n/a, unknown"\r\n')).toBe(true); // trailing CRLF kept, no line lost
  expect(out).toContain('p/m2,Acme,CHF,2,2.5,9.67773,0.0483887,,');
});
