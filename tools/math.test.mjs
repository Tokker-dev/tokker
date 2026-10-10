// Tests for tools/math.ts (issue #13, subscription token math):
//  a. runs the shared vectors in tests/vectors/token-math.json against
//     data/profiles/*.json,
//  b. drift-checks every data/pricing.json subscription row against a fresh
//     enrichSubscriptionRow computation,
//  c. proves the build's write path (rows + binding_window) still validates
//     against schema/pricing.v1.json, without writing any data file,
//  d. sanity-checks every data/profiles/*.json.

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { expect, test } from 'vitest';
import {
  enrichSubscriptionRow,
  estimateForPlan,
  profileCostPerCall,
  usdPriceMonthly,
} from './math.ts';

const readJson = (rel) => JSON.parse(readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf-8'));

const pricing = readJson('../data/pricing.json');
const fx = pricing.fx;
const profile = (name) => readJson(`../data/profiles/${name}.json`);

/** Number: exact, or within 1e-9 (vectors may print fewer digits). Strings/null: literal. */
function expectMatches(actual, expected, label) {
  if (typeof expected === 'number') {
    const ok =
      typeof actual === 'number' && (actual === expected || Math.abs(actual - expected) <= 1e-9);
    expect(ok, `${label}: computed ${actual} vs expected ${expected}`).toBe(true);
  } else {
    expect(actual, `${label}: computed ${String(actual)} vs expected ${String(expected)}`).toBe(
      expected
    );
  }
}

// --- a. shared vectors ----------------------------------------------------

const vectors = readJson('../tests/vectors/token-math.json').vectors;
expect(Array.isArray(vectors) && vectors.length > 0).toBe(true);

for (const v of vectors) {
  test(`vector: ${v.name}`, () => {
    const got = estimateForPlan(v.plan, profile(v.profile));
    const want = v.expected;
    expectMatches(got.tokensPerWindow, want.tokens_per_window, 'tokens_per_window');
    expectMatches(got.tokensPerWeek, want.tokens_per_week, 'tokens_per_week');
    expectMatches(got.estTokensPerMonth, want.est_tokens_per_month, 'est_tokens_per_month');
    expectMatches(got.bindingWindow, want.binding_window, 'binding_window');
    expectMatches(
      got.estUsdPerMtokAtFullUse,
      want.est_usd_per_mtok_at_full_use,
      'est_usd_per_mtok_at_full_use'
    );
  });
}

// --- b. drift check against the real dataset ------------------------------

// Vendor unit conversions, keyed by vendor_id. Sources:
// - zai: every zai row's per_request limit quotes the GLM-5.3 multipliers
//   "6.9 / 1.7 / 24" over 10,000: (2000x6.9 + 18000x1.7 + 1500x24)/10,000 = 8.04
//   credits per standard agentic-coding-v1 call.
// - github: the rows' assumption quotes GitHub's docs (models-and-pricing):
//   "Copilot bills GitHub AI Credits (1 credit = $0.01)".
const VENDOR_CONVERSIONS = {
  zai: {
    credits_per_call: 8.04,
    source: 'zai rows per_request quote: GLM-5.3 multipliers 6.9/1.7/24 over 10,000',
  },
  github: { usd_per_credit: 0.01, source: 'github rows: 1 AI Credit = $0.01 (docs models-and-pricing)' },
};

// Rows whose committed values come from non-mechanical derivations, documented
// in their estimate_assumption strings. The mechanical formula deliberately
// does not reproduce them; each id is pinned (the test asserts it exists).
const KNOWN_EXCEPTIONS = {
  // Secondary finopsllm measurement factor (assumption: "SECONDARY measurements
  // (finopsllm.com ...) into the standard mix by API-dollar equivalence").
  'anthropic/pro': 'secondary finopsllm factor, weekly cap unpublished',
  'anthropic/max-5x': 'secondary finopsllm factor',
  'anthropic/max-20x': 'secondary finopsllm factor',
  // Midpoints/multiples of published ranges (assumption: "midpoint of published
  // GPT-6.1 Sol range (15-160 -> 87.5 local messages/5h)").
  'openai/plus': 'published-range midpoint (87.5 messages/5h)',
  'openai/pro-100': 'secondary multiple of the plus midpoint',
  'openai/pro-200': 'secondary multiple of the plus midpoint',
  'openai/pro-500': 'secondary multiple of the plus midpoint',
  'openai/business': 'published-range midpoint (87.5 messages/5h)',
  // Assumption: "Includes 10% markup" (overage at API list price +10%).
  'zed/pro': '10% markup on the dollar pool',
  // Assumption: "4 usable windows/day x $0.40 + $4 overage = $52 API value/month"
  // (window is "unspecified"/4h, not one of the volume windows).
  't3chat/pro': '4h dollar-window + overage text',
  // Row-level confidence flag is "secondary" but the caps themselves come from
  // Z.AI's / BytePlus's official docs (the vectors use official confidence);
  // the confidence flag needs owner review. Flagged in tests/vectors too.
  'zai/pro': 'secondary row flag; caps official (needs owner review)',
  'zai/max': 'secondary row flag; caps official (needs owner review)',
  'byteplus/lite': 'secondary row flag; caps official (needs owner review)',
  // Committed "unknown" by documented judgement while the mechanical rule would
  // compute a number; the rows' own estimate_assumption/notes document why.
  // Found by this drift check's first run and reported to the issue owner.
  'github/free': 'assumption "unknown: vendor publishes no absolute quota" (computed would be 43000000 from 2,000 completions/month)',
  'replit/core': 'assumption "unknown: vendor publishes no absolute quota"; notes: effort-based checkpoints (computed would be 19026549)',
  'replit/pro': 'assumption "unknown: vendor publishes no absolute quota"; notes: effort-based checkpoints (computed would be 95132743)',
  'featherless/developer': 'assumption: credits never expire, billed per token -> no monthly cap (computed would be 47566372)',
  'openrouter/pay-as-you-go-credits-no-subscription': 'assumption: no subscription, list price x 1.055 fee (computed would be 32250000 from the free-model daily cap)',
  'byteplus/pro': 'assumption: "5x Lite estimate" (a relative multiple, not a cap); secondary row flag',
};

test('every subscription row agrees with a fresh computation (or is a known exception)', () => {
  const agentic = profile('agentic-coding-v1');
  const ids = new Set(pricing.subscriptions.map((r) => r.id));

  // Exception ids stay pinned: each must actually exist in the dataset.
  for (const [id, why] of Object.entries(KNOWN_EXCEPTIONS)) {
    expect(ids.has(id), `known-exception id not in dataset: ${id} (${why})`).toBe(true);
  }

  const buckets = { computable: [], unknown_agrees: [], exceptions: [] };
  const unbucketed = [];

  for (const row of pricing.subscriptions) {
    const computed = enrichSubscriptionRow(row, agentic, VENDOR_CONVERSIONS, fx);
    const committedTok = row.est_tokens_per_month;
    const committedUsd = row.est_usd_per_mtok_at_full_use;

    if (KNOWN_EXCEPTIONS[row.id] !== undefined) {
      buckets.exceptions.push(row.id);
      continue;
    }

    if (computed.estTokensPerMonth === 'unknown') {
      // UNKNOWN-AGREES: nothing is derivable; the committed row must say so too.
      if (committedTok === 'unknown') buckets.unknown_agrees.push(row.id);
      else
        unbucketed.push(
          `${row.id}: computed unknown but committed est_tokens_per_month=${String(committedTok)}`
        );
      continue;
    }

    // COMPUTABLE: the committed numbers must equal the fresh computation.
    if (committedTok === computed.estTokensPerMonth && committedUsd === computed.estUsdPerMtokAtFullUse) {
      buckets.computable.push(row.id);
    } else {
      unbucketed.push(
        `${row.id}: computed est=${computed.estTokensPerMonth} usd=${computed.estUsdPerMtokAtFullUse} ` +
          `binding=${computed.bindingWindow} vs committed est=${String(committedTok)} usd=${String(committedUsd)}`
      );
    }
  }

  // A row that fits no bucket is dataset drift: surface it, never widen the
  // exception list silently.
  expect(
    unbucketed,
    `${unbucketed.length} subscription row(s) fit no bucket:\n  ${unbucketed.join('\n  ')}`
  ).toEqual([]);

  console.log(
    `token-math drift: ${buckets.computable.length} computable, ` +
      `${buckets.unknown_agrees.length} unknown-agrees, ${buckets.exceptions.length} known exceptions ` +
      `(of ${pricing.subscriptions.length} rows)`
  );
  expect(buckets.computable.length + buckets.unknown_agrees.length + buckets.exceptions.length).toBe(
    pricing.subscriptions.length
  );
});

// --- c. schema validation of the write path --------------------------------

test('an enriched copy carrying binding_window validates against schema/pricing.v1.json', () => {
  const schema = readJson('../schema/pricing.v1.json');
  const agentic = profile('agentic-coding-v1');
  const doc = structuredClone(pricing);

  for (const row of doc.subscriptions) {
    row.binding_window = enrichSubscriptionRow(row, agentic, VENDOR_CONVERSIONS, fx).bindingWindow;
  }

  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const validate = ajv.compile(schema);
  expect(validate(doc), JSON.stringify(validate.errors?.slice(0, 3))).toBe(true);

  // The schema change is additive: the untouched dataset validates unchanged.
  expect(ajv.validate(schema, pricing)).toBe(true);
});

// --- d. profile sanity ------------------------------------------------------

test('every data/profiles/*.json parses and is internally consistent', () => {
  const dir = fileURLToPath(new URL('../data/profiles/', import.meta.url));
  const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThan(0);

  for (const f of files) {
    const p = readJson(`../data/profiles/${f}`);
    expect(
      p.call.tokens_per_call,
      `${f}: tokens_per_call != input + output`
    ).toBe(p.call.input_tokens + p.call.output_tokens);
    expect(
      p.call.cached_input_tokens <= p.call.input_tokens,
      `${f}: cached_input_tokens > input_tokens`
    ).toBe(true);
    for (const key of ['five_hour_windows_per_day', 'days_per_week', 'days_per_month']) {
      expect(p.windows[key], `${f}: ${key} must be positive`).toBeGreaterThan(0);
    }
  }

  // The dataset's committed estimates and the drift check above depend on this one.
  expect(files).toContain('agentic-coding-v1.json');
});

// --- focused unit tests for the library's own invariants -------------------

test('profileCostPerCall: agentic-coding-v1 K = 0.0226 and the shape checks fire', () => {
  const agentic = profile('agentic-coding-v1');
  // (2000*2 + 18000*0.2 + 1500*10) / 1e6
  expect(profileCostPerCall(agentic)).toBeCloseTo(0.0226, 12);

  const badTokens = structuredClone(agentic);
  badTokens.call.tokens_per_call = 1;
  expect(() => profileCostPerCall(badTokens)).toThrow(/tokens_per_call/);

  const badCache = structuredClone(agentic);
  badCache.call.cached_input_tokens = badCache.call.input_tokens + 1;
  expect(() => profileCostPerCall(badCache)).toThrow(/cached_input_tokens/);
});

test('usdPriceMonthly: usd block, then native USD, then fx division, else unknown', () => {
  expect(usdPriceMonthly({ usd: { price_month: 10 } }, fx)).toBe(10);
  expect(
    usdPriceMonthly({ usd: { price_month: null }, price_month: 20, currency: 'USD' }, fx)
  ).toBe(20);
  // fx rates are one USD in the target currency: 8.9087 EUR / 0.89087 = 10 USD.
  expect(
    usdPriceMonthly({ usd: { price_month: null }, price_month: 8.9087, currency: 'EUR' }, fx)
  ).toBeCloseTo(10, 9);
  expect(usdPriceMonthly({ price_month: 'unknown', currency: 'USD' }, fx)).toBe('unknown');
  expect(usdPriceMonthly({ price_month: 100, currency: 'XXX' }, fx)).toBe('unknown');
  expect(usdPriceMonthly({}, fx)).toBe('unknown');
});

test('exact ties on the monthly candidate prefer the coarser window', () => {
  const agentic = profile('agentic-coding-v1');
  // weekly 3500 -> (3500*30)/7 = 15000; monthly 15000 -> 15000. Tie.
  const tied = {
    price_usd_per_month: 10,
    confidence: 'official_page',
    limits: [
      { window: 'weekly', unit: 'requests', amount: 3500 },
      { window: 'monthly', unit: 'requests', amount: 15000 },
    ],
  };
  expect(estimateForPlan(tied, agentic).bindingWindow).toBe('monthly');
  // Order flipped must not change the winner.
  expect(estimateForPlan({ ...tied, limits: [...tied.limits].reverse() }, agentic).bindingWindow).toBe(
    'monthly'
  );
});
