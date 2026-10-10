#!/usr/bin/env node
// FX for the price index: one dated rate set (ECB euro reference rates served
// by frankfurter.app, cross-rate to USD) in data/fx.json; every usd{} block is
// derived from it by tools/build.mjs. Policy: docs/fx.md.
// Usage: npm run fx [-- --out <path>] — fetch today's rates, write data/fx.json.

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const FRANKFURTER_URL = 'https://api.frankfurter.app/latest?from=USD';
// api.frankfurter.app 301s here; kept as the constant we *ask for* — the URL
// actually used is the response's final URL, recorded as fx.source.
export const FRANKFURTER_FINAL_URL = 'https://api.frankfurter.dev/v1/latest?from=USD';
export const USER_AGENT = 'tokker-fx/1 (+https://github.com/Tokker-dev/tokker)';

const fxFileUrl = new URL('../data/fx.json', import.meta.url);
const pricingFileUrl = new URL('../data/pricing.json', import.meta.url);

/**
 * Round to `digits` significant digits, collapsing float artefacts
 * (0.005966052 -> 0.00596605). 0 stays 0; non-finite input passes through.
 */
export function roundSig(x, digits = 6) {
  if (typeof x !== 'number' || !Number.isFinite(x)) return x;
  if (x === 0) return 0;
  return Number(x.toPrecision(digits));
}

/** The row's currency converts: it is the fx base or has an explicit rate. */
export function isSupportedCurrency(currency, fx) {
  if (typeof currency !== 'string') return false;
  return currency === fx?.base || typeof fx?.rates?.[currency] === 'number';
}

/**
 * Convert a published native amount to USD and round the result once to 6
 * significant digits. fx.rates are units of currency per 1 USD (ECB cross
 * rates), so usd = native / rate. `null` (not applicable), `"unknown"` (not
 * published by the source) and any other non-number pass through unchanged —
 * CLAUDE.md rule 1: never invent a number. A currency with no rate throws:
 * add it to fx first, never guess a rate.
 */
export function toUsd(amount, currency, fx) {
  if (amount === null || typeof amount !== 'number') return amount;
  if (currency === fx.base) return roundSig(amount);
  if (!isSupportedCurrency(currency, fx)) {
    throw new Error(`currency "${currency}" has no rate in fx (unsupported; see docs/fx.md)`);
  }
  return roundSig(amount / fx.rates[currency]);
}

/** Every currency any row publishes in, across api_offers and subscriptions. */
export function usedCurrencies(doc) {
  const used = new Set();
  for (const key of ['api_offers', 'subscriptions']) {
    for (const row of Array.isArray(doc?.[key]) ? doc[key] : []) {
      if (typeof row?.currency === 'string') used.add(row.currency);
    }
  }
  return [...used];
}

/** The rates map every conversion trusts: a finite positive number each. */
export function validateRates(rates, label = 'fx') {
  if (rates === null || typeof rates !== 'object') {
    throw new Error(`${label}: rates must be an object`);
  }
  for (const [currency, rate] of Object.entries(rates)) {
    if (typeof rate !== 'number' || !Number.isFinite(rate) || rate <= 0) {
      throw new Error(`${label}: rate for "${currency}" is not a positive finite number: ${JSON.stringify(rate)}`);
    }
  }
  return rates;
}

/** An fx block's shape: base and date strings over a valid rates map. */
export function validateFx(fx, label = 'fx') {
  if (typeof fx?.base !== 'string') throw new Error(`${label}: base must be a currency string`);
  if (typeof fx?.date !== 'string') throw new Error(`${label}: date must be an ISO date string`);
  validateRates(fx.rates, label);
}

/**
 * Shape a frankfurter.latest response into the dataset's fx block: rates
 * sorted by currency code, `source` set to the URL actually fetched.
 * @returns {{base: string, date: string, source: string, rates: Record<string, number>}}
 */
export function fxFromFrankfurter(json, sourceUrl) {
  validateFx(json, 'frankfurter response');
  const sorted = {};
  for (const currency of Object.keys(json.rates).sort()) {
    sorted[currency] = json.rates[currency];
  }
  return { base: json.base, date: json.date, source: sourceUrl, rates: sorted };
}

/**
 * Refresh data/fx.json from frankfurter. Refuses to write when the response is
 * missing a rate for any currency the dataset uses — a silent gap would break
 * the next build. @returns {status code} 0 written, 1 refused.
 */
export async function run(argv, { log = console.log, error = console.error, fetchImpl = fetch } = {}) {
  let outUrl = fxFileUrl;
  const args = argv.slice(2);
  const outFlag = args.indexOf('--out');
  if (outFlag !== -1) {
    const path = args[outFlag + 1];
    if (!path) {
      error('--out needs a path');
      return 1;
    }
    outUrl = pathToFileURL(resolve(path));
  }

  let response;
  try {
    response = await fetchImpl(FRANKFURTER_URL, { headers: { 'User-Agent': USER_AGENT } });
  } catch (err) {
    error(`frankfurter request failed: ${err.message}`);
    return 1;
  }
  if (!response.ok) {
    error(`frankfurter request failed: HTTP ${response.status} from ${response.url}`);
    return 1;
  }
  let fx;
  try {
    fx = fxFromFrankfurter(await response.json(), response.url);
  } catch (err) {
    error(`frankfurter response unusable: ${err.message}`);
    return 1;
  }

  let doc;
  try {
    doc = JSON.parse(readFileSync(pricingFileUrl, 'utf-8'));
  } catch (err) {
    error(`cannot read ${pricingFileUrl.pathname}: ${err.message}`);
    return 1;
  }
  const missing = usedCurrencies(doc).filter((currency) => !isSupportedCurrency(currency, fx));
  if (missing.length > 0) {
    error(
      `refusing to write: frankfurter (${response.url}) publishes no rate for ${missing.join(', ')}; ` +
        'the build would fail. Check docs/fx.md before adding a secondary source.'
    );
    return 1;
  }

  writeFileSync(outUrl, JSON.stringify(fx, null, 2) + '\n');
  log(`wrote ${fileURLToPath(outUrl)}: base ${fx.base}, ${fx.date}, ${Object.keys(fx.rates).length} rates, source ${fx.source}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  run(process.argv).then((code) => process.exit(code));
}
