import { existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test } from 'vitest';

import {
  fxFromFrankfurter,
  isSupportedCurrency,
  roundSig,
  run,
  toUsd,
  usedCurrencies,
  validateFx,
} from './fx.mjs';

const fx = {
  base: 'USD',
  date: '2026-10-02',
  source: 'https://api.frankfurter.app/latest?from=USD',
  rates: { CNY: 6.7046, EUR: 0.89087, INR: 96.32 },
};

test('roundSig keeps 6 significant digits and no float artefacts', () => {
  expect(roundSig(649 / 96.32)).toBe(6.73796); // 6.7379568...
  expect(roundSig(0.04 / 6.7046)).toBe(0.00596605); // 0.0059660523...
  expect(roundSig(1234567)).toBe(1234570);
  expect(roundSig(0.0000123456789)).toBe(0.0000123457);
  expect(roundSig(-3.14159265)).toBe(-3.14159);
  expect(roundSig(20)).toBe(20);
  expect(roundSig(0.5)).toBe(0.5);
  expect(roundSig(0)).toBe(0);
});

test('roundSig honours the digits argument', () => {
  expect(roundSig(1234567, 4)).toBe(1235000);
  expect(roundSig(3.14159265, 3)).toBe(3.14);
});

test('toUsd divides by the rate and rounds once', () => {
  expect(toUsd(2, 'CNY', fx)).toBe(0.298303); // 2 / 6.7046 = 0.2983026...
  expect(toUsd(39, 'CNY', fx)).toBe(5.8169); // 5.8169024...
  expect(toUsd(10.98, 'INR', fx)).toBe(0.113995);
});

test('toUsd passes null, "unknown" and non-numbers through unchanged', () => {
  expect(toUsd(null, 'CNY', fx)).toBe(null);
  expect(toUsd('unknown', 'CNY', fx)).toBe('unknown');
  expect(toUsd(undefined, 'CNY', fx)).toBe(undefined);
});

test('toUsd normalises base-currency rows through the same rounding', () => {
  expect(toUsd(20, 'USD', fx)).toBe(20);
  expect(toUsd((3 * 3 + 15) / 4, 'USD', fx)).toBe(6);
  expect(toUsd(0.1 + 0.2, 'USD', fx)).toBe(0.3);
});

test('toUsd throws on a currency fx has no rate for', () => {
  expect(() => toUsd(5, 'CHF', fx)).toThrowError(/CHF.*docs\/fx\.md/);
});

test('isSupportedCurrency accepts the base and rated currencies only', () => {
  expect(isSupportedCurrency('USD', fx)).toBe(true);
  expect(isSupportedCurrency('CNY', fx)).toBe(true);
  expect(isSupportedCurrency('CHF', fx)).toBe(false);
  expect(isSupportedCurrency(undefined, fx)).toBe(false);
});

test('usedCurrencies collects every row currency', () => {
  const doc = {
    api_offers: [{ currency: 'USD' }, { currency: 'CNY' }],
    subscriptions: [{ currency: 'INR' }, { currency: 'CNY' }],
  };
  expect(usedCurrencies(doc)).toEqual(['USD', 'CNY', 'INR']);
});

test('fxFromFrankfurter shapes the response and sorts the rates', () => {
  const fxBlock = fxFromFrankfurter(
    {
      amount: 1.0,
      base: 'USD',
      date: '2026-10-09',
      rates: { ZAR: 16.5331, AUD: 1.4324, CHF: 0.83107 },
    },
    'https://api.frankfurter.dev/v1/latest?from=USD'
  );
  expect(fxBlock).toEqual({
    base: 'USD',
    date: '2026-10-09',
    source: 'https://api.frankfurter.dev/v1/latest?from=USD',
    rates: { AUD: 1.4324, CHF: 0.83107, ZAR: 16.5331 },
  });
  expect(Object.keys(fxBlock.rates)).toEqual(['AUD', 'CHF', 'ZAR']);
});

test('fxFromFrankfurter rejects a response it cannot trust', () => {
  expect(() => fxFromFrankfurter({ base: 'USD' }, 'https://x')).toThrowError(/date must be an ISO date string/);
  expect(() =>
    fxFromFrankfurter({ base: 'USD', date: '2026-10-09', rates: { EUR: 0 } }, 'https://x')
  ).toThrowError(/not a positive finite number/);
});

test('validateFx accepts the dataset block and rejects rates no conversion can trust', () => {
  validateFx(fx); // the block every toUsd call below relies on
  expect(() => validateFx({ ...fx, rates: { CNY: 0 } })).toThrowError(/not a positive finite number/);
  expect(() => validateFx({ ...fx, rates: { CNY: '6.7' } })).toThrowError(/not a positive finite number/);
  expect(() => validateFx({ ...fx, rates: undefined })).toThrowError(/rates must be an object/);
  expect(() => validateFx({ ...fx, date: undefined })).toThrowError(/date must be an ISO date string/);
});

test('run exits 1 with a clean message when the fetch itself fails', async () => {
  const errors = [];
  const code = await run(['node', 'fx.mjs'], {
    log: () => {},
    error: (message) => errors.push(message),
    fetchImpl: async () => {
      throw new Error('getaddrinfo EAI_AGAIN api.frankfurter.app');
    },
  });
  expect(code).toBe(1);
  expect(errors.join('\n')).toContain('frankfurter request failed');
  expect(errors.join('\n')).toContain('EAI_AGAIN');
});

test('run refuses to write when a currency the dataset uses has no rate', async () => {
  const out = join(tmpdir(), `tokker-fx-refused-${process.pid}.json`);
  const errors = [];
  const code = await run(['node', 'fx.mjs', '--out', out], {
    log: () => {},
    error: (message) => errors.push(message),
    fetchImpl: async () => ({
      ok: true,
      url: 'https://api.frankfurter.dev/v1/latest?from=USD',
      json: async () => ({ base: 'USD', date: '2026-10-09', rates: { CNY: 6.7, EUR: 0.89 } }),
    }),
  });
  expect(code).toBe(1);
  expect(errors.join('\n')).toContain('refusing to write');
  expect(errors.join('\n')).toContain('INR');
  expect(existsSync(out)).toBe(false);
});

test('run writes the shaped block to --out, rates sorted, final URL as source', async () => {
  const out = join(tmpdir(), `tokker-fx-ok-${process.pid}.json`);
  const code = await run(['node', 'fx.mjs', '--out', out], {
    log: () => {},
    error: () => {},
    fetchImpl: async () => ({
      ok: true,
      url: 'https://api.frankfurter.dev/v1/latest?from=USD',
      json: async () => ({
        base: 'USD',
        date: '2026-10-09',
        rates: { ZAR: 16.5, CNY: 6.7, EUR: 0.89, CHF: 0.83, INR: 96.5 },
      }),
    }),
  });
  expect(code).toBe(0);
  const written = JSON.parse(readFileSync(out, 'utf8'));
  expect(written.source).toBe('https://api.frankfurter.dev/v1/latest?from=USD');
  expect(Object.keys(written.rates)).toEqual(['CHF', 'CNY', 'EUR', 'INR', 'ZAR']);
  rmSync(out);
});
