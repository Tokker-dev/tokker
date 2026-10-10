// Freshness SLAs (docs/plan.md §4.5). Every row matches one class with an
// sla_days budget: row type first (a subscription is a subscription whatever
// its volatility), then fetch_recipe.volatility. A row is stale once more
// whole UTC days than sla_days separate its last_verified_at date from the
// build/read date; the Worker recomputes this at read time from the same
// rules, because data keeps ageing after a merge. Both implementations must
// agree on every vector in tests/vectors/staleness.json.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const RULES_FILE = 'data/rules/freshness.json';
const rulesUrl = new URL('../' + RULES_FILE, import.meta.url);

let cachedRules;

/** The rules to work with: the argument if given, else the repo file (once). */
function ruleSet(override) {
  if (override !== undefined) return override;
  cachedRules ??= JSON.parse(readFileSync(rulesUrl, 'utf-8'));
  return cachedRules;
}

const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Days since 1970-01-01 for the date part (first 10 chars) of an iso_date. */
function daySerial(value, what) {
  const match = DATE.exec(String(value).slice(0, 10));
  if (!match) throw new Error(`${what} is not an ISO date: ${value}`);
  const [year, month, day] = match.slice(1).map(Number);
  const serial = Date.UTC(year, month - 1, day) / 86_400_000;
  const back = new Date(serial * 86_400_000);
  // Date.UTC rolls overflow (2026-02-30) over; the round trip catches it.
  if (back.getUTCFullYear() !== year || back.getUTCMonth() !== month - 1 || back.getUTCDate() !== day) {
    throw new Error(`${what} is not a real calendar date: ${value}`);
  }
  return serial;
}

/** The YYYY-MM-DD for a day serial. */
function dateOf(serial) {
  return new Date(serial * 86_400_000).toISOString().slice(0, 10);
}

/** The first rule whose row_type and volatility (absent = any) both match. */
function matchRule(rowType, volatility, set) {
  for (const rule of set.rules) {
    if (rule.row_type !== undefined && rule.row_type !== rowType) continue;
    if (rule.volatility !== undefined && rule.volatility !== volatility) continue;
    const cls = set.classes[rule.class];
    if (!cls || !Number.isInteger(cls.sla_days) || cls.sla_days < 0) {
      throw new Error(`freshness class '${rule.class}' has no non-negative integer sla_days`);
    }
    return { name: rule.class, slaDays: cls.sla_days };
  }
  throw new Error(`no freshness rule matches row_type '${rowType}' volatility '${volatility}'`);
}

/**
 * The freshness class for a row: the first matching rule in the rules file.
 * @param {string} rowType 'api_offer' or 'subscription'
 * @param {string|undefined} volatility the row's fetch_recipe.volatility
 * @param {object} [rules] rules object; defaults to data/rules/freshness.json
 * @returns {string} a class name from the rules file
 */
export function classify(rowType, volatility, rules) {
  return matchRule(rowType, volatility, ruleSet(rules)).name;
}

/**
 * Staleness for one row. Age is whole UTC days from the last_verified_at date
 * to `today`; stale = age > sla_days, so age == SLA is still fresh and a row
 * verified today (or in the future) never is. stale_since is the first stale
 * day. A malformed date throws — it is never silently fresh.
 * @param {{rowType: string, volatility?: string, lastVerifiedAt: string, today: string}} row
 * @param {object} [rules] rules object; defaults to data/rules/freshness.json
 * @returns {{class: string, sla_days: number, stale: boolean, stale_since: string|null}}
 */
export function staleness({ rowType, volatility, lastVerifiedAt, today }, rules) {
  const { name, slaDays } = matchRule(rowType, volatility, ruleSet(rules));
  const verified = daySerial(lastVerifiedAt, 'last_verified_at');
  const stale = daySerial(today, 'today') - verified > slaDays;
  return {
    class: name,
    sla_days: slaDays,
    stale,
    stale_since: stale ? dateOf(verified + slaDays + 1) : null,
  };
}

const ROW_ARRAYS = [
  ['api_offers', 'api_offer'],
  ['subscriptions', 'subscription'],
];

/** Stamp stale, stale_since and stale_fields onto one row (in place). */
function stampRow(row, rowType, today, set) {
  const verdict = staleness(
    { rowType, volatility: row.fetch_recipe?.volatility, lastVerifiedAt: row.last_verified_at, today },
    set
  );
  row.stale = verdict.stale;
  row.stale_since = verdict.stale_since;
  const verified = daySerial(row.last_verified_at, 'last_verified_at');
  const staleFields = {};
  for (const [field, entry] of Object.entries(row.provenance?.fields ?? {})) {
    if (typeof entry === 'string') continue; // "default" shares the row's verification
    // A per-field source from an older fetch ages on its own: flagged once it,
    // too, is past the row's SLA.
    const fetched = daySerial(entry.fetched_at, `provenance.fields.${field}.fetched_at`);
    if (fetched < verified && daySerial(today, 'today') - fetched > verdict.sla_days) {
      staleFields[field] = dateOf(fetched + verdict.sla_days + 1);
    }
  }
  if (Object.keys(staleFields).length > 0) row.stale_fields = staleFields;
}

/**
 * Stamp freshness onto a copy of a pricing document: every row gets `stale`
 * and `stale_since` (plus `stale_fields` when a per-field provenance override
 * is itself stale), `counts.stale` counts the stale rows, and a top-level
 * `freshness` block records `as_of` and the five oldest rows (ties by id).
 * Returns a new document; the input is not mutated. Throws on a bad date.
 * @param {object} doc a parsed pricing document
 * @param {{today: string, rules?: object}} options `today` is YYYY-MM-DD
 * @returns {object} the annotated copy
 */
export function annotate(doc, { today, rules } = {}) {
  const set = ruleSet(rules);
  const entries = [];
  const out = { ...doc };
  for (const [key, rowType] of ROW_ARRAYS) {
    out[key] = (doc[key] ?? []).map((row) => {
      const stamped = { ...row };
      stampRow(stamped, rowType, today, set);
      entries.push({ row: stamped, rowType });
      return stamped;
    });
  }
  out.counts = { ...doc.counts, stale: entries.filter(({ row }) => row.stale).length };
  const oldest = entries
    .map((entry) => ({ ...entry, at: daySerial(entry.row.last_verified_at, `${entry.row.id} last_verified_at`) }))
    .sort((a, b) => a.at - b.at || (a.row.id < b.row.id ? -1 : 1))
    .slice(0, 5)
    .map(({ row, rowType }) => ({
      id: row.id,
      row_type: rowType,
      last_verified_at: row.last_verified_at,
      stale: row.stale,
      stale_since: row.stale_since,
    }));
  out.freshness = { as_of: today, oldest };
  return out;
}
