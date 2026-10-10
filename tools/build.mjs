#!/usr/bin/env node
// Build: recompute every usd{} block and blended_3to1 in data/pricing.json
// from the native values and data/fx.json, then refresh the derived
// cheapest-provider ranking and the committed CSV exports' usd_* columns.
// Hand-edited usd values are impossible: the validator re-derives them
// (docs/fx.md). Usage: npm run build [-- --out <path>].

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { toUsd, validateFx } from './fx.mjs';

const fxFileUrl = new URL('../data/fx.json', import.meta.url);
const pricingFileUrl = new URL('../data/pricing.json', import.meta.url);

const rowsOf = (doc, key) => (Array.isArray(doc?.[key]) ? doc[key] : []);

/** One native amount as usd: converted and rounded, or null when the source
 * does not publish a number ("unknown", null) — usd never carries a string. */
function convertField(amount, currency, fx) {
  const usd = toUsd(amount, currency, fx);
  return typeof usd === 'number' ? usd : null;
}

/** Recomputed usd block for one api_offers row, keys in the dataset's order. */
export function offerUsd(row, fx) {
  const usd = {
    input_per_mtok: convertField(row.input_per_mtok, row.currency, fx),
    output_per_mtok: convertField(row.output_per_mtok, row.currency, fx),
    cached_input_per_mtok: convertField(row.cached_input_per_mtok, row.currency, fx),
    cache_write_per_mtok: convertField(row.cache_write_per_mtok, row.currency, fx),
  };
  if (row.currency !== fx.base) usd.fx_rate_date = fx.date;
  // The blend converts the UNROUNDED native blend, so rounding happens once,
  // on the final value (docs/fx.md).
  const native =
    typeof row.input_per_mtok === 'number' && typeof row.output_per_mtok === 'number'
      ? (3 * row.input_per_mtok + row.output_per_mtok) / 4
      : null;
  usd.blended_3to1 = native === null ? null : toUsd(native, row.currency, fx);
  return usd;
}

/** Recomputed usd block for one subscriptions row, keys in the dataset's order. */
export function subscriptionUsd(row, fx) {
  const usd = {
    price_month: convertField(row.price_month, row.currency, fx),
    price_year: convertField(row.price_year, row.currency, fx),
  };
  if (row.currency !== fx.base) usd.fx_rate_date = fx.date;
  return usd;
}

/** Min blend wins; ties break on the smaller row id. */
function rankRows(rows) {
  const ranked = rows
    .filter((row) => typeof row.usd?.blended_3to1 === 'number')
    .sort((a, b) => a.usd.blended_3to1 - b.usd.blended_3to1 || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  if (ranked.length === 0) return null;
  return {
    offers: ranked.length,
    cheapest_offer: ranked[0].id,
    blended_3to1_usd: ranked[0].usd.blended_3to1,
  };
}

/**
 * Rebuild derived.cheapest_provider_per_model from the rows themselves: an
 * entry per model_slug two or more rows can rank (existing entries with one
 * ranked row are recomputed in place, not dropped); a model whose rows all
 * lost their blend loses its entry.
 */
function rebuildDerived(doc) {
  const derived = doc.derived?.cheapest_provider_per_model;
  if (derived === null || typeof derived !== 'object') return;
  const byModel = new Map();
  for (const row of rowsOf(doc, 'api_offers')) {
    if (!byModel.has(row.model_slug)) byModel.set(row.model_slug, []);
    byModel.get(row.model_slug).push(row);
  }
  for (const slug of Object.keys(derived)) {
    const entry = rankRows(byModel.get(slug) ?? []);
    if (entry) Object.assign(derived[slug], entry);
    else delete derived[slug];
  }
  for (const [slug, rows] of byModel) {
    if (derived[slug] !== undefined) continue;
    const entry = rankRows(rows);
    if (entry && entry.offers >= 2) derived[slug] = entry;
  }
}

/**
 * Recompute every derived number in `doc` from its native values and `fx`:
 * the top-level fx block (a copy), each row's usd block, and the derived
 * cheapest-provider ranking. Mutates and returns doc. Throws on a currency
 * fx has no rate for — add the rate, never guess one (docs/fx.md).
 */
export function buildDocument(doc, fx) {
  doc.fx = {
    base: fx.base,
    date: fx.date,
    source: fx.source,
    rates: { ...fx.rates },
  };
  for (const row of rowsOf(doc, 'api_offers')) row.usd = offerUsd(row, fx);
  for (const row of rowsOf(doc, 'subscriptions')) row.usd = subscriptionUsd(row, fx);
  rebuildDerived(doc);
  return doc;
}

// --- formatting: write JSON back byte-stably -------------------------------
// The dataset is committed text: untouched numbers must keep their written
// form (20.0 stays 20.0), or every build would churn lines the build does not
// mean to change. Changed numbers print as JS prints them.

function escapePointerToken(token) {
  return token.replace(/~/g, '~0').replace(/\//g, '~1');
}

/** Number tokens in document order (a JSON number, never inside a string). */
function scanNumberTokens(text) {
  const tokens = [];
  for (let i = 0; i < text.length; ) {
    const c = text[i];
    if (c === '"') {
      i += 1;
      while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      i += 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i + 1;
      while (j < text.length && /[0-9.eE+-]/.test(text[j])) j += 1;
      tokens.push(text.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

/**
 * Map each value's JSON Pointer to the exact lexeme the document was read
 * from, so unchanged numbers can be written back unchanged.
 * @param {string} text raw JSON text
 * @param {unknown} doc JSON.parse(text)
 */
export function collectNumberLexemes(text, doc) {
  const tokens = scanNumberTokens(text);
  const map = new Map();
  let i = 0;
  const visit = (value, pointer) => {
    if (typeof value === 'number') map.set(pointer, tokens[i++]);
    else if (Array.isArray(value)) value.forEach((v, idx) => visit(v, `${pointer}/${idx}`));
    else if (value !== null && typeof value === 'object') {
      for (const [key, v] of Object.entries(value)) visit(v, `${pointer}/${escapePointerToken(key)}`);
    }
  };
  visit(doc, '');
  if (i !== tokens.length) {
    throw new Error(`internal: read ${tokens.length} number token(s) but walked ${i} value(s)`);
  }
  return map;
}

/** JSON.stringify(doc, null, 2), except numbers keep their original lexeme. */
export function serializeDocument(doc, lexemes = new Map()) {
  const write = (value, pointer, depth) => {
    if (value === null) return 'null';
    const type = typeof value;
    if (type === 'number') {
      const lexeme = lexemes.get(pointer);
      return lexeme !== undefined && Number(lexeme) === value ? lexeme : String(value);
    }
    if (type === 'string' || type === 'boolean') return JSON.stringify(value);
    const pad = '  '.repeat(depth);
    const padIn = '  '.repeat(depth + 1);
    if (Array.isArray(value)) {
      if (value.length === 0) return '[]';
      return `[\n${value.map((v, i) => padIn + write(v, `${pointer}/${i}`, depth + 1)).join(',\n')}\n${pad}]`;
    }
    const keys = Object.keys(value);
    if (keys.length === 0) return '{}';
    return `{\n${keys
      .map((key) => `${padIn}${JSON.stringify(key)}: ${write(value[key], `${pointer}/${escapePointerToken(key)}`, depth + 1)}`)
      .join(',\n')}\n${pad}}`;
  };
  return write(doc, '', 0);
}

// --- CSV exports: refresh the usd_* columns by row id -----------------------

function unquoteCsvCell(cell) {
  const trimmed = cell.length >= 2 && cell.startsWith('"') && cell.endsWith('"') ? cell.slice(1, -1) : cell;
  return trimmed.replace(/""/g, '"');
}

/** Quote-aware split into records of raw cells (original quoting preserved). */
function splitCsvRecords(text, eol) {
  const records = [[]];
  let cell = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; ) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"' && text[i + 1] === '"') {
        cell += '""';
        i += 2;
      } else {
        if (c === '"') inQuotes = false;
        cell += c;
        i += 1;
      }
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      cell += c;
      i += 1;
    } else if (c === ',') {
      records[records.length - 1].push(cell);
      cell = '';
      i += 1;
    } else if (text.startsWith(eol, i)) {
      records[records.length - 1].push(cell);
      cell = '';
      records.push([]);
      i += eol.length;
    } else {
      cell += c;
      i += 1;
    }
  }
  if (cell !== '' || records[records.length - 1].length > 0) records[records.length - 1].push(cell);
  if (records.length > 0 && records[records.length - 1].length === 0) records.pop(); // trailing eol
  return records;
}

/**
 * Rewrite the given usd columns per row id, leaving every other byte of every
 * other cell untouched (a cell whose value did not change keeps its written
 * form). @param {Map<string, Map<string, number|null>>} updates id -> column -> value
 */
export function updateCsvUsd(text, updates) {
  if (updates.size === 0 || text === '') return text;
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const records = splitCsvRecords(text, eol);
  const column = new Map(records[0].map((cell, i) => [unquoteCsvCell(cell), i]));
  let changed = 0;
  for (const record of records.slice(1)) {
    const rowUpdates = updates.get(unquoteCsvCell(record[0]));
    if (!rowUpdates) continue;
    for (const [name, value] of rowUpdates) {
      const index = column.get(name);
      if (index === undefined) throw new Error(`csv has no '${name}' column`);
      const before = record[index];
      const written = unquoteCsvCell(before);
      // an empty cell means null, not 0: only a non-empty written number may stand in
      const after =
        value === null || value === undefined
          ? ''
          : written !== '' && Number(written) === value
            ? before
            : String(value);
      if (after !== before) changed += 1;
      record[index] = after;
    }
  }
  if (changed === 0) return text;
  return records.map((record) => record.join(',')).join(eol) + (text.endsWith(eol) ? eol : '');
}

/** The usd_* column values build publishes for one row. */
export function csvUsdColumns(kind, row) {
  if (kind === 'api') {
    return new Map([
      ['usd_input', row.usd.input_per_mtok],
      ['usd_output', row.usd.output_per_mtok],
      ['usd_cached_input', row.usd.cached_input_per_mtok],
      ['usd_blended_3to1', row.usd.blended_3to1],
    ]);
  }
  return new Map([['usd_price_month', row.usd.price_month]]);
}

export function run(argv, { log = console.log, error = console.error } = {}) {
  const args = argv.slice(2);
  const outFlag = args.indexOf('--out');
  const outPath = outFlag !== -1 ? args[outFlag + 1] : null;
  if (outFlag !== -1 && !outPath) {
    error('--out needs a path');
    return 1;
  }

  let fx;
  let doc;
  let originalText;
  try {
    fx = JSON.parse(readFileSync(fxFileUrl, 'utf-8'));
    validateFx(fx, 'data/fx.json'); // a 0 or non-finite rate would divide to a silent wrong usd
    originalText = readFileSync(pricingFileUrl, 'utf-8');
    doc = JSON.parse(originalText);
  } catch (err) {
    error(`cannot read inputs (need data/fx.json and data/pricing.json): ${err.message}`);
    return 1;
  }

  try {
    buildDocument(doc, fx);
  } catch (err) {
    error(`${err.message}`);
    return 1;
  }

  const lexemes = collectNumberLexemes(originalText, JSON.parse(originalText));
  const outUrl = outPath ? pathToFileURL(resolve(outPath)) : pricingFileUrl;
  writeFileSync(outUrl, serializeDocument(doc, lexemes));

  // The committed CSV exports carry the same usd_* numbers; refresh them by
  // row id next to the written pricing file.
  const dir = dirname(fileURLToPath(outUrl));
  for (const [csvName, rows, kind] of [
    ['pricing_api.csv', doc.api_offers ?? [], 'api'],
    ['pricing_subscriptions.csv', doc.subscriptions ?? [], 'subscription'],
  ]) {
    const csvPath = resolve(dir, csvName);
    if (!existsSync(csvPath)) continue;
    const updates = new Map(
      rows.map((row) => [row.id, csvUsdColumns(kind, row)])
    );
    const text = readFileSync(csvPath, 'utf-8');
    writeFileSync(csvPath, updateCsvUsd(text, updates));
    log(`refreshed ${csvPath}`);
  }
  log(`built ${fileURLToPath(outUrl)}: fx ${fx.base} ${fx.date}, ${doc.api_offers?.length ?? 0} api_offers, ${doc.subscriptions?.length ?? 0} subscriptions`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exit(run(process.argv));
}
