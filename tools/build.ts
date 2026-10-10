#!/usr/bin/env node
// Deterministic builder: rebuild data/pricing.json and the two CSV exports
// from the fragment files under data/ (written once by tools/split.ts).
//
// Determinism: no clocks, no randomness, no locale-dependent comparison — the
// output depends only on the fragment bytes. generated_at is re-derived as the
// maximum last_verified_at across all rows (date-only values become
// T00:00:00Z), never the wall clock.
//
// Usage: vite-node tools/build.ts   (writes dist/, prints one line per output)

import { mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateDocuments, formatError } from './validate.mjs';

// -- types ------------------------------------------------------------------

export interface Meta {
  schema_version: string;
  dataset: string;
  license: string;
  conventions: Record<string, string>;
  research_notes: Record<string, string>;
}

export interface Fx {
  base: string;
  date: string;
  source: string;
  rates: Record<string, number>;
}

export interface ProviderRow {
  id: string;
  name: string;
  type: string;
  country: string;
  api_offer_count: number;
  subscription_count: number;
}

export interface OfferRow {
  id: string;
  provider_id: string;
  model_slug: string;
  usd: { blended_3to1: number | string | null } | null;
  last_verified_at: string;
  [key: string]: unknown;
}

export interface PlanRow {
  id: string;
  vendor_id: string;
  last_verified_at: string;
  [key: string]: unknown;
}

export interface SourceRow {
  provider_id: string;
  url: string;
  part: string;
  [key: string]: unknown;
}

export interface OfferFragment {
  provider_id: string;
  offers: OfferRow[];
}

export interface PlanFragment {
  vendor_id: string;
  plans: PlanRow[];
}

export interface Fragments {
  meta: Meta;
  fx: Fx;
  providers: ProviderRow[];
  offers: OfferFragment[];
  plans: PlanFragment[];
  sources: SourceRow[];
}

export interface PriceIndexDoc {
  schema_version: string;
  dataset: string;
  generated_at: string;
  license: string;
  conventions: Record<string, string>;
  fx: Fx;
  counts: {
    api_providers: number;
    api_offers: number;
    subscription_vendors: number;
    subscriptions: number;
    sources: number;
  };
  providers: ProviderRow[];
  api_offers: OfferRow[];
  subscriptions: PlanRow[];
  derived: {
    cheapest_provider_per_model: Record<
      string,
      { offers: number; cheapest_offer: string; blended_3to1_usd: number }
    >;
  };
  sources: SourceRow[];
  research_notes: Record<string, string>;
}

function fail(message: string): never {
  throw new Error(`build: ${message}`);
}

/** Plain code-unit string comparison — never localeCompare (locale-dependent). */
function byPlainString(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

// -- loading ----------------------------------------------------------------

export function loadFragments(dataDir: string): Fragments {
  const readJson = (path: string): unknown =>
    JSON.parse(readFileSync(path, 'utf-8'));

  const meta = readJson(join(dataDir, 'meta.json')) as Meta;
  const fx = readJson(join(dataDir, 'fx.json')) as Fx;
  const providers = readJson(join(dataDir, 'providers.json')) as ProviderRow[];
  const sources = readJson(join(dataDir, 'sources.json')) as SourceRow[];

  // File lists are re-sorted here so the build never depends on readdir order.
  const offers = readdirSync(join(dataDir, 'offers'))
    .filter((name) => name.endsWith('.json'))
    .sort(byPlainString)
    .map((name) => readJson(join(dataDir, 'offers', name)) as OfferFragment);
  const plans = readdirSync(join(dataDir, 'plans'))
    .filter((name) => name.endsWith('.json'))
    .sort(byPlainString)
    .map((name) => readJson(join(dataDir, 'plans', name)) as PlanFragment);

  return { meta, fx, providers, offers, plans, sources };
}

// -- derived ----------------------------------------------------------------

/**
 * cheapest_provider_per_model: group api_offers by model_slug; among the rows
 * whose usd.blended_3to1 is a number ("unknown"/null cannot rank), keep groups
 * with at least 2 such rows; cheapest_offer is the row with the smallest
 * blended_3to1, ties broken by lexicographically smallest id; the value is
 * that smallest blended price. Rule reconstructed from and verified against
 * the seed dataset (zero mismatches, including all 20 tied groups).
 */
export function computeCheapestProviderPerModel(
  offers: OfferRow[]
): PriceIndexDoc['derived']['cheapest_provider_per_model'] {
  const groups = new Map<string, OfferRow[]>();
  for (const row of offers) {
    if (!groups.has(row.model_slug)) groups.set(row.model_slug, []);
    groups.get(row.model_slug)!.push(row);
  }

  const out: PriceIndexDoc['derived']['cheapest_provider_per_model'] = {};
  for (const slug of [...groups.keys()].sort(byPlainString)) {
    const rankable = groups.get(slug)!.filter((row) => typeof row.usd?.blended_3to1 === 'number');
    if (rankable.length < 2) continue;
    let best = rankable[0];
    for (const row of rankable) {
      const value = row.usd!.blended_3to1 as number;
      const bestValue = best.usd!.blended_3to1 as number;
      if (value < bestValue || (value === bestValue && row.id < best.id)) best = row;
    }
    out[slug] = {
      offers: rankable.length,
      cheapest_offer: best.id,
      blended_3to1_usd: best.usd!.blended_3to1 as number,
    };
  }
  return out;
}

/** generated_at = max last_verified_at over all rows; date-only gains T00:00:00Z. */
export function deriveGeneratedAt(rows: { last_verified_at: string }[]): string {
  if (rows.length === 0) fail('no rows to derive generated_at from');
  let max = '';
  let maxMs = Number.NEGATIVE_INFINITY;
  for (const row of rows) {
    const ms = Date.parse(row.last_verified_at);
    if (Number.isNaN(ms)) fail(`unparseable last_verified_at '${row.last_verified_at}'`);
    if (ms > maxMs) {
      maxMs = ms;
      max = row.last_verified_at;
    }
  }
  return max.length === 10 ? `${max}T00:00:00Z` : max;
}

// -- assembly ---------------------------------------------------------------

/**
 * Concatenate fragment row groups in file order, then sort by id. The sort is
 * what makes the output globally id-sorted: row ids do not always share the
 * fragment file name's separator (vendor `alibaba_cn` ships ids
 * `alibaba-cn/...`, and '_' > '.' sorts `alibaba_cn.json` after
 * `alibaba.json` while '-' < '/' sorts `alibaba-cn/...` before
 * `alibaba/...`), so filename order alone is not id order. Ids are unique
 * (validated before write), so the result is fully deterministic.
 */
function concatSorted<T extends { id: string }>(groups: T[][], label: string): T[] {
  const rows: T[] = [];
  for (const group of groups) rows.push(...group);
  rows.sort((a, b) => byPlainString(a.id, b.id));
  for (let i = 1; i < rows.length; i++) {
    if (!(rows[i - 1].id < rows[i].id)) {
      fail(`duplicate ${label} id '${rows[i].id}' (adjacent after sort at index ${i})`);
    }
  }
  return rows;
}

export function assembleDataset(fragments: Fragments): PriceIndexDoc {
  const { meta, fx, providers, offers, plans, sources } = fragments;

  const apiOffers = concatSorted(offers.map((fragment) => fragment.offers), 'api_offers');
  const subscriptions = concatSorted(plans.map((fragment) => fragment.plans), 'subscriptions');

  const doc: PriceIndexDoc = {
    schema_version: meta.schema_version,
    dataset: meta.dataset,
    generated_at: deriveGeneratedAt([...apiOffers, ...subscriptions]),
    license: meta.license,
    conventions: meta.conventions,
    fx,
    counts: {
      api_providers: new Set(apiOffers.map((row) => row.provider_id)).size,
      api_offers: apiOffers.length,
      subscription_vendors: new Set(subscriptions.map((row) => row.vendor_id)).size,
      subscriptions: subscriptions.length,
      sources: sources.length,
    },
    providers,
    api_offers: apiOffers,
    subscriptions,
    derived: {
      cheapest_provider_per_model: computeCheapestProviderPerModel(apiOffers),
    },
    sources,
    research_notes: meta.research_notes,
  };
  return doc;
}

export function serializeJson(doc: unknown): string {
  return JSON.stringify(doc, null, 2) + '\n';
}

// -- CSV --------------------------------------------------------------------

const API_HEADER = [
  'id', 'provider_id', 'provider_name', 'provider_type', 'provider_country',
  'model_slug', 'model_name', 'model_creator', 'open_weights', 'currency',
  'input_per_mtok', 'output_per_mtok', 'cached_input_per_mtok',
  'cache_write_per_mtok', 'usd_input', 'usd_output', 'usd_cached_input',
  'usd_blended_3to1', 'batch_discount_pct', 'offpeak', 'tiered_pricing',
  'context_window', 'max_output', 'free_tier', 'region_notes', 'fetch_method',
  'fetch_endpoint', 'volatility', 'source', 'checked', 'confidence', 'notes',
] as const;

const SUBSCRIPTIONS_HEADER = [
  'id', 'vendor_id', 'vendor_name', 'product', 'plan_name', 'category',
  'currency', 'price_month', 'price_year', 'usd_price_month',
  'models_included', 'limits_published', 'fair_use', 'est_tokens_per_month',
  'est_usd_per_mtok_at_full_use', 'estimate_assumption', 'fetch_method',
  'volatility', 'source', 'checked', 'confidence', 'notes',
] as const;

/** One CSV cell: null -> empty, booleans Python-style, numbers via String(n). */
function cell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'boolean') return value ? 'True' : 'False';
  return String(value);
}

/** Minimal RFC4180 quoting: quote only when needed; double embedded quotes. */
function quoteCell(text: string): string {
  if (/[",\r\n]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
  return text;
}

/** limits_published entry: {window}:{amount} {unit} ("{quote}") */
function renderLimit(limit: { window: unknown; amount: unknown; unit: unknown; quote: unknown }): string {
  return `${cell(limit.window)}:${cell(limit.amount)} ${cell(limit.unit)} ("${cell(limit.quote)}")`;
}

function toCsv(header: readonly string[], rows: string[][]): string {
  const lines = [header, ...rows].map((cells) => cells.map(quoteCell).join(','));
  return lines.join('\r\n') + '\r\n';
}

export function toCsvApi(rows: OfferRow[]): string {
  return toCsv(
    API_HEADER,
    rows.map((row) => [
      cell(row.id),
      cell(row.provider_id),
      cell(row.provider_name),
      cell(row.provider_type),
      cell(row.provider_country),
      cell(row.model_slug),
      cell(row.model_name),
      cell(row.model_creator),
      cell(row.open_weights),
      cell(row.currency),
      cell(row.input_per_mtok),
      cell(row.output_per_mtok),
      cell(row.cached_input_per_mtok),
      cell(row.cache_write_per_mtok),
      cell(row.usd?.input_per_mtok),
      cell(row.usd?.output_per_mtok),
      cell(row.usd?.cached_input_per_mtok),
      cell(row.usd?.blended_3to1),
      cell(row.batch_discount_pct),
      cell(row.offpeak),
      cell(row.tiered_pricing),
      cell(row.context_window),
      cell(row.max_output),
      cell(row.free_tier),
      cell(row.region_notes),
      cell(row.fetch_recipe && (row.fetch_recipe as Record<string, unknown>).method),
      cell(row.fetch_recipe && (row.fetch_recipe as Record<string, unknown>).endpoint),
      cell(row.fetch_recipe && (row.fetch_recipe as Record<string, unknown>).volatility),
      cell(row.source),
      cell(row.checked),
      cell(row.confidence),
      cell(row.notes),
    ])
  );
}

export function toCsvSubscriptions(rows: PlanRow[]): string {
  return toCsv(
    SUBSCRIPTIONS_HEADER,
    rows.map((row) => [
      cell(row.id),
      cell(row.vendor_id),
      cell(row.vendor_name),
      cell(row.product),
      cell(row.plan_name),
      cell(row.category),
      cell(row.currency),
      cell(row.price_month),
      cell(row.price_year),
      cell(row.usd?.price_month),
      cell(Array.isArray(row.models_included) ? row.models_included.join('; ') : row.models_included),
      cell(
        Array.isArray(row.limits_published)
          ? row.limits_published
              .map((limit) => renderLimit(limit as { window: unknown; amount: unknown; unit: unknown; quote: unknown }))
              .join(' | ')
          : row.limits_published
      ),
      cell(row.fair_use),
      cell(row.est_tokens_per_month),
      cell(row.est_usd_per_mtok_at_full_use),
      cell(row.estimate_assumption),
      cell(row.fetch_recipe && (row.fetch_recipe as Record<string, unknown>).method),
      cell(row.fetch_recipe && (row.fetch_recipe as Record<string, unknown>).volatility),
      cell(row.source),
      cell(row.checked),
      cell(row.confidence),
      cell(row.notes),
    ])
  );
}

// -- CLI --------------------------------------------------------------------

export function main(): number {
  const repoRoot = fileURLToPath(new URL('..', import.meta.url));
  const dataDir = resolve(repoRoot, 'data');
  const distDir = resolve(repoRoot, 'dist');

  const fragments = loadFragments(dataDir);
  const doc = assembleDataset(fragments);

  const problems = validateDocuments(
    [{ file: 'data/pricing.json (assembled)', doc }],
    JSON.parse(readFileSync(resolve(repoRoot, 'schema/pricing.v1.json'), 'utf-8'))
  );
  if (problems.length > 0) {
    for (const problem of problems) console.error(formatError(problem));
    console.error(`${problems.length} error(s) in the assembled dataset; dist/ not written`);
    return 1;
  }

  const outputs: [string, string][] = [
    ['pricing.json', serializeJson(doc)],
    ['pricing_api.csv', toCsvApi(doc.api_offers)],
    ['pricing_subscriptions.csv', toCsvSubscriptions(doc.subscriptions)],
  ];
  mkdirSync(distDir, { recursive: true });
  for (const [name, content] of outputs) {
    writeFileSync(join(distDir, name), content);
    console.log(`wrote dist/${name} (${Buffer.byteLength(content)} bytes)`);
  }
  return 0;
}

/**
 * Main-module guard. validate.mjs compares import.meta.url against
 * process.argv[1], which works for `node tools/validate.mjs` but not here:
 * under `vite-node tools/build.ts` the CLI rewrites argv to [node, its-own-cli]
 * and erases the script path entirely. Two signals remain:
 *   - vitest imports tool modules for its tests; it sets VITEST, and main must
 *     not fire for those.
 *   - under vite-node, the entry file's module-eval frame is the only project
 *     frame on the stack — an imported module always shows its importer's frame
 *     above the vite-node runner frames. Verified against vite-node 3.2.4.
 */
function isMainModule(): boolean {
  const argv1 = process.argv[1];
  if (argv1 && resolve(argv1) === fileURLToPath(import.meta.url)) return true;
  if (process.env.VITEST) return false;
  // The stack heuristic below is only meaningful under the vite-node CLI,
  // which erases the script path from argv. Any other runner (plain node
  // importing this module, other tools) must not fire main on import.
  if (!isViteNodeCli(argv1)) return false;

  const thisFile = fileURLToPath(import.meta.url);
  const internal = /node_modules[\\/](vite-node|vite)[\\/]|node:internal/;
  let sawSelf = false;
  for (const line of (new Error().stack ?? '').split('\n')) {
    if (!line.trimStart().startsWith('at ')) continue; // skip the "Error: ..." header
    if (internal.test(line)) continue;
    if (line.includes(thisFile)) {
      sawSelf = true;
      continue;
    }
    return false; // a non-internal frame that is not ours: we were imported
  }
  return sawSelf;
}

/** `node_modules/.bin/vite-node` symlinks to vite-node's own launcher script. */
function isViteNodeCli(argv1: string | undefined): boolean {
  if (!argv1) return false;
  const base = (path: string) => path.split(/[\\/]/).pop() ?? path;
  if (base(argv1).startsWith('vite-node')) return true;
  try {
    return base(realpathSync(argv1)).startsWith('vite-node');
  } catch {
    return false;
  }
}

if (isMainModule()) {
  process.exit(main());
}
