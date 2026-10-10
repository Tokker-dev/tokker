#!/usr/bin/env node
// One-off splitter: cut the monolithic seed data/pricing.json into the fragment
// files the builder (tools/build.ts) consumes. Kept for the record; running it
// again is safe (it is deterministic and idempotent) but never necessary.
//
// Layout written:
//   data/meta.json               schema_version/dataset/license/conventions/research_notes
//   data/fx.json                 the fx block, rates keys sorted
//   data/providers.json          bare array, sorted by id
//   data/sources.json            bare array, sorted by (provider_id, part, url)
//   data/offers/<provider>.json  {provider_id, offers:[...]}, rows sorted by id
//   data/plans/<vendor>.json     {vendor_id, plans:[...]}, rows sorted by id
//
// Every fragment is 2-space JSON + one trailing newline. The tool refuses
// loudly (throws) on any invariant violation rather than writing a fragment.
// Usage: vite-node tools/split.ts

import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

interface ProviderRow {
  id: string;
  name: string;
  type: string;
  country: string;
  api_offer_count: number;
  subscription_count: number;
}

interface OfferRow {
  id: string;
  provider_id: string;
  model_slug: string;
  last_verified_at: string;
  [key: string]: unknown;
}

interface PlanRow {
  id: string;
  vendor_id: string;
  last_verified_at: string;
  [key: string]: unknown;
}

interface SourceRow {
  provider_id: string;
  url: string;
  part: string;
  [key: string]: unknown;
}

interface SeedDoc {
  schema_version: string;
  dataset: string;
  license: string;
  conventions: Record<string, string>;
  research_notes: Record<string, string>;
  fx: { base: string; date: string; source: string; rates: Record<string, number> };
  counts: Record<string, number>;
  providers: ProviderRow[];
  api_offers: OfferRow[];
  subscriptions: PlanRow[];
  sources: SourceRow[];
  [key: string]: unknown;
}

/** Invariant violation: split refuses to write anything. */
function fail(message: string): never {
  throw new Error(`split: invariant violation: ${message}`);
}

function assertUnique(label: string, values: string[]): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) fail(`duplicate ${label} '${value}'`);
    seen.add(value);
  }
}

function isSorted(values: string[]): boolean {
  for (let i = 1; i < values.length; i++) {
    if (!(values[i - 1] < values[i])) return false;
  }
  return true;
}

/** Write one fragment: 2-space indent, one trailing newline. */
function writeFragment(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

/** A provider id becomes a file name; keep the data dir escape-proof. */
function assertSafeFileName(name: string): void {
  if (name === '' || name.includes('/') || name.includes('\\') || name.includes('..')) {
    fail(`'${name}' is not a safe fragment file name`);
  }
}

export function split(seedPath: string, dataDir: string): void {
  const doc = JSON.parse(readFileSync(seedPath, 'utf-8')) as SeedDoc;

  // -- invariants -----------------------------------------------------------
  if (doc.providers.length !== 77) {
    fail(`expected 77 providers, found ${doc.providers.length}`);
  }
  assertUnique('provider id', doc.providers.map((p) => p.id));
  // Row ids are unique across api_offers AND subscriptions (one id space).
  assertUnique(
    'row id',
    [...doc.api_offers, ...doc.subscriptions].map((r) => r.id)
  );
  assertUnique('source tuple', doc.sources.map((s) => `${s.provider_id}\n${s.url}\n${s.part}`));

  const providerIds = new Set(doc.providers.map((p) => p.id));
  for (const offer of doc.api_offers) {
    if (!providerIds.has(offer.provider_id)) {
      fail(`offer '${offer.id}' references unknown provider '${offer.provider_id}'`);
    }
    assertSafeFileName(offer.provider_id);
  }
  for (const plan of doc.subscriptions) {
    if (!providerIds.has(plan.vendor_id)) {
      fail(`plan '${plan.id}' references unknown vendor '${plan.vendor_id}'`);
    }
    assertSafeFileName(plan.vendor_id);
  }
  // Note: sources.provider_id is intentionally NOT checked against providers —
  // the seed records fetched sources for surveyed-but-not-priced providers
  // (naver, liquid, inflection, lambda, hyperbolic, kluster) that have no row.

  const recomputed = {
    api_providers: new Set(doc.api_offers.map((o) => o.provider_id)).size,
    api_offers: doc.api_offers.length,
    subscription_vendors: new Set(doc.subscriptions.map((s) => s.vendor_id)).size,
    subscriptions: doc.subscriptions.length,
    sources: doc.sources.length,
  };
  for (const key of Object.keys(recomputed) as (keyof typeof recomputed)[]) {
    if (doc.counts[key] !== recomputed[key]) {
      fail(`counts.${key} says ${doc.counts[key]}, arrays hold ${recomputed[key]}`);
    }
  }

  // -- fragments ------------------------------------------------------------
  const byPlainString = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

  const providers = [...doc.providers].sort((a, b) => byPlainString(a.id, b.id));
  const sources = [...doc.sources].sort((a, b) =>
    byPlainString(`${a.provider_id}\n${a.part}\n${a.url}`, `${b.provider_id}\n${b.part}\n${b.url}`)
  );

  const offersByProvider = new Map<string, OfferRow[]>();
  for (const offer of doc.api_offers) {
    if (!offersByProvider.has(offer.provider_id)) offersByProvider.set(offer.provider_id, []);
    offersByProvider.get(offer.provider_id)!.push(offer);
  }
  const plansByVendor = new Map<string, PlanRow[]>();
  for (const plan of doc.subscriptions) {
    if (!plansByVendor.has(plan.vendor_id)) plansByVendor.set(plan.vendor_id, []);
    plansByVendor.get(plan.vendor_id)!.push(plan);
  }
  for (const rows of offersByProvider.values()) rows.sort((a, b) => byPlainString(a.id, b.id));
  for (const rows of plansByVendor.values()) rows.sort((a, b) => byPlainString(a.id, b.id));

  writeFragment(
    join(dataDir, 'meta.json'),
    {
      schema_version: doc.schema_version,
      dataset: doc.dataset,
      license: doc.license,
      conventions: doc.conventions,
      research_notes: doc.research_notes,
    }
  );
  writeFragment(join(dataDir, 'fx.json'), {
    base: doc.fx.base,
    date: doc.fx.date,
    source: doc.fx.source,
    rates: Object.fromEntries(Object.keys(doc.fx.rates).sort().map((k) => [k, doc.fx.rates[k]])),
  });
  writeFragment(join(dataDir, 'providers.json'), providers);
  writeFragment(join(dataDir, 'sources.json'), sources);

  const offersDir = join(dataDir, 'offers');
  const plansDir = join(dataDir, 'plans');
  mkdirSync(offersDir, { recursive: true });
  mkdirSync(plansDir, { recursive: true });
  for (const [providerId, rows] of [...offersByProvider].sort(([a], [b]) => byPlainString(a, b))) {
    writeFragment(join(offersDir, `${providerId}.json`), { provider_id: providerId, offers: rows });
  }
  for (const [vendorId, rows] of [...plansByVendor].sort(([a], [b]) => byPlainString(a, b))) {
    writeFragment(join(plansDir, `${vendorId}.json`), { vendor_id: vendorId, plans: rows });
  }

  // -- summary --------------------------------------------------------------
  const log = (line: string) => console.log(line);
  log(`meta.json        (schema_version ${doc.schema_version})`);
  log(`fx.json          (${Object.keys(doc.fx.rates).length} rates)`);
  log(`providers.json   (${providers.length} providers)`);
  log(`sources.json     (${sources.length} sources)`);
  log(
    `offers/          (${offersByProvider.size} files, ${doc.api_offers.length} offers, ` +
      (isSorted(doc.api_offers.map((o) => o.id)) ? 'id-sorted' : 'sorted per file') +
      `)`
  );
  log(
    `plans/           (${plansByVendor.size} files, ${doc.subscriptions.length} plans, ` +
      (isSorted(doc.subscriptions.map((s) => s.id)) ? 'id-sorted' : 'sorted per file') +
      `)`
  );
}

const repoRoot = fileURLToPath(new URL('..', import.meta.url));

/**
 * Main-module guard. validate.mjs compares import.meta.url against
 * process.argv[1], which works for `node tools/validate.mjs` but not here:
 * under `vite-node tools/split.ts` the CLI rewrites argv to [node, its-own-cli]
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
  split(resolve(repoRoot, 'data/pricing.json'), resolve(repoRoot, 'data'));
}
