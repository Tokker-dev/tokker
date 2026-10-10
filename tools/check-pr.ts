#!/usr/bin/env node
// PR guard for the Tokker price data (docs/plan.md §4.4). Compare the head side
// of data/ against a base ref and report: ids removed without a `supersedes`
// successor or `retired_at` (id.removed) or taking a new identity (id.reused);
// sanity bounds (bounds.*: no negatives, no >10x move, input <= output unless the
// provider is registered as inverting, currency unchanged, cache <= input);
// provenance freshness and registered source hosts on new or changed rows
// (provenance.*; secondary-confidence entries are exempt); and limit window/unit
// changes as data:review flags (limits.*), not violations. Bounds and provenance
// rules apply to new rows and rows with non-bookkeeping changes, so untouched
// legacy rows never block an unrelated PR.
//
// Usage: npm run check-pr [-- --base <ref>] [--base-dir <dir>] [--head-dir <dir>]
//   [--date YYYY-MM-DD] [--json]
//
// The base side comes from git (`git ls-tree`/`git show`) or --base-dir; the head
// side is the working tree data/ next to this script or --head-dir. A --*-dir is
// the data directory itself; a repo root with a data/ child works too. Exit 1
// iff there are violations.

import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const DEFAULT_BASE_REF = 'origin/main';
const DEFAULT_DATA_DIR = fileURLToPath(new URL('../data', import.meta.url));
const MOVE_RATIO = 10;
/** Rounding slack: float division must not turn a decimal-exact 10x move into a violation. */
const MOVE_EPS = 1e-9;
const REVIEW_LABEL = 'data:review';

/** Fields that never make a row "changed" on their own: identity bookkeeping
 * (id, supersedes, retired_at), derived values and estimate metadata. A PR
 * touching only these is an annotation, not a price change. */
const BOOKKEEPING_KEYS: ReadonlySet<string> = new Set([
  'id', 'supersedes', 'retired_at', 'last_verified_at', 'provenance', 'checked', 'usd',
  'notes', 'source', 'fetch_recipe', 'confidence',
  'est_tokens_per_month', 'est_usd_per_mtok_at_full_use', 'estimate_assumption',
]);

/** Which keys carry identity, prices and the provider owner, per row kind. */
const OFFER_IDENTITY_KEYS = ['provider_id', 'model_slug', 'model_name'];
const PLAN_IDENTITY_KEYS = ['vendor_id', 'product', 'plan_name'];
const OFFER_PRICE_KEYS = ['input_per_mtok', 'output_per_mtok', 'cached_input_per_mtok', 'cache_write_per_mtok'];
const PLAN_PRICE_KEYS = ['price_month', 'price_year'];

export interface Finding {
  rule: string; id: string; field?: string; message: string;
  base?: unknown; head?: unknown;
  /** Flags carry the review label instead of failing the check. */
  label?: string;
}

export type Row = Record<string, unknown>;
export interface RowSet { offers: Map<string, Row>; plans: Map<string, Row>; }
export interface LoadedFile { path: string; json: unknown; }
export interface Rules { invertedProviders: Set<string>; providerHosts: Record<string, string[]>; }
export interface CheckOptions { date?: string; invertedProviders?: Set<string>; providerHosts?: Record<string, string[]>; }

function isRow(value: unknown): value is Row {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Order-insensitive structural equality (JSON key order must not count as a change). */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b))
    return a.length === b.length && a.every((v, i) => deepEqual(v, b[i]));
  if (isRow(a) && isRow(b)) {
    const keys = Object.keys(b);
    return Object.keys(a).length === keys.length && keys.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

const todayUtc = (): string => new Date().toISOString().slice(0, 10);

/** Classify parsed data files into offer/plan rows. If any data/offers/ or
 * data/plans/ file is present (the per-provider shard layout), only those files
 * are read and data/pricing.json is ignored. Within one file the keys api_offers/
 * offers map to offers and subscriptions/plans to plans; a top-level array is
 * classified by its directory. On a duplicate id the later file wins. */
export function loadRows(files: LoadedFile[]): RowSet {
  const rows: RowSet = { offers: new Map(), plans: new Map() };
  const kindOfPath = (path: string): 'offers' | 'plans' | undefined =>
    path.includes('data/offers/') ? 'offers' : path.includes('data/plans/') ? 'plans' : undefined;
  const keyKinds: Record<string, 'offers' | 'plans'> = {
    api_offers: 'offers', offers: 'offers', subscriptions: 'plans', plans: 'plans',
  };
  const add = (kind: 'offers' | 'plans', list: unknown[]): void => {
    for (const row of list) {
      if (isRow(row) && typeof row.id === 'string') rows[kind].set(row.id, row);
    }
  };

  const shards = files.filter((f) => kindOfPath(f.path) !== undefined);
  const source = shards.length > 0 ? shards : files.filter((f) => !f.path.includes('data/rules/'));
  for (const file of source) {
    const doc = file.json;
    const keyed = isRow(doc) ? Object.entries(keyKinds).filter(([k]) => Array.isArray(doc[k])) : [];
    if (keyed.length > 0) {
      for (const [key, kind] of keyed) add(kind, doc[key] as unknown[]);
    } else {
      const kind = kindOfPath(file.path);
      if (kind && Array.isArray(doc)) add(kind, doc);
    }
  }
  return rows;
}

/** Read the rule files (inverted-pricing.json, provider-hosts.json) out of the
 * head side's data/rules/. Unknown files and shapes are ignored. */
export function loadRules(files: LoadedFile[]): Rules {
  const rules: Rules = { invertedProviders: new Set(), providerHosts: {} };
  for (const file of files) {
    if (!file.path.includes('data/rules/') || !isRow(file.json)) continue;
    const name = file.path.split('/').pop();
    const providers = file.json.providers;
    if (name === 'inverted-pricing.json' && Array.isArray(providers)) {
      for (const p of providers) if (typeof p === 'string') rules.invertedProviders.add(p);
    } else if (name === 'provider-hosts.json' && isRow(file.json.hosts)) {
      for (const [id, list] of Object.entries(file.json.hosts)) {
        if (Array.isArray(list)) {
          rules.providerHosts[id] = list
            .filter((h): h is string => typeof h === 'string')
            .map((h) => h.toLowerCase());
        }
      }
    }
  }
  return rules;
}

/** Top-level keys whose value differs between base and head, excluding
 * bookkeeping keys, sorted. For a new row this is every value field. */
function changedFields(baseRow: Row | undefined, headRow: Row): string[] {
  const keys = new Set([...Object.keys(headRow), ...Object.keys(baseRow ?? {})]);
  return [...keys]
    .filter((k) => !BOOKKEEPING_KEYS.has(k) && (!baseRow || !deepEqual(baseRow[k], headRow[k])))
    .sort();
}

/** Sorted multiset of one limits_published[] property, for change detection. */
function limitsMultiset(row: Row, key: 'window' | 'unit'): string[] {
  const limits = row.limits_published;
  if (!Array.isArray(limits)) return [];
  return limits.map((l) => (isRow(l) && typeof l[key] === 'string' ? l[key] : '')).sort();
}

const isRetired = (row: Row | undefined): boolean =>
  typeof row?.retired_at === 'string' && row.retired_at !== '';

const supersededIn = (rows: Map<string, Row>): Set<string> =>
  new Set(
    [...rows.values()]
      .filter((r) => typeof r.supersedes === 'string' && r.supersedes !== '')
      .map((r) => r.supersedes as string)
  );

/** Diff base against head. Violations fail the PR; flags only carry the
 * data:review label (docs/plan.md §4.4). */
export function checkPr(
  base: RowSet,
  head: RowSet,
  options: CheckOptions = {}
): { violations: Finding[]; flags: Finding[] } {
  const date = options.date ?? todayUtc();
  const invertedProviders = options.invertedProviders ?? new Set<string>();
  const providerHosts = options.providerHosts ?? {};
  const violations: Finding[] = [];
  const flags: Finding[] = [];
  const add = (
    rule: string, id: string, field: string | undefined, message: string,
    extra: Partial<Finding> = {}
  ) => violations.push({ rule, id, field, message, ...extra });

  for (const kind of ['offers', 'plans'] as const) {
    const identityKeys = kind === 'offers' ? OFFER_IDENTITY_KEYS : PLAN_IDENTITY_KEYS;
    const priceKeys = kind === 'offers' ? OFFER_PRICE_KEYS : PLAN_PRICE_KEYS;
    const ownerKey = kind === 'offers' ? 'provider_id' : 'vendor_id';
    const baseMap = base[kind];
    const headMap = head[kind];
    const supersededBase = supersededIn(baseMap);
    const supersededHead = supersededIn(headMap);

    for (const [id, headRow] of headMap) {
      const baseRow = baseMap.get(id);
      const owner = typeof headRow[ownerKey] === 'string' ? headRow[ownerKey] : '';

      if (baseRow) {
        // The id must keep its identity; a rename needs a new id + supersedes.
        for (const key of identityKeys) {
          if (!deepEqual(baseRow[key], headRow[key])) {
            add('id.reused', id, key,
              `identity field '${key}' changed from ${JSON.stringify(baseRow[key])} to ` +
                `${JSON.stringify(headRow[key])}; a renamed ${kind === 'offers' ? 'model' : 'plan'} ` +
                `needs a new id with supersedes`,
              { base: baseRow[key], head: headRow[key] });
          }
        }
        // An id the base retired or superseded must not come back changed.
        if ((isRetired(baseRow) || supersededBase.has(id)) && !deepEqual(baseRow, headRow)) {
          add('id.reused', id, undefined,
            `id is ${isRetired(baseRow) ? 'retired' : 'superseded'} in the base but ` +
              `re-added with different content in the head`);
        }
      }

      const changed = changedFields(baseRow, headRow);
      if (baseRow && changed.length === 0) continue; // untouched legacy row

      for (const key of priceKeys) {
        const hv = headRow[key];
        if (typeof hv !== 'number') continue; // "unknown" and null are not prices
        if (hv < 0) add('bounds.negative', id, key, `${key} is negative (${hv})`);
        const bv = baseRow?.[key];
        if (typeof bv === 'number' && bv > 0 && hv > 0) {
          const ratio = hv / bv;
          if (ratio > MOVE_RATIO + MOVE_EPS || ratio < 1 / MOVE_RATIO - MOVE_EPS)
            add('bounds.move', id, key,
              `${key} moved from ${bv} to ${hv}, more than ${MOVE_RATIO}x`, { base: bv, head: hv });
        }
      }

      if (kind === 'offers') {
        const input = headRow.input_per_mtok;
        const output = headRow.output_per_mtok;
        const inverted =
          typeof input === 'number' && typeof output === 'number' && input > output;
        if (inverted && !invertedProviders.has(owner)) {
          add('bounds.inverted', id, 'input_per_mtok',
            `input_per_mtok (${input}) is greater than output_per_mtok (${output}); add ` +
              `'${owner}' to data/rules/inverted-pricing.json only if it really publishes this`);
        }
        const cached = headRow.cached_input_per_mtok;
        if (typeof cached === 'number' && typeof input === 'number' && cached > input) {
          add('bounds.cache', id, 'cached_input_per_mtok',
            `cached_input_per_mtok (${cached}) is greater than input_per_mtok (${input})`);
        }
      }

      if (baseRow && !deepEqual(baseRow.currency, headRow.currency)) {
        add('bounds.currency', id, 'currency',
          `currency changed from ${JSON.stringify(baseRow.currency ?? null)} to ` +
            `${JSON.stringify(headRow.currency ?? null)}`,
          { base: baseRow.currency ?? null, head: headRow.currency ?? null });
      }

      // Provenance: group the changed fields by the entry provenance.fields maps
      // them to and report once per (row, entry), naming the fields it covers.
      const provenance = isRow(headRow.provenance) ? headRow.provenance : {};
      const fieldsMap = isRow(provenance.fields) ? provenance.fields : {};
      const byEntry = new Map<string, string[]>();
      for (const field of changed) {
        const raw = fieldsMap[field];
        const key = typeof raw === 'string' && raw !== '' ? raw : 'default';
        byEntry.set(key, [...(byEntry.get(key) ?? []), field]);
      }
      for (const entryKey of [...byEntry.keys()].sort()) {
        const names = (byEntry.get(entryKey) ?? []).join(', ');
        const entry = provenance[entryKey];
        if (!isRow(entry)) {
          add('provenance.fetched_at', id, entryKey,
            `field(s) ${names} resolve to provenance entry '${entryKey}', which is missing`);
          continue;
        }
        const fetchedAt = entry.fetched_at;
        if (typeof fetchedAt !== 'string' || fetchedAt < date) {
          add('provenance.fetched_at', id, entryKey,
            `field(s) ${names}: provenance '${entryKey}' fetched_at ` +
              `${JSON.stringify(fetchedAt ?? null)} is before the PR date ${date}`);
        }
        if (entry.confidence === 'secondary') continue; // secondary is exempt from the host rule
        const allowed = providerHosts[owner] ?? [];
        const source = typeof entry.source === 'string' ? entry.source : '';
        let host: string | null = null;
        try {
          host = new URL(source).host.toLowerCase();
        } catch {
          // unparsable URL: reported as an unregistered host below
        }
        if (host === null || !allowed.some((h) => host === h || host!.endsWith('.' + h))) {
          add('provenance.host', id, entryKey,
            `field(s) ${names}: provenance '${entryKey}' source host ` +
              `${JSON.stringify(host ?? (source || null))} is not registered for '${owner}' in ` +
              `data/rules/provider-hosts.json`);
        }
      }

      const lastVerified = headRow.last_verified_at;
      if (typeof lastVerified !== 'string' || lastVerified < date) {
        add('provenance.last_verified_at', id, 'last_verified_at',
          `last_verified_at ${JSON.stringify(lastVerified ?? null)} is missing or before ` +
            `the PR date ${date}`);
      }

      for (const key of ['window', 'unit'] as const) {
        const before = baseRow ? limitsMultiset(baseRow, key) : [];
        const after = limitsMultiset(headRow, key);
        if (JSON.stringify(before) === JSON.stringify(after)) continue;
        flags.push({
          rule: `limits.${key}`, id, field: 'limits_published', label: REVIEW_LABEL,
          message: `published limit ${key}s changed from [${before.join(', ')}] to [${after.join(', ')}]`,
          base: before, head: after,
        });
      }
    }

    for (const [id, baseRow] of baseMap) {
      if (headMap.has(id) || supersededHead.has(id) || isRetired(baseRow)) continue;
      add('id.removed', id, undefined,
        'row removed but no head row supersedes it and the base row was not retired');
    }
  }

  return { violations, flags };
}

// --- loading the two sides ---------------------------------------------------

function readJsonFiles(dataDir: string): LoadedFile[] {
  const out: LoadedFile[] = [];
  const walk = (dir: string): void => {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.name.endsWith('.json')) continue;
      let json: unknown;
      try {
        json = JSON.parse(readFileSync(full, 'utf8'));
      } catch (err) {
        throw new Error(`cannot parse ${full}: ${(err as Error).message}`);
      }
      out.push({ path: 'data/' + full.slice(dataDir.length + 1).split(sep).join('/'), json });
    }
  };
  walk(dataDir);
  return out;
}

/** A --*-dir argument is the data directory itself; a contained data/ child
 * directory wins, so a repo root works too. */
function filesFromDir(dir: string): LoadedFile[] {
  const abs = resolve(dir);
  try {
    const child = join(abs, 'data');
    if (statSync(child).isDirectory()) return readJsonFiles(child);
  } catch {
    // no data/ child: the argument is the data directory itself
  }
  return readJsonFiles(abs);
}

function filesFromGit(ref: string): LoadedFile[] {
  const git = (args: string[]): string =>
    execFileSync('git', args, { maxBuffer: 512 * 1024 * 1024 }).toString('utf8');
  // -z keeps git from C-quoting paths, so `show ref:<path>` still resolves them.
  const listing = git(['ls-tree', '-r', '--name-only', '-z', ref, '--', 'data/']);
  const out: LoadedFile[] = [];
  for (const path of listing.split('\0')) {
    if (!path.endsWith('.json') || path.includes('data/rules/')) continue;
    let json: unknown;
    try {
      json = JSON.parse(git(['show', `${ref}:${path}`]));
    } catch (err) {
      throw new Error(`cannot read ${path} from ${ref}: ${(err as Error).message}`);
    }
    out.push({ path, json });
  }
  return out;
}

// --- CLI ---------------------------------------------------------------------

const formatFinding = (f: Finding): string =>
  `${f.rule} ${f.id}${f.field ? '.' + f.field : ''}: ${f.message}`;

export function run(
  argv: string[],
  io: { log?: (...args: unknown[]) => void; error?: (...args: unknown[]) => void } = {}
): number {
  const log = io.log ?? console.log;
  const error = io.error ?? console.error;
  const args: { base?: string; baseDir?: string; headDir?: string; date?: string; json?: boolean } = {};
  try {
    for (let i = 0; i < argv.length; i++) {
      const eq = argv[i].indexOf('=');
      const name = eq === -1 ? argv[i] : argv[i].slice(0, eq);
      const value = (): string => {
        if (eq !== -1) return argv[i].slice(eq + 1);
        const v = argv[++i];
        if (v === undefined) throw new Error(`missing value for ${name}`);
        return v;
      };
      if (name === '--base') args.base = value();
      else if (name === '--base-dir') args.baseDir = value();
      else if (name === '--head-dir') args.headDir = value();
      else if (name === '--date') args.date = value();
      else if (name === '--json') args.json = true;
      else throw new Error(`unknown argument '${argv[i]}'`);
    }

    const date = args.date ?? todayUtc();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      throw new Error(`--date must be YYYY-MM-DD, got '${date}'`);
    }

    const headFiles = args.headDir ? filesFromDir(args.headDir) : readJsonFiles(DEFAULT_DATA_DIR);
    const baseFiles = args.baseDir ? filesFromDir(args.baseDir) : filesFromGit(args.base ?? DEFAULT_BASE_REF);
    const rules = loadRules(headFiles);
    const headRows = loadRows(headFiles);
    const { violations, flags } = checkPr(loadRows(baseFiles), headRows, {
      date, invertedProviders: rules.invertedProviders, providerHosts: rules.providerHosts,
    });

    const baseLabel = args.baseDir ?? args.base ?? DEFAULT_BASE_REF;
    if (args.json) {
      const report = { ok: violations.length === 0, date, base: baseLabel, violations, flags };
      log(JSON.stringify(report, null, 2));
    } else {
      for (const flag of flags) log(`flag ${formatFinding(flag)}`);
      for (const v of violations) error(formatFinding(v));
      if (violations.length > 0) error(`${violations.length} violation(s), ${flags.length} flag(s)`);
      else log(`ok: ${headRows.offers.size} offers, ${headRows.plans.size} plans checked`);
    }
    return violations.length === 0 ? 0 : 1;
  } catch (err) {
    error(`check-pr: ${(err as Error).message}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // exitCode, not exit(): piped stdout is async and exit() can drop the report.
  process.exitCode = run(process.argv.slice(2));
}
