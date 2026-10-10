#!/usr/bin/env node
// Validate Tokker price-index data files against schema/pricing.v1.json plus
// dataset-wide checks a per-row schema cannot express (id uniqueness, estimate
// assumptions). The data lives as fragments (data/offers/, data/plans/ and the
// registries beside them); data/pricing.json and the CSV exports are generated
// from them by tools/build.ts and get no fragment-specific checks.
//
// Usage: npm run validate [files...] — with no files it validates every
// fragment plus data/pricing.json; files are classified by their data/ path
// (a shard is checked against its slice of the schema, its file name, its row
// order and its canonical formatting). Prints each problem as
// `file:jsonpath: message`, exits 1 if any exist.

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const SCHEMA_FILE = 'schema/pricing.v1.json';
const DEFAULT_DATA_FILE = 'data/pricing.json';
const schemaUrl = new URL('../' + SCHEMA_FILE, import.meta.url);
const defaultDataUrl = new URL('../' + DEFAULT_DATA_FILE, import.meta.url);

// A numeric estimate must say how it was derived: a named, versioned profile —
// STANDARD is the dataset's (docs/plan.md §2 plans the other three) — or an
// explicit statement that the vendor publishes the token allowance itself.
export const ESTIMATE_PROFILES = ['standard', 'agentic-coding-v1', 'light-chat', 'heavy-agentic'];
export const VENDOR_DIRECT_ASSUMPTIONS = [
  'vendor quotes raw tokens',
  'vendor counts tokens directly',
];

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/** One path step: [0] for indexes, .ident for identifiers, ["odd key"] else. */
function renderPart(part) {
  if (/^\d+$/.test(part)) return `[${part}]`;
  if (IDENTIFIER.test(part)) return `.${part}`;
  return `[${JSON.stringify(part)}]`;
}

/** Translate a JSON Pointer (ajv instancePath) to a JSONPath like $.a[0].b. */
export function pointerToJsonPath(pointer) {
  if (!pointer) return '$';
  const trimmed = pointer.startsWith('/') ? pointer.slice(1) : pointer;
  const unescaped = trimmed
    .split('/')
    .map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
  return `$${unescaped.map(renderPart).join('')}`;
}

function joinPath(base, key) {
  return base + renderPart(key);
}

const TYPE_NOUNS = {
  number: 'a number',
  integer: 'an integer',
  string: 'a string',
  null: 'null',
  boolean: 'a boolean',
  array: 'an array',
  object: 'an object',
};

/** One readable fragment of what the schema wants at a path. */
function describeError(err) {
  const params = err.params ?? {};
  if (err.keyword === 'type') {
    const types = Array.isArray(params.type) ? params.type : [params.type];
    return types.map((t) => TYPE_NOUNS[t] ?? String(t)).join(' or ');
  }
  if (err.keyword === 'const') {
    return params.allowedValue === 'unknown'
      ? 'the string "unknown"'
      : `the value ${JSON.stringify(params.allowedValue)}`;
  }
  if (err.keyword === 'enum') {
    return `one of: ${(params.allowedValues ?? []).map((v) => JSON.stringify(v)).join(', ')}`;
  }
  if (err.keyword === 'minimum' || err.keyword === 'maximum' || err.keyword === 'exclusiveMinimum') {
    const op = err.keyword === 'minimum' ? '>=' : err.keyword === 'maximum' ? '<=' : '>';
    return `${op} ${params.limit}`;
  }
  if (err.keyword === 'minLength') return `a string of at least ${params.limit} character(s)`;
  if (err.keyword === 'pattern') return `a string matching ${params.pattern}`;
  return err.message ?? 'is invalid';
}

/** Attach bound fragments (">= 0") to the preceding type noun: "a number (>= 0)". */
function mergeBounds(fragments) {
  const out = [];
  for (const fragment of fragments) {
    const prev = out[out.length - 1];
    if (/^[<>]=? /.test(fragment) && prev) out[out.length - 1] = `${prev} (${fragment})`;
    else out.push(fragment);
  }
  return out;
}

/**
 * Turn raw ajv errors into {path, message} pairs: readable JSONPaths, the
 * missing/extra property named in the path, and anyOf unions collapsed to one
 * "must be X or Y" message per path.
 */
export function translateErrors(ajvErrors) {
  const raw = (ajvErrors ?? []).map((err) => ({
    instancePath: err.instancePath ?? '',
    keyword: err.keyword,
    message: err.message ?? 'is invalid',
    params: err.params ?? {},
  }));

  // Drop anyOf/oneOf parent errors where the branches already reported, and
  // remember which paths are unions so their leaves merge into one message.
  const unionPaths = new Set(
    raw.filter((e) => ['anyOf', 'oneOf'].includes(e.keyword)).map((e) => e.instancePath)
  );
  const byPath = new Map();
  for (const e of raw) {
    if (['anyOf', 'oneOf'].includes(e.keyword) && raw.some((c) => c !== e && c.instancePath === e.instancePath)) continue;
    if (!byPath.has(e.instancePath)) byPath.set(e.instancePath, []);
    byPath.get(e.instancePath).push(e);
  }

  const out = [];
  for (const [instancePath, errs] of byPath) {
    const path = pointerToJsonPath(instancePath);

    if (unionPaths.has(instancePath)) {
      const fragments = mergeBounds([...new Set(errs.map(describeError))]);
      out.push({ path, message: `must be ${fragments.join(' or ')}` });
      continue;
    }

    const typeErr = errs.find((e) => e.keyword === 'type');
    for (const e of errs) {
      if (e.keyword === 'required') {
        if (typeErr) continue; // the value is not even an object; skip the pile-up
        out.push({
          path: joinPath(path, String(e.params.missingProperty)),
          message: `required property '${e.params.missingProperty}' is missing`,
        });
      } else if (e.keyword === 'additionalProperties') {
        out.push({
          path: joinPath(path, String(e.params.additionalProperty)),
          message: `unknown property '${e.params.additionalProperty}' is not allowed`,
        });
      } else if (e.keyword === 'type') {
        if (typeErr === e) out.push({ path, message: `must be ${describeError(e)}` });
      } else if (e.keyword === 'propertyNames') {
        out.push({ path, message: `property name must match ${e.params.pattern ?? e.message}` });
      } else {
        out.push({ path, message: `must be ${describeError(e)}` });
      }
    }
  }
  return out;
}

function namesProfile(assumption) {
  const a = String(assumption).trim().toLowerCase();
  return (
    ESTIMATE_PROFILES.some((p) => a === p || a.startsWith(p + ':')) ||
    VENDOR_DIRECT_ASSUMPTIONS.some((p) => a.startsWith(p))
  );
}

/** Subscription rows with a numeric estimate must name an assumption profile. */
function checkSubscriptionEstimates(rows, file, arrayName) {
  const errors = [];
  (Array.isArray(rows) ? rows : []).forEach((row, i) => {
    const numeric =
      typeof row?.est_tokens_per_month === 'number' ||
      typeof row?.est_usd_per_mtok_at_full_use === 'number';
    if (!numeric) return;
    const assumption = typeof row?.estimate_assumption === 'string' ? row.estimate_assumption : '';
    if (namesProfile(assumption)) return;
    errors.push({
      file,
      path: `$.${arrayName}[${i}].estimate_assumption`,
      message:
        `a numeric est_tokens_per_month/est_usd_per_mtok_at_full_use needs an ` +
        `estimate_assumption naming a profile (${ESTIMATE_PROFILES.join(', ')}) ` +
        `or stating the vendor publishes tokens directly (${VENDOR_DIRECT_ASSUMPTIONS.join('; ')})`,
    });
  });
  return errors;
}

/** Per-document checks the JSON Schema cannot express. */
function checkDocument(doc, file) {
  return checkSubscriptionEstimates(doc?.subscriptions, file, 'subscriptions');
}

/** Row ids are unique across api_offers + subscriptions; provider ids likewise. */
function indexIds(entries, errors) {
  const seen = { row: new Map(), provider: new Map() };
  const index = (kind, id, file, path) => {
    const first = seen[kind].get(id);
    if (first) {
      errors.push({
        file,
        path,
        message: `duplicate ${kind} id '${id}' (first occurrence at ${first.file} ${first.path})`,
      });
    } else {
      seen[kind].set(id, { file, path });
    }
  };
  for (const entry of entries) {
    const doc = entry.idDoc !== undefined ? entry.idDoc : entry.doc;
    // Fragments name the arrays they contribute (idKeys); full documents
    // contribute all three.
    const keys =
      entry.idKeys ?? [['api_offers', 'row'], ['subscriptions', 'row'], ['providers', 'provider']];
    for (const [key, kind] of keys) {
      (Array.isArray(doc?.[key]) ? doc[key] : []).forEach((row, i) => {
        if (typeof row?.id === 'string') index(kind, row.id, entry.file, `$.${key}[${i}].id`);
      });
    }
  }
}

// -- fragments ---------------------------------------------------------------

/** Plain code-unit string comparison — never localeCompare (locale-dependent). */
function byPlainString(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Which shape a file has, read from its `data/...` segment so both
 * repo-relative and absolute paths classify (including test fixtures laid out
 * like data/ in a tmpdir). Anything unrecognised is a full document.
 */
function classifyPath(file) {
  const parts = file.split(/[\\/]/);
  const at = parts.lastIndexOf('data');
  if (at === -1) return 'document';
  const rest = parts.slice(at + 1);
  if (rest.length === 2 && rest[0] === 'offers' && rest[1].endsWith('.json')) return 'offers';
  if (rest.length === 2 && rest[0] === 'plans' && rest[1].endsWith('.json')) return 'plans';
  if (rest.length === 1 && ['providers.json', 'sources.json', 'fx.json', 'meta.json'].includes(rest[0])) {
    return rest[0].replace('.json', '');
  }
  return 'document';
}

/**
 * Per-fragment JSON Schemas. There are no $defs for these shapes, so they are
 * built here and $ref the root schema's $defs (the root is registered with ajv
 * under its $id first). meta.json mirrors the root schema's constraints for the
 * five keys it carries.
 */
function fragmentSchemas(rootSchema) {
  const def = (name) => ({ $ref: `${rootSchema.$id}#/$defs/${name}` });
  return {
    offers: {
      type: 'object',
      additionalProperties: false,
      required: ['provider_id', 'offers'],
      properties: { provider_id: def('slug'), offers: { type: 'array', items: def('api_offer') } },
    },
    plans: {
      type: 'object',
      additionalProperties: false,
      required: ['vendor_id', 'plans'],
      properties: { vendor_id: def('slug'), plans: { type: 'array', items: def('subscription') } },
    },
    providers: { type: 'array', items: def('provider') },
    sources: { type: 'array', items: def('source') },
    fx: def('fx'),
    meta: {
      type: 'object',
      additionalProperties: false,
      required: ['schema_version', 'dataset', 'license', 'conventions', 'research_notes'],
      properties: {
        schema_version: { type: 'string', pattern: '^1\\.\\d+\\.\\d+$' },
        dataset: { type: 'string', minLength: 1 },
        license: { type: 'string', minLength: 1 },
        conventions: { type: 'object', additionalProperties: { type: 'string' } },
        research_notes: {
          type: 'object',
          propertyNames: { pattern: '^[A-Za-z0-9][A-Za-z0-9._-]*$' },
          additionalProperties: { type: 'string' },
        },
      },
    },
  };
}

/**
 * Fragment-only hand checks: file-name/wrapper agreement, in-file ordering and
 * canonical bytes. Paths use the fragment's own shape ($.offers[i].id) rather
 * than the assembled document's ($.api_offers[i].id).
 */
function checkFragment(entry) {
  const { file, kind, doc, raw } = entry;
  const errors = [];

  // Fragments are hand-edited inputs, so their bytes are pinned: build output
  // (and every diff) stays clean. Generated files are exempt.
  const canonical = () => {
    if (typeof raw === 'string' && raw !== JSON.stringify(doc, null, 2) + '\n') {
      errors.push({
        file,
        path: '$',
        message:
          'file is not in canonical form (2-space indent, one trailing newline, nothing else); ' +
          'rewrite it in exactly that form',
      });
    }
  };

  const ascendingIds = (rows, renderPath) => {
    rows.forEach((row, i) => {
      if (i === 0) return;
      const prev = rows[i - 1]?.id;
      const id = row?.id;
      if (typeof prev === 'string' && typeof id === 'string' && !(prev < id)) {
        errors.push({
          file,
          path: renderPath(i),
          message: `ids must be strictly ascending (sorted, unique): '${id}' does not follow '${prev}'`,
        });
      }
    });
  };

  const rowsOf = (name) => (Array.isArray(doc?.[name]) ? doc[name] : []);

  if (kind === 'offers' || kind === 'plans') {
    const ownerKey = kind === 'offers' ? 'provider_id' : 'vendor_id';
    const arrayName = kind === 'offers' ? 'offers' : 'plans';
    const stem = file.split(/[\\/]/).pop().replace(/\.json$/, '');
    if (doc?.[ownerKey] !== stem) {
      errors.push({
        file,
        path: `$.${ownerKey}`,
        message: `'${doc?.[ownerKey]}' does not match the file name '${stem}'`,
      });
    }
    rowsOf(arrayName).forEach((row, i) => {
      if (row && row[ownerKey] !== doc?.[ownerKey]) {
        errors.push({
          file,
          path: `$.${arrayName}[${i}].${ownerKey}`,
          message: `'${row[ownerKey]}' does not match the fragment ${ownerKey} '${doc?.[ownerKey]}'`,
        });
      }
    });
    ascendingIds(rowsOf(arrayName), (i) => `$.${arrayName}[${i}].id`);
    canonical();
  } else if (kind === 'providers') {
    ascendingIds(Array.isArray(doc) ? doc : [], (i) => `$[${i}].id`);
    canonical();
  } else if (kind === 'sources') {
    const rows = Array.isArray(doc) ? doc : [];
    const tupleOf = (row) =>
      [row?.provider_id, row?.part, row?.url].map((v) => (typeof v === 'string' ? v : ''));
    const render = (tuple) => `(${tuple.map((t) => `'${t}'`).join(', ')})`;
    const compare = (a, b) => {
      for (let i = 0; i < a.length; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
      }
      return 0;
    };
    const firstAt = new Map();
    rows.forEach((row, i) => {
      const tuple = tupleOf(row);
      const key = JSON.stringify(tuple);
      if (firstAt.has(key)) {
        errors.push({
          file,
          path: `$[${i}]`,
          message: `duplicate source (provider_id, part, url) ${render(tuple)}; first occurrence at $[${firstAt.get(key)}]`,
        });
      } else {
        firstAt.set(key, i);
      }
      if (i > 0 && compare(tupleOf(rows[i - 1]), tuple) > 0) {
        errors.push({
          file,
          path: `$[${i}]`,
          message: `sources must be sorted by (provider_id, part, url): ${render(tuple)} does not follow ${render(tupleOf(rows[i - 1]))}`,
        });
      }
    });
    canonical();
  } else if (kind === 'fx') {
    const keys = Object.keys(doc?.rates ?? {});
    for (let i = 1; i < keys.length; i++) {
      if (!(keys[i - 1] < keys[i])) {
        errors.push({
          file,
          path: '$.rates',
          message: `rate keys must be sorted ascending: '${keys[i]}' does not follow '${keys[i - 1]}'`,
        });
      }
    }
    canonical();
  } else {
    canonical(); // meta
  }
  return errors;
}

/** How a fragment's rows join the pool-wide id index. */
function fragmentIdView(entry) {
  switch (entry.kind) {
    case 'offers':
      return { idDoc: { offers: entry.doc?.offers }, idKeys: [['offers', 'row']] };
    case 'plans':
      return { idDoc: { plans: entry.doc?.plans }, idKeys: [['plans', 'row']] };
    case 'providers':
      return { idDoc: { providers: entry.doc }, idKeys: [['providers', 'provider']] };
    default:
      return { idDoc: {}, idKeys: [] };
  }
}

/**
 * Validate one pool of documents: each against the root schema (untagged or
 * kind 'document') or its fragment wrapper schema, then the pool-wide checks —
 * per-fragment hand checks and id uniqueness across the whole pool.
 * @returns {{file: string, path: string, message: string}[]} every problem found
 */
function validatePool(entries, schema) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  if (schema.$id) ajv.addSchema(schema);
  const rootValidate = schema.$id ? ajv.getSchema(schema.$id) : ajv.compile(schema);
  const wrappers = fragmentSchemas(schema);
  const validators = new Map();
  const validatorFor = (entry) => {
    if (entry.kind === undefined || entry.kind === 'document') return rootValidate;
    if (!validators.has(entry.kind)) validators.set(entry.kind, ajv.compile(wrappers[entry.kind]));
    return validators.get(entry.kind);
  };

  const errors = [];
  for (const entry of entries) {
    const validate = validatorFor(entry);
    if (!validate(entry.doc)) {
      for (const e of translateErrors(validate.errors)) {
        errors.push({ file: entry.file, path: e.path, message: e.message });
      }
    }
    if (entry.kind === 'plans') {
      errors.push(...checkSubscriptionEstimates(entry.doc?.plans, entry.file, 'plans'));
    } else if (entry.kind === undefined || entry.kind === 'document') {
      errors.push(...checkDocument(entry.doc, entry.file));
    }
  }
  for (const entry of entries) {
    if (entry.kind !== undefined && entry.kind !== 'document') errors.push(...checkFragment(entry));
  }
  indexIds(
    entries.map((entry) =>
      entry.kind !== undefined && entry.kind !== 'document' ? { ...entry, ...fragmentIdView(entry) } : entry
    ),
    errors
  );
  return errors;
}

/**
 * Validate parsed documents: schema first, then dataset-wide checks.
 * @param {{file: string, doc: unknown}[]} entries
 * @param {object} [schema] defaults to the repo schema
 * @returns {{file: string, path: string, message: string}[]} every problem found
 */
export function validateDocuments(entries, schema) {
  if (schema === undefined) schema = JSON.parse(readFileSync(schemaUrl, 'utf-8'));
  return validatePool(entries.map((entry) => ({ ...entry, kind: 'document' })), schema);
}

/** Render one error the way the CLI prints it: `file:jsonpath: message`. */
export function formatError(error) {
  return `${error.file}:${error.path}: ${error.message}`;
}

/** Every fragment file in sorted path order, then the generated document. */
function defaultFiles() {
  const offersUrl = new URL('../data/offers/', import.meta.url);
  const plansUrl = new URL('../data/plans/', import.meta.url);
  if (!existsSync(offersUrl) || !existsSync(plansUrl)) {
    return [{ file: DEFAULT_DATA_FILE, url: defaultDataUrl }];
  }
  const jsonFiles = (relDir) =>
    readdirSync(new URL(`../${relDir}/`, import.meta.url))
      .filter((name) => name.endsWith('.json'))
      .sort(byPlainString)
      .map((name) => ({ file: `${relDir}/${name}`, url: new URL(name, new URL(`../${relDir}/`, import.meta.url)) }));
  const fragments = [
    ...jsonFiles('data/offers'),
    ...jsonFiles('data/plans'),
    { file: 'data/providers.json', url: new URL('../data/providers.json', import.meta.url) },
    { file: 'data/sources.json', url: new URL('../data/sources.json', import.meta.url) },
    { file: 'data/fx.json', url: new URL('../data/fx.json', import.meta.url) },
    { file: 'data/meta.json', url: new URL('../data/meta.json', import.meta.url) },
  ].sort((a, b) => byPlainString(a.file, b.file));
  return [...fragments, { file: DEFAULT_DATA_FILE, url: defaultDataUrl }];
}

export function run(argv, { log = console.log, error = console.error } = {}) {
  const problems = [];
  const isDefault = argv.length === 0;
  const files = isDefault
    ? defaultFiles()
    : argv.map((arg) => ({ file: arg, url: pathToFileURL(resolve(arg)) }));

  let schema;
  try {
    schema = JSON.parse(readFileSync(schemaUrl, 'utf-8'));
  } catch (err) {
    error(formatError({ file: SCHEMA_FILE, path: '$', message: `cannot read schema: ${err.message}` }));
    return 1;
  }

  const entries = [];
  for (const { file, url } of files) {
    try {
      const raw = readFileSync(url, 'utf-8');
      entries.push({ file, raw, doc: JSON.parse(raw), kind: classifyPath(file) });
    } catch (err) {
      problems.push({ file, path: '$', message: `cannot read file: ${err.message}` });
    }
  }

  if (isDefault) {
    // Default view: all fragments share one pool (ids stay unique across
    // shards); the generated document gets its own pool, since it repeats the
    // fragments' rows and would otherwise collide with them as duplicates.
    problems.push(...validatePool(entries.filter((e) => e.kind !== 'document'), schema));
    for (const entry of entries.filter((e) => e.kind === 'document')) {
      problems.push(...validatePool([entry], schema));
    }
  } else {
    // Explicit files share one pool, whatever their kind.
    problems.push(...validatePool(entries, schema));
  }

  if (problems.length > 0) {
    for (const p of problems) error(formatError(p));
    error(`${problems.length} error(s) in ${entries.length}/${files.length} file(s)`);
    return 1;
  }
  for (const { file } of files) log(`ok ${file}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exit(run(process.argv.slice(2)));
}
