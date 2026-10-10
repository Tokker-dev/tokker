#!/usr/bin/env node
// Validate Tokker price-index data files against schema/pricing.v1.json plus
// dataset-wide checks a per-row schema cannot express (id uniqueness, estimate
// assumptions, and — via the model registry — that every api_offers[].model_slug
// is a known model with a matching creator). Usage: npm run validate [files...]
// (default data/pricing.json); prints each problem as `file:jsonpath: message`,
// exits 1 if any exist.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { CREATORS_FILE, MODELS_FILE, checkRegistry, loadRegistry } from './slugs.mjs';

import { offerUsd, subscriptionUsd } from './build.mjs';
import { isSupportedCurrency } from './fx.mjs';

const SCHEMA_FILE = 'schema/pricing.v1.json';
const DEFAULT_DATA_FILE = 'data/pricing.json';
const FX_DATA_FILE = 'data/fx.json';
const MODELS_SCHEMA_FILE = 'schema/models.v1.json';
const CREATORS_SCHEMA_FILE = 'schema/creators.v1.json';
const schemaUrl = new URL('../' + SCHEMA_FILE, import.meta.url);
const defaultDataUrl = new URL('../' + DEFAULT_DATA_FILE, import.meta.url);
const fxDataUrl = new URL('../' + FX_DATA_FILE, import.meta.url);
const registrySchemaUrls = [
  [MODELS_FILE, new URL('../' + MODELS_SCHEMA_FILE, import.meta.url)],
  [CREATORS_FILE, new URL('../' + CREATORS_SCHEMA_FILE, import.meta.url)],
];

// A numeric estimate must say how it was derived: a named, versioned profile —
// STANDARD is the dataset's (docs/plan.md §2 plans the other three) — or an
// explicit statement that the vendor publishes the token allowance itself.
export const ESTIMATE_PROFILES = ['standard', 'agentic-coding-v1', 'light-chat', 'heavy-agentic', 'light-chat-v1', 'heavy-agentic-v1'];
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

/** Render a value the way the usd-drift message quotes it. */
function renderValue(value) {
  return typeof value === 'string' ? JSON.stringify(value) : String(value);
}

/**
 * A row's usd block is build output: every field must equal what
 * tools/build.mjs computes from the native values and the document's fx block
 * (docs/fx.md) — a hand-edited usd value is a drift error.
 */
function checkRowUsd(row, basePath, fx, compute, file, errors) {
  const currency = row?.currency;
  if (typeof currency === 'string' && !isSupportedCurrency(currency, fx)) {
    errors.push({
      file,
      path: `${basePath}.currency`,
      message: `currency "${currency}" has no rate in fx (unsupported; see docs/fx.md)`,
    });
    return;
  }
  let expected;
  try {
    expected = compute(row, fx);
  } catch {
    return; // an unsupported currency is already reported above
  }
  const actual = row?.usd;
  if (actual === null || typeof actual !== 'object') return; // the schema reports the shape
  const fields = new Set([...Object.keys(expected), ...Object.keys(actual)]);
  for (const field of fields) {
    if (!(field in expected)) {
      errors.push({
        file,
        path: `${basePath}.usd.${field}`,
        message: `build does not produce '${field}' from native values and fx; run npm run build`,
      });
    } else if (!Object.is(actual[field], expected[field])) {
      errors.push({
        file,
        path: `${basePath}.usd.${field}`,
        message: `is ${renderValue(actual[field])}, build computes ${renderValue(expected[field])} ` +
          'from native values and fx; run npm run build',
      });
    }
  }
}

/** Per-document checks the JSON Schema cannot express. */
function checkDocument(doc, file) {
  const errors = [];
  const subs = Array.isArray(doc?.subscriptions) ? doc.subscriptions : [];
  subs.forEach((row, i) => {
    const numeric =
      typeof row?.est_tokens_per_month === 'number' ||
      typeof row?.est_usd_per_mtok_at_full_use === 'number';
    if (!numeric) return;
    const assumption = typeof row?.estimate_assumption === 'string' ? row.estimate_assumption : '';
    if (namesProfile(assumption)) return;
    errors.push({
      file,
      path: `$.subscriptions[${i}].estimate_assumption`,
      message:
        `a numeric est_tokens_per_month/est_usd_per_mtok_at_full_use needs an ` +
        `estimate_assumption naming a profile (${ESTIMATE_PROFILES.join(', ')}) ` +
        `or stating the vendor publishes tokens directly (${VENDOR_DIRECT_ASSUMPTIONS.join('; ')})`,
    });
  });

  // Check model_weights constraints
  subs.forEach((row, i) => {
    const weights = Array.isArray(row?.model_weights) ? row.model_weights : [];
    const included = new Set(Array.isArray(row?.models_included) ? row.models_included : []);

    if (weights.length > 0) {
      // If model_weights is non-empty and est_tokens_per_month is numeric, default_model must be set
      const hasNumericEstimate = typeof row?.est_tokens_per_month === 'number';
      if (hasNumericEstimate && typeof row?.default_model !== 'string') {
        errors.push({
          file,
          path: `$.subscriptions[${i}].default_model`,
          message: `default_model is required when model_weights is non-empty and est_tokens_per_month is numeric`,
        });
      }

      // Every model in model_weights must be in models_included
      weights.forEach((weight, j) => {
        if (typeof weight?.model === 'string' && !included.has(weight.model)) {
          errors.push({
            file,
            path: `$.subscriptions[${i}].model_weights[${j}].model`,
            message: `model '${weight.model}' is not in models_included`,
          });
        }
      });
    }
  });
  const fx = doc?.fx;
  if (fx !== null && typeof fx === 'object' && typeof fx.base === 'string' && fx.rates !== null && typeof fx.rates === 'object') {
    (Array.isArray(doc.api_offers) ? doc.api_offers : []).forEach((row, i) => {
      checkRowUsd(row, `$.api_offers[${i}]`, fx, offerUsd, file, errors);
    });
    subs.forEach((row, i) => {
      checkRowUsd(row, `$.subscriptions[${i}]`, fx, subscriptionUsd, file, errors);
    });
  }
  return errors;
}

/**
 * Every api_offers[].model_slug must be a known model whose creator matches the
 * row's model_creator, and every derived key must be a known slug.
 */
function checkAgainstRegistry(doc, file, modelBySlug) {
  const errors = [];
  const offers = Array.isArray(doc?.api_offers) ? doc.api_offers : [];
  offers.forEach((row, i) => {
    const slug = row?.model_slug;
    const model = typeof slug === 'string' ? modelBySlug.get(slug) : undefined;
    if (!model) {
      errors.push({
        file,
        path: `$.api_offers[${i}].model_slug`,
        message: `model_slug '${slug}' is not in ${MODELS_FILE}`,
      });
      return;
    }
    if (row?.model_creator !== model.creator) {
      errors.push({
        file,
        path: `$.api_offers[${i}].model_creator`,
        message:
          `model_creator '${row?.model_creator}' does not match ${MODELS_FILE} ` +
          `creator '${model.creator}' for model '${slug}'`,
      });
    }
  });
  const derived = doc?.derived?.cheapest_provider_per_model;
  if (derived !== undefined && typeof derived === 'object' && !Array.isArray(derived)) {
    for (const key of Object.keys(derived)) {
      if (!modelBySlug.has(key)) {
        errors.push({
          file,
          path: `$.derived.cheapest_provider_per_model[${JSON.stringify(key)}]`,
          message: `derived key '${key}' is not a known model_slug`,
        });
      }
    }
  }
  return errors;
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
  for (const { file, doc } of entries) {
    for (const [key, kind] of [['api_offers', 'row'], ['subscriptions', 'row'], ['providers', 'provider']]) {
      (Array.isArray(doc?.[key]) ? doc[key] : []).forEach((row, i) => {
        if (typeof row?.id === 'string') index(kind, row.id, file, `$.${key}[${i}].id`);
      });
    }
  }
}

/** Deep equality ignoring key order (both values are JSON values). */
function deepEqualJson(a, b) {
  const canonical = (v) => JSON.stringify(v, (key, value) => {
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      return Object.fromEntries(Object.entries(value).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)));
    }
    return value;
  });
  return canonical(a) === canonical(b);
}

/**
 * Validate the registry documents against their schemas and run the registry
 * consistency checks. Attributed to the registry files themselves.
 */
function checkRegistryDocuments(registry, ajv) {
  const errors = [];
  const docs = { [MODELS_FILE]: { models: registry.models }, [CREATORS_FILE]: { creators: registry.creators } };
  for (const [file, schemaUrl] of registrySchemaUrls) {
    const validate = ajv.compile(JSON.parse(readFileSync(schemaUrl, 'utf-8')));
    if (!validate(docs[file])) {
      for (const e of translateErrors(validate.errors)) {
        errors.push({ file, path: e.path, message: e.message });
      }
    }
  }
  errors.push(...checkRegistry(registry));
  return errors;
}

/**
 * Validate parsed documents: schema first, then dataset-wide checks.
 * @param {{file: string, doc: unknown}[]} entries
 * @param {object} [schema] defaults to the repo schema
 * @param {{models: object[], creators: object[]}} [registry] defaults to
 *   loading data/models.json + data/creators.json from the repo
 * @returns {{file: string, path: string, message: string}[]} every problem found
 */
export function validateDocuments(entries, schema, registry) {
  if (schema === undefined) schema = JSON.parse(readFileSync(schemaUrl, 'utf-8'));
  if (registry === undefined) registry = loadRegistry();
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const validate = ajv.compile(schema);
  const errors = [];
  if (registry) errors.push(...checkRegistryDocuments(registry, ajv));
  const modelBySlug = registry
    ? new Map(registry.models.map((m) => [m.slug, m]).filter(([slug]) => typeof slug === 'string'))
    : null;
  for (const { file, doc } of entries) {
    if (!validate(doc)) {
      for (const e of translateErrors(validate.errors)) {
        errors.push({ file, path: e.path, message: e.message });
      }
    }
    errors.push(...checkDocument(doc, file));
    if (modelBySlug) errors.push(...checkAgainstRegistry(doc, file, modelBySlug));
  }
  indexIds(entries, errors);
  return errors;
}

/** Render one error the way the CLI prints it: `file:jsonpath: message`. */
export function formatError(error) {
  return `${error.file}:${error.path}: ${error.message}`;
}

export function run(argv, { log = console.log, error = console.error } = {}) {
  const problems = [];
  const files =
    argv.length > 0
      ? argv.map((arg) => ({ file: arg, url: pathToFileURL(resolve(arg)) }))
      : [{ file: DEFAULT_DATA_FILE, url: defaultDataUrl }];

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
      entries.push({ file, doc: JSON.parse(readFileSync(url, 'utf-8')) });
    } catch (err) {
      problems.push({ file, path: '$', message: `cannot read file: ${err.message}` });
    }
  }

  let registry;
  try {
    registry = loadRegistry();
  } catch (err) {
    error(formatError({ file: MODELS_FILE, path: '$', message: `cannot read registry: ${err.message}` }));
    return 1;
  }
  try {
    problems.push(...validateDocuments(entries, schema, registry));
  } catch (err) {
    error(formatError({ file: SCHEMA_FILE, path: '$', message: `cannot run validation: ${err.message}` }));
    return 1;
  }

  // The dataset holds one dated rate set; every document's fx block must be
  // exactly what data/fx.json holds (docs/fx.md).
  let fxBlock;
  try {
    fxBlock = JSON.parse(readFileSync(fxDataUrl, 'utf-8'));
  } catch (err) {
    if (err?.code !== 'ENOENT') {
      problems.push({ file: FX_DATA_FILE, path: '$', message: `cannot read file: ${err.message}` });
    }
  }
  if (fxBlock !== undefined) {
    for (const { file, doc } of entries) {
      if (doc?.fx === undefined) continue;
      if (typeof doc.fx === 'object' && doc.fx !== null && !deepEqualJson(doc.fx, fxBlock)) {
        problems.push({
          file,
          path: '$.fx',
          message: `does not match ${FX_DATA_FILE} (base/date/source/rates must be one dated rate set); run npm run fx && npm run build`,
        });
      }
    }
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
