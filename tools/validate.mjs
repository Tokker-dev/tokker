#!/usr/bin/env node
// Validate Tokker price-index data files against schema/pricing.v1.json plus
// dataset-wide checks a per-row schema cannot express (id uniqueness, estimate
// assumptions). Usage: npm run validate [files...] (default data/pricing.json);
// prints each problem as `file:jsonpath: message`, exits 1 if any exist.

import { readFileSync } from 'node:fs';
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

/**
 * Validate parsed documents: schema first, then dataset-wide checks.
 * @param {{file: string, doc: unknown}[]} entries
 * @param {object} [schema] defaults to the repo schema
 * @returns {{file: string, path: string, message: string}[]} every problem found
 */
export function validateDocuments(entries, schema) {
  if (schema === undefined) schema = JSON.parse(readFileSync(schemaUrl, 'utf-8'));
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const validate = ajv.compile(schema);
  const errors = [];
  for (const { file, doc } of entries) {
    if (!validate(doc)) {
      for (const e of translateErrors(validate.errors)) {
        errors.push({ file, path: e.path, message: e.message });
      }
    }
    errors.push(...checkDocument(doc, file));
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
  problems.push(...validateDocuments(entries, schema));

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
