// Model/creator registry helpers: load data/models.json + data/creators.json,
// normalise a source's model name to the canonical slug, and check the registry
// itself for consistency errors. Matching is exact on a canonical slug or an
// alias after trim + lowercase only — an extractor must never guess, so there
// is no fuzzy matching and no dot/dash repair: anything else is "unmapped".

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const DEFAULT_REGISTRY_DIR = fileURLToPath(new URL('../data', import.meta.url));
export const MODELS_FILE = 'data/models.json';
export const CREATORS_FILE = 'data/creators.json';

/** The string a normaliser returns when nothing in the registry matches. */
export const UNMAPPED = 'unmapped';

/** Map '.' to '-' so look-alike slugs (a-1 vs a.1) can be detected. */
export function dashFold(slug) {
  return slug.replace(/\./g, '-');
}

/**
 * Read the registry from a directory (default: the repo's data/).
 * @param {string} [dir]
 * @returns {{models: object[], creators: object[]}}
 */
export function loadRegistry(dir = DEFAULT_REGISTRY_DIR) {
  const models = JSON.parse(readFileSync(`${dir}/models.json`, 'utf-8')).models;
  const creators = JSON.parse(readFileSync(`${dir}/creators.json`, 'utf-8')).creators;
  if (!Array.isArray(models) || !Array.isArray(creators)) {
    throw new Error('registry files must hold {"models": [...]} / {"creators": [...]}');
  }
  return { models, creators };
}

/**
 * Build a name -> slug resolver over the model list. Exact match on canonical
 * slug first, then on any alias; both after trim + lowercase. No other
 * transformation is ever applied.
 * @param {{slug: string, aliases?: string[]}[]} models
 * @returns {(name: unknown) => string} canonical slug or "unmapped"
 */
export function createNormaliser(models) {
  const bySlug = new Map();
  const byAlias = new Map();
  for (const model of models ?? []) {
    if (typeof model?.slug === 'string') bySlug.set(model.slug.trim().toLowerCase(), model.slug);
  }
  for (const model of models ?? []) {
    for (const alias of model.aliases ?? []) {
      if (typeof alias !== 'string') continue;
      const key = alias.trim().toLowerCase();
      if (!byAlias.has(key)) byAlias.set(key, model.slug);
    }
  }
  return function normalise(name) {
    if (typeof name !== 'string') return UNMAPPED;
    const key = name.trim().toLowerCase();
    if (bySlug.has(key)) return bySlug.get(key);
    if (byAlias.has(key)) return byAlias.get(key);
    return UNMAPPED;
  };
}

/**
 * Registry-wide consistency checks a per-entry schema cannot express.
 * @param {{models: object[], creators: object[]}} registry
 * @returns {{file: string, path: string, message: string}[]} every problem found
 */
export function checkRegistry(registry) {
  const errors = [];
  const models = Array.isArray(registry?.models) ? registry.models : [];
  const creators = Array.isArray(registry?.creators) ? registry.creators : [];
  const creatorIds = new Set(creators.map((c) => c?.id).filter((id) => typeof id === 'string'));

  const firstSlug = new Map();
  const foldedSlug = new Map();
  models.forEach((model, i) => {
    const slug = model?.slug;
    if (typeof slug !== 'string') return;
    const at = `$.models[${i}].slug`;
    const first = firstSlug.get(slug);
    if (first) {
      errors.push({ file: MODELS_FILE, path: at, message: `duplicate model slug '${slug}' (first occurrence at ${first})` });
    } else {
      firstSlug.set(slug, at);
    }
    const folded = dashFold(slug);
    const other = foldedSlug.get(folded);
    if (other !== undefined && other !== slug) {
      errors.push({
        file: MODELS_FILE,
        path: at,
        message: `model slugs '${other}' and '${slug}' differ only by '.' vs '-' and are indistinguishable to a normaliser`,
      });
    } else if (other === undefined) {
      foldedSlug.set(folded, slug);
    }
  });
  const slugSet = new Set(firstSlug.keys());

  const aliasOwner = new Map();
  models.forEach((model, i) => {
    const slug = model?.slug;
    (Array.isArray(model?.aliases) ? model.aliases : []).forEach((alias, j) => {
      if (typeof alias !== 'string') return;
      const key = alias.trim().toLowerCase();
      const at = `$.models[${i}].aliases[${j}]`;
      const owner = aliasOwner.get(key);
      if (owner !== undefined && owner !== slug) {
        errors.push({
          file: MODELS_FILE,
          path: at,
          message: `alias '${alias}' maps to two models ('${owner}' and '${slug}')`,
        });
      } else if (owner === undefined) {
        aliasOwner.set(key, slug);
      }
      if (key !== slug && slugSet.has(key)) {
        errors.push({
          file: MODELS_FILE,
          path: at,
          message: `alias '${alias}' equals another model's slug ('${key}')`,
        });
      }
    });
  });

  models.forEach((model, i) => {
    const slug = model?.slug;
    if (typeof slug !== 'string') return;
    if (!creatorIds.has(model?.creator)) {
      errors.push({
        file: MODELS_FILE,
        path: `$.models[${i}].creator`,
        message: `model '${slug}' creator '${model?.creator}' is not in ${CREATORS_FILE}`,
      });
    }
    const supersedes = model?.supersedes;
    if (supersedes !== undefined && !slugSet.has(supersedes) && !aliasOwner.has(supersedes)) {
      errors.push({
        file: MODELS_FILE,
        path: `$.models[${i}].supersedes`,
        message: `model '${slug}' supersedes '${supersedes}', which is not a known slug or alias`,
      });
    }
    // A model's display name must not normalise into another model's namespace:
    // it would make two models share one resolved name.
    if (typeof model?.name === 'string') {
      const key = model.name.trim().toLowerCase();
      const nameOfOther =
        slugSet.has(key) && key !== slug
          ? { kind: 'slug', owner: key }
          : aliasOwner.has(key) && aliasOwner.get(key) !== slug
            ? { kind: 'alias', owner: aliasOwner.get(key) }
            : undefined;
      if (nameOfOther) {
        errors.push({
          file: MODELS_FILE,
          path: `$.models[${i}].name`,
          message:
            `model '${slug}' name '${model.name}' normalises to '${key}', ` +
            `the ${nameOfOther.kind} of model '${nameOfOther.owner}'`,
        });
      }
    }
  });

  // A creator alias must not collide with another creator's id or alias.
  const creatorAliasOwner = new Map();
  creators.forEach((creator, i) => {
    (Array.isArray(creator?.aliases) ? creator.aliases : []).forEach((alias, j) => {
      if (typeof alias !== 'string') return;
      const key = alias.trim().toLowerCase();
      const at = `$.creators[${i}].aliases[${j}]`;
      if (creatorIds.has(key) && key !== creator?.id) {
        errors.push({
          file: CREATORS_FILE,
          path: at,
          message: `creator '${creator?.id}' alias '${alias}' equals another creator's id ('${key}')`,
        });
      }
      const owner = creatorAliasOwner.get(key);
      if (owner !== undefined && owner !== creator?.id) {
        errors.push({
          file: CREATORS_FILE,
          path: at,
          message: `creator '${creator?.id}' alias '${alias}' equals another creator's alias of '${owner}'`,
        });
      } else if (owner === undefined) {
        creatorAliasOwner.set(key, creator?.id);
      }
    });
  });

  return errors;
}
