import { fileURLToPath } from 'node:url';
import { expect, test } from 'vitest';
import {
  UNMAPPED,
  checkRegistry,
  createNormaliser,
  dashFold,
  loadRegistry,
} from './slugs.mjs';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));

function makeModel(overrides = {}) {
  return {
    slug: 'a-1',
    name: 'A 1',
    creator: 'testco',
    open_weights: false,
    aliases: [],
    released: 'unknown',
    ...overrides,
  };
}

function makeCreators() {
  return [{ id: 'testco', name: 'TestCo', aliases: [] }];
}

function errorsOf(models, creators = makeCreators()) {
  return checkRegistry({ models, creators });
}

test('loadRegistry reads the repo registry: 145 models, 31 creators, sorted by slug/id', () => {
  const registry = loadRegistry();
  expect(registry.models.length).toBe(145);
  expect(registry.creators.length).toBe(31);
  const slugs = registry.models.map((m) => m.slug);
  expect(slugs).toEqual([...slugs].sort());
  const ids = registry.creators.map((c) => c.id);
  expect(ids).toEqual([...ids].sort());
});

test('checkRegistry passes the real data/models.json + data/creators.json', () => {
  expect(checkRegistry(loadRegistry())).toEqual([]);
});

test('no two slugs in data/models.json differ only by . or -', () => {
  const slugs = loadRegistry().models.map((m) => m.slug);
  const folded = new Map();
  for (const slug of slugs) {
    const key = dashFold(slug);
    expect(folded.has(key), `${slug} folds into ${folded.get(key)}`).toBe(false);
    folded.set(key, slug);
  }
});

test('normalise resolves slugs, provider-native names and aliases after trim+lowercase', () => {
  const normalise = createNormaliser(loadRegistry().models);
  expect(normalise('claude-opus-5.5')).toBe('claude-opus-5.5');
  expect(normalise('  CLAUDE-OPUS-5.5  ')).toBe('claude-opus-5.5');
  // a provider-native model_name is an alias
  expect(normalise('Claude Opus 5.5')).toBe('claude-opus-5.5');
  expect(normalise('DeepSeek-V4.1-Flash (deepseek-flash)')).toBe('deepseek-flash');
  // the superseded dotted spelling still resolves
  expect(normalise('claude-opus-5-5')).toBe('claude-opus-5.5');
});

test('normalise returns "unmapped" for anything unregistered — no dot/dash guessing', () => {
  const normalise = createNormaliser(loadRegistry().models);
  expect(normalise('gpt-5-5')).toBe(UNMAPPED); // the real slug is gpt-5.5
  expect(normalise('claude_opus_5_5')).toBe(UNMAPPED);
  expect(normalise('claude-opus-55')).toBe(UNMAPPED);
  expect(normalise('totally-made-up-model')).toBe(UNMAPPED);
  expect(normalise('')).toBe(UNMAPPED);
  expect(normalise(undefined)).toBe(UNMAPPED);
  expect(normalise(42)).toBe(UNMAPPED);
});

test('duplicate slugs are registry errors naming both places', () => {
  const errors = errorsOf([makeModel(), makeModel()]);
  const hit = errors.find((e) => e.path === '$.models[1].slug');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("duplicate model slug 'a-1'");
  expect(hit.message).toContain('$.models[0].slug');
});

test("two slugs equal after mapping '.'→'-' collide", () => {
  const errors = errorsOf([makeModel(), makeModel({ slug: 'a.1' })]);
  const hit = errors.find((e) => e.path === '$.models[1].slug');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("'a-1' and 'a.1' differ only by '.' vs '-'");
});

test('an alias mapping to two models is a registry error', () => {
  const errors = errorsOf([
    makeModel({ aliases: ['shared name'] }),
    makeModel({ slug: 'b-2', aliases: ['shared name'] }),
  ]);
  const hit = errors.find((e) => e.path === '$.models[1].aliases[0]');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("alias 'shared name' maps to two models ('a-1' and 'b-2')");
});

test('an alias equal to another model’s slug is a registry error', () => {
  const errors = errorsOf([makeModel({ aliases: ['B-2'] }), makeModel({ slug: 'b-2' })]);
  const hit = errors.find((e) => e.path === '$.models[0].aliases[0]');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("alias 'B-2' equals another model's slug ('b-2')");
  // but an alias that only normalises (case-insensitively) to its own slug is fine
  expect(errorsOf([makeModel({ aliases: ['A-1'] })])).toEqual([]);
});

test('model.creator must exist in creators.json', () => {
  const errors = errorsOf([makeModel({ creator: 'ghost-labs' })]);
  const hit = errors.find((e) => e.path === '$.models[0].creator');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("creator 'ghost-labs' is not in data/creators.json");
});

test('supersedes must be a known slug (or a registered alias); unknown is an error', () => {
  const unknown = errorsOf([makeModel({ supersedes: 'nope' })]);
  const hit = unknown.find((e) => e.path === '$.models[0].supersedes');
  expect(hit).toBeDefined();
  expect(hit.message).toContain("supersedes 'nope', which is not a known slug or alias");

  // a rename: the old slug lives on as an alias, so supersedes resolves
  const renamed = errorsOf([
    makeModel({ supersedes: 'old-name', aliases: ['old-name'] }),
  ]);
  expect(renamed).toEqual([]);

  // pointing at a current slug is fine too
  expect(errorsOf([makeModel(), makeModel({ slug: 'b-2', supersedes: 'a-1' })])).toEqual([]);
});

test('a model name must not normalise to another model’s slug or alias', () => {
  const asSlug = errorsOf([makeModel(), makeModel({ slug: 'b-2', name: 'A-1' })]);
  const hitSlug = asSlug.find((e) => e.path === '$.models[1].name');
  expect(hitSlug).toBeDefined();
  expect(hitSlug.message).toContain("model 'b-2' name 'A-1' normalises to 'a-1', the slug of model 'a-1'");

  const asAlias = errorsOf([
    makeModel({ aliases: ['Shared-Alias'] }),
    makeModel({ slug: 'b-2', name: 'shared-alias' }),
  ]);
  const hitAlias = asAlias.find((e) => e.path === '$.models[1].name');
  expect(hitAlias).toBeDefined();
  expect(hitAlias.message).toContain("normalises to 'shared-alias', the alias of model 'a-1'");

  // its own slug or its own alias is fine
  expect(errorsOf([makeModel({ name: 'A-1', aliases: ['A 1'] })])).toEqual([]);
});

test('a creator alias must not equal another creator’s id or alias', () => {
  const byId = checkRegistry({
    models: [],
    creators: [
      { id: 'testco', name: 'TestCo', aliases: [] },
      { id: 'otherco', name: 'OtherCo', aliases: ['TestCo'] },
    ],
  });
  const hitId = byId.find((e) => e.path === '$.creators[1].aliases[0]');
  expect(hitId).toBeDefined();
  expect(hitId.message).toContain("creator 'otherco' alias 'TestCo' equals another creator's id ('testco')");

  const byAlias = checkRegistry({
    models: [],
    creators: [
      { id: 'testco', name: 'TestCo', aliases: ['Legacy-Name'] },
      { id: 'otherco', name: 'OtherCo', aliases: ['legacy-name'] },
    ],
  });
  const hitAlias = byAlias.find((e) => e.path === '$.creators[1].aliases[0]');
  expect(hitAlias).toBeDefined();
  expect(hitAlias.message).toContain("equals another creator's alias of 'testco'");
});
