# data

The dataset, licensed separately (see `LICENSE`). The schema every file must
pass is `schema/pricing.v1.json`; what the fields mean is in `docs/SCHEMA.md`.

## Files

| Path | What it is | Edit |
| :--- | :--- | :--- |
| `meta.json` | Dataset-level metadata: `schema_version`, name, licence, `conventions`, `research_notes`. | yes |
| `fx.json` | FX rates the derived `usd` blocks are computed from. | yes |
| `providers.json` | Provider registry (bare array), sorted by `id`. | yes |
| `sources.json` | Source registry (bare array): one entry per fetched page, sorted by `(provider_id, part, url)`. | yes |
| `offers/<provider_id>.json` | One provider's `api_offers` rows as `{provider_id, offers}`, rows sorted by `id`. | yes |
| `plans/<vendor_id>.json` | One vendor's subscription rows as `{vendor_id, plans}`, rows sorted by `id`. | yes |
| `pricing.json` | GENERATED: the assembled dataset — all fragments merged. | never |
| `pricing_api.csv` | GENERATED: flat CSV export of `api_offers`. | never |
| `pricing_subscriptions.csv` | GENERATED: flat CSV export of subscriptions. | never |

Edit the fragments and registries, never the generated files. A hand edit to
`pricing.json` or either CSV is overwritten by the next build and fails CI
(the build step re-runs the build and `cmp`s the output against the committed
files).

## Editing workflow

1. Edit `offers/`, `plans/`, the registries, `fx.json` or `meta.json`.
2. `npm run build` — writes `dist/pricing.json`, `dist/pricing_api.csv` and
   `dist/pricing_subscriptions.csv`, after validating the assembled dataset.
3. `cp dist/pricing.json dist/pricing_api.csv dist/pricing_subscriptions.csv data/`
4. `npm run validate && npm test` — validate checks the fragments too; the
   test suite fails if a committed generated file drifted from build output.
5. Commit the fragment change and the regenerated files together.

## Formatting rules

`npm run validate` enforces these on every fragment:

- 2-space indent, exactly one trailing newline, nothing else.
- Offer and plan rows sorted by `id`, strictly ascending (which also means
  unique).
- A shard's rows all carry the shard's `provider_id`/`vendor_id`, which must
  match the file name.
- `providers.json` sorted by `id`; `sources.json` sorted by
  `(provider_id, part, url)` with no duplicate triple; `fx.json` rate keys
  sorted by currency code.

## What build recomputes

Never edit these by hand in the generated file — they come from the fragments:

- `counts`, recomputed from the assembled arrays.
- `generated_at`: the maximum `last_verified_at` across all rows; a date-only
  value becomes `T00:00:00Z`. Never the wall clock — the build is
  deterministic and rerunnable.
- `derived.cheapest_provider_per_model`: per `model_slug`, among rows whose
  `usd.blended_3to1` is a number, groups with at least 2 such rows; cheapest
  is the smallest blended price, ties broken by lexicographically smallest id.

## See also

- `schema/pricing.v1.json` — the JSON Schema; fragment rows are validated
  against its `$defs`.
- `docs/SCHEMA.md` — field meanings and the provenance rules.
- `tools/split.ts` — the one-off migration script that cut the original
  monolithic `pricing.json` into these fragments; kept for the record, not
  part of the pipeline.
