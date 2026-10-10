# tools

Data tooling for the Tokker price index. Each lives as a script here and is
wired to an `npm run` command in the root `package.json`.

| Script | What it does |
| :--- | :--- |
| `validate` | Validate `data/pricing.json` against `schema/pricing.v1.json` with ajv (draft 2020-12), plus dataset-wide checks: unique ids, non-empty `fetch_recipe.endpoint`, and an assumption profile on every numeric subscription estimate. `npm run validate [files...]`; with no files it validates every fragment (`data/offers/`, `data/plans/`, the registries beside them) plus the generated `data/pricing.json`; named files are classified by their `data/` path, so a shard is checked against its slice of the schema, its file name, its row order and its canonical formatting. Prints each problem as `file:jsonpath: message` and exits 1 if any exist. |
| `build` | `tools/build.ts`. Rebuild `data/pricing.json` and the two CSV exports from the fragments under `data/` into `dist/`, validating the assembled dataset before writing. Deterministic: the output depends only on the fragment bytes — `generated_at` is re-derived from the maximum `last_verified_at` (date-only becomes `T00:00:00Z`), `counts` and `derived.cheapest_provider_per_model` are recomputed. `npm run build`. |
| `fetch` | Fetch source pages per `data/sources.json` into the evidence store. |
| `extract` | Run the per-provider extractors against fetched evidence into the schema. |
| `diff` | Diff extracted data against `data/`, reporting old → new with % delta. |
| `confirm` | Second-fetch a numeric change and verify the two extractions agree. |
| `split` | `tools/split.ts`. One-off migration that cut the original monolithic `data/pricing.json` into the fragments the builder consumes. Kept for the record; deterministic and idempotent, but never necessary to run again. No npm script — `vite-node tools/split.ts`. |

See `docs/plan.md` §4 for the full data pipeline.
