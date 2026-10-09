# tools

Data tooling for the Tokker price index. Each lives as a script here and is
wired to an `npm run` command in the root `package.json`.

| Script | What it will do |
| :--- | :--- |
| `validate` | Validate `data/pricing.json` against `schema/pricing.v1.json` with ajv (draft 2020-12), plus dataset-wide checks: unique ids, non-empty `fetch_recipe.endpoint`, and an assumption profile on every numeric subscription estimate. `npm run validate [files...]`, default `data/pricing.json`; prints each problem as `file:jsonpath: message` and exits 1 if any exist. |
| `build` | Assemble the dataset from per-provider shards into `data/pricing.json` and CSV exports. |
| `fetch` | Fetch source pages per `data/sources.json` into the evidence store. |
| `extract` | Run the per-provider extractors against fetched evidence into the schema. |
| `diff` | Diff extracted data against `data/`, reporting old → new with % delta. |
| `confirm` | Second-fetch a numeric change and verify the two extractions agree. |

See `docs/plan.md` §4 for the full data pipeline.
