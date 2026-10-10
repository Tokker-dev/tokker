# schema

The JSON Schema every data file must pass: [`pricing.v1.json`](pricing.v1.json)
(JSON Schema draft 2020-12), plus the model and creator registries
[`models.v1.json`](models.v1.json) and [`creators.v1.json`](creators.v1.json).
`npm run validate` checks `data/pricing.json`
against them (or any files you pass it) and enforces the dataset-wide rules the
per-row schema cannot express: unique ids, non-empty `fetch_recipe.endpoint`,
an assumption profile on every numeric subscription estimate, and registry
membership for every `model_slug`.

The field-level contract — what `"unknown"` vs `null` means, per-field types,
provenance — lives in [`docs/SCHEMA.md`](../docs/SCHEMA.md) and
[`docs/plan.md`](../docs/plan.md) §3.

Schema changes follow semver (CLAUDE.md rule 7): additive is minor, a rename or
removal is major and needs a new `/v2`.
