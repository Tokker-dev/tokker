# Data schema v1

The machine contract is [`schema/pricing.v1.json`](../schema/pricing.v1.json)
(JSON Schema draft 2020-12); this file is the human one. Check data with
`npm run validate [files…]` (default `data/pricing.json`): problems print one
per line as `file:jsonpath: message` and the run exits 1 (`ok <file>` when
clean). Decisions: [`plan.md`](plan.md) §3.

## Versioning

`schema_version` is semver pinned to major 1 (pattern `^1\.\d+\.\d+$`). An
additive change (a new optional field) bumps the minor version. A rename or
removal is major: it ships as a new schema file `pricing.v2.json` and a new
`/v2` API path — v1 is never edited in place.

## Value conventions

- Never invent a number (CLAUDE.md rule 1): not published by the source = `"unknown"`, not applicable = `null`, else a number.
- Priced numbers are `>= 0`; the one exception is `batch_discount_pct` (max 100; negatives record marketplace spreads).
- Dates are ISO `YYYY-MM-DD` with real calendar ranges (month 01-12, day 01-31); a time part (`2026-10-05T14:30:00Z`) is optional on `iso_date` but must carry `Z` or a `±hh:mm` offset when present; `generated_at` must carry time and zone.
- Currency is ISO 4217 (`^[A-Z]{3}$`); country is `^[A-Z]{2}$`.

## Ids

| Where | Shape |
|---|---|
| `providers[].id`, `provider_id`, `vendor_id` | slug `^[a-z0-9][a-z0-9._-]*$` |
| `api_offers[].id` | `"<provider_id>/<model_slug>"` |
| `subscriptions[].id` | `"<vendor_id>/<plan_slug>"` |

Composite ids match `^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`, lowercase. Ids
are stable and never reused; a renamed model or plan gets a new id with `supersedes`.

## Model and creator registries

`data/models.json` ([`schema/models.v1.json`](../schema/models.v1.json)) lists one
entry per canonical model — `slug`, `name`, `creator`, `open_weights`, `aliases`,
`released` (`"unknown"` when no source publishes a date), optional `supersedes`.
`data/creators.json` ([`schema/creators.v1.json`](../schema/creators.v1.json))
folds creator spellings (`moonshot`/`moonshotai`, `zhipu`/`zai`, `alibaba`/`qwen`)
into one canonical id per lab; the other spellings are `aliases`.

- **Dotted-version slugs are canonical**: `claude-opus-5.5`, never `claude-opus-5-5`.
  A renamed model keeps its old spelling only as an alias (+ `supersedes`), and two
  slugs may never differ only by `.` vs `-`.
- **The normaliser never guesses** (`tools/slugs.mjs`): a name resolves on an exact
  match of a canonical slug or alias after trim + lowercase; anything else is
  `"unmapped"` — never dot/dash-repaired, stemmed or fuzzy-matched.
- Extractors write the slug they resolved to; `model_creator` must be the model's
  canonical creator id.

## Top level (all keys required, no extras)

| Key | Shape |
|---|---|
| `schema_version` | string `1.x.y` |
| `dataset`, `license` | non-empty strings |
| `generated_at` | timestamp (date + time + zone) |
| `conventions` | map of convention name → human-readable string |
| `fx` | [fx](#fx) |
| `counts` | map name → integer >= 0; required keys `api_providers`, `api_offers`, `subscription_vendors`, `subscriptions`, `sources` |
| `providers` | [providers[]](#providers) |
| `api_offers` | [api_offers[]](#api_offers) |
| `subscriptions` | [subscriptions[]](#subscriptions) |
| `derived` | `{cheapest_provider_per_model}` — keyed by `model_slug`; each entry `{offers: integer >= 1, cheapest_offer: composite id, blended_3to1_usd: number|null}` |
| `sources` | [sources[]](#sources) |
| `research_notes` | map of part-file name → notes string |

## providers[] (all fields required)

| Field | Type |
|---|---|
| `id`, `name` | slug; non-empty string |
| `type` | `first_party` \| `aggregator` \| `inference_host` \| `cloud` \| `null` |
| `country` | `^[A-Z]{2}$` \| `null` |
| `api_offer_count`, `subscription_count` | integer >= 0 |

`type` and `country` may be `null` here (plan-only vendors). On rows,
`provider_type` must be an enum value; `provider_country` may still be `null`.

## api_offers[] — one row per provider x model (required unless marked optional)

| Field | Type |
|---|---|
| `id` | composite id |
| `provider_id`, `model_slug` | slugs |
| `provider_name`, `model_name`, `model_creator` | non-empty strings |
| `provider_type` | `first_party` \| `aggregator` \| `inference_host` \| `cloud` |
| `provider_country` | `^[A-Z]{2}$` \| `null` |
| `open_weights`, `currency` | `true` \| `false` \| `"unknown"`; ISO 4217 |
| `input_per_mtok`, `output_per_mtok` | number >= 0 \| `"unknown"` |
| `cached_input_per_mtok`, `cache_write_per_mtok` | number >= 0 \| `null` \| `"unknown"` |
| `batch_discount_pct` | number (max 100, may be negative) \| `null` \| `"unknown"` — negative records a marketplace spread |
| `offpeak`, `tiered_pricing`, `free_tier`, `region_notes`, `notes` | string \| `null` |
| `context_window`, `max_output` | integer >= 0 \| `"unknown"` |
| `source` | non-empty string — the exact URL the row came from |
| `checked`, `last_verified_at` | ISO dates — day researched / day the source last agreed with the row |
| `confidence` | `official_page` \| `official_docs` \| `secondary` |
| `fetch_recipe`, `usd`, `provenance` | see [shared objects](#shared-objects) |
| `supersedes` *(optional)* | composite id this row replaces |

## subscriptions[] — one row per plan (required unless marked optional)

| Field | Type |
|---|---|
| `id`, `vendor_id` | composite id; slug |
| `vendor_name`, `product`, `plan_name` | non-empty strings |
| `category` | `chat` \| `coding_agent` \| `ide` \| `token_plan` \| `api_credit_bundle` |
| `currency` | ISO 4217 |
| `price_month`, `price_year` | number >= 0 \| `null` \| `"unknown"` (`price_year` = total per year if annual billing is offered) |
| `models_included` | array of non-empty strings |
| `limits_published` | [limits_published[]](#limits_published); may be empty |
| `fair_use` | string \| `null` — verbatim fair-use wording |
| `est_tokens_per_month`, `est_usd_per_mtok_at_full_use` | number >= 0 \| `"unknown"` |
| `estimate_assumption` | non-empty string — how the estimate was derived |
| `source`, `checked`, `confidence`, `notes`, `last_verified_at`, `provenance` | as in api_offers[] |
| `fetch_recipe`, `usd` | [shared objects](#shared-objects) (`usd` is the subscription block) |
| `supersedes` *(optional)* | composite id this row replaces |

### limits_published[] (all fields required)

The vendor's limits, quoted verbatim — an estimate never invents a cap.

| Field | Type |
|---|---|
| `window` | `5h_rolling` \| `daily` \| `weekly` \| `monthly` \| `per_request` \| `unspecified` |
| `unit` | `tokens` \| `requests` \| `prompts` \| `messages` \| `credits` \| `usd` \| `unspecified` |
| `amount` | number >= 0 \| `"unknown"` |
| `quote` | non-empty string — the limit word for word as published |

## Shared objects

### fetch_recipe (all fields required; the refresh loops read it)

| Field | Type |
|---|---|
| `method` | `json_api` \| `html_static` \| `html_js_rendered` \| `docs_markdown` \| `pdf` \| `manual` |
| `endpoint` | non-blank string (`\S`, no leading/trailing-only whitespace) — the URL actually best to fetch |
| `selector_hint` | string, may be `""` — where on the page the numbers live |
| `volatility` | `high` \| `medium` \| `low` — sets the re-check cadence |

### provenance (every row carries one; a field from a different page gets its own entry)

| Field | Type |
|---|---|
| `default` *(required)* | provenance entry `{source: non-empty string, fetched_at: ISO date, method: fetch method, confidence}` — all four required |
| `fields` *(optional)* | map of field name (`^[a-z_][a-z0-9_]*$`) → `"default"` or a full provenance entry |

### usd (derived from the row's native numbers at `fx.date`; number|null fields >= 0)

Build output, never hand-edited: `tools/build.mjs` recomputes every block
(native / rate, 6 significant digits) and the validator rejects drift —
conversion and rounding rules: [fx.md](fx.md).

| Block | Fields |
|---|---|
| API (`api_offers[].usd`) | `input_per_mtok`, `output_per_mtok`, `cached_input_per_mtok`, `cache_write_per_mtok`, `blended_3to1` (the 3:1 input:output blend used for ranking); `fx_rate_date` (ISO date) optional |
| subscription (`subscriptions[].usd`) | `price_month`, `price_year`; `fx_rate_date` optional |

### fx

`base` (ISO 4217 currency); `date` (ISO date — the rate date for the whole
dataset); `source` (non-empty string); `rates` (map of ISO 4217 currency →
number > 0: one unit of base in that currency).

### sources[] (all fields required) — one entry per distinct page fetched

`provider_id` (slug) · `url` (`^https?://\S+$`) · `fetch_recipe`
([fetch_recipe](#fetch_recipe)) · `fetch_ok` (boolean) · `notes` (string) ·
`part` (non-empty string — the part file that produced it).

## What the validator checks beyond the schema

`tools/validate.mjs` adds the dataset-wide rules a per-row schema cannot express:

- **Id uniqueness.** Row ids are unique across `api_offers` + `subscriptions`,
  across every file passed in one run; `providers[].id` likewise. A duplicate
  reports where the first occurrence sits.
- **Estimates name their assumption.** A numeric `est_tokens_per_month` or
  `est_usd_per_mtok_at_full_use` needs an `estimate_assumption` that starts with
  a profile — `standard` (the dataset's), `agentic-coding-v1`, `light-chat`,
  `heavy-agentic`; case-insensitive, optionally `profile: detail` — or states the
  vendor publishes the token count itself (`vendor quotes raw tokens…`,
  `vendor counts tokens directly…`).
- **USD is build output.** A row's `currency` must be supported by `fx`
  (the base or a key in `fx.rates`; see [fx.md](fx.md)), and every `usd` field
  must equal what `npm run build` computes from the native values and the
  document's `fx` block. When `data/fx.json` exists, every document's `fx`
  block must match it exactly — one dated rate set per dataset.
- **Model registry.** `data/models.json` + `data/creators.json` are validated
  against their schemas and checked for collisions (duplicate slugs, slugs equal
  after `.`→`-`, an alias mapping to two models or to another model's slug,
  unknown creators, unknown `supersedes`). Every `api_offers[].model_slug` must be
  a known model with a matching `model_creator`, and every `derived.
  cheapest_provider_per_model` key a known slug.

## Part files (research agents)

Research agents do not write `pricing.json`. Write ONE part file:
`{"api_offers": [...], "subscriptions": [...], "notes": "..."}`, omitting keys
you don't fill. Rows use the `api_offers[]` / `subscriptions[]` shapes above
minus the merge step's fields (`usd`, `provenance`, and the top-level
`providers[]`, `fx`, `counts`, `derived`, `research_notes`). Rules:

- Money in the provider's native currency plus its ISO code; leave USD to the merge.
- Never invent a number: `"unknown"` if not published, `null` if not applicable.
- `checked` = today. `source` = the exact official URL you fetched.
- Every row needs its `fetch_recipe`. Note in `notes` if a fetch failed
  (JS-rendered, blocked) and what you did instead.
- Add top-level `sources[]` entries (one per distinct page fetched, `part` = your part-file name).
