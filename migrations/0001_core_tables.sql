-- Tokker core tables (migration 0001): the public price index, one table per
-- dataset collection in docs/SCHEMA.md, loaded from data/pricing.json by the
-- repo-mirror work (plan.md §5.2 G1).
--
-- Table privacy: these tables hold nothing personal — published price data
-- only (plan.md §5.1 table_privacy: holds nothing).
--
-- These tables are applied by wrangler (`migrations_dir` in wrangler.toml,
-- `wrangler d1 migrations apply DB --local` for dev). The module's Rust-side
-- `Migrations` stay EMPTY: on Workers the runtime never applies SQL itself.
--
-- Conventions: `id` is the stable dataset id, never reused (CLAUDE.md rule 3).
-- Scalar columns are the plain numeric form the API filters on; the dataset's
-- "unknown" and null both collapse to NULL here (the verbatim row — including
-- every "unknown" — is `json`, which is what `/v1/*` returns).

CREATE TABLE providers (
  id TEXT PRIMARY KEY,            -- slug, e.g. "openrouter"
  name TEXT NOT NULL,
  type TEXT CHECK (type IN ('first_party', 'aggregator', 'inference_host', 'cloud')),
                                  -- NULL = plan-only vendor
  country TEXT,                   -- ISO 3166-1 alpha-2, or NULL
  api_offer_count INTEGER NOT NULL DEFAULT 0,
  subscription_count INTEGER NOT NULL DEFAULT 0,
  json TEXT NOT NULL
);

CREATE TABLE models (
  id TEXT PRIMARY KEY,            -- canonical model_slug
  name TEXT NOT NULL,             -- model_name
  creator TEXT NOT NULL,          -- model_creator
  open_weights TEXT NOT NULL CHECK (open_weights IN ('true', 'false', 'unknown')),
  context_window INTEGER,         -- NULL when "unknown"
  json TEXT NOT NULL
);

CREATE TABLE offers (
  id TEXT PRIMARY KEY,            -- "<provider_id>/<model_slug>"
  provider_id TEXT NOT NULL REFERENCES providers(id),
  model_id TEXT NOT NULL REFERENCES models(id),
  creator TEXT NOT NULL,          -- model_creator; the /v1/offers filter
  provider_type TEXT NOT NULL CHECK (provider_type IN ('first_party', 'aggregator', 'inference_host', 'cloud')),
  open_weights TEXT NOT NULL CHECK (open_weights IN ('true', 'false', 'unknown')),
  currency TEXT NOT NULL,         -- ISO 4217; native currency first (CLAUDE.md rule 4)
  input_per_mtok REAL,            -- native currency; NULL when "unknown"
  output_per_mtok REAL,
  usd_input_per_mtok REAL,        -- the row's derived usd block, at fx.date
  usd_output_per_mtok REAL,
  usd_blended_3to1 REAL,          -- the 3:1 input:output blend used for ranking
  context_window INTEGER,
  max_output INTEGER,
  batch_discount_pct REAL,
  region_notes TEXT,
  source TEXT NOT NULL,           -- the exact URL the row came from
  confidence TEXT NOT NULL CHECK (confidence IN ('official_page', 'official_docs', 'secondary')),
  last_verified_at TEXT NOT NULL, -- ISO date; shown everywhere (plan.md §3)
  json TEXT NOT NULL
);

CREATE INDEX offers_creator ON offers(creator);
CREATE INDEX offers_provider ON offers(provider_id);
CREATE INDEX offers_model ON offers(model_id);
CREATE INDEX offers_open_weights ON offers(open_weights);
CREATE INDEX offers_usd_input ON offers(usd_input_per_mtok);
CREATE INDEX offers_cheapest ON offers(model_id, usd_blended_3to1); -- /v1/models/{slug}/cheapest

CREATE TABLE plans (
  id TEXT PRIMARY KEY,            -- "<vendor_id>/<plan_slug>"
  vendor_id TEXT NOT NULL REFERENCES providers(id),
  vendor_name TEXT NOT NULL,
  product TEXT NOT NULL,
  plan_name TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('chat', 'coding_agent', 'ide', 'token_plan', 'api_credit_bundle')),
  currency TEXT NOT NULL,
  price_month REAL,               -- native currency; NULL when "unknown"
  price_year REAL,
  usd_price_month REAL,
  usd_price_year REAL,
  last_verified_at TEXT NOT NULL,
  json TEXT NOT NULL
);

CREATE INDEX plans_vendor ON plans(vendor_id);
CREATE INDEX plans_category ON plans(category);

CREATE TABLE sources (
  id TEXT PRIMARY KEY,            -- "<part>/<provider_id>"; sources[] has no id in the dataset, so the loader assigns this
  provider_id TEXT NOT NULL,
  url TEXT NOT NULL,
  method TEXT NOT NULL CHECK (method IN ('json_api', 'html_static', 'html_js_rendered', 'docs_markdown', 'pdf', 'manual')),
  endpoint TEXT NOT NULL,
  volatility TEXT NOT NULL CHECK (volatility IN ('high', 'medium', 'low')),
  fetch_ok INTEGER NOT NULL,      -- boolean
  part TEXT NOT NULL,             -- the part file that produced the entry
  notes TEXT,
  json TEXT NOT NULL
);

CREATE INDEX sources_provider ON sources(provider_id);

CREATE TABLE fx (
  currency TEXT PRIMARY KEY,      -- ISO 4217; one row per fx.rates entry
  rate REAL NOT NULL CHECK (rate > 0),  -- one unit of base in that currency
  base TEXT NOT NULL,
  date TEXT NOT NULL,             -- the rate date for the whole dataset
  json TEXT NOT NULL
);
