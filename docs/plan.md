# LLM price index: venture plan

Name: **Tokker** ([tokker.dev](https://tokker.dev)), chosen by the owner on 2026-10-05. This plan was written under the working name Tokdex; references are updated to Tokker. Status: repos created in [Tokker-dev](https://github.com/Tokker-dev); the plan is filed as issues in [Tokker-dev/tokker](https://github.com/Tokker-dev/tokker/issues). No domain is attached and nothing is deployed.

## 1. What it is

An independent, sourced and dated price index for AI tokens and AI plans. It has two halves:

1. **API pricing.** Every provider and every model, in $ per 1M tokens: input, output, cache read and write, batch and off-peak discounts, context tiers, free tiers, and region and currency notes.
2. **Subscriptions.** Claude, ChatGPT, Gemini, Cursor, Copilot, the Chinese and Asian coding/token plans and the rest. Each plan carries its **published limits verbatim** (5-hour rolling, daily, weekly and monthly; tokens, requests or "prompts") and an **estimated $ per 1M tokens at full use** with the assumption stated. That lets you compare a $200 plan directly with an API.

Positioning: "the price index for AI tokens and plans". It is open data under CC BY 4.0, every number carries a source and a `last_verified_at` date, and the data is built for LLMs and agents to read (llms.txt, JSON, MCP).

Why now (from `docs/research/affiliates_competitors.json`):
- **No competitor turns subscription windows into tokens.** Price Per Token and AI Pricing Guru describe plans but never convert 5-hour or weekly windows to $/Mtok. Only stale blog posts do that math.
- **Nobody joins Western and Chinese plans.** codingplan.org and similar sites cover the Chinese coding plans as static HTML with referral codes, with no token math and no API prices.
- **The open datasets cover APIs only.** models.dev, LiteLLM, Portkey, Helicone and genai-prices have no subscription data and no UI.
- **History and alerts are scattered.** They exist on BenchLM Radar and on OpenRouter-only snapshot sites, but not together with plans.

## 2. Product

| Surface | What | Notes |
|---|---|---|
| **Compare** | Sortable table of all API offers, with filters for creator, open weights, context, region and provider type. A "cheapest provider for this model" view joins on canonical `model_slug`. | Blended price (3:1 input:output) for ranking, with the raw columns always shown |
| **Calculator** | "Given my usage, what is cheapest?" Inputs: monthly input and output tokens, cache-hit %, batch-eligible %, latency tier, and must-have models. Output: ranked API offers **and** subscriptions that would fit inside their windows, with a break-even line ("above ~X Mtok/month, Max 20x beats the API"). | The subscription fit check uses the window math below and shows which window binds (5h or weekly) |
| **Plan pages** | One page per subscription: price, models, the verbatim limits quote, fair-use quote, the token math worked through step by step, and history | The explainer for "what does 'at least 5x Pro' actually mean?" |
| **Window explainers** | Evergreen pages: "5-hour rolling windows explained", "weekly caps vs 5h caps", "prompts vs requests vs tokens", "why $/Mtok on a plan is a ceiling, not a price" | SEO and LLM-citation magnets |
| **Change history** | Every field change, with old and new values, date, source and the PR link. Per-model and per-plan timelines, plus a global "what changed this week" feed (RSS/Atom and JSON) | Built from merged data PRs |
| **Price-drop alerts** | Anonymous double-opt-in email or a signed webhook: "notify me when X's output price drops below $Y", "any change to plan Z's limits", "a new provider for model M" | Generic Cratefield alerts module (see §7) |
| **Public API** | REST/JSON, versioned `/v1`. CORS-open reads with no key up to a free rate limit; an API key gives higher limits | Same shape as `pricing.json` (schema 1.0.0) |
| **MCP server** | Tools: `search_models`, `get_price`, `cheapest_provider(model)`, `estimate_cost(usage)`, `compare_plans(usage)`, `get_changes(since)` | Ships as a stdio npm package first (the Sealbin pattern), then as Streamable HTTP from the Worker once Cratefield has it |
| **llms.txt / llms-full.txt** | Served from the static site, plus `/data/pricing.json` and CSV downloads | Agent-first discovery |
| **Embeds** | `<script>` and iframe widgets: a price badge for a model, a "cheapest host" box, a plan card. Each shows `last_verified_at` | Distribution through blogs and docs |
| **Freshness UI** | Every number shows "verified N days ago". Anything older than its SLA is greyed and badged **stale**. A public coverage and freshness dashboard | Trust is the product |

### Subscription token math (venture-specific)

For each plan: `est_tokens_per_month = min(window_cap × windows_per_month, weekly_cap × 4.33, monthly_cap) × tokens_per_unit`. Here `tokens_per_unit` converts a "prompt", "request" or "message" into tokens using a **published, versioned assumption profile**. The default is `agentic-coding-v1`; light-chat and heavy-agentic profiles are also offered, and users can override it in the calculator. Then `est_usd_per_mtok_at_full_use = price_month / est_tokens_per_month × 1e6`. When a vendor publishes no number, the estimate is `unknown`, and we never derive one from an invented cap. Credible community measurements may be shown separately, labelled **secondary**, with the link. The assumption string is stored on every row. Implementation note (issue #13): the build computes `window_cap × (4 × 30 = 120)` and `weekly_cap × 30 / 7` left-to-right, matching the dataset's STANDARD assumption strings; `4.33` is shorthand for the weekly factor.

## 3. Data model (public API shape)

`pricing.json` is schema **1.0.0** (semver: additive changes are minor, renames and removals are major and get a new `/v2`).

- **Top level:** `schema_version`, `generated_at`, `license`, `conventions`, `fx` (ECB reference rates with their date), `counts`, `providers[]`, `api_offers[]`, `subscriptions[]`, `derived.cheapest_provider_per_model`, `sources[]`.
- **Stable ids:** `api_offers[].id = "<provider_id>/<model_slug>"` and `subscriptions[].id = "<vendor_id>/<plan_slug>"`. Ids are never reused. A renamed model gets a new id with `supersedes`.
- **Native currency:** prices are stored in the provider's native currency (`currency`), with a `usd{}` block converted at the dataset's `fx.date`.
- **Unknown vs not applicable:** `"unknown"` means the source does not publish the value. `null` means not applicable.
- **Provenance on every field:** `provenance.default = {source, fetched_at, method, confidence}`, and `provenance.fields.<field>` is either `"default"` or its own provenance object when the field came from a different page (for example a limits help-center article). `confidence` is one of `official_page`, `official_docs` or `secondary`.
- **`last_verified_at`:** the date the source was last fetched and agreed with the row. It is shown everywhere.
- **`fetch_recipe`:** `{method: json_api|html_static|html_js_rendered|docs_markdown|pdf|manual, endpoint, selector_hint, volatility}`. This is the scheduled agent's instruction for how to re-check the row (see §4).
- **API endpoints:**
  - `GET /v1/offers?model=&provider=&creator=&open_weights=&max_input=`
  - `GET /v1/offers/{id}`
  - `GET /v1/models/{slug}/cheapest`
  - `GET /v1/plans`, `GET /v1/plans/{id}`
  - `GET /v1/changes?since=&id=`
  - `POST /v1/estimate` (calculator)
  - `GET /v1/sources` (freshness)
  - `GET /data/pricing.json`, `/data/*.csv`

## 4. Freshness: scheduled agents (core system)

Freshness is the product. Every number is re-verified on a schedule by agents, and every change lands as a reviewed, evidenced data PR.

### 4.1 Topology

```
            ┌──────────────── Colonizer mothership (omarchy) ─────────────────┐
            │ loop: api-daily        daily@05:00    (per-provider shards)     │
            │ loop: volatile-6h      6h             (OpenRouter, DeepSeek,    │
            │                                        Z.AI, Kimi, MiniMax,     │
            │                                        Cursor, Copilot, ...)    │
            │ loop: plans-weekly     weekly@mon@06:00 + daily for volatile    │
            │ loop: discovery        weekly@thu@07:00                         │
            │ loop: merge-train      (built-in, auto-merges green data PRs)   │
            └───────────────┬─────────────────────────────────────────────────┘
                            │ autopilot: mothership pushes branch + opens PR
                            ▼
   venture repo  data/offers/<provider>.json, data/plans/<vendor>.json,
                 data/sources.json, evidence/<date>/<source-hash>.{html,json,txt}
     CI: schema validate · sanity bounds · id stability · second-fetch agreement
                            │ merge to main
                            ▼
   Cratefield Worker (api.tokker.dev) ── module "repo-mirror" (generic) pulls main@sha
     on cron (etag) → D1: current rows + versioned history (module "record-history")
     → serves /v1/*, MCP, alerts evaluate on the diff (module "watch-alerts")
                            ▲
   Cloudflare cron on the Worker (every 30 min): lightweight change detector —
   HEAD/ETag/hash of each source's endpoint (budget 40 subreq/tick, round-robin).
   Hash changed → POST Colonizer /api/loops/{id}/run-now for that provider shard
   (scoped API token), so volatile changes are caught within ~30 min, not 24 h.
```

There are two runners. Each is lightweight where it can be:
- **The Worker cron** only detects change, by comparing hashes, ETags or JSON digests. It never parses prices, which keeps it inside Cratefield's ADR 0023 per-tick budget of 40 subrequests and 25 s.
- **Colonizer loops** do the extraction, because pages change layout and an LLM agent with an extractor library copes with that.

The Worker also stays useful when the mothership is down: it keeps serving the last merged data, and staleness shows up on the site.

### 4.2 Cadence

| Class | Cadence | Examples |
|---|---|---|
| API pricing, standard | daily | Anthropic, OpenAI, Google, Mistral, clouds |
| API pricing, volatile | every 6 h, plus change-detector triggers | OpenRouter (public JSON `https://openrouter.ai/api/v1/models`), DeepSeek, SiliconFlow, Chinese labs, inference hosts with promos |
| Subscription limits, volatile | daily | Cursor, Copilot premium requests, Claude/Codex limits, Z.AI/Kimi/MiniMax/Bailian/Volcengine/BytePlus coding plans |
| Subscription limits, standard | weekly | Le Chat, Perplexity, JetBrains, Zed and the rest |
| Discovery | weekly | new providers, models and plans |

`fetch_recipe.volatility` on each row sets its class, so the loop prompts read the schedule from the data.

### 4.3 One run, step by step

1. Load `data/sources.json` and pick the shard: the sources due by cadence, plus any forced by the change detector.
2. **Fetch** per `fetch_recipe`:
   - `json_api`: GET and parse.
   - `docs_markdown`: fetch the `.md` or docs variant.
   - `html_static`: fetch and extract text.
   - `html_js_rendered`: headless browser in the colony microVM.
   - `pdf`: download and extract text.
   - `manual`: open an issue instead.

   Save the raw evidence to `evidence/<date>/<sha256>.*` and record the hash.
3. **Extract** with a per-provider extractor (`extractors/<provider>.ts`: a deterministic parser where possible, with the LLM as fallback) into the schema.
4. **Diff** against `data/`. If there is no change, bump `last_verified_at` only. These "verified, unchanged" commits are batched into one PR per run and auto-merge.
5. **Second fetch:** for any numeric change, re-fetch after 2+ minutes, from a different egress where possible, and re-extract. The two results must agree.
6. **Open a PR** with:
   - the change table (old → new, % delta);
   - the source URL, fetch time and evidence hash and path;
   - the extractor version;
   - a confidence class per change.

   Labels: `data:auto` or `data:review`.

### 4.4 Merge policy

| Change | Policy |
|---|---|
| `last_verified_at` bump only | auto-merge |
| Numeric price change where the schema passes, sanity bounds pass (no more than 10× move, no negatives, input ≤ output unless the provider is known to invert, currency unchanged) and the second fetch agrees | **auto-merge** through the merge-train loop (`colonizer loop merge-train allow Tokker-dev/tokker`) |
| A new model row from an official page or JSON API | auto-merge if every required field has a source |
| Limit window or unit change (5h → weekly, prompts → tokens), fair-use wording, a plan added or removed, a currency change, any `secondary` source, a price move over 10×, or extractor fallback to the LLM | **human review** (`data:review`), assigned to the owner |
| A source fetch fails | no PR. Increment the per-source failure counter (§4.6) |

### 4.5 What the product shows

- Every field carries `last_verified_at`, and the API returns it on every row and field.
- **Stale SLA:** volatile 3 days, standard 10 days, subscriptions 14 days. Past the SLA a row gets `stale: true`, is greyed on the site, and the API includes `stale_since`.
- Every merged change becomes a `changes` row, which feeds the history pages, the RSS/JSON change feed and the alert evaluation.

### 4.6 Monitoring

- **Per-source health** (`sources` table): last success, consecutive failures, last evidence hash, extractor version, and the last error class (`http`, `blocked`, `layout_changed`, `extract_empty`, `schema_fail`).
  - After 2 consecutive failures, open a GitHub issue `source-broken:<provider>`, and the next run tries the LLM fallback extractor.
  - After 3 failures, alert the owner through the Owlpost email adapter or a webhook.
- **Coverage dashboard** (public page plus `/v1/sources`): providers, offers, plans, % verified within SLA, oldest rows, broken sources, and discovery backlog.
- **Loop health:** the Worker cron checks the newest merged data commit. If no successful verify PR has landed in 36 h, alert the owner, because the mothership may be down.

### 4.7 Coverage growth: the discovery agent

A weekly loop searches the web, OpenRouter and the Hugging Face Inference Providers JSON, models.dev, LiteLLM's price JSON and provider changelogs for **new providers, models and plans** not yet in `data/sources.json`. It opens one GitHub issue per candidate, with links and a proposed `fetch_recipe`. A human, or the next colony, accepts it by adding the source.

### 4.8 Loop setup (illustrative)

```sh
colonizer loop create Tokker-dev/tokker --name "api-daily"     --prompt-file loops/api-daily.md     daily@05:00
colonizer loop create Tokker-dev/tokker --name "volatile-6h"   --prompt-file loops/volatile.md      6h
colonizer loop create Tokker-dev/tokker --name "plans-weekly"  --prompt-file loops/plans.md         weekly@mon@06:00
colonizer loop create Tokker-dev/tokker --name "discovery"     --prompt-file loops/discovery.md     weekly@thu@07:00
colonizer loop merge-train allow Tokker-dev/tokker
```

Loops run autopilot, and the mothership opens the PRs. The colony egress is `open`, or an allowlist built from `data/sources.json`. Pick cheap models for the loops, such as the GLM or Qwen coding plans, because each run is a full colony with real spend. Budget this explicitly; the price index has its own numbers to work it out.

## 5. Stack: Cratefield harness on Cloudflare

The same pattern as Sealbin, Owlpost and Living Brain: a Rust Worker built on `cratefield-core` and `cratefield-runtime-cloudflare`, with D1, KV and R2, plus a static Pages site for the website, `llms.txt` and the downloads. Module names were checked against Cratefield/harness @9b42523.

### 5.1 Mapping onto existing Cratefield modules and ports

| Need | Existing Cratefield piece |
|---|---|
| SQL storage | `Db` port → D1 (`.db("DB")`) |
| Cache of hot JSON responses | `KeyValue` port → Workers KV |
| Evidence snapshots, CSV/JSON downloads | `Blob` port → R2 |
| Public tables (providers, offers, plans, changes) | Manifest `tables` with `table_access: public-read`, `table_privacy: holds nothing`, and `/v1/tables/{t}` CRUD for simple reads |
| Outbound fetch for the change detector | `HttpClient` port (`BoundedHttpClient`, 4 MiB, 30 s) |
| Cron | `Module::scheduled(ctx, cron)` with the ADR 0023 budget (`ctx.scheduled.try_spend`), plus `[triggers] crons` in `wrangler.toml` |
| Waitlist at launch | `cratefield-module-waitlist` (`waitlist`), with the `Captcha` port → `adapter-turnstile` |
| Newsletter / "what changed this week" | `cratefield-module-email-signup` + the `Mailer` port → `adapter-owlpost` (or `adapter-resend`) |
| Outbound webhooks for alerts | `cratefield-module-webhooks` (HMAC, outbox, backoff, replay) |
| Changelog of the product itself | `cratefield-module-changelog` |
| Telemetry | `cratefield-module-telemetry` (consent-first aggregates) |
| Privacy (alert subscribers' emails) | `cratefield-module-privacy` |
| API keys | Core `ApiKeys` / `require_api_key` / `ApiKeyMode::{Live,Test}` |
| Rate limiting | `RateLimiter` port: the Workers ratelimit binding for anonymous IP limits, `d1_rate_limiter` for per-key limits |
| Monthly API allowances | Core `usage.rs` (`Usage`) |
| Paid tiers later | `Payments` port → `adapter-polar` (Polar as merchant of record, with usage meters) |
| Typed TS client for widgets and the SDK | `/__surface` → `cratefield-client-ts` |
| Calling Colonizer run-now | `HttpClient` with a scoped Colonizer API token in a secret |

### 5.2 New work, split by where it lives

Rule from the owner: a new Cratefield module or port is only OK if it is **generic code any venture could reuse**. Anything borderline stays in the venture repo.

#### A. Generic → Cratefield (become Cratefield issues later)

| # | Module (domain-neutral) | What it does | Other FZ venture that would reuse it |
|---|---|---|---|
| G1 | **`module-repo-mirror`**, a generalisation of `module-changelog` | On cron, mirrors one or more structured data files (JSON, CSV or NDJSON) from a Git repo at a ref into D1 tables, keyed by declared id fields. It uses ETags or commit SHAs, records the source commit for each row, and is idempotent. | **Living Brain** (wiki/knowledge files authored in git), **Rateclaim** (rate tables kept as data files), any venture whose content is "data in a repo, reviewed by PR" |
| G2 | **`module-record-history`** (versioned record store) | Append-only versions of any keyed record: per-field diffs, `valid_from`/`valid_to`, provenance `{source, fetched_at, method, confidence}` per version, `as_of` queries, range queries, and "lowest/highest value in N days" rollups. It fills the `tables` gap (no ranges or aggregates). | **Rateclaim** (rate changes over time), **Owlpost** (deliverability metrics history), **Bloodrank** (ranking history) |
| G3 | **`module-source-watcher`** | Registry of external URLs and APIs, each with a cadence, fetch method, content hash and ETag. On cron it does a cheap change check within the scheduled budget, keeps a per-source health record (consecutive failures, error class), and emits a "source changed" or "source broken" event to a webhook, the outbox or an HTTP callback (for example Colonizer run-now). It does no domain parsing; extraction is pluggable or external. | **Rateclaim** (watching published rate cards), **Groove Guru** (release feeds), **Keep Shipping** (watching dependency or changelog pages), **Living Brain** (source re-verification) |
| G4 | **`module-watch-alerts`** (rule-based change alerts) | Anonymous double-opt-in subscriptions (email via the `Mailer` port, with Owlpost as the adapter, or a signed webhook via `module-webhooks`) to **rules over records**: `field changed`, `field < threshold`, `new record matching filter`. Rules are evaluated against G2 diffs, delivered through the outbox, with unsubscribe and privacy declarations. Fills the gap that `notifications` needs signed-in accounts and `email-signup` has no criteria. | **Rateclaim** (rate-drop alerts), **Owlpost** (status alerts), **Bloodrank** (rank-change alerts) |
| G5 | **`module-public-api-keys`** (self-serve keys plus a console) | Magic-link sign-up, key create/rotate/revoke on core `ApiKeys`, plan → rate limit and `Usage` allowance mapping, usage page. Generalises Owlpost's `owlpost-accounts`/`owlpost-console`; overlaps with the `module-crm` #576 key work, so coordinate. | **Owlpost** (could replace its custom crate), **Sealbin** (API keys), any venture with a public API |
| G6 | **Runtime MCP serving (ADR 0028 §4)** | Streamable HTTP JSON-RPC route in core that maps a module's `surface()` actions to MCP tools, gated by `require_api_key`. Designed but unbuilt, and no issue tracks it, so file one. | **Sealbin** (move its stdio MCP into the Worker), **Owlpost**, **Living Brain** |
| G7 | **Small harness items** | (a) a cron field in the manifest so `fz build` emits `[triggers]` (today it is lost on regeneration); (b) a tiny static-text route helper for `/llms.txt` on API hosts; (c) a Queues port so watchers can fan out past 40 subrequests per tick | All ventures |
| G8 | **Colonizer: a "refresh data and open PR" loop template** | A first-class loop kind: given `sources.json` and a validate command, fetch, extract, diff, validate, then open a PR with evidence. Domain-neutral. | Any data-repo venture |

Filed on 2026-10-05:
- **Cratefield/harness:** G1 [#768](https://github.com/Cratefield/harness/issues/768), G2 [#769](https://github.com/Cratefield/harness/issues/769), G3 [#770](https://github.com/Cratefield/harness/issues/770), G4 [#771](https://github.com/Cratefield/harness/issues/771), G5 [#772](https://github.com/Cratefield/harness/issues/772) (coordinated with #576), G6 [#773](https://github.com/Cratefield/harness/issues/773), G7a [#774](https://github.com/Cratefield/harness/issues/774), G7b [#775](https://github.com/Cratefield/harness/issues/775), G7c [#776](https://github.com/Cratefield/harness/issues/776).
- **Colonizer-dev/harness:** G8 [#1037](https://github.com/Colonizer-dev/harness/issues/1037); the §6.1 integration as [#1038](https://github.com/Colonizer-dev/harness/issues/1038) (per-model pricing and the price feed) and [#1039](https://github.com/Colonizer-dev/harness/issues/1039) (cheapest-host hint).
- **Owlpost-to/backend:** nothing needed. Batch sends (up to 100), topic-scoped unsubscribe and `email.unsubscribed` webhooks already exist, and Cratefield `adapter-owlpost` exposes `batch` and topics.

#### B. Venture-specific → the venture's own repo only

- The pricing schema (`schema/pricing.v1.json`), canonical model slugs, and the provider and creator registry.
- Provider and plan extractors (`extractors/<provider>.*`) and the `fetch_recipe` entries in `data/sources.json`.
- The subscription token math, the assumption profiles (`agentic-coding-v1`) and the `$ / 1M at full use` estimates.
- The blended-price, "cheapest provider for model X" and calculator logic (`POST /v1/estimate`), plus the break-even computation.
- FX normalisation policy (ECB rates, rate date per dataset).
- Sanity-bound rules for auto-merge (price-specific thresholds).
- Affiliate and referral link handling: a link registry, `rel="sponsored"`, the disclosure banner and click attribution.
- The Colonizer feed format (`/v1/feeds/colonizer.json`) and MCP tool definitions. The tool **logic** is venture code even after G6 provides the serving.
- Website, explainers, widgets and `llms.txt` content.

## 6. Integrations

### 6.1 Colonizer (colonizer.dev)

Today Colonizer prices **per provider connection** (`Pricing{input,output,cache_read,cache_write,thinking}_per_mtok` in `crates/colonizer/src/providers.rs`, stored in `providers.json`). `providerCatalog.ts` has an empty optional `pricing` field. Unpriced connections count as $0, and the routing cost gate (#470) silently skips when pricing is missing.

What we provide:
1. **`GET /v1/feeds/colonizer.json`**: per `(provider_id, model_slug)` prices, using Colonizer's exact field names (`input_per_mtok`, `output_per_mtok`, `cache_read_per_mtok`, `cache_write_per_mtok`, `thinking_per_mtok`), with `last_verified_at` and an ETag. A compact, stable contract.
2. **Catalogue prefill:** Colonizer fills `CatalogEntry.pricing` and preset pricing from the feed. This is a small PR on the Colonizer side.
3. **Per-model pricing** (Colonizer change): extend `pricing_for` to look up `<provider>/<model>` before the provider-prefix fallback, so two models on one connection can be priced differently. The routing cost gate (#470) and `budget_usd` then work for every model.
4. **"Cheapest provider for this model" hint:** `GET /v1/models/{slug}/cheapest?among=<connected providers>` returns a ranked list. Colonizer's router can show it as a suggestion, or use it as a policy ("route open-weight models to the cheapest healthy host").
5. **Subscription-aware budgeting:** for Claude Max, GLM Coding Plan and the like, the feed also exposes window caps, so Colonizer can show "you have used ~X% of this 5h window" style estimates where vendors publish caps.
6. Colonizer **also runs** the freshness loops (§4). It is both the producer and a consumer of the data.

### 6.2 Cratefield

Cratefield is both the backend (§5) and a consumer of the data: core `cost.rs` `PriceSheet` (pico-USD per token, populated only in tests today) can be filled from the feed for classifier and TextModel cost accounting.

## 7. Business

- **At launch: no affiliate links and no commission.** It is free, open data. Disclosure page from day one: "We earn nothing from any listing today. If that changes, links will be marked and rankings will never depend on it."
- **Later, in order:**
  1. **Affiliate and referral links**, clearly labelled and never affecting rank. They only appear next to an independently computed ranking. Programs with public cash terms (see `docs/research/affiliates_competitors.json`) are Novita (10% for 180 days), BytePlus (Impact, up to 50%, image/video products), Perplexity (Dub, $15–20 per Pro), Vercel v0, Lovable (up to $100), Kilo Code (flat per pass) and Abacus ChatLLM. The Chinese coding plans (Z.AI, Volcengine, MiniMax) pay **credits only**; they cut cost for our own Colonizer runs but are not revenue.
  2. **Paid API tier** through `adapter-polar`: higher rate limits, webhooks, history depth, a commercial-use bulk dataset licence, and SLA'd freshness.
  3. **Sponsored "deal of the week"** slots, labelled, separate from rankings.
  4. **Team budget reports**: upload usage and see the cheapest plan mix. Later, possibly a reseller tie-in.
- **Licence:** data is CC BY 4.0, which creates attribution backlinks. The bulk commercial redistribution feed and SLA are paid.

## 8. Launch milestones

1. **M0 (week 1):** repo with `data/`, the schema, the validator CI and this dataset. A static site on Pages with compare tables, plan pages, `llms.txt` and the JSON/CSV downloads. Waitlist Worker (`waitlist` + Turnstile).
2. **M1 (weeks 2–3):** Colonizer loops for api-daily, plans and discovery, plus merge-train, auto-merge policy and the evidence store. Freshness badges.
3. **M2 (weeks 3–5):** Cratefield Worker serving `/v1` (repo-mirror G1 and history G2 can start as venture-local crates and be upstreamed once proven), the Colonizer feed, the stdio MCP package and the calculator.
4. **M3:** alerts (G4), the change detector (G3), embeds, and API keys (G5).
5. **M4:** affiliate disclosure goes live with the first programs. Paid tier via Polar.

## 9. Risks

- **Vendors that publish no limits** (for example Anthropic's "at least 5x Pro"). Mark these `unknown`, show the vendor's wording, and keep community measurements in a separate, clearly labelled secondary layer.
- **ToS and scraping:** fetch public pages only, at low frequency, honour robots.txt, and prefer JSON/docs endpoints.
- **Mothership dependency:** loops run on one host. The Worker's loop-health alert and the visible staleness are the mitigation; a second mothership is the fix.
- **Credibility with affiliate income:** keep ranking code open-source, never sort by commission, and disclose.
