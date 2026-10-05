<p align="center">
  <b>What AI tokens really cost, per million, with the source for every number.</b><br>
  An open price index for AI APIs and AI subscriptions, kept current by scheduled agents.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/STATUS-IN%20DEVELOPMENT-F2B33D?style=flat-square&labelColor=101418" alt="Status: in development">
  <img src="https://img.shields.io/badge/DATA-CC%20BY%204.0%20(PROPOSED)-E8EAED?style=flat-square&labelColor=101418" alt="Data: CC BY 4.0, proposed">
  <img src="https://img.shields.io/badge/CODE-APACHE--2.0-E8EAED?style=flat-square&labelColor=101418" alt="Code: Apache-2.0">
  <img src="https://img.shields.io/badge/RUNTIME-CLOUDFLARE%20WORKERS-E8EAED?style=flat-square&labelColor=101418" alt="Runtime: Cloudflare Workers">
  <img src="https://img.shields.io/badge/HARNESS-CRATEFIELD-E8EAED?style=flat-square&labelColor=101418" alt="Harness: Cratefield">
</p>

<p align="center">
  <a href="https://tokker.dev">tokker.dev</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/Tokker-dev/tokker/issues">The plan, as issues</a>
  &nbsp;·&nbsp;
  <a href="docs/plan.md">The plan</a>
  &nbsp;·&nbsp;
  <a href="data/pricing.json">The data</a>
  &nbsp;·&nbsp;
  <a href="docs/SCHEMA.md">Schema</a>
</p>

> **In development.** What exists today is the seed dataset in [`data/`](data/) (prices as of 2026-10-05) and the plan.
> There is no API, MCP server, alert or website yet; each lands issue by issue. Nothing is deployed.

---

## Why

AI pricing is a mess. About 60 API providers quote $/1M tokens in different currencies, with cache, batch,
off-peak and regional surcharges. Subscriptions (Claude Max, ChatGPT Pro, Gemini, Cursor, Copilot, the Z.AI,
Alibaba and BytePlus coding plans and others) hide their limits in 5-hour windows, weekly caps and
"fair use" wording. Nobody can say what a plan's tokens cost, and Western and Chinese plans are never
compared side by side.

Tokker is one open, sourced index of both halves:

1. **API prices.** Every provider and model in $ per 1M tokens: input, output, cache read and write,
   batch and off-peak discounts, context tiers, free tiers, and region and currency notes.
2. **Subscriptions.** Each plan's **published limits, verbatim**, and an **estimated $ per 1M tokens at
   full use**, with the assumption written on the row. That puts a $200 plan and an API on one scale.

## What is in the seed dataset

As of 2026-10-05: 62 API providers and 480 offers, 103 subscription plans from 32 vendors, 158 sources,
and 47 models priced at two or more providers. Highlights are in [`docs/report.md`](docs/report.md).

| File | What it is |
| :--- | :--- |
| [`data/pricing.json`](data/pricing.json) | The whole dataset, schema `1.0.0`: providers, API offers, subscriptions, FX, cheapest provider per model, sources |
| [`data/pricing_api.csv`](data/pricing_api.csv) | API offers, one row per provider × model |
| [`data/pricing_subscriptions.csv`](data/pricing_subscriptions.csv) | Subscriptions, one row per plan |
| [`docs/SCHEMA.md`](docs/SCHEMA.md) | The row contract the research used; schema v1 formalises it |

Three rules hold for every row:

- **Every number has a source.** `provenance` names the page, when it was fetched, how, and how official it is
  (`official_page`, `official_docs` or `secondary`). `last_verified_at` says when it last agreed with the source.
- **Missing is `"unknown"`, never a guess.** `null` means not applicable. A plan whose vendor publishes no cap
  gets no $/1M estimate.
- **Native currency first.** Prices stay in the currency the provider publishes; the `usd` block converts
  them at the dataset's ECB reference date.

## How it stays true

Prices change weekly, so freshness is the product. Scheduled [Colonizer](https://colonizer.dev) loops re-check
every source on a cadence set by its `fetch_recipe.volatility` (daily for most APIs, every 6 hours for volatile
providers, daily or weekly for plans, plus a weekly discovery run for new providers and plans). Each run saves
the fetched page as evidence, extracts the numbers, diffs them against `data/`, fetches again to confirm any
change, and opens a pull request with the change table. Small, confirmed changes merge automatically; changes to
limit windows, units, fair-use wording or anything from a secondary source wait for a human. Anything past its
freshness window is flagged stale on every surface. The details are in [`docs/plan.md` §4](docs/plan.md).

## Planned surfaces

Planned; names and paths may change before launch.

```sh
curl "https://api.tokker.dev/v1/offers?model=claude-opus-5-5"
curl "https://api.tokker.dev/v1/models/glm-5.3/cheapest"
curl -X POST https://api.tokker.dev/v1/estimate -d '{"input_mtok":400,"output_mtok":30,"cache_hit_pct":90}'
```

```json
{
  "mcpServers": {
    "tokker": { "command": "npx", "args": ["-y", "@tokker/mcp"] }
  }
}
```

- A free JSON API (`/v1`), CORS-open, with a free anonymous rate limit and keys for more.
- An MCP server with `search_models`, `get_price`, `cheapest_provider`, `estimate_cost`, `compare_plans` and `get_changes`.
- `llms.txt`, JSON and CSV downloads, and tagged dataset releases.
- Change history and a weekly "what changed" feed; price-drop alerts by email (through [Owlpost](https://owlpost.pages.dev)) or webhook.
- A price feed in [Colonizer](https://colonizer.dev)'s own field names, for its router and budgets.

## Architecture

A Rust Worker on the [Cratefield harness](https://github.com/Cratefield/harness) (D1, KV, R2) serves the API.
It mirrors `data/` from `main` into D1, so a merged pull request is the only way a price changes. Data tooling
(validation, fetch, extract, diff) lives in this repository and runs in CI and in the Colonizer loops.

Only generic, reusable pieces go into Cratefield (mirroring data files from a repo, versioned record history,
a source watcher, rule-based alerts, self-serve API keys, MCP serving from the Worker). Everything about prices
(the schema, extractors, token math, the calculator, FX and the merge rules) stays here. The split and the
upstream issues are in [`docs/plan.md` §5](docs/plan.md).

## Roadmap

| Milestone | What it delivers | Issues |
| :--- | :--- | :--- |
| **M0 · Foundation** | the workspace and CI, schema v1 and its validator, the seed dataset split per provider, the Worker, the waitlist | [label: M0](https://github.com/Tokker-dev/tokker/issues?q=is%3Aissue+label%3AM0) |
| **M1 · Launch** | the read API, the calculator, the MCP server, `llms.txt`; the scheduled freshness loops, extractors, evidence and merge rules | [label: M1](https://github.com/Tokker-dev/tokker/issues?q=is%3Aissue+label%3AM1) |
| **M2 · After launch** | history and the change feed, price-drop alerts through Owlpost, API keys, the Colonizer feed, dataset releases, embeds | [label: M2](https://github.com/Tokker-dev/tokker/issues?q=is%3Aissue+label%3AM2) |
| **Later** | affiliate links (disclosed, never affecting rank) and a paid tier through Polar | [label: later](https://github.com/Tokker-dev/tokker/issues?q=is%3Aissue+label%3Alater) |

The critical path to a launched API is #8 → #9 → #10 → #15 → #16 → #19 → #20 / #21 → #22 → #28, and freshness
runs #30 → #31 → #37 → #38 → #39 → #44. Upstream harness work it waits on:
[Cratefield/harness#768](https://github.com/Cratefield/harness/issues/768) (repo mirror),
[#775](https://github.com/Cratefield/harness/issues/775) (llms.txt route) and
[Colonizer-dev/harness#1037](https://github.com/Colonizer-dev/harness/issues/1037) (the data-refresh loop template).
Epics: [#1](https://github.com/Tokker-dev/tokker/issues/1) M0 · [#2](https://github.com/Tokker-dev/tokker/issues/2) API and MCP ·
[#3](https://github.com/Tokker-dev/tokker/issues/3) freshness · [#4](https://github.com/Tokker-dev/tokker/issues/4) alerts and accounts ·
[#5](https://github.com/Tokker-dev/tokker/issues/5) integrations · [#6](https://github.com/Tokker-dev/tokker/issues/6) later.

## Money

Free and open first. There are **no affiliate or referral links at launch** and we earn nothing from any
listing. If that changes, links will be marked, and ranking code stays open and never sorts by commission.

## Licence

Code: [Apache-2.0](LICENSE). Data in [`data/`](data/): [CC BY 4.0](data/LICENSE) (proposed; the decision is
tracked as an issue). Attribution: "Tokker (tokker.dev)", with a link.

---

<p align="center">
  <a href="https://tokker.dev"><b>tokker.dev</b></a>
  &nbsp;·&nbsp;
  a <a href="https://factory0.ventures">Factory Zero</a> venture
</p>
