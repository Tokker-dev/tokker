# CLAUDE.md

House rules for coding agents and humans working on Tokker. `AGENTS.md` is a symlink to this file.
Read [`docs/plan.md`](docs/plan.md) before changing behaviour; it records what was decided and why.

## What this repository is

The product: the open price index for AI tokens and subscriptions. It holds the data, the schema,
the data tooling (validate, fetch, extract, diff), the Colonizer loop prompts, and the Cratefield
Worker that serves the API and MCP. The website lives in `Tokker-dev/website`.

## Layout

| Path | What it is |
| :--- | :--- |
| `data/` | the dataset, licensed separately (`data/LICENSE`). Today `pricing.json` plus two CSV exports; it is split per provider by an M0 issue |
| `docs/` | the plan, the research report, the schema notes, design decisions |
| `schema/` | (planned) `pricing.v1.json`, the JSON Schema every data file must pass |
| `tools/` | (planned) data tooling: validate, build, fetch, extract, diff, confirm |
| `extractors/` | (planned) one extractor per provider or plan source |
| `loops/` | (planned) the Colonizer loop prompts and their `colonizer loop create` lines |
| `evidence/` | (planned) fetched source snapshots, `evidence/<date>/<sha256>.*` |
| `crates/` | (planned) the Rust workspace: the Worker and its modules |

## Data rules (the product is trust)

1. **Never invent a number.** Not published by the source means the string `"unknown"`. Not applicable means `null`.
2. **Every value has a source.** A new or changed value comes with `provenance` (source URL, `fetched_at`,
   `method`, `confidence`) and a fresh `last_verified_at`. A value from a page other than the row's default
   gets its own entry in `provenance.fields`.
3. **Ids are stable and never reused.** `"<provider_id>/<model_slug>"` and `"<vendor_id>/<plan_slug>"`,
   lowercase. A renamed model gets a new id with `supersedes`.
4. **Native currency first.** Store the published currency; the `usd` block is derived from `fx`.
5. **Subscription limits are quoted verbatim** in `limits_published[].quote`. An estimate of
   $/1M at full use names its assumption profile; with no published cap the estimate is `"unknown"`.
6. **Secondary sources are labelled** `confidence: "secondary"` and always need human review.
7. **Schema changes follow semver.** Additive is minor; a rename or removal is major and needs a new `/v2`.

## Where code goes

Generic, reusable code (no pricing concepts) belongs in [Cratefield/harness](https://github.com/Cratefield/harness)
or [Colonizer-dev/harness](https://github.com/Colonizer-dev/harness) as an upstream issue, not here. The
pricing schema, extractors, token math, calculator, FX policy, merge-policy thresholds and affiliate
handling stay in this repository. Issues blocked on an upstream change carry the `needs-harness` label.

## Dependencies

All `cratefield-*` crates share one source: the same crates.io line, or all pinned to the same
Cratefield/harness git rev in the root `[workspace.dependencies]`. Never mix them;
`cargo tree -d --depth 0 | grep cratefield` must print nothing.

## Fetching sources

Fetch public pages only, at low frequency, honour `robots.txt`, identify the client in `User-Agent`, and
prefer JSON and docs endpoints over rendered HTML. Never use an account, a login or a paid key to read a price.

## Secrets

Never print, log or commit a secret: `HARNESS_SECRET`, `ADMIN_TOKEN`, Owlpost and Polar keys, the Colonizer
API token, Turnstile secrets, or any Tokker API key. `.dev.vars` and `.env*` stay untracked.

## Deploys and money

Run `wrangler deploy`, remote D1 migrations, DNS changes and Colonizer loop creation only when a human asks.
Issues labelled `needs-human` are owner decisions or owner-only actions; do not attempt them.
No affiliate or referral link ships without the disclosure issue being done.

## Before handing work back

Run the checks CI runs (they land with the scaffold issue). Work that fails them is not done.
Commits follow Conventional Commits and name the issue number.
