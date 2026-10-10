# FX policy

Every `usd{}` block in `data/pricing.json` is derived output: the native
numbers converted at one dated rate set (`fx` at the top level, held in
[`data/fx.json`](../data/fx.json)). No hand-edited USD values — the validator
re-derives every block and rejects drift.

## Source

One source, no blending: the **ECB euro foreign exchange reference rates**,
served as JSON by [frankfurter.app](https://frankfurter.app) (the request goes
to `https://api.frankfurter.app/latest?from=USD`, which today answers at
`https://api.frankfurter.dev/v1/latest?from=USD`; the URL actually fetched is
recorded as `fx.source`). The ECB publishes the reference rates once per
working day, around 16:00 CET on TARGET working days. frankfurter computes the
cross rates for the `USD` base, so `fx.rates` is *units of currency per 1 USD*
and `fx.base` is always the dataset's accounting currency, `USD`.

The daily loop refreshes rates with `npm run fx` (writes `data/fx.json`) and
then rebuilds with `npm run build`. `npm run fx` refuses to write if the
response is missing a rate for any currency a row uses — a silent gap would
break the build.

## Conversion

- **One rate set per dataset.** `fx.date` is the rate date for every row; a
  non-USD row records it as `usd.fx_rate_date`. USD rows convert at 1 and
  carry no `fx_rate_date`.
- **`usd = native / rate`**, per field: the four `*_per_mtok` fields for
  `api_offers`, `price_month`/`price_year` for `subscriptions`.
- **Rounding: 6 significant digits, once.** Each final USD value is rounded to
  6 significant digits (`tools/fx.mjs` `roundSig`); no intermediate result is
  rounded first. `blended_3to1` converts the *unrounded* native blend
  `(3 × input + output) / 4` and rounds only the result.
- **USD rows are normalised too** — the same rounding applies to values that
  need no conversion, so a row's block looks the same in every currency.
- **`null` and `"unknown"` never convert.** A native value the source does not
  publish (`"unknown"`) or that does not apply (`null`) is `null` in `usd`;
  `blended_3to1` is `null` unless input and output are both published numbers.

## Supported currencies

A row's `currency` must be `fx.base` or a key in `fx.rates`. Anything else is
refused: `npm run build` throws and `npm run validate` reports
`currency "XYZ" has no rate in fx (unsupported; see docs/fx.md)`. The seed
dataset uses USD, CNY, EUR, CHF and INR — all covered by the ECB list. There
is **no secondary FX source**; adding one (e.g. for a currency the ECB does
not publish) is a policy change, not a data fix.

**Rows never mix currencies.** One `currency` per row; a provider that bills
the same model in two currencies gets two rows with distinct ids.

## Drift is an error

`tools/validate.mjs` re-derives every usd block from the native values and the
document's `fx` block. A block that disagrees with the build (or an `fx` block
that disagrees with `data/fx.json`) fails validation with
`run npm run build`. After `npm run fx`, always run `npm run build` so the
derived `blended_3to1` values and `derived.cheapest_provider_per_model`
follow the new rates.
