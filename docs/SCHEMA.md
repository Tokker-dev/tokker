# Part-file contract (for research agents)

Write ONE JSON file: `{"api_offers": [...], "subscriptions": [...], "notes": "..."}` (omit keys you don't fill).
All money in USD unless the provider only publishes another currency — then put the native number + `currency` (ISO) and leave USD conversion to the merge step.
Never invent a number. If not published: the string "unknown". If not applicable: null.
checked = "2026-10-05" (today). source = the exact official URL you fetched.

## api_offers[] (one row per provider x model)
{
  "id": "<provider_id>/<model_slug>",            // stable, lowercase, e.g. "anthropic/claude-sonnet-4-5"
  "provider_id": "anthropic",
  "provider_name": "Anthropic",
  "provider_type": "first_party" | "aggregator" | "inference_host" | "cloud",
  "provider_country": "US",
  "model_slug": "claude-sonnet-4-5",
  "model_name": "Claude Sonnet 4.5",
  "model_creator": "anthropic",
  "open_weights": false,
  "currency": "USD",
  "input_per_mtok": 3.0,
  "output_per_mtok": 15.0,
  "cached_input_per_mtok": 0.3,                 // cache read / hit price
  "cache_write_per_mtok": 3.75 | null | "unknown",
  "batch_discount_pct": 50 | null | "unknown",
  "offpeak": "text e.g. 'DeepSeek 50-75% off 16:30-00:30 UTC'" | null,
  "tiered_pricing": "text if price changes above N tokens context" | null,
  "context_window": 200000 | "unknown",
  "max_output": 64000 | "unknown",
  "free_tier": "text" | null,
  "region_notes": "text" | null,
  "source": "https://...",
  "checked": "2026-10-05",
  "confidence": "official_page" | "official_docs" | "secondary"   // secondary = not from provider's own site; say which in notes
  "notes": "..."
}

## subscriptions[] (one row per plan)
{
  "id": "<vendor_id>/<plan_slug>",              // e.g. "anthropic/claude-max-5x"
  "vendor_id": "anthropic",
  "vendor_name": "Anthropic",
  "product": "Claude",
  "plan_name": "Max 5x",
  "category": "chat" | "coding_agent" | "ide" | "token_plan" | "api_credit_bundle",
  "currency": "USD",
  "price_month": 100,
  "price_year": 1200 | null | "unknown",        // total per year if annual billing offered
  "models_included": ["claude-opus-...", "..."],
  "limits_published": [                          // EXACT wording/numbers as published
     {"window": "5h_rolling" | "daily" | "weekly" | "monthly" | "per_request" | "unspecified",
      "unit": "tokens" | "requests" | "prompts" | "messages" | "credits" | "usd" | "unspecified",
      "amount": 225 | "unknown",
      "quote": "verbatim text from the page"}
  ],
  "fair_use": "verbatim fair-use wording" | null,
  "est_tokens_per_month": 123000000 | "unknown",
  "est_usd_per_mtok_at_full_use": 0.81 | "unknown",
  "estimate_assumption": "e.g. 3 x 5h windows/day x 30d, 40 prompts/window, 30k in + 2k out tokens per prompt (agentic), blended",
  "source": "https://...",
  "checked": "2026-10-05",
  "confidence": "official_page" | "official_docs" | "secondary",
  "notes": "..."
}

## REQUIRED on every api_offers[] and subscriptions[] row: fetch recipe
  "fetch_recipe": {
    "method": "json_api" | "html_static" | "html_js_rendered" | "docs_markdown" | "pdf" | "manual",
    "endpoint": "URL actually best to fetch (e.g. https://openrouter.ai/api/v1/models, or the docs .md URL)",
    "selector_hint": "where on the page the numbers live, e.g. 'pricing table under ## Model pricing' or JSON path 'data[].pricing.prompt'",
    "volatility": "high" | "medium" | "low"   // how often this provider changes prices/limits, your judgement
  }
Note in `notes` if WebFetch failed (JS-rendered / blocked) and what you did instead.

## Also add top-level "sources": [ {"provider_id", "url", "fetch_recipe", "fetch_ok": true|false, "notes"} ] — one per distinct page you fetched.
