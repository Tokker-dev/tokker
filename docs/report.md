> Research snapshot from 2026-10-05, written before the name was chosen. The venture is **Tokker** (tokker.dev); the "Name" section below is the shortlist as it stood then.

# LLM price index: findings (2026-10-05)

## Coverage
- 62 API providers and 480 offer rows. OpenRouter alone lists 466 models; 31 representative ones are included.
- 103 subscription plans from 32 vendors.
- 47 models are priced at two or more providers.
- 158 sources, each with a fetch recipe.
- Numbers a vendor doesn't publish are `unknown`.
- Non-USD prices are kept as published and converted at ECB rates dated 2026-10-02.

## Cheapest by tier (USD per 1M tokens, input/output)
- **Frontier:**
  - Claude Opus 5.5: $4/$20 (cache read $0.20)
  - GPT-6 Sol: $2/$10
  - Gemini 3.1 Pro Preview: $2/$12
  - Regional endpoints add 10%.
- **Mid:**
  - Gemini 3.x Flash: $0.75/$3.75 (doubles on 2027-01-01)
  - Mistral Large 3: $0.50/$1.50
  - MiniMax-M3: $0.30/$1.20
- **Open-weight:**
  - Kimi K3: about $3/$15 (DeepInfra $2.85/$14.25)
  - GLM-5.3: $1.40/$4.40 (DeepInfra $0.90/$4.00)
  - DeepSeek V4 Flash: $0.30/$1.20 at peak, half price off-peak; $0.06/$0.18 on DeepInfra.
- **Cheap:**
  - gpt-oss-120b: from $0.037/$0.17
  - gpt-oss-20b and Qwen3.7-Flash: about $0.03–0.05 blended
  - GLM-4.7-Flash and Cohere Command A+: free
- **International vs China:** international sites are often cheaper than the China sites (BytePlus vs Volcengine, api.z.ai vs bigmodel.cn).

## Subscription token math
Assumption `agentic-coding-v1`: one call = 20k input tokens (90% cached) + 1.5k output; 4 five-hour windows a day; a lower weekly or monthly cap binds first.

| Plan | $ per 1M tokens at full use |
|---|---|
| Google AI Pro (Gemini CLI) | 0.021 |
| Synthetic $30 | 0.023 |
| Alibaba Coding Plan Pro | 0.026 |
| BytePlus Lite | 0.039 |
| ChatGPT Pro | about 0.044 (low confidence) |
| Claude Pro / Max 5x | about 0.065 (secondary sources) |
| Claude Max 20x | about 0.077 (weekly cap binds) |
| Z.AI | 0.10–0.16 (about half off-peak) |
| Copilot credits | 0.53–1.05 |

- The same tokens cost about $1.05 per 1M through the Sonnet API, so subscriptions are 20–200x cheaper at full use.
- The weekly or monthly cap almost always binds before the 5-hour window does.
- No absolute limits published: Anthropic, Cursor, Devin/Windsurf, Factory, MiniMax M Plan, xAI, Mistral, Perplexity, Kimi Code, Volcengine, Alibaba Token Plan, Amp, Kiro, CodeBuddy.

## Affiliates
- **Cash:**
  - Novita: 10% of spend for 180 days.
  - BytePlus: via Impact, up to 50%, for image/video products.
  - Perplexity: $15–20 per Pro subscription.
  - Vercel v0: unverified.
  - Lovable: up to $100 per subscriber.
  - Kilo Code, Abacus, RunPod, Alibaba Cloud, Google Workspace.
- **Credits only:** the Chinese coding plans (Z.AI, Volcengine, MiniMax) and others.
- **None:** OpenAI, xAI, Mistral, Copilot, DeepSeek, OpenRouter, Together, Groq, Fireworks, DeepInfra.
- **Takeaway:** the money sits with app-layer tools, so launching without affiliates loses little.

## Competitors
- Artificial Analysis: benchmarks, with a restrictive data licence.
- Price Per Token: MCP and price history, but no subscription window math.
- AI Pricing Guru: 31 plans, non-commercial licence.
- models.dev, LiteLLM, Portkey, Helicone: API prices only.
- codingplan.org: Chinese plans with referral codes, no math.

**Gap:** open, sourced data that covers both API prices and subscription windows, China and the EU included, with an API, MCP, history and alerts.

## Name (none registered)
| Rank | Domain | Spaceship price (first year / renewal) |
|---|---|---|
| 1 | tokdex.dev | $8.48 / $12.62 |
| 2 | permtok.dev | $8.48 / $12.62 |
| 3 | tokenbarga.in | $5.97 / $5.97 |

- All three are unregistered per RDAP, checked against a control domain.
- The best domain hack, tokenco.st, can't be bought on Spaceship.

## Caveats
- Some vendor pages returned 403 or only render in a browser; those rows come from secondary sources or are `unknown`.
- Joining the same model across hosts depends on consistent model naming, which is the main risk.
- OpenRouter's top-level price can pair a promotional input price with a high output price.
- Every number is as of 2026-10-05.
