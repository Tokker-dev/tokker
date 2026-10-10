# loops

The Colonizer loop prompts and their `colonizer loop create` lines.

| Loop | Cadence | Purpose |
| :--- | :--- | :--- |
| `api-daily` | daily@05:00 | Per-provider API pricing shards. |
| `volatile-6h` | 6h | Volatile sources: OpenRouter, DeepSeek, Z.AI, Cursor, Copilot, etc. |
| `plans-weekly` | weekly@mon@06:00 | Subscription limits and plans. |
| `discovery` | weekly@thu@07:00 | New providers, models and plans. |

See `docs/plan.md` §4.8 for the `colonizer loop create` lines. The `api-daily`
loop starts with `npm run fx && npm run build` so USD conversions and the
derived cheapest-provider ranking follow the fresh rates (`docs/fx.md`).
