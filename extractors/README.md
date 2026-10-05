# extractors

One extractor per provider or plan source (`extractors/<provider>.ts`). A
deterministic parser where possible, with the LLM as fallback. Each reads
fetched evidence and emits rows in the `pricing.json` schema.

See `docs/plan.md` §4.3 for the extract step.
