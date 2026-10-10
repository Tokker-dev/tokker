<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-core.png" alt="cratefield-core — The kernel." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-core"><img src="https://img.shields.io/crates/v/cratefield-core.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-core on crates.io"></a>
  <a href="https://docs.rs/cratefield-core"><img src="https://img.shields.io/docsrs/cratefield-core?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-core documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-core

The runtime-agnostic kernel of the Cratefield harness: the [`Module`]
contract, the [`Harness`] builder, the port traits, RFC 9457
problem+json errors, the request [`Scope`], an in-process [`EventBus`],
and the template registry (ADRs 0001, 0002, 0007).

Core depends only on `http`, `axum` (default features off), `serde`,
`tracing`, `sea-query` and pure-Rust crypto. It must never depend on
`worker`, `wasm-bindgen`, `tokio`, `reqwest`, `sqlx` or `rusqlite` — a
CI job fails the build if one appears. That is what lets the same
modules run on Cloudflare Workers (wasm) and, in phase 3, as a native
binary.

## The shape

```text
Harness::builder()
    .venture(Venture::new("acme", "acme.example.com").cors_origins([..]))
    .module(EmailSignup::new().double_opt_in(true))     // any Module impl
    .templates(EmailSignup::default_templates())        // + overrides
    .runtime(Cloudflare::new().db("DB"))                // any Runtime impl
    .build()?                                            // all problems at once
```

`build()` refuses a module that requires a port the runtime does not
provide, two modules claiming the same table or route prefix, a module
built against a different contract version (`HARNESS_API`), or a
template override naming an unknown module — and it reports every
problem in one error, not the first. `router(ports)` then mounts each
module under `/v1/<name>`, adds `GET /__health` / `GET /__ready`, the
request-scope middleware (request id + `Scope` in extensions, ADR 0007),
CORS from `venture.cors_origins`, a 64 KiB body limit and `/v1/*`
security headers.

## What lives here

| Piece | What it is |
|---|---|
| `Module` / `ModuleContext` | the module contract; see [docs/MODULE-AUTHORING.md](https://github.com/Cratefield/harness/blob/main/docs/MODULE-AUTHORING.md) |
| `Harness` / `HarnessBuilder` | composition, validation, router assembly |
| `ports::*` | `Database`, `Mailer`, `Captcha`, `RateLimiter`, `Signer`, `KeyValue`, `HttpClient`, `Clock`, `IdGen`, `Defer` — `Send + Sync` trait objects |
| `Problem` / `problems!` | RFC 9457 errors with a stable slug taxonomy (generated into `docs/ERRORS.md`) |
| `Scope` | per-request id + span + `wait_until`, an axum extractor, never shared state |
| `EventBus` | in-process `"<module>.<event>"` handlers, run in the emitting request's scope |
| `TemplateRegistry` | mail templates with per-venture overrides |
| `HmacSigner` | signed tokens for confirm/unsubscribe links with key rotation (ADR 0006) |
| admin / csv / email / rate-limit helpers | constant-time admin auth, formula-injection-safe CSV, email normalization |

## Writing a module

Start with [docs/MODULE-AUTHORING.md](https://github.com/Cratefield/harness/blob/main/docs/MODULE-AUTHORING.md) —
it builds a complete module, `cratefield-module-hello`, step by step.

## Testing a module

[`cratefield-testing`](https://github.com/Cratefield/harness/tree/main/crates/testing) is the conformance kit: fake ports, an
in-memory SQLite `Database`, and request helpers over the real axum
router, no network. Every module — public or private — passes it.

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
