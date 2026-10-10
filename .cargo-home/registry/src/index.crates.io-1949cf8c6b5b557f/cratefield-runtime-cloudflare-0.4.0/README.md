<p align="center">
  <a href="https://github.com/Cratefield/harness">
    <img src="https://raw.githubusercontent.com/Cratefield/harness/main/assets/banners/cratefield-runtime-cloudflare.png" alt="cratefield-runtime-cloudflare — One stateless Worker." width="100%">
  </a>
</p>

<p align="center">
  <a href="https://crates.io/crates/cratefield-runtime-cloudflare"><img src="https://img.shields.io/crates/v/cratefield-runtime-cloudflare.svg?style=flat-square&labelColor=0A0A0B&color=4C6FFF" alt="cratefield-runtime-cloudflare on crates.io"></a>
  <a href="https://docs.rs/cratefield-runtime-cloudflare"><img src="https://img.shields.io/docsrs/cratefield-runtime-cloudflare?style=flat-square&labelColor=0A0A0B&color=EDEBE6" alt="cratefield-runtime-cloudflare documentation"></a>
  <a href="https://github.com/Cratefield/harness/blob/main/LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-4C6FFF?style=flat-square&labelColor=0A0A0B" alt="MIT"></a>
</p>

# cratefield-runtime-cloudflare

Cloudflare Workers runtime for the [Cratefield harness](https://github.com/Cratefield/harness):
maps Workers bindings to the harness ports and serves a `Harness` on
`#[event(fetch)]` / `#[event(scheduled)]`.

## Usage

A venture's Worker is three lines:

```rust,ignore
use cratefield_core::Harness;
use cratefield_runtime_cloudflare::{serve, serve_scheduled, Cloudflare};
use std::sync::OnceLock;
use worker::{event, Context, Env, Request, Response};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let (harness, runtime) = INSTANCE.get_or_init(build);
    serve(harness, runtime, req, env, ctx).await
}

#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    let (harness, runtime) = INSTANCE.get_or_init(build);
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
```

The runtime builder: `Cloudflare::new().db("DB").kv("KV").rate_limiter("RATE_LIMITER")`
plus `.mailer(...)`/`.captcha(...)` with adapter instances. For per-key
limits (per plan, per address — the binding above is one limit per
namespace), wire `.d1_rate_limiter("DB", policy)` instead: a D1-backed
fixed window per key whose policy maps each key to its cap. Ship the
table it counts in by adding the `RATE_LIMIT_COUNTERS_SQL` statement to
the venture's `migrations/` directory.

## wrangler.toml

```toml
name = "my-venture-api"
main = "build/worker/shim.mjs"
compatibility_date = "2026-09-01"

[build]
command = "cargo install -q worker-build && worker-build --release"

[observability]
enabled = true

[[d1_databases]]
binding = "DB"
database_name = "my-venture-db"
database_id = "<uuid>"
migrations_dir = "migrations"

# Optional bindings:
# [kv_namespaces] binding = "KV", id = "..."
# [unsafe.bindings] name = "RATE_LIMITER", type = "ratelimit"
```

Secrets (`wrangler secret put`, or `.dev.vars` locally — copy `.dev.vars.example`):
`HARNESS_SECRET` (required for the Signer port, ≥ 32 bytes),
`HARNESS_SECRET_PREVIOUS` (rotation), `ADMIN_TOKEN`, `ENV`.

## wasm notes (workerd/miniflare, wrangler 4.x)

These are empirical facts recorded while building this crate; see
`PROGRESS.md` issue #5 for the full debugging history:

- The `worker` crate's `http` feature stays **off**: with it enabled, D1
  writes hang the isolate. `serve()` therefore takes the native
  `worker::Request` (the fetch macro's `FromRequest` accepts it).
- Request bodies are gated before they are resident (issue #440): a
  `content-length` over the route's ceiling is refused unread, and a body
  with no usable `content-length` is read through `Request::stream()` and
  cut off once the ceiling is passed. A request with no body at all (most
  GETs) is answered as empty without any read: 0.8.5's `stream()` sets
  `body_used` before discovering there is no body, after which `bytes()`
  only answers `BodyUsed`. Declared lengths within the ceiling
  are still buffered via `Request::bytes()`; every streaming bridge
  between `worker::Body` and axum hangs.
- A route a module declares in `streaming_routes()` is served opt-in in
  streaming mode (issue #585). The request half turns `Request::stream()`
  into a `RequestStream` (a `!Send` worker `ByteStream` behind
  `worker::send::SendWrapper`, sound because an isolate is single-threaded
  — ADR 0002) and hands the router an empty body plus the handle, so
  nothing is buffered; a `content-length` over the route's own ceiling is
  still refused unread. The response half takes the `ResponseStream` a
  handler left in the response extensions and bridges it with
  `worker::Response::from_stream` — never `to_bytes`, which is capped at
  1 MiB and for a stream would be the hang above. Every non-streaming
  response is still buffered under that 1 MiB ceiling.
- `wrangler dev` only: refusing a body unread (issue #440) leaves the
  tail undrained, and the dev proxy's `middleware-ensure-req-body-drained`
  logs `Failed to drain the unused request body. Error: Network connection
  lost.` and breaks miniflare's `ProxyWorker` loopback slot, so the NEXT
  local request fails with a spurious 500 `Network connection lost` — it
  never reaches the isolate. Exactly one request is lost and the dev
  server recovers by itself; a client that overstates `content-length`
  and then sends fewer bytes may see the 413 withheld locally for the
  same reason. Dev-proxy artefact only: production workerd cancels
  unread request bodies natively (no `ProxyWorker`, no drain middleware).
  Verified wrangler 4.135.0 / workerd 1.20260918.1; known upstream as
  workers-sdk issue #4562.
- Installing a `tracing` dispatcher (`set_global_default`/`set_default`)
  hangs the isolate, so `install_tracing()` is a no-op on wasm and runtime
  logs go through `worker::console_log!`/`console_error!` directly
  (`rt_log!`). The JSON-lines subscriber with field redaction is used on
  native runs.
- The `time` crate needs its `wasm-bindgen` feature for `now_utc()` on
  wasm (pinned in the workspace `Cargo.toml`); without it every clock read
  panics (`time not implemented on this platform`).

---

MIT. Built in the open for [Cratefield](https://cratefield.com), a [Factory Zero](https://factory0.ventures) venture.
