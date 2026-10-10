//! The Tokker Cloudflare Worker.
//!
//! A venture's Worker is three lines (ADR 0001):
//!
//! ```ignore
//! #[event(fetch)]
//! pub async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
//!     let (harness, runtime) = instance();
//!     serve(harness, runtime, req, env, ctx).await
//! }
//! ```
//!
//! Bindings follow plan.md §5.1: D1 (`DB`) for the price tables, KV (`KV`)
//! for hot JSON responses, R2 (`BUCKET`) for evidence snapshots and CSV
//! downloads, and the Workers rate limiting binding (`RATE_LIMITER`) for
//! anonymous IP limits. The crons live in `wrangler.toml` `[triggers]`,
//! hand-maintained until Cratefield's manifest cron field lands
//! (plan.md §5.2 G7a).

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use cratefield_core::{Harness, Venture};
use cratefield_runtime_cloudflare::{Cloudflare, serve, serve_scheduled};
use tokker_api::TokkerApi;
use worker::{Context, Env, Request, Response, ScheduleContext, ScheduledEvent, event};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

/// The harness and its runtime, built once per isolate.
///
/// The runtime is constructed once and cloned into the builder —
/// `Cloudflare` is `Clone` (it carries binding names, not bindings) — so
/// the fetch and scheduled entry points share one composition.
fn instance() -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let runtime = Cloudflare::new()
            .db("DB")
            .kv("KV")
            .blob("BUCKET")
            .rate_limiter("RATE_LIMITER");
        let harness = Harness::builder()
            .venture(
                Venture::new("tokker", "tokker.dev")
                    .public_url("https://tokker.dev")
                    // The site that embeds the API (plan.md §5): build()
                    // refuses a venture with no CORS origin at all.
                    .cors_origins(["https://tokker.dev"]),
            )
            .module(TokkerApi)
            .runtime(runtime.clone())
            .build()
            .expect("tokker harness is valid");
        (harness, runtime)
    })
}

/// Worker fetch entry point: the harness router answers `/v1/*` and the
/// built-in probes (`/__health`, `/__ready`, `/__surface`).
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router.
#[event(fetch)]
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let (harness, runtime) = instance();
    serve(harness, runtime, req, env, ctx).await
}

/// Worker cron entry point: fans the scheduled event out to every module's
/// `scheduled` under the runtime's scheduled limits.
#[event(scheduled)]
pub async fn scheduled(event: ScheduledEvent, env: Env, ctx: ScheduleContext) {
    let (harness, runtime) = instance();
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
