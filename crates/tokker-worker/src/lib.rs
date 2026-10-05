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

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use cratefield_core::{Harness, Venture};
use cratefield_runtime_cloudflare::{Cloudflare, serve};
use tokker_api::TokkerApi;
use worker::{Context, Env, Request, Response, event};

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

fn instance() -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let harness = Harness::builder()
            .venture(Venture::new("tokker", "tokker.dev").public_url("https://tokker.dev"))
            .module(TokkerApi)
            .runtime(Cloudflare::new().db("DB"))
            .build()
            .expect("tokker harness is valid");
        let runtime = Cloudflare::new().db("DB");
        (harness, runtime)
    })
}

/// Worker fetch entry point.
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router.
#[event(fetch)]
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let (harness, runtime) = instance();
    serve(harness, runtime, req, env, ctx).await
}
