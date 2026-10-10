//! `cratefield-runtime-cloudflare` runs a Factory Zero [`Harness`] on
//! Cloudflare Workers (ADR 0001, 0002). It maps bindings to ports:
//! D1 -> `Database`, KV -> `KeyValue`, the Rate Limiting binding ->
//! `RateLimiter`, `HARNESS_SECRET` -> `Signer`, `Context::wait_until` ->
//! `Defer`, `worker::Fetch` -> `HttpClient`.
//!
//! A venture's Worker is three lines:
//!
//! ```ignore
//! #[event(fetch)]
//! pub async fn fetch(req: HttpRequest, env: Env, ctx: Context)
//!     -> Result<http::Response<axum::body::Body>> {
//!     let (harness, runtime) = INSTANCE.get_or_init(build);
//!     serve(harness, runtime, req, env, ctx).await
//! }
//! ```
//!
//! Every port adapter here holds JS handles that workers-rs already marks
//! `Send + Sync` (`unsafe impl` inside the `worker` crate, sound because a
//! Workers isolate is single-threaded — ADR 0002). This crate itself
//! contains no `unsafe`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod body_limit;
mod config;
mod ports;
mod runtime;
mod tracing_setup;

pub use config::EnvConfig;
pub use ports::{
    ContextDefer, D1Database, D1RateLimiter, FetchClient, KvStorePort, Limit,
    RATE_LIMIT_COUNTERS_SQL, RateLimitPolicy, RateLimitPort, RoomDriver, ScheduleDefer,
    WorkersClock, client_ip,
};
pub use runtime::Cloudflare;
pub use tracing_setup::install_tracing;

use crate::body_limit::{BodyPlan, Capped, body_plan, read_capped};
use crate::runtime::{WARNED_UNRESOLVED_LIMITER, warn_once};
use cratefield_core::{
    Harness, Problem, RequestStream, RequestSummary, ResponseStream, SLUGS, ScheduledLimits,
    ScheduledSplit,
};
use futures_core::Stream;
use futures_util::StreamExt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use time::OffsetDateTime;
use tower::ServiceExt;
use worker::send::SendWrapper;
use worker::{Context, Env, Request as WorkerRequest, Response as WorkerResponse};

/// Runs every module's [`Module::validate_config`] against the live config
/// once per isolate and logs any failure to `console_error!`. `validate_config`
/// cannot run at build or in `fz doctor` (neither has the deploy config; it
/// lives on the `Env`), so cold start is the first place it can, and this
/// makes a misconfigured deployment loud in Workers Logs (issue #101). It only
/// logs — a bad module still degrades per request rather than failing the whole
/// Worker's boot; that harder behaviour is a decision for an ADR.
fn check_module_config_once(harness: &Harness, config: &dyn cratefield_core::Config) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CHECKED: AtomicBool = AtomicBool::new(false);
    if CHECKED.swap(true, Ordering::Relaxed) {
        return;
    }
    for module in harness.modules() {
        if let Err(err) = module.validate_config(config) {
            worker::console_error!(
                "[config] module `{}` has invalid configuration: {err}",
                module.name()
            );
        }
    }
}

/// Logs the push wiring report once per isolate, next to
/// [`check_module_config_once`] (issue #191). Names and verdicts only —
/// [`PushWiring::summary`](cratefield_push_wiring::PushWiring::summary) never
/// carries a value, so no secret can reach Workers Logs through it.
///
/// A half-wired transport is `console_error!` in production and
/// `console_log!` below it: a venture that meant to enable FCM and mistyped
/// one variable must not boot into a state where every Android send silently
/// answers `NotConfigured`, while a developer wiring a transport one variable
/// at a time must still be able to boot. Like the module-config check this
/// only logs; refusing to serve is a decision for an ADR, and `fz doctor` is
/// what refuses a deploy.
///
/// Nothing is logged when the venture passed its own adapter: `push_wiring`
/// answers `None`, so no environment is read and no transport the venture
/// deliberately overrode is reported on. It runs after `ports()`, which has
/// already assembled and memoised the adapters, so this reads a report
/// rather than building one.
#[cfg(feature = "push")]
fn check_push_wiring_once(
    harness: &Harness,
    runtime: &Cloudflare,
    env: &Env,
    config: &dyn cratefield_core::Config,
) {
    use cratefield_push_wiring::WiringSeverity;
    use std::sync::atomic::{AtomicBool, Ordering};
    static CHECKED: AtomicBool = AtomicBool::new(false);
    if CHECKED.swap(true, Ordering::Relaxed) {
        return;
    }
    let Some(wiring) = runtime.push_wiring(env) else {
        return;
    };
    worker::console_log!("[push] {}", wiring.summary());
    let deployed = cratefield_core::deployed_env(harness.venture().env, config);
    match wiring.severity(deployed) {
        WiringSeverity::Ok => {}
        WiringSeverity::Warning => {
            for problem in wiring.problems() {
                worker::console_log!("[push] warning: {problem}");
            }
        }
        WiringSeverity::Error => {
            for problem in wiring.problems() {
                worker::console_error!("[push] {problem}");
            }
        }
    }
}

/// Serves one fetch event: resolves ports from the bindings, builds the
/// router, refuses an oversize body before it is resident, hands the
/// request over, and converts the response (issue #440).
///
/// Takes the native `worker::Request` (the fetch macro's `FromRequest`
/// accepts it): `Request::bytes()` is the only body read that reliably
/// resolves under workerd/miniflare — streaming a `worker::Body` through
/// the axum bridge or re-wrapping it into `web_sys::Request` hangs the
/// isolate (verified empirically). `bytes()` therefore remains the read for
/// every body that declares a `content-length` within the ceiling.
///
/// Before any byte is read, the request's per-module body ceiling is looked
/// up from the path ([`Harness::max_body_bytes`]) — the coarse value a
/// module may raise (LinkedIn's image upload), never lower. A declared
/// `content-length` above it is answered `413` (`request-too-large`)
/// without reading the body: an isolate has a fixed memory ceiling, and the
/// router's `DefaultBodyLimit` only fires once the body is already
/// resident, which is too late for a Worker that has already died. A body
/// with no usable `content-length` — chunked, streamed, or a header that
/// does not parse — is read through `Request::stream()` (a worker-native
/// stream, not the hanging axum bridge) and aborted the moment it passes
/// the ceiling, so nothing larger than the ceiling is ever held. A request
/// with no body at all — most GETs, HEAD, OPTIONS — reaches the router as
/// an empty buffer without any read: worker 0.8.5's `Request::stream()`
/// sets `body_used` before discovering there is no body, so the bodyless
/// case is detected through `inner()` first (issue #440). Inside the
/// router, `DefaultBodyLimit` stays the precise per-route enforcer.
///
/// A route the owning module declared in
/// [`Module::streaming_routes`](cratefield_core::Module::streaming_routes)
/// is never buffered (issue #585): the runtime consults
/// [`Harness::streaming_route`] for the route's own ceiling, and — for a
/// body within it — breaks the request into a
/// [`RequestStream`] and hands the router an
/// empty axum body. The core streaming request layer sees that handle in the
/// extensions and passes the request through untouched, so a handler reads
/// the body chunk by chunk instead of resident. A declared `content-length`
/// over the route ceiling is refused unread, exactly as the buffered path
/// refuses one over the module's. On the way out, a handler that answered
/// with a [`ResponseStream`] is bridged to
/// the wire through `worker::Response::from_stream`, never buffered.
///
/// # Errors
///
/// `worker::Error` on conversion/transport failures; problem+json
/// responses are ordinary 4xx/5xx Worker responses.
pub async fn serve(
    harness: &Harness,
    runtime: &Cloudflare,
    mut req: WorkerRequest,
    env: Env,
    ctx: Context,
) -> worker::Result<WorkerResponse> {
    install_tracing();
    let ports = runtime.ports(&env, Arc::new(ContextDefer(ctx)));
    check_module_config_once(harness, ports.config.as_ref());
    #[cfg(feature = "push")]
    check_push_wiring_once(harness, runtime, &env, ports.config.as_ref());
    // `ports` moves into `router()` below, and the ceiling lookup reads the
    // same config the module contexts were built with — clone the `Arc`
    // out first.
    let config = Arc::clone(&ports.config);
    let url = req.url()?;
    // The short-circuits below — the unresolved-limiter `503` and the
    // `413` — answer before the router runs, so no layer stands behind
    // them to name the venture (issue #557): name it here, the same way
    // the router's outermost layer would.
    let problem_type_base = harness.venture().problem_type_base();
    // Fail closed when the composition named a limiter binding that did
    // not resolve (issue #562): those routes were written to be throttled,
    // and a missing binding used to degrade to serving them unlimited with
    // only a logged warning. `/v1/*` only, like the readiness guard — the
    // probes and the UI stay up to say why — and in every environment:
    // unlimited is a decision the composition makes, never one a missing
    // binding makes for it. `ports.rate_limiter` stays `None`, so
    // `production_readiness` still reads this as "not readiness".
    if let Some(detail) = runtime.unresolved_limiter_refusal(ports.rate_limiter.is_some())
        && url.path().starts_with("/v1/")
    {
        // Once per isolate, not once per refused request (the readiness
        // guard's record discipline, issue #441).
        warn_once(&WARNED_UNRESOLVED_LIMITER, &detail);
        // This short-circuits before the router, so the 503 carries no
        // CORS headers and an OPTIONS preflight is refused like any other
        // request — accepted: a Worker that cannot throttle is down.
        return response_to_worker(unresolved_limiter_response(detail, &problem_type_base)).await;
    }
    let router = harness.router(ports);

    // The method is needed before the body is read: it decides whether the
    // route streams (issue #585).
    let method = http::Method::from_bytes(req.method().to_string().as_bytes())
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    // A streaming route's own ceiling replaces the module's coarse buffered
    // one — the precise per-route enforcer, not a pre-buffer guard.
    let streaming = harness.streaming_route(url.path(), &method);
    let limit = streaming.unwrap_or_else(|| harness.max_body_bytes(url.path(), config.as_ref()));
    // HEAD never carries a response body: axum serves it through the GET
    // handler with an emptied body, so the streamed path must not bridge the
    // (still present) `ResponseStream` handle to the wire.
    let is_head = method == http::Method::HEAD;

    // Copied out so the header borrow ends before the body is read mutably.
    // `worker::Headers::get` already yields `Option<String>`; a lookup
    // failure is treated as no declaration at all, which earns the capped
    // stream rather than trust.
    let declared = req.headers().get("content-length").ok().flatten();

    // When set, a `RequestStream` for a declared streaming route: the router
    // gets an empty buffered body and this handle in its extensions, and the
    // core streaming layer passes the request through untouched (issue #585).
    let mut request_stream: Option<RequestStream> = None;

    let bytes = match body_plan(declared.as_deref(), limit) {
        BodyPlan::Refuse => {
            // The tail left unread here trips `wrangler dev`'s drain
            // middleware — a dev-only artefact, recorded in this README's
            // wasm notes.
            return response_to_worker(
                Problem::request_too_large().into_response_with_base(&problem_type_base),
            )
            .await;
        }
        // A streaming route: never buffer, whatever the declared length —
        // a `content-length` at or under the ceiling earns the same
        // streaming read a chunked body does. Probe `inner().body()` first,
        // exactly as the buffered path below does and for the same reason
        // (worker 0.8.5's `stream()` poisons a bodyless request).
        BodyPlan::Stream | BodyPlan::Buffer if streaming.is_some() => {
            request_stream = Some(match req.inner().body() {
                None => RequestStream::empty(),
                Some(_) => match req.stream() {
                    Ok(stream) => RequestStream::new(send_stream(stream), limit),
                    // Unreachable past the probe, as below: answer empty
                    // rather than swallow a genuine transport error.
                    Err(_) => RequestStream::empty(),
                },
            });
            Vec::new()
        }
        BodyPlan::Buffer => req.bytes().await?,
        BodyPlan::Stream => {
            // A bodyless request (most GETs, HEAD, OPTIONS) must reach the
            // router as an empty body, and worker 0.8.5 makes that a
            // non-obvious requirement: `Request::stream()` sets
            // `body_used = true` *before* it looks for a body
            // (request.rs:199-204), so a null-body request answers
            // `Err("no body for request")` having already poisoned the
            // request — and `bytes()` afterwards can only answer
            // `Error::BodyUsed` (request.rs:158-173). The old
            // `Err(_) => req.bytes()` fallback therefore failed every
            // bodyless request out of `serve()` — `/__health`, `/__ready`,
            // `/ui/*`, `/.well-known/jwks.json` (issue #440). Probe
            // non-destructively through `inner()`, the raw
            // `web_sys::Request`, whose `body()` answers `None` exactly
            // where `stream()` would fail: with no body, hand the router
            // the empty buffer the Fetch spec gives a null body and never
            // touch `stream()` at all.
            match req.inner().body() {
                None => Vec::new(),
                Some(_) => match req.stream() {
                    Ok(stream) => match read_capped(stream, limit).await {
                        Ok(Capped::Within(bytes)) => bytes,
                        Ok(Capped::TooLarge) => {
                            return response_to_worker(
                                Problem::request_too_large()
                                    .into_response_with_base(&problem_type_base),
                            )
                            .await;
                        }
                        Err(err) => return Err(err),
                    },
                    // Belt and braces: past the probe, `stream()`'s only
                    // remaining failure mode is the `body_used` poison, and
                    // `bytes()` reads that same flag — so no read can
                    // succeed here. The arm answers empty, not silently:
                    // it is unreachable while the probe and `stream()` read
                    // the same `body()` getter (a body the probe saw cannot
                    // disappear), so a genuine transport error is not being
                    // swallowed, and a 500 on a body the getter had just
                    // reported would be strictly worse.
                    Err(_) => Vec::new(),
                },
            }
        }
    };

    let mut builder = http::Request::builder().method(method).uri(url.to_string());
    {
        let headers = req.headers();
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    let mut buffered = builder
        .body(axum::body::Body::from(bytes))
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    if let Some(stream) = request_stream {
        // The core streaming layer reads this and leaves the empty body
        // above alone (issue #585).
        buffered.extensions_mut().insert(stream);
    }

    let mut response = router
        .oneshot(buffered)
        .await
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    if is_head {
        // Drop the handle: axum has already emptied the body for HEAD, and
        // the buffered path below reads that empty body, keeping status and
        // headers — taking the stream instead would send the whole body a
        // HEAD must not carry.
        response.extensions_mut().remove::<ResponseStream>();
    }
    if let Some(line) = response.extensions().get().and_then(summary_line) {
        // The request span is inert on Workers (no dispatcher, see
        // `tracing_setup`), so its fields reach Workers Logs as one JSON
        // line instead — indexed as fields, and matched by
        // `wrangler tail --search <request-id>`.
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("{line}");
        #[cfg(not(target_arch = "wasm32"))]
        tracing::info!("{line}");
    }
    response_to_worker(response).await
}

/// The Workers Logs line for one request: the core [`RequestSummary`]
/// serialized as JSON.
fn summary_line(summary: &RequestSummary) -> Option<String> {
    serde_json::to_string(summary).ok()
}

async fn response_to_worker(
    response: http::Response<axum::body::Body>,
) -> worker::Result<WorkerResponse> {
    let (parts, body) = response.into_parts();

    // A streamed response (issue #585): the handler answered with a
    // `ResponseStream`, whose `IntoResponse` left a lazy axum body *and* the
    // handle in the extensions. Polling that axum body on wasm is the hang
    // this path exists to avoid, so take the stream and bridge it to a
    // Worker response directly. Whoever takes first wins; if the body
    // already consumed it (`take` answers `None`) fall through to the
    // buffered read, which then sees the empty remainder.
    if let Some(stream) = parts.extensions.get::<ResponseStream>()
        && let Some(inner) = stream.take()
    {
        let mapped =
            inner.map(|chunk| chunk.map_err(|err| worker::Error::RustError(err.to_string())));
        let mut out = WorkerResponse::from_stream(mapped)?.with_status(parts.status.as_u16());
        copy_headers(out.headers_mut(), &parts.headers);
        return Ok(out);
    }

    let bytes = axum::body::to_bytes(body, MAX_RESPONSE_BUFFER)
        .await
        .map_err(|err| worker::Error::RustError(err.to_string()))?;
    let mut out =
        WorkerResponse::from_bytes(bytes.as_ref().to_vec())?.with_status(parts.status.as_u16());
    copy_headers(out.headers_mut(), &parts.headers);
    Ok(out)
}

/// Copies every response header onto the Worker response, per name: drop what
/// the `worker` builder pre-set (a default `content-type:
/// application/octet-stream` from `from_bytes`), then `append` every value.
/// `set` kept only the last value of a multi-valued header (`Vary` from the
/// CORS layer plus the handler's own, later `Set-Cookie`; found by
/// `GET /__surface` losing `Vary: Authorization`, issue #70), and a bare
/// `append` stacked onto the pre-set default (found by `/ui` pages answering
/// `content-type: application/octet-stream, text/html`, issue #72). Shared by
/// the buffered and streamed paths so both carry the same headers.
fn copy_headers(worker_headers: &mut worker::Headers, headers: &http::HeaderMap) {
    for name in headers.keys() {
        let _ = worker_headers.delete(name.as_str());
        for value in headers.get_all(name) {
            let _ = worker_headers.append(name.as_str(), value.to_str().unwrap_or_default());
        }
    }
}

/// The boxed worker body stream [`SendStream`] holds.
type BoxedWorkerBody = Pin<Box<dyn Stream<Item = Result<Vec<u8>, worker::Error>>>>;

/// A `worker::ByteStream` is `!Send` — its `JsFuture` holds an `Rc` — but a
/// Workers isolate is single-threaded (ADR 0002), which is exactly what
/// `worker::send::SendWrapper` is for: the `worker` crate's own safe (mis)claim
/// that a JS-backed type may cross a `Send` bound. Coercing the stream to a
/// boxed trait object and wrapping that costs no `unsafe` of our own — the
/// crate still `forbid`s it — and gives [`RequestStream::new`], which needs
/// `Send + 'static`, a stream to hold.
struct SendStream(SendWrapper<BoxedWorkerBody>);

impl Stream for SendStream {
    type Item = Result<Vec<u8>, worker::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        // `Pin<Box<_>>` is `Unpin`, so the whole newtype is and `get_mut` is
        // sound; the boxed stream stays pinned.
        self.get_mut().0.0.as_mut().poll_next(cx)
    }
}

/// [`SendStream`]s a worker body stream. `Box::new` before `Pin::from` so the
/// unsizing coercion to the trait object is the well-worn one.
fn send_stream<S>(stream: S) -> SendStream
where
    S: Stream<Item = Result<Vec<u8>, worker::Error>> + 'static,
{
    let boxed: Box<dyn Stream<Item = Result<Vec<u8>, worker::Error>>> = Box::new(stream);
    SendStream(SendWrapper::new(Pin::from(boxed)))
}

/// Responses are JSON (small); 1 MiB is a generous ceiling.
const MAX_RESPONSE_BUFFER: usize = 1024 * 1024;

/// The conservative limits a scheduled invocation runs under when the
/// venture does not choose its own: 25 seconds of wall time and 40
/// subrequest-shaped steps. Chosen to fit the Workers Free plan's 50
/// subrequests per invocation with headroom, not taken from the plan: it
/// is a default, not a platform fact, and a venture on a paid plan passes
/// its own limits to [`serve_scheduled_with_limits`].
pub const CLOUDFLARE_SCHEDULED_LIMITS: ScheduledLimits = ScheduledLimits {
    wall: Some(time::Duration::seconds(25)),
    subrequests: Some(40),
};

/// Fans a scheduled event out to every module's `scheduled(ctx, cron)`
/// under [`CLOUDFLARE_SCHEDULED_LIMITS`]. Handler errors are logged and
/// never fail the cron.
pub async fn serve_scheduled(
    harness: &Harness,
    runtime: &Cloudflare,
    event: worker::ScheduledEvent,
    env: Env,
    ctx: worker::ScheduleContext,
) {
    serve_scheduled_with_limits(
        harness,
        runtime,
        event,
        env,
        ctx,
        CLOUDFLARE_SCHEDULED_LIMITS,
    )
    .await;
}

/// [`serve_scheduled`] with the invocation's limits named explicitly
/// (issue #537): the whole run may spend `limits.wall` of wall time and
/// `limits.subrequests` subrequest-shaped steps, split across the modules
/// in order with each module's unspent share rolling forward to the ones
/// after it. A module's share arrives as `ModuleContext::scheduled`, which
/// the module — and `Outbox::drain_within` — checks cooperatively before
/// each unit of work; the runtime never cancels a module that ignores it.
/// A module that runs its share out is named in Workers Logs, and a
/// handler error is still only logged, never a failed cron.
pub async fn serve_scheduled_with_limits(
    harness: &Harness,
    runtime: &Cloudflare,
    event: worker::ScheduledEvent,
    env: Env,
    ctx: worker::ScheduleContext,
    limits: ScheduledLimits,
) {
    install_tracing();
    let cron = event.cron();
    let ports = runtime.ports(&env, Arc::new(ScheduleDefer(ctx)));
    check_module_config_once(harness, ports.config.as_ref());
    #[cfg(feature = "push")]
    check_push_wiring_once(harness, runtime, &env, ports.config.as_ref());
    // `ports` always wires WorkersClock, so the first arm is the real one.
    // A ports set without a clock cannot check a wall limit at all, so it
    // runs the unbounded split — which reads no clock and computes no
    // deadline, so the epoch placeholders below are never observed.
    let clock = ports.clock.clone();
    let mut split = match clock.as_ref() {
        Some(clock) => ScheduledSplit::new(limits, clock.now(), harness.modules().len()),
        None => ScheduledSplit::new(
            ScheduledLimits::UNBOUNDED,
            OffsetDateTime::UNIX_EPOCH,
            harness.modules().len(),
        ),
    };
    for module in harness.modules() {
        let now = clock
            .as_ref()
            .map_or(OffsetDateTime::UNIX_EPOCH, |clock| clock.now());
        let budget = Arc::new(split.next(now));
        let mut module_ctx = harness.module_context(module.as_ref(), &ports);
        module_ctx.scheduled = Arc::clone(&budget);
        if let Err(err) = module.scheduled(&module_ctx, &cron).await {
            tracing::error!(
                module = module.name(),
                cron = %cron,
                error = %err,
                "scheduled module work failed",
            );
        }
        // Judged on a fresh reading: a module that overran spent wall time
        // this invocation does not have to wait for the next one to be named.
        let after = clock
            .as_ref()
            .map_or(OffsetDateTime::UNIX_EPOCH, |clock| clock.now());
        if budget.exhausted(after) {
            tracing::warn!(
                module = module.name(),
                cron = %cron,
                spent = budget.spent(),
                "scheduled module work exhausted its budget",
            );
        }
        split.settle(&budget);
    }
}

/// The unresolved-limiter refusal (issue #562), named under the serving
/// venture's problem base (issue #557): it short-circuits before the
/// router, whose outermost layer would otherwise have named it.
fn unresolved_limiter_response(
    detail: String,
    problem_type_base: &str,
) -> axum::response::Response {
    Problem::new(&SLUGS.not_production_ready)
        .with_detail(detail)
        .into_response_with_base(problem_type_base)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("the body reads");
        serde_json::from_slice(&bytes).expect("the body is JSON")
    }

    #[test]
    fn unresolved_limiter_refusal_names_the_serving_venture() {
        // Issues #557 and #562 meet here: the fail-closed 503 answers
        // before the router, so it must name the venture itself.
        let venture = cratefield_core::Venture::new("acme", "acme.example")
            .public_url("https://acme.example");
        let response = unresolved_limiter_response(
            "limiter binding RATE_LIMITER did not resolve".to_owned(),
            &venture.problem_type_base(),
        );
        assert_eq!(response.status(), 503);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/problem+json"
        );
        let body = pollster::block_on(body_json(response));
        assert_eq!(
            body["type"],
            "https://acme.example/problems/not-production-ready"
        );
        assert!(
            !body.to_string().contains("factory0.ventures"),
            "no other venture's domain: {body}"
        );
    }

    #[test]
    fn unresolved_limiter_refusal_without_public_url_is_about_blank() {
        // `Venture::new` defaults the public URL to the domain; clear it.
        let venture = cratefield_core::Venture::new("acme", "acme.example").public_url("");
        let response = unresolved_limiter_response(
            "limiter binding RATE_LIMITER did not resolve".to_owned(),
            &venture.problem_type_base(),
        );
        assert_eq!(
            pollster::block_on(body_json(response))["type"],
            cratefield_core::ABOUT_BLANK
        );
    }

    #[test]
    fn summary_line_is_one_json_object_carrying_the_request_id() {
        let summary = RequestSummary {
            request_id: "01J9ZQ4V6X8Y2K3M5N7P9R1T3W".to_owned(),
            method: "GET".to_owned(),
            route: "/v1/sample/hello".to_owned(),
            module: "sample".to_owned(),
            status: 200,
            ip_hash: "0123456789ab".to_owned(),
            ua_family: "mozilla".to_owned(),
        };
        let line = summary_line(&summary).expect("serializes");
        assert!(!line.contains('\n'), "one line: {line}");
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["request_id"], "01J9ZQ4V6X8Y2K3M5N7P9R1T3W");
        assert_eq!(parsed["route"], "/v1/sample/hello");
        assert_eq!(parsed["status"], 200);
    }
}
