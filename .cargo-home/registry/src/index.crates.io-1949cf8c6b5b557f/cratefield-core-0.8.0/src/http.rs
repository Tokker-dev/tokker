//! HTTP plumbing every venture router shares (issue #2): the problem+json
//! `Json` and `Form` extractors, the request-id middleware that creates
//! the [`Scope`], and the `/v1/*` security headers.

use axum::body::Body;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderValue, Request as HttpRequest, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response as AxumResponse};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;

use crate::module::HARNESS_API;
use crate::ports::{Decision, Defer, IdGen, Quota};
use crate::problem::Problem;
use crate::scope::Scope;
use crate::sidecar::{X_HARNESS_API, X_HARNESS_MODULE};
use crate::usage::Exhausted;
use tracing::info_span;

/// `x-request-id`: accepted from the client when it matches
/// `^[A-Za-z0-9_-]{8,128}$`, otherwise generated as a ULID. Always set on
/// the response (architecture section 6).
pub const X_REQUEST_ID: &str = "x-request-id";

/// Default request body limit for `/v1/*` JSON endpoints.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

// `Duration::from_days` is unstable on the pinned toolchain
// (`duration_constructors`), so this stays in seconds.
#[allow(clippy::duration_suboptimal_units)]
const CORS_PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(86_400);

/// The character class and length bounds of an accepted request id.
pub fn request_id_is_valid(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The per-request span's fields as plain data, attached to every
/// response's extensions by the request-id layer so a runtime with no
/// tracing dispatcher — Cloudflare — can still log them. `route` is the
/// matched pattern, never the raw path (`""` when nothing matched). There
/// is no `duration_ms`: wasm32 has no monotonic clock to measure it with.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RequestSummary {
    pub request_id: String,
    pub method: String,
    pub route: String,
    pub module: String,
    pub status: u16,
    pub ip_hash: String,
    pub ua_family: String,
}

/// State the request-id layer needs, resolved from `Ports` when the router
/// is assembled.
#[derive(Clone)]
pub(crate) struct ScopeState {
    pub defer: Arc<dyn Defer>,
    pub id_gen: Arc<dyn IdGen>,
    /// The one module this deployment serves, when it serves exactly one —
    /// the sidecar shape (ADR 0009). Set, the response carries
    /// `x-harness-module` next to [`crate::sidecar::X_HARNESS_API`]; the
    /// host reads both on every forwarded response, which is how a sidecar
    /// redeployed against a different contract is caught within one
    /// request instead of at a cold start that isolates do not have.
    pub module: Option<&'static str>,
}

/// Middleware: resolve the request id, build the [`Scope`] (request id,
/// defer, tracing span), insert it into extensions, echo the id on the
/// response.
pub(crate) async fn scope_layer(
    axum::extract::State(state): axum::extract::State<ScopeState>,
    mut request: Request,
    next: Next,
) -> AxumResponse {
    use tracing::Instrument as _;
    use tracing::field::Empty;

    let incoming = request
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| request_id_is_valid(value));
    let request_id = match incoming {
        Some(valid) => valid.to_owned(),
        None => state.id_gen.ulid(),
    };

    // The one structured span per request (issue #14). `route`,
    // `module`, `status` and `duration_ms` are recorded after the
    // handler runs; no field ever carries an email (only `ip_hash`).
    let method = request.method().as_str().to_owned();
    let ip_hash = crate::logging::subject_hash(
        &crate::rate_limit::client_ip(request.headers()).unwrap_or_default(),
    );
    let ua_family = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| "unknown".to_owned(), ua_family_of);
    let span = info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        route = Empty,
        module = Empty,
        status = Empty,
        duration_ms = Empty,
        ip_hash = %ip_hash,
        ua_family = %ua_family,
    );

    let scope = Scope {
        defer: Arc::clone(&state.defer),
        span: span.clone(),
        request_id: request_id.clone(),
    };
    request.extensions_mut().insert(scope);

    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|matched| matched.as_str().to_owned())
        .unwrap_or_default();

    // `std::time::Instant::now()` panics on wasm32-unknown-unknown with
    // "time not implemented on this platform", which took down every
    // request on Workers — `/__health` included. There is no monotonic
    // clock in that target, and `Date.now()` is frozen between I/O in
    // workerd, so a wall-clock delta would read 0 and look measured.
    // Timing is therefore recorded only where a real clock exists;
    // Cloudflare's own request logs carry it on Workers.
    #[cfg(not(target_arch = "wasm32"))]
    let started = std::time::Instant::now();
    let future = next.run(request);
    let mut response = future.instrument(span.clone()).await;

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    // The identity stamp (issue #61): one insert, on every response, and
    // never a cold-start subrequest. A sidecar is built and deployed
    // separately, so the compile-time `Harness::build` contract check does
    // not cover it; the host instead reads this header back on every
    // forwarded response and refuses the prefix on a wrong number. That
    // catches a sidecar redeployed under a warm host within one request —
    // an isolate can outlive the sidecar for hours, so a cached cold-start
    // verdict would keep serving a contract that no longer holds.
    if let Ok(value) = HeaderValue::from_str(&HARNESS_API.to_string()) {
        response.headers_mut().insert(X_HARNESS_API, value);
    }
    // The module name rides along so a host mounting several sidecars can
    // tell whose answer it is looking at. It is only well-defined when the
    // deployment serves exactly one module — the sidecar shape — so a
    // multi-module host stays silent rather than stamping a guess.
    if let Some(name) = state.module
        && let Ok(value) = HeaderValue::from_str(name)
    {
        response.headers_mut().insert(X_HARNESS_MODULE, value);
    }
    let module = route
        .strip_prefix("/v1/")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default()
        .to_owned();
    let status = response.status().as_u16();
    span.record("route", route.as_str());
    span.record("module", module.as_str());
    span.record("status", status);
    #[cfg(not(target_arch = "wasm32"))]
    {
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        span.record("duration_ms", duration_ms);
    }
    response.extensions_mut().insert(RequestSummary {
        request_id,
        method,
        route,
        module,
        status,
        ip_hash,
        ua_family,
    });
    response
}

/// Coarse user-agent family: the first product token, lowercased —
/// enough to group browsers, bots and libraries without a UA parser.
fn ua_family_of(user_agent: &str) -> String {
    let token = user_agent
        .split(['/', ' ', ';', '('])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let truncated: String = token.chars().take(24).collect();
    if truncated.is_empty() {
        "unknown".to_owned()
    } else {
        truncated
    }
}

/// Middleware: `/v1/*` responses carry
/// `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
/// `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and
/// `Content-Security-Policy: frame-ancestors 'none'` (architecture
/// section 6). `/v1` is never meant to be framed: the API answers in
/// JSON no page has business embedding, and the one document it serves —
/// the magic-link confirmation — is HTML that must refuse to render
/// inside a third party's frame, where a surrounding attacker page could
/// clickjack the confirm button (issue #435).
pub(crate) async fn security_headers_layer(request: Request, next: Next) -> AxumResponse {
    let is_api = request.uri().path().starts_with("/v1/");
    let mut response = next.run(request).await;
    if is_api {
        insert_no_store_headers(response.headers_mut());
        insert_framing_headers(response.headers_mut());
    }
    response
}

/// Middleware for token-bearing URLs (issue #135). A `token` query
/// parameter is the credential — confirmation links and
/// `/ui/waitlist/status?token=…` authenticate with the URL itself, and
/// `/ui/*` is outside the `/v1/*` rule above. Any response to a request
/// whose query carries a `token` parameter therefore gets the same
/// no-store headers at the root: no cache may keep the credential and no
/// outbound navigation may leak it through `Referer`.
pub(crate) async fn token_response_layer(request: Request, next: Next) -> AxumResponse {
    let carries_token = request.uri().query().is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair == "token" || pair.starts_with("token="))
    });
    let mut response = next.run(request).await;
    if carries_token {
        insert_no_store_headers(response.headers_mut());
    }
    response
}

fn insert_no_store_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
}

/// Frame-blocking headers, scoped to `/v1/*` only. Deliberately not
/// folded into [`insert_no_store_headers`]: the token-bearing layer below
/// shares that helper for *any* path whose query carries a `token` —
/// including `/ui/*`, which sets its own `Content-Security-Policy` and
/// `X-Frame-Options` (and deliberately none on `?fragment=1` fragments).
/// Stamping the framing pair there would override the UI's answer; here
/// it only ever lands on `/v1`, which has none of its own (issue #435).
fn insert_framing_headers(headers: &mut axum::http::HeaderMap) {
    // `insert`, not `append`: duplicated `X-Frame-Options` values are
    // ill-defined and some browsers ignore the header entirely when it
    // repeats, so the strictest value simply replaces whatever was there.
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // `append`, not `insert`: a browser handed several CSP policies
    // enforces all of them — their intersection — so appending can only
    // tighten whatever a `/v1` module set on its own response, where an
    // `insert` would silently delete a fuller policy and substitute this
    // one-directive one. No module sets a CSP under `/v1` today; this is
    // written for the one that eventually does.
    headers.append(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
}

/// A `Json` extractor and response whose rejections and serializations are
/// problem+json (architecture section 6). Deserialization failures become a
/// `400 validation-failed` problem listing the field.
pub struct Json<T>(pub T);

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request(request: HttpRequest<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let instance = request
            .extensions()
            .get::<Scope>()
            .map(|scope| scope.request_id.clone());
        match axum::Json::<T>::from_request(request, state).await {
            Ok(axum::Json(value)) => Ok(Json(value)),
            Err(rejection) => {
                // Body reads fail through the shared 413 slug (the size
                // limit); everything else is a 400 validation problem.
                let mut problem = match &rejection {
                    axum::extract::rejection::JsonRejection::BytesRejection(_) => {
                        Problem::request_too_large()
                    }
                    _ => Problem::validation_failed(rejection.body_text()),
                };
                if let Some(instance) = instance {
                    problem = problem.instance(&instance);
                }
                Err(problem)
            }
        }
    }
}

impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> AxumResponse {
        axum::Json(self.0).into_response()
    }
}

/// A form (`application/x-www-form-urlencoded`) extractor whose
/// rejections are problem+json with the same shape as [`Json`]'s: body
/// reads fail through the shared 413 slug (the size limit), everything
/// else is a 400 validation problem. Needed for cross-site `form_post`
/// callbacks (issue #46).
pub struct Form<T>(pub T);

impl<T, S> FromRequest<S> for Form<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request(request: HttpRequest<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let instance = request
            .extensions()
            .get::<Scope>()
            .map(|scope| scope.request_id.clone());
        match axum::Form::<T>::from_request(request, state).await {
            Ok(axum::Form(value)) => Ok(Form(value)),
            Err(rejection) => {
                let mut problem = match &rejection {
                    axum::extract::rejection::FormRejection::BytesRejection(_) => {
                        Problem::request_too_large()
                    }
                    _ => Problem::validation_failed(rejection.body_text()),
                };
                if let Some(instance) = instance {
                    problem = problem.instance(&instance);
                }
                Err(problem)
            }
        }
    }
}

/// A `429 rate-limited` problem (architecture section 6). `Retry-After:
/// <seconds>` comes from the [`Decision`]'s own pause, falling back to the
/// quota's reset when the limiter reports a window but no pause; a known
/// quota also rides the IETF draft `RateLimit-Limit`, `RateLimit-Remaining`
/// and `RateLimit-Reset` headers (delta-seconds), so a well-behaved client
/// can pace itself without probing (issue #538). A decision with no quota
/// at all — a Workers Rate Limiting binding, or a failure resolved at the
/// call site — is a bare `429` + `Retry-After`, exactly as before.
pub fn rate_limited(decision: &Decision) -> AxumResponse {
    let problem = Problem::new(&crate::problems::SLUGS.rate_limited);
    let mut response = problem.into_response();
    let pause = decision
        .retry_after
        .or_else(|| decision.quota.as_ref().map(|quota| quota.reset));
    if let Some(pause) = pause
        && let Ok(value) = HeaderValue::from_str(&delta_seconds(pause))
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    if let Some(quota) = decision.quota.as_ref() {
        for (name, value) in quota_headers(quota) {
            if let Ok(value) = HeaderValue::from_str(&value) {
                response
                    .headers_mut()
                    .insert(header::HeaderName::from_static(name), value);
            }
        }
    }
    response
}

/// A `429 usage/allowance-exhausted` problem (issue #588): a metered
/// allowance is spent for the current period. The body carries extension
/// members a caller acts on — the `meter`, the `limit`, the `used` total and
/// the `period_end` as RFC 3339 — and `Retry-After` is the delta-seconds to
/// that reset, the same header [`rate_limited`] sets.
pub fn allowance_exhausted(meter: &str, outcome: &Exhausted) -> AxumResponse {
    let mut response = allowance_exhausted_problem(meter, outcome).into_response();
    if let Ok(value) = HeaderValue::from_str(&delta_seconds(outcome.retry_after)) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The problem behind [`allowance_exhausted`], without the header — built in
/// one place so the response and the harness's re-render under the serving
/// venture's base carry the same members.
fn allowance_exhausted_problem(meter: &str, outcome: &Exhausted) -> Problem {
    Problem::new(&crate::problems::SLUGS.allowance_exhausted)
        .with_extension("meter", meter)
        .with_extension("limit", outcome.limit)
        .with_extension("used", outcome.used)
        .with_extension("period_end", crate::usage::rfc3339(outcome.period_end))
}

/// The `RateLimit-*` headers for one quota, as `(name, value)` pairs with
/// lowercase static names.
fn quota_headers(quota: &Quota) -> [(&'static str, String); 3] {
    [
        ("ratelimit-limit", quota.limit.to_string()),
        ("ratelimit-remaining", quota.remaining.to_string()),
        ("ratelimit-reset", delta_seconds(quota.reset)),
    ]
}

/// Delta-seconds for `Retry-After` and `RateLimit-Reset`: rounded up, so a
/// client never waits a shorter time than the truth, and never zero.
fn delta_seconds(pause: Duration) -> String {
    let millis = u64::try_from(pause.as_millis()).unwrap_or(u64::MAX);
    millis.div_ceil(1_000).max(1).to_string()
}

/// CORS allowlist from the venture's origins; never a wildcard
/// (architecture section 6). Tower-http echoes the matched origin rather
/// than emitting `*`, and requests from other origins get no CORS headers.
///
/// `PUT` and `Authorization` are on the list because a browser client on
/// the venture's own site is a cross-origin caller: `cf.js` is served
/// from the API origin but runs on the site's, and registering for
/// notifications is `PUT /v1/notifications/subscriptions` with a bearer
/// token (issue #183). Left off, the preflight fails and the fetch never
/// leaves the browser — with a console message and no server-side trace
/// at all.
///
/// Credentials stay off, which is what keeps that safe: no cookie is ever
/// attached to a cross-origin request, so allowing the header only lets a
/// script send a token it already holds and had to be given deliberately.
pub(crate) fn cors_layer(origins: &[String]) -> tower_http::cors::CorsLayer {
    use tower_http::cors::{AllowOrigin, CorsLayer};
    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(CORS_PREFLIGHT_MAX_AGE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    fn header(response: &AxumResponse, name: &str) -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok().map(str::to_owned))
    }

    #[test]
    fn a_pause_becomes_retry_after_and_nothing_else() {
        let response = rate_limited(&Decision {
            ok: false,
            retry_after: Some(Duration::from_secs(7)),
            quota: None,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&response, "retry-after").as_deref(), Some("7"));
        assert!(header(&response, "ratelimit-limit").is_none());
    }

    #[test]
    fn a_quota_rides_the_ratelimit_headers() {
        let response = rate_limited(&Decision {
            ok: false,
            retry_after: None,
            quota: Some(Quota {
                limit: 30,
                remaining: 0,
                reset: Duration::from_secs(43),
            }),
        });
        assert_eq!(header(&response, "retry-after").as_deref(), Some("43"));
        assert_eq!(header(&response, "ratelimit-limit").as_deref(), Some("30"));
        assert_eq!(
            header(&response, "ratelimit-remaining").as_deref(),
            Some("0")
        );
        assert_eq!(header(&response, "ratelimit-reset").as_deref(), Some("43"));
    }

    #[test]
    fn the_quotas_reset_backfills_a_missing_retry_after() {
        let response = rate_limited(&Decision {
            ok: false,
            retry_after: None,
            quota: Some(Quota {
                limit: 5,
                remaining: 2,
                reset: Duration::from_millis(1500),
            }),
        });
        // Delta-seconds round up: a client never waits less than the truth.
        assert_eq!(header(&response, "retry-after").as_deref(), Some("2"));
        assert_eq!(header(&response, "ratelimit-reset").as_deref(), Some("2"));
    }

    #[test]
    fn an_answerless_decision_is_a_bare_429() {
        let response = rate_limited(&Decision {
            ok: false,
            retry_after: None,
            quota: None,
        });
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(header(&response, "retry-after").is_none());
        assert!(header(&response, "ratelimit-limit").is_none());
    }

    fn exhausted() -> Exhausted {
        Exhausted {
            used: 100,
            limit: 100,
            period_end: time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("in range"),
            retry_after: Duration::from_secs(120),
        }
    }

    #[test]
    fn an_exhausted_allowance_is_a_429_with_a_retry_after() {
        let response = allowance_exhausted("mail_sent", &exhausted());
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&response, "retry-after").as_deref(), Some("120"));
    }

    #[test]
    fn an_exhausted_allowance_carries_its_meter_limit_used_and_period_end() {
        // Rendered under a venture base, the way the harness's outermost
        // layer renders every problem: the type URI and the extension
        // members must both survive (issue #588).
        let body = allowance_exhausted_problem("mail_sent", &exhausted())
            .body("https://api.test.example/problems/");
        assert_eq!(
            body["type"],
            "https://api.test.example/problems/usage/allowance-exhausted"
        );
        assert_eq!(body["meter"], "mail_sent");
        assert_eq!(body["limit"], 100);
        assert_eq!(body["used"], 100);
        assert_eq!(body["period_end"], "2027-01-15T08:00:00Z");
        assert_eq!(body["status"], 429);
    }
}
