//! Sidecar mounts (ADR 0009): a module served by its own Worker, mounted at
//! the same `/v1/<name>` as an in-process module and indistinguishable to a
//! caller.
//!
//! The mount table is **runtime configuration**, never a builder call. A
//! `.sidecar()` in `src/lib.rs` would bake a customer-specific mount into
//! the artifact, so the artifact would stop being a function of the module set
//! and could no longer be shared between ventures (#59).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use crate::admin::require_admin;
use crate::config::Config;
use crate::events::EventBus;
use crate::http::{Json, MAX_BODY_BYTES, X_REQUEST_ID};
use crate::module::HARNESS_API;
use crate::ports::{Clock, Dispatcher, Kid, Payload, RateLimiter, Signer};
use crate::problem::Problem;
use crate::problems::SLUGS;
use crate::rate_limit::{
    RateLimit, RateLimitFailure, check_rate_limit, client_ip, rate_limit_keys,
};
use crate::scope::Scope;
use crate::signer::{HmacSigner, KeyRing, MIN_SECRET_BYTES, TokenPolicy};

/// Config key holding the mount table, a JSON object of
/// `{"<module name>": "<service binding>"}`.
pub const HARNESS_SIDECARS: &str = "HARNESS_SIDECARS";

/// Contract version stamped on every harness response, checked by the host on
/// every forwarded response. Stamping beats a cold-start handshake because an
/// isolate outlives a sidecar redeploy (ADR 0009).
pub const X_HARNESS_API: &str = "x-harness-api";
/// Module name stamped alongside [`X_HARNESS_API`].
pub const X_HARNESS_MODULE: &str = "x-harness-module";

/// Shared secret between the host and a sidecar that enforces the gateway
/// (issue #131). The host mints short-lived per-request tokens with it; the
/// sidecar verifies them on `/v1/*` and `/__surface`. It is its own secret —
/// `HARNESS_SECRET` stays venture-local (ADR 0009) — and must appear on
/// both ends of a mounted pair.
pub const SIDECAR_GATEWAY_SECRET: &str = "SIDECAR_GATEWAY_SECRET";
/// Sidecar-side switch: truthy means every `/v1/*` and `/__surface` request
/// must carry a valid gateway token minted with [`SIDECAR_GATEWAY_SECRET`].
/// Requiring it without the secret is a configuration error and fails
/// closed, not open (issue #131).
pub const SIDECAR_REQUIRE_GATEWAY: &str = "SIDECAR_REQUIRE_GATEWAY";
/// Truthy declares "this venture deploys as one Worker": mounting a sidecar
/// then contradicts the shape, and [`SidecarMounts::from_config`] rejects
/// the mount table rather than starting a deployment that cannot reach it
/// (issue #131).
pub const HARNESS_ONE_WORKER: &str = "HARNESS_ONE_WORKER";

/// Gateway token header, minted by the host per forwarded request and
/// verified by a sidecar that set [`SIDECAR_REQUIRE_GATEWAY`] (issue #131).
pub const X_HARNESS_GATEWAY: &str = "x-harness-gateway";

/// The token purpose bound into the gateway MAC. A token minted for any
/// other purpose — a confirm link, an admin session — cannot pass
/// verification, and vice versa (issue #137's rule, applied to #131).
pub const GATEWAY_PURPOSE: &str = "sidecar-gateway";

/// The purpose the host mints **only** after its own [`require_admin`]
/// has passed for an admin path (issue #131). It is what lets a sidecar
/// re-materialize its own admin token: a token proving nothing more than
/// "this came through the host" must not open the admin plane, or any
/// captured forwarded stamp would be an admin credential for its whole
/// lifetime.
pub const GATEWAY_ADMIN_PURPOSE: &str = "sidecar-gateway-admin";

/// Gateway token lifetime: a forwarded request completes in one hop, so a
/// minute is generous. Short TTLs shrink the replay window a stolen token
/// buys an attacker (issue #131).
pub const GATEWAY_TOKEN_TTL_SECS: i64 = 120;

/// Request headers forwarded verbatim, everything else dropped (issue
/// #131). Notably never `authorization` or `cookie`: the venture's admin
/// token is the host's alone, and the sidecar answers to its own
/// credentials.
const FORWARDED_REQUEST_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "accept",
    "accept-language",
    "user-agent",
];

/// Response headers copied back to the caller (issue #131). Everything
/// else stops at the host — most importantly `set-cookie`, which would
/// let a sidecar plant cookies on the venture's origin.
const FORWARDED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "location",
    "cache-control",
    "etag",
    "last-modified",
    "vary",
    "retry-after",
    "content-disposition",
    X_HARNESS_API,
    X_HARNESS_MODULE,
    X_REQUEST_ID,
];

/// `true` when `key` is set to one of `1`, `true`, `yes` or `on`
/// (case-insensitive) — the same reading `ModuleConfig::get_bool` gives,
/// applied to harness-level keys.
#[must_use]
pub(crate) fn truthy(config: &dyn Config, key: &str) -> bool {
    config.get(key).is_some_and(|raw| {
        matches!(
            raw.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// The gateway signer for this deployment, or `None` when
/// [`SIDECAR_GATEWAY_SECRET`] is unset. The host role uses it to mint
/// per-request tokens; a sidecar that set [`SIDECAR_REQUIRE_GATEWAY`]
/// uses the same construction as its verification key. The secret joins
/// its own bounded ring (issue #137) — venture secrets never cross a
/// Worker boundary (ADR 0009) — and the ring holds only the current key:
/// a gateway token lives 120 s, so rotation has no grace window to
/// serve. The host's venture/env labels do not either: host and sidecar
/// are different deployments and must not have to match them.
pub(crate) fn gateway_signer(
    config: &dyn Config,
    clock: Arc<dyn Clock>,
) -> Option<Arc<HmacSigner>> {
    let secret = config
        .get(SIDECAR_GATEWAY_SECRET)
        .filter(|value| !value.trim().is_empty())?;
    let mut ring = KeyRing::new();
    match ring.rotate_signing(Kid::Cur, secret.into_bytes()) {
        Ok(_) => {}
        Err(crate::signer::SignerError::SecretTooShort) => {
            let detail =
                format!("{SIDECAR_GATEWAY_SECRET} must be at least {MIN_SECRET_BYTES} bytes");
            tracing::error!("{detail}");
            // A secret that will not load silently downgrades the gateway
            // (issue #441): the boot-time misconfiguration must be readable
            // on wasm, where the tracing event goes nowhere.
            crate::logging::forward_control_event(crate::logging::ControlLevel::Error, &detail);
            return None;
        }
        Err(err) => {
            let detail =
                format!("{SIDECAR_GATEWAY_SECRET} could not enter the gateway ring: {err}");
            tracing::error!(error = %err, "{detail}");
            crate::logging::forward_control_event(crate::logging::ControlLevel::Error, &detail);
            return None;
        }
    }
    let policy = TokenPolicy::default()
        .with_max(GATEWAY_PURPOSE, Some(GATEWAY_TOKEN_TTL_SECS))
        .with_max(GATEWAY_ADMIN_PURPOSE, Some(GATEWAY_TOKEN_TTL_SECS));
    Some(Arc::new(
        HmacSigner::from_ring(ring)
            .with_clock(clock)
            .with_policy(policy),
    ))
}

/// A gateway token for one forwarded request. `exp` is left unset: the
/// policy ceiling is the lifetime. `admin` is the host's assertion that
/// [`require_admin`] already passed for this request, and it is bound
/// into the MAC as the purpose — a caller cannot promote a plain stamp.
pub(crate) fn mint_gateway(signer: &HmacSigner, mount: &str, admin: bool) -> String {
    let purpose = if admin {
        GATEWAY_ADMIN_PURPOSE
    } else {
        GATEWAY_PURPOSE
    };
    signer.sign(&Payload {
        purpose: purpose.to_owned(),
        subject: mount.to_owned(),
        exp: None,
        kid: Kid::Cur,
    })
}

/// What a presented gateway token proves: `Some(true)` when the host
/// minted it after authorizing an admin request, `Some(false)` for an
/// ordinary forwarded request, `None` when it is not this deployment's
/// token or has expired. The subject (the mounted module name) is
/// carried for forensics, not checked: a token is valid at any sidecar
/// sharing the gateway secret, and the alternative — the sidecar
/// guessing under what name the host mounted it — cannot work for
/// `/__surface`.
pub(crate) fn gateway_grant(signer: &HmacSigner, token: &str) -> Option<bool> {
    if signer.verify(token, GATEWAY_ADMIN_PURPOSE).is_some() {
        return Some(true);
    }
    signer.verify(token, GATEWAY_PURPOSE).map(|_| false)
}

/// One mounted sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarMount {
    /// Module name; mounted at `/v1/<name>`.
    pub name: String,
    /// Service binding the runtime resolves to reach it.
    pub binding: String,
}

/// The mount table, parsed from configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SidecarMounts(Vec<SidecarMount>);

impl SidecarMounts {
    /// Reads and validates [`HARNESS_SIDECARS`]. Absent or empty is not an
    /// error: most ventures mount no sidecars.
    ///
    /// # Errors
    ///
    /// Every malformed entry, reported together so one deploy surfaces them
    /// all rather than one per attempt.
    pub fn from_config(config: &dyn Config) -> Result<Self, Vec<String>> {
        let Some(raw) = config
            .get(HARNESS_SIDECARS)
            .filter(|v| !v.trim().is_empty())
        else {
            return Ok(Self::default());
        };
        if truthy(config, HARNESS_ONE_WORKER) {
            return Err(vec![format!(
                "{HARNESS_SIDECARS} names a sidecar while {HARNESS_ONE_WORKER} is set: a one-Worker \
                 deployment serves every module in-process and can mount nothing (issue #131)"
            )]);
        }
        let parsed: BTreeMap<String, String> = serde_json::from_str(&raw).map_err(|err| {
            vec![format!(
                "{HARNESS_SIDECARS} must be a JSON object of {{\"module-name\": \"BINDING\"}}: {err}"
            )]
        })?;

        let mut errors = Vec::new();
        let mut mounts = Vec::new();
        for (name, binding) in parsed {
            if !is_kebab(&name) {
                errors.push(format!(
                    "sidecar name `{name}` must be kebab-case ([a-z0-9]+ separated by '-')"
                ));
            }
            if binding.trim().is_empty() {
                errors.push(format!("sidecar `{name}` has an empty service binding"));
            }
            mounts.push(SidecarMount { name, binding });
        }
        if errors.is_empty() {
            Ok(Self(mounts))
        } else {
            Err(errors)
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SidecarMount> {
        self.0.iter()
    }

    /// Names that collide with an in-process module. Both sides are known
    /// without an `Env`, so this is the one sidecar check that can run early.
    #[must_use]
    pub fn collisions(&self, module_names: &[&str]) -> Vec<String> {
        self.0
            .iter()
            .filter(|m| module_names.contains(&m.name.as_str()))
            .map(|m| {
                format!(
                    "sidecar `{}` claims `/v1/{}`, already served in-process",
                    m.name, m.name
                )
            })
            .collect()
    }
}

fn is_kebab(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

struct SidecarState {
    mount: SidecarMount,
    dispatcher: Option<Arc<dyn Dispatcher>>,
    config: Arc<dyn Config>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    gateway: Option<Arc<HmacSigner>>,
}

/// The router for one sidecar prefix: a fallback that forwards everything
/// the trust boundary lets through (issue #131).
pub(crate) fn router(
    mount: SidecarMount,
    dispatcher: Option<Arc<dyn Dispatcher>>,
    config: Arc<dyn Config>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    gateway: Option<Arc<HmacSigner>>,
) -> Router {
    Router::new()
        .fallback(forward)
        .with_state(Arc::new(SidecarState {
            mount,
            dispatcher,
            config,
            rate_limiter,
            gateway,
        }))
}

async fn forward(
    State(state): State<Arc<SidecarState>>,
    scope: Scope,
    // `nest` strips the mount prefix from `parts.uri`, but a sidecar is a
    // whole harness serving its module at `/v1/<name>`: it must be given the
    // path the caller used, or every forwarded request 404s at the far end.
    OriginalUri(uri): OriginalUri,
    request: axum::extract::Request,
) -> Response {
    let unavailable = |detail: String| -> Response {
        Problem::new(&SLUGS.sidecar_unavailable)
            .with_detail(detail)
            .instance(&scope.request_id)
            .into_response()
    };

    let Some(dispatcher) = state.dispatcher.clone() else {
        tracing::warn!(
            module = state.mount.name,
            "sidecar mounted but the runtime provides no dispatcher"
        );
        return unavailable(format!(
            "`{}` is mounted as a sidecar but this runtime cannot dispatch",
            state.mount.name
        ));
    };
    if !dispatcher.has(&state.mount.binding) {
        tracing::warn!(
            module = state.mount.name,
            binding = state.mount.binding,
            "sidecar binding is not present in this deployment"
        );
        return unavailable(format!(
            "`{}` is mounted on binding `{}`, which this deployment does not have",
            state.mount.name, state.mount.binding
        ));
    }

    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return Problem::new(&SLUGS.request_too_large)
            .instance(&scope.request_id)
            .into_response();
    };

    // The host owns the venture's admin plane: `ADMIN_TOKEN` never
    // crosses the boundary, so admin paths are authorized here, against
    // the host's own configuration, before anything is forwarded
    // (issue #131). The verdict is what the gateway stamp then asserts.
    let admin = is_admin_path(uri.path());
    if admin && let Err(problem) = require_admin(state.config.as_ref(), &parts.headers) {
        return problem.instance(&scope.request_id).into_response();
    }

    // The host's abuse controls run for every mounted request: the sidecar
    // cannot resolve the caller's address (the header allowlist above is
    // the only channel it has), and a limiter failure fails closed — a
    // forwarded write has no captcha-or-cooldown backstop behind it.
    // Reads are exempt: throttling a `GET` budgets would punish health
    // polls and link landing pages for one noisy neighbor.
    if matches!(
        parts.method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        let keys = rate_limit_keys(client_ip(&parts.headers).as_deref(), None);
        if let RateLimit::Denied { decision } = check_rate_limit(
            state.rate_limiter.as_ref(),
            &keys,
            RateLimitFailure::FailClosed,
        )
        .await
        {
            return crate::http::rate_limited(&decision);
        }
    }

    let mut outbound = http::Request::builder()
        .method(parts.method.clone())
        .uri(uri);
    if let Some(headers) = outbound.headers_mut() {
        write_forwarded_headers(headers, &state, &scope, &parts.headers, admin);
    }
    let outbound = match outbound.body(body) {
        Ok(req) => req,
        Err(err) => return unavailable(format!("could not build the forwarded request: {err}")),
    };

    match dispatcher.dispatch(&state.mount.binding, outbound).await {
        Ok(response) => match contract_of(&response) {
            Some(api) if api != HARNESS_API => {
                tracing::warn!(
                    module = state.mount.name,
                    sidecar_api = api,
                    host_api = HARNESS_API,
                    "sidecar contract mismatch"
                );
                Problem::new(&SLUGS.sidecar_contract_mismatch)
                    .with_detail(format!(
                        "`{}` answers contract {api}; this harness speaks {HARNESS_API}",
                        state.mount.name
                    ))
                    .instance(&scope.request_id)
                    .into_response()
            }
            _ => into_axum(response),
        },
        Err(err) => {
            tracing::warn!(module = state.mount.name, error = %err, "sidecar dispatch failed");
            unavailable(err.to_string())
        }
    }
}

/// The contract a response claims, if it claims one. A sidecar that stamps
/// nothing is not rejected here: it may predate the header, and the mismatch
/// that matters is a *wrong* number, not a missing one.
/// Builds the forwarded request's headers: the allowlist, the shared
/// request id, the host-resolved caller address and the gateway stamp
/// (issue #131).
fn write_forwarded_headers(
    headers: &mut http::HeaderMap,
    state: &SidecarState,
    scope: &Scope,
    inbound: &http::HeaderMap,
    admin: bool,
) {
    // An allowlist, not a denylist: `authorization`, `cookie`, and every
    // unregistered header stop at the host. The caller's credentials
    // belong to this Worker alone.
    for name in FORWARDED_REQUEST_HEADERS {
        let name = HeaderName::from_static(name);
        if let Some(value) = inbound.get(&name) {
            headers.append(name, value.clone());
        }
    }
    // One trail across both Workers. `insert`, so a client-supplied id
    // cannot arrive twice.
    if let Ok(value) = scope.request_id.parse() {
        headers.insert(X_REQUEST_ID, value);
    }
    // The caller's address travels exactly once, and it is the address
    // the *host* resolved: a client-forged `cf-connecting-ip` is
    // replaced here, never copied.
    if let Some(ip) = client_ip(inbound)
        && let Ok(value) = HeaderValue::from_str(&ip)
    {
        headers.insert(HeaderName::from_static("cf-connecting-ip"), value);
    }
    // The gateway stamp: proof to the sidecar that this request came
    // through the host, and — only when the host authorized it — that
    // the caller cleared the admin gate. No secret, no stamp, and a
    // sidecar that *requires* the gateway then refuses every request,
    // loudly, rather than quietly serving the open internet.
    if let Some(signer) = state.gateway.as_ref() {
        let token = mint_gateway(signer, &state.mount.name, admin);
        if let Ok(value) = HeaderValue::from_str(&token) {
            headers.insert(HeaderName::from_static(X_HARNESS_GATEWAY), value);
        }
    }
}

fn contract_of(response: &http::Response<Bytes>) -> Option<u32> {
    response
        .headers()
        .get(X_HARNESS_API)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

/// Copy the sidecar's answer back to the caller header-by-header: the
/// response allowlist is the boundary (issue #131). `set-cookie` stops
/// here — a sidecar that can plant cookies on the venture's origin owns
/// the caller's session on a surface it does not serve.
fn into_axum(response: http::Response<Bytes>) -> Response {
    let (parts, body) = response.into_parts();
    let mut out = Response::new(axum::body::Body::from(body));
    *out.status_mut() = parts.status;
    *out.version_mut() = parts.version;
    for name in FORWARDED_RESPONSE_HEADERS {
        let name = HeaderName::from_static(name);
        if let Some(value) = parts.headers.get(&name) {
            out.headers_mut().append(name.clone(), value.clone());
        }
    }
    out
}

// ------------------------------------------------------------- events (#62)

/// The wire shape of the host's `POST /__events` body. One event, one
/// payload — the same values `EventBus::emit_in` was given, serialized once
/// and forwarded verbatim (issue #62).
#[derive(serde::Deserialize)]
pub(crate) struct EventEnvelope {
    event: String,
    payload: serde_json::Value,
}

/// Carries every event a harness emits to the sidecars it has mounted
/// (ADR 0017). Built per router — per `Harness::router(ports)` — because
/// only there are the `Dispatcher` and the mount table resolved; the bus
/// itself is built in `Harness::build`, which has no `Env` (ADR 0009).
pub(crate) struct EventForwarder {
    mounts: Vec<SidecarMount>,
    dispatcher: Arc<dyn Dispatcher>,
    gateway: Option<Arc<HmacSigner>>,
}

impl EventForwarder {
    pub(crate) fn new(
        mounts: Vec<SidecarMount>,
        dispatcher: Arc<dyn Dispatcher>,
        gateway: Option<Arc<HmacSigner>>,
    ) -> Self {
        Self {
            mounts,
            dispatcher,
            gateway,
        }
    }

    /// Nothing to forward to: a harness with no mounted sidecars.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// Delivers one event to every mounted sidecar, at most once each
    /// (ADR 0017). A sidecar that does not answer, answers with an error
    /// or does not recognize the event is logged and otherwise forgotten:
    /// the in-process bus never promised delivery, and forwarding must not
    /// promise more than the bus it extends. Never retries — a retry would
    /// be the durable-queue design this issue explicitly rules out.
    pub(crate) async fn forward(&self, request_id: &str, name: &str, payload: &serde_json::Value) {
        let body = match serde_json::to_vec(&serde_json::json!({
            "event": name,
            "payload": payload,
        })) {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(event = %name, error = %err, "event payload did not serialize");
                return;
            }
        };
        for mount in &self.mounts {
            if !self.dispatcher.has(&mount.binding) {
                continue;
            }
            let mut builder = http::Request::builder()
                .method(Method::POST)
                .uri("/__events")
                .header(HeaderName::from_static("content-type"), "application/json");
            // One trail across both Workers, as for a forwarded request.
            if let Ok(value) = HeaderValue::from_str(request_id) {
                builder = builder.header(HeaderName::from_static(X_REQUEST_ID), value);
            }
            if let Some(signer) = self.gateway.as_ref() {
                // An event forward authorizes nothing: the plain purpose.
                builder = builder.header(
                    HeaderName::from_static(X_HARNESS_GATEWAY),
                    mint_gateway(signer, &mount.name, false),
                );
            }
            let request = match builder.body(Bytes::from(body.clone())) {
                Ok(request) => request,
                Err(err) => {
                    tracing::warn!(event = %name, error = %err, "event forward could not be built");
                    continue;
                }
            };
            match self.dispatcher.dispatch(&mount.binding, request).await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    let detail = format!(
                        "event forward to `{}` answered {}",
                        mount.name,
                        response.status()
                    );
                    tracing::warn!(event = %name, module = %mount.name, detail, "event forward was not accepted");
                    crate::logging::forward_internal_error(&detail);
                }
                Err(err) => {
                    let detail = format!(
                        "event forward to `{mount}` failed: {err}",
                        mount = mount.name
                    );
                    tracing::warn!(event = %name, module = %mount.name, error = %err, "event forward failed");
                    crate::logging::forward_internal_error(&detail);
                }
            }
        }
    }
}

/// The `POST /__events` route's state: the bus to deliver into and the key
/// that decides whether the caller may trigger it at all. The route is only
/// mounted when a gateway signer exists — without the shared secret there
/// is no way to tell the host's forward from anyone else's `POST`, and an
/// unauthenticated event trigger would let a stranger forge the payloads
/// in-process handlers act on.
pub(crate) struct InboundEvents {
    pub(crate) bus: EventBus,
    pub(crate) gateway: Option<Arc<HmacSigner>>,
}

/// The sidecar half of event forwarding (ADR 0017): accept the host's
/// delivery, answer `202` immediately, and run any local handlers in this
/// deployment's **own** `wait_until`. Running them here — not before
/// answering — is the whole point: a slow subscriber must not hold the
/// host's deferred future open, only its own.
pub(crate) async fn events_inbound(
    State(state): State<Arc<InboundEvents>>,
    scope: Scope,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    // The host always stamps its forwards; anything unstamped is not the
    // host, and a stamp that does not verify gets the same answer.
    if let Some(signer) = state.gateway.as_ref() {
        let presented = headers
            .get(X_HARNESS_GATEWAY)
            .and_then(|value| value.to_str().ok());
        if presented
            .and_then(|token| gateway_grant(signer, token))
            .is_none()
        {
            return Problem::new(&SLUGS.sidecar_unauthorized)
                .instance(&scope.request_id)
                .into_response();
        }
    }
    let Ok(envelope) = serde_json::from_slice::<EventEnvelope>(&body) else {
        return Problem::new(&SLUGS.validation_failed)
            .with_detail("body must be `{\"event\": \"<name>\", \"payload\": …}`")
            .instance(&scope.request_id)
            .into_response();
    };
    let handled = state
        .bus
        .deliver_inbound(&scope, &envelope.event, &envelope.payload);
    if handled == 0 {
        // The amendment to #62: an event nobody hears is exactly the
        // silent failure this issue exists to prevent, so the inbound
        // half refuses to be silent too.
        let detail = format!(
            "event `{}` arrived over the boundary with no subscriber",
            envelope.event
        );
        tracing::warn!(event = %envelope.event, "{detail}");
        crate::logging::forward_internal_error(&detail);
    }
    // 202, not 200: the handlers have *not* run when this answers. They
    // run in this deployment's own `wait_until`, after the response, and
    // a status that claimed the work was done would be the one lie this
    // route cannot afford - the host reads it to decide whether the
    // forward was accepted, never whether it succeeded (ADR 0017).
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "accepted": handled > 0, "handlers": handled })),
    )
        .into_response()
}

/// Admin paths as the host sees them: a sidecar's own `/admin` plane
/// arrives under its mount, so both spellings are authorized here, before
/// the header that proves the caller is an admin is dropped by the
/// forward allowlist (issue #131). This mirrors the renderer's gating
/// rule from #130. Also the harness-layer predicate the admin rate limit
/// keys on (issue #437) — one answer to "is this an admin path", not two.
pub(crate) fn is_admin_path(path: &str) -> bool {
    path == "/admin" || path.ends_with("/admin") || path.contains("/admin/")
}

/// Sidecar-role gateway enforcement state, built once at startup from
/// [`SIDECAR_REQUIRE_GATEWAY`] and [`SIDECAR_GATEWAY_SECRET`] (issue #131).
#[derive(Clone)]
pub(crate) struct GatewayGuard {
    /// Whether the gate is closed at all.
    pub require: bool,
    /// The verification key; `require` without it fails closed.
    pub signer: Option<Arc<HmacSigner>>,
    /// The sidecar's own admin token, used only to re-assert host-verified
    /// admin requests to the module routes behind the gate (issue #131).
    pub admin_token: Option<String>,
}

/// The boundary a sidecar enforces from its own side: with
/// [`SIDECAR_REQUIRE_GATEWAY`] set, every `/v1/*`, `/__surface` and
/// `/__events` request must carry a gateway token this deployment's secret
/// minted and has not outlived (issues #131 and #62). `/__health`, `/ui`
/// and well-known routes stay
/// open — probes must probe, and the page is the deployment's own
/// surface. A require without a usable secret is a broken deploy, and the
/// answer is a loud 503 on every guarded request, never a quiet 200.
pub(crate) async fn gateway_guard(
    State(guard): State<GatewayGuard>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    // `/__events` joins the guarded set with issue #62: the host's event
    // forward carries a stamp like any other forwarded request, and an
    // event trigger a stranger can reach is a payload a handler trusts.
    if !guard.require || !(path.starts_with("/v1/") || path == "/__surface" || path == "/__events")
    {
        return next.run(request).await;
    }
    let instance = request
        .extensions()
        .get::<Scope>()
        .map(|scope| scope.request_id.clone());
    let refused = |problem: Problem| match &instance {
        Some(id) => problem.instance(id),
        None => problem,
    };
    let Some(signer) = guard.signer.as_ref() else {
        let detail = format!(
            "{SIDECAR_REQUIRE_GATEWAY} is set but {SIDECAR_GATEWAY_SECRET} is \
             missing; refusing every guarded request"
        );
        tracing::error!("{detail}");
        // The fail-closed 503 is the loud answer a broken deploy deserves
        // (issue #131); on wasm the tracing event goes nowhere (issue
        // #441), so the reason rides the forwarder too.
        crate::logging::forward_control_event(crate::logging::ControlLevel::Error, &detail);
        return refused(Problem::new(&SLUGS.sidecar_unavailable).with_detail(
            "this sidecar requires a gateway token but no gateway secret is configured",
        ))
        .into_response();
    };
    let presented = request
        .headers()
        .get(X_HARNESS_GATEWAY)
        .and_then(|value| value.to_str().ok());
    let Some(host_authorized_admin) = presented.and_then(|token| gateway_grant(signer, token))
    else {
        return refused(Problem::new(&SLUGS.sidecar_unauthorized)).into_response();
    };
    // A gateway token minted under the *admin* purpose is the host's
    // assertion that this request already passed the host's admin
    // authorization (issue #131). The caller's bearer stopped at the
    // host, so the sidecar's own token — read from the sidecar's own
    // config, never crossing the boundary — is re-materialized for the
    // module routes behind the gate. An ordinary forwarded stamp buys
    // nothing here: every proxied request carries one, so treating it as
    // proof of admin would make a captured stamp an admin credential for
    // its whole lifetime. A request that presented a bearer anyway keeps
    // it: the comparison is constant-time either way.
    let mut request = request;
    if host_authorized_admin
        && is_admin_path(&path)
        && !request.headers().contains_key("authorization")
        && let Some(token) = &guard.admin_token
        && let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}"))
    {
        request
            .headers_mut()
            .insert(HeaderName::from_static("authorization"), value);
    }
    next.run(request).await
}
