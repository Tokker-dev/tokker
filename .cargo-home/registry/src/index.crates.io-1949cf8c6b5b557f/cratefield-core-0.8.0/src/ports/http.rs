//! The `HttpClient` port (architecture section 5): plain `http` types over
//! bytes, so adapters (Resend, Turnstile) run unchanged on Workers
//! (`worker::Fetch`) and native (`reqwest`, phase 3).
//!
//! # Contract (issue #136)
//!
//! An outbound request is the one place a module or adapter can make the
//! runtime allocate or wait on behalf of an upstream it does not control,
//! so the port itself defines the bounds:
//!
//! 1. **Response size.** An implementation MUST refuse a response whose
//!    body exceeds the effective [`HttpPolicy`] cap, with
//!    [`HttpError::ResponseTooLarge`] — and MUST check the declared
//!    `Content-Length` before consuming the body, so a hostile length does
//!    not cost an allocation. A caller can only ever *lower* the cap
//!    below [`MAX_RESPONSE_BYTES`].
//! 2. **Deadline.** Every send is bounded by the effective
//!    [`HttpPolicy::timeout`]; an upstream that has not answered by then
//!    is abandoned (not awaited) with [`HttpError::DeadlineExceeded`], so
//!    a hung service cannot pin a Worker request or a native tenant. The
//!    native runtime enforces this inside `reqwest` (and thereby against
//!    each redirect hop); the Workers runtime cannot time `worker::Fetch`
//!    itself, so it is enforced through the [`Clock`](super::Clock) port by
//!    [`BoundedHttpClient`], which every runtime wires around its
//!    implementation.
//! 3. **Destinations.** An implementation that opens real sockets MUST
//!    refuse destinations a caller-supplied URL must never reach — non
//!    `http(s)` schemes, userinfo, and loopback, private, link-local,
//!    multicast or cloud-metadata addresses (169.254.169.254 and
//!    friends, in IPv6 and decimal/octal/hex encodings alike) — with
//!    [`HttpError::BlockedDestination`], and MUST re-vet **every redirect
//!    hop** rather than trusting the first destination. On Workers this
//!    falls to the platform, whose `fetch` refuses non-public
//!    destinations; the native runtime implements the vetting itself.
//! 4. **Concurrency budget.** A runtime with a shared outbound client MUST
//!    cap in-flight requests at [`MAX_CONCURRENT_REQUESTS`] per process
//!    (one native process serves one tenant, so that cap *is* the
//!    per-tenant budget) and refuse past it rather than queue unbounded
//!    work.
//!
//! Bounds are per-operation and travel as a request extension
//! ([`HttpPolicy::of_request`]); the extensions never reach the wire,
//! implementations read them before rebuilding the transport request.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

use super::Clock;
use crate::ports::timeout;

/// Hard ceiling on a response body this port may return: an adapter's
/// largest legitimate upstream reply (JWKS documents, Stripe objects,
/// LinkedIn `people` payloads) is orders of magnitude below it, and it is
/// far below anything that threatens isolate memory. Callers may lower it
/// per operation, never raise it.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Deadline applied to an outbound call that asks for none. Longer than
/// the strictest in-tree self-bound (Turnstile's 5s verify), shorter than
/// anything that could pin a request.
pub const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on a caller-supplied deadline. A 30 s Worker request cannot
/// responsibly spend more than half of it waiting on one upstream.
pub const MAX_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-process budget for concurrent outbound requests. The native
/// runtime shares one connection pool across the tenant it serves; this
/// is what stops one request's fan-out (say a cron fanning out emails)
/// from monopolising the pool and the response-buffer memory behind it.
pub const MAX_CONCURRENT_REQUESTS: usize = 32;

/// Per-operation outbound bounds, attached to a request as an extension
/// and resolved by every implementation with [`HttpPolicy::of_request`].
/// Both fields clamp to the port maxima: a caller may only tighten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpPolicy {
    /// Maximum accepted response body size.
    pub max_response_bytes: usize,
    /// Maximum time to wait for the upstream to answer.
    pub timeout: Duration,
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            timeout: DEFAULT_RESPONSE_TIMEOUT,
        }
    }
}

impl HttpPolicy {
    /// The effective policy for `request`: the attached [`HttpPolicy`]
    /// extension if any, clamped to the port ceilings.
    #[must_use]
    pub fn of_request<T>(request: &http::Request<T>) -> Self {
        request
            .extensions()
            .get::<HttpPolicy>()
            .copied()
            .unwrap_or_default()
            .clamped()
    }

    /// Clamps to [`MAX_RESPONSE_BYTES`] / [`MAX_RESPONSE_TIMEOUT`]:
    /// callers may lower a bound, never raise it.
    #[must_use]
    pub fn clamped(self) -> Self {
        Self {
            max_response_bytes: self.max_response_bytes.min(MAX_RESPONSE_BYTES),
            timeout: self.timeout.min(MAX_RESPONSE_TIMEOUT),
        }
    }
}

/// The declared `Content-Length` of a response, when it parses as a
/// non-negative size. Implementations check this before touching the
/// body, so an oversized declared length is refused without allocating
/// for it (issue #136).
#[must_use]
pub fn declared_content_length(headers: &http::HeaderMap) -> Option<usize> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
}

#[derive(Debug, Clone, Error)]
pub enum HttpError {
    #[error("http request failed: {0}")]
    Transport(String),
    /// The upstream's response body exceeded the [`HttpPolicy`] cap.
    #[error("upstream response exceeds the {limit}-byte bound")]
    ResponseTooLarge {
        /// The effective cap that was exceeded.
        limit: usize,
    },
    /// The upstream did not answer within the [`HttpPolicy`] deadline and
    /// was abandoned.
    #[error("upstream deadline of {after:?} exceeded")]
    DeadlineExceeded {
        /// The effective deadline.
        after: Duration,
    },
    /// The destination (or one of its redirect hops) is refused by the
    /// outbound policy: scheme, userinfo, or a loopback / private /
    /// link-local / metadata address.
    #[error("destination refused by outbound policy: {0}")]
    BlockedDestination(String),
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Sends `request` and returns the fully-buffered response under the
    /// bounds this port carries: the body is at most
    /// [`MAX_RESPONSE_BYTES`] unless an [`HttpPolicy`] tightens it, the
    /// exchange is bounded by that policy's deadline
    /// (enforced through [`BoundedHttpClient`] on runtimes that wrap),
    /// the destination is vetted where real sockets are opened, and a
    /// runtime that keeps a concurrency budget holds one for the send.
    async fn send(&self, request: http::Request<Bytes>)
    -> Result<http::Response<Bytes>, HttpError>;
}

/// Wraps any [`HttpClient`] so the port's bounds hold on every runtime:
/// the deadline is enforced through the [`Clock`](super::Clock) port (the
/// only timer core is allowed to use), and the response is refused — by
/// declared length before anything else, then by actual size — when it
/// exceeds the [`HttpPolicy`] cap.
///
/// This is defence in depth, not the only defence: the native adapter
/// also enforces the cap while streaming (before the oversized body is
/// ever buffered) and the Workers adapter checks the declared length
/// before calling `bytes()`. Runtimes wire every `ports.http` through
/// this wrapper.
pub struct BoundedHttpClient {
    inner: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
}

impl BoundedHttpClient {
    /// Bounds `inner`'s sends by `clock`-measured deadlines and caps.
    #[must_use]
    pub fn new(inner: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self { inner, clock }
    }
}

#[async_trait]
impl HttpClient for BoundedHttpClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let policy = HttpPolicy::of_request(&request);
        let inner = Arc::clone(&self.inner);
        let Some(outcome) = timeout(
            self.clock.as_ref(),
            async move { inner.send(request).await },
            policy.timeout,
        )
        .await
        else {
            return Err(HttpError::DeadlineExceeded {
                after: policy.timeout,
            });
        };
        let response = outcome?;
        if declared_content_length(response.headers())
            .is_some_and(|len| len > policy.max_response_bytes)
        {
            return Err(HttpError::ResponseTooLarge {
                limit: policy.max_response_bytes,
            });
        }
        if response.body().len() > policy.max_response_bytes {
            return Err(HttpError::ResponseTooLarge {
                limit: policy.max_response_bytes,
            });
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;

    /// Policy resolution is the port's whole vocabulary; pin the clamps.
    #[test]
    fn a_policy_clamps_to_the_port_ceilings() {
        let loose = HttpPolicy {
            max_response_bytes: usize::MAX,
            timeout: Duration::from_secs(3600),
        };
        let clamped = loose.clamped();
        assert_eq!(clamped.max_response_bytes, MAX_RESPONSE_BYTES);
        assert_eq!(clamped.timeout, MAX_RESPONSE_TIMEOUT);

        let tight = HttpPolicy {
            max_response_bytes: 1024,
            timeout: Duration::from_millis(50),
        };
        assert_eq!(tight.clamped(), tight, "tightening is honoured");

        let defaulted = HttpPolicy::of_request(&http::Request::new(Bytes::new()));
        assert_eq!(defaulted, HttpPolicy::default());
        let mut request = http::Request::new(Bytes::new());
        request.extensions_mut().insert(HttpPolicy {
            max_response_bytes: usize::MAX,
            timeout: Duration::from_secs(3600),
        });
        let resolved = HttpPolicy::of_request(&request);
        assert_eq!(resolved.max_response_bytes, MAX_RESPONSE_BYTES);
        assert_eq!(resolved.timeout, MAX_RESPONSE_TIMEOUT);
    }

    /// The inner client is never asked to police itself: a body over the
    /// cap, by declared length or by actual size, is refused here.
    struct ScriptedClient {
        response: Result<Response<Bytes>, HttpError>,
    }

    #[async_trait]
    impl HttpClient for ScriptedClient {
        async fn send(&self, _request: http::Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
            self.response.clone()
        }
    }

    struct NoTimerClock;

    #[async_trait]
    impl Clock for NoTimerClock {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::UNIX_EPOCH
        }
        // default timeout_any: runs to completion — the wrapper's own
        // checks must then catch the violation.
    }

    struct AlwaysTimeoutClock;

    #[async_trait]
    impl Clock for AlwaysTimeoutClock {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::UNIX_EPOCH
        }
        async fn timeout_any(
            &self,
            fut: futures_core::future::BoxFuture<'static, Box<dyn std::any::Any + Send>>,
            _after: Duration,
        ) -> Option<Box<dyn std::any::Any + Send>> {
            drop(fut);
            None
        }
    }

    fn bounded(inner: ScriptedClient, clock: Arc<dyn Clock>) -> BoundedHttpClient {
        BoundedHttpClient::new(Arc::new(inner), clock)
    }

    #[pollster::test]
    async fn an_oversized_response_body_is_refused() {
        let inner = ScriptedClient {
            response: Ok(Response::new(Bytes::from(vec![0_u8; 4_096]))),
        };
        let mut request = http::Request::new(Bytes::new());
        request.extensions_mut().insert(HttpPolicy {
            max_response_bytes: 1_024,
            timeout: Duration::from_secs(5),
        });
        let err = bounded(inner, Arc::new(NoTimerClock))
            .send(request)
            .await
            .expect_err("4 KiB over a 1 KiB cap must be refused");
        assert!(
            matches!(err, HttpError::ResponseTooLarge { limit: 1_024 }),
            "got {err}"
        );
    }

    #[pollster::test]
    async fn an_oversized_declared_length_is_refused_before_the_body_counts() {
        // Actual body is small, but the declared length lies about a huge
        // response; the wrapper refuses on the header alone.
        let inner = ScriptedClient {
            response: Ok(Response::builder()
                .header(http::header::CONTENT_LENGTH, "9000")
                .body(Bytes::from_static(b"hi"))
                .expect("test response")),
        };
        let mut request = http::Request::new(Bytes::new());
        request.extensions_mut().insert(HttpPolicy {
            max_response_bytes: 1_024,
            timeout: Duration::from_secs(5),
        });
        let err = bounded(inner, Arc::new(NoTimerClock))
            .send(request)
            .await
            .expect_err("a declared 9 KB over a 1 KiB cap must be refused");
        assert!(
            matches!(err, HttpError::ResponseTooLarge { .. }),
            "got {err}"
        );
    }

    #[pollster::test]
    async fn an_abandoned_send_is_a_deadline_not_a_hang() {
        // The clock gives up on the future (its contract: abandon, do not
        // await); the wrapper maps that to DeadlineExceeded with the
        // effective duration, even though the inner would have answered.
        let inner = ScriptedClient {
            response: Ok(Response::new(Bytes::from_static(b"late"))),
        };
        let err = bounded(inner, Arc::new(AlwaysTimeoutClock))
            .send(http::Request::new(Bytes::new()))
            .await
            .expect_err("an abandoned send must surface as the deadline");
        assert!(
            matches!(&err, HttpError::DeadlineExceeded { after } if *after == DEFAULT_RESPONSE_TIMEOUT),
            "got {err}"
        );
    }
}
