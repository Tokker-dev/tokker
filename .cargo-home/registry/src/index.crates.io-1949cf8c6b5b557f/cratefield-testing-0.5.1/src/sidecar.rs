//! A sidecar without a network (issue #64): a [`Dispatcher`] whose bound
//! "Worker" is a second in-process harness. What a Cloudflare service
//! binding does at runtime (ADR 0009), in a test.
//!
//! [`Fault`] deliberately breaks the hop. It exists so the parity axis
//! can be shown to have teeth: a suite that passes against a forwarder
//! which drops the request id proves nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{DispatchError, Dispatcher};
use tower::ServiceExt;

/// A way the hop can be wrong. Used by the kit's own tests to prove the
/// parity checks fail when the forwarder misbehaves; never by a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Strips `x-request-id` from the response. The host re-adds its
    /// own, so this is a resilience case rather than a defect.
    DropRequestId,
    /// Answers a second, different `x-request-id`, so the caller cannot
    /// tell which trail to follow.
    DuplicateRequestId,
    /// Answers `500` whatever the sidecar said.
    RemapStatus,
    /// Rewrites the response body, keeping the status.
    MangleBody,
    /// Drops the request headers on the way out, so the sidecar sees a
    /// bare request (the caller's ip, admin bearer and id are lost).
    StripRequestHeaders,
    /// Never answers: the binding exists but the Worker does not reply.
    Unavailable,
    /// The binding is not in this deployment at all.
    NotBound,
}

/// A dispatcher backed by an in-process router.
pub struct FakeSidecar {
    binding: String,
    router: axum::Router,
    calls: AtomicUsize,
    fault: Option<Fault>,
}

impl FakeSidecar {
    /// Binds `router` (a whole harness serving the module at
    /// `/v1/<name>`) to `binding`.
    #[must_use]
    pub fn new(binding: impl Into<String>, router: axum::Router) -> Self {
        Self {
            binding: binding.into(),
            router,
            calls: AtomicUsize::new(0),
            fault: None,
        }
    }

    /// The same, with the hop deliberately broken.
    #[must_use]
    pub fn faulty(binding: impl Into<String>, router: axum::Router, fault: Fault) -> Self {
        Self {
            fault: Some(fault),
            ..Self::new(binding, router)
        }
    }

    /// How many requests reached the dispatcher. `0` proves the host
    /// answered without forwarding (an oversized body, a missing mount).
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Dispatcher for FakeSidecar {
    fn has(&self, binding: &str) -> bool {
        self.fault != Some(Fault::NotBound) && binding == self.binding
    }

    async fn dispatch(
        &self,
        binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if binding != self.binding {
            return Err(DispatchError::NotBound(binding.to_owned()));
        }
        if self.fault == Some(Fault::Unavailable) {
            return Err(DispatchError::Unavailable {
                binding: binding.to_owned(),
                reason: "fake sidecar is not answering".to_owned(),
            });
        }
        let (mut parts, body) = request.into_parts();
        if self.fault == Some(Fault::StripRequestHeaders) {
            parts.headers.clear();
        }
        let inbound = http::Request::from_parts(parts, axum::body::Body::from(body));
        let response = self
            .router
            .clone()
            .oneshot(inbound)
            .await
            .expect("in-process router is infallible");
        let (mut parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 8 * 1024 * 1024)
            .await
            .unwrap_or_default();
        let bytes = match self.fault {
            Some(Fault::DropRequestId) => {
                parts.headers.remove(cratefield_core::X_REQUEST_ID);
                bytes
            }
            Some(Fault::RemapStatus) => {
                parts.status = http::StatusCode::INTERNAL_SERVER_ERROR;
                bytes
            }
            Some(Fault::DuplicateRequestId) => {
                parts.headers.append(
                    cratefield_core::X_REQUEST_ID,
                    http::HeaderValue::from_static("a-second-id-from-the-sidecar"),
                );
                bytes
            }
            Some(Fault::MangleBody) => Bytes::from_static(b"{\"not\":\"what the module said\"}"),
            _ => bytes,
        };
        Ok(http::Response::from_parts(parts, bytes))
    }
}

/// Wraps a [`FakeSidecar`] so the same handle can be given to `Ports` and
/// still be asked how many calls it saw.
#[must_use]
pub fn shared(sidecar: FakeSidecar) -> (Arc<FakeSidecar>, Arc<dyn Dispatcher>) {
    let sidecar = Arc::new(sidecar);
    let handle: Arc<dyn Dispatcher> = sidecar.clone();
    (sidecar, handle)
}
