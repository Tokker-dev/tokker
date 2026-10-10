//! The `Dispatcher` port (ADR 0009): forwards a request to the Worker that
//! serves a sidecar-mounted module.
//!
//! Deliberately **not** a [`Port`](super::Port) variant, so it never appears in
//! a module's `requires()` or `optional()` and `view_for` can never hand it to
//! one. Only the harness router dispatches; a module that could reach this
//! trait could call any sidecar the venture has bound, which is not a
//! capability any module has a reason to hold.

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum DispatchError {
    /// The runtime has no binding of that name. Discovered on the first
    /// request that needs it, never at build time: `HarnessBuilder::build`
    /// has no `Env` to look in (ADR 0009).
    #[error("no service binding named `{0}`")]
    NotBound(String),
    /// The binding exists but the sidecar did not answer.
    #[error("sidecar `{binding}` did not answer: {reason}")]
    Unavailable { binding: String, reason: String },
}

#[async_trait]
pub trait Dispatcher: Send + Sync {
    /// Whether a binding of this name exists. Cheap; called per request before
    /// dispatching so a missing binding degrades one prefix rather than
    /// surfacing as a transport error.
    fn has(&self, binding: &str) -> bool;

    /// Forward `request` to the bound Worker and return its response
    /// unaltered. Implementations must not retry: a sidecar call is inside
    /// the caller's request, and a retry would double any side effect.
    async fn dispatch(
        &self,
        binding: &str,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, DispatchError>;
}
