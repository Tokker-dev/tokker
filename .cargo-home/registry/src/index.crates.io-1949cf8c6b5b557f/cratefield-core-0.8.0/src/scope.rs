//! Per-request scope (ADR 0007): travels in axum request extensions, never
//! in shared mutable state. The discarded TypeScript v1 kept "the current
//! request" in a closure variable and two concurrent requests swapped ids;
//! Rust makes the same mistake possible with `thread_local!` or a `static`
//! `RefCell` — this module is the cure, and the concurrency test in
//! `tests/router.rs` is the regression test.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::future::Future;
use std::sync::Arc;
use tracing::Span;

use crate::ports::Defer;
use crate::problem::Problem;

/// Per-request scope, inserted into extensions by the request-id layer
/// (issue #2). Handlers receive it through the `Scope` extractor; there is
/// no ambient "current request".
#[derive(Clone)]
pub struct Scope {
    pub request_id: String,
    pub defer: Arc<dyn Defer>,
    pub span: Span,
}

impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("request_id", &self.request_id)
            .field("span", &self.span.metadata().map(tracing::Metadata::name))
            .finish_non_exhaustive()
    }
}

impl<S> FromRequestParts<S> for Scope
where
    S: Send + Sync,
{
    type Rejection = Problem;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Scope>()
                .cloned()
                .ok_or_else(Problem::internal),
        )
    }
}
