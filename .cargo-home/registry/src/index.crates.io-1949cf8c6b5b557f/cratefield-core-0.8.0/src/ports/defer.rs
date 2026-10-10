//! The `Defer` port (architecture section 5, ADR 0007): work that outlives
//! the response. Request-scoped; travels inside [`crate::Scope`], never in
//! shared state.

use futures_core::future::BoxFuture;

pub trait Defer: Send + Sync {
    /// Schedule work to continue after the response is returned
    /// (`Context::wait_until` on Workers, `tokio::spawn` natively).
    fn wait_until(&self, fut: BoxFuture<'static, ()>);
}

/// Drops deferred futures with a warning. Used when no runtime defer is
/// available; tests that assert on deferred work supply their own.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopDefer;

impl Defer for NoopDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        tracing::warn!("deferred work dropped: no Defer port configured");
        drop(fut);
    }
}
