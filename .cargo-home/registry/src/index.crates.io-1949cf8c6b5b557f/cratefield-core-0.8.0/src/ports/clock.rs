//! The `Clock` port (architecture section 5): wall time plus a timeout
//! facility so core can bound work without depending on a timer runtime.
//!
//! The timeout is supplied by the runtime's clock because core has no
//! timer of its own: Workers implements it with `setTimeout`, the native
//! runtime (phase 3) with tokio's timer. The default implementation runs
//! the future to completion and ignores the deadline — acceptable only in
//! tests, and documented as such.

use async_trait::async_trait;
use futures_core::future::BoxFuture;
use std::any::Any;
use std::time::Duration;

#[async_trait]
pub trait Clock: Send + Sync {
    fn now(&self) -> time::OffsetDateTime;

    /// Runs `fut` to completion, abandoning it after `after` elapses.
    /// Returns `None` on timeout. Default: runs to completion (no timer;
    /// test-only — runtimes override).
    async fn timeout_any(
        &self,
        fut: BoxFuture<'static, Box<dyn Any + Send>>,
        after: Duration,
    ) -> Option<Box<dyn Any + Send>> {
        let _ = after;
        Some(fut.await)
    }
}

/// Typed wrapper over [`Clock::timeout_any`]. `None` means the clock
/// abandoned the future after `after`.
pub async fn timeout<T: Send + 'static>(
    clock: &dyn Clock,
    fut: impl Future<Output = T> + Send + 'static,
    after: Duration,
) -> Option<T> {
    let boxed: BoxFuture<'static, Box<dyn Any + Send>> =
        Box::pin(async move { Box::new(fut.await) as Box<dyn Any + Send> });
    match clock.timeout_any(boxed, after).await {
        Some(any) => any.downcast::<T>().ok().map(|v| *v),
        None => None,
    }
}

/// Real wall clock (`time` crate). Its timeout runs futures to completion —
/// tests that need a real timeout supply their own clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[async_trait]
impl Clock for SystemClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}
