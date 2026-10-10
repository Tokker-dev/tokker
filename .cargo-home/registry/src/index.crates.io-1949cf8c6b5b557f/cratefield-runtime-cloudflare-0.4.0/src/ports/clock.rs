//! `Clock` with a real timeout on Workers: races the future against
//! `worker::Delay` (setTimeout).

use async_trait::async_trait;
use futures_core::future::BoxFuture;
use futures_util::future::{Either, select};
use std::any::Any;
use std::time::Duration;

pub struct WorkersClock;

#[async_trait]
impl cratefield_core::Clock for WorkersClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    async fn timeout_any(
        &self,
        fut: BoxFuture<'static, Box<dyn Any + Send>>,
        after: Duration,
    ) -> Option<Box<dyn Any + Send>> {
        // worker::Delay holds Rc (single-threaded isolate); SendFuture is
        // the workers-rs-sanctioned Send wrapper (ADR 0002).
        let delay = worker::send::SendFuture::new(worker::Delay::from(after));
        match select(fut, Box::pin(delay)).await {
            Either::Left((output, _)) => Some(output),
            Either::Right(((), _)) => None,
        }
    }
}
