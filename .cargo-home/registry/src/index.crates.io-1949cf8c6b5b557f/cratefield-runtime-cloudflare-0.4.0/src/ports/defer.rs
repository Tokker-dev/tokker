//! `Defer` over the Workers `wait_until` entry points: fetch contexts and
//! scheduled contexts each have one.

use cratefield_core::Defer;
use futures_core::future::BoxFuture;
use worker::{Context, ScheduleContext};

pub struct ContextDefer(pub Context);

impl Defer for ContextDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        self.0.wait_until(fut);
    }
}

pub struct ScheduleDefer(pub ScheduleContext);

impl Defer for ScheduleDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        self.0.wait_until(fut);
    }
}
