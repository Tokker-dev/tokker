//! The in-process event bus (issue #4, architecture section 4).
//!
//! It exists so `waitlist.confirmed` can feed `email-signup` without a crate
//! dependency between them. Handlers run through the request's [`Scope`]
//! defer (`wait_until` on Workers); errors are logged with the event name
//! and never fail the request. There is **no ordering guarantee and no
//! persistence** — if the isolate dies between response and deferred run,
//! the event is lost. Durable workflows are out of scope for the harness.
//!
//! ## The sidecar boundary and the delivery contract (issue #62, ADR 0017)
//!
//! The bus is one wasm instance wide. A module compiled into a sidecar
//! Worker cannot hear an event the host emits, and the host cannot hear one
//! the sidecar emits, so the harness forwards **inbound only**: every
//! emission is also posted to each mounted sidecar's `POST /__events`, and
//! a sidecar answers `202` and runs its own handlers in its *own* defer.
//! Sidecars do not emit back — a delivery-guarantee question the in-process
//! bus never had to answer stays unanswered rather than answered badly.
//!
//! What a subscriber gets across the boundary is exactly what it gets in
//! process: at-most-once, no retry, no ordering, failures logged and never
//! surfaced to the emitting request. No module gains a guarantee it did not
//! already have. The forwarder is attached where ports are resolved —
//! `Harness::router(ports)`, via [`EventBus::forwarding_to`] — because
//! `Harness::build` has no `Env`, and that is also why [`Scope`] stays
//! untouched and no handler signature changes, so [`HARNESS_API`] is
//! unbumped.
//!
//! A module author reads the boundary at the call site: `ctx.events` is an
//! [`EventBus`], and what `emit_in` reaches depends only on what the
//! deployment mounts, never on the emitting module. Which side of the
//! boundary a *subscriber* sits on is the deployment's choice
//! (`HARNESS_SIDECARS`), not the module's — a subscription written against
//! the bus works identically compiled in or in a sidecar.
//!
//! [`HARNESS_API`]: crate::module::HARNESS_API

use crate::scope::Scope;
use crate::sidecar::EventForwarder;
use futures_core::future::BoxFuture;
use serde_json::Value;
use std::sync::Arc;
use tracing::{error, warn};

/// Error type for handler and scheduled-work results.
pub type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Event names are `"<module>.<event>"`, e.g. `waitlist.confirmed`.
pub type EventName = String;

/// A registered handler: receives the emitting request's scope and the
/// payload.
pub type EventHandler =
    Arc<dyn Fn(&Scope, Value) -> BoxFuture<'static, Result<(), AnyError>> + Send + Sync>;

/// Registry of handlers, built once by `Harness::build` from every module's
/// `events()`. Cheap to clone (two `Arc`s).
#[derive(Clone, Default)]
pub struct EventBus {
    handlers: Arc<Vec<(EventName, EventHandler)>>,
    /// Attached where ports are resolved (`Harness::router`); `None` for a
    /// bus with nothing to forward to. See the module docs for the
    /// contract the attachment implies (issue #62).
    forwarder: Option<Arc<EventForwarder>>,
}

impl EventBus {
    /// An empty bus (a harness with no subscriptions).
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a bus from collected `(name, handler)` pairs, appending the
    /// new pairs after any existing ones (copy-on-write if the bus is
    /// already shared). Modules register via `Module::events()` at
    /// `Harness::build`.
    #[must_use]
    pub fn on(self, name: impl Into<EventName>, handler: EventHandler) -> Self {
        let mut handlers: Vec<(EventName, EventHandler)> = match Arc::try_unwrap(self.handlers) {
            Ok(handlers) => handlers,
            Err(shared) => (*shared).clone(),
        };
        handlers.push((name.into(), handler));
        Self {
            handlers: Arc::new(handlers),
            forwarder: None,
        }
    }

    /// The registered (name, handler) pairs, in registration order.
    pub fn handlers(&self) -> &[(EventName, EventHandler)] {
        &self.handlers
    }

    /// Attaches the sidecar forwarder (issue #62). Internal on purpose:
    /// who forwards, to which bindings and stamped with which key is the
    /// deployment's decision, made once in `Harness::router` — never a
    /// module's.
    #[must_use]
    pub(crate) fn forwarding_to(self, forwarder: EventForwarder) -> Self {
        Self {
            forwarder: Some(Arc::new(forwarder)),
            ..self
        }
    }

    /// Runs every local handler registered for `name` through the scope's
    /// defer. Returns how many ran. The sidecar's `POST /__events` uses the
    /// same path, so an inbound delivery carries the same "handler errors
    /// are logged, never surfaced" rule as an in-process emission.
    fn run_local(&self, scope: &Scope, name: &str, payload: &Value) -> usize {
        let matched: Vec<&(EventName, EventHandler)> = self
            .handlers
            .iter()
            .filter(|(handler_name, _)| handler_name == name)
            .collect();
        for (_, handler) in &matched {
            let fut = handler(scope, payload.clone());
            let event = name.to_string();
            scope.defer.wait_until(Box::pin(async move {
                if let Err(err) = fut.await {
                    error!(event = %event, error = %err, "event handler failed");
                    crate::logging::forward_internal_error(&format!(
                        "event handler failed for {event}: {err}"
                    ));
                }
            }));
        }
        matched.len()
    }

    /// The sidecar half of event forwarding (issue #62): the delivery the
    /// host posted to `POST /__events`, run against this deployment's own
    /// handlers and this request's defer. Returns the number of handlers
    /// that subscribed, so the route can refuse to be silent about an
    /// event nobody hears.
    pub fn deliver_inbound(&self, scope: &Scope, name: &str, payload: &Value) -> usize {
        self.run_local(scope, name, payload)
    }

    /// Runs every handler registered for `name` through the scope's defer,
    /// in the emitting request's `wait_until`, and forwards the event to
    /// every mounted sidecar (ADR 0017). Never fails the request; handler
    /// errors are logged with the event name. An emission nothing heard —
    /// no local handler and nothing forwarded — is warned about: the
    /// silent delivery this issue was written to prevent.
    // The by-value payload is the API fixed by issue #4; handlers each get
    // a clone.
    #[allow(clippy::needless_pass_by_value)]
    pub fn emit_in(&self, scope: &Scope, name: &str, payload: Value) {
        let handled = self.run_local(scope, name, &payload);
        let forwarded = match self.forwarder.as_ref() {
            Some(forwarder) if !forwarder.is_empty() => {
                let forwarder = Arc::clone(forwarder);
                let request_id = scope.request_id.clone();
                let event = name.to_string();
                scope.defer.wait_until(Box::pin(async move {
                    forwarder.forward(&request_id, &event, &payload).await;
                }));
                true
            }
            _ => false,
        };
        if handled == 0 && !forwarded {
            let detail = format!("emitted event `{name}` has no registered handler");
            warn!(event = %name, "{detail}");
            // Also to the forwarder, for the same reason the inbound half
            // does it: on Workers the tracing output is dropped, so a
            // report that exists only there is a report nobody reads —
            // which is the failure this warning was added to prevent.
            crate::logging::forward_internal_error(&detail);
        }
    }
}
