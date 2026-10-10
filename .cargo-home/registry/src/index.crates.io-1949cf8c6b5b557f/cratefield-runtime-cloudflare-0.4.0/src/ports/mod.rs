//! Port adapters over Workers bindings (ADR 0002).

mod blob;
mod clock;
mod d1;
mod d1_rate_limit;
mod defer;
mod dispatcher;
mod http;
mod kv;
mod rate_limit;
mod realtime;
mod vectorize;

pub(crate) use blob::{R2Blob, R2Presigner};
pub use clock::WorkersClock;
pub use d1::D1Database;
pub use d1_rate_limit::{D1RateLimiter, Limit, RATE_LIMIT_COUNTERS_SQL, RateLimitPolicy};
pub use defer::{ContextDefer, ScheduleDefer};
pub(crate) use dispatcher::ServiceDispatcher;
pub use http::FetchClient;
pub use kv::KvStorePort;
pub use rate_limit::RateLimitPort;
pub use realtime::RoomDriver;
pub(crate) use vectorize::vector_index_from_env;

use axum::http::HeaderMap;

/// The caller's IP from `cf-connecting-ip`. Never `x-forwarded-for` on
/// Workers (architecture section 11): that header is client-controlled.
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
