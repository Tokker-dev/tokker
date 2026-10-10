//! The `RateLimiter` port (architecture section 5).

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// The budget a key spends against, when the limiter knows one (issue
/// #538). A Workers Rate Limiting binding does not; a D1-backed fixed
/// window does. `limit` is the budget per window, `remaining` what is
/// left of the current one, and `reset` how long until it turns over —
/// the three numbers `rate_limited` puts on the `RateLimit-*` headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quota {
    pub limit: u32,
    pub remaining: u32,
    pub reset: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub ok: bool,
    pub retry_after: Option<Duration>,
    /// The quota this decision was taken against, when the limiter
    /// reports one. `None` for limiters that cannot know (the Workers
    /// binding, Redis sliding windows without a count).
    pub quota: Option<Quota>,
}

#[derive(Debug, Clone, Error)]
pub enum RateLimitError {
    #[error("rate limiter transport error: {0}")]
    Transport(String),
}

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn limit(&self, key: &str) -> Result<Decision, RateLimitError>;
}
