//! `RateLimiter` over the Workers Rate Limiting binding. The binding does
//! not expose a retry-after, so `Decision::retry_after` is `None`.

use async_trait::async_trait;
use cratefield_core::{Decision, RateLimitError, RateLimiter};
use worker::RateLimiter as WorkerRateLimiter;

pub struct RateLimitPort(pub WorkerRateLimiter);

#[async_trait]
impl RateLimiter for RateLimitPort {
    async fn limit(&self, key: &str) -> Result<Decision, RateLimitError> {
        let outcome = self
            .0
            .limit(key.to_owned())
            .await
            .map_err(|err| RateLimitError::Transport(err.to_string()))?;
        Ok(Decision {
            ok: outcome.success,
            retry_after: None,
            // The binding answers a boolean per namespace: it has no
            // window to report, so no quota and no `RateLimit-*` headers.
            quota: None,
        })
    }
}
