//! `RateLimiter` over D1 (issue #538): a fixed window per key, so limits
//! can vary per key where the Workers Rate Limiting binding offers one
//! boolean per namespace. One row per key, and the whole turn is a single
//! atomic upsert whose `RETURNING` row carries the new count — no
//! read-before-write race, even with isolates in different regions hitting
//! the same key inside one window.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

use cratefield_core::{Decision, Quota, RateLimitError, RateLimiter};
use worker::D1Database as WorkerD1;
use worker::send::IntoSendFuture;

/// The forward-only DDL for the `rate_limit_counters` table the upsert
/// below counts in. A venture wiring `.d1_rate_limiter(..)` ships this as
/// a migration in its `migrations/` directory, next to the module SQL.
pub const RATE_LIMIT_COUNTERS_SQL: &str = "CREATE TABLE IF NOT EXISTS rate_limit_counters (\
key TEXT PRIMARY KEY, \
window_start INTEGER NOT NULL, \
count INTEGER NOT NULL);";

/// One spent request, counted in the window the statement below opens.
const UPSERT_SQL: &str = "INSERT INTO rate_limit_counters \
(key, window_start, count) VALUES (?1, ?2, 1) \
ON CONFLICT(key) DO UPDATE SET \
count = CASE WHEN window_start = excluded.window_start THEN count + 1 ELSE 1 END, \
window_start = excluded.window_start \
RETURNING count, window_start";

/// The per-key budget a [`RateLimitPolicy`] answers with: `max` requests
/// per `period`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// Requests allowed in one window; the request that raises the count
    /// to `max` is the last one allowed before the window turns.
    pub max: u32,
    /// How long one window runs. Windows align to whole periods since the
    /// epoch, so every isolate agrees on the edges without talking.
    pub period: Duration,
}

/// Maps a rate-limit key to its budget — the hook that makes limits
/// per-key. `None` means **unlimited**: the key is allowed without a D1
/// round trip and no row is written for it. Apps encode the plan in the
/// key itself (`plan:pro:ip:203.0.113.7`, `plan:pro:email:n@x.co`) and
/// match on the prefix; the `ip:`/`email:` keys of
/// `cratefield_core::rate_limit_keys` slot in unchanged.
pub type RateLimitPolicy = Arc<dyn Fn(&str) -> Option<Limit> + Send + Sync>;

/// The answer for an unlimited key: allowed, nothing spent, nothing known.
const UNLIMITED: Decision = Decision {
    ok: true,
    retry_after: None,
    quota: None,
};

pub struct D1RateLimiter {
    db: WorkerD1,
    policy: RateLimitPolicy,
}

impl D1RateLimiter {
    #[must_use]
    pub fn new(db: WorkerD1, policy: RateLimitPolicy) -> Self {
        Self { db, policy }
    }
}

/// The whole period in whole milliseconds, at least one: a degenerate
/// `period` must not divide by zero, and a window of less than a
/// millisecond would count nothing anyway.
fn period_ms(period: Duration) -> i64 {
    i64::try_from(period.as_millis()).unwrap_or(i64::MAX).max(1)
}

/// The window a timestamp falls in: the whole multiple of the period the
/// epoch last reached before it.
fn window_start(now_ms: i64, period: Duration) -> i64 {
    let period = period_ms(period);
    now_ms - now_ms.rem_euclid(period)
}

/// The [`Decision`] for the count the upsert returned. `count` is what the
/// window has now seen *including* this request, so exactly the `max`-th
/// request passes and the next one waits for the rest of the window —
/// which is both its `retry_after` and the quota's `reset`.
fn decide(limit: Limit, now_ms: i64, window: i64, count: i64) -> Decision {
    let left_ms = (window + period_ms(limit.period) - now_ms).max(0);
    let reset = Duration::from_millis(u64::try_from(left_ms).unwrap_or(u64::MAX));
    let remaining = i64::from(limit.max)
        .saturating_sub(count)
        .clamp(0, i64::from(u32::MAX));
    let quota = Quota {
        limit: limit.max,
        // `unwrap_or(0)` covers the negative side (`try_from` fails); the
        // clamp above already bounds the positive side.
        remaining: u32::try_from(remaining).unwrap_or(0),
        reset,
    };
    if count <= i64::from(limit.max) {
        Decision {
            ok: true,
            retry_after: None,
            quota: Some(quota),
        }
    } else {
        Decision {
            ok: false,
            retry_after: Some(reset),
            quota: Some(Quota {
                remaining: 0,
                ..quota
            }),
        }
    }
}

fn transport(err: &worker::Error) -> RateLimitError {
    RateLimitError::Transport(err.to_string())
}

#[async_trait]
impl RateLimiter for D1RateLimiter {
    async fn limit(&self, key: &str) -> Result<Decision, RateLimitError> {
        let Some(limit) = (self.policy)(key) else {
            return Ok(UNLIMITED);
        };
        let now = time::OffsetDateTime::now_utc();
        let now_ms = now.unix_timestamp() * 1_000 + i64::from(now.millisecond());
        let window = window_start(now_ms, limit.period);

        // Bind through serde_json + serde_wasm_bindgen, the path
        // `ports/d1.rs` proved under workerd (the `D1Type` binds fail or
        // hang there). Both values are JSON-representable: a string and a
        // millisecond timestamp (< 2^53).
        let json = [
            serde_json::Value::String(key.to_owned()),
            serde_json::Value::from(window),
        ];
        let values: Vec<worker::wasm_bindgen::JsValue> = json
            .iter()
            .map(worker::d1::serde_wasm_bindgen::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| transport(&worker::Error::SerdeWasmBindgenError(err)))?;
        let prepared = self
            .db
            .prepare(UPSERT_SQL)
            .bind(&values)
            .map_err(|err| transport(&err))?;
        // Writes resolve through `batch`, not `.run()`/`.all()` (see
        // `ports/d1.rs`): plain write promises hang under local workerd.
        // The `RETURNING` row comes back in the statement's results.
        let results = self
            .db
            .batch(vec![prepared])
            .into_send()
            .await
            .map_err(|err| transport(&err))?;
        let row: serde_json::Value = results
            .first()
            .and_then(|result| result.results().ok())
            .and_then(|rows| rows.into_iter().next())
            .ok_or_else(|| {
                RateLimitError::Transport("rate-limit upsert returned no row".to_owned())
            })?;
        let count = row
            .get("count")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(1);
        let returned_window = row
            .get("window_start")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(window);
        Ok(decide(limit, now_ms, returned_window, count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn windows_align_to_whole_periods_since_the_epoch() {
        // 12:01:59.500 falls in the window that opened at 12:01:00.
        assert_eq!(
            window_start(12 * 60 * 1_000 + 1_500, MINUTE),
            12 * 60 * 1_000
        );
        assert_eq!(window_start(0, MINUTE), 0);
    }

    #[test]
    fn a_degenerate_period_divides_by_one_millisecond() {
        assert_eq!(window_start(1_500, Duration::ZERO), 1_500);
    }

    #[test]
    fn the_nth_request_passes_and_the_next_waits_out_the_window() {
        let limit = Limit {
            max: 3,
            period: MINUTE,
        };
        let (now, window) = (90_000, 60_000);

        let third = decide(limit, now, window, 3);
        assert!(third.ok);
        assert_eq!(third.retry_after, None);
        let quota = third.quota.expect("quota");
        assert_eq!((quota.limit, quota.remaining), (3, 0));
        assert_eq!(quota.reset, Duration::from_secs(30));

        let fourth = decide(limit, now, window, 4);
        assert!(!fourth.ok);
        assert_eq!(fourth.retry_after, Some(Duration::from_secs(30)));
        let quota = fourth.quota.expect("quota");
        assert_eq!((quota.limit, quota.remaining), (3, 0));
        assert_eq!(quota.reset, Duration::from_secs(30));
    }

    #[test]
    fn remaining_counts_down_from_the_limit() {
        let limit = Limit {
            max: 5,
            period: MINUTE,
        };
        let decision = decide(limit, 0, 0, 2);
        assert!(decision.ok);
        assert_eq!(decision.quota.expect("quota").remaining, 3);
    }

    #[test]
    fn a_count_beyond_the_cap_clamps_to_zero_remaining() {
        let limit = Limit {
            max: 5,
            period: MINUTE,
        };
        let decision = decide(limit, 1_000, 0, 500);
        assert!(!decision.ok);
        assert_eq!(decision.quota.expect("quota").remaining, 0);
    }
}
