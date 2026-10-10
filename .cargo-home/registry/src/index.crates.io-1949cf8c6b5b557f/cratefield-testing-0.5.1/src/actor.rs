//! The `Actors` contract (issue #583), asserted against a host rather than
//! trusted from its docs. A host that returns an `Ok` reply without
//! serializing its actor's calls, commits a write a failing handler staged,
//! or fires an alarm early would pass a hand-written spot check and lose a
//! counter, a cursor or a lease in production.
//!
//! [`assert_actor_contract`] drives one host through every promise the port
//! makes — serialization, all-or-nothing commits, the size bounds, the alarm
//! lifecycle — using [`CONTRACT_ACTOR_KIND`]'s handler, which the kit ships
//! alongside it so any implementation can be held to the same standard.

use std::future::Future;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{
    ActorContext, ActorError, ActorHandler, ActorHandlers, Actors, MAX_ACTOR_MESSAGE_BYTES,
    MAX_ACTOR_REPLY_BYTES, MAX_ACTOR_VALUE_BYTES,
};
use futures_util::future::join_all;
use time::Duration as TimeDuration;

/// The kind [`contract_actor_handler`] answers for and
/// [`assert_actor_contract`] drives.
pub const CONTRACT_ACTOR_KIND: &str = "contract";

/// Message opcodes. The first byte of every message selects the behaviour;
/// a few carry a little-endian `u32` length after it.
const OP_INCR: u8 = 1;
const OP_GET: u8 = 2;
const OP_INCR_THEN_FAIL: u8 = 3;
const OP_PUT_N: u8 = 4;
const OP_DATA_LEN: u8 = 5;
const OP_REPLY_N: u8 = 6;
const OP_MARKER: u8 = 7;
const OP_PAD: u8 = 8;
const OP_ARM: u8 = 9;
const OP_ALARMS: u8 = 10;

/// Storage keys the contract handler uses. Every count is a decimal string,
/// so a reply is readable in a failure message.
const KEY_COUNTER: &str = "counter";
const KEY_DATA: &str = "data";
const KEY_ALARMS: &str = "alarms";
const KEY_MARKER: &str = "marker";
const KEY_REARM: &str = "rearm";
const KEY_SECS: &str = "secs";

/// The one handler the contract drives.
///
/// It is deliberately stateful-looking while staying stateless itself: every
/// value lives in the actor and is reached through [`ActorContext`], so a
/// host that drops the handler between events (a hibernating Durable Object)
/// still passes.
struct ContractActor;

#[async_trait]
impl ActorHandler for ContractActor {
    async fn on_message(
        &self,
        ctx: &mut dyn ActorContext,
        message: &[u8],
    ) -> Result<Vec<u8>, ActorError> {
        let Some((&op, rest)) = message.split_first() else {
            return Err(ActorError::Handler("contract: empty message".to_owned()));
        };
        match op {
            OP_INCR => {
                let next = stored_count(ctx, KEY_COUNTER).await? + 1;
                // Yield once before committing: a host that does not
                // serialize calls to one actor lets a second call read the
                // same value here, and the lost update is what the contract
                // looks for.
                yield_once().await;
                ctx.put(KEY_COUNTER, next.to_string().into_bytes()).await?;
                Ok(next.to_string().into_bytes())
            }
            OP_GET => Ok(stored_count(ctx, KEY_COUNTER)
                .await?
                .to_string()
                .into_bytes()),
            OP_INCR_THEN_FAIL => {
                let next = stored_count(ctx, KEY_COUNTER).await? + 1;
                ctx.put(KEY_COUNTER, next.to_string().into_bytes()).await?;
                Err(ActorError::Handler("contract: refused".to_owned()))
            }
            OP_PUT_N => {
                let n = read_size(rest)?;
                ctx.put(KEY_DATA, vec![0_u8; n]).await?;
                Ok(Vec::new())
            }
            OP_DATA_LEN => {
                let len = ctx.get(KEY_DATA).await?.map(|value| value.len());
                Ok(match len {
                    Some(len) => len.to_string().into_bytes(),
                    None => b"absent".to_vec(),
                })
            }
            OP_REPLY_N => {
                let n = read_size(rest)?;
                // Stage a marker before the oversized reply: a host that
                // committed it would prove it never checked the bound.
                ctx.put(KEY_MARKER, b"1".to_vec()).await?;
                Ok(vec![0_u8; n])
            }
            OP_MARKER => Ok(if ctx.get(KEY_MARKER).await?.is_some() {
                b"yes".to_vec()
            } else {
                b"no".to_vec()
            }),
            OP_PAD => Ok(b"ok".to_vec()),
            OP_ARM => {
                let raw = rest
                    .get(..4)
                    .ok_or_else(|| ActorError::Handler("contract: arm needs seconds".to_owned()))?;
                let rearm = rest.get(4).copied().unwrap_or(0) != 0;
                ctx.put(KEY_DATA, b"present".to_vec()).await?;
                ctx.put(KEY_SECS, raw.to_vec()).await?;
                if rearm {
                    ctx.put(KEY_REARM, b"1".to_vec()).await?;
                } else {
                    ctx.delete(KEY_REARM).await?;
                }
                let secs = i64::from(u32::from_le_bytes(
                    raw.try_into().expect("exactly four bytes"),
                ));
                ctx.set_alarm(ctx.now() + TimeDuration::seconds(secs))
                    .await?;
                Ok(Vec::new())
            }
            OP_ALARMS => Ok(stored_count(ctx, KEY_ALARMS)
                .await?
                .to_string()
                .into_bytes()),
            other => Err(ActorError::Handler(format!(
                "contract: unknown opcode {other}"
            ))),
        }
    }

    async fn on_alarm(&self, ctx: &mut dyn ActorContext) -> Result<(), ActorError> {
        let alarms = stored_count(ctx, KEY_ALARMS).await? + 1;
        ctx.put(KEY_ALARMS, alarms.to_string().into_bytes()).await?;
        if ctx.get(KEY_REARM).await?.is_some() {
            // Re-arm once: consume the flag and schedule the next firing.
            ctx.delete(KEY_REARM).await?;
            let secs = stored_secs(ctx).await?;
            let at = ctx.now() + TimeDuration::seconds(secs);
            ctx.set_alarm(at).await?;
        } else {
            // No re-arm: the alarm is spent and the actor's data is dropped.
            ctx.delete(KEY_DATA).await?;
        }
        Ok(())
    }
}

/// The contract handler, for a host that takes one [`Arc`].
#[must_use]
pub fn contract_actor_handler() -> Arc<dyn ActorHandler> {
    Arc::new(ContractActor)
}

/// A registry holding just the contract handler under
/// [`CONTRACT_ACTOR_KIND`], for a host built from [`ActorHandlers`].
#[must_use]
pub fn contract_actor_handlers() -> ActorHandlers {
    ActorHandlers::new().with(CONTRACT_ACTOR_KIND, contract_actor_handler())
}

/// Proves `actors` keeps the `Actors` contract, using `advance` to move the
/// host's clock forward by a [`Duration`] so a pending alarm fires — an
/// in-process host advances its own clock, an adapter's test drives
/// whatever its runtime exposes.
///
/// It runs its own keys under [`CONTRACT_ACTOR_KIND`], so it can be called
/// against any host with the contract handler registered.
///
/// # Panics
///
/// Panics when the contract is violated: concurrent calls to one actor lose
/// an update, a failing handler commits a write, a message, reply or value
/// over its bound is accepted (or one at the bound is refused), an alarm
/// fires early or not at all, or an unknown kind is not refused.
pub async fn assert_actor_contract<F, Fut>(actors: Arc<dyn Actors>, advance: F)
where
    F: Fn(Duration) -> Fut,
    Fut: Future<Output = ()>,
{
    let actors = actors.as_ref();
    check_serialization(actors).await;
    check_atomic_commit(actors).await;
    check_size_bounds(actors).await;
    check_alarm(actors, &advance).await;

    // (f) A kind the host has no handler for is refused, not guessed at.
    let err = actors.call("no-such-kind", "key", b"x").await.unwrap_err();
    assert!(
        matches!(err, ActorError::NotConfigured),
        "an unknown kind is NotConfigured: {err}"
    );
}

/// (a) and (b): calls to one actor run one at a time, and two actors do not
/// share a fate.
async fn check_serialization(actors: &dyn Actors) {
    // One hundred concurrent calls each see a distinct value and the counter
    // settles at exactly 100 — the serialization promise, read through the
    // increment's yield to the executor.
    let calls = (0..100).map(|_| actors.call(CONTRACT_ACTOR_KIND, "concurrent", &[OP_INCR]));
    let replies = join_all(calls).await;
    let mut values: Vec<usize> = replies
        .into_iter()
        .map(|reply| parse_decimal(&reply.expect("each concurrent increment succeeds")))
        .collect();
    values.sort_unstable();
    assert_eq!(
        values,
        (1..=100).collect::<Vec<usize>>(),
        "100 serialized increments must each see a distinct value"
    );
    assert_eq!(
        count(actors, "concurrent").await,
        100,
        "the counter settles at 100, no update lost"
    );

    // Two actors progress independently: incrementing one leaves the other
    // where it was.
    assert_eq!(increment(actors, "independent-a").await, 1);
    assert_eq!(increment(actors, "independent-b").await, 1);
    assert_eq!(increment(actors, "independent-a").await, 2);
    assert_eq!(count(actors, "independent-a").await, 2);
    assert_eq!(count(actors, "independent-b").await, 1);
}

/// (c): a handler that stages a write and then fails commits nothing.
async fn check_atomic_commit(actors: &dyn Actors) {
    assert_eq!(increment(actors, "failing").await, 1);
    let err = actors
        .call(CONTRACT_ACTOR_KIND, "failing", &[OP_INCR_THEN_FAIL])
        .await
        .unwrap_err();
    assert!(
        matches!(err, ActorError::Handler(_)),
        "a handler error surfaces as Handler: {err}"
    );
    assert_eq!(
        count(actors, "failing").await,
        1,
        "the staged write of a failing handler never lands"
    );
}

/// (d): the three size bounds, each at the limit and one byte over.
async fn check_size_bounds(actors: &dyn Actors) {
    let at_bound = vec![OP_PAD; MAX_ACTOR_MESSAGE_BYTES];
    call_ok(actors, "message-max", &at_bound).await;
    let over = vec![OP_PAD; MAX_ACTOR_MESSAGE_BYTES + 1];
    let err = actors
        .call(CONTRACT_ACTOR_KIND, "message-max", &over)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ActorError::TooLarge(_)),
        "a message one byte over the bound is refused: {err}"
    );

    let reply = call_ok(
        actors,
        "reply-max",
        &sized_message(OP_REPLY_N, MAX_ACTOR_REPLY_BYTES),
    )
    .await;
    assert_eq!(
        reply.len(),
        MAX_ACTOR_REPLY_BYTES,
        "a reply at the bound is accepted"
    );
    assert!(
        marker_present(actors, "reply-max").await,
        "the accepted reply's marker write committed"
    );
    let err = actors
        .call(
            CONTRACT_ACTOR_KIND,
            "reply-over",
            &sized_message(OP_REPLY_N, MAX_ACTOR_REPLY_BYTES + 1),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, ActorError::TooLarge(_)),
        "a reply one byte over the bound is refused: {err}"
    );
    assert!(
        !marker_present(actors, "reply-over").await,
        "an oversized reply commits nothing"
    );

    call_ok(
        actors,
        "value-max",
        &sized_message(OP_PUT_N, MAX_ACTOR_VALUE_BYTES),
    )
    .await;
    assert_eq!(
        data_len(actors, "value-max").await,
        Some(MAX_ACTOR_VALUE_BYTES),
        "a value at the bound is stored"
    );
    let err = actors
        .call(
            CONTRACT_ACTOR_KIND,
            "value-over",
            &sized_message(OP_PUT_N, MAX_ACTOR_VALUE_BYTES + 1),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, ActorError::TooLarge(_)),
        "a value one byte over the bound is refused: {err}"
    );
    assert_eq!(
        data_len(actors, "value-over").await,
        None,
        "an oversized value stores nothing"
    );
}

/// (e): an alarm fires only once the clock reaches it, re-arms once, fires
/// again, and then the actor's data is gone.
async fn check_alarm<F, Fut>(actors: &dyn Actors, advance: &F)
where
    F: Fn(Duration) -> Fut,
    Fut: Future<Output = ()>,
{
    call_ok(actors, "alarm", &arm_message(10, true)).await;
    assert_eq!(
        data_len(actors, "alarm").await,
        Some(b"present".len()),
        "arming leaves the actor's data in place"
    );
    advance(Duration::from_secs(5)).await;
    assert_eq!(
        alarm_count(actors, "alarm").await,
        0,
        "the alarm does not fire before its time"
    );
    advance(Duration::from_secs(5)).await;
    assert_eq!(
        alarm_count(actors, "alarm").await,
        1,
        "the alarm fires at its time"
    );
    advance(Duration::from_secs(10)).await;
    assert_eq!(
        alarm_count(actors, "alarm").await,
        2,
        "the alarm re-armed once and fired again"
    );
    assert_eq!(
        data_len(actors, "alarm").await,
        None,
        "a spent alarm deletes the actor's data"
    );
}

/// A call that is expected to succeed.
async fn call_ok(actors: &dyn Actors, key: &str, message: &[u8]) -> Vec<u8> {
    actors
        .call(CONTRACT_ACTOR_KIND, key, message)
        .await
        .expect("the contract call succeeds")
}

/// The value at `key`'s counter as a message reply.
async fn count(actors: &dyn Actors, key: &str) -> usize {
    parse_decimal(&call_ok(actors, key, &[OP_GET]).await)
}

/// Increments `key`'s counter and returns the reply.
async fn increment(actors: &dyn Actors, key: &str) -> usize {
    parse_decimal(&call_ok(actors, key, &[OP_INCR]).await)
}

/// How many times `key`'s alarm has fired.
async fn alarm_count(actors: &dyn Actors, key: &str) -> usize {
    parse_decimal(&call_ok(actors, key, &[OP_ALARMS]).await)
}

/// The length of `key`'s `data` value, or `None` when it is absent.
async fn data_len(actors: &dyn Actors, key: &str) -> Option<usize> {
    parse_len(&call_ok(actors, key, &[OP_DATA_LEN]).await)
}

/// Whether `key`'s marker write is present.
async fn marker_present(actors: &dyn Actors, key: &str) -> bool {
    call_ok(actors, key, &[OP_MARKER]).await.as_slice() == b"yes"
}

/// An opcode followed by a little-endian `u32` count.
fn sized_message(op: u8, n: usize) -> Vec<u8> {
    let mut message = vec![op];
    let n = u32::try_from(n).expect("a bounded size fits u32");
    message.extend_from_slice(&n.to_le_bytes());
    message
}

/// [`OP_ARM`] with a delay in seconds and whether the handler re-arms once.
fn arm_message(secs: u32, rearm: bool) -> Vec<u8> {
    let mut message = vec![OP_ARM];
    message.extend_from_slice(&secs.to_le_bytes());
    message.push(u8::from(rearm));
    message
}

/// The `u32` after an opcode.
fn read_size(rest: &[u8]) -> Result<usize, ActorError> {
    let raw: [u8; 4] = rest
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ActorError::Handler("contract: message too short".to_owned()))?;
    Ok(usize::try_from(u32::from_le_bytes(raw)).expect("a u32 fits usize"))
}

/// An ASCII decimal count, or zero when the value is absent or malformed.
fn parse_decimal(bytes: &[u8]) -> usize {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0)
}

/// A decimal length reply, or `None` for the `absent` sentinel.
fn parse_len(bytes: &[u8]) -> Option<usize> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// The counter stored at `key` inside the handler, zero when absent.
async fn stored_count(ctx: &mut dyn ActorContext, key: &str) -> Result<usize, ActorError> {
    Ok(parse_decimal(&ctx.get(key).await?.unwrap_or_default()))
}

/// The seconds the arming message stored, for a re-arm; zero if unreadable.
async fn stored_secs(ctx: &mut dyn ActorContext) -> Result<i64, ActorError> {
    let Some(raw) = ctx.get(KEY_SECS).await? else {
        return Ok(0);
    };
    Ok(match <[u8; 4]>::try_from(raw) {
        Ok(bytes) => i64::from(u32::from_le_bytes(bytes)),
        Err(_) => 0,
    })
}

/// Yields to the executor once, so a host that does not serialize calls to
/// one actor interleaves two handlers here and the lost update the contract
/// looks for becomes visible.
async fn yield_once() {
    let mut yielded = false;
    poll_fn(move |cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}
