//! The `Realtime` port (issue #103): rooms of WebSocket connections that share
//! a clock and a chat — Yoginini's "together rooms", 2-20 people practising the
//! same sequence.
//!
//! The harness is otherwise one stateless Worker over ports, with no way to
//! hold a connection or coordinate between requests. This port is the
//! exception: on Cloudflare a Durable Object holds the sockets (with the
//! hibernation API, so an idle room costs nothing); on the native runtime an
//! in-process registry does.
//!
//! **Split of responsibilities.** The port owns the sockets; the module owns
//! the protocol. A module implements [`RoomHandler`] (`on_join`, `on_message`,
//! `on_leave`, `on_alarm`) and the runtime calls it as events arrive, passing a
//! [`RoomContext`] to reach the sockets. A module's ordinary HTTP handlers poke
//! a room from outside a socket through the [`Realtime`] trait
//! (`broadcast`/`members`). Because a handler holds no socket itself — it
//! reaches them only through the context it is handed — a hibernating Durable
//! Object can drop the handler between events and reconstruct it on the next.
//!
//! **The Durable Object is a coordinator, not the record.** Anything that must
//! survive (a chat transcript) is the module's job to write to the database;
//! room state is ephemeral coordination.

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// A connected participant, identified by the venture *after* it verified the
/// upgrade request's bearer token (through the `Signer` or the auth client).
/// A [`RoomHandler`] only ever sees this verified id, never a raw token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id: String,
}

impl Member {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Realtime failures.
#[derive(Debug, Clone, Error)]
pub enum RealtimeError {
    /// No realtime adapter configured (no Durable Object binding): the caller
    /// should degrade, not fail.
    #[error("realtime is not configured")]
    NotConfigured,
    /// A message arrived from a socket whose member is not in the room (it left
    /// or never joined): drop it.
    #[error("sender is not a member of this room")]
    NotAMember,
    /// The room does not exist or has no connected members.
    #[error("no such room: {0}")]
    NoSuchRoom(String),
    /// A transport or storage failure.
    #[error("realtime operation failed: {0}")]
    Operation(String),
}

/// The operations a [`RoomHandler`] performs on its room while handling an
/// event. The handler holds no sockets of its own — it reaches them through
/// this context — so a Durable Object can hibernate between events.
#[async_trait]
pub trait RoomContext: Send + Sync {
    /// The room this event is for.
    fn room_id(&self) -> &str;

    /// The members currently connected.
    async fn members(&self) -> Vec<Member>;

    /// Send `message` to every connected socket.
    async fn broadcast(&self, message: &[u8]) -> Result<(), RealtimeError>;

    /// Send `message` to one member's socket(s).
    async fn send(&self, member_id: &str, message: &[u8]) -> Result<(), RealtimeError>;

    /// Schedule [`RoomHandler::on_alarm`] to fire once after `delay` — the
    /// shared clock. Setting it again replaces the pending alarm.
    async fn set_alarm(&self, delay: Duration) -> Result<(), RealtimeError>;
}

/// The protocol for one kind of room. A module implements it; the runtime owns
/// the sockets and calls these as events arrive.
///
/// Implementations must be **stateless** — all room state lives in the room and
/// is reached through [`RoomContext`] — so a hibernating Durable Object can
/// reconstruct the handler on the next event. `route()` is the path prefix the
/// runtime mounts the upgrade endpoint under (`GET <route>/<room_id>`).
#[async_trait]
pub trait RoomHandler: Send + Sync {
    /// The path prefix for this room's upgrade endpoint, e.g. `"/rooms"`. The
    /// runtime serves `GET <route>/<room_id>` as the WebSocket upgrade.
    fn route(&self) -> &'static str {
        "/rooms"
    }

    /// A member's socket has opened and joined the room.
    async fn on_join(&self, ctx: &dyn RoomContext, member: &Member) -> Result<(), RealtimeError> {
        let _ = (ctx, member);
        Ok(())
    }

    /// A message arrived from a member's socket.
    async fn on_message(
        &self,
        ctx: &dyn RoomContext,
        member: &Member,
        message: &[u8],
    ) -> Result<(), RealtimeError>;

    /// A member's socket has closed and left the room.
    async fn on_leave(&self, ctx: &dyn RoomContext, member: &Member) -> Result<(), RealtimeError> {
        let _ = (ctx, member);
        Ok(())
    }

    /// A previously scheduled alarm fired (the shared clock tick).
    async fn on_alarm(&self, ctx: &dyn RoomContext) -> Result<(), RealtimeError> {
        let _ = ctx;
        Ok(())
    }
}

/// Poke a room from outside a socket — a module's HTTP handler (e.g. an admin
/// ends a session) or a cron. The socket lifecycle itself is the runtime's job
/// (it calls [`RoomHandler`]); this is the part a module holds via [`Ports`].
///
/// [`Ports`]: crate::Ports
#[async_trait]
pub trait Realtime: Send + Sync {
    /// Send `message` to every socket in `room_id`.
    async fn broadcast(&self, room_id: &str, message: &[u8]) -> Result<(), RealtimeError>;

    /// The members currently connected to `room_id`.
    async fn members(&self, room_id: &str) -> Result<Vec<Member>, RealtimeError>;
}
