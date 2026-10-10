//! Opt-in streamed request and response bodies (issue #585).
//!
//! The buffered half of the harness — the [`crate::Json`]/[`crate::Form`]
//! extractors and the 64 KiB `/v1/*` [`MAX_BODY_BYTES`] ceiling — reads a
//! whole body into memory before a handler sees it. That is the right
//! default (it is what lets a route answer problem+json before doing any
//! work) but it cannot carry a body larger than memory, in either
//! direction.
//!
//! A module opts a route out by naming it in
//! [`Module::streaming_routes`](crate::Module::streaming_routes). On such a
//! route:
//!
//! - the handler extracts a [`RequestStream`] instead of a buffered body (a
//!   [`crate::Json`]/[`crate::Form`] extractor would see an empty body), and
//!   reads it in chunks with the route's [`StreamRoute::max_bytes`] enforced
//!   as it goes: the chunk that would cross the ceiling is refused with
//!   [`StreamError::TooLarge`] rather than delivered, and the stream is fused
//!   and its source dropped;
//! - a declared `content-length` over the ceiling is refused with the same
//!   `413 request-too-large` every buffered route gives, answered by the
//!   router before any byte is read;
//! - the handler may answer with a [`ResponseStream`], which the runtime
//!   bridges to the wire without buffering it first.
//!
//! Every other route keeps the buffered behaviour it always had.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::Method;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures_core::Stream;

use crate::problem::Problem;
use crate::scope::Scope;

/// The shared one-shot cell both stream types wrap: whoever polls the body
/// or calls [`ResponseStream::take`] first gets the underlying stream, and
/// the other side then sees an empty stream. `Mutex` because the two sides
/// live in different parts of one request and the cell has to be `Sync`;
/// this is request-scoped state carried in the request/response, not the
/// ambient state ADR 0007 forbids.
#[allow(clippy::disallowed_types)]
type Slot =
    std::sync::Arc<std::sync::Mutex<Option<BoxStream<'static, Result<Bytes, StreamError>>>>>;

/// Builds the shared one-shot cell. The single place the `std::sync::Mutex`
/// [`Slot`] names is constructed, so the disallowed-types allow lives here
/// and the two stream types never name it themselves.
#[allow(clippy::disallowed_types)]
fn slot(inner: Option<BoxStream<'static, Result<Bytes, StreamError>>>) -> Slot {
    std::sync::Arc::new(std::sync::Mutex::new(inner))
}

/// A type-erased, `Send` stream of body chunks: the shape a runtime bridges
/// to the wire, and what [`ResponseStream::take`] hands one. Same definition
/// as `futures_util::stream::BoxStream`, written here because core depends
/// on `futures-core` only.
pub type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + 'a>>;

/// One route a module serves in streaming mode (issue #585). `path` is
/// relative to the module's `/v1/<name>` mount and uses axum's pattern
/// syntax: a literal segment, `{param}` for exactly one segment, or
/// `{*rest}` for the remaining one-or-more (`/upload`, `/files/{id}`,
/// `/files/{*rest}`).
///
/// `max_bytes` is this route's own ceiling, enforced chunk by chunk by
/// [`RequestStream`] and consulted by the router for the declared
/// `content-length` pre-check. It replaces [`Module::max_body_bytes`] on
/// this route, and may be raised or lowered freely: unlike the buffered
/// ceiling it is the precise per-route enforcer, not a coarse guard in front
/// of the router.
///
/// [`Module::max_body_bytes`]: crate::Module::max_body_bytes
#[derive(Debug, Clone)]
pub struct StreamRoute {
    pub method: Method,
    pub path: &'static str,
    pub max_bytes: usize,
}

impl StreamRoute {
    /// A `POST` route. `const` so a module's routes are one `static`
    /// slice, the way its migrations are.
    #[must_use]
    pub const fn post(path: &'static str, max_bytes: usize) -> Self {
        Self {
            method: Method::POST,
            path,
            max_bytes,
        }
    }

    /// A `PUT` route.
    #[must_use]
    pub const fn put(path: &'static str, max_bytes: usize) -> Self {
        Self {
            method: Method::PUT,
            path,
            max_bytes,
        }
    }

    /// A `GET` route (a streamed response with no request body).
    #[must_use]
    pub const fn get(path: &'static str, max_bytes: usize) -> Self {
        Self {
            method: Method::GET,
            path,
            max_bytes,
        }
    }
}

/// Why a [`RequestStream`] ended early.
#[derive(Debug, Clone)]
pub enum StreamError {
    /// The body crossed the route's [`StreamRoute::max_bytes`]. The chunk
    /// that would have crossed it is refused, not delivered, and the stream
    /// is fused from here on.
    TooLarge,
    /// The underlying transport failed mid-stream. The text is for logs and
    /// never reaches a response body.
    Transport(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("streamed body exceeded its route ceiling"),
            Self::Transport(detail) => write!(f, "stream transport error: {detail}"),
        }
    }
}

impl std::error::Error for StreamError {}

/// A mid-stream failure is a [`Problem`]: a ceiling breach is exactly the
/// `413 request-too-large` a buffered route answers with, and a transport
/// failure is a server-side fault the caller cannot fix, so it becomes the
/// generic `500 internal` (the same mapping [`crate::ports::DbError`] gets —
/// no internals in the body, the error only logged).
impl From<StreamError> for Problem {
    fn from(error: StreamError) -> Self {
        match error {
            StreamError::TooLarge => Self::request_too_large(),
            StreamError::Transport(detail) => {
                tracing::error!(error = %detail, "stream transport error mapped to internal problem");
                // wasm has no tracing dispatcher (it hangs the isolate), so
                // also forward to the runtime's sink, as the DbError mapping
                // does (issue #107).
                crate::logging::forward_internal_error(&format!(
                    "stream transport error: {detail}"
                ));
                Self::internal()
            }
        }
    }
}

/// A streamed request body (issue #585). Extracted by a handler on a route
/// its module declared in
/// [`Module::streaming_routes`](crate::Module::streaming_routes); the router
/// has already put it in the request extensions and emptied the buffered
/// body.
///
/// It is `Clone`, and clones share one cursor: the router's request layer
/// inserts one handle and a handler may clone it, but they read the same
/// underlying stream. It is one-shot — once the source ends (or is refused),
/// every later poll answers `None` forever.
#[derive(Clone)]
pub struct RequestStream {
    slot: Slot,
}

impl RequestStream {
    /// Wraps `stream`, enforcing `max_bytes` as chunks are read. Accepts any
    /// `Send` stream of `Result<O, E>` where `O` converts into [`Bytes`] and
    /// `E` renders — an axum `Body::into_data_stream()`, a runtime's own
    /// body stream, or a test's synthetic one.
    #[must_use]
    pub fn new<S, O, E>(stream: S, max_bytes: usize) -> Self
    where
        S: Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<Bytes> + 'static,
        E: fmt::Display + 'static,
    {
        let capped: BoxStream<'static, Result<Bytes, StreamError>> = Box::pin(Capped {
            inner: Some(map_stream(stream)),
            delivered: 0,
            max: max_bytes,
        });
        Self {
            slot: slot(Some(capped)),
        }
    }

    /// A stream that ends immediately. The empty exchange a test or a
    /// runtime hands a route that has no body of its own.
    #[must_use]
    pub fn empty() -> Self {
        Self { slot: slot(None) }
    }

    /// The next chunk, or `None` once the source has ended (or was refused).
    /// A convenience for core callers, who have no `StreamExt`: it is
    /// [`futures_core::Stream::poll_next`] behind `std::future::poll_fn`.
    pub async fn next_chunk(&mut self) -> Option<Result<Bytes, StreamError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}

impl Stream for RequestStream {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut slot = this.slot.lock().expect("stream slot lock uncontended");
        match slot.as_mut() {
            Some(stream) => stream.as_mut().poll_next(cx),
            None => Poll::Ready(None),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestStream {
    type Rejection = Problem;

    /// Removes the router-inserted stream from the request extensions. A
    /// route that was not declared in `Module::streaming_routes` has none,
    /// and extracting here is a programming error — never a client one — so
    /// it answers a `500 internal` naming the declaration that is missing.
    // The trait method is `async`; this impl never awaits, which the lint
    // reads as a mistake but the signature does not allow otherwise.
    #[allow(clippy::unused_async_trait_impl)]
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(stream) = parts.extensions.remove::<RequestStream>() {
            return Ok(stream);
        }
        let mut problem = Problem::internal().with_detail(
            "RequestStream is only available on a route declared in the owning module's \
             streaming_routes()",
        );
        if let Some(scope) = parts.extensions.get::<Scope>() {
            problem = problem.instance(&scope.request_id);
        }
        Err(problem)
    }
}

/// A streamed response body (issue #585).
///
/// Answering with one bridges the chunks to the wire without buffering them:
/// on native (and in the test kit) the [`axum`] body is polled directly, so
/// nothing runtime-specific is needed. A runtime that cannot bridge an axum
/// body — `runtime-cloudflare` — instead calls [`ResponseStream::take`] to
/// pull the stream out of the response extensions. Whoever takes first wins;
/// the other side then sees an empty body.
#[derive(Clone)]
pub struct ResponseStream {
    slot: Slot,
}

impl ResponseStream {
    /// Wraps `stream` as a response body. No ceiling: a streamed response is
    /// bounded by the handler that produced it, not by a request limit.
    #[must_use]
    pub fn new<S, O, E>(stream: S) -> Self
    where
        S: Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<Bytes> + 'static,
        E: fmt::Display + 'static,
    {
        Self {
            slot: slot(Some(map_stream(stream))),
        }
    }

    /// Takes the underlying stream, for a runtime that bridges it to its own
    /// response type rather than polling the axum body — `runtime-cloudflare`
    /// builds a Worker response from it, because converting an axum body into
    /// a Worker `Response` hangs the isolate. `None` once the body has
    /// already been polled (or taken).
    ///
    /// # Panics
    ///
    /// Panics if the slot's lock is poisoned — only reachable if a prior
    /// poll panicked while holding it.
    #[must_use]
    pub fn take(&self) -> Option<BoxStream<'static, Result<Bytes, StreamError>>> {
        self.slot
            .lock()
            .expect("stream slot lock uncontended")
            .take()
    }
}

impl IntoResponse for ResponseStream {
    fn into_response(self) -> Response {
        let body = Body::from_stream(BodySource {
            slot: std::sync::Arc::clone(&self.slot),
            inner: None,
        });
        let mut response = Response::new(body);
        // The handle rides along on the response so a runtime can `take` the
        // stream out of it instead of polling the axum body.
        response.extensions_mut().insert(self);
        response
    }
}

/// The axum-body side of a [`ResponseStream`]: takes the inner stream from
/// the shared slot the first time it is polled, then delegates to it. If a
/// runtime took it first the slot is already empty and this yields `None`.
struct BodySource {
    slot: Slot,
    inner: Option<BoxStream<'static, Result<Bytes, StreamError>>>,
}

impl Stream for BodySource {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.inner.is_none() {
            this.inner = this
                .slot
                .lock()
                .expect("stream slot lock uncontended")
                .take();
        }
        match this.inner.as_mut() {
            Some(stream) => stream.as_mut().poll_next(cx),
            None => Poll::Ready(None),
        }
    }
}

/// Enforces a byte ceiling on an already-mapped chunk stream: the chunk that
/// would cross `max` is replaced by [`StreamError::TooLarge`] (it is not
/// delivered), the source is dropped, and every later poll answers `None`.
struct Capped {
    inner: Option<BoxStream<'static, Result<Bytes, StreamError>>>,
    delivered: usize,
    max: usize,
}

impl Stream for Capped {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let polled = match this.inner.as_mut() {
            Some(stream) => stream.as_mut().poll_next(cx),
            None => return Poll::Ready(None),
        };
        match polled {
            Poll::Ready(Some(Ok(chunk))) => {
                if this.delivered.saturating_add(chunk.len()) > this.max {
                    // Drop the source and fuse: nothing further is read.
                    this.inner = None;
                    Poll::Ready(Some(Err(StreamError::TooLarge)))
                } else {
                    this.delivered += chunk.len();
                    Poll::Ready(Some(Ok(chunk)))
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => {
                this.inner = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Type-erases a `Stream<Item = Result<O, E>>` into the `BoxStream` shape,
/// mapping each item into [`Bytes`] and each error into
/// [`StreamError::Transport`]. The inner stream is boxed first, so the
/// adapter itself is `Unpin` and needs no `pin_project`.
fn map_stream<S, O, E>(stream: S) -> BoxStream<'static, Result<Bytes, StreamError>>
where
    S: Stream<Item = Result<O, E>> + Send + 'static,
    O: Into<Bytes> + 'static,
    E: fmt::Display + 'static,
{
    Box::pin(MapStream {
        inner: Box::pin(stream),
    })
}

struct MapStream<T, E> {
    inner: Pin<Box<dyn Stream<Item = Result<T, E>> + Send + 'static>>,
}

impl<T, E> Stream for MapStream<T, E>
where
    T: Into<Bytes> + 'static,
    E: fmt::Display + 'static,
{
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item.into()))),
            Poll::Ready(Some(Err(err))) => {
                Poll::Ready(Some(Err(StreamError::Transport(err.to_string()))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tiny `Stream` over a `Vec`, written out because the crate has no
    // `futures-util` and the tests need nothing more than this.
    struct VecStream<T> {
        items: std::vec::IntoIter<T>,
    }

    impl<T: std::marker::Unpin> Stream for VecStream<T> {
        type Item = T;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<T>> {
            Poll::Ready(self.get_mut().items.next())
        }
    }

    /// A `Send` chunk stream whose items are `Ok(Vec<u8>)`/`Err(String)`,
    /// the shape a runtime's body stream maps to.
    fn chunks(
        items: Vec<Result<&'static [u8], &'static str>>,
    ) -> impl Stream<Item = Result<Vec<u8>, String>> + Send {
        VecStream {
            items: items
                .into_iter()
                .map(|item| item.map(<[u8]>::to_vec).map_err(str::to_owned))
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    #[pollster::test]
    async fn the_crossing_chunk_is_refused_and_the_stream_fuses() {
        let mut stream = RequestStream::new(
            chunks(vec![Ok(b"12345"), Ok(b"67890"), Ok(b"unreachable")]),
            8,
        );
        assert_eq!(stream.next_chunk().await.unwrap().unwrap(), "12345");
        // 5 + 5 crosses 8 on the second chunk: refused, not delivered.
        assert!(matches!(
            stream.next_chunk().await.unwrap(),
            Err(StreamError::TooLarge)
        ));
        assert!(stream.next_chunk().await.is_none(), "fused after refusal");
    }

    #[pollster::test]
    async fn a_body_exactly_at_the_ceiling_is_allowed() {
        let mut stream = RequestStream::new(chunks(vec![Ok(b"1234"), Ok(b"5678")]), 8);
        assert_eq!(stream.next_chunk().await.unwrap().unwrap(), "1234");
        assert_eq!(stream.next_chunk().await.unwrap().unwrap(), "5678");
        assert!(
            stream.next_chunk().await.is_none(),
            "clean end at the limit"
        );
    }

    #[pollster::test]
    async fn a_transport_error_is_mapped_not_swallowed() {
        let mut stream = RequestStream::new(chunks(vec![Ok(b"hi"), Err("boom")]), 1024);
        assert_eq!(stream.next_chunk().await.unwrap().unwrap(), "hi");
        match stream.next_chunk().await.unwrap() {
            Err(StreamError::Transport(detail)) => assert!(detail.contains("boom"), "{detail}"),
            other => panic!("expected a transport error, got {other:?}"),
        }
    }

    #[pollster::test]
    async fn an_empty_stream_ends_at_once() {
        let mut stream = RequestStream::empty();
        assert!(stream.next_chunk().await.is_none());
    }

    #[pollster::test]
    async fn all_response_chunks_reach_the_body() {
        let response =
            ResponseStream::new(chunks(vec![Ok(b"one"), Ok(b"two"), Ok(b"three")])).into_response();
        let body = axum::body::to_bytes(response.into_parts().1, 1024)
            .await
            .expect("body reads");
        assert_eq!(&body[..], b"onetwothree");
    }

    #[pollster::test]
    async fn take_after_the_body_was_consumed_answers_none() {
        let stream = ResponseStream::new(chunks(vec![Ok(b"one")]));
        let response = stream.clone().into_response();
        let body = axum::body::to_bytes(response.into_parts().1, 1024)
            .await
            .expect("body reads");
        assert_eq!(&body[..], b"one");
        assert!(stream.take().is_none(), "the body already took the stream");
    }

    #[pollster::test]
    async fn take_first_leaves_the_axum_body_empty() {
        let stream = ResponseStream::new(chunks(vec![Ok(b"one")]));
        assert!(stream.take().is_some(), "the runtime takes the stream");
        let response = stream.into_response();
        let body = axum::body::to_bytes(response.into_parts().1, 1024)
            .await
            .expect("body reads");
        assert!(body.is_empty(), "whoever takes first wins");
    }
}
