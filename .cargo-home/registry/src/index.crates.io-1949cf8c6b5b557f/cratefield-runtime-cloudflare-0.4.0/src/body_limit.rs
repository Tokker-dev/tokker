//! The request-body gate that runs before anything is resident (issue #440).
//!
//! A Workers isolate has a fixed memory ceiling, and the router's
//! `DefaultBodyLimit` only refuses once the body is already buffered — a few
//! large unauthenticated POSTs could kill the Worker before the limit was
//! ever consulted. `serve()` therefore decides how — and whether — to read
//! each body before reading it, and caps the streaming read for bodies that
//! declare no length.
//!
//! Everything here is pure and generic over the stream type, because a
//! `worker::Request` cannot be constructed outside wasm: native
//! `#[cfg(test)]` tests drive the same decision logic the isolate runs.

use futures_core::Stream;
use futures_util::StreamExt;

/// How `serve` may read this request's body, decided from the
/// `content-length` header before any byte is read.
pub(crate) enum BodyPlan {
    /// The declared length fits under the ceiling: buffer it. This is the
    /// `Request::bytes()` path, the one empirically verified under workerd,
    /// and stays the default for the common case.
    Buffer,
    /// The declared length is over the ceiling: refuse without reading.
    Refuse,
    /// No usable `content-length` (a chunked or streamed body, or a header
    /// that does not parse as a byte count): read streaming and abort the
    /// moment the ceiling is passed.
    Stream,
}

/// Decides the read plan for a body from its declared `content-length`.
///
/// `limit` is the harness's per-module pre-buffer ceiling
/// (`Harness::max_body_bytes`). A declaration of exactly `limit` still
/// buffers — the router's `DefaultBodyLimit` accepts a body at the limit,
/// so the guard in front of it must too. Absent, empty, non-numeric,
/// negative (which `usize` cannot parse) or overflowing declarations are
/// unusable, and an unusable declaration earns the streaming cap rather
/// than trust: a lying header must not buy an unbounded buffer.
pub(crate) fn body_plan(content_length: Option<&str>, limit: usize) -> BodyPlan {
    let Some(raw) = content_length else {
        return BodyPlan::Stream;
    };
    match raw.trim().parse::<usize>() {
        Ok(len) if len > limit => BodyPlan::Refuse,
        Ok(_) => BodyPlan::Buffer,
        Err(_) => BodyPlan::Stream,
    }
}

/// What a capped read of a body produced.
pub(crate) enum Capped {
    /// The body finished at or under the cap, read intact and in order.
    Within(Vec<u8>),
    /// The cap was passed. The bytes are dropped, not returned: the caller
    /// answers 413 and nothing past the cap is ever held in memory.
    TooLarge,
}

/// Reads a streaming body, refusing it the moment it passes `limit`.
///
/// Unlike collecting the stream, this never holds more than `limit` bytes:
/// the chunk that crosses the cap is examined only as a length and then
/// dropped along with everything streamed after it. Generic over the item
/// and error types so a test can feed it a synthetic stream — including one
/// that never ends, which under a collect-everything reader would never
/// terminate.
pub(crate) async fn read_capped<S, E>(stream: S, limit: usize) -> Result<Capped, E>
where
    S: Stream<Item = Result<Vec<u8>, E>>,
{
    futures_util::pin_mut!(stream);
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Ok(Capped::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Capped::Within(body))
}

#[cfg(test)]
mod tests {
    use super::{BodyPlan, Capped, body_plan, read_capped};
    use futures_core::Stream;
    use futures_util::stream;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    /// The ceiling every plan test below is measured against.
    const LIMIT: usize = 4096;
    /// The chunk size the synthetic bodies below use: four of them fill
    /// `LIMIT` exactly.
    const CHUNK: usize = 1024;

    /// A stream error, for tests that exercise the error path.
    #[derive(Debug, PartialEq)]
    struct TestError;

    /// A finite stream of fixed-size chunks, counting the chunks handed
    /// out so a test can see how much a reader consumed before it stopped.
    struct CountingChunks {
        remaining: usize,
        pulled: Arc<AtomicUsize>,
    }

    impl CountingChunks {
        /// `chunks` chunks of `CHUNK` bytes, plus the shared counter.
        fn new(chunks: usize) -> (Self, Arc<AtomicUsize>) {
            let pulled = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    remaining: chunks,
                    pulled: Arc::clone(&pulled),
                },
                pulled,
            )
        }
    }

    impl Stream for CountingChunks {
        type Item = Result<Vec<u8>, TestError>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            if this.remaining == 0 {
                return Poll::Ready(None);
            }
            this.remaining -= 1;
            this.pulled.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok(vec![b'x'; CHUNK])))
        }
    }

    /// A stream that never ends. Under the old collect-everything read a
    /// test feeding this never terminates; under the capped reader it must
    /// be cut off at the cap.
    struct Unbounded {
        pulled: Arc<AtomicUsize>,
    }

    impl Unbounded {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let pulled = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    pulled: Arc::clone(&pulled),
                },
                pulled,
            )
        }
    }

    impl Stream for Unbounded {
        type Item = Result<Vec<u8>, TestError>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            this.pulled.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok(vec![b'x'; CHUNK])))
        }
    }

    // ------------------------------------------------ the header decision

    #[test]
    fn a_declared_length_at_or_under_the_ceiling_is_buffered() {
        assert!(matches!(body_plan(Some("4096"), LIMIT), BodyPlan::Buffer));
        assert!(matches!(body_plan(Some("4095"), LIMIT), BodyPlan::Buffer));
        assert!(matches!(body_plan(Some("0"), LIMIT), BodyPlan::Buffer));
        // Header values may carry optional whitespace.
        assert!(matches!(body_plan(Some(" 4095 "), LIMIT), BodyPlan::Buffer));
    }

    #[test]
    fn a_declared_length_one_over_the_ceiling_is_refused_unread() {
        assert!(matches!(body_plan(Some("4097"), LIMIT), BodyPlan::Refuse));
    }

    #[test]
    fn a_body_without_a_usable_declared_length_is_streamed_under_the_cap() {
        assert!(matches!(body_plan(None, LIMIT), BodyPlan::Stream));
        // Garbage…
        assert!(matches!(body_plan(Some("chunks"), LIMIT), BodyPlan::Stream));
        // …an empty header…
        assert!(matches!(body_plan(Some(""), LIMIT), BodyPlan::Stream));
        // …a negative count (`usize` cannot parse it)…
        assert!(matches!(body_plan(Some("-1"), LIMIT), BodyPlan::Stream));
        // …and one too big for any byte count on any target.
        assert!(matches!(
            body_plan(Some("99999999999999999999999"), LIMIT),
            BodyPlan::Stream
        ));
    }

    // -------------------------------------------------------- the reading

    #[test]
    fn a_chunked_body_at_or_under_the_cap_is_read_intact() {
        // Exactly at the cap: the route would accept this body, so the
        // guard in front of it must read it.
        let (chunks, _) = CountingChunks::new(4);
        match pollster::block_on(read_capped(chunks, LIMIT)).expect("no stream error") {
            Capped::Within(body) => {
                assert_eq!(body.len(), LIMIT);
                assert!(body.iter().all(|byte| *byte == b'x'));
            }
            Capped::TooLarge => panic!("a body exactly at the cap must read"),
        }

        let (chunks, _) = CountingChunks::new(3);
        match pollster::block_on(read_capped(chunks, LIMIT)).expect("no stream error") {
            Capped::Within(body) => assert_eq!(body.len(), 3 * CHUNK),
            Capped::TooLarge => panic!("a body under the cap must read"),
        }
    }

    #[test]
    fn a_chunked_body_of_varied_chunks_is_read_intact_in_order() {
        let parts: Vec<Result<Vec<u8>, TestError>> = vec![
            Ok(b"hello ".to_vec()),
            Ok(b"capped ".to_vec()),
            Ok(b"world".to_vec()),
        ];
        match pollster::block_on(read_capped(stream::iter(parts), LIMIT)).expect("no stream error")
        {
            Capped::Within(body) => assert_eq!(body, b"hello capped world"),
            Capped::TooLarge => panic!("a body under the cap must read"),
        }
    }

    #[test]
    fn a_chunked_body_larger_than_the_cap_is_refused() {
        // Six chunks of 1024 against 4096: oversize with no usable
        // content-length, the shape an unauthenticated streamed POST has.
        let (chunks, pulled) = CountingChunks::new(6);
        let verdict = pollster::block_on(read_capped(chunks, LIMIT)).expect("no stream error");
        assert!(matches!(verdict, Capped::TooLarge));
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            5,
            "reading stops at the chunk that crosses the cap"
        );
    }

    #[test]
    fn an_endless_body_is_cut_off_once_it_passes_the_cap() {
        // The test the issue asks for: under the old
        // buffer-the-whole-body behaviour this stream would never
        // terminate, and would exhaust the isolate's memory trying.
        let (endless, pulled) = Unbounded::new();
        let verdict = pollster::block_on(read_capped(endless, LIMIT)).expect("no stream error");
        assert!(matches!(verdict, Capped::TooLarge));

        let consumed = pulled.load(Ordering::SeqCst);
        assert!(consumed > LIMIT / CHUNK, "the cap must actually be crossed");
        assert!(
            consumed <= LIMIT / CHUNK + 1,
            "abort within one chunk of the cap, not long after: {consumed}"
        );
        // The buffer held before the refused chunk: never over the cap.
        assert!(
            (consumed - 1) * CHUNK <= LIMIT,
            "the accumulated body never exceeded the cap"
        );
    }

    #[test]
    fn a_stream_error_stops_the_read_and_propagates() {
        let parts: Vec<Result<Vec<u8>, TestError>> = vec![Ok(b"ok".to_vec()), Err(TestError)];
        let verdict = pollster::block_on(read_capped(stream::iter(parts), LIMIT));
        assert!(matches!(verdict, Err(TestError)));
    }
}
