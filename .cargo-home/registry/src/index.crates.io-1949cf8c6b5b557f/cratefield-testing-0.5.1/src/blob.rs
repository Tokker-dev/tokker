//! The `Database` blob round-trip contract (issue #39), asserted against
//! a live adapter rather than trusted from its docs. A database that
//! mangles bound bytes — trimming a NUL, re-encoding through text,
//! padding a base64 hop — cannot hold a ciphertext, a wrapped key or a
//! nonce.
//!
//! The `Blob` large-object contract (issue #586) lives beside it: the
//! streamed reads/writes and multipart uploads an adapter needs to carry
//! an object past [`MAX_BLOB_BYTES`](cratefield_core::MAX_BLOB_BYTES).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;

use cratefield_core::{
    Blob, BlobError, BoxStream, Database, PartReceipt, ScopedBlob, Statement, StreamError, UploadId,
};

/// Proves `db` round-trips bound bytes exactly: a `Vec<u8>` bound as
/// `Value::Bytes` reads back byte-for-byte identical, and a NULL blob
/// reads back as no bytes. Runs its own probe table, so it can be called
/// against any adapter with a writable connection.
///
/// An adapter that stores blobs as text fails loudly here — the port's
/// answer to "bytes where supported" (issue #39).
///
/// # Panics
///
/// Panics when the blob contract is violated: the bound payload does not
/// read back exactly, a NULL blob reads back as bytes, or the probe
/// table cannot be created on the given connection.
pub async fn assert_blob_round_trips(db: &dyn Database) {
    // One DDL for both engines: Postgres spells the byte column BYTEA and
    // has no BLOB (the portability lint bans the token outright), while
    // SQLite accepts any declared type and stores a bound blob faithfully
    // under it — the same reason auth-core's Postgres migration
    // overrides only ever rename the byte columns.
    db.execute(&Statement::new(
        "CREATE TABLE IF NOT EXISTS blob_round_trip_probe \
         (id INTEGER PRIMARY KEY, payload BYTEA)",
    ))
    .await
    .expect("probe table");

    db.execute(&Statement::new("DELETE FROM blob_round_trip_probe"))
        .await
        .expect("clear probe");

    // Bytes that die in any text-encoding hop: a NUL (truncation bait),
    // 0xFF and 0xFE (invalid UTF-8 in any position), a stray continuation
    // byte 0x80, the broken pair 0xC3 0x28, and a newline (trim bait).
    // Eleven bytes — not a multiple of three, so a base64 round trip
    // would leave padding artefacts behind.
    let payload: Vec<u8> = vec![
        0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x80, 0xFE, 0xC3, 0x28, 0x0A,
    ];
    db.execute(&Statement::with_values(
        "INSERT INTO blob_round_trip_probe (id, payload) VALUES (?, ?)",
        vec![1_i32.into(), payload.clone().into()],
    ))
    .await
    .expect("bind the byte payload");

    // A NULL blob: `Value::Bytes(None)` binds as SQL NULL. The adapters
    // do not agree on how NULL is reported back — adapter-sqlite
    // flattens every SQL NULL to `Value::String(None)` (its
    // `sqlite_to_sea`), adapter-postgres uses the type-appropriate
    // `Value::Bytes(None)` — so the raw variant is not portable. What
    // every adapter must agree on is the typed read: no bytes came back.
    db.execute(&Statement::with_values(
        "INSERT INTO blob_round_trip_probe (id, payload) VALUES (?, ?)",
        vec![2_i32.into(), None::<Vec<u8>>.into()],
    ))
    .await
    .expect("bind a NULL blob");

    let stored = db
        .query(&Statement::with_values(
            "SELECT payload FROM blob_round_trip_probe WHERE id = ?",
            vec![1_i32.into()],
        ))
        .await
        .expect("read the payload back");
    let row = stored.first().expect("the payload row is visible");
    assert_eq!(
        row.get::<Vec<u8>>("payload"),
        Some(payload),
        "the bytes read back are exactly the bytes bound"
    );

    let nulled = db
        .query(&Statement::with_values(
            "SELECT payload FROM blob_round_trip_probe WHERE id = ?",
            vec![2_i32.into()],
        ))
        .await
        .expect("read the NULL blob back");
    let row = nulled.first().expect("the NULL row is visible");
    assert!(
        row.get::<Vec<u8>>("payload").is_none(),
        "a NULL blob reads back as no bytes, not as empty or garbage"
    );

    db.execute(&Statement::new("DELETE FROM blob_round_trip_probe"))
        .await
        .expect("clean probe");
}

/// One MiB, the unit the large-object contract is written in.
const MIB: usize = 1024 * 1024;

/// The chunk size the contract streams a body in: small enough that the
/// 12 MiB probe arrives in many chunks, not one.
const CHUNK: usize = 64 * 1024;

/// The declared ceiling the contract gives its [`ScopedBlob`]: 16 MiB,
/// above the 12 MiB probe and below the 20 MiB refusal probe.
const CEILING: u64 = 16 * 1024 * 1024;

/// The content type the probe objects are stored with.
const CONTENT_TYPE: &str = "application/octet-stream";

/// Proves `blob` satisfies the large-object half of the [`Blob`] port
/// (issue #586): streamed puts and gets for an object past
/// [`MAX_BLOB_BYTES`](cratefield_core::MAX_BLOB_BYTES), the declared
/// ceiling enforced mid-stream, multipart uploads that assemble in part
/// order, abort leaving nothing behind, the bad-key rules, and a listing
/// that never surfaces another module's keys.
///
/// Wraps `blob` in a [`ScopedBlob`] for module `large_probe` with a 16 MiB
/// declared ceiling, so the probe also exercises the scoping and the
/// ceiling the harness applies. Objects it creates are removed before it
/// returns; run it against a store a test can leave empty, or accept that
/// it writes under `large_probe/` and `other_probe/`.
///
/// # Panics
///
/// Panics with a message naming the violated expectation when the store
/// does not honour the contract.
pub async fn assert_blob_large_round_trips(blob: Arc<dyn Blob>) {
    let scoped = ScopedBlob::new(Arc::clone(&blob), "large_probe").with_max_object_bytes(CEILING);

    check_streamed_round_trip(&scoped).await;
    check_ceiling_refusal(&scoped).await;
    check_multipart(&scoped).await;
    check_complete_ceiling(&scoped).await;
    check_abort(&scoped).await;
    check_bad_keys(&scoped).await;
    check_listing(&blob).await;

    for key in ["clip.bin", "movie.bin", "huge.bin"] {
        scoped
            .delete(key)
            .await
            .expect("the contract removes the objects it created");
    }
}

/// A streamed object larger than `MAX_BLOB_BYTES` round-trips exactly, and
/// `head` reports its size and content type without reading the body.
async fn check_streamed_round_trip(scoped: &ScopedBlob) {
    let payload = pattern(12 * MIB, 7);
    let written = scoped
        .put_stream(
            "clip.bin",
            body_stream(&payload, CHUNK),
            CONTENT_TYPE,
            (12 * MIB) as u64,
        )
        .await
        .expect("a 12 MiB streamed put is under the 16 MiB declared ceiling");
    assert_eq!(
        written,
        payload.len() as u64,
        "put_stream reports the bytes it wrote"
    );

    let stream = scoped
        .get_stream("clip.bin")
        .await
        .expect("get_stream succeeds")
        .expect("the object is present");
    assert_eq!(
        stream.size,
        payload.len() as u64,
        "the streamed size matches"
    );
    assert_eq!(
        stream.content_type, CONTENT_TYPE,
        "the streamed content type matches"
    );
    assert_eq!(
        read_all(stream.body).await,
        payload,
        "the streamed bytes round trip exactly"
    );

    let meta = scoped
        .head("clip.bin")
        .await
        .expect("head succeeds")
        .expect("the object is present");
    assert_eq!(meta.key, "clip.bin", "head reports the module-relative key");
    assert_eq!(meta.size, payload.len() as u64, "head reports the size");
    assert_eq!(
        meta.content_type, CONTENT_TYPE,
        "head reports the content type"
    );
}

/// A put past the declared ceiling is refused mid-stream and leaves no
/// object; so is one past the caller's own `max_bytes`.
async fn check_ceiling_refusal(scoped: &ScopedBlob) {
    let oversized = pattern(20 * MIB, 1);
    let err = scoped
        .put_stream(
            "too-big.bin",
            body_stream(&oversized, CHUNK),
            CONTENT_TYPE,
            (20 * MIB) as u64,
        )
        .await
        .expect_err("20 MiB is over the 16 MiB declared ceiling");
    assert!(
        matches!(err, BlobError::TooLarge(_)),
        "the ceiling breach is TooLarge, got {err:?}"
    );
    assert!(
        scoped.head("too-big.bin").await.expect("head").is_none(),
        "a refused streamed put leaves no object behind"
    );

    let payload = pattern(12 * MIB, 2);
    let err = scoped
        .put_stream(
            "capped.bin",
            body_stream(&payload, CHUNK),
            CONTENT_TYPE,
            1024,
        )
        .await
        .expect_err("a raw max_bytes below the stream is refused");
    assert!(
        matches!(err, BlobError::TooLarge(_)),
        "the raw cap is TooLarge, got {err:?}"
    );
    assert!(
        scoped.head("capped.bin").await.expect("head").is_none(),
        "the raw cap leaves no object behind"
    );
}

/// Parts uploaded out of order assemble in part-number order, min part
/// size included.
async fn check_multipart(scoped: &ScopedBlob) {
    let part1 = pattern(5 * MIB, 11);
    let part2 = pattern(5 * MIB, 22);
    let part3 = pattern(MIB, 33);

    let upload = scoped
        .create_multipart("movie.bin", "video/mp4")
        .await
        .expect("create_multipart");
    let receipt2 = scoped
        .upload_part(
            "movie.bin",
            &upload,
            2,
            body_stream(&part2, CHUNK),
            (5 * MIB) as u64,
        )
        .await
        .expect("part 2");
    let receipt1 = scoped
        .upload_part(
            "movie.bin",
            &upload,
            1,
            body_stream(&part1, CHUNK),
            (5 * MIB) as u64,
        )
        .await
        .expect("part 1");
    let receipt3 = scoped
        .upload_part(
            "movie.bin",
            &upload,
            3,
            body_stream(&part3, CHUNK),
            (5 * MIB) as u64,
        )
        .await
        .expect("part 3");
    assert_eq!(
        (
            receipt1.part_number,
            receipt2.part_number,
            receipt3.part_number
        ),
        (1, 2, 3),
        "each receipt carries the part number it was uploaded as"
    );

    scoped
        .complete_multipart("movie.bin", &upload, &[receipt1, receipt2, receipt3])
        .await
        .expect("complete_multipart");

    let mut expected = part1.clone();
    expected.extend_from_slice(&part2);
    expected.extend_from_slice(&part3);
    let stream = scoped
        .get_stream("movie.bin")
        .await
        .expect("get_stream")
        .expect("the assembled object is present");
    assert_eq!(
        read_all(stream.body).await,
        expected,
        "parts assemble in part-number order"
    );
}

/// A completed object larger than the declared ceiling is refused and
/// removed, even though every part was itself under the ceiling — the
/// assembled size is only known at completion.
async fn check_complete_ceiling(scoped: &ScopedBlob) {
    let upload = scoped
        .create_multipart("huge.bin", CONTENT_TYPE)
        .await
        .expect("create_multipart");
    let mut receipts = Vec::new();
    for number in 1..=4u16 {
        let part = pattern(
            5 * MIB,
            u8::try_from(number).expect("a part number below 5 fits a byte"),
        );
        let receipt = scoped
            .upload_part(
                "huge.bin",
                &upload,
                number,
                body_stream(&part, CHUNK),
                (5 * MIB) as u64,
            )
            .await
            .expect("a 5 MiB part is under the 16 MiB ceiling");
        receipts.push(receipt);
    }
    let err = scoped
        .complete_multipart("huge.bin", &upload, &receipts)
        .await
        .expect_err("four 5 MiB parts assemble to 20 MiB, over the 16 MiB ceiling");
    assert!(
        matches!(err, BlobError::TooLarge(_)),
        "the assembled-object breach is TooLarge, got {err:?}"
    );
    assert!(
        scoped.head("huge.bin").await.expect("head").is_none(),
        "a refused completion leaves no object behind"
    );
}

/// Aborting an upload leaves no object and no pending upload.
async fn check_abort(scoped: &ScopedBlob) {
    let upload = scoped
        .create_multipart("draft.bin", CONTENT_TYPE)
        .await
        .expect("create_multipart");
    scoped
        .upload_part("draft.bin", &upload, 1, body_stream(b"partial", 4), CEILING)
        .await
        .expect("upload a part");
    scoped
        .abort_multipart("draft.bin", &upload)
        .await
        .expect("abort_multipart");

    assert!(
        scoped.head("draft.bin").await.expect("head").is_none(),
        "abort leaves no object"
    );
    match scoped.list_multipart_uploads("").await {
        Ok(uploads) => assert!(
            !uploads.iter().any(|pending| pending.upload_id == upload),
            "the aborted upload is gone"
        ),
        // A store without multipart listing is acceptable for this one call.
        Err(BlobError::Unsupported(_)) => {}
        Err(err) => panic!("list_multipart_uploads failed: {err:?}"),
    }
    let page = scoped.list("", None, 100).await.expect("list");
    assert!(
        !page.objects.iter().any(|meta| meta.key == "draft.bin"),
        "abort leaves no listed object"
    );
}

/// Every new method refuses an escaping key; a listing refuses an escaping
/// prefix but allows the empty one.
async fn check_bad_keys(scoped: &ScopedBlob) {
    let receipt = PartReceipt {
        part_number: 1,
        etag: "irrelevant".to_owned(),
    };
    let upload = UploadId::new("missing");
    for bad in ["", "/abs", "../escape"] {
        assert!(
            matches!(
                scoped
                    .put_stream(bad, body_stream(b"x", 1), "text/plain", 16)
                    .await
                    .unwrap_err(),
                BlobError::BadKey(_)
            ),
            "put_stream must refuse `{bad}`"
        );
        assert!(
            matches!(
                scoped.get_stream(bad).await.unwrap_err(),
                BlobError::BadKey(_)
            ),
            "get_stream must refuse `{bad}`"
        );
        assert!(
            matches!(scoped.head(bad).await.unwrap_err(), BlobError::BadKey(_)),
            "head must refuse `{bad}`"
        );
        assert!(
            matches!(
                scoped
                    .create_multipart(bad, "text/plain")
                    .await
                    .unwrap_err(),
                BlobError::BadKey(_)
            ),
            "create_multipart must refuse `{bad}`"
        );
        assert!(
            matches!(
                scoped
                    .upload_part(bad, &upload, 1, body_stream(b"x", 1), 16)
                    .await
                    .unwrap_err(),
                BlobError::BadKey(_)
            ),
            "upload_part must refuse `{bad}`"
        );
        assert!(
            matches!(
                scoped
                    .complete_multipart(bad, &upload, std::slice::from_ref(&receipt))
                    .await
                    .unwrap_err(),
                BlobError::BadKey(_)
            ),
            "complete_multipart must refuse `{bad}`"
        );
        assert!(
            matches!(
                scoped.abort_multipart(bad, &upload).await.unwrap_err(),
                BlobError::BadKey(_)
            ),
            "abort_multipart must refuse `{bad}`"
        );
    }
    for bad in ["/abs", "../escape"] {
        assert!(
            matches!(
                scoped.list(bad, None, 10).await.unwrap_err(),
                BlobError::BadKey(_)
            ),
            "list must refuse prefix `{bad}`"
        );
        assert!(
            matches!(
                scoped.list_multipart_uploads(bad).await.unwrap_err(),
                BlobError::BadKey(_)
            ),
            "list_multipart_uploads must refuse prefix `{bad}`"
        );
    }
}

/// A listing returns only the module's keys, stripped and in order,
/// paginates, and never surfaces another module's object.
async fn check_listing(blob: &Arc<dyn Blob>) {
    let scoped = ScopedBlob::new(Arc::clone(blob), "large_probe");
    let other = ScopedBlob::new(Arc::clone(blob), "other_probe");
    for name in ["list/a.txt", "list/b.txt", "list/c.txt"] {
        scoped
            .put(name, b"x", "text/plain")
            .await
            .expect("seed a listed object");
    }
    other
        .put("list/other.txt", b"x", "text/plain")
        .await
        .expect("seed another module's object");

    let other_page = other.list("list/", None, 100).await.expect("other list");
    assert!(
        other_page
            .objects
            .iter()
            .any(|meta| meta.key == "list/other.txt"),
        "the other module sees its own object"
    );

    let first = scoped.list("list/", None, 2).await.expect("first page");
    let keys: Vec<&str> = first.objects.iter().map(|meta| meta.key.as_str()).collect();
    assert_eq!(
        keys,
        ["list/a.txt", "list/b.txt"],
        "list strips the module prefix and orders keys"
    );
    assert!(first.cursor.is_some(), "more pages remain");

    let second = scoped
        .list("list/", first.cursor.as_deref(), 2)
        .await
        .expect("second page");
    let keys: Vec<&str> = second
        .objects
        .iter()
        .map(|meta| meta.key.as_str())
        .collect();
    assert_eq!(
        keys,
        ["list/c.txt"],
        "the second page continues past the cursor"
    );
    assert!(second.cursor.is_none(), "the last page has no cursor");

    let all = scoped.list("", None, 1000).await.expect("all keys");
    assert!(
        all.objects
            .iter()
            .all(|meta| !meta.key.starts_with("other_probe")),
        "another module's keys never surface"
    );
    assert!(
        all.objects
            .iter()
            .all(|meta| !meta.key.starts_with("large_probe")),
        "returned keys are module-relative"
    );

    scoped.delete("list/a.txt").await.expect("cleanup a");
    scoped.delete("list/b.txt").await.expect("cleanup b");
    scoped.delete("list/c.txt").await.expect("cleanup c");
    other.delete("list/other.txt").await.expect("cleanup other");
}

/// A deterministic probe body: byte `i` is `(i + seed) % 251`, so two
/// different seeds never produce the same bytes and a wrong reassembly is
/// visible.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            u8::try_from((i + usize::from(seed)) % 251).expect("a value below 251 fits a byte")
        })
        .collect()
}

/// Type-erases `bytes` into a body stream of `chunk`-sized chunks.
fn body_stream(bytes: &[u8], chunk: usize) -> BoxStream<'static, Result<Bytes, StreamError>> {
    let chunks: Vec<Result<Bytes, StreamError>> = bytes
        .chunks(chunk)
        .map(|piece| Ok(Bytes::copy_from_slice(piece)))
        .collect();
    Box::pin(Chunks {
        chunks: chunks.into_iter(),
    })
}

/// Reads a body stream to the end, panicking on a mid-stream error.
async fn read_all(mut body: BoxStream<'static, Result<Bytes, StreamError>>) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await {
        out.extend_from_slice(&chunk.expect("the body stream did not fail"));
    }
    out
}

/// A `Stream` over pre-built chunks. Written out because the kit has no
/// `futures-util`.
struct Chunks {
    chunks: std::vec::IntoIter<Result<Bytes, StreamError>>,
}

impl Stream for Chunks {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().chunks.next())
    }
}
