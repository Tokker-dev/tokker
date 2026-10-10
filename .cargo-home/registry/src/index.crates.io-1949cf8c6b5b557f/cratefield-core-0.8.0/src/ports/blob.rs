//! The `Blob` port (issue #105): small media stored outside the database —
//! R2 on Workers, a directory or S3-compatible store when self-hosted.
//!
//! KV caps a value at 25 MB and is the wrong tool for media, and D1 `BLOB`
//! columns are banned by the portable lint, so a coach's voice clip (the
//! request in `yoginini-backend#4`) has nowhere to live. This port gives it
//! one, keyed and content-typed, with the same ownership rule the tables have:
//! a module only ever touches keys under its own `<module>/` prefix, enforced
//! by the [`ScopedBlob`] the harness hands each module.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;

/// Hard ceiling on one stored object (issue #136). The port exists for
/// *small* media — a coach's voice clip, an avatar — and every caller
/// reaches it through [`ScopedBlob`] or an adapter that enforces this
/// bound before allocating or writing. Ten MiB is well past any legit
/// clip at conversational bitrates and far below what threatens a
/// self-hosted process or an isolate that buffers the bytes.
pub const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;

/// The longest presign lifetime a store accepts: seven days, the S3 maximum.
/// [`ScopedBlob`] refuses a longer one before any adapter sees it
/// (issue #622).
pub const MAX_PRESIGN_TTL: Duration = Duration::from_hours(7 * 24);

/// The presign lifetime a caller gets when it does not choose one: one hour —
/// long enough for a browser to fetch or upload, short enough that a leaked
/// URL ages out (issue #622).
pub const DEFAULT_PRESIGN_TTL: Duration = Duration::from_hours(1);

/// Rejects a presign lifetime outside `1 s ..= MAX_PRESIGN_TTL` before any
/// store sees it (issue #622): a sub-second TTL truncates to `X-Amz-Expires=0`
/// — an already-dead URL — and [`BlobError`] is not `#[non_exhaustive]`, so
/// this reuses [`BlobError::Operation`] rather than adding a variant.
fn check_presign_ttl(ttl: Duration) -> Result<(), BlobError> {
    if ttl < Duration::from_secs(1) || ttl > MAX_PRESIGN_TTL {
        return Err(BlobError::Operation(format!(
            "presign ttl must be between 1 and {} seconds, got {}",
            MAX_PRESIGN_TTL.as_secs(),
            ttl.as_secs(),
        )));
    }
    Ok(())
}

/// Rejects a write whose payload exceeds [`MAX_BLOB_BYTES`] (issue #136).
/// Every [`Blob::put`] implementation MUST call this before touching
/// storage; [`ScopedBlob`] (the module-facing wrapper) already does, so
/// an adapter's own call is the second, defence-in-depth gate for
/// runtimes-wired stores and direct users.
///
/// # Errors
///
/// [`BlobError::TooLarge`] when `bytes.len()` exceeds the bound.
pub fn check_blob_size(bytes: &[u8]) -> Result<(), BlobError> {
    if bytes.len() > MAX_BLOB_BYTES {
        return Err(BlobError::TooLarge(format!(
            "blob of {} bytes exceeds the {MAX_BLOB_BYTES}-byte bound",
            bytes.len()
        )));
    }
    Ok(())
}

/// A stored object: its bytes and the content type to serve it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobObject {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// Blob store failures.
#[derive(Debug, Clone, Error)]
pub enum BlobError {
    /// The store rejected or could not complete the operation.
    #[error("blob operation failed: {0}")]
    Operation(String),
    /// The key is empty, absolute, or tries to escape its prefix (`..`).
    #[error("invalid blob key: {0}")]
    BadKey(String),
    /// The object is bigger than [`MAX_BLOB_BYTES`] (issue #136).
    #[error("blob rejected by size: {0}")]
    TooLarge(String),
    /// The adapter does not support this operation (e.g. a directory store has
    /// no presigned URLs).
    #[error("blob operation not supported: {0}")]
    Unsupported(String),
}

/// A presigned upload: the URL to `PUT` to, the method, and the headers the
/// client must send **exactly** — the signature covers each signed header, so
/// a different value is refused by the store (issue #622).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedPut {
    /// The `https://…` URL, query string and all. A bearer credential until
    /// it expires: never log it.
    pub url: String,
    /// Always `"PUT"`; carried so a caller need not hard-code it.
    pub method: &'static str,
    /// Headers the client must send with exactly these values (e.g.
    /// `Content-Type`, `Content-Length`).
    pub headers: Vec<(String, String)>,
}

/// A blob store. Keys are module-prefixed; the harness wraps this in a
/// [`ScopedBlob`] per module so a module cannot name another's objects.
#[async_trait]
pub trait Blob: Send + Sync {
    /// Stores `bytes` at `key` with `content_type`, replacing any existing
    /// object. Implementations MUST reject a payload larger than
    /// [`MAX_BLOB_BYTES`] with [`BlobError::TooLarge`] via
    /// [`check_blob_size`], before writing (issue #136).
    async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError>;
    /// Fetches the object at `key`, or `None` if there is none.
    async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError>;
    /// Removes the object at `key`. Idempotent: removing a missing key is `Ok`.
    async fn delete(&self, key: &str) -> Result<(), BlobError>;
    /// A presigned `GET` for `key`, valid for `ttl`: a URL that serves the
    /// object directly, skipping the Worker. Adapters without presigned URLs
    /// (a directory store) return [`BlobError::Unsupported`]; callers then
    /// serve the bytes through [`get`](Blob::get). The URL's query string is
    /// a bearer credential: never log it.
    async fn signed_url(&self, key: &str, ttl: Duration) -> Result<String, BlobError>;
    /// A presigned `PUT` for `key` with `content_type`, valid for `ttl`.
    ///
    /// The signature cannot cover the body, but when `content_length` is
    /// `Some` adapters sign `Content-Length` for that value, so a store that
    /// honours it rejects any other size. The returned [`PresignedPut`] names
    /// the headers the client must send exactly. Adapters without presigned
    /// URLs return [`BlobError::Unsupported`] (the default). The URL's query
    /// string is a bearer credential: never log it.
    async fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: Duration,
    ) -> Result<PresignedPut, BlobError> {
        let _ = (key, content_type, content_length, ttl);
        Err(BlobError::Unsupported(
            "this blob store has no presigned uploads".to_owned(),
        ))
    }
}

/// Wraps a [`Blob`] so every key is prefixed with `<module>/` and no key can
/// escape it. The harness applies this in `Ports::view_for`, so a module sees a
/// store scoped to itself — the blob equivalent of the table-ownership check.
pub struct ScopedBlob {
    inner: Arc<dyn Blob>,
    prefix: String,
}

impl ScopedBlob {
    /// Scopes `inner` to `<module>/`.
    #[must_use]
    pub fn new(inner: Arc<dyn Blob>, module: &str) -> Self {
        Self {
            inner,
            prefix: format!("{module}/"),
        }
    }

    /// Prefixes a caller key, refusing one that is empty, absolute, or walks
    /// out of the prefix with `..`.
    fn scope(&self, key: &str) -> Result<String, BlobError> {
        if key.is_empty() {
            return Err(BlobError::BadKey("a blob key cannot be empty".to_owned()));
        }
        if key.starts_with('/') {
            return Err(BlobError::BadKey(format!("key `{key}` must be relative")));
        }
        if key
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
        {
            return Err(BlobError::BadKey(format!(
                "key `{key}` must not contain `.` or `..` segments"
            )));
        }
        Ok(format!("{}{key}", self.prefix))
    }
}

#[async_trait]
impl Blob for ScopedBlob {
    async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError> {
        check_blob_size(bytes)?;
        self.inner.put(&self.scope(key)?, bytes, content_type).await
    }
    async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError> {
        self.inner.get(&self.scope(key)?).await
    }
    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        self.inner.delete(&self.scope(key)?).await
    }
    async fn signed_url(&self, key: &str, ttl: Duration) -> Result<String, BlobError> {
        let key = self.scope(key)?;
        check_presign_ttl(ttl)?;
        self.inner.signed_url(&key, ttl).await
    }
    async fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: Duration,
    ) -> Result<PresignedPut, BlobError> {
        let key = self.scope(key)?;
        check_presign_ttl(ttl)?;
        self.inner
            .signed_put_url(&key, content_type, content_length, ttl)
            .await
    }
}

#[cfg(test)]
mod tests {
    // A recording test fixture, not request state (ADR 0007). The scoped
    // allow follows the policy in the workspace clippy.toml, as the fakes
    // in `cratefield-testing` and the sibling tests in this crate do.
    #![allow(clippy::disallowed_types)]

    use super::*;
    use std::sync::Mutex;

    /// An in-memory blob store for testing the scoping.
    #[derive(Default)]
    struct MemBlob {
        objects: Mutex<std::collections::HashMap<String, BlobObject>>,
        /// The keys the presign methods were reached with, so a test can prove
        /// a refused call never arrived.
        presigned: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Blob for MemBlob {
        async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError> {
            self.objects.lock().unwrap().insert(
                key.to_owned(),
                BlobObject {
                    bytes: bytes.to_vec(),
                    content_type: content_type.to_owned(),
                },
            );
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError> {
            Ok(self.objects.lock().unwrap().get(key).cloned())
        }
        async fn delete(&self, key: &str) -> Result<(), BlobError> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }
        async fn signed_url(&self, key: &str, _ttl: Duration) -> Result<String, BlobError> {
            self.presigned.lock().unwrap().push(key.to_owned());
            Ok(format!("mem://{key}"))
        }
        async fn signed_put_url(
            &self,
            key: &str,
            content_type: &str,
            _content_length: Option<u64>,
            _ttl: Duration,
        ) -> Result<PresignedPut, BlobError> {
            self.presigned.lock().unwrap().push(key.to_owned());
            Ok(PresignedPut {
                url: format!("mem://{key}"),
                method: "PUT",
                headers: vec![("content-type".to_owned(), content_type.to_owned())],
            })
        }
    }

    /// Implements only the required [`Blob`] methods, so the provided
    /// [`Blob::signed_put_url`] default is what a test exercises.
    struct BareBlob;

    #[async_trait]
    impl Blob for BareBlob {
        async fn put(
            &self,
            _key: &str,
            _bytes: &[u8],
            _content_type: &str,
        ) -> Result<(), BlobError> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> Result<Option<BlobObject>, BlobError> {
            Ok(None)
        }
        async fn delete(&self, _key: &str) -> Result<(), BlobError> {
            Ok(())
        }
        async fn signed_url(&self, _key: &str, _ttl: Duration) -> Result<String, BlobError> {
            Err(BlobError::Unsupported("memory store".to_owned()))
        }
    }

    #[pollster::test]
    async fn a_scoped_blob_prefixes_the_key() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "waitlist");
        scoped.put("clip.mp3", b"x", "audio/mpeg").await.unwrap();
        // The underlying store sees the prefixed key.
        assert!(mem.get("waitlist/clip.mp3").await.unwrap().is_some());
        assert!(mem.get("clip.mp3").await.unwrap().is_none());
        // And the scoped view reads it back by the bare key.
        assert!(scoped.get("clip.mp3").await.unwrap().is_some());
    }

    #[pollster::test]
    async fn a_scoped_blob_refuses_an_escaping_key() {
        let scoped = ScopedBlob::new(Arc::new(MemBlob::default()), "cms");
        for bad in ["", "/etc/passwd", "../secrets/x", "a/../../b", "."] {
            assert!(
                matches!(scoped.get(bad).await.unwrap_err(), BlobError::BadKey(_)),
                "key `{bad}` should be refused"
            );
        }
    }

    #[pollster::test]
    async fn delete_is_idempotent() {
        let scoped = ScopedBlob::new(Arc::new(MemBlob::default()), "cms");
        scoped.delete("missing").await.expect("no-op delete is ok");
    }

    #[pollster::test]
    async fn an_oversized_put_is_refused_before_the_store_is_reached() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms");
        let oversized = vec![0_u8; MAX_BLOB_BYTES + 1];
        let err = scoped
            .put("big.bin", &oversized, "application/octet-stream")
            .await
            .expect_err("one byte past the bound must be refused");
        assert!(matches!(err, BlobError::TooLarge(_)), "got {err}");
        assert!(
            mem.get("cms/big.bin").await.unwrap().is_none(),
            "the store never saw the rejected key"
        );
    }

    #[pollster::test]
    async fn a_put_at_exactly_the_bound_is_accepted() {
        let scoped = ScopedBlob::new(Arc::new(MemBlob::default()), "cms");
        let exact = vec![0_u8; MAX_BLOB_BYTES];
        scoped
            .put("edge.bin", &exact, "application/octet-stream")
            .await
            .expect("the bound itself is allowed");
    }

    #[pollster::test]
    async fn a_scoped_blob_prefixes_both_presign_keys() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms");
        let get = scoped
            .signed_url("clip.mp3", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(get, "mem://cms/clip.mp3");
        let put = scoped
            .signed_put_url("clip.mp3", "audio/mpeg", Some(3), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(put.url, "mem://cms/clip.mp3");
        assert_eq!(
            *mem.presigned.lock().unwrap(),
            vec!["cms/clip.mp3".to_owned(), "cms/clip.mp3".to_owned()],
        );
    }

    #[pollster::test]
    async fn a_scoped_blob_refuses_an_escaping_presign_key_before_the_store() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms");
        for bad in ["", "/etc/passwd", "../secrets/x"] {
            assert!(
                matches!(
                    scoped
                        .signed_url(bad, Duration::from_secs(60))
                        .await
                        .unwrap_err(),
                    BlobError::BadKey(_)
                ),
                "key `{bad}` should be refused"
            );
            assert!(
                matches!(
                    scoped
                        .signed_put_url(bad, "image/png", None, Duration::from_secs(60))
                        .await
                        .unwrap_err(),
                    BlobError::BadKey(_)
                ),
                "key `{bad}` should be refused"
            );
        }
        assert!(
            mem.presigned.lock().unwrap().is_empty(),
            "the store never saw a key"
        );
    }

    #[pollster::test]
    async fn a_scoped_blob_refuses_a_presign_ttl_outside_the_bound() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms");
        for bad in [
            // A sub-second TTL truncates to `X-Amz-Expires=0`, so it is
            // refused alongside zero and over-long ones.
            Duration::from_millis(500),
            Duration::ZERO,
            MAX_PRESIGN_TTL + Duration::from_secs(1),
        ] {
            assert!(
                matches!(
                    scoped.signed_url("clip.mp3", bad).await.unwrap_err(),
                    BlobError::Operation(_)
                ),
                "ttl {bad:?} should be refused"
            );
        }
        // The bound itself is allowed, and the store is reached.
        scoped
            .signed_url("clip.mp3", MAX_PRESIGN_TTL)
            .await
            .unwrap();
        assert_eq!(mem.presigned.lock().unwrap().len(), 1);
    }

    #[pollster::test]
    async fn the_default_signed_put_url_is_unsupported() {
        let scoped = ScopedBlob::new(Arc::new(BareBlob), "cms");
        assert!(matches!(
            scoped
                .signed_put_url("clip.mp3", "audio/mpeg", None, Duration::from_secs(60))
                .await
                .unwrap_err(),
            BlobError::Unsupported(_)
        ));
    }
}
