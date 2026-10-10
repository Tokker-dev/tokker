//! Fake ports for module tests (issue #9). All fakes are `Clone` handles
//! over shared interiors so they can be wired into `Ports` and still be
//! asserted on from the test.
//!
//! Interior mutability here records test observations; it is not request
//! state (ADR 0007) — the scoped `Mutex` allow follows the policy in the
//! workspace `clippy.toml`.

#![allow(clippy::disallowed_types)]
// Every accessor locks an unpoisoned fixture mutex; per-method `# Panics`
// sections would add noise without information.
#![allow(clippy::missing_panics_doc)]

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::sigv4::{self, Credentials, SigV4Error, SignableRequest};
use cratefield_core::{
    ActorError, ActorHandlers, ActorStore, ActorWrites, Actors, Answer, AnswerValue, Calibration,
    Capability, Captcha, CaptchaError, CertificateStatus, Classifier, ClassifierError,
    ClassifierProfile, Clock, Completion, Credential, CustomHostname, CustomHostnameError,
    CustomHostnames, Database, DbError, Decision, Defer, Destination, DnsRecordType, Filed,
    HostnameClaim, HttpClient, HttpError, KeyValue, KvError, MailError, Mailer, Message, ModelTier,
    Prompt, ProviderStatus, Question, RateLimitError, RateLimiter, Row, Rows, SendOutcome,
    Statement, TextModel, TextModelError, TicketComment, TicketDraft, TicketState, TicketStatus,
    Tracker, TrackerError, Validation, Verdict, check_hostname, run_actor_alarm, run_actor_message,
    validate_questions,
};
use futures_core::Stream;
use futures_core::future::BoxFuture;
use http::header::{CONTENT_TYPE, RETRY_AFTER};
use http::{HeaderValue, Request, Response, StatusCode};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

// Recording fixtures, not request state (see module docs).
#[allow(clippy::disallowed_types)]
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// FakeMailer

/// How a [`FakeMailer`] answers.
///
/// [`Error`](Self::Error) is what makes the failure arms testable at all
/// (issue #236): before it the fake could only ever produce
/// `MailError::Upstream("fake mailer failure")`, so `Invalid { detail }`
/// and `DomainNotVerified { domain }` — the two variants that carry the
/// provider's own text, and therefore the two that can carry a recipient
/// address — could not be driven from a test. Every arm of a caller's
/// outcome mapping is now reachable, with the text the caller chooses:
///
/// ```
/// # use cratefield_testing::{FakeMailer, MailerMode};
/// # use cratefield_core::MailError;
/// let mailer = FakeMailer::new(MailerMode::Error(MailError::Invalid {
///     detail: "to: alice@example.test is suppressed".to_owned(),
/// }));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailerMode {
    /// Accept and record the message.
    SendOk,
    /// Report that the adapter has no API key or no verified domain.
    NotConfigured,
    /// A generic upstream failure, for a caller that does not care which.
    Fail,
    /// Exactly this error, text and all.
    Error(MailError),
}

#[derive(Clone)]
pub struct FakeMailer {
    inner: Arc<FakeMailerInner>,
}

struct FakeMailerInner {
    mode: Mutex<MailerMode>,
    sent: Mutex<Vec<Message>>,
}

impl FakeMailer {
    #[must_use]
    pub fn new(mode: MailerMode) -> Self {
        Self {
            inner: Arc::new(FakeMailerInner {
                mode: Mutex::new(mode),
                sent: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Every message recorded so far.
    #[must_use]
    pub fn sent(&self) -> Vec<Message> {
        self.inner.sent.lock().expect("mailer lock").clone()
    }

    /// The most recent message.
    #[must_use]
    pub fn last_message(&self) -> Option<Message> {
        self.inner.sent.lock().expect("mailer lock").last().cloned()
    }

    /// Switches the mode (e.g. degrade to `NotConfigured` mid-test).
    pub fn set_mode(&self, mode: MailerMode) {
        *self.inner.mode.lock().expect("mailer lock") = mode;
    }
}

#[async_trait]
impl Mailer for FakeMailer {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError> {
        let mode = self.inner.mode.lock().expect("mailer lock").clone();
        match mode {
            MailerMode::SendOk => {
                let id = format!(
                    "fake-{}",
                    self.inner.sent.lock().expect("mailer lock").len()
                );
                self.inner.sent.lock().expect("mailer lock").push(message);
                Ok(SendOutcome::Sent { id })
            }
            MailerMode::NotConfigured => Ok(SendOutcome::NotConfigured),
            MailerMode::Fail => Err(MailError::Upstream("fake mailer failure".to_string())),
            MailerMode::Error(error) => Err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// FakeCaptcha

#[derive(Clone)]
pub struct FakeCaptcha {
    allow_all: bool,
    allowed_tokens: Arc<Vec<String>>,
}

impl FakeCaptcha {
    /// Every token verifies.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            allow_all: true,
            allowed_tokens: Arc::new(Vec::new()),
        }
    }

    /// Only the listed tokens verify.
    #[must_use]
    pub fn with_tokens(tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allow_all: false,
            allowed_tokens: Arc::new(tokens.into_iter().map(Into::into).collect()),
        }
    }
}

#[async_trait]
impl Captcha for FakeCaptcha {
    async fn verify(&self, token: &str, _remote_ip: Option<&str>) -> Result<Verdict, CaptchaError> {
        let ok = self.allow_all || self.allowed_tokens.iter().any(|t| t == token);
        Ok(Verdict {
            ok,
            reason: (!ok).then(|| "token not allowed".to_string()),
        })
    }

    fn binding(&self) -> Option<cratefield_core::CaptchaBinding> {
        Some(cratefield_core::CaptchaBinding {
            hostname_bound: true,
            action_bound: true,
            fail_open: false,
        })
    }
}

// ---------------------------------------------------------------------------
// FakeRateLimiter (scripted)

#[derive(Clone)]
pub struct FakeRateLimiter {
    inner: Arc<FakeRateLimiterInner>,
}

struct FakeRateLimiterInner {
    scripted: Mutex<VecDeque<Decision>>,
    default: Decision,
    calls: AtomicUsize,
}

impl FakeRateLimiter {
    /// Falls through to `default` once the script is exhausted.
    #[must_use]
    pub fn scripted(decisions: Vec<Decision>, default: Decision) -> Self {
        Self {
            inner: Arc::new(FakeRateLimiterInner {
                scripted: Mutex::new(decisions.into_iter().collect()),
                default,
                calls: AtomicUsize::new(0),
            }),
        }
    }

    /// Always allows.
    #[must_use]
    pub fn always_allow() -> Self {
        Self::scripted(
            Vec::new(),
            Decision {
                ok: true,
                retry_after: None,
                quota: None,
            },
        )
    }

    #[must_use]
    pub fn calls(&self) -> usize {
        self.inner.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RateLimiter for FakeRateLimiter {
    async fn limit(&self, _key: &str) -> Result<Decision, RateLimitError> {
        self.inner.calls.fetch_add(1, Ordering::SeqCst);
        let scripted = self
            .inner
            .scripted
            .lock()
            .expect("limiter lock")
            .pop_front();
        Ok(scripted.unwrap_or_else(|| self.inner.default.clone()))
    }
}

// ---------------------------------------------------------------------------
// FixedClock

#[derive(Debug, Clone)]
pub struct FixedClock(pub time::OffsetDateTime);

#[async_trait]
impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

// ---------------------------------------------------------------------------
// ManualClock

/// A [`Clock`] a test moves by hand (issue #583), for a fake whose behaviour
/// depends on time — [`MemoryActors`] fires an alarm once the clock reaches
/// it. Every clone shares the one instant, so the host and the test that
/// advances it never diverge.
#[derive(Debug, Clone)]
pub struct ManualClock {
    at: Arc<Mutex<time::OffsetDateTime>>,
}

impl ManualClock {
    /// A clock stopped at `at`.
    #[must_use]
    pub fn new(at: time::OffsetDateTime) -> Self {
        Self {
            at: Arc::new(Mutex::new(at)),
        }
    }

    /// Moves the clock forward by `by`. Panics if `by` is too large for
    /// `time`'s `Duration`.
    pub fn advance(&self, by: Duration) {
        let span = time::Duration::try_from(by).expect("a representable span");
        *self.at.lock().expect("clock lock") += span;
    }
}

#[async_trait]
impl Clock for ManualClock {
    fn now(&self) -> time::OffsetDateTime {
        *self.at.lock().expect("clock lock")
    }
}

// ---------------------------------------------------------------------------
// MemoryKeyValue

#[derive(Clone, Default)]
pub struct MemoryKeyValue {
    inner: Arc<MemoryKeyValueInner>,
}

#[derive(Default)]
struct MemoryKeyValueInner {
    entries: Mutex<HashMap<String, String>>,
}

impl MemoryKeyValue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyValue for MemoryKeyValue {
    async fn get(&self, key: &str) -> Result<Option<String>, KvError> {
        Ok(self
            .inner
            .entries
            .lock()
            .expect("kv lock")
            .get(key)
            .cloned())
    }

    async fn put(&self, key: &str, value: &str, _ttl: Option<Duration>) -> Result<(), KvError> {
        self.inner
            .entries
            .lock()
            .expect("kv lock")
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.inner.entries.lock().expect("kv lock").remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FakeHttpClient (scripted responses, captures requests)

#[derive(Clone)]
pub struct FakeHttpClient {
    inner: Arc<FakeHttpInner>,
}

struct FakeHttpInner {
    responses: Mutex<VecDeque<Result<Response<Bytes>, HttpError>>>,
    captured: Mutex<Vec<(String, String, String)>>, // method, uri, body
}

impl FakeHttpClient {
    /// Responds with `responses` in order, then always with a 500.
    #[must_use]
    pub fn scripted(responses: Vec<Result<Response<Bytes>, HttpError>>) -> Self {
        Self {
            inner: Arc::new(FakeHttpInner {
                responses: Mutex::new(responses.into_iter().collect()),
                captured: Mutex::new(Vec::new()),
            }),
        }
    }

    #[must_use]
    pub fn ok_json(body: &'static str) -> Self {
        Self::scripted(vec![
            Response::builder()
                .status(200)
                .body(Bytes::from(body))
                .map_err(|err| HttpError::Transport(err.to_string())),
        ])
    }

    /// One Owlpost-shaped `application/problem+json` error (issue #666).
    #[must_use]
    pub fn owlpost_problem(status: StatusCode, title: &str, detail: &str) -> Self {
        Self::scripted(vec![Ok(problem_json(status, title, detail))])
    }

    /// Owlpost's 429: a problem body carrying `Retry-After: <secs>`, which
    /// the adapter maps to `MailError::RateLimited` with that delay.
    #[must_use]
    pub fn owlpost_rate_limited(retry_after_secs: u64) -> Self {
        Self::scripted(vec![Ok(with_retry_after(
            problem_json(
                StatusCode::TOO_MANY_REQUESTS,
                "Too Many Requests",
                "slow down",
            ),
            retry_after_secs,
        ))])
    }

    /// One Colonizer-shaped error: `{"error": message}`.
    #[must_use]
    pub fn colonizer_error(status: StatusCode, message: &str) -> Self {
        Self::scripted(vec![Ok(error_json(status, message))])
    }

    /// Colonizer's 429: an `{"error": …}` body carrying `Retry-After`.
    #[must_use]
    pub fn colonizer_rate_limited(retry_after_secs: u64) -> Self {
        Self::scripted(vec![Ok(with_retry_after(
            error_json(StatusCode::TOO_MANY_REQUESTS, "rate limited"),
            retry_after_secs,
        ))])
    }

    /// Every captured request as `(method, uri, body)`.
    #[must_use]
    pub fn captured(&self) -> Vec<(String, String, String)> {
        self.inner.captured.lock().expect("http lock").clone()
    }
}

/// An RFC 9457 `application/problem+json` response — the shape Owlpost
/// answers errors with: `type`, `title`, `status` and `detail`, the
/// `status` both the HTTP status and the body's own field. Build one for
/// a [`scripted`](FakeHttpClient::scripted) sequence, or take it from a
/// preset like [`FakeHttpClient::owlpost_problem`].
#[must_use]
pub fn problem_json(status: StatusCode, title: &str, detail: &str) -> Response<Bytes> {
    let body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
    })
    .to_string();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/problem+json")
        .body(Bytes::from(body))
        .expect("a problem+json response builds")
}

/// A Colonizer-shaped error body, `{"error": message}` under
/// `application/json`.
#[must_use]
pub fn error_json(status: StatusCode, message: &str) -> Response<Bytes> {
    let body = serde_json::json!({ "error": message }).to_string();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Bytes::from(body))
        .expect("an error response builds")
}

/// Adds `Retry-After: <retry_after_secs>` to a response in seconds — the
/// header a 429 carries and the adapters read as a retry hint.
#[must_use]
pub fn with_retry_after(mut response: Response<Bytes>, retry_after_secs: u64) -> Response<Bytes> {
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(retry_after_secs));
    response
}

#[async_trait]
impl HttpClient for FakeHttpClient {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        self.inner.captured.lock().expect("http lock").push((
            parts.method.to_string(),
            parts.uri.to_string(),
            String::from_utf8_lossy(&body).to_string(),
        ));
        let next = self.inner.responses.lock().expect("http lock").pop_front();
        next.unwrap_or_else(|| Err(HttpError::Transport("fake http exhausted".to_string())))
    }
}

// ---------------------------------------------------------------------------
// FakeDefer (collects futures; drain runs them)

#[derive(Clone, Default)]
pub struct FakeDefer {
    inner: Arc<FakeDeferInner>,
}

#[derive(Default)]
struct FakeDeferInner {
    pending: Mutex<Vec<BoxFuture<'static, ()>>>,
    deferred: AtomicUsize,
}

impl FakeDefer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs every deferred future to completion, in deferral order.
    // Async for API symmetry with `drain().await` call sites (the futures
    // run on a sync block-on inside).
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn drain(&self) {
        while !self.inner.pending.lock().expect("defer lock").is_empty() {
            let next = self.inner.pending.lock().expect("defer lock").remove(0);
            pollster::block_on(next);
        }
    }

    #[must_use]
    pub fn deferred_count(&self) -> usize {
        self.inner.deferred.load(Ordering::SeqCst)
    }
}

impl Defer for FakeDefer {
    fn wait_until(&self, fut: BoxFuture<'static, ()>) {
        self.inner.deferred.fetch_add(1, Ordering::SeqCst);
        self.inner.pending.lock().expect("defer lock").push(fut);
    }
}

// ---------------------------------------------------------------------------
// Transparent Database passthrough (re-exported for tests that need a
// trivial Database without SQLite): an always-empty database.

#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyDatabase;

#[async_trait]
impl Database for EmptyDatabase {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        Err(DbError::Execute(format!("empty database: {}", stmt.sql)))
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        if stmt.sql.trim() == "SELECT 1" {
            Ok(Rows::new(vec![Row::new(vec![(
                "1".to_string(),
                sea_query::Value::Int(Some(1)),
            )])]))
        } else {
            Err(DbError::Query(format!("empty database: {}", stmt.sql)))
        }
    }

    async fn batch_atomic(&self, _stmts: &[Statement]) -> Result<(), DbError> {
        Err(DbError::Batch("empty database".to_string()))
    }
}

/// An in-process [`Dispatcher`](cratefield_core::Dispatcher) that answers from an
/// axum [`Router`](axum::Router), so a
/// module can be exercised through a sidecar mount without a network or a
/// second Worker (ADR 0009). The conformance kit uses it to run the same
/// assertions against both mounts (#64).
///
/// Also the failure fixture: [`unbound`](FakeDispatcher::unbound) has no
/// binding at all, and [`failing`](FakeDispatcher::failing) accepts the
/// binding and then refuses to answer.
#[derive(Clone)]
pub struct FakeDispatcher {
    binding: String,
    behaviour: FakeDispatch,
    calls: Arc<AtomicUsize>,
}

#[derive(Clone)]
enum FakeDispatch {
    Serve(Arc<Mutex<axum::Router>>),
    Unbound,
    Failing(String),
}

impl FakeDispatcher {
    /// Serves `router` on `binding`.
    #[must_use]
    pub fn serving(binding: impl Into<String>, router: axum::Router) -> Self {
        Self {
            binding: binding.into(),
            behaviour: FakeDispatch::Serve(Arc::new(Mutex::new(router))),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Has no bindings, so `has()` is always false: the "mounted but this
    /// deployment has no such binding" case.
    #[must_use]
    pub fn unbound() -> Self {
        Self {
            binding: String::new(),
            behaviour: FakeDispatch::Unbound,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Accepts `binding` and then fails to answer.
    #[must_use]
    pub fn failing(binding: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            binding: binding.into(),
            behaviour: FakeDispatch::Failing(reason.into()),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// How many dispatches were attempted. A forwarder must not retry, so a
    /// single request must leave this at one.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl cratefield_core::Dispatcher for FakeDispatcher {
    fn has(&self, binding: &str) -> bool {
        !matches!(self.behaviour, FakeDispatch::Unbound) && binding == self.binding
    }

    async fn dispatch(
        &self,
        binding: &str,
        request: Request<Bytes>,
    ) -> Result<Response<Bytes>, cratefield_core::DispatchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.behaviour {
            FakeDispatch::Unbound => {
                Err(cratefield_core::DispatchError::NotBound(binding.to_owned()))
            }
            FakeDispatch::Failing(reason) => Err(cratefield_core::DispatchError::Unavailable {
                binding: binding.to_owned(),
                reason: reason.clone(),
            }),
            FakeDispatch::Serve(router) => {
                let router = router.lock().unwrap().clone();
                let (parts, body) = request.into_parts();
                let request = Request::from_parts(parts, axum::body::Body::from(body));
                let response =
                    tower::ServiceExt::oneshot(router, request)
                        .await
                        .map_err(|err| cratefield_core::DispatchError::Unavailable {
                            binding: binding.to_owned(),
                            reason: err.to_string(),
                        })?;
                let (parts, body) = response.into_parts();
                let bytes = axum::body::to_bytes(body, usize::MAX)
                    .await
                    .map_err(|err| cratefield_core::DispatchError::Unavailable {
                        binding: binding.to_owned(),
                        reason: err.to_string(),
                    })?;
                Ok(Response::from_parts(parts, bytes))
            }
        }
    }
}

/// An in-memory [`cratefield_core::Blob`] store for module tests.
/// [`MemoryBlob::new`] has no presigned URLs (`signed_url` reports
/// `Unsupported`, as a directory store does); [`MemoryBlob::with_presign`] signs
/// real `SigV4` URLs that [`MemoryBlob::verify_presigned`] checks back.
#[derive(Clone, Default)]
pub struct MemoryBlob {
    objects: Arc<std::sync::Mutex<std::collections::HashMap<String, cratefield_core::BlobObject>>>,
    /// Multipart uploads in flight, by upload id (issue #586).
    uploads: Arc<std::sync::Mutex<std::collections::HashMap<String, MemoryUpload>>>,
    /// Hands out upload ids. Shared across clones so two handles never mint
    /// the same id.
    next_upload_id: Arc<AtomicUsize>,
    /// The clock presigning stamps from; `Some` once `with_presign` is called.
    presign_clock: Option<Arc<dyn Clock>>,
}

/// One multipart upload in flight in [`MemoryBlob`] (issue #586): its
/// target key, content type, and the parts uploaded so far, by part
/// number, each with the `ETag` the store handed back.
struct MemoryUpload {
    key: String,
    content_type: String,
    parts: BTreeMap<u16, (String, Vec<u8>)>,
}

/// Consumes a body stream, refusing once it passes `max_bytes`: the chunk
/// that would cross the bound is not delivered, and the caller sees
/// [`cratefield_core::BlobError::TooLarge`] (issue #586). Because nothing
/// is stored until the whole body is in hand, an over-limit write leaves
/// no object behind.
async fn collect_capped(
    mut body: cratefield_core::BoxStream<'static, Result<Bytes, cratefield_core::StreamError>>,
    max_bytes: u64,
) -> Result<(u64, Vec<u8>), cratefield_core::BlobError> {
    let mut written: u64 = 0;
    let mut out = Vec::new();
    while let Some(chunk) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await {
        let chunk = chunk.map_err(cratefield_core::blob_error_from_stream)?;
        written = written.saturating_add(chunk.len() as u64);
        if written > max_bytes {
            return Err(cratefield_core::BlobError::TooLarge(format!(
                "streamed body of {written} bytes passed the {max_bytes}-byte bound"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok((written, out))
}

/// The read side of [`MemoryBlob`]: `bytes` split into a few fixed-size
/// chunks, so a streamed get is genuinely a stream (issue #586).
fn stored_body_stream(
    bytes: &[u8],
) -> cratefield_core::BoxStream<'static, Result<Bytes, cratefield_core::StreamError>> {
    const CHUNK: usize = 1 << 20;
    let chunks: Vec<Result<Bytes, cratefield_core::StreamError>> = bytes
        .chunks(CHUNK)
        .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
        .collect();
    Box::pin(ChunkStream {
        chunks: chunks.into_iter(),
    })
}

/// A `Stream` over pre-built chunks. Written out because the kit has no
/// `futures-util`.
struct ChunkStream {
    chunks: std::vec::IntoIter<Result<Bytes, cratefield_core::StreamError>>,
}

impl Stream for ChunkStream {
    type Item = Result<Bytes, cratefield_core::StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().chunks.next())
    }
}

/// The fixed, obviously fake presigning identity, stable so a test can assert
/// on the URL text. `blob.test` is reserved for documentation (RFC 2606).
const PRESIGN_ACCESS_KEY_ID: &str = "AKIATESTACCESSKEY000000";
const PRESIGN_SECRET_ACCESS_KEY: &str = "memory-blob-presign-test-secret";
const PRESIGN_HOST: &str = "blob.test";

impl MemoryBlob {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Opts the store into presigning: `signed_url` and `signed_put_url` sign
    /// real `SigV4` URLs stamped from `clock`, checked back by
    /// [`verify_presigned`](Self::verify_presigned).
    #[must_use]
    pub fn with_presign(clock: Arc<dyn Clock>) -> Self {
        Self {
            presign_clock: Some(clock),
            ..Self::default()
        }
    }

    /// How many objects are stored, for assertions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.lock().unwrap().len()
    }

    /// Whether the store is empty, for assertions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Signs `method` on `key` (used verbatim as the URL path — keep test keys
    /// URL-safe) with `headers`, or `Unsupported` without `with_presign`.
    fn presign(
        &self,
        method: &str,
        key: &str,
        headers: &[(String, String)],
        ttl: Duration,
    ) -> Result<String, cratefield_core::BlobError> {
        let clock = self
            .presign_clock
            .as_ref()
            .ok_or_else(|| cratefield_core::BlobError::Unsupported("no presigner".to_owned()))?;
        let path = format!("/{key}");
        let request = SignableRequest {
            method,
            host: PRESIGN_HOST,
            path: &path,
            query: &[],
            headers,
        };
        Ok(sigv4::presign(
            &Credentials::new(PRESIGN_ACCESS_KEY_ID, PRESIGN_SECRET_ACCESS_KEY),
            "auto",
            "s3",
            &request,
            ttl.as_secs(),
            clock.now(),
        ))
    }

    /// Verifies a URL this store minted, at its clock's current time, and
    /// returns the key it names.
    ///
    /// # Errors
    ///
    /// As [`sigv4::verify_presigned`](cratefield_core::sigv4::verify_presigned),
    /// or [`SigV4Error::Malformed`] without a clock or a URL path.
    pub fn verify_presigned(
        &self,
        url: &str,
        method: &str,
        headers: &[(String, String)],
    ) -> Result<String, SigV4Error> {
        let clock = self
            .presign_clock
            .as_ref()
            .ok_or_else(|| SigV4Error::Malformed("no presigning clock".to_owned()))?;
        let credentials = Credentials::new(PRESIGN_ACCESS_KEY_ID, PRESIGN_SECRET_ACCESS_KEY);
        sigv4::verify_presigned(
            url,
            method,
            headers,
            &credentials,
            "auto",
            "s3",
            clock.now(),
        )?;
        url.split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map(|(_, path)| path.split(['?', '#']).next().unwrap_or(path).to_owned())
            .ok_or_else(|| SigV4Error::Malformed("not an absolute URL".to_owned()))
    }
}

#[async_trait]
impl cratefield_core::Blob for MemoryBlob {
    async fn put(
        &self,
        key: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<(), cratefield_core::BlobError> {
        cratefield_core::check_blob_size(bytes)?;
        self.objects.lock().unwrap().insert(
            key.to_owned(),
            cratefield_core::BlobObject {
                bytes: bytes.to_vec(),
                content_type: content_type.to_owned(),
            },
        );
        Ok(())
    }
    async fn get(
        &self,
        key: &str,
    ) -> Result<Option<cratefield_core::BlobObject>, cratefield_core::BlobError> {
        Ok(self.objects.lock().unwrap().get(key).cloned())
    }
    async fn delete(&self, key: &str) -> Result<(), cratefield_core::BlobError> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
    async fn signed_url(
        &self,
        key: &str,
        ttl: std::time::Duration,
    ) -> Result<String, cratefield_core::BlobError> {
        self.presign("GET", key, &[], ttl)
    }
    async fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: std::time::Duration,
    ) -> Result<cratefield_core::PresignedPut, cratefield_core::BlobError> {
        let mut headers = vec![("content-type".to_owned(), content_type.to_owned())];
        if let Some(length) = content_length {
            headers.push(("content-length".to_owned(), length.to_string()));
        }
        Ok(cratefield_core::PresignedPut {
            url: self.presign("PUT", key, &headers, ttl)?,
            method: "PUT",
            headers,
        })
    }
    async fn put_stream(
        &self,
        key: &str,
        body: cratefield_core::BoxStream<'static, Result<Bytes, cratefield_core::StreamError>>,
        content_type: &str,
        max_bytes: u64,
    ) -> Result<u64, cratefield_core::BlobError> {
        let (written, bytes) = collect_capped(body, max_bytes).await?;
        self.objects.lock().unwrap().insert(
            key.to_owned(),
            cratefield_core::BlobObject {
                bytes,
                content_type: content_type.to_owned(),
            },
        );
        Ok(written)
    }
    async fn get_stream(
        &self,
        key: &str,
    ) -> Result<Option<cratefield_core::BlobStream>, cratefield_core::BlobError> {
        let Some(object) = self.objects.lock().unwrap().get(key).cloned() else {
            return Ok(None);
        };
        let size = object.bytes.len() as u64;
        Ok(Some(cratefield_core::BlobStream {
            content_type: object.content_type,
            size,
            body: stored_body_stream(&object.bytes),
        }))
    }
    async fn head(
        &self,
        key: &str,
    ) -> Result<Option<cratefield_core::BlobMeta>, cratefield_core::BlobError> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .map(|object| cratefield_core::BlobMeta {
                key: key.to_owned(),
                size: object.bytes.len() as u64,
                content_type: object.content_type.clone(),
            }))
    }
    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<cratefield_core::BlobPage, cratefield_core::BlobError> {
        let objects = self.objects.lock().unwrap();
        let mut keys: Vec<String> = objects
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect();
        keys.sort();
        let start = cursor.map_or(0, |cursor| {
            keys.partition_point(|key| key.as_str() <= cursor)
        });
        let take = (keys.len() - start).min(limit);
        let selected = &keys[start..start + take];
        let page = selected
            .iter()
            .map(|key| {
                let object = &objects[key];
                cratefield_core::BlobMeta {
                    key: key.clone(),
                    size: object.bytes.len() as u64,
                    content_type: object.content_type.clone(),
                }
            })
            .collect();
        let cursor = if start + take < keys.len() {
            selected.last().cloned()
        } else {
            None
        };
        Ok(cratefield_core::BlobPage {
            objects: page,
            cursor,
        })
    }
    async fn create_multipart(
        &self,
        key: &str,
        content_type: &str,
    ) -> Result<cratefield_core::UploadId, cratefield_core::BlobError> {
        let id = self.next_upload_id.fetch_add(1, Ordering::Relaxed) + 1;
        let upload_id = cratefield_core::UploadId::new(format!("upload-{id}"));
        self.uploads.lock().unwrap().insert(
            upload_id.as_str().to_owned(),
            MemoryUpload {
                key: key.to_owned(),
                content_type: content_type.to_owned(),
                parts: BTreeMap::new(),
            },
        );
        Ok(upload_id)
    }
    async fn upload_part(
        &self,
        key: &str,
        upload_id: &cratefield_core::UploadId,
        part_number: u16,
        body: cratefield_core::BoxStream<'static, Result<Bytes, cratefield_core::StreamError>>,
        max_part_bytes: u64,
    ) -> Result<cratefield_core::PartReceipt, cratefield_core::BlobError> {
        cratefield_core::check_part_number(part_number)?;
        let (_, bytes) = collect_capped(body, max_part_bytes).await?;
        let mut uploads = self.uploads.lock().unwrap();
        let upload = uploads.get_mut(upload_id.as_str()).ok_or_else(|| {
            cratefield_core::BlobError::Operation(format!(
                "no multipart upload `{}`",
                upload_id.as_str()
            ))
        })?;
        if upload.key != key {
            return Err(cratefield_core::BlobError::Operation(
                "multipart upload belongs to a different key".to_owned(),
            ));
        }
        let etag = format!("part-{part_number}-{}", bytes.len());
        upload.parts.insert(part_number, (etag.clone(), bytes));
        Ok(cratefield_core::PartReceipt { part_number, etag })
    }
    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &cratefield_core::UploadId,
        parts: &[cratefield_core::PartReceipt],
    ) -> Result<(), cratefield_core::BlobError> {
        let mut uploads = self.uploads.lock().unwrap();
        // Validate against the stored upload **without** removing it, so a
        // refused complete leaves the upload intact for a retry, as a real
        // store does.
        let assembled = {
            let upload = uploads.get(upload_id.as_str()).ok_or_else(|| {
                cratefield_core::BlobError::Operation(format!(
                    "no multipart upload `{}`",
                    upload_id.as_str()
                ))
            })?;
            if upload.key != key {
                return Err(cratefield_core::BlobError::Operation(
                    "multipart upload belongs to a different key".to_owned(),
                ));
            }
            let mut ordered = parts.to_vec();
            ordered.sort_by_key(|receipt| receipt.part_number);
            let mut assembled = Vec::new();
            for (index, receipt) in ordered.iter().enumerate() {
                let (etag, bytes) = upload.parts.get(&receipt.part_number).ok_or_else(|| {
                    cratefield_core::BlobError::Operation(format!(
                        "part {} was never uploaded",
                        receipt.part_number
                    ))
                })?;
                if *etag != receipt.etag {
                    return Err(cratefield_core::BlobError::Operation(format!(
                        "part {} etag mismatch",
                        receipt.part_number
                    )));
                }
                let is_last = index + 1 == ordered.len();
                if !is_last && (bytes.len() as u64) < cratefield_core::MIN_MULTIPART_PART_BYTES {
                    return Err(cratefield_core::BlobError::Operation(format!(
                        "part {} is below the {}-byte minimum for a non-final part",
                        receipt.part_number,
                        cratefield_core::MIN_MULTIPART_PART_BYTES,
                    )));
                }
                assembled.extend_from_slice(bytes);
            }
            assembled
        };
        let upload = uploads
            .remove(upload_id.as_str())
            .expect("the upload was checked above");
        let content_type = upload.content_type;
        drop(uploads);
        self.objects.lock().unwrap().insert(
            key.to_owned(),
            cratefield_core::BlobObject {
                bytes: assembled,
                content_type,
            },
        );
        Ok(())
    }
    async fn abort_multipart(
        &self,
        key: &str,
        upload_id: &cratefield_core::UploadId,
    ) -> Result<(), cratefield_core::BlobError> {
        let mut uploads = self.uploads.lock().unwrap();
        let upload = uploads.remove(upload_id.as_str()).ok_or_else(|| {
            cratefield_core::BlobError::Operation(format!(
                "no multipart upload `{}`",
                upload_id.as_str()
            ))
        })?;
        if upload.key != key {
            uploads.insert(upload_id.as_str().to_owned(), upload);
            return Err(cratefield_core::BlobError::Operation(
                "multipart upload belongs to a different key".to_owned(),
            ));
        }
        Ok(())
    }
    async fn list_multipart_uploads(
        &self,
        prefix: &str,
    ) -> Result<Vec<cratefield_core::PendingUpload>, cratefield_core::BlobError> {
        let uploads = self.uploads.lock().unwrap();
        let mut pending: Vec<cratefield_core::PendingUpload> = uploads
            .iter()
            .filter(|(_, upload)| upload.key.starts_with(prefix))
            .map(|(id, upload)| cratefield_core::PendingUpload {
                key: upload.key.clone(),
                upload_id: cratefield_core::UploadId::new(id.clone()),
            })
            .collect();
        pending.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(pending)
    }
}

// ---------------------------------------------------------------------------
// MemoryActors

/// How many times one actor's alarm may fire inside a single
/// [`MemoryActors::advance`] before the fake stops. A handler that re-arms
/// its alarm into the past would otherwise never let the advance return.
const MAX_ALARMS_PER_ADVANCE: usize = 4;

/// An in-process [`Actors`] host for module tests (issue #583): one
/// serialized actor per `(kind, key)`, its values in memory, its one alarm
/// driven by a [`ManualClock`] the test advances.
///
/// It dispatches to the [`ActorHandlers`] a venture registered and owns the
/// serialization core leaves to the host: a call takes its actor's async lock
/// for the whole of [`run_actor_message`], so two calls to one actor run one
/// at a time, and an unknown kind is [`ActorError::NotConfigured`], as a host
/// with no handler is.
#[derive(Clone)]
pub struct MemoryActors {
    inner: Arc<MemoryActorsInner>,
}

struct MemoryActorsInner {
    handlers: ActorHandlers,
    clock: ManualClock,
    /// One entry per `(kind, key)` seen so far; created on first use under
    /// the lock, so concurrent first calls share one actor.
    actors: Mutex<HashMap<(String, String), Arc<ActorState>>>,
}

/// One actor instance: its store and the lock that serializes every call and
/// alarm run for it.
#[derive(Default)]
struct ActorState {
    store: MemoryActorStore,
    lock: futures_util::lock::Mutex<()>,
}

/// The backing store for one [`MemoryActors`] actor: a sorted map of values
/// plus the one alarm. `commit` applies a whole [`ActorWrites`] set under a
/// single lock, so a handler's writes land all-or-nothing.
#[derive(Default)]
struct MemoryActorStore {
    state: Mutex<MemoryActorState>,
}

#[derive(Default)]
struct MemoryActorState {
    values: BTreeMap<String, Vec<u8>>,
    alarm: Option<time::OffsetDateTime>,
}

#[async_trait]
impl ActorStore for MemoryActorStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ActorError> {
        Ok(self
            .state
            .lock()
            .expect("store lock")
            .values
            .get(key)
            .cloned())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, ActorError> {
        Ok(self
            .state
            .lock()
            .expect("store lock")
            .values
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    async fn alarm(&self) -> Result<Option<time::OffsetDateTime>, ActorError> {
        Ok(self.state.lock().expect("store lock").alarm)
    }

    async fn commit(&self, writes: ActorWrites) -> Result<(), ActorError> {
        let mut state = self.state.lock().expect("store lock");
        if writes.clear_all {
            state.values.clear();
        }
        for (key, value) in writes.entries {
            match value {
                Some(value) => {
                    state.values.insert(key, value);
                }
                None => {
                    state.values.remove(&key);
                }
            }
        }
        if let Some(alarm) = writes.alarm {
            state.alarm = alarm;
        }
        Ok(())
    }
}

impl MemoryActors {
    /// A host that dispatches to `handlers` and reads `clock`, which its
    /// alarms are measured against.
    #[must_use]
    pub fn new(handlers: ActorHandlers, clock: ManualClock) -> Self {
        Self {
            inner: Arc::new(MemoryActorsInner {
                handlers,
                clock,
                actors: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The actor for `(kind, key)`, creating it on first use.
    fn actor(&self, kind: &str, key: &str) -> Arc<ActorState> {
        self.inner
            .actors
            .lock()
            .expect("actors lock")
            .entry((kind.to_owned(), key.to_owned()))
            .or_default()
            .clone()
    }

    /// Moves the clock forward by `by`, then runs every alarm due at the new
    /// instant under its actor's lock — the way a real host wakes a Durable
    /// Object when its alarm passes.
    ///
    /// An alarm a handler re-arms into the past or now fires again in the
    /// same call, up to `MAX_ALARMS_PER_ADVANCE`; one whose handler fails
    /// stays armed for the next advance.
    pub async fn advance(&self, by: Duration) {
        self.inner.clock.advance(by);
        let now = self.inner.clock.now();
        let actors: Vec<(String, String, Arc<ActorState>)> = {
            let registry = self.inner.actors.lock().expect("actors lock");
            registry
                .iter()
                .map(|((kind, key), state)| (kind.clone(), key.clone(), Arc::clone(state)))
                .collect()
        };
        for (kind, key, state) in actors {
            let Some(handler) = self.inner.handlers.get(&kind) else {
                continue;
            };
            for _ in 0..MAX_ALARMS_PER_ADVANCE {
                let _held = state.lock.lock().await;
                let due = matches!(state.store.alarm().await, Ok(Some(at)) if at <= now);
                if !due {
                    break;
                }
                if run_actor_alarm(
                    handler.as_ref(),
                    &state.store,
                    &self.inner.clock,
                    &kind,
                    &key,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl Actors for MemoryActors {
    async fn call(&self, kind: &str, key: &str, message: &[u8]) -> Result<Vec<u8>, ActorError> {
        let Some(handler) = self.inner.handlers.get(kind) else {
            return Err(ActorError::NotConfigured);
        };
        let state = self.actor(kind, key);
        let _held = state.lock.lock().await;
        run_actor_message(
            handler.as_ref(),
            &state.store,
            &self.inner.clock,
            kind,
            key,
            message,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// FakeEmbedder

/// The width of every [`FakeEmbedder`] vector, and so of the
/// [`ExactVectorIndex`](cratefield_core::ExactVectorIndex) the kit wires in
/// [`full_fake_ports`](crate::full_fake_ports) — the two must agree.
pub const FAKE_EMBEDDER_DIMENSIONS: usize = 8;

/// The model name a [`FakeEmbedder`] reports.
pub const FAKE_EMBEDDER_MODEL: &str = "fake-embedder";

/// A deterministic [`cratefield_core::Embedder`] for module tests: one
/// fixed-width vector per input text, derived from the text's own bytes,
/// and a whitespace-word-count `input_tokens`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeEmbedder;

impl FakeEmbedder {
    /// The vector `text` embeds to: its bytes accumulated round-robin into
    /// [`FAKE_EMBEDDER_DIMENSIONS`] slots. Pure, so a test can compute the
    /// expected vector itself.
    #[must_use]
    pub fn vector(text: &str) -> Vec<f32> {
        let mut out = vec![0.0; FAKE_EMBEDDER_DIMENSIONS];
        for (index, byte) in text.bytes().enumerate() {
            out[index % FAKE_EMBEDDER_DIMENSIONS] += f32::from(byte);
        }
        out
    }
}

#[async_trait]
impl cratefield_core::Embedder for FakeEmbedder {
    async fn embed(
        &self,
        texts: &[String],
    ) -> Result<cratefield_core::Embeddings, cratefield_core::EmbedError> {
        let input_tokens = texts
            .iter()
            .map(|text| text.split_whitespace().count() as u64)
            .sum();
        let mut embeddings =
            cratefield_core::Embeddings::new(FAKE_EMBEDDER_MODEL).usage(input_tokens);
        for text in texts {
            embeddings = embeddings.vector(Self::vector(text));
        }
        Ok(embeddings)
    }
}

// ---------------------------------------------------------------------------
// FakePush

/// How a [`FakePush`] responds, mirroring [`MailerMode`] for the push port.
///
/// [`Error`](Self::Error) carries the provider text a real adapter would
/// have wrapped (issue #236). The fixed modes only ever produce clean
/// strings, so no test using them could show a device token or a push
/// endpoint arriving somewhere it should not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushMode {
    /// Accept and record the notification.
    DeliverOk,
    /// Report the adapter is not configured (no key).
    NotConfigured,
    /// Report the device token is dead (APNs `410`): the caller prunes it.
    Unregistered,
    /// A retryable failure.
    Transient,
    /// Exactly this error, text and all.
    Error(cratefield_core::PushError),
}

/// An in-memory [`cratefield_core::Push`] for module tests: records every
/// `(recipient, notification)` and answers according to its [`PushMode`].
///
/// The mode is global by default and can be overridden **per recipient**
/// ([`FakePush::set_mode_for`]), so a fan-out test can make exactly one of
/// five devices dead and assert that only that one is pruned — the thing a
/// single global mode cannot express (issue #177).
#[derive(Clone)]
pub struct FakePush {
    inner: Arc<FakePushInner>,
}

struct FakePushInner {
    mode: Mutex<PushMode>,
    per_recipient: Mutex<HashMap<cratefield_core::Recipient, PushMode>>,
    sent: Mutex<Vec<(cratefield_core::Recipient, cratefield_core::Notification)>>,
}

impl FakePush {
    #[must_use]
    pub fn new(mode: PushMode) -> Self {
        Self {
            inner: Arc::new(FakePushInner {
                mode: Mutex::new(mode),
                per_recipient: Mutex::new(HashMap::new()),
                sent: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Every `(recipient, notification)` delivered so far. A send that
    /// answered `NotConfigured` or failed is not recorded.
    #[must_use]
    pub fn sent(&self) -> Vec<(cratefield_core::Recipient, cratefield_core::Notification)> {
        self.inner.sent.lock().expect("push lock").clone()
    }

    /// The most recent `(recipient, notification)`.
    #[must_use]
    pub fn last(&self) -> Option<(cratefield_core::Recipient, cratefield_core::Notification)> {
        self.inner.sent.lock().expect("push lock").last().cloned()
    }

    /// Everything delivered to one recipient.
    #[must_use]
    pub fn sent_to(
        &self,
        recipient: &cratefield_core::Recipient,
    ) -> Vec<cratefield_core::Notification> {
        self.inner
            .sent
            .lock()
            .expect("push lock")
            .iter()
            .filter(|(to, _)| to == recipient)
            .map(|(_, notification)| notification.clone())
            .collect()
    }

    /// Switches the mode every recipient without an override answers with
    /// (e.g. flip to `Unregistered` mid-test).
    pub fn set_mode(&self, mode: PushMode) {
        *self.inner.mode.lock().expect("push lock") = mode;
    }

    /// Makes one recipient answer with `mode`, whatever the global mode is —
    /// one dead token among live ones, say.
    pub fn set_mode_for(&self, recipient: &cratefield_core::Recipient, mode: PushMode) {
        self.inner
            .per_recipient
            .lock()
            .expect("push lock")
            .insert(recipient.clone(), mode);
    }

    /// Drops one recipient's override, putting it back on the global mode.
    pub fn clear_mode_for(&self, recipient: &cratefield_core::Recipient) {
        self.inner
            .per_recipient
            .lock()
            .expect("push lock")
            .remove(recipient);
    }

    /// The mode `recipient` will answer with.
    #[must_use]
    pub fn mode_for(&self, recipient: &cratefield_core::Recipient) -> PushMode {
        self.inner
            .per_recipient
            .lock()
            .expect("push lock")
            .get(recipient)
            .cloned()
            .unwrap_or_else(|| self.inner.mode.lock().expect("push lock").clone())
    }
}

impl Default for FakePush {
    fn default() -> Self {
        Self::new(PushMode::DeliverOk)
    }
}

#[async_trait]
impl cratefield_core::Push for FakePush {
    async fn send(
        &self,
        to: &cratefield_core::Recipient,
        notification: &cratefield_core::Notification,
    ) -> Result<cratefield_core::PushOutcome, cratefield_core::PushError> {
        match self.mode_for(to) {
            PushMode::DeliverOk => {
                let id = format!(
                    "fake-push-{}",
                    self.inner.sent.lock().expect("push lock").len()
                );
                self.inner
                    .sent
                    .lock()
                    .expect("push lock")
                    .push((to.clone(), notification.clone()));
                Ok(cratefield_core::PushOutcome::Delivered { id: Some(id) })
            }
            PushMode::NotConfigured => Ok(cratefield_core::PushOutcome::NotConfigured),
            PushMode::Unregistered => Err(cratefield_core::PushError::Unregistered),
            PushMode::Transient => Err(cratefield_core::PushError::transient("fake push failure")),
            PushMode::Error(error) => Err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// FakeTextModel

/// How a [`FakeTextModel`] answers, mirroring [`PushMode`] for the text
/// model port (issue #429).
///
/// [`Error`](Self::Error) carries the exact error a test wants, and
/// [`Rejected`](Self::Rejected)/[`Transient`](Self::Transient) are the two
/// fixed modes the port's own contract names — a caller's retry and
/// back-off arms stay reachable without inventing provider responses.
#[derive(Debug, Clone, PartialEq)]
pub enum TextModelMode {
    /// Complete with this text, under a deterministic `fake-<tier>` model
    /// name and plausible token counts.
    Reply(String),
    /// Answer exactly this completion, usage and parsed JSON included.
    Complete(cratefield_core::Completion),
    /// Report the tier is unwired (`TextModelError::NotConfigured`).
    NotConfigured,
    /// A non-retryable refusal carrying the provider text.
    Rejected(String),
    /// A retryable failure with the provider's back-off, where it said one.
    Transient { retry_after: Option<Duration> },
    /// Exactly this error, text and all.
    Error(cratefield_core::TextModelError),
}

/// An in-memory [`TextModel`] for module tests: records every [`Prompt`]
/// it completed and answers according to its [`TextModelMode`].
///
/// The mode is global by default and can be overridden **per tier**
/// ([`FakeTextModel::set_mode_for`]), mirroring [`FakePush`]'s
/// per-recipient override — the natural analogue, and the thing the port
/// exists for: one test can wire the fast tier to a drafted reply and the
/// strong tier to a refusal, and watch a module treat the two differently
/// without either vendor being named.
///
/// A completion that answered `NotConfigured` or failed is **not**
/// recorded, the same rule [`FakePush`] applies to a send — the recording
/// means "the model answered", and a caller that retried on
/// `Transient { .. }` then sees one recorded prompt per attempt it got an
/// answer for.
#[derive(Clone)]
pub struct FakeTextModel {
    inner: Arc<FakeTextModelInner>,
}

struct FakeTextModelInner {
    mode: Mutex<TextModelMode>,
    per_tier: Mutex<HashMap<ModelTier, TextModelMode>>,
    prompts: Mutex<Vec<Prompt>>,
}

/// Plausible, deterministic token counts for a fake answer: roughly four
/// characters per token on both sides. Stable for a given prompt and text,
/// which is what an assertion needs — no test wants to guess a provider's
/// tokenizer.
fn fake_usage(prompt: &Prompt, text: &str) -> (u64, u64) {
    let prompt_chars = prompt.system.as_deref().map_or(0, str::len)
        + prompt
            .messages
            .iter()
            .map(|turn| turn.content.len())
            .sum::<usize>();
    let input = (prompt_chars / 4).max(1) as u64;
    let output = (text.len() / 4).max(1) as u64;
    (input, output)
}

impl FakeTextModel {
    #[must_use]
    pub fn new(mode: TextModelMode) -> Self {
        Self {
            inner: Arc::new(FakeTextModelInner {
                mode: Mutex::new(mode),
                per_tier: Mutex::new(HashMap::new()),
                prompts: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Every prompt answered so far, in order. A completion that answered
    /// `NotConfigured` or failed is not recorded.
    #[must_use]
    pub fn prompts(&self) -> Vec<Prompt> {
        self.inner.prompts.lock().expect("text model lock").clone()
    }

    /// The most recent prompt answered.
    #[must_use]
    pub fn last(&self) -> Option<Prompt> {
        self.inner
            .prompts
            .lock()
            .expect("text model lock")
            .last()
            .cloned()
    }

    /// Switches the mode every tier without an override answers with
    /// (e.g. flip to `NotConfigured` mid-test).
    pub fn set_mode(&self, mode: TextModelMode) {
        *self.inner.mode.lock().expect("text model lock") = mode;
    }

    /// Makes one tier answer with `mode`, whatever the global mode is —
    /// the fast tier drafting and the strong tier refusing, say.
    pub fn set_mode_for(&self, tier: ModelTier, mode: TextModelMode) {
        self.inner
            .per_tier
            .lock()
            .expect("text model lock")
            .insert(tier, mode);
    }

    /// Drops one tier's override, putting it back on the global mode.
    pub fn clear_mode_for(&self, tier: ModelTier) {
        self.inner
            .per_tier
            .lock()
            .expect("text model lock")
            .remove(&tier);
    }

    /// The mode `tier` will answer with.
    #[must_use]
    pub fn mode_for(&self, tier: ModelTier) -> TextModelMode {
        self.inner
            .per_tier
            .lock()
            .expect("text model lock")
            .get(&tier)
            .cloned()
            .unwrap_or_else(|| self.inner.mode.lock().expect("text model lock").clone())
    }

    fn record(&self, prompt: &Prompt) {
        self.inner
            .prompts
            .lock()
            .expect("text model lock")
            .push(prompt.clone());
    }
}

impl Default for FakeTextModel {
    fn default() -> Self {
        Self::new(TextModelMode::Reply("fake completion".to_owned()))
    }
}

#[async_trait]
impl TextModel for FakeTextModel {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, TextModelError> {
        // The fake answers plain completions; a prompt carrying tools would
        // otherwise be answered as if none were offered. Refuse it the way
        // a real adapter without the capability does, so a caller is told
        // rather than silently misled.
        if !prompt.tools.is_empty() {
            return Err(TextModelError::Unsupported(Capability::Tools));
        }
        // An image prompt over a bound is refused here too, before the
        // prompt is recorded or answered — the same rule a real adapter
        // applies before any network call.
        prompt.check_images()?;
        match self.mode_for(prompt.tier) {
            TextModelMode::Reply(text) => {
                self.record(prompt);
                let (input_tokens, output_tokens) = fake_usage(prompt, &text);
                Ok(
                    Completion::new(text, format!("fake-{}", prompt.tier.name()))
                        .usage(input_tokens, output_tokens),
                )
            }
            TextModelMode::Complete(completion) => {
                self.record(prompt);
                Ok(completion)
            }
            TextModelMode::NotConfigured => Err(TextModelError::NotConfigured),
            TextModelMode::Rejected(message) => Err(TextModelError::Rejected(message)),
            TextModelMode::Transient { retry_after } => {
                Err(TextModelError::Transient { retry_after })
            }
            TextModelMode::Error(error) => Err(error),
        }
    }

    fn supports(&self, _tier: ModelTier, capability: Capability) -> bool {
        // The fake answers an image prompt — it refuses neither text nor
        // images — so it reports vision, and a router lets an image prompt
        // through to it rather than refusing it for capability. It carries
        // no tools, and still reports none.
        capability == Capability::Images
    }
}

// ---------------------------------------------------------------------------
// FakeClassifier

/// How a [`FakeClassifier`] answers, mirroring [`TextModelMode`] for the
/// classifier port (issue #456).
///
/// The fixed modes [`NotConfigured`](Self::NotConfigured),
/// [`Rejected`](Self::Rejected) and [`Transient`](Self::Transient) are the
/// three the port's own contract names, and [`Error`](Self::Error) carries
/// any `ClassifierError` a test wants — between them every arm of a
/// caller's error mapping is reachable, `Transport` included.
#[derive(Debug, Clone, PartialEq)]
pub enum ClassifierMode {
    /// Answer exactly these, keyed by question id. A question the set asks
    /// that the map does not name falls back to the deterministic answer,
    /// so one test can script a subset and let the rest stay plausible.
    Answers(BTreeMap<String, Answer>),
    /// Answer every question deterministically from its own labels (the
    /// default): the first label, with a plausible normalised distribution
    /// over all of them. A module under conformance gets a usable answer
    /// without scripting anything.
    Deterministic,
    /// Report the port is unwired (`ClassifierError::NotConfigured`).
    NotConfigured,
    /// A non-retryable refusal carrying the provider text.
    Rejected(String),
    /// A retryable failure with the provider's back-off, where it said one.
    Transient { retry_after: Option<Duration> },
    /// Exactly this error, text and all.
    Error(ClassifierError),
}

/// One `Classifier::ask` a [`FakeClassifier`] answered, for assertions:
/// the state as it arrived (untruncated — this fake has no provider
/// budget to spend) and the question ids in the set, in map order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// The state the questions were asked about.
    pub state: String,
    /// The ids of the questions in the set, in `BTreeMap` order.
    pub question_ids: Vec<String>,
}

/// An in-memory [`Classifier`] for module tests: records every ask it
/// answered and answers according to its [`ClassifierMode`].
///
/// The mode is global by default and can be overridden **per question**
/// ([`FakeClassifier::set_answer_for`]), mirroring [`FakeTextModel`]'s
/// per-tier override: one test can script one question's probabilities
/// while the rest stay deterministic.
///
/// An ask that failed (`NotConfigured`, `Rejected`, `Transient` or
/// `Error`) is **not** recorded, the same rule [`FakeTextModel`] applies
/// to a completion — the recording means "the classifier answered", so a
/// caller that retried on `Transient { .. }` sees one recorded ask per
/// attempt that got answers.
#[derive(Clone)]
pub struct FakeClassifier {
    inner: Arc<FakeClassifierInner>,
}

struct FakeClassifierInner {
    mode: Mutex<ClassifierMode>,
    per_question: Mutex<BTreeMap<String, Answer>>,
    asks: Mutex<Vec<Ask>>,
    profile: Mutex<ClassifierProfile>,
}

/// The deterministic answer for `question`: its first label
/// ([`Question::labels`] order — first criterion, first level, or `true`
/// for a `Noul`) carries most of the mass, spread plausibly over all the
/// labels. Pure: the same question always answers the same way, which is
/// what an assertion needs.
fn deterministic_answer(question: &Question) -> Answer {
    let labels = question.labels();
    let chosen = labels.first().copied().unwrap_or_default();
    // Most of the mass on the chosen label, the rest split evenly: for a
    // two-label question 0.6/0.4, for five 0.6 then four shares of 0.1.
    let share = if labels.len() > 1 {
        0.4 / f32::from(u16::try_from(labels.len() - 1).unwrap_or(1))
    } else {
        0.0
    };
    let probabilities: BTreeMap<String, f32> = labels
        .iter()
        .map(|label| {
            let mass = if *label == chosen { 0.6 } else { share };
            ((*label).to_owned(), mass)
        })
        .collect();
    match question {
        Question::Choice { .. } => Answer::choice(chosen, probabilities),
        Question::Noul { .. } => Answer::noul(chosen == "true", probabilities),
        // A scale's labels are usually named for their scores ("1".."5"),
        // so the first level parses; when it does not, the score is 0.0
        // and the confidence still comes from the label itself.
        Question::Score { .. } => Answer::new(
            AnswerValue::Score(chosen.parse().unwrap_or_default()),
            probabilities,
            0.6,
        ),
    }
}

impl FakeClassifier {
    #[must_use]
    pub fn new(mode: ClassifierMode) -> Self {
        Self {
            inner: Arc::new(FakeClassifierInner {
                mode: Mutex::new(mode),
                per_question: Mutex::new(BTreeMap::new()),
                asks: Mutex::new(Vec::new()),
                profile: Mutex::new(ClassifierProfile::new(
                    Calibration::Classifier,
                    cratefield_core::DEFAULT_MAX_STATE_CHARS,
                )),
            }),
        }
    }

    /// Every ask answered so far, in order. An ask that failed is not
    /// recorded.
    #[must_use]
    pub fn asks(&self) -> Vec<Ask> {
        self.inner.asks.lock().expect("classifier lock").clone()
    }

    /// The most recent ask answered.
    #[must_use]
    pub fn last(&self) -> Option<Ask> {
        self.inner
            .asks
            .lock()
            .expect("classifier lock")
            .last()
            .cloned()
    }

    /// Switches the mode every question without an override answers with
    /// (e.g. flip to `NotConfigured` mid-test).
    pub fn set_mode(&self, mode: ClassifierMode) {
        *self.inner.mode.lock().expect("classifier lock") = mode;
    }

    /// Makes one question answer with `answer`, whatever the mode is —
    /// scripting one question's probabilities while the rest stay
    /// deterministic, say.
    pub fn set_answer_for(&self, question_id: impl Into<String>, answer: Answer) {
        self.inner
            .per_question
            .lock()
            .expect("classifier lock")
            .insert(question_id.into(), answer);
    }

    /// Drops one question's override, putting it back on the mode.
    pub fn clear_answer_for(&self, question_id: &str) {
        self.inner
            .per_question
            .lock()
            .expect("classifier lock")
            .remove(question_id);
    }

    /// Reports `calibration` and `max_state_chars` from
    /// [`Classifier::profile`], so a test can exercise a module's
    /// calibration- or truncation-aware behaviour against either family.
    pub fn set_profile(&self, calibration: Calibration, max_state_chars: usize) {
        *self.inner.profile.lock().expect("classifier lock") =
            ClassifierProfile::new(calibration, max_state_chars);
    }
}

impl Default for FakeClassifier {
    fn default() -> Self {
        Self::new(ClassifierMode::Deterministic)
    }
}

#[async_trait]
impl Classifier for FakeClassifier {
    fn profile(&self) -> ClassifierProfile {
        *self.inner.profile.lock().expect("classifier lock")
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        // A malformed set lands on `Rejected`, never a panic — the same
        // way a real adapter refuses it.
        validate_questions(questions)?;

        let mode = self.inner.mode.lock().expect("classifier lock").clone();
        match mode {
            ClassifierMode::NotConfigured => return Err(ClassifierError::NotConfigured),
            ClassifierMode::Rejected(message) => return Err(ClassifierError::Rejected(message)),
            ClassifierMode::Transient { retry_after } => {
                return Err(ClassifierError::Transient { retry_after });
            }
            ClassifierMode::Error(error) => return Err(error),
            ClassifierMode::Answers(_) | ClassifierMode::Deterministic => {}
        }

        let overrides = self.inner.per_question.lock().expect("classifier lock");
        let answers: BTreeMap<String, Answer> = questions
            .iter()
            .map(|(id, question)| {
                let answer = overrides.get(id).cloned().unwrap_or_else(|| match &mode {
                    ClassifierMode::Answers(map) => map
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| deterministic_answer(question)),
                    _ => deterministic_answer(question),
                });
                (id.clone(), answer)
            })
            .collect();
        drop(overrides);

        self.inner.asks.lock().expect("classifier lock").push(Ask {
            state: state.to_owned(),
            question_ids: questions.keys().cloned().collect(),
        });
        Ok(answers)
    }
}

// ---------------------------------------------------------------------------
// FakePayments

/// How a [`FakePayments`] responds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentsMode {
    /// Succeed and record the call.
    Ok,
    /// Report `NotConfigured` (no Stripe key).
    NotConfigured,
    /// A retryable failure.
    Transient,
}

/// What a [`FakePayments`] recorded, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentsCall {
    Checkout,
    SubscriptionCheckout,
    ConnectAccountLink,
    ChargeWithTransfer,
    Refund,
    VerifyWebhook,
}

/// An in-memory [`cratefield_core::Payments`] for module tests: records which
/// calls were made and answers per its [`PaymentsMode`]. `verify_webhook`
/// treats a signature header of `"invalid"` as a tampered event.
#[derive(Clone)]
pub struct FakePayments {
    inner: Arc<FakePaymentsInner>,
}

struct FakePaymentsInner {
    mode: Mutex<PaymentsMode>,
    calls: Mutex<Vec<PaymentsCall>>,
}

impl FakePayments {
    #[must_use]
    pub fn new(mode: PaymentsMode) -> Self {
        Self {
            inner: Arc::new(FakePaymentsInner {
                mode: Mutex::new(mode),
                calls: Mutex::new(Vec::new()),
            }),
        }
    }

    /// The calls recorded so far.
    #[must_use]
    pub fn calls(&self) -> Vec<PaymentsCall> {
        self.inner.calls.lock().expect("payments lock").clone()
    }

    pub fn set_mode(&self, mode: PaymentsMode) {
        *self.inner.mode.lock().expect("payments lock") = mode;
    }

    fn record(&self, call: PaymentsCall) {
        self.inner.calls.lock().expect("payments lock").push(call);
    }

    fn guard(&self) -> Result<(), cratefield_core::PaymentsError> {
        match *self.inner.mode.lock().expect("payments lock") {
            PaymentsMode::Ok => Ok(()),
            PaymentsMode::NotConfigured => Err(cratefield_core::PaymentsError::NotConfigured),
            PaymentsMode::Transient => Err(cratefield_core::PaymentsError::Transient(
                "fake payments failure".to_owned(),
            )),
        }
    }
}

impl Default for FakePayments {
    fn default() -> Self {
        Self::new(PaymentsMode::Ok)
    }
}

#[async_trait]
impl cratefield_core::Payments for FakePayments {
    async fn create_checkout(
        &self,
        _request: &cratefield_core::CheckoutRequest,
    ) -> Result<cratefield_core::CheckoutSession, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::Checkout);
        Ok(cratefield_core::CheckoutSession {
            id: "cs_fake".to_owned(),
            url: "https://checkout.stripe.test/cs_fake".to_owned(),
        })
    }

    async fn create_subscription_checkout(
        &self,
        _request: &cratefield_core::SubscriptionCheckoutRequest,
    ) -> Result<cratefield_core::CheckoutSession, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::SubscriptionCheckout);
        Ok(cratefield_core::CheckoutSession {
            id: "cs_sub_fake".to_owned(),
            url: "https://checkout.stripe.test/cs_sub_fake".to_owned(),
        })
    }

    async fn create_connect_account_link(
        &self,
        _request: &cratefield_core::ConnectAccountLinkRequest,
    ) -> Result<cratefield_core::ConnectAccountLink, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::ConnectAccountLink);
        Ok(cratefield_core::ConnectAccountLink {
            account_id: "acct_fake".to_owned(),
            url: "https://connect.stripe.test/acct_fake".to_owned(),
        })
    }

    async fn charge_with_transfer(
        &self,
        _request: &cratefield_core::TransferCharge,
    ) -> Result<cratefield_core::Charge, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::ChargeWithTransfer);
        Ok(cratefield_core::Charge {
            id: "pi_fake".to_owned(),
            status: "succeeded".to_owned(),
        })
    }

    async fn refund(
        &self,
        _request: &cratefield_core::RefundRequest,
    ) -> Result<cratefield_core::Refund, cratefield_core::PaymentsError> {
        self.guard()?;
        self.record(PaymentsCall::Refund);
        Ok(cratefield_core::Refund {
            id: "re_fake".to_owned(),
        })
    }

    async fn verify_webhook(
        &self,
        signature_header: &str,
        _body: &[u8],
    ) -> Result<cratefield_core::WebhookEvent, cratefield_core::PaymentsError> {
        self.record(PaymentsCall::VerifyWebhook);
        if signature_header == "invalid" {
            return Err(cratefield_core::PaymentsError::SignatureInvalid(
                "fake tampered signature".to_owned(),
            ));
        }
        self.guard()?;
        Ok(cratefield_core::WebhookEvent {
            id: "evt_fake".to_owned(),
            kind: "checkout.session.completed".to_owned(),
            data: serde_json::json!({ "object": "checkout.session" }),
        })
    }
}

// ---------------------------------------------------------------------------
// FakeTracker

/// A short, non-reversible stand-in for a [`Credential`] in a recorded
/// call, after `push.rs`'s `fingerprint` for `Recipient`: enough to tell
/// two credentials apart in an assertion, useless for recovering the
/// token.
///
/// `push.rs` hashes with `sha2`, which is not a dependency of the kit; a
/// test fake needs no cross-version stability and no collision resistance
/// beyond "different credentials assert differently", so std's
/// [`DefaultHasher`](std::hash::DefaultHasher) does the same job. The
/// plaintext is never stored — that is the point of the port: a fake that
/// recorded the secret would make every "the token went nowhere" assertion
/// unfalsifiable.
fn fingerprint(credential: &Credential) -> String {
    use std::hash::{Hash, Hasher};

    // The one `expose` in the kit: the fingerprint is computed and the
    // borrow dropped before anything is recorded.
    let mut hasher = std::hash::DefaultHasher::new();
    credential.expose().hash(&mut hasher);
    format!("fp:{:016x}", hasher.finish())
}

/// How a [`FakeTracker`] answers, mirroring [`MailerMode`] and [`PushMode`]
/// for the tracker port (issue #431).
///
/// [`Error`](Self::Error) carries the exact `TrackerError` a test wants,
/// text and delay and all (issue #236's rule): the fixed modes only ever
/// produce clean strings, so the arms of a caller's outcome mapping — a
/// `Rejected` carrying the tracker's own words, a `Transient` carrying a
/// provider-stated delay — would otherwise be unreachable from a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackerMode {
    /// Accept and record the ticket.
    FileOk,
    /// Report that no adapter is configured for this destination.
    NotConfigured,
    /// Report that the per-tenant credential was refused (`401`/`403`).
    Unauthorized,
    /// Report that the tracker refused the ticket — a `4xx` about the
    /// draft, not about the credential.
    Rejected,
    /// A retryable failure with no delay stated.
    Transient,
    /// Exactly this error, text and all.
    Error(TrackerError),
}

/// One `Tracker::file` a [`FakeTracker`] accepted, for assertions.
///
/// The credential appears only as its non-reversible
/// `fingerprint`: proof that a credential reached the port, and never
/// the secret itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiledCall {
    /// Where the ticket was filed.
    pub dest: Destination,
    /// The ticket as the caller handed it over.
    pub draft: TicketDraft,
    /// A fingerprint of the credential the caller passed.
    pub credential_fingerprint: String,
}

/// One `Tracker::status` a [`FakeTracker`] accepted, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusedCall {
    /// Where the ticket lives.
    pub dest: Destination,
    /// The external id the caller asked about.
    pub external_id: String,
    /// A fingerprint of the credential the caller passed.
    pub credential_fingerprint: String,
}

/// One `Tracker::comment` a [`FakeTracker`] accepted, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentedCall {
    /// Where the ticket lives.
    pub dest: Destination,
    /// The ticket the note was added to.
    pub external_id: String,
    /// The note as the caller handed it over.
    pub comment: TicketComment,
    /// A fingerprint of the credential the caller passed.
    pub credential_fingerprint: String,
}

/// An in-memory [`Tracker`] for module tests: records every accepted
/// `file`/`status`/`comment` call and answers according to its
/// [`TrackerMode`]. A
/// call the mode answered with an error is not recorded, as [`FakePush`]
/// does not record a failed send.
///
/// The mode is global by default and can be overridden **per destination**
/// ([`FakeTracker::set_mode_for`]), the [`FakePush`] shape: one tenant's
/// expired token among live ones. The state an accepted `status` reports
/// is scripted separately ([`FakeTracker::set_state`]), because "the file
/// succeeded" and "the ticket has moved on since" are two different
/// answers a test wants to set independently.
#[derive(Clone, Debug)]
pub struct FakeTracker {
    inner: Arc<FakeTrackerInner>,
}

#[derive(Debug)]
struct FakeTrackerInner {
    mode: Mutex<TrackerMode>,
    per_destination: Mutex<HashMap<Destination, TrackerMode>>,
    filed: Mutex<Vec<FiledCall>>,
    statused: Mutex<Vec<StatusedCall>>,
    commented: Mutex<Vec<CommentedCall>>,
    state: Mutex<TicketState>,
}

impl FakeTracker {
    #[must_use]
    pub fn new(mode: TrackerMode) -> Self {
        Self {
            inner: Arc::new(FakeTrackerInner {
                mode: Mutex::new(mode),
                per_destination: Mutex::new(HashMap::new()),
                filed: Mutex::new(Vec::new()),
                statused: Mutex::new(Vec::new()),
                commented: Mutex::new(Vec::new()),
                state: Mutex::new(TicketState::Open),
            }),
        }
    }

    /// Every `file` accepted so far, in order.
    #[must_use]
    pub fn filed(&self) -> Vec<FiledCall> {
        self.inner.filed.lock().expect("tracker lock").clone()
    }

    /// The most recent `file` accepted.
    #[must_use]
    pub fn last_filed(&self) -> Option<FiledCall> {
        self.inner
            .filed
            .lock()
            .expect("tracker lock")
            .last()
            .cloned()
    }

    /// Every `status` accepted so far, in order.
    #[must_use]
    pub fn statused(&self) -> Vec<StatusedCall> {
        self.inner.statused.lock().expect("tracker lock").clone()
    }

    /// Every `comment` accepted so far, in order.
    #[must_use]
    pub fn commented(&self) -> Vec<CommentedCall> {
        self.inner.commented.lock().expect("tracker lock").clone()
    }

    /// Switches the mode every destination without an override answers
    /// with (e.g. flip to `Unauthorized` mid-test).
    pub fn set_mode(&self, mode: TrackerMode) {
        *self.inner.mode.lock().expect("tracker lock") = mode;
    }

    /// Makes one destination answer with `mode`, whatever the global mode
    /// is — one tenant's expired token among live ones, say.
    pub fn set_mode_for(&self, dest: &Destination, mode: TrackerMode) {
        self.inner
            .per_destination
            .lock()
            .expect("tracker lock")
            .insert(dest.clone(), mode);
    }

    /// Drops one destination's override, putting it back on the global
    /// mode.
    pub fn clear_mode_for(&self, dest: &Destination) {
        self.inner
            .per_destination
            .lock()
            .expect("tracker lock")
            .remove(dest);
    }

    /// The mode `dest` will answer with.
    #[must_use]
    pub fn mode_for(&self, dest: &Destination) -> TrackerMode {
        self.inner
            .per_destination
            .lock()
            .expect("tracker lock")
            .get(dest)
            .cloned()
            .unwrap_or_else(|| self.inner.mode.lock().expect("tracker lock").clone())
    }

    /// The state an accepted `status` reports.
    pub fn set_state(&self, state: TicketState) {
        *self.inner.state.lock().expect("tracker lock") = state;
    }

    /// The state an accepted `status` currently reports.
    #[must_use]
    pub fn state(&self) -> TicketState {
        *self.inner.state.lock().expect("tracker lock")
    }

    /// The error arms shared by `file`, `status` and `comment`: the same
    /// fixed modes script all three, the way a real adapter answers the
    /// one `TrackerError` vocabulary on every method.
    fn error_for(mode: &TrackerMode) -> Option<TrackerError> {
        match mode {
            TrackerMode::FileOk => None,
            TrackerMode::NotConfigured => Some(TrackerError::NotConfigured),
            TrackerMode::Unauthorized => Some(TrackerError::Unauthorized),
            TrackerMode::Rejected => {
                Some(TrackerError::Rejected("fake tracker rejection".to_owned()))
            }
            TrackerMode::Transient => Some(TrackerError::Transient { retry_after: None }),
            TrackerMode::Error(error) => Some(error.clone()),
        }
    }
}

impl Default for FakeTracker {
    fn default() -> Self {
        Self::new(TrackerMode::FileOk)
    }
}

#[async_trait]
impl Tracker for FakeTracker {
    async fn file(
        &self,
        dest: &Destination,
        cred: &Credential,
        draft: &TicketDraft,
    ) -> Result<Filed, TrackerError> {
        if let Some(error) = Self::error_for(&self.mode_for(dest)) {
            return Err(error);
        }
        let id = format!(
            "fake-{}",
            self.inner.filed.lock().expect("tracker lock").len()
        );
        self.inner
            .filed
            .lock()
            .expect("tracker lock")
            .push(FiledCall {
                dest: dest.clone(),
                draft: draft.clone(),
                credential_fingerprint: fingerprint(cred),
            });
        Ok(Filed {
            url: format!("https://tracker.fake.test/browse/{id}"),
            external_id: id,
        })
    }

    async fn status(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
    ) -> Result<TicketStatus, TrackerError> {
        if let Some(error) = Self::error_for(&self.mode_for(dest)) {
            return Err(error);
        }
        self.inner
            .statused
            .lock()
            .expect("tracker lock")
            .push(StatusedCall {
                dest: dest.clone(),
                external_id: external_id.to_owned(),
                credential_fingerprint: fingerprint(cred),
            });
        Ok(TicketStatus {
            external_id: external_id.to_owned(),
            state: self.state(),
            url: None,
        })
    }

    async fn comment(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
        comment: &TicketComment,
    ) -> Result<(), TrackerError> {
        if let Some(error) = Self::error_for(&self.mode_for(dest)) {
            return Err(error);
        }
        self.inner
            .commented
            .lock()
            .expect("tracker lock")
            .push(CommentedCall {
                dest: dest.clone(),
                external_id: external_id.to_owned(),
                comment: comment.clone(),
                credential_fingerprint: fingerprint(cred),
            });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FakeRealtime

/// Room id -> the member ids a [`FakeRealtime`] reports for it.
type RealtimeMembers = std::collections::HashMap<String, Vec<String>>;
/// The `(room_id, message)` broadcasts a [`FakeRealtime`] recorded.
type RealtimeBroadcasts = Vec<(String, Vec<u8>)>;

/// An in-memory [`cratefield_core::Realtime`] for module tests: records every
/// broadcast per room and reports a fixed member list. It exercises the port a
/// module holds (broadcast/members from outside a socket); the socket lifecycle
/// and `RoomHandler` are the runtime adapter's job, covered by the native
/// adapter's own tests.
#[derive(Clone, Default)]
pub struct FakeRealtime {
    broadcasts: Arc<Mutex<RealtimeBroadcasts>>,
    members: Arc<Mutex<RealtimeMembers>>,
}

impl FakeRealtime {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Presets the members a room reports (for `members` assertions).
    pub fn set_members(&self, room_id: &str, ids: &[&str]) {
        self.members.lock().expect("realtime lock").insert(
            room_id.to_owned(),
            ids.iter().map(|id| (*id).to_owned()).collect(),
        );
    }

    /// Every `(room_id, message)` broadcast so far.
    #[must_use]
    pub fn broadcasts(&self) -> Vec<(String, Vec<u8>)> {
        self.broadcasts.lock().expect("realtime lock").clone()
    }
}

#[async_trait]
impl cratefield_core::Realtime for FakeRealtime {
    async fn broadcast(
        &self,
        room_id: &str,
        message: &[u8],
    ) -> Result<(), cratefield_core::RealtimeError> {
        self.broadcasts
            .lock()
            .expect("realtime lock")
            .push((room_id.to_owned(), message.to_vec()));
        Ok(())
    }

    async fn members(
        &self,
        room_id: &str,
    ) -> Result<Vec<cratefield_core::Member>, cratefield_core::RealtimeError> {
        Ok(self
            .members
            .lock()
            .expect("realtime lock")
            .get(room_id)
            .map(|ids| ids.iter().map(cratefield_core::Member::new).collect())
            .unwrap_or_default())
    }
}

/// What a [`FakeAuth`] answers.
///
/// Every outcome the port has, because a fake that cannot produce one
/// makes the arm handling it unreachable from every test — which is how
/// a five-arm mapping shipped with four of the arms never executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Every request is anonymous, header or not. The deployment where
    /// nobody signs in.
    Anonymous,
    /// A bearer token is taken at face value as the subject's id, and a
    /// request with no `Authorization` header is anonymous. The mode for
    /// a test that wants both branches without minting a JWT.
    TokenIsTheSubject,
    /// Every presented credential is refused, and a request with no
    /// header is still anonymous — the distinction the port exists to
    /// keep.
    NotVerified,
    /// The verifier cannot answer, credential or not.
    Unavailable,
}

/// A [`cratefield_core::Auth`] answering from a mode rather than from
/// a key set.
pub struct FakeAuth {
    mode: AuthMode,
    calls: std::sync::Mutex<Vec<String>>,
}

impl FakeAuth {
    /// A fake in `mode`.
    #[must_use]
    pub fn new(mode: AuthMode) -> Self {
        Self {
            mode,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A fake that reads the bearer token as the subject's id.
    #[must_use]
    pub fn subjects() -> Self {
        Self::new(AuthMode::TokenIsTheSubject)
    }

    /// The bearer values it was asked about, in order. `""` records a
    /// request that carried no `Authorization` header at all.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("uncontended").clone()
    }
}

#[async_trait::async_trait]
impl cratefield_core::Auth for FakeAuth {
    async fn identify(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<cratefield_core::Caller, cratefield_core::AuthError> {
        let presented = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::to_owned);
        self.calls
            .lock()
            .expect("uncontended")
            .push(presented.clone().unwrap_or_default());
        match self.mode {
            AuthMode::Anonymous => Ok(cratefield_core::Caller::Anonymous),
            AuthMode::Unavailable => Err(cratefield_core::AuthError::Unavailable(
                "the fake is in Unavailable mode".to_owned(),
            )),
            AuthMode::NotVerified | AuthMode::TokenIsTheSubject => match presented {
                None => Ok(cratefield_core::Caller::Anonymous),
                Some(_) if self.mode == AuthMode::NotVerified => {
                    Err(cratefield_core::AuthError::NotVerified)
                }
                Some(token) => Ok(cratefield_core::Caller::Subject(
                    cratefield_core::Subject::new(token).session("fake-session"),
                )),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// FakeCustomHostnames

/// An in-memory [`cratefield_core::CustomHostnames`] for module tests:
/// records every call, walks a claim from pending to live on demand, and
/// scripts the error the next call answers with.
///
/// `create` runs [`cratefield_core::check_hostname`] first, exactly as a
/// real adapter must, so a test can drive the `Refused` arm — the refusal
/// never reaches a provider.
#[derive(Clone)]
pub struct FakeCustomHostnames {
    inner: Arc<FakeCustomHostnamesInner>,
}

struct FakeCustomHostnamesInner {
    own_zone: String,
    hostnames: Mutex<BTreeMap<String, CustomHostname>>,
    calls: Mutex<Vec<String>>,
    /// The scripted answer for the next call, if any.
    refusals: Mutex<VecDeque<CustomHostnameError>>,
    next_id: AtomicUsize,
}

impl FakeCustomHostnames {
    /// A fake serving hostnames outside `own_zone` — the zone whose names
    /// are refused as the deployment's own.
    #[must_use]
    pub fn new(own_zone: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(FakeCustomHostnamesInner {
                own_zone: own_zone.into(),
                hostnames: Mutex::new(BTreeMap::new()),
                calls: Mutex::new(Vec::new()),
                refusals: Mutex::new(VecDeque::new()),
                next_id: AtomicUsize::new(0),
            }),
        }
    }

    /// Every call so far, in order, as `"create share.acme.com"`.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.inner
            .calls
            .lock()
            .expect("custom hostnames lock")
            .clone()
    }

    /// Walks a claim to `Active`/`Active` with no records left to publish.
    ///
    /// A hostname that was never claimed is a no-op rather than a panic:
    /// a test's setup failing should fail on the assertion, not here.
    pub fn activate(&self, hostname: &str) {
        let key = self.key(hostname);
        if let Some(claim) = self
            .inner
            .hostnames
            .lock()
            .expect("custom hostnames lock")
            .get_mut(&key)
        {
            claim.status = ProviderStatus::Active;
            claim.certificate = CertificateStatus::Active;
            claim.validation.clear();
        }
    }

    /// Records the claim as failed with the provider's own `reason`.
    pub fn fail(&self, hostname: &str, reason: &str) {
        let key = self.key(hostname);
        if let Some(claim) = self
            .inner
            .hostnames
            .lock()
            .expect("custom hostnames lock")
            .get_mut(&key)
        {
            claim.status = ProviderStatus::Failed {
                reason: reason.to_owned(),
            };
        }
    }

    /// Makes the next call answer `error` instead of its normal answer.
    /// Queue several to script a sequence.
    pub fn refuse_next(&self, error: CustomHostnameError) {
        self.inner
            .refusals
            .lock()
            .expect("custom hostnames lock")
            .push_back(error);
    }

    /// The key a hostname is stored under: the same normalisation the
    /// adapter's `check_hostname` call produces.
    fn key(&self, hostname: &str) -> String {
        check_hostname(hostname, &self.inner.own_zone)
            .unwrap_or_else(|_| hostname.trim().trim_end_matches('.').to_ascii_lowercase())
    }

    fn log(&self, call: String) {
        self.inner
            .calls
            .lock()
            .expect("custom hostnames lock")
            .push(call);
    }

    fn take_refusal(&self) -> Option<CustomHostnameError> {
        self.inner
            .refusals
            .lock()
            .expect("custom hostnames lock")
            .pop_front()
    }
}

#[async_trait]
impl CustomHostnames for FakeCustomHostnames {
    async fn create(&self, claim: &HostnameClaim) -> Result<CustomHostname, CustomHostnameError> {
        self.log(format!("create {}", claim.hostname));
        if let Some(error) = self.take_refusal() {
            return Err(error);
        }
        let hostname = check_hostname(&claim.hostname, &self.inner.own_zone)
            .map_err(CustomHostnameError::Refused)?;
        let mut hostnames = self.inner.hostnames.lock().expect("custom hostnames lock");
        if hostnames.contains_key(&hostname) {
            return Err(CustomHostnameError::AlreadyExists);
        }
        let id = format!(
            "fake-{}",
            self.inner.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let created = CustomHostname {
            id: id.clone(),
            hostname: hostname.clone(),
            status: ProviderStatus::Pending,
            certificate: CertificateStatus::Pending,
            validation: vec![Validation {
                record_type: DnsRecordType::Txt,
                name: format!("_cf-custom-hostname.{hostname}"),
                value: id,
            }],
        };
        hostnames.insert(hostname, created.clone());
        Ok(created)
    }

    async fn get(&self, hostname: &str) -> Result<Option<CustomHostname>, CustomHostnameError> {
        self.log(format!("get {hostname}"));
        if let Some(error) = self.take_refusal() {
            return Err(error);
        }
        let key = self.key(hostname);
        Ok(self
            .inner
            .hostnames
            .lock()
            .expect("custom hostnames lock")
            .get(&key)
            .cloned())
    }

    async fn delete(&self, hostname: &str) -> Result<(), CustomHostnameError> {
        self.log(format!("delete {hostname}"));
        if let Some(error) = self.take_refusal() {
            return Err(error);
        }
        let key = self.key(hostname);
        self.inner
            .hostnames
            .lock()
            .expect("custom hostnames lock")
            .remove(&key);
        Ok(())
    }

    async fn refresh(&self, hostname: &str) -> Result<CustomHostname, CustomHostnameError> {
        self.log(format!("refresh {hostname}"));
        if let Some(error) = self.take_refusal() {
            return Err(error);
        }
        let key = self.key(hostname);
        self.inner
            .hostnames
            .lock()
            .expect("custom hostnames lock")
            .get(&key)
            .cloned()
            .ok_or(CustomHostnameError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::Blob as _;

    fn json_body(response: &Response<Bytes>) -> serde_json::Value {
        serde_json::from_slice(response.body()).expect("the body is json")
    }

    #[test]
    fn problem_json_carries_the_problem_fields_and_media_type() {
        let response = problem_json(
            StatusCode::TOO_MANY_REQUESTS,
            "Too Many Requests",
            "slow down",
        );
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
        let body = json_body(&response);
        assert_eq!(body["type"], "about:blank");
        assert_eq!(body["title"], "Too Many Requests");
        assert_eq!(body["status"], 429);
        assert_eq!(body["detail"], "slow down");
    }

    #[test]
    fn error_json_is_the_colonizer_shape() {
        let response = error_json(StatusCode::BAD_REQUEST, "bad request");
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(json_body(&response)["error"], "bad request");
    }

    #[test]
    fn with_retry_after_sets_the_header_in_seconds() {
        let response = with_retry_after(error_json(StatusCode::TOO_MANY_REQUESTS, "slow"), 42);
        assert_eq!(response.headers()[RETRY_AFTER], "42");
    }

    #[test]
    fn a_preset_answers_through_the_port() {
        // Drive a preset end to end: it must be wired into `scripted`, not
        // merely build a body.
        let http = FakeHttpClient::owlpost_rate_limited(7);
        let request = Request::builder()
            .uri("https://api.owlpost.fake/v1/emails")
            .body(Bytes::new())
            .expect("the request builds");
        let response = pollster::block_on(http.send(request)).expect("the preset answers");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "7");
        assert_eq!(json_body(&response)["detail"], "slow down");
    }

    #[pollster::test]
    async fn memory_blob_presigns_and_verifies_back() {
        // A clock dated in the past: a URL it stamps is expired if verification
        // reads the wall clock instead of the store's.
        let at = time::OffsetDateTime::from_unix_timestamp(1_577_836_800).expect("a valid epoch");
        let blob = MemoryBlob::with_presign(Arc::new(FixedClock(at)));
        let ttl = Duration::from_secs(3600);

        let get = blob.signed_url("cms/clip.mp3", ttl).await.unwrap();
        assert!(get.starts_with("https://blob.test/cms/clip.mp3?"), "{get}");
        assert_eq!(
            blob.verify_presigned(&get, "GET", &[]).unwrap(),
            "cms/clip.mp3"
        );

        let put = blob
            .signed_put_url("cms/clip.mp3", "audio/mpeg", Some(3), ttl)
            .await
            .unwrap();
        assert_eq!((put.method, put.headers.len()), ("PUT", 2));
        assert!(blob.verify_presigned(&put.url, "PUT", &put.headers).is_ok());
        // A header the URL was not signed for is refused.
        assert!(blob.verify_presigned(&put.url, "PUT", &[]).is_err());

        // Without presigning, the Unsupported default stands.
        assert!(matches!(
            MemoryBlob::new().signed_url("k", ttl).await.unwrap_err(),
            cratefield_core::BlobError::Unsupported(_)
        ));
    }
}
