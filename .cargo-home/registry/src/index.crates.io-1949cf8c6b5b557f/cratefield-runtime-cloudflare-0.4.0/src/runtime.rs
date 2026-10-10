//! The `Cloudflare` runtime builder (issue #5).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cratefield_core::sigv4::Credentials;
use cratefield_core::{
    Auth, BoundedHttpClient, Captcha, Classifier, Clock, Config, CustomHostnames, Defer,
    HarnessConfig, Mailer, Payments, Port, Ports, Push, Runtime, SidecarMounts, TextModel, Tracker,
    UlidIdGen,
};
use worker::Env;

use crate::config::EnvConfig;
use crate::ports::{
    D1Database, D1RateLimiter, FetchClient, KvStorePort, Limit, R2Blob, R2Presigner,
    RateLimitPolicy, RateLimitPort, ServiceDispatcher, WorkersClock, vector_index_from_env,
};

pub(crate) fn warn_once(flag: &AtomicBool, message: &str) {
    if !flag.load(Ordering::Relaxed) {
        flag.store(true, Ordering::Relaxed);
        rt_log!(warn, "{message}");
    }
}

/// Runtime logging: `worker::console_log!` on Workers (no tracing
/// dispatcher can be installed there — see `tracing_setup`), `tracing!`
/// natively.
#[macro_export]
macro_rules! rt_log {
    (warn, $($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[warn] {}", format!($($arg)*));
        #[cfg(not(target_arch = "wasm32"))]
        tracing::warn!($($arg)*);
    }};
    (error, $($arg:tt)*) => {{
        #[cfg(target_arch = "wasm32")]
        worker::console_error!("[error] {}", format!($($arg)*));
        #[cfg(not(target_arch = "wasm32"))]
        tracing::error!($($arg)*);
    }};
}
use rt_log;

static WARNED_DB: AtomicBool = AtomicBool::new(false);
static WARNED_KV: AtomicBool = AtomicBool::new(false);
static WARNED_BLOB: AtomicBool = AtomicBool::new(false);
static WARNED_BLOB_PRESIGN: AtomicBool = AtomicBool::new(false);
static WARNED_VECTOR_INDEX: AtomicBool = AtomicBool::new(false);
static WARNED_RATE_LIMIT: AtomicBool = AtomicBool::new(false);
/// The missing-binding refusal (issue #562): logged once per isolate, the
/// same `warn_once` discipline as the degraded-binding warning above.
pub(crate) static WARNED_UNRESOLVED_LIMITER: AtomicBool = AtomicBool::new(false);
static WARNED_SIGNER: AtomicBool = AtomicBool::new(false);
static WARNED_SIDECAR: AtomicBool = AtomicBool::new(false);

/// The Workers runtime. Binding names are static; `.mailer()`/`.captcha()`
/// take adapter instances (`cratefield-adapter-resend`,
/// `cratefield-adapter-turnstile`).
///
/// `Clone`, like the native runtime's `Native`, so a venture can hand one
/// instance to `Harness::builder().runtime(..)` and keep the same one to
/// serve with. Two separately-built instances are the shape of a
/// silent bug: `Harness::build` validates every module's `requires()`
/// against the ports of the instance it was given, and the one that actually
/// serves is the other.
#[derive(Clone)]
pub struct Cloudflare {
    db_binding: Option<&'static str>,
    kv_binding: Option<&'static str>,
    blob_binding: Option<&'static str>,
    /// The four Worker var/secret names presigned R2 URLs read (issue #622):
    /// account id, access key id, secret access key, bucket. Resolved in
    /// `ports()` where the `Blob` port is assembled; `None` leaves
    /// presigning off.
    blob_presign: Option<(&'static str, &'static str, &'static str, &'static str)>,
    /// The Vectorize index binding backing the `VectorIndex` port
    /// (issue #561), resolved per event like KV and D1.
    vector_index_binding: Option<&'static str>,
    rate_limiter_binding: Option<&'static str>,
    /// The D1-backed per-key limiter (issue #538): the binding it reads its
    /// counters from, plus the policy mapping a key to its budget. Fills
    /// the same `RateLimiter` slot as `rate_limiter_binding`.
    d1_rate_limiter: Option<(&'static str, RateLimitPolicy)>,
    mailer: Option<Arc<dyn Mailer>>,
    push: Option<Arc<dyn Push>>,
    payments: Option<Arc<dyn Payments>>,
    tracker: Option<Arc<dyn Tracker>>,
    /// The `TextModel` port (issue #429): like `mailer` and `push`, the
    /// adapter is built from the venture's vendor keys and passed in, not
    /// resolved from a Worker binding.
    text_model: Option<Arc<dyn TextModel>>,
    /// The `Classifier` port (issue #456), the sibling of `text_model`:
    /// passed in the same way. The Workers AI adapter reads the `env.AI`
    /// binding itself, so the wiring a venture writes is identical to the
    /// native runtime's.
    classifier: Option<Arc<dyn Classifier>>,
    /// The `CustomHostnames` port (issue #590): like `mailer`, the adapter
    /// is built from the venture's vendor keys and passed in — the
    /// Cloudflare for `SaaS` adapter (`cratefield-adapter-cloudflare-saas`)
    /// is portable over the `HttpClient` port.
    custom_hostnames: Option<Arc<dyn CustomHostnames>>,
    captcha: Option<Arc<dyn Captcha>>,
    auth: Option<Arc<dyn Auth>>,
    /// Whether to assemble the `Auth` port from the environment.
    auth_from_env: bool,
    /// Whether to assemble the `Push` port from the environment
    /// (issue #191). The `Env` only exists per event, so the assembly is
    /// deferred to `ports()` and memoised for the isolate.
    #[cfg(feature = "push")]
    push_from_env: bool,
    /// Shared through an `Arc` so a clone assembles the adapters once
    /// between them, rather than parsing the `.p8`, the RSA key and the
    /// VAPID scalar again per copy.
    #[cfg(feature = "push")]
    assembled_push: Arc<std::sync::OnceLock<(Arc<dyn Push>, cratefield_push_wiring::PushWiring)>>,
}

impl Default for Cloudflare {
    fn default() -> Self {
        Self::new()
    }
}

impl Cloudflare {
    pub fn new() -> Self {
        Self {
            db_binding: None,
            kv_binding: None,
            blob_binding: None,
            blob_presign: None,
            vector_index_binding: None,
            rate_limiter_binding: None,
            d1_rate_limiter: None,
            mailer: None,
            push: None,
            payments: None,
            text_model: None,
            classifier: None,
            custom_hostnames: None,
            tracker: None,
            captcha: None,
            auth: None,
            auth_from_env: false,
            #[cfg(feature = "push")]
            push_from_env: false,
            #[cfg(feature = "push")]
            assembled_push: Arc::new(std::sync::OnceLock::new()),
        }
    }

    #[must_use]
    pub fn db(mut self, binding: &'static str) -> Self {
        self.db_binding = Some(binding);
        self
    }

    #[must_use]
    pub fn kv(mut self, binding: &'static str) -> Self {
        self.kv_binding = Some(binding);
        self
    }

    /// The R2 bucket binding backing the `Blob` port.
    #[must_use]
    pub fn blob(mut self, binding: &'static str) -> Self {
        self.blob_binding = Some(binding);
        self
    }

    /// Presigned R2 URLs on the `Blob` port (issue #622): a `GET` a browser
    /// can fetch directly from R2, skipping the Worker, and a `PUT` it can
    /// upload to — both through R2's S3-compatible API, which the binding
    /// alone cannot reach.
    ///
    /// Each argument names a Worker var or secret — the account id (the R2
    /// endpoint's subdomain), an R2 API token's access key id and secret
    /// access key, and the bucket (the endpoint's first path segment) — read
    /// from the request's `Env` (secrets first, then vars). The `Env` exists
    /// only per request, so the values cannot be resolved at compose time.
    /// Scope the R2 token to the one bucket this port serves: a token that
    /// reaches every bucket in the account reads every tenant's media.
    ///
    /// Without this call, or with any value missing or empty at request time,
    /// presigning stays off and both presign methods answer
    /// [`BlobError::Unsupported`](cratefield_core::BlobError::Unsupported).
    #[must_use]
    pub fn blob_presign(
        mut self,
        account_id: &'static str,
        access_key_id: &'static str,
        secret_access_key: &'static str,
        bucket: &'static str,
    ) -> Self {
        self.blob_presign = Some((account_id, access_key_id, secret_access_key, bucket));
        self
    }

    /// The Vectorize index binding backing the `VectorIndex` port (issue
    /// #561): nearest-neighbour search, one namespace per tenant. A
    /// deployment without the binding leaves the port unwired.
    #[must_use]
    pub fn vector_index(mut self, binding: &'static str) -> Self {
        self.vector_index_binding = Some(binding);
        self
    }

    #[must_use]
    pub fn rate_limiter(mut self, binding: &'static str) -> Self {
        self.rate_limiter_binding = Some(binding);
        self
    }

    /// The `RateLimiter` port over D1 (issue #538): a fixed window per key,
    /// one atomic upsert per request ([`D1RateLimiter`]), so the budget can
    /// vary per key — the Workers Rate Limiting binding above is one limit
    /// per namespace. The policy maps a key to its [`Limit`]; `None` means
    /// unlimited, allowed without a D1 round trip. Encode the plan in the
    /// key (`plan:pro:ip:203.0.113.7`) and match on the prefix.
    ///
    /// Fills the same port slot as [`rate_limiter`](Self::rate_limiter);
    /// where both are wired, this one wins. The counters table ships as
    /// `RATE_LIMIT_COUNTERS_SQL`: add it to the venture's `migrations/`
    /// directory.
    #[must_use]
    pub fn d1_rate_limiter(
        mut self,
        binding: &'static str,
        policy: impl Fn(&str) -> Option<Limit> + Send + Sync + 'static,
    ) -> Self {
        self.d1_rate_limiter = Some((binding, Arc::new(policy)));
        self
    }

    #[must_use]
    pub fn mailer(mut self, mailer: impl Mailer + 'static) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }

    #[must_use]
    pub fn mailer_arc(mut self, mailer: Arc<dyn Mailer>) -> Self {
        self.mailer = Some(mailer);
        self
    }

    /// The `Push` port. Like `mailer`, the adapter is built from the
    /// venture's secrets (`cratefield-adapter-apns` from an APNs `.p8`) and
    /// passed in, not resolved from a Worker binding.
    #[must_use]
    pub fn push(mut self, push: impl Push + 'static) -> Self {
        self.push = Some(Arc::new(push));
        self
    }

    #[must_use]
    pub fn push_arc(mut self, push: Arc<dyn Push>) -> Self {
        self.push = Some(push);
        self
    }

    /// Assembles the `Push` port from the venture's environment instead of
    /// taking an adapter (issue #191): one `RoutingPush` over whichever of
    /// APNs, FCM and Web Push the deployment configured, built once per
    /// isolate by `cratefield_push_wiring::build_push` — the same function
    /// `fz push` and `fz doctor` call, so the three cannot drift apart on a
    /// variable name.
    ///
    /// The port is then always provided, even with nothing configured: the
    /// router answers `NotConfigured` for every recipient, exactly as an
    /// unconfigured adapter does. `serve()` logs the resulting
    /// [`PushWiring`](cratefield_push_wiring::PushWiring) report once at cold
    /// start, and an explicit `.push(..)`/`.push_arc(..)` still wins.
    ///
    /// # This is a declaration, and `fz doctor` is what checks it
    ///
    /// `Harness::build` asks the runtime for its ports before any `Env`
    /// exists — a Worker's bindings arrive with the first fetch — so the
    /// build cannot know whether this deployment configured a transport.
    /// Calling this therefore *declares* the Push port: a module that
    /// requires push builds against it either way.
    ///
    /// `fz doctor` is the gate that used to be the build's. It runs where
    /// the deployment's environment is known, and refuses a production
    /// venture whose modules require push and whose environment routes no
    /// transport at all (issue #191).
    #[cfg(feature = "push")]
    #[must_use]
    pub fn push_from_env(mut self) -> Self {
        self.push_from_env = true;
        self
    }

    /// The environment-assembled `Push` port and its report, built once per
    /// isolate.
    ///
    /// `None` when the venture did not ask for it — **and** when it passed
    /// an explicit adapter, which wins: assembling a stack of adapters
    /// nothing will serve with costs a `.p8` parse, an RSA parse and a VAPID
    /// scalar per isolate, and then reports on transports the venture
    /// deliberately overrode.
    #[cfg(feature = "push")]
    fn env_push(&self, env: &Env) -> Option<&(Arc<dyn Push>, cratefield_push_wiring::PushWiring)> {
        if !self.push_from_env || self.push.is_some() {
            return None;
        }
        Some(self.assembled_push.get_or_init(|| {
            let clock: Arc<dyn Clock> = Arc::new(WorkersClock);
            let http: Arc<dyn cratefield_core::HttpClient> = Arc::new(BoundedHttpClient::new(
                Arc::new(FetchClient),
                Arc::clone(&clock),
            ));
            cratefield_push_wiring::build_push(&EnvConfig(env.clone()), &http, &clock)
        }))
    }

    /// Which push transports this deployment configured. `serve()` logs this
    /// at cold start; nothing else needs it.
    ///
    /// `None` when the venture did not call
    /// [`push_from_env`](Self::push_from_env), or passed an explicit adapter
    /// that wins over it — there is nothing to report about an environment
    /// nothing reads.
    ///
    /// Call it *after* `ports()`, as `serve()` does: `ports()` has then
    /// already assembled and memoised the adapters, and this is the getter
    /// it looks like.
    #[cfg(feature = "push")]
    #[must_use]
    pub fn push_wiring(&self, env: &Env) -> Option<&cratefield_push_wiring::PushWiring> {
        self.env_push(env).map(|(_, wiring)| wiring)
    }

    /// The `Payments` port. Like `mailer`, the adapter is built from the
    /// venture's secrets (`cratefield-adapter-stripe` from the Stripe keys)
    /// and passed in, not resolved from a Worker binding.
    #[must_use]
    pub fn payments(mut self, payments: impl Payments + 'static) -> Self {
        self.payments = Some(Arc::new(payments));
        self
    }

    #[must_use]
    pub fn payments_arc(mut self, payments: Arc<dyn Payments>) -> Self {
        self.payments = Some(payments);
        self
    }

    /// The `Tracker` port. Like `mailer` and `payments`, the adapter is
    /// built by the venture and passed in, not resolved from a Worker
    /// binding.
    ///
    /// Unlike those adapters, it holds no credential: which tracker to file
    /// into and under whose token are tenant data, supplied per call by the
    /// module that files — see [`cratefield_core::Tracker`] for why that
    /// differs from the Resend/Stripe shape.
    #[must_use]
    pub fn tracker(mut self, tracker: impl Tracker + 'static) -> Self {
        self.tracker = Some(Arc::new(tracker));
        self
    }

    /// `tracker` for an already-shared adapter.
    #[must_use]
    pub fn tracker_arc(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.tracker = Some(tracker);
        self
    }

    /// The `TextModel` port (issue #429): an adapter over the venture's
    /// vendor of choice for each [`ModelTier`](cratefield_core::ModelTier),
    /// or one `RoutingTextModel` over both tiers. Passed in, not resolved
    /// from a Worker binding — there is no vendor-neutral binding to sniff
    /// out of the environment.
    #[must_use]
    pub fn text_model(mut self, text_model: impl TextModel + 'static) -> Self {
        self.text_model = Some(Arc::new(text_model));
        self
    }

    #[must_use]
    pub fn text_model_arc(mut self, text_model: Arc<dyn TextModel>) -> Self {
        self.text_model = Some(text_model);
        self
    }

    /// The `Classifier` port (issue #456): a typed, calibrated decision —
    /// "which of these is it, and how sure are you" — passed in like
    /// `text_model`. An adapter over the Workers AI `env.AI` binding is
    /// still built by the venture and handed here, so there is no new
    /// binding name to learn.
    #[must_use]
    pub fn classifier(mut self, classifier: impl Classifier + 'static) -> Self {
        self.classifier = Some(Arc::new(classifier));
        self
    }

    /// `classifier` for an already-shared adapter.
    #[must_use]
    pub fn classifier_arc(mut self, classifier: Arc<dyn Classifier>) -> Self {
        self.classifier = Some(classifier);
        self
    }

    /// The `CustomHostnames` port (issue #590): a customer's own hostname
    /// served by a venture, passed in like `mailer`. The Cloudflare for
    /// `SaaS` adapter is `cratefield-adapter-cloudflare-saas`, portable over
    /// the `HttpClient` port, so this is the same wiring on either runtime.
    #[must_use]
    pub fn custom_hostnames(mut self, custom_hostnames: impl CustomHostnames + 'static) -> Self {
        self.custom_hostnames = Some(Arc::new(custom_hostnames));
        self
    }

    /// `custom_hostnames` for an already-shared adapter.
    #[must_use]
    pub fn custom_hostnames_arc(mut self, custom_hostnames: Arc<dyn CustomHostnames>) -> Self {
        self.custom_hostnames = Some(custom_hostnames);
        self
    }

    #[must_use]
    pub fn captcha(mut self, captcha: impl Captcha + 'static) -> Self {
        self.captcha = Some(Arc::new(captcha));
        self
    }

    /// Wires who a request's credentials speak for (issue #153).
    ///
    /// Without one the deployment cannot identify a caller, and a module
    /// that declares [`Port::Auth`] is refused composition rather than
    /// mounted and left guessing.
    #[must_use]
    pub fn auth(mut self, auth: impl Auth + 'static) -> Self {
        self.auth = Some(Arc::new(auth));
        self
    }

    #[must_use]
    pub fn auth_arc(mut self, auth: Arc<dyn Auth>) -> Self {
        self.auth = Some(auth);
        self
    }

    /// The clock, the HTTP client built on it, and the verifier built on
    /// both — the verifier fetches the issuer's key set over HTTP and
    /// dates the tokens by the clock, so it comes after them.
    ///
    /// Its own method because `ports` is at clippy's line limit.
    fn clock_http_and_auth(&self, ports: &mut Ports) {
        let clock: Arc<dyn Clock> = Arc::new(WorkersClock);
        ports.clock = Some(Arc::clone(&clock));
        let http: Arc<dyn cratefield_core::HttpClient> = Arc::new(BoundedHttpClient::new(
            Arc::new(FetchClient),
            Arc::clone(&clock),
        ));
        ports.http = Some(Arc::clone(&http));
        if ports.auth.is_none() && self.auth_from_env {
            ports.auth = Some(cratefield_auth_client::from_config(
                ports.config.as_ref(),
                http,
                clock,
            ));
        }
    }

    /// The two `RateLimiter` sources: the Workers Rate Limiting binding
    /// (one limit per namespace) and the D1-backed per-key limiter over a
    /// D1 binding (issue #538), which wins where both are wired — the
    /// per-key policy is what a venture with plans needs, the binding is
    /// the cheaper default.
    ///
    /// Its own method because `ports` is at clippy's line limit.
    fn rate_limiter_port(&self, env: &Env, ports: &mut Ports) {
        if let Some(name) = self.rate_limiter_binding {
            match env.rate_limiter(name) {
                Ok(limiter) => ports.rate_limiter = Some(Arc::new(RateLimitPort(limiter))),
                Err(err) => warn_once(
                    &WARNED_RATE_LIMIT,
                    &format!("Rate limit binding {name:?} not available: {err}"),
                ),
            }
        }
        if let Some((name, policy)) = &self.d1_rate_limiter {
            match env.d1(name) {
                Ok(db) => {
                    ports.rate_limiter = Some(Arc::new(D1RateLimiter::new(db, Arc::clone(policy))));
                }
                Err(err) => warn_once(
                    &WARNED_RATE_LIMIT,
                    &format!("D1 rate limit binding {name:?} not available: {err}"),
                ),
            }
        }
    }

    /// The `/v1/*` refusal when a limiter binding is **named** on this
    /// runtime but resolved to nothing (issue #562): the detail of the
    /// problem the serve path answers with, or `None` to serve.
    ///
    /// Composition named a binding, so the venture was written to be
    /// throttled; a deployment where that binding is missing from the
    /// uploaded Worker (or is the wrong type) used to degrade to no
    /// limiter with only a warning — `ports.rate_limiter == None`, which
    /// `production_readiness` reads as "not readiness" and refuses in
    /// production, but which served **unlimited** everywhere a deployment
    /// did not declare production. Failing closed here closes that gap in
    /// every environment while leaving the readiness semantics alone: an
    /// advertised-but-unresolved limiter is still not readiness.
    #[must_use]
    pub(crate) fn unresolved_limiter_refusal(&self, resolved: bool) -> Option<String> {
        let mut named: Vec<&str> = Vec::new();
        if let Some(name) = self.rate_limiter_binding {
            named.push(name);
        }
        if let Some((name, _)) = &self.d1_rate_limiter {
            named.push(name);
        }
        missing_limiter_detail(&named, resolved)
    }

    /// The `VectorIndex` port over a Vectorize index binding (issue #561).
    ///
    /// Its own method because `ports` is at clippy's line limit.
    fn vector_index_port(&self, env: &Env, ports: &mut Ports) {
        if let Some(name) = self.vector_index_binding {
            match vector_index_from_env(env, name) {
                Some(index) => ports.vector_index = Some(index),
                None => warn_once(
                    &WARNED_VECTOR_INDEX,
                    &format!("Vectorize index binding {name:?} not available"),
                ),
            }
        }
    }

    /// The R2 presigning seam (issue #622): the four names
    /// [`blob_presign`](Self::blob_presign) stored, resolved from this
    /// request's `Env`.
    ///
    /// `None` — presigning off — when the venture never called `blob_presign`
    /// (silently: it did not ask for it) or when any value is missing or empty
    /// (logged once per isolate, by name, never by value).
    fn r2_presigner(&self, env: &Env) -> Option<R2Presigner> {
        let (account_id_name, access_key_name, secret_name, bucket_name) = self.blob_presign?;
        let config = EnvConfig(env.clone());
        let read =
            |name: &'static str| Config::get(&config, name).filter(|value| !value.is_empty());
        let (Some(account_id), Some(access_key_id), Some(secret_access_key), Some(bucket)) = (
            read(account_id_name),
            read(access_key_name),
            read(secret_name),
            read(bucket_name),
        ) else {
            warn_once(
                &WARNED_BLOB_PRESIGN,
                "blob_presign is wired but a value it named is missing or empty in this \
                 deployment's environment: R2 presigning stays off, and the bytes are served \
                 through the harness",
            );
            return None;
        };
        Some(R2Presigner::new(
            account_id,
            bucket,
            Credentials::new(access_key_id, secret_access_key),
            Arc::new(WorkersClock),
        ))
    }

    /// Assembles the `Auth` port from `AUTH_ISSUER` and `AUTH_CLIENT_ID`
    /// (issue #153), the way `push_from_env` assembles push.
    ///
    /// The port is provided either way. The `Env` exists per request on
    /// Workers, so a runtime cannot know at compose time whether the
    /// issuer is set, and refusing to provide the port would make every
    /// such deployment fail to boot — including the ones whose tables are
    /// all public. With the variables unset the port is a
    /// `cratefield_core::Unconfigured`, which answers 503 to a request
    /// that presents a credential and leaves an anonymous one anonymous.
    #[must_use]
    pub fn auth_from_env(mut self) -> Self {
        self.auth_from_env = true;
        self
    }

    #[must_use]
    pub fn captcha_arc(mut self, captcha: Arc<dyn Captcha>) -> Self {
        self.captcha = Some(captcha);
        self
    }

    /// Resolves the per-request `Ports` from the actual bindings and the
    /// event's `wait_until` context. Absent optional bindings leave the
    /// port `None` (logged once per isolate); a missing `HARNESS_SECRET`
    /// leaves `Signer` unset the same way.
    pub fn ports(&self, env: &Env, defer: Arc<dyn Defer>) -> Ports {
        let mut ports = Ports::with_config(Arc::new(EnvConfig(env.clone())));

        if let Some(name) = self.db_binding {
            match env.d1(name) {
                Ok(db) => ports.db = Some(Arc::new(D1Database(db))),
                Err(err) => warn_once(
                    &WARNED_DB,
                    &format!("D1 binding {name:?} not available: {err}"),
                ),
            }
        }
        if let Some(name) = self.blob_binding {
            match env.bucket(name) {
                Ok(bucket) => {
                    ports.blob = Some(Arc::new(R2Blob::new(bucket, self.r2_presigner(env))));
                }
                Err(err) => warn_once(
                    &WARNED_BLOB,
                    &format!("R2 bucket binding {name:?} not available: {err}"),
                ),
            }
        }
        if let Some(name) = self.kv_binding {
            match env.kv(name) {
                Ok(kv) => ports.kv = Some(Arc::new(KvStorePort(kv))),
                Err(err) => warn_once(
                    &WARNED_KV,
                    &format!("KV binding {name:?} not available: {err}"),
                ),
            }
        }
        self.rate_limiter_port(env, &mut ports);
        self.vector_index_port(env, &mut ports);

        match HarnessConfig::from_config(&EnvConfig(env.clone())) {
            Ok(config) => {
                // Key logged email pseudonyms from the harness secret (#135).
                cratefield_core::set_log_pseudonym_key(config.harness_secret.as_bytes());
                ports.signer = Some(Arc::new(config.signer()));
            }
            Err(err) => warn_once(&WARNED_SIGNER, &format!("Signer port not provided: {err}")),
        }

        // Sidecar bindings come from the mount table in config, not from the
        // composition (ADR 0009), so the same artifact serves ventures with
        // and without sidecars. A binding named by the table but absent from
        // this deployment is left unresolved: `has()` then reports false and
        // that one prefix answers 503, rather than the Worker failing.
        match SidecarMounts::from_config(&EnvConfig(env.clone())) {
            Ok(mounts) if !mounts.is_empty() => {
                let mut bindings = BTreeMap::new();
                for mount in mounts.iter() {
                    match env.service(&mount.binding) {
                        Ok(fetcher) => {
                            bindings.insert(mount.binding.clone(), fetcher);
                        }
                        Err(err) => warn_once(
                            &WARNED_SIDECAR,
                            &format!(
                                "service binding {:?} for sidecar {:?} not available: {err}",
                                mount.binding, mount.name
                            ),
                        ),
                    }
                }
                ports.dispatcher = Some(Arc::new(ServiceDispatcher::new(bindings)));
            }
            Ok(_) => {}
            Err(errors) => {
                for error in errors {
                    warn_once(&WARNED_SIDECAR, &error);
                }
            }
        }

        self.clock_http_and_auth(&mut ports);
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ports.defer = Some(defer);
        ports.mailer.clone_from(&self.mailer);
        ports.push.clone_from(&self.push);
        ports.payments.clone_from(&self.payments);
        ports.tracker.clone_from(&self.tracker);
        ports.text_model.clone_from(&self.text_model);
        ports.classifier.clone_from(&self.classifier);
        ports.custom_hostnames.clone_from(&self.custom_hostnames);
        ports.captcha.clone_from(&self.captcha);
        // Only when set: `clock_http_and_auth` may already have assembled
        // `ports.auth` from `AUTH_ISSUER` + `AUTH_CLIENT_ID` under
        // `auth_from_env`, and `Option::clone_from(None)` would wipe it —
        // leaving every `Port::Auth` route with `no-verifier`.
        if let Some(auth) = &self.auth {
            ports.auth = Some(Arc::clone(auth));
        }

        // An explicit adapter wins; otherwise assemble one from the
        // environment when the venture asked for it (issue #191).
        #[cfg(feature = "push")]
        if ports.push.is_none()
            && let Some((push, _)) = self.env_push(env)
        {
            ports.push = Some(Arc::clone(push));
        }

        ports
    }
}

impl Runtime for Cloudflare {
    /// The static set used by `Harness::build`. `Signer` is included: its
    /// presence is validated at `ports()` time (and by `fz doctor`).
    fn provides(&self) -> Vec<Port> {
        let mut provided = vec![
            Port::Signer,
            Port::HttpClient,
            Port::Clock,
            Port::IdGen,
            Port::Defer,
        ];
        if self.db_binding.is_some() {
            provided.push(Port::Db);
        }
        if self.kv_binding.is_some() {
            provided.push(Port::KeyValue);
        }
        if self.blob_binding.is_some() {
            provided.push(Port::Blob);
        }
        if self.vector_index_binding.is_some() {
            provided.push(Port::VectorIndex);
        }
        if self.rate_limiter_binding.is_some() || self.d1_rate_limiter.is_some() {
            provided.push(Port::RateLimiter);
        }
        if self.mailer.is_some() {
            provided.push(Port::Mailer);
        }
        // `push_from_env` provides the port whatever the environment holds:
        // with nothing configured the router answers `NotConfigured` for
        // every recipient, which is a provided port that sends nothing, not
        // an absent one (issue #191).
        //
        // It cannot be otherwise here. `provides()` runs inside
        // `Harness::build`, and a Worker's `Env` does not exist until the
        // first fetch, so there is nothing to consult. That does move a
        // check: a module requiring push used to fail the build on a venture
        // with no push wiring, and now builds. `fz doctor` carries that
        // refusal instead, where the deployment's environment is readable —
        // see `push_from_env`.
        #[cfg(feature = "push")]
        let push_provided = self.push.is_some() || self.push_from_env;
        #[cfg(not(feature = "push"))]
        let push_provided = self.push.is_some();
        if push_provided {
            provided.push(Port::Push);
        }
        if self.payments.is_some() {
            provided.push(Port::Payments);
        }
        if self.tracker.is_some() {
            provided.push(Port::Tracker);
        }
        if self.text_model.is_some() {
            provided.push(Port::TextModel);
        }
        if self.classifier.is_some() {
            provided.push(Port::Classifier);
        }
        if self.custom_hostnames.is_some() {
            provided.push(Port::CustomHostnames);
        }
        // Provided whatever the environment holds — see `auth_from_env`.
        if self.auth.is_some() || self.auth_from_env {
            provided.push(Port::Auth);
        }
        if self.captcha.is_some() {
            provided.push(Port::Captcha);
        }
        provided
    }

    /// `Harness::build` gate (issue #133): a Turnstile adapter that is not
    /// hostname-bound, or left fail-open, cannot verify a production
    /// `HumanForm` route — the port is present but not usable, so report
    /// it as not effectively configured. Adapters that do not report
    /// (`binding() == None`) count as effective when present: presence is
    /// all the runtime can know about them.
    fn effectively_configured(&self, port: Port) -> bool {
        match port {
            // `is_none_or`, not `is_some_and`: the doc above and the
            // `Captcha::binding` contract both say a non-reporting adapter
            // counts as effective when present, and the code said the
            // opposite — so a venture with any Captcha adapter that does
            // not report could not boot in production (issue #143).
            Port::Captcha => self.captcha.as_ref().is_some_and(|captcha| {
                captcha
                    .binding()
                    .is_none_or(|binding| binding.hostname_bound && !binding.fail_open)
            }),
            _ => self.provides().contains(&port),
        }
    }
}

/// The fail-closed decision behind
/// [`Cloudflare::unresolved_limiter_refusal`](crate::Cloudflare::unresolved_limiter_refusal),
/// pure so it can be unit-tested off-wasm: bindings are named on the
/// runtime, `resolved` says whether any of them actually handed a limiter
/// over.
/// Nothing named is the composition choosing to run without one — not a
/// failure here, and readiness is the gate that judges it in production.
fn missing_limiter_detail(named: &[&str], resolved: bool) -> Option<String> {
    if named.is_empty() || resolved {
        return None;
    }
    let quoted = named
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "rate limit binding {quoted} is configured on this Worker but did not resolve at \
         request time: /v1/* is refused rather than served without a budget — the binding is \
         missing from this deployment or is the wrong type, and the readiness gate would \
         refuse it in production all the same (issue #562)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use cratefield_core::{
        Answer, Calibration, ClassifierError, ClassifierProfile, Credential, Destination, Filed,
        Harness, Question, TicketDraft, TicketState, TicketStatus, TrackerError, Venture,
        VentureEnv,
    };

    /// Stands in for an adapter the venture passed itself. Answers the
    /// cheapest thing that satisfies the trait; what these tests assert is
    /// wiring, not adapter behaviour.
    struct StubTracker;

    #[async_trait::async_trait]
    impl Tracker for StubTracker {
        async fn file(
            &self,
            _dest: &Destination,
            _cred: &Credential,
            _draft: &TicketDraft,
        ) -> Result<Filed, TrackerError> {
            Err(TrackerError::NotConfigured)
        }

        async fn status(
            &self,
            _dest: &Destination,
            _cred: &Credential,
            external_id: &str,
        ) -> Result<TicketStatus, TrackerError> {
            Ok(TicketStatus {
                external_id: external_id.to_owned(),
                state: TicketState::Open,
                url: None,
            })
        }
    }

    // `ports()` cannot be exercised here: it needs a `worker::Env`, which
    // only exists per fetch on a Workers isolate. The clone into the bundle
    // is the same one line `payments` does.

    // ------------------------------------------- fail-closed limiter (#562)

    #[test]
    fn a_named_but_unresolved_limiter_binding_refuses() {
        let detail = missing_limiter_detail(&["RATE_LIMITER"], false)
            .expect("a named, unresolved binding refuses");
        assert!(detail.contains("RATE_LIMITER"), "{detail}");
        assert!(detail.contains("not resolve"), "{detail}");

        // Both limiter sources named and neither resolved: both named.
        let detail = missing_limiter_detail(&["RATE_LIMITER", "RATE_LIMIT_COUNTERS"], false)
            .expect("neither source resolved");
        assert!(detail.contains("RATE_LIMITER"), "{detail}");
        assert!(detail.contains("RATE_LIMIT_COUNTERS"), "{detail}");
    }

    #[test]
    fn an_unnamed_limiter_binding_is_not_a_refusal() {
        // No binding named is the composition choosing to run without a
        // limiter — readiness's business in production, not the serve
        // path's in every environment.
        assert_eq!(missing_limiter_detail(&[], false), None);
    }

    #[test]
    fn a_resolved_limiter_binding_serves() {
        assert_eq!(missing_limiter_detail(&["RATE_LIMITER"], true), None);
        // Both sources named, the D1 one winning: resolved is resolved.
        assert_eq!(
            missing_limiter_detail(&["RATE_LIMITER", "RATE_LIMIT_COUNTERS"], true),
            None
        );
    }

    #[test]
    fn the_refusal_follows_exactly_the_named_bindings() {
        // Through the accessor the serve path uses: nothing configured on
        // the runtime, serve; the Workers binding configured, refuse only
        // when nothing resolved.
        assert_eq!(Cloudflare::new().unresolved_limiter_refusal(false), None);
        assert!(
            Cloudflare::new()
                .rate_limiter("RATE_LIMITER")
                .unresolved_limiter_refusal(false)
                .is_some()
        );
        assert_eq!(
            Cloudflare::new()
                .rate_limiter("RATE_LIMITER")
                .unresolved_limiter_refusal(true),
            None
        );
    }

    #[test]
    fn a_runtime_with_no_tracker_provides_no_tracker_port() {
        assert!(!Cloudflare::new().provides().contains(&Port::Tracker));
    }

    /// A public read published by a module that declares the limiter port
    /// (issue #562) — the shape of every waitlist/auth composition.
    struct DeclaresLimiter;

    impl cratefield_core::Module for DeclaresLimiter {
        fn name(&self) -> &'static str {
            "search"
        }
        fn version(&self) -> &'static str {
            "0.0.0-test"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn optional(&self) -> &'static [Port] {
            &[Port::RateLimiter]
        }
        fn migrations(&self) -> cratefield_core::Migrations {
            cratefield_core::Migrations::default()
        }
        fn validate_config(
            &self,
            _: &dyn cratefield_core::Config,
        ) -> Result<(), cratefield_core::ConfigError> {
            Ok(())
        }
        fn surface(&self) -> cratefield_core::Surface {
            cratefield_core::Surface::new().action(
                cratefield_core::Action::get("search", "/search")
                    .audience(cratefield_core::Audience::Public),
            )
        }
        fn router(&self, _: cratefield_core::ModuleContext) -> axum::Router {
            axum::Router::new()
        }
    }

    #[test]
    fn a_production_harness_without_a_limiter_binding_fails_to_build_naming_the_module() {
        let error = Harness::builder()
            .venture(
                Venture::new("venture", "test.example")
                    .cors_origins(["https://test.example"])
                    .env(VentureEnv::Production),
            )
            .module(DeclaresLimiter)
            .runtime(Cloudflare::new())
            .build()
            .expect_err("no limiter binding named: the build refuses");
        let message = error.problems.join("\n");
        assert!(message.contains("search"), "{message}");
        assert!(message.contains("GET /v1/search/search"), "{message}");

        // The binding named: the build-time leg reads the runtime's own
        // answer, which is provisionally satisfied — resolution at request
        // time is the serve path's fail-closed rule.
        Harness::builder()
            .venture(
                Venture::new("venture", "test.example")
                    .cors_origins(["https://test.example"])
                    .env(VentureEnv::Production),
            )
            .module(DeclaresLimiter)
            .runtime(Cloudflare::new().rate_limiter("RATE_LIMITER"))
            .build()
            .expect("a named binding satisfies the build-time limiter leg");
    }

    #[test]
    fn a_wired_tracker_is_provided_by_either_builder_form() {
        assert!(
            Cloudflare::new()
                .tracker(StubTracker)
                .provides()
                .contains(&Port::Tracker)
        );
        assert!(
            Cloudflare::new()
                .tracker_arc(Arc::new(StubTracker))
                .provides()
                .contains(&Port::Tracker)
        );
    }

    /// Stands in for an adapter the venture passed itself — a
    /// `cratefield-adapter-workers-ai` or `cratefield-adapter-typesafe`,
    /// say. Answers the cheapest thing that satisfies the trait; what
    /// these tests assert is wiring, not adapter behaviour.
    struct StubClassifier;

    #[async_trait::async_trait]
    impl Classifier for StubClassifier {
        fn profile(&self) -> ClassifierProfile {
            ClassifierProfile::new(Calibration::LanguageModel, 1_000)
        }

        async fn ask(
            &self,
            _state: &str,
            _questions: &BTreeMap<String, Question>,
        ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
            Err(ClassifierError::NotConfigured)
        }
    }

    #[test]
    fn a_runtime_with_no_classifier_provides_no_classifier_port() {
        assert!(!Cloudflare::new().provides().contains(&Port::Classifier));
    }

    #[test]
    fn a_vector_index_binding_is_provided_by_name() {
        // Like `.kv(..)`: the builder stores a binding name, resolved per
        // event in `ports()`, which needs a live `Env`.
        assert!(
            Cloudflare::new()
                .vector_index("VINDEX")
                .provides()
                .contains(&Port::VectorIndex)
        );
        assert!(!Cloudflare::new().provides().contains(&Port::VectorIndex));
    }

    #[test]
    fn a_wired_classifier_is_provided_by_either_builder_form() {
        assert!(
            Cloudflare::new()
                .classifier(StubClassifier)
                .provides()
                .contains(&Port::Classifier)
        );
        assert!(
            Cloudflare::new()
                .classifier_arc(Arc::new(StubClassifier))
                .provides()
                .contains(&Port::Classifier)
        );
    }
}
