//! Port traits (ADR 0002, architecture section 5). Modules see these traits
//! and nothing else — never a Cloudflare binding, never a vendor client.
//!
//! All traits are `Send + Sync` and object-safe, used as `Arc<dyn Trait>`.
//! Async methods use `async_trait` until native `async fn` in traits is
//! ergonomic for trait objects.

mod auth;
mod blob;
mod captcha;
mod classifier;
mod clock;
mod custom_hostnames;
mod database;
mod defer;
mod dispatcher;
mod embedder;
mod http;
mod idgen;
mod kv;
mod mailer;
mod payments;
mod push;
mod rate_limiter;
mod realtime;
pub(crate) mod signer;
mod text_model;
mod tracker;
mod vector_index;

pub use auth::{Auth, AuthError, Caller, Subject, Unconfigured};
pub use blob::{
    Blob, BlobError, BlobObject, DEFAULT_PRESIGN_TTL, MAX_BLOB_BYTES, MAX_PRESIGN_TTL,
    PresignedPut, ScopedBlob, check_blob_size,
};
pub use captcha::{Captcha, CaptchaBinding, CaptchaError, Verdict};
pub use classifier::{
    Answer, AnswerValue, Calibration, Classifier, ClassifierError, ClassifierProfile,
    DEFAULT_MAX_STATE_CHARS, Question, validate_questions,
};
pub use clock::{Clock, SystemClock, timeout};
pub use custom_hostnames::{
    CertificateStatus, CustomHostname, CustomHostnameError, CustomHostnames, DnsRecordType,
    HostnameClaim, HostnameRefusal, ProviderStatus, Validation, ValidationMethod, check_hostname,
};
pub use database::{Database, DbError, Row, Rows, Statement, TryFromValue};
pub use defer::{Defer, NoopDefer};
pub use dispatcher::{DispatchError, Dispatcher};
pub use embedder::{EmbedError, Embedder, Embeddings};
pub use http::{
    BoundedHttpClient, DEFAULT_RESPONSE_TIMEOUT, HttpClient, HttpError, HttpPolicy,
    MAX_CONCURRENT_REQUESTS, MAX_RESPONSE_BYTES, MAX_RESPONSE_TIMEOUT, declared_content_length,
};
pub use idgen::{IdGen, UlidIdGen};
pub use kv::{KeyValue, KvError};
pub use mailer::{MailError, Mailer, Message, SendOutcome};
pub use payments::{
    Charge, CheckoutRequest, CheckoutSession, ConnectAccountLink, ConnectAccountLinkRequest,
    Dispute, DisputeListRequest, DisputePage, DisputePhase, DisputeStatus, LineItem, Money,
    Payments, PaymentsError, PortalSession, PortalSessionRequest, Refund, RefundRequest,
    SubscriptionCheckoutRequest, TransferCharge, UsageReport, UsageReported, WebhookEvent,
};
pub use push::{
    LocKeys, Notification, Platform, Priority, Push, PushError, PushOutcome, Recipient,
    RoutingPush, retry_after, ttl_secs,
};
pub use rate_limiter::{Decision, Quota, RateLimitError, RateLimiter};
pub use realtime::{Member, Realtime, RealtimeError, RoomContext, RoomHandler};
pub use signer::{Kid, MAX_KID_NAME, Payload, SignatureError, Signer};
pub use text_model::{
    Capability, Completion, DEFAULT_MAX_TOKENS, ModelTier, Prompt, Role, RoutingTextModel,
    TextModel, TextModelError, ToolCall, ToolChoice, ToolResult, ToolSpec, Turn,
};
pub use tracker::{
    Credential, Destination, Filed, InboundStatusError, RoutingTracker, Severity, StatusUpdate,
    StatusWebhook, TicketComment, TicketDraft, TicketState, TicketStatus, Tracker, TrackerError,
    receive_status,
};
pub use vector_index::{
    ExactVectorIndex, MAX_NAMESPACE_BYTES, VectorFilter, VectorIndex, VectorIndexError,
    VectorMatch, VectorNamespace, VectorRecord,
};

use crate::config::Config;
use crate::module::Module;
use std::sync::Arc;
use tracing::warn;

/// Every port a module can declare in `requires()` / `optional()`
/// (architecture section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Port {
    Db,
    Auth,
    Mailer,
    Captcha,
    RateLimiter,
    Signer,
    KeyValue,
    Blob,
    Push,
    Payments,
    Tracker,
    Realtime,
    TextModel,
    Classifier,
    VectorIndex,
    Embedder,
    CustomHostnames,
    HttpClient,
    Clock,
    IdGen,
    Defer,
}

/// Declares [`Port::ALL`] and, from the same list, a match that has to be
/// exhaustive.
///
/// `ALL` is walked by [`Ports::provides`], so a variant missing from it
/// is a port no bundle ever reports — which is exactly the bug that left
/// `Port::Auth` out of `provides` when that was fifteen hand-written
/// branches. Writing the list twice is what made it possible; writing it
/// once is what stops it.
///
/// `#[non_exhaustive]` does not make an in-crate match non-exhaustive, so
/// the check is real here even though a downstream `match` on `Port`
/// needs a wildcard.
macro_rules! ports {
    ($($variant:ident),+ $(,)?) => {
        impl Port {
            /// Every port.
            pub const ALL: &'static [Port] = &[$(Port::$variant),+];
        }

        /// Never called. It exists so that a variant absent from the list
        /// above is a compile error here.
        #[expect(dead_code, reason = "its only job is to be exhaustive")]
        fn every_port_is_in_all(port: Port) {
            match port {
                $(Port::$variant => {}),+
            }
        }
    };
}

ports!(
    Db,
    Auth,
    Mailer,
    Captcha,
    RateLimiter,
    Signer,
    KeyValue,
    Blob,
    Push,
    Payments,
    Tracker,
    Realtime,
    TextModel,
    Classifier,
    VectorIndex,
    Embedder,
    CustomHostnames,
    HttpClient,
    Clock,
    IdGen,
    Defer,
);

impl Port {
    pub fn name(&self) -> &'static str {
        match self {
            Port::Db => "Database",
            Port::Auth => "Auth",
            Port::Mailer => "Mailer",
            Port::Captcha => "Captcha",
            Port::RateLimiter => "RateLimiter",
            Port::Signer => "Signer",
            Port::KeyValue => "KeyValue",
            Port::Blob => "Blob",
            Port::Push => "Push",
            Port::Payments => "Payments",
            Port::Tracker => "Tracker",
            Port::Realtime => "Realtime",
            Port::TextModel => "TextModel",
            Port::Classifier => "Classifier",
            Port::VectorIndex => "vector_index",
            Port::Embedder => "embedder",
            Port::CustomHostnames => "custom_hostnames",
            Port::HttpClient => "HttpClient",
            Port::Clock => "Clock",
            Port::IdGen => "IdGen",
            Port::Defer => "Defer",
        }
    }
}

/// The per-request bundle of resolved port implementations plus the typed
/// config the runtime built from environment/secrets.
///
/// Every port is optional: the Cloudflare runtime resolves what the venture's
/// bindings actually provide and leaves the rest `None`.
pub struct Ports {
    pub config: Arc<dyn Config>,
    pub db: Option<Arc<dyn Database>>,
    /// Who a request's credentials speak for (issue #153). `None` is a
    /// deployment that cannot identify a caller at all; a module needing
    /// one declares [`Port::Auth`] and is refused composition here.
    pub auth: Option<Arc<dyn Auth>>,
    pub mailer: Option<Arc<dyn Mailer>>,
    pub captcha: Option<Arc<dyn Captcha>>,
    pub rate_limiter: Option<Arc<dyn RateLimiter>>,
    pub signer: Option<Arc<dyn Signer>>,
    pub kv: Option<Arc<dyn KeyValue>>,
    pub blob: Option<Arc<dyn Blob>>,
    pub push: Option<Arc<dyn Push>>,
    pub payments: Option<Arc<dyn Payments>>,
    pub tracker: Option<Arc<dyn Tracker>>,
    pub realtime: Option<Arc<dyn Realtime>>,
    /// A text completion by [`ModelTier`](crate::ModelTier), never by
    /// vendor (issue #429).
    pub text_model: Option<Arc<dyn TextModel>>,
    /// A typed, calibrated decision by a set of
    /// [`Question`](crate::Question)s, never by vendor (issue #456) —
    /// the sibling of `text_model`.
    pub classifier: Option<Arc<dyn Classifier>>,
    /// Nearest-neighbour search over tenant-scoped namespaces (issue
    /// #561), the output side of embeddings, as `text_model` is.
    pub vector_index: Option<Arc<dyn VectorIndex>>,
    /// Text into embedding vectors (issue #561), the input side of
    /// [`Ports::vector_index`].
    pub embedder: Option<Arc<dyn Embedder>>,
    /// Custom hostnames a customer owns, served by a venture (issue
    /// #590) — Cloudflare for `SaaS` behind the same trait on every
    /// runtime.
    pub custom_hostnames: Option<Arc<dyn CustomHostnames>>,
    pub http: Option<Arc<dyn HttpClient>>,
    pub clock: Option<Arc<dyn Clock>>,
    pub id_gen: Option<Arc<dyn IdGen>>,
    pub defer: Option<Arc<dyn Defer>>,
    /// Set by the runtime when the venture mounts sidecar modules. Not a
    /// [`Port`], so `view_for` never copies it and no module can reach it.
    pub dispatcher: Option<Arc<dyn Dispatcher>>,
    /// How this deployment turns a host into a tenant, and a tenant into
    /// its database (TENANT-ROUTING.md §3-§5). `None` is the *no registry*
    /// deployment — Cloudflare, the browser, and native in development and
    /// test — which resolves every host to the implicit tenant and hands
    /// back [`Ports::db`].
    ///
    /// Not a [`Port`] for the same reason `dispatcher` is not: `view_for`
    /// must never copy it into a module's view. A module reaches a
    /// database through the `TenantConn` extractor, which can only give it
    /// the one the request resolved.
    pub tenants: Option<Arc<dyn crate::tenant::TenantRouting>>,
}

impl Ports {
    /// An empty bundle with no ports resolved and an
    /// [`EmptyConfig`](crate::config::EmptyConfig).
    pub fn empty() -> Self {
        Self::with_config(Arc::new(crate::config::EmptyConfig))
    }

    pub fn with_config(config: Arc<dyn Config>) -> Self {
        Self {
            config,
            db: None,
            auth: None,
            mailer: None,
            captcha: None,
            rate_limiter: None,
            signer: None,
            kv: None,
            blob: None,
            push: None,
            payments: None,
            tracker: None,
            realtime: None,
            text_model: None,
            classifier: None,
            vector_index: None,
            embedder: None,
            custom_hostnames: None,
            http: None,
            clock: None,
            id_gen: None,
            defer: None,
            dispatcher: None,
            tenants: None,
        }
    }

    /// The set of ports this bundle actually provides.
    ///
    /// Walks [`Port::ALL`] and asks [`Self::has`], so a variant added to
    /// the enum cannot be left out of the answer: the match in `has` is
    /// exhaustive and the compiler refuses a new one until it is
    /// handled. Written out as fifteen `if`s, it had already lost one —
    /// `Port::Auth` was missing, so this reported fourteen of fifteen
    /// and a bundle with a verifier wired said it had none.
    #[must_use]
    pub fn provides(&self) -> Vec<Port> {
        Port::ALL
            .iter()
            .copied()
            .filter(|port| self.has(*port))
            .collect()
    }

    /// Whether one port is wired in this bundle.
    ///
    /// The exhaustive match is the point. `dispatcher` and `tenants` are
    /// deliberately absent from [`Port`] — no module may reach either —
    /// so they have nothing to answer here.
    #[must_use]
    pub fn has(&self, port: Port) -> bool {
        match port {
            Port::Db => self.db.is_some(),
            Port::Auth => self.auth.is_some(),
            Port::Mailer => self.mailer.is_some(),
            Port::Captcha => self.captcha.is_some(),
            Port::RateLimiter => self.rate_limiter.is_some(),
            Port::Signer => self.signer.is_some(),
            Port::KeyValue => self.kv.is_some(),
            Port::Blob => self.blob.is_some(),
            Port::Push => self.push.is_some(),
            Port::Payments => self.payments.is_some(),
            Port::Tracker => self.tracker.is_some(),
            Port::Realtime => self.realtime.is_some(),
            Port::TextModel => self.text_model.is_some(),
            Port::Classifier => self.classifier.is_some(),
            Port::VectorIndex => self.vector_index.is_some(),
            Port::Embedder => self.embedder.is_some(),
            Port::CustomHostnames => self.custom_hostnames.is_some(),
            Port::HttpClient => self.http.is_some(),
            Port::Clock => self.clock.is_some(),
            Port::IdGen => self.id_gen.is_some(),
            Port::Defer => self.defer.is_some(),
        }
    }

    /// A copy of this bundle in which every port the module did not declare
    /// in `requires()` or `optional()` is `None`, so a module cannot use
    /// what it did not declare (issue #3). Undeclared-but-provided ports are
    /// logged once per module by `Harness::build`.
    #[must_use]
    pub fn view_for(&self, module: &dyn Module) -> Self {
        let declared = module
            .requires()
            .iter()
            .chain(module.optional())
            .copied()
            .collect::<Vec<_>>();
        let allows = |p: &[Port], port: Port| p.contains(&port);
        let mut view = Ports::with_config(self.config.clone());
        if allows(&declared, Port::Db) {
            view.db.clone_from(&self.db);
        }
        if allows(&declared, Port::Auth) {
            view.auth.clone_from(&self.auth);
        }
        if allows(&declared, Port::Mailer) {
            view.mailer.clone_from(&self.mailer);
        }
        if allows(&declared, Port::Captcha) {
            view.captcha.clone_from(&self.captcha);
        }
        if allows(&declared, Port::RateLimiter) {
            view.rate_limiter.clone_from(&self.rate_limiter);
        }
        if allows(&declared, Port::Signer) {
            view.signer.clone_from(&self.signer);
        }
        if allows(&declared, Port::KeyValue) {
            view.kv.clone_from(&self.kv);
        }
        if allows(&declared, Port::Blob) {
            // Scope the store to this module's prefix, the blob equivalent of
            // the table-ownership rule: a module cannot name another's objects.
            view.blob = self.blob.as_ref().map(|blob| {
                Arc::new(ScopedBlob::new(Arc::clone(blob), module.name())) as Arc<dyn Blob>
            });
        }
        if allows(&declared, Port::Push) {
            view.push.clone_from(&self.push);
        }
        if allows(&declared, Port::Payments) {
            view.payments.clone_from(&self.payments);
        }
        if allows(&declared, Port::Tracker) {
            view.tracker.clone_from(&self.tracker);
        }
        if allows(&declared, Port::Realtime) {
            view.realtime.clone_from(&self.realtime);
        }
        if allows(&declared, Port::TextModel) {
            view.text_model.clone_from(&self.text_model);
        }
        if allows(&declared, Port::Classifier) {
            view.classifier.clone_from(&self.classifier);
        }
        if allows(&declared, Port::VectorIndex) {
            view.vector_index.clone_from(&self.vector_index);
        }
        if allows(&declared, Port::Embedder) {
            view.embedder.clone_from(&self.embedder);
        }
        if allows(&declared, Port::CustomHostnames) {
            view.custom_hostnames.clone_from(&self.custom_hostnames);
        }
        if allows(&declared, Port::HttpClient) {
            view.http.clone_from(&self.http);
        }
        if allows(&declared, Port::Clock) {
            view.clock.clone_from(&self.clock);
        }
        if allows(&declared, Port::IdGen) {
            view.id_gen.clone_from(&self.id_gen);
        }
        if allows(&declared, Port::Defer) {
            view.defer.clone_from(&self.defer);
        }
        view
    }
}

/// Log (once, at `Harness::build`) the provided ports a module did not
/// declare — the ports `view_for` will hide from it.
pub(crate) fn warn_undeclared_ports(module: &dyn Module, provided: &[Port]) {
    for port in provided {
        if !module.requires().contains(port) && !module.optional().contains(port) {
            warn!(
                module = module.name(),
                port = port.name(),
                "runtime provides a port the module did not declare; hiding it",
            );
        }
    }
}
