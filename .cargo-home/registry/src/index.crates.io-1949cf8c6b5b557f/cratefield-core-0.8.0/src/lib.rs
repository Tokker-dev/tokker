//! `cratefield-core` is the runtime-agnostic kernel of the Factory Zero harness:
//! the [`Module`] contract, the [`Harness`] builder, port traits, RFC 9457
//! problem+json errors, the request [`Scope`], an in-process [`EventBus`] and
//! a [`TemplateRegistry`] (ADR 0001, 0002, 0007).
//!
//! Core depends only on `http`, `axum` (default features off), `serde`,
//! `tracing`, `sea-query` and pure-Rust crypto. It must never depend on
//! `worker`, `wasm-bindgen`, `tokio`, `reqwest`, `sqlx` or `rusqlite`, and
//! never touches `std::fs` or `std::net` — CI enforces this with a
//! `cargo tree` check and the wasm build of `examples/venture`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod admin;
mod api_key;
mod classifier_agreement;
mod classifier_routing;
mod config;
mod cooldown;
mod cost;
mod csv;
mod email;
mod events;
mod harness;
mod http;
mod idempotency;
mod lint;
mod logging;
mod module;
mod origin;
mod outbox;
mod personal_data;
mod ports;
mod problem;
mod problems;
mod rate_limit;
mod route_policy;
mod scheduled;
mod scope;
mod sidecar;
mod signer;
// The `Blob` port's presigned URLs (issue #622); pure `SigV4`, public so
// adapters and tests share one implementation.
pub mod sigv4;
mod stream;
mod surface;
mod template;
mod tenant;
mod tenant_conn;
mod tenant_lifecycle;
mod tool_loop;
mod usage;
mod venture;
mod webhook_signature;

// `Module::router` returns an `axum::Router` and `well_known` an
// `Option<axum::Router>`, so a module author cannot implement the trait
// without axum — and an out-of-tree one has no workspace to inherit the
// version from. Picking a semver-incompatible one gives a type error
// about two `Router`s that look identical, which is a bad afternoon.
// Re-exported so there is one axum and it is this crate's.
pub use axum;

pub use admin::{bearer_token, constant_time_eq, require_admin};
pub use api_key::{
    ApiKeyError, ApiKeyMode, ApiKeyPrincipal, ApiKeys, IssuedKey, RandomBytes, RandomError,
    require_api_key,
};
pub use classifier_agreement::{
    AgreementAt, AgreementLog, AgreementReport, CalibrationPoint, CorpusItem, Disagreement,
    GroundTruth, KindAgreement, answer_margin, measure_agreement, values_agree,
};
pub use classifier_routing::{
    RouteReason, Routed, RoutingClassifier, RoutingError, RoutingMode, RoutingPolicy,
    ShadowClassifier, Thresholds,
};
pub use config::{Config, ConfigError, EmptyConfig, HarnessConfig, MapConfig, ModuleConfig};
pub use cooldown::SendCooldown;
pub use cost::{
    Accounting, AdapterId, CallOutcome, CallRecord, CallRole, Cost, CostLedger, InMemoryLedger,
    LedgerTotals, Price, PriceSheet, QuestionKind, TokenSource, Tokens,
};
pub use csv::{FORMULA_PREFIXES, MAX_EXPORT_ROWS, escape as csv_escape, row as csv_row};
pub use email::{
    MAX_EMAIL_BYTES, MAX_LOCAL_BYTES, invalid_email_problem, is_valid,
    normalize as normalize_email, validation_error,
};
pub use events::{AnyError, EventBus, EventHandler, EventName};
pub use harness::{Harness, HarnessBuilder, Runtime};
pub use http::{
    Form, Json, MAX_BODY_BYTES, RequestSummary, X_REQUEST_ID, allowance_exhausted, rate_limited,
    request_id_is_valid,
};
pub use idempotency::Inbox;
pub use lint::{CARD_DATA, card_data_hit, created_tables, lint_card_data, lint_portable_sql};
pub use logging::{
    ControlLevel, RedactingVisitor, forward_control_event, is_email_field, is_secret_field,
    redacted_value, scrub_request_url, scrub_text, set_error_forwarder, set_log_pseudonym_key,
    subject_hash,
};
pub use module::{
    BoxFuture, HARNESS_API, Migrations, Module, ModuleContext, SqlMigration, assert_migration_set,
    harness_api_mismatch, is_idempotent_sql, migration_checksum, migration_edited,
    migration_missing_guard,
};
pub use origin::{OriginError, origin_of};
pub use outbox::{DrainOptions, DrainReport, Outbox, OutboxRecord, Processed};
pub use personal_data::{
    CatalogEntry, DataKind, Disposition, PersonalDataCatalog, PersonalDataSet, SubjectVia,
    is_plain_identifier, migration_tables, undeclared_tables, unlisted_tables,
};
pub use ports::{
    Answer, AnswerValue, Auth, AuthError, Blob, BlobError, BlobObject, BoundedHttpClient,
    Calibration, Caller, Capability, Captcha, CaptchaBinding, CaptchaError, CertificateStatus,
    Charge, CheckoutRequest, CheckoutSession, Classifier, ClassifierError, ClassifierProfile,
    Clock, Completion, ConnectAccountLink, ConnectAccountLinkRequest, Credential, CustomHostname,
    CustomHostnameError, CustomHostnames, DEFAULT_MAX_STATE_CHARS, DEFAULT_MAX_TOKENS,
    DEFAULT_RESPONSE_TIMEOUT, Database, DbError, Decision, Defer, Destination, DispatchError,
    Dispatcher, DnsRecordType, EmbedError, Embedder, Embeddings, ExactVectorIndex, Filed,
    HostnameClaim, HostnameRefusal, HttpClient, HttpError, HttpPolicy, IdGen, InboundStatusError,
    KeyValue, Kid, KvError, LineItem, LocKeys, MAX_BLOB_BYTES, MAX_CONCURRENT_REQUESTS,
    MAX_KID_NAME, MAX_NAMESPACE_BYTES, MAX_RESPONSE_BYTES, MAX_RESPONSE_TIMEOUT, MailError, Mailer,
    Member, Message, ModelTier, Money, NoopDefer, Notification, Payload, Payments, PaymentsError,
    Platform, Port, Ports, Priority, Prompt, ProviderStatus, Push, PushError, PushOutcome,
    Question, Quota, RateLimitError, RateLimiter, Realtime, RealtimeError, Recipient, Refund,
    RefundRequest, Role, RoomContext, RoomHandler, RoutingPush, RoutingTextModel, RoutingTracker,
    Row, Rows, ScopedBlob, SendOutcome, Severity, SignatureError, Signer, Statement, StatusUpdate,
    StatusWebhook, Subject, SubscriptionCheckoutRequest, SystemClock, TextModel, TextModelError,
    TicketComment, TicketDraft, TicketState, TicketStatus, ToolCall, ToolChoice, ToolResult,
    ToolSpec, Tracker, TrackerError, TransferCharge, TryFromValue, Turn, UlidIdGen, Unconfigured,
    UsageReport, UsageReported, Validation, ValidationMethod, VectorFilter, VectorIndex,
    VectorIndexError, VectorMatch, VectorNamespace, VectorRecord, Verdict, WebhookEvent,
    check_blob_size, check_hostname, declared_content_length, receive_status, retry_after, timeout,
    ttl_secs, validate_questions,
};
// The dispute and portal types on `Payments` (issues #589, #602, #690).
pub use ports::{
    Dispute, DisputeListRequest, DisputePage, DisputePhase, DisputeStatus, PortalSession,
    PortalSessionRequest,
};
// The Blob presign API (issue #622), kept out of the wholesale block above.
pub use ports::{DEFAULT_PRESIGN_TTL, MAX_PRESIGN_TTL, PresignedPut};
pub use problem::{ABOUT_BLANK, Problem};
// `Slugs` is exported beside the `SLUGS` value it types. Without it a
// caller can read `SLUGS.validation_failed` and cannot write a function
// that takes the table — the value was reachable and its type was not
// nameable, which `unnameable_types` is what noticed.
pub use problems::{ProblemDef, SLUGS, Slugs, registry as problem_registry};
pub use rate_limit::{RateLimit, RateLimitFailure, check_rate_limit, client_ip, rate_limit_keys};
pub use route_policy::{
    ALLOW_UNLIMITED_PUBLIC_ROUTES, ALLOW_UNPROTECTED_WRITES, RoutePolicy, SignatureVerification,
    WriteGuards, captcha_effective, deployed_env, env_disagreement, payments_effective,
    production_readiness, rate_limiter_effective, signer_effective, stated_reason,
    unlimited_public_routes_override, unprotected_writes_override, verify_human_form,
    webhook_secret_readiness,
};
pub use scheduled::{ScheduledBudget, ScheduledLimits, ScheduledSplit};
pub use scope::Scope;
pub use sidecar::{
    GATEWAY_ADMIN_PURPOSE, GATEWAY_PURPOSE, GATEWAY_TOKEN_TTL_SECS, HARNESS_ONE_WORKER,
    HARNESS_SIDECARS, SIDECAR_GATEWAY_SECRET, SIDECAR_REQUIRE_GATEWAY, SidecarMount, SidecarMounts,
    X_HARNESS_API, X_HARNESS_GATEWAY, X_HARNESS_MODULE,
};
pub use signer::{
    CONFIRM_TOKEN_MAX_TTL_SECS, DEFAULT_TOKEN_MAX_TTL_SECS, HmacSigner, KeyRing, KeyState,
    MIN_SECRET_BYTES, RingKey, STATUS_TOKEN_MAX_TTL_SECS, SignerError, TokenPolicy,
    UNSUBSCRIBE_ACTION,
};
pub use stream::{BoxStream, RequestStream, ResponseStream, StreamError, StreamRoute};
pub use surface::{
    Action, Audience, Column, HINT_KEYWORDS, MAX_SIDECAR_ACTIONS, MAX_SIDECAR_SURFACE_BYTES,
    MAX_SIDECAR_VIEWS, ModuleSurface, Outcome, RenderedSurface, SURFACE_API, Surface,
    SurfaceDocument, SurfaceSource, UiContext, UiMount, VentureSurface, View, hint_field,
    schema_for,
};
pub use template::{Rendered, Template, TemplateError, TemplateRegistry};
pub use tenant::{
    IMPLICIT_TENANT, ImplicitTenant, Resolution, ResolveTenant, Tenancy, Tenant, TenantDatabases,
    TenantDbError, TenantId, TenantRouting, TenantStatus,
};
pub use tenant_conn::TenantConn;
pub use tenant_lifecycle::{
    ErasureStep, TenantLifecycle, TenantLifecycleError, TenantSummary, remaining_erasure,
};
pub use tool_loop::{
    StepUsage, ToolBudget, ToolExecutor, ToolLoopError, ToolLoopOutcome, run_tool_loop,
};
pub use usage::{Consumed, Consumption, Exhausted, Months, Period, PeriodWindow, Usage};
pub use venture::{Brand, Venture, VentureEnv};
pub use webhook_signature::{
    DEFAULT_TOLERANCE_SECS, Digest, Github, Gitlab, ProviderScheme, SharedTokenScheme,
    SignatureEncoding, SignatureScheme, SignedDelivery, StripeStyle, Svix, Vercel, WebhookVerifier,
    svix_secret_key,
};
