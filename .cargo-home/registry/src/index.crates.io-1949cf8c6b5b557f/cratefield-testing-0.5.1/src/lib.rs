//! `cratefield-testing`: the conformance kit every Factory Zero module runs
//! against (issue #9) — fake ports, an in-memory SQLite `Database`, and
//! request helpers over the axum router with **no network**.
//!
//! ```no_run
//! use cratefield_testing::{conformance, TestHarness, request};
//!
//! #[test]
//! fn my_module_conforms() {
//!     conformance(Box::new(my_module::MyModule::new()));
//! }
//!
//! #[pollster::test]
//! async fn join_returns_202() {
//!     let kit = TestHarness::new(vec![Box::new(my_module::MyModule::new())]);
//!     let response = request(&kit.router, http::Method::POST,
//!         "/v1/my-module/join", Some(r#"{"email":"nick@example.com"}"#)).await;
//!     assert_eq!(response.status, http::StatusCode::ACCEPTED);
//! }
//! ```

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

// Needs only `cratefield-core`, so it is ungated like `vectors` and
// `tmp`: a light consumer can assert the batch contract without the
// harness graph (issues #126, #201).
mod batch;
// The `Actors` contract (issue #583): gated with the harness because it
// drives a host with the kit's handler and needs `async-trait`.
#[cfg(feature = "harness")]
mod actor;
// Byte round-trips (issue #39): ungated for the same reason as `batch`
// — it binds through sea-query's `From` impls without naming the crate,
// so it needs nothing beyond `cratefield-core`.
mod blob;
#[cfg(feature = "harness")]
mod conformance;
#[cfg(feature = "harness")]
mod dialect;
#[cfg(feature = "harness")]
mod fakes;
#[cfg(feature = "harness")]
mod harness;
#[cfg(feature = "postgres")]
mod pg;
#[cfg(feature = "port-conformance")]
mod port;
#[cfg(feature = "harness")]
mod privacy_provider;
#[cfg(feature = "harness")]
mod request;
#[cfg(feature = "harness")]
mod sidecar;
// Webhook request signers (issue #666): mint the headers a provider
// sends, for a test to feed `WebhookVerifier`. Like `batch` and `blob`
// it is ungated — it needs only `cratefield-core` and the `http`/HMAC
// crates core already carries, none of the harness graph.
mod signing;
mod tmp;
pub mod vectors;

#[cfg(feature = "harness")]
pub use actor::{
    CONTRACT_ACTOR_KIND, assert_actor_contract, contract_actor_handler, contract_actor_handlers,
};
pub use batch::assert_batch_is_atomic;
pub use blob::{assert_blob_large_round_trips, assert_blob_round_trips};
#[cfg(feature = "harness")]
pub use conformance::{conformance, conformance_in_process_only, full_fake_ports, sidecar_parity};
#[cfg(feature = "harness")]
pub use dialect::Dialect;
#[cfg(feature = "harness")]
pub use fakes::{
    Ask, AuthMode, ClassifierMode, CommentedCall, EmptyDatabase, FAKE_EMBEDDER_DIMENSIONS,
    FAKE_EMBEDDER_MODEL, FakeAuth, FakeCaptcha, FakeClassifier, FakeCustomHostnames, FakeDefer,
    FakeDispatcher, FakeEmbedder, FakeHttpClient, FakeMailer, FakePayments, FakePush,
    FakeRateLimiter, FakeRealtime, FakeTextModel, FakeTracker, FiledCall, FixedClock, MailerMode,
    ManualClock, MemoryActors, MemoryBlob, MemoryKeyValue, PaymentsCall, PaymentsMode, PushMode,
    StatusedCall, TextModelMode, TrackerMode, error_json, problem_json, with_retry_after,
};
#[cfg(feature = "harness")]
pub use harness::TestHarness;
#[cfg(feature = "port-conformance")]
pub use port::{
    TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS, TEXT_MODEL_CONFORMANCE_INPUT_TOKENS,
    TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS, TEXT_MODEL_CONFORMANCE_REPLY, assert_wasm_safe_deps,
    classifier_conformance, classifier_conformance_questions, classifier_conformance_state,
    classifier_not_configured, classifier_rejects_malformed_questions,
    classifier_truncates_long_state, push_recipient_conformance, text_model_conformance,
    text_model_conformance_not_configured, text_model_conformance_prompt,
    text_model_image_bounds_conformance, vector_index_conformance,
};
#[cfg(feature = "harness")]
pub use privacy_provider::{FakePrivacyProvider, ProviderCall};
#[cfg(feature = "harness")]
pub use request::{TestResponse, request, request_as, request_chunks};
#[cfg(feature = "harness")]
pub use sidecar::{FakeSidecar, Fault, shared as shared_sidecar};
pub use signing::{sign_provider_scheme, sign_stripe_style};
pub use tmp::TempDir;

// The fixed test secret for the kit's Signer — an obvious dummy, never real.
pub const TEST_HARNESS_SECRET: &str = "cratefield-testing-dummy-secret-0123456789";

// Mirrors cratefield-adapter-postgres's integration-test skip reason.
// The dialect axis (behind `harness`) prints it when the Postgres leg is
// unavailable, so it exists whenever that axis or the leg itself does.
#[cfg(any(feature = "harness", feature = "postgres"))]
const POSTGRES_SKIP_REASON: &str = "start a local postgres:16 \
     (docker run --rm -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16) \
     and set FZ_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres";
