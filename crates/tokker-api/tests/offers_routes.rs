//! Route tests for `/v1/offers` (issue #19): the real Harness router, real
//! SQL through the rusqlite-backed `Database` port (with D1's integral-REAL
//! quirk mimicked), and a fake KV with counters.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    Database, DbError, Harness, KeyValue, KvError, Port, Ports, Row, Rows, Runtime, SqlMigration,
    Statement, SystemClock, Venture,
};
use sea_query::Value as SeaValue;
use serde_json::{Value as Json, json};
use tower::ServiceExt;

use tokker_api::offers::{DATASET_LICENSE, invalidate_cache};
use tokker_api::{Offers, freshness};

/// The pinned "today" every test computes staleness against.
const TODAY: &str = "2026-10-18";

// ---------------------------------------------------------------------------
// Fakes

/// A runtime that provides exactly what the offers module requires.
struct TestRuntime;

impl Runtime for TestRuntime {
    fn provides(&self) -> Vec<Port> {
        vec![Port::Db, Port::KeyValue, Port::Clock]
    }
}

/// `SqliteDatabase` behind a counting decorator that also mimics D1: D1 hands
/// integral REAL values back as `BigInt`, rusqlite as `Double`, so every REAL
/// read in the module is exercised through its defensive path.
struct CountingD1 {
    inner: Arc<SqliteDatabase>,
    queries: AtomicUsize,
}

impl CountingD1 {
    fn queries(&self) -> usize {
        self.queries.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Database for CountingD1 {
    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        let rows = self.inner.query(stmt).await?;
        self.queries.fetch_add(1, Ordering::Relaxed);
        Ok(d1_flavour(rows))
    }

    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        self.inner.execute(stmt).await
    }

    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), DbError> {
        self.inner.batch_atomic(stmts).await
    }
}

fn d1_flavour(rows: Rows) -> Rows {
    let rewritten = rows
        .rows
        .into_iter()
        .map(|row| {
            let columns = row
                .columns()
                .map(|(name, value)| {
                    let value = match value {
                        SeaValue::Double(Some(v)) if v.is_finite() && v.fract() == 0.0 =>
                        {
                            #[allow(clippy::cast_possible_truncation)]
                            SeaValue::BigInt(Some(*v as i64))
                        }
                        other => other.clone(),
                    };
                    (name.to_string(), value)
                })
                .collect();
            Row::new(columns)
        })
        .collect();
    Rows::new(rewritten)
}

/// An in-memory KV with counters and a kill switch (cache fall-through).
#[derive(Default)]
struct TestKv {
    entries: Mutex<HashMap<String, String>>,
    gets: AtomicUsize,
    puts: AtomicUsize,
    fail: AtomicBool,
}

impl TestKv {
    fn failing() -> Arc<Self> {
        let kv = Arc::new(Self::default());
        kv.fail.store(true, Ordering::Relaxed);
        kv
    }
}

#[async_trait]
impl KeyValue for TestKv {
    async fn get(&self, key: &str) -> Result<Option<String>, KvError> {
        self.gets.fetch_add(1, Ordering::Relaxed);
        if self.fail.load(Ordering::Relaxed) {
            return Err(KvError::Operation("kv is down (test)".to_string()));
        }
        Ok(self.entries.lock().expect("kv lock").get(key).cloned())
    }

    async fn put(&self, key: &str, value: &str, _ttl: Option<Duration>) -> Result<(), KvError> {
        self.puts.fetch_add(1, Ordering::Relaxed);
        if self.fail.load(Ordering::Relaxed) {
            return Err(KvError::Operation("kv is down (test)".to_string()));
        }
        self.entries
            .lock()
            .expect("kv lock")
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.entries.lock().expect("kv lock").remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fixtures

/// One offer, shaped like a `data/pricing.json` `api_offers[]` row.
struct OfferFixture {
    id: &'static str,
    creator: &'static str,
    provider_type: &'static str,
    open_weights: bool,
    currency: &'static str,
    native_input: Json,
    native_output: Json,
    usd_input: Option<f64>,
    usd_output: Option<f64>,
    verified: &'static str,
    volatility: &'static str,
    cache_write: Json,
}

impl OfferFixture {
    fn provider(&self) -> &str {
        self.id.split('/').next().expect("id is provider/model")
    }

    fn model(&self) -> &str {
        self.id.split('/').nth(1).expect("id is provider/model")
    }

    fn usd_blended(&self) -> Option<f64> {
        Some((3.0 * self.usd_input? + self.usd_output?) / 4.0)
    }

    /// The verbatim dataset row the mirror stores in `offers.json`.
    fn json(&self) -> Json {
        let unknown_or =
            |value: Option<f64>| value.map_or(Json::String("unknown".to_string()), |v| json!(v));
        json!({
            "id": self.id,
            "provider_id": self.provider(),
            "provider_name": self.provider(),
            "provider_type": self.provider_type,
            "provider_country": "US",
            "model_slug": self.model(),
            "model_name": self.model(),
            "model_creator": self.creator,
            "open_weights": self.open_weights,
            "currency": self.currency,
            "input_per_mtok": self.native_input,
            "output_per_mtok": self.native_output,
            "cached_input_per_mtok": "unknown",
            "cache_write_per_mtok": self.cache_write,
            "context_window": 128_000,
            "max_output": 16_384,
            "source": "https://example.test/pricing",
            "checked": self.verified,
            "confidence": "official_docs",
            "notes": "fixture",
            "fetch_recipe": {
                "method": "docs_markdown",
                "endpoint": "https://example.test/pricing",
                "volatility": self.volatility,
            },
            "usd": {
                "input_per_mtok": unknown_or(self.usd_input),
                "output_per_mtok": unknown_or(self.usd_output),
                "blended_3to1": unknown_or(self.usd_blended()),
            },
            "last_verified_at": self.verified,
            "provenance": {
                "default": {
                    "source": "https://example.test/pricing",
                    "fetched_at": self.verified,
                    "method": "docs_markdown",
                    "confidence": "official_docs",
                },
                "fields": {},
            },
        })
    }

    /// The verbatim row plus the two fields the API stamps at read time.
    fn expected_row(&self) -> Json {
        let verdict = freshness::staleness(
            freshness::RowType::ApiOffer,
            Some(self.volatility),
            self.verified,
            TODAY,
        )
        .expect("fixture dates are real");
        let mut row = self.json();
        row["stale"] = json!(verdict.stale);
        row["stale_since"] = match &verdict.stale_since {
            Some(day) => json!(day),
            None => Json::Null,
        };
        row
    }
}

/// The offers every test starts from (see `TODAY` for the freshness maths):
/// two stale rows (high-volatility and standard), an unpriced row, a blended
/// tie between two providers, and a spread of types, creators, weights and
/// currencies.
fn fixtures() -> Vec<OfferFixture> {
    let mut all = closed_model_fixtures();
    all.extend(llama_fixtures());
    all
}

/// The closed-model and two-of-them-stale half of the fixture set.
fn closed_model_fixtures() -> Vec<OfferFixture> {
    [
        OfferFixture {
            id: "anthropic/claude-fable-5-1",
            creator: "anthropic",
            provider_type: "first_party",
            open_weights: false,
            currency: "USD",
            native_input: json!(10),
            native_output: json!(50),
            usd_input: Some(10.0),
            usd_output: Some(50.0),
            verified: "2026-10-10",
            volatility: "medium",
            cache_write: json!(12.5),
        },
        OfferFixture {
            id: "openrouter/claude-fable-5-1",
            creator: "anthropic",
            provider_type: "aggregator",
            open_weights: false,
            currency: "USD",
            native_input: json!(11),
            native_output: json!(55),
            usd_input: Some(11.0),
            usd_output: Some(55.0),
            verified: "2026-10-12",
            volatility: "medium",
            cache_write: json!(13.75),
        },
        OfferFixture {
            id: "openrouter/gpt-5.1",
            creator: "openai",
            provider_type: "aggregator",
            open_weights: false,
            currency: "USD",
            native_input: json!(1.25),
            native_output: json!(10),
            usd_input: Some(1.25),
            usd_output: Some(10.0),
            // high volatility, age exactly the SLA: still fresh.
            verified: "2026-10-15",
            volatility: "high",
            cache_write: json!(1.25),
        },
        OfferFixture {
            id: "deepseek/deepseek-chat-v3.2",
            creator: "deepseek",
            provider_type: "first_party",
            open_weights: true,
            currency: "CNY",
            native_input: json!(2),
            native_output: json!(8),
            usd_input: Some(0.27),
            usd_output: Some(1.10),
            verified: "2026-09-01", // high, 47 days: stale since 2026-09-05
            volatility: "high",
            cache_write: json!(0.27),
        },
        OfferFixture {
            id: "mistral/mistral-large-2411",
            creator: "mistral",
            provider_type: "inference_host",
            open_weights: true,
            currency: "EUR",
            native_input: json!(2),
            native_output: json!(6),
            usd_input: Some(2.2),
            usd_output: Some(6.6),
            verified: "2026-10-02", // standard, 16 days: stale since 2026-10-13
            volatility: "low",
            cache_write: json!("unknown"),
        },
    ]
    .into_iter()
    .collect()
}

/// The same open model across four providers: two unpriced (the NULL-USD
/// block), two tied on blended so the id tiebreak shows.
fn llama_fixtures() -> Vec<OfferFixture> {
    [
        OfferFixture {
            id: "fireworks/llama-4-maverick",
            creator: "meta",
            provider_type: "inference_host",
            open_weights: true,
            currency: "USD",
            native_input: json!("unknown"),
            native_output: json!("unknown"),
            usd_input: None,
            usd_output: None,
            verified: "2026-10-12",
            volatility: "medium",
            cache_write: json!("unknown"),
        },
        OfferFixture {
            id: "groq/llama-4-maverick",
            creator: "meta",
            provider_type: "inference_host",
            open_weights: true,
            currency: "USD",
            native_input: json!("unknown"),
            native_output: json!("unknown"),
            usd_input: None,
            usd_output: None,
            verified: "2026-10-10",
            volatility: "medium",
            cache_write: json!("unknown"),
        },
        OfferFixture {
            id: "together/llama-4-maverick",
            creator: "meta",
            provider_type: "inference_host",
            open_weights: true,
            currency: "USD",
            native_input: json!(0.55),
            native_output: json!(2.15),
            usd_input: Some(0.55),
            usd_output: Some(2.15),
            verified: "2026-10-11",
            volatility: "medium",
            cache_write: json!(0.55),
        },
        OfferFixture {
            id: "cloudflare/llama-4-maverick",
            creator: "meta",
            provider_type: "cloud",
            open_weights: true,
            currency: "USD",
            native_input: json!(0.55),
            native_output: json!(2.15),
            usd_input: Some(0.55),
            usd_output: Some(2.15),
            verified: "2026-10-11", // blended ties with together/: id breaks it
            volatility: "low",
            cache_write: json!(0.55),
        },
    ]
    .into_iter()
    .collect()
}

/// The expected ids under the default (blended) sort: ascending USD, the
/// NULL (unpriced) block last in id order, id breaking the 0.95 tie.
const BLENDED_ORDER: [&str; 9] = [
    "deepseek/deepseek-chat-v3.2",
    "cloudflare/llama-4-maverick",
    "together/llama-4-maverick",
    "mistral/mistral-large-2411",
    "openrouter/gpt-5.1",
    "anthropic/claude-fable-5-1",
    "openrouter/claude-fable-5-1",
    "fireworks/llama-4-maverick",
    "groq/llama-4-maverick",
];

const INPUT_ORDER: [&str; 9] = [
    "deepseek/deepseek-chat-v3.2",
    "cloudflare/llama-4-maverick",
    "together/llama-4-maverick",
    "openrouter/gpt-5.1",
    "mistral/mistral-large-2411",
    "anthropic/claude-fable-5-1",
    "openrouter/claude-fable-5-1",
    "fireworks/llama-4-maverick",
    "groq/llama-4-maverick",
];

const OUTPUT_ORDER: [&str; 9] = [
    "deepseek/deepseek-chat-v3.2",
    "cloudflare/llama-4-maverick",
    "together/llama-4-maverick",
    "mistral/mistral-large-2411",
    "openrouter/gpt-5.1",
    "anthropic/claude-fable-5-1",
    "openrouter/claude-fable-5-1",
    "fireworks/llama-4-maverick",
    "groq/llama-4-maverick",
];

fn text(value: &str) -> SeaValue {
    SeaValue::String(Some(Box::new(value.to_string())))
}

fn real(value: Option<f64>) -> SeaValue {
    SeaValue::Double(value)
}

/// A fresh seeded world for one test: router, counting D1 and KV.
async fn offers() -> (Router, Arc<CountingD1>, Arc<TestKv>) {
    world(Arc::new(TestKv::default()), false).await
}

/// The same world with `dataset_meta` seeded (`source_commit`, `license`).
async fn offers_with_meta() -> (Router, Arc<CountingD1>, Arc<TestKv>) {
    world(Arc::new(TestKv::default()), true).await
}

/// A world whose KV fails every operation — requests must still succeed.
async fn offers_with_failing_kv() -> Router {
    world(TestKv::failing(), false).await.0
}

/// Builds the harness router over a fresh seeded database and the given KV.
async fn world(kv: Arc<TestKv>, meta: bool) -> (Router, Arc<CountingD1>, Arc<TestKv>) {
    let sqlite = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite"));
    sqlite
        .apply_migrations(
            "tokker",
            &[
                SqlMigration::new(
                    "0001",
                    "core_tables",
                    include_str!("../../../migrations/0001_core_tables.sql"),
                ),
                SqlMigration::new(
                    "0002",
                    "dataset_meta",
                    include_str!("../../../migrations/0002_dataset_meta.sql"),
                ),
            ],
        )
        .expect("migrations apply");
    seed(&sqlite, meta).await;
    let db = Arc::new(CountingD1 {
        inner: sqlite,
        queries: AtomicUsize::new(0),
    });

    let harness = Harness::builder()
        .venture(Venture::new("tokker-test", "test.example").cors_origins(["https://test.example"]))
        .module(Offers::with_today(TODAY))
        .runtime(TestRuntime)
        .build()
        .expect("test harness builds");
    let mut ports = Ports::empty();
    ports.db = Some(db.clone());
    ports.kv = Some(kv.clone());
    ports.clock = Some(Arc::new(SystemClock));
    (harness.router(ports), db, kv)
}

async fn insert(db: &SqliteDatabase, sql: &str, values: Vec<SeaValue>) {
    db.execute(&Statement::with_values(sql, values))
        .await
        .expect("seed insert");
}

async fn seed(db: &SqliteDatabase, meta: bool) {
    let offers = fixtures();
    let mut providers: Vec<&str> = Vec::new();
    let mut models: Vec<&str> = Vec::new();
    for offer in &offers {
        if !providers.contains(&offer.provider()) {
            providers.push(offer.provider());
        }
        if !models.contains(&offer.model()) {
            models.push(offer.model());
        }
    }
    for provider in providers {
        insert(
            db,
            "INSERT INTO providers (id, name, type, country, api_offer_count, \
             subscription_count, json) VALUES (?, ?, ?, 'US', 0, 0, '{}')",
            vec![text(provider), text(provider), text("first_party")],
        )
        .await;
    }
    for model in models {
        insert(
            db,
            "INSERT INTO models (id, name, creator, open_weights, context_window, json) \
             VALUES (?, ?, 'meta', 'true', NULL, '{}')",
            vec![text(model), text(model)],
        )
        .await;
    }
    for offer in &offers {
        insert(
            db,
            "INSERT INTO offers (id, provider_id, model_id, creator, provider_type, \
             open_weights, currency, input_per_mtok, output_per_mtok, usd_input_per_mtok, \
             usd_output_per_mtok, usd_blended_3to1, source, confidence, last_verified_at, json) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(offer.id),
                text(offer.provider()),
                text(offer.model()),
                text(offer.creator),
                text(offer.provider_type),
                text(if offer.open_weights { "true" } else { "false" }),
                text(offer.currency),
                real(offer.usd_input),
                real(offer.usd_output),
                real(offer.usd_input),
                real(offer.usd_output),
                real(offer.usd_blended()),
                text("https://example.test/pricing"),
                text("official_docs"),
                text(offer.verified),
                text(&serde_json::to_string(&offer.json()).expect("fixture serialises")),
            ],
        )
        .await;
    }
    // A plan newer than every offer: `as_of` must read across both tables.
    insert(
        db,
        "INSERT INTO plans (id, vendor_id, vendor_name, product, plan_name, category, \
         currency, last_verified_at, json) \
         VALUES ('openai/chatgpt-pro', 'openrouter', 'OpenAI', 'chatgpt', 'pro', 'chat', \
         'USD', '2026-10-16', '{}')",
        vec![],
    )
    .await;
    if meta {
        insert(
            db,
            "INSERT INTO dataset_meta (key, value) VALUES ('source_commit', '9b4a2dc')",
            vec![],
        )
        .await;
        insert(
            db,
            "INSERT INTO dataset_meta (key, value) VALUES ('license', 'CC BY 4.0')",
            vec![],
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// Request helpers

struct Answer {
    status: axum::http::StatusCode,
    content_type: String,
    body: Json,
}

async fn get(router: &Router, uri: &str) -> Answer {
    let request = axum::http::Request::builder()
        .uri(uri)
        .body(axum::body::Body::empty())
        .expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let status = response.status();
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body = serde_json::from_slice(&bytes).expect("body is JSON");
    Answer {
        status,
        content_type,
        body,
    }
}

fn ids(answer: &Json) -> Vec<String> {
    answer["data"]
        .as_array()
        .expect("data is an array")
        .iter()
        .map(|row| row["id"].as_str().expect("row has an id").to_string())
        .collect()
}

fn problem_parameter(answer: &Json) -> &str {
    answer["parameter"]
        .as_str()
        .expect("problem names parameter")
}

// ---------------------------------------------------------------------------
// Tests

#[tokio::test]
async fn lists_every_offer_in_blended_order_with_the_envelope() {
    let (router, _db, _kv) = offers().await;
    let answer = get(&router, "/v1/offers").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    assert_eq!(answer.content_type, "application/json");
    assert_eq!(ids(&answer.body), BLENDED_ORDER);
    assert_eq!(answer.body["next_cursor"], Json::Null, "all 9 fit one page");
    assert_eq!(
        answer.body["as_of"],
        json!("2026-10-16"),
        "plans drive as_of"
    );
    assert_eq!(answer.body["source_commit"], json!("unknown"));
    assert_eq!(answer.body["license"], json!(DATASET_LICENSE));

    // The upper limit bound is accepted, not just rejected at 201.
    let answer = get(&router, "/v1/offers?limit=200").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    assert_eq!(ids(&answer.body), BLENDED_ORDER);
}

#[tokio::test]
async fn each_filter_alone_narrows_the_list() {
    let (router, _db, _kv) = offers().await;
    let cases: [(&str, Vec<&str>); 8] = [
        (
            "model=llama-4-maverick",
            vec![
                "cloudflare/llama-4-maverick",
                "together/llama-4-maverick",
                "fireworks/llama-4-maverick",
                "groq/llama-4-maverick",
            ],
        ),
        (
            "provider=openrouter",
            vec!["openrouter/gpt-5.1", "openrouter/claude-fable-5-1"],
        ),
        (
            "creator=anthropic",
            vec!["anthropic/claude-fable-5-1", "openrouter/claude-fable-5-1"],
        ),
        ("provider_type=cloud", vec!["cloudflare/llama-4-maverick"]),
        (
            "open_weights=false",
            vec![
                "openrouter/gpt-5.1",
                "anthropic/claude-fable-5-1",
                "openrouter/claude-fable-5-1",
            ],
        ),
        ("currency=eur", vec!["mistral/mistral-large-2411"]),
        ("max_input=0.3", vec!["deepseek/deepseek-chat-v3.2"]),
        ("max_output=1.15", vec!["deepseek/deepseek-chat-v3.2"]),
    ];
    for (query, expected) in cases {
        let answer = get(&router, &format!("/v1/offers?{query}")).await;
        assert_eq!(answer.status, axum::http::StatusCode::OK, "{query}");
        assert_eq!(ids(&answer.body), expected, "{query}");
    }
}

#[tokio::test]
async fn filters_combine_as_a_conjunction() {
    let (router, _db, _kv) = offers().await;
    let answer = get(
        &router,
        "/v1/offers?provider_type=aggregator&currency=USD&max_input=2",
    )
    .await;
    assert_eq!(ids(&answer.body), ["openrouter/gpt-5.1"]);

    // A stale-only filter over a model whose offers are all fresh is empty.
    let answer = get(&router, "/v1/offers?model=llama-4-maverick&stale=true").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    assert_eq!(ids(&answer.body), Vec::<String>::new());
    assert_eq!(answer.body["next_cursor"], Json::Null);
}

#[tokio::test]
async fn each_sort_orders_by_its_column_with_nulls_last() {
    let (router, _db, _kv) = offers().await;
    for (sort, expected) in [
        ("sort=blended", BLENDED_ORDER),
        ("sort=input", INPUT_ORDER),
        ("sort=output", OUTPUT_ORDER),
    ] {
        let answer = get(&router, &format!("/v1/offers?{sort}")).await;
        assert_eq!(answer.status, axum::http::StatusCode::OK, "{sort}");
        assert_eq!(ids(&answer.body), expected, "{sort}");
    }
}

#[tokio::test]
async fn walking_pages_yields_every_row_exactly_once_in_order() {
    let (router, _db, _kv) = offers().await;
    let mut walked: Vec<String> = Vec::new();
    let mut cursor = String::new();
    loop {
        let uri = if cursor.is_empty() {
            "/v1/offers?limit=3".to_string()
        } else {
            format!("/v1/offers?limit=3&cursor={cursor}")
        };
        let answer = get(&router, &uri).await;
        assert_eq!(answer.status, axum::http::StatusCode::OK, "{uri}");
        walked.extend(ids(&answer.body));
        match answer.body["next_cursor"].as_str() {
            Some(next) => cursor = next.to_string(),
            None => break,
        }
    }
    assert_eq!(walked, BLENDED_ORDER);
}

#[tokio::test]
async fn pages_split_cleanly_inside_the_unpriced_block() {
    let (router, _db, _kv) = offers().await;
    // The model filter yields two priced rows then two unpriced (NULL USD)
    // rows; limit=1 makes every boundary a page edge, including the two
    // inside the NULL block, which must walk in id order without a skip or
    // a repeat.
    let mut walked: Vec<String> = Vec::new();
    let mut cursor = String::new();
    loop {
        let uri = if cursor.is_empty() {
            "/v1/offers?model=llama-4-maverick&limit=1".to_string()
        } else {
            format!("/v1/offers?model=llama-4-maverick&limit=1&cursor={cursor}")
        };
        let answer = get(&router, &uri).await;
        assert_eq!(answer.status, axum::http::StatusCode::OK, "{uri}");
        assert!(ids(&answer.body).len() <= 1, "{uri}: a one-row page");
        walked.extend(ids(&answer.body));
        match answer.body["next_cursor"].as_str() {
            Some(next) => cursor = next.to_string(),
            None => break,
        }
    }
    let expected = [
        "cloudflare/llama-4-maverick",
        "together/llama-4-maverick",
        "fireworks/llama-4-maverick",
        "groq/llama-4-maverick",
    ];
    assert_eq!(walked, expected);
}

#[tokio::test]
async fn pagination_is_stable_through_the_stale_filter() {
    let (router, _db, _kv) = offers().await;
    let answer = get(&router, "/v1/offers?stale=true&limit=1").await;
    assert_eq!(ids(&answer.body), ["deepseek/deepseek-chat-v3.2"]);
    let cursor = answer.body["next_cursor"]
        .as_str()
        .expect("a next page")
        .to_string();
    let answer = get(
        &router,
        &format!("/v1/offers?stale=true&limit=1&cursor={cursor}"),
    )
    .await;
    assert_eq!(ids(&answer.body), ["mistral/mistral-large-2411"]);
    assert_eq!(answer.body["next_cursor"], Json::Null);
}

#[tokio::test]
async fn a_cursor_minted_for_another_sort_is_rejected() {
    let (router, _db, _kv) = offers().await;
    let answer = get(&router, "/v1/offers?sort=input&limit=3").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    let cursor = answer.body["next_cursor"].as_str().expect("a next page");
    let answer = get(
        &router,
        &format!("/v1/offers?sort=output&limit=3&cursor={cursor}"),
    )
    .await;
    assert_eq!(answer.status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(problem_parameter(&answer.body), "cursor");
    let detail = answer.body["detail"].as_str().expect("a detail");
    assert!(detail.contains("input"), "{detail}");
    assert!(detail.contains("output"), "{detail}");
}

#[tokio::test]
async fn bad_parameters_are_400s_naming_the_parameter() {
    let (router, _db, _kv) = offers().await;
    let cases = [
        ("foo=1", "foo"),
        ("model=a&model=b", "model"),
        ("model=Bad-Slug", "model"),
        ("provider_type=party", "provider_type"),
        ("open_weights=yes", "open_weights"),
        ("currency=US", "currency"),
        ("max_input=-1", "max_input"),
        ("stale=TRUE", "stale"),
        ("sort=price", "sort"),
        ("limit=0", "limit"),
        ("limit=201", "limit"),
        ("limit=abc", "limit"),
        ("limit=1.5", "limit"),
        ("cursor=Zm9v", "cursor"),
        ("cursor=%21%21%21", "cursor"),
        ("cursor=short_but_fine", "cursor"),
    ];
    for (query, parameter) in cases {
        let answer = get(&router, &format!("/v1/offers?{query}")).await;
        assert_eq!(
            answer.status,
            axum::http::StatusCode::BAD_REQUEST,
            "{query}"
        );
        assert_eq!(problem_parameter(&answer.body), parameter, "{query}");
        assert!(
            answer.content_type.starts_with("application/problem+json"),
            "{query}"
        );
    }
}

#[tokio::test]
async fn the_item_route_serves_one_offer() {
    let (router, _db, _kv) = offers().await;
    let answer = get(&router, "/v1/offers/anthropic/claude-fable-5-1").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    assert_eq!(answer.content_type, "application/json");
    assert_eq!(
        answer.body["data"]["id"],
        json!("anthropic/claude-fable-5-1")
    );
    assert_eq!(answer.body["data"]["input_per_mtok"], json!(10));
    assert_eq!(answer.body["data"]["stale"], json!(false));
    assert_eq!(answer.body["data"]["stale_since"], Json::Null);
    assert_eq!(answer.body["as_of"], json!("2026-10-16"));
    assert!(answer.body.get("next_cursor").is_none());
}

#[tokio::test]
async fn an_unknown_id_is_a_404_naming_it() {
    let (router, _db, _kv) = offers().await;
    let answer = get(&router, "/v1/offers/anthropic/no-such-model").await;
    assert_eq!(answer.status, axum::http::StatusCode::NOT_FOUND);
    assert!(answer.content_type.starts_with("application/problem+json"));
    let detail = answer.body["detail"].as_str().expect("a detail");
    assert!(detail.contains("anthropic/no-such-model"), "{detail}");
}

#[tokio::test]
async fn a_malformed_id_is_a_400_naming_id() {
    let (router, _db, _kv) = offers().await;
    let answer = get(&router, "/v1/offers/BadSlug/also-bad").await;
    assert_eq!(answer.status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(problem_parameter(&answer.body), "id");
}

#[tokio::test]
async fn a_row_with_unknown_prices_round_trips_unchanged() {
    let (router, _db, _kv) = offers().await;
    let groq = fixtures()
        .into_iter()
        .find(|offer| offer.id == "groq/llama-4-maverick")
        .expect("the groq fixture");

    let answer = get(&router, "/v1/offers/groq/llama-4-maverick").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    // "unknown" is the string "unknown", never null or 0.
    assert_eq!(
        answer.body["data"]["cache_write_per_mtok"],
        json!("unknown")
    );
    assert_eq!(answer.body["data"]["input_per_mtok"], json!("unknown"));
    assert_eq!(answer.body["data"]["usd"]["blended_3to1"], json!("unknown"));
    // The whole row equals the fixture except the two stamped fields.
    assert_eq!(answer.body["data"], groq.expected_row());

    // And the same is true inside a list page.
    let answer = get(&router, "/v1/offers?provider=groq").await;
    let rows = answer.body["data"].as_array().expect("an array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], groq.expected_row());
}

#[tokio::test]
async fn stale_rows_carry_their_first_stale_day() {
    let (router, _db, _kv) = offers().await;
    let answer = get(&router, "/v1/offers/deepseek/deepseek-chat-v3.2").await;
    assert_eq!(answer.body["data"]["stale"], json!(true));
    assert_eq!(answer.body["data"]["stale_since"], json!("2026-09-05"));
    let answer = get(&router, "/v1/offers/mistral/mistral-large-2411").await;
    assert_eq!(answer.body["data"]["stale"], json!(true));
    assert_eq!(answer.body["data"]["stale_since"], json!("2026-10-13"));
}

#[tokio::test]
async fn dataset_meta_overrides_the_envelope_fallbacks() {
    let (router, _db, _kv) = offers_with_meta().await;
    let answer = get(&router, "/v1/offers?limit=1").await;
    assert_eq!(answer.body["source_commit"], json!("9b4a2dc"));
    assert_eq!(answer.body["license"], json!("CC BY 4.0"));
    let answer = get(&router, "/v1/offers/anthropic/claude-fable-5-1").await;
    assert_eq!(answer.body["source_commit"], json!("9b4a2dc"));
    assert_eq!(answer.body["license"], json!("CC BY 4.0"));
}

#[tokio::test]
async fn cache_hits_and_invalidation_apply_to_both_routes() {
    for uri in [
        "/v1/offers?provider=openrouter",
        "/v1/offers/openrouter/gpt-5.1",
    ] {
        let (router, db, kv) = offers().await;

        let first = get(&router, uri).await;
        assert_eq!(first.status, axum::http::StatusCode::OK, "{uri}");
        let after_first = db.queries();

        // The second identical request is the cached body, not a D1 read.
        let second = get(&router, uri).await;
        assert_eq!(second.body, first.body, "{uri}: the cached body");
        assert_eq!(db.queries(), after_first, "{uri}: the cache answered");

        // A changed dataset identity orphans the entry: D1 again.
        invalidate_cache(kv.as_ref(), "9b4a2dc")
            .await
            .expect("the bump writes");
        let third = get(&router, uri).await;
        assert_eq!(third.body, first.body, "{uri}: rebuilt identically");
        assert!(db.queries() > after_first, "{uri}: a new generation missed");

        // Re-loading the same dataset keeps the cache: the write is
        // idempotent, and no invalidation is lost by re-setting it.
        let after_third = db.queries();
        invalidate_cache(kv.as_ref(), "9b4a2dc")
            .await
            .expect("the re-bump writes");
        let fourth = get(&router, uri).await;
        assert_eq!(fourth.body, first.body, "{uri}");
        assert_eq!(db.queries(), after_third, "{uri}: same generation, hit");
    }

    // A malformed identity must fail the load, never silently keep serving
    // the previous dataset's cache.
    let (_router, _db, kv) = offers().await;
    for bad in ["", "9b4a2dc ", "dead:beef", "sha/1"] {
        assert!(
            invalidate_cache(kv.as_ref(), bad).await.is_err(),
            "{bad:?} must be rejected"
        );
    }
}

#[tokio::test]
async fn a_failing_kv_never_fails_the_request() {
    let router = offers_with_failing_kv().await;
    let answer = get(&router, "/v1/offers?limit=2").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    assert_eq!(ids(&answer.body).len(), 2);
    let answer = get(&router, "/v1/offers/deepseek/deepseek-chat-v3.2").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    assert_eq!(
        answer.body["data"]["id"],
        json!("deepseek/deepseek-chat-v3.2")
    );
}

#[tokio::test]
async fn an_empty_result_page_has_no_cursor() {
    let (router, _db, _kv) = offers().await;
    let answer = get(&router, "/v1/offers?open_weights=unknown").await;
    assert_eq!(answer.status, axum::http::StatusCode::OK);
    assert_eq!(answer.body["data"], json!([]));
    assert_eq!(answer.body["next_cursor"], Json::Null);
}

#[test]
fn the_license_fallback_is_the_datasets_own_license() {
    // The fallback the envelope serves must be exactly what
    // data/pricing.json declares, not a drift-prone copy of it.
    let dataset: Json =
        serde_json::from_str(include_str!("../../../data/pricing.json")).expect("dataset parses");
    assert_eq!(dataset["license"], json!(DATASET_LICENSE));
}
