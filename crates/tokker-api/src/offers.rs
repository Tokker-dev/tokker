//! `/v1/offers` — the public price index over the `offers` table
//! (issue #19, plan.md §3).
//!
//! # Contract
//!
//! **`GET /v1/offers`** — filter, sort and page the API offers:
//!
//! ```text
//! ?model=&provider=&creator=&provider_type=&open_weights=&currency=
//! &max_input=&max_output=&stale=&sort=blended|input|output&limit=&cursor=
//! ```
//!
//! - `model` (canonical model slug), `provider`, `creator` are slug values;
//!   `provider_type` is `first_party|aggregator|inference_host|cloud`;
//!   `open_weights` is `true|false|unknown`; `currency` is a 3-letter ISO
//!   4217 code (upper-cased for you).
//! - `max_input`/`max_output` are USD per Mtok ceilings compared against the
//!   derived `usd{}` block; offers whose USD price is unknown are excluded.
//! - `stale=true|false` keeps only rows whose read-time freshness verdict
//!   matches (the same [`staleness`](crate::freshness::staleness) rules the
//!   build stamps).
//! - `sort` defaults to `blended` (the 3:1 input:output blend); unknown USD
//!   sorts last; the id breaks ties. The raw price columns are always in the
//!   row — sorting never rewrites the data.
//! - `limit` is 1..=200 (default 50); `cursor` is the opaque `next_cursor`
//!   of the previous page. Walking pages yields every matching row exactly
//!   once, in order.
//!
//! Every row is the verbatim dataset row (`offers.json`) — `"unknown"` stays
//! the string `"unknown"`, never null or 0 — with `stale` and `stale_since`
//! stamped at read time (`stale_since` is null while fresh). The envelope
//! carries `as_of` (the dataset's latest `last_verified_at` across offers
//! and plans), `source_commit` and `license` (from the `dataset_meta` table
//! the repo-mirror fills; `"unknown"` and the dataset's own license string
//! when it has not), `data`, and `next_cursor` (null on the last page).
//!
//! **`GET /v1/offers/{provider}/{model}`** — one offer by its id
//! (`"<provider_id>/<model_slug>"`), same envelope with a single object as
//! `data`. An unknown id is a 404 problem naming it.
//!
//! Errors are problem+json: 400 names the parameter (extension `parameter`)
//! for an unknown parameter, a repeated one, or a bad value; 404 names the
//! id; a cursor minted for another `sort` is a 400 naming `cursor`.
//!
//! # Caching
//!
//! Both routes read through the KV port, keyed by
//! `offers:v1:<generation>:<today>:<query or id>`, where `<generation>` is
//! the identity of the loaded dataset (its source commit; `0` when the
//! mirror has not written one). Only 200 responses are cached (TTL 1 h).
//! A KV failure never fails a request: the route falls through to D1.
//! After loading a dataset, the repo-mirror's diff hook calls
//! [`invalidate_cache`] with the dataset's identity: a new identity orphans
//! every cached entry at once, and re-loading the same dataset keeps the
//! cache valid.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use cratefield_core::{
    Config, ConfigError, ControlLevel, Database, KeyValue, KvError, Migrations, Module,
    ModuleContext, Port, Problem, Row, Statement, forward_control_event,
};
use sea_query::Value as SeaValue;
use serde_json::Value as Json;

use crate::freshness::{self, RowType};
use crate::offers_query::{
    self, Cursor, InvalidParam, NormalisedQuery, Position, decode_cursor, encode_cursor, not_after,
    param_error, valid_slug,
};

/// The dataset's own license (data/pricing.json `license`), served when the
/// mirror has not written one into `dataset_meta`. Public so the route tests
/// can pin it to the file it comes from.
pub const DATASET_LICENSE: &str = "CC BY 4.0 (proposed)";

/// How long a cached 200 response stays in KV. The mirror's diff hook
/// invalidates earlier; the TTL is only the safety net.
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// The KV key holding the cache generation: the identity of the loaded
/// dataset ([`invalidate_cache`] writes it).
const GENERATION_KEY: &str = "offers:generation";

/// A usable cache generation: a non-empty token of `[A-Za-z0-9._-]`. The
/// expected input is a hex source-commit sha; `:` (the key separator) and
/// whitespace are refused so the token can never blur the key format.
fn valid_generation(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// The `/v1/offers` module: the public price index.
///
/// Construct plain (`Offers`) for the real clock, or
/// [`Offers::with_today`] to pin the date staleness is computed against —
/// that is what the route tests do.
#[derive(Default)]
pub struct Offers {
    /// A fixed `YYYY-MM-DD` the module treats as today, for deterministic
    /// tests; `None` reads the `Clock` port per request.
    today: Option<String>,
}

impl Offers {
    /// Pins the date staleness is computed against (`YYYY-MM-DD`).
    #[must_use]
    pub fn with_today(today: impl Into<String>) -> Self {
        Self {
            today: Some(today.into()),
        }
    }
}

impl Module for Offers {
    fn name(&self) -> &'static str {
        "offers"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// D1 for the price tables, KV for the response cache, and a clock:
    /// staleness is computed at read time against today, so a module without
    /// a date cannot serve honest rows.
    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::KeyValue, Port::Clock]
    }

    fn tables(&self) -> &'static [&'static str] {
        &["dataset_meta"]
    }

    /// The tables are applied by wrangler from `migrations/` (see the header
    /// of `migrations/0001_core_tables.sql`); the Worker applies no SQL.
    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, _cfg: &dyn Config) -> Result<(), ConfigError> {
        Ok(())
    }

    fn router(&self, ctx: ModuleContext) -> Router {
        let state = Arc::new(OffersState {
            ctx: Arc::new(ctx),
            today: self.today.clone(),
        });
        Router::new()
            .route("/", get(list_offers))
            .route("/{provider}/{model}", get(get_offer))
            .with_state(state)
    }
}

/// What the handlers see: the module context plus the pinned test date.
struct OffersState {
    ctx: Arc<ModuleContext>,
    today: Option<String>,
}

impl OffersState {
    fn db(&self) -> Result<Arc<dyn Database>, Problem> {
        self.ctx.ports.db.clone().ok_or_else(|| {
            Problem::not_ready("Database port is not configured for the offers module")
        })
    }

    fn kv(&self) -> Option<Arc<dyn KeyValue>> {
        self.ctx.ports.kv.clone()
    }

    /// Today as `YYYY-MM-DD`: the pinned test date, else the clock port's
    /// UTC date. Both clock implementations (`SystemClock`,
    /// `WorkersClock`) report UTC.
    fn today(&self) -> Result<String, Problem> {
        if let Some(today) = &self.today {
            return Ok(today.clone());
        }
        let clock = self.ctx.ports.clock.as_ref().ok_or_else(|| {
            Problem::not_ready("Clock port is not configured: staleness needs today's date")
        })?;
        let now = clock.now();
        Ok(format!(
            "{:04}-{:02}-{:02}",
            now.year(),
            u8::from(now.month()),
            now.day()
        ))
    }
}

/// `GET /v1/offers`: filter, sort and page.
async fn list_offers(
    State(state): State<Arc<OffersState>>,
    RawQuery(raw): RawQuery,
) -> Result<Response, Problem> {
    let query = offers_query::parse_query(raw.as_deref()).map_err(problem)?;
    let cursor = decode_request_cursor(&query)?;
    let today = state.today()?;

    // Read-through cache: only well-formed requests reach the key, and only
    // 200 bodies are ever stored, so a hit is always the final response.
    let mut cache: Option<(Arc<dyn KeyValue>, String)> = match state.kv() {
        Some(kv) => {
            let key = cache_key(kv.as_ref(), &today, &format!("q:{}", query.canonical())).await;
            match kv.get(&key).await {
                Ok(Some(body)) => return Ok(ok_json(body)),
                _ => Some((kv, key)),
            }
        }
        None => None,
    };

    let meta = fetch_meta(state.db()?.as_ref()).await?;
    let rows = fetch_rows(state.db()?.as_ref(), &query).await?;
    let (data, next_cursor) =
        assemble_page(rows, &query, cursor.as_ref(), &today).map_err(internal)?;
    let body = serde_json::to_string(&serde_json::json!({
        "as_of": meta.as_of,
        "source_commit": meta.source_commit,
        "license": meta.license,
        "data": data,
        "next_cursor": next_cursor,
    }))
    .expect("a json! value serialises");
    if let Some((kv, key)) = cache.take() {
        // A failed write only costs the next request a D1 read.
        let _ = kv.put(&key, &body, Some(CACHE_TTL)).await;
    }
    Ok(ok_json(body))
}

/// `GET /v1/offers/{provider}/{model}`: one offer by id.
async fn get_offer(
    State(state): State<Arc<OffersState>>,
    Path((provider, model)): Path<(String, String)>,
) -> Result<Response, Problem> {
    for segment in [&provider, &model] {
        if !valid_slug(segment) {
            return Err(problem(param_error(
                "id",
                format!(
                    "must be `<provider_id>/<model_slug>`, lowercase slugs — got `{provider}/{model}`"
                ),
            )));
        }
    }
    let id = format!("{provider}/{model}");
    let today = state.today()?;

    let mut cache: Option<(Arc<dyn KeyValue>, String)> = match state.kv() {
        Some(kv) => {
            let key = cache_key(kv.as_ref(), &today, &format!("id:{id}")).await;
            match kv.get(&key).await {
                Ok(Some(body)) => return Ok(ok_json(body)),
                _ => Some((kv, key)),
            }
        }
        None => None,
    };

    let meta = fetch_meta(state.db()?.as_ref()).await?;
    let rows = state
        .db()?
        .query(&Statement::with_values(
            "SELECT json, last_verified_at FROM offers WHERE id = ?",
            vec![SeaValue::String(Some(Box::new(id.clone())))],
        ))
        .await?;
    let Some(row) = rows.first() else {
        return Err(Problem::not_found()
            .with_detail(format!("no offer with id `{id}`"))
            .with_extension("id", id));
    };
    let (offer, _stale) = shape(
        &row.get::<String>("json").unwrap_or_default(),
        &row.get::<String>("last_verified_at").unwrap_or_default(),
        &today,
    )
    .map_err(internal)?;
    let body = serde_json::to_string(&serde_json::json!({
        "as_of": meta.as_of,
        "source_commit": meta.source_commit,
        "license": meta.license,
        "data": offer,
    }))
    .expect("a json! value serialises");
    if let Some((kv, key)) = cache.take() {
        let _ = kv.put(&key, &body, Some(CACHE_TTL)).await;
    }
    Ok(ok_json(body))
}

/// Decodes and validates the request's cursor: it must decode and have been
/// minted for the requested sort.
fn decode_request_cursor(query: &NormalisedQuery) -> Result<Option<Cursor>, Problem> {
    let Some(raw) = &query.cursor else {
        return Ok(None);
    };
    let cursor = decode_cursor(raw).map_err(problem)?;
    if cursor.sort != query.sort {
        return Err(problem(param_error(
            "cursor",
            format!(
                "was minted for sort `{}` but the request sorts by `{}`",
                cursor.sort.as_str(),
                query.sort.as_str(),
            ),
        )));
    }
    Ok(Some(cursor))
}

/// The dataset-wide fields of the envelope, in one query.
struct DatasetMeta {
    as_of: String,
    source_commit: String,
    license: String,
}

async fn fetch_meta(db: &dyn Database) -> Result<DatasetMeta, Problem> {
    let rows = db
        .query(&Statement::new(
            "SELECT \
               (SELECT MAX(last_verified_at) FROM offers) AS offers_as_of, \
               (SELECT MAX(last_verified_at) FROM plans) AS plans_as_of, \
               (SELECT value FROM dataset_meta WHERE key = 'source_commit') AS source_commit, \
               (SELECT value FROM dataset_meta WHERE key = 'license') AS license",
        ))
        .await?;
    let row = rows.first().ok_or_else(Problem::internal)?;
    let as_of = ["offers_as_of", "plans_as_of"]
        .into_iter()
        .filter_map(|column| row.get::<Option<String>>(column).flatten())
        .max()
        .unwrap_or_else(|| "unknown".to_string());
    Ok(DatasetMeta {
        as_of,
        source_commit: row
            .get::<Option<String>>("source_commit")
            .flatten()
            .unwrap_or_else(|| "unknown".to_string()),
        license: row
            .get::<Option<String>>("license")
            .flatten()
            .unwrap_or_else(|| DATASET_LICENSE.to_string()),
    })
}

/// One row as the SQL layer produced it: the verbatim dataset JSON plus the
/// columns pagination and freshness need.
struct FetchedRow {
    json: String,
    last_verified_at: String,
    sort_value: Option<f64>,
    id: String,
}

async fn fetch_rows(
    db: &dyn Database,
    query: &NormalisedQuery,
) -> Result<Vec<FetchedRow>, Problem> {
    let mut conditions: Vec<&'static str> = Vec::new();
    let mut values: Vec<SeaValue> = Vec::new();
    // Every filter is a bound parameter; the only interpolated strings are
    // these fixed condition texts and the whitelisted sort column below.
    let mut text = |condition: &'static str, value: &str| {
        conditions.push(condition);
        values.push(SeaValue::String(Some(Box::new(value.to_string()))));
    };
    if let Some(model) = &query.model {
        text("model_id = ?", model);
    }
    if let Some(provider) = &query.provider {
        text("provider_id = ?", provider);
    }
    if let Some(creator) = &query.creator {
        text("creator = ?", creator);
    }
    if let Some(provider_type) = &query.provider_type {
        text("provider_type = ?", provider_type);
    }
    if let Some(open_weights) = &query.open_weights {
        text("open_weights = ?", open_weights);
    }
    if let Some(currency) = &query.currency {
        text("currency = ?", currency);
    }
    if let Some(max_input) = query.max_input {
        conditions.push("usd_input_per_mtok <= ?");
        values.push(SeaValue::Double(Some(max_input)));
    }
    if let Some(max_output) = query.max_output {
        conditions.push("usd_output_per_mtok <= ?");
        values.push(SeaValue::Double(Some(max_output)));
    }
    // The sort column comes from the fixed `Sort` whitelist, never user
    // input; every value above is a bound parameter.
    let sort_column = query.sort_column();
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    let sql = format!(
        "SELECT json, {sort_column} AS sort_value, last_verified_at, id \
         FROM offers{where_clause} \
         ORDER BY {sort_column} IS NULL, {sort_column}, id"
    );
    let rows = db.query(&Statement::with_values(sql, values)).await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| FetchedRow {
            json: row.get::<String>("json").unwrap_or_default(),
            last_verified_at: row.get::<String>("last_verified_at").unwrap_or_default(),
            sort_value: real(row, "sort_value"),
            id: row.get::<String>("id").unwrap_or_default(),
        })
        .collect())
}

/// Applies the `stale` filter, walks past the cursor position, takes the
/// page and mints the next cursor. The SQL order and the cursor comparison
/// agree by construction: both are (value IS NULL, value, id).
fn assemble_page(
    rows: Vec<FetchedRow>,
    query: &NormalisedQuery,
    cursor: Option<&Cursor>,
    today: &str,
) -> Result<(Vec<Json>, Option<String>), PageError> {
    let cursor_position = cursor.map(|cursor| Position {
        is_null: cursor.value.is_none(),
        value: cursor.value.unwrap_or(0.0),
        id: cursor.id.clone(),
    });
    let limit = query.limit as usize;
    let mut page: Vec<(Position, Json)> = Vec::new();
    for row in rows {
        let (offer, stale) = shape(&row.json, &row.last_verified_at, today)?;
        if let Some(wanted) = query.stale {
            if stale != wanted {
                continue;
            }
        }
        let position = Position {
            is_null: row.sort_value.is_none(),
            value: row.sort_value.unwrap_or(0.0),
            id: row.id.clone(),
        };
        // Skip everything up to and including the cursor's row.
        if cursor_position
            .as_ref()
            .is_some_and(|cursor| not_after(&position, cursor))
        {
            continue;
        }
        page.push((position, offer));
        // One row past the page is enough to know more remain.
        if page.len() > limit {
            break;
        }
    }
    let more_remain = page.len() > limit;
    let next_cursor = more_remain.then(|| {
        let (position, _) = &page[limit - 1];
        encode_cursor(&Cursor {
            sort: query.sort,
            value: (!position.is_null).then_some(position.value),
            id: position.id.clone(),
        })
    });
    let data: Vec<Json> = page
        .into_iter()
        .take(limit)
        .map(|(_, offer)| offer)
        .collect();
    Ok((data, next_cursor))
}

/// Stamps `stale`/`stale_since` onto one row's verbatim JSON. Returns the
/// shaped row and its staleness (the caller filters on it). `"unknown"`
/// strings and every other value pass through untouched — only the two
/// freshness fields are added.
fn shape(json_text: &str, last_verified_at: &str, today: &str) -> Result<(Json, bool), PageError> {
    let mut offer: Json = serde_json::from_str(json_text)
        .map_err(|err| PageError(format!("stored row is not valid JSON: {err}")))?;
    let volatility = offer
        .pointer("/fetch_recipe/volatility")
        .and_then(Json::as_str);
    let verdict = freshness::staleness(RowType::ApiOffer, volatility, last_verified_at, today)
        .map_err(|err| PageError(format!("staleness of a stored row: {err}")))?;
    let stale = verdict.stale;
    if let Some(object) = offer.as_object_mut() {
        object.insert("stale".into(), Json::Bool(stale));
        object.insert(
            "stale_since".into(),
            verdict.stale_since.map_or(Json::Null, Json::String),
        );
    }
    Ok((offer, stale))
}

/// Why a page could not be assembled: a stored row the API refuses to serve
/// rather than silently mis-date (data rule 1: never invent).
struct PageError(String);

impl From<PageError> for Problem {
    fn from(error: PageError) -> Self {
        forward_control_event(ControlLevel::Error, &error.0);
        Problem::internal()
    }
}

fn internal(error: PageError) -> Problem {
    error.into()
}

/// A 200 body with the JSON content type. No `Cache-Control` here: the
/// harness's security-headers layer overwrites it with `no-store` on every
/// `/v1/*` response (cratefield-core `insert_no_store_headers`), so a
/// module-set value would never reach a client. Caching is the KV read
/// through, keyed by generation and day.
fn ok_json(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// The KV generation: the identity of the loaded dataset, or `0` when the
/// key is absent, unreadable or malformed (a KV error must never fail the
/// request, so this degrades to a static prefix and at worst orphans an
/// entry nobody will ask for again).
async fn generation(kv: &dyn KeyValue) -> String {
    kv.get(GENERATION_KEY)
        .await
        .ok()
        .flatten()
        .filter(|token| valid_generation(token))
        .unwrap_or_else(|| "0".to_string())
}

async fn cache_key(kv: &dyn KeyValue, today: &str, payload: &str) -> String {
    format!("offers:v1:{}:{today}:{payload}", generation(kv).await)
}

/// Invalidates every cached `/v1/offers` response by setting the cache
/// generation their keys carry to the identity of the loaded dataset.
///
/// This is the entry point the repo-mirror's diff hook calls (plan.md §5.2
/// G1) after loading a new `pricing.json` into D1. The mirror passes the
/// dataset's identity — its source commit (a hex sha). The write is
/// idempotent and needs no read-modify-write, so concurrent loads cannot
/// lose an invalidation: a *changed* identity orphans every cached entry at
/// once (per-key deletes are not needed), and re-loading the *same* dataset
/// keeps the cache valid.
///
/// The migration loader should treat an error as a failed load — the
/// dataset is in D1 but readers may still be served the previous one.
///
/// # Errors
///
/// `dataset` is not a usable identity token (empty, or containing `:` or
/// whitespace — it is part of the cache key), or the KV write failed. The
/// request path is unaffected: it keeps falling through to D1 on KV errors.
pub async fn invalidate_cache(kv: &dyn KeyValue, dataset: &str) -> Result<(), KvError> {
    if !valid_generation(dataset) {
        return Err(KvError::Operation(format!(
            "`{dataset}` is not a usable cache generation: pass the dataset's source commit \
             (a non-empty token of [A-Za-z0-9._-])"
        )));
    }
    kv.put(GENERATION_KEY, dataset, None).await
}

/// Reads a REAL column defensively: D1 hands integral REALs back as `BigInt`,
/// rusqlite as Double, and both adapters report SQL NULL as `String(None)`.
fn real(row: &Row, column: &str) -> Option<f64> {
    match row.get::<SeaValue>(column) {
        Some(SeaValue::Double(Some(value))) => Some(value),
        Some(SeaValue::Float(Some(value))) => Some(f64::from(value)),
        Some(SeaValue::BigInt(Some(value))) => {
            // An integral REAL from D1. Lossless for every price in range.
            #[allow(clippy::cast_precision_loss)]
            Some(value as f64)
        }
        _ => None,
    }
}

/// An [`InvalidParam`] as a 400 problem that names the parameter.
fn problem(error: InvalidParam) -> Problem {
    Problem::validation_failed(error.message).with_extension("parameter", error.name)
}
