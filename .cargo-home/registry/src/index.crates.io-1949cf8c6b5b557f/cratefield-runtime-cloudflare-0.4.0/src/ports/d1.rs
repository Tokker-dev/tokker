//! `Database` over `worker::D1Database` (ADR 0004): sea-query renders the
//! statement, values bind positionally, `batch` uses D1's atomic batch.

use async_trait::async_trait;
use cratefield_core::{Database, DbError, Row, Rows, Statement};
use sea_query::Value as SeaValue;
use serde_json::Value as Json;
use worker::D1Database as WorkerD1;
use worker::send::IntoSendFuture;

pub struct D1Database(pub WorkerD1);

/// A value ready to hand to D1's `bind()`. The decision is pure and unit
/// tested natively; only the `JsValue` construction in [`bind_statement`]
/// needs wasm.
#[derive(Debug)]
enum Bind {
    Null,
    Json(Json),
    Bytes(Vec<u8>),
}

/// D1 BLOB marshalling, verified empirically under workerd/miniflare:
/// - `bind()` stores an `ArrayBuffer` or typed array as BLOB; we build a real
///   `Uint8Array`. A plain array of numbers happens to work locally but is
///   undocumented, and a `DataView` silently stores zero bytes.
/// - `serde_wasm_bindgen` can never produce a typed array out of a
///   `serde_json::Value` (it has no bytes variant, so `serialize_bytes` is
///   never called), so bytes must bypass the JSON hop entirely.
/// - Reads are unambiguous: BLOB comes back as a plain array of numbers, and
///   because D1 is SQLite (storage classes NULL/INTEGER/REAL/TEXT/BLOB map to
///   null/number/string/array on read), a JSON array in a result row can only
///   be a BLOB — TEXT containing `[1,2,3]` comes back as a string. So
///   [`json_to_sea`] decodes arrays as bytes; no `typeof(col)` SQL is needed.
fn decide_bind(value: &SeaValue) -> Bind {
    // Bytes bypass the JSON hop entirely: `serde_wasm_bindgen` has no bytes
    // variant, so a `serde_json::Value` can never come back out as a typed
    // array (see the module comment). `Bytes(None)` falls through and joins
    // every other null in [`Bind::Null`].
    if let SeaValue::Bytes(Some(bytes)) = value {
        return Bind::Bytes(bytes.to_vec());
    }
    let json = sea_to_json(value);
    if json.is_null() {
        Bind::Null
    } else {
        Bind::Json(json)
    }
}

fn bind_statement(
    db: &WorkerD1,
    stmt: &Statement,
) -> worker::Result<worker::d1::D1PreparedStatement> {
    let prepared = db.prepare(&stmt.sql);
    if stmt.values.0.is_empty() {
        return Ok(prepared);
    }
    // Bind through serde_json + serde_wasm_bindgen rather than `bind_refs`
    // with `D1Type`: the `D1Type` conversion path fails (integer binds
    // error, text binds hang) under workerd/miniflare, while the
    // JSON->JsValue path is the one workers-rs itself uses for D1 results.
    //
    // `decide_bind` routes every null (JSON null and `Bytes(None)`) to a
    // single [`Bind::Null`]: `serde_wasm_bindgen` renders JSON null as
    // `undefined`, and D1 rejects `undefined` with `D1_TYPE_ERROR: Type
    // 'undefined' not supported`, so any write with a NULL column (a
    // nullable field left unset) would fail. Bytes bypass the JSON hop (see
    // [`decide_bind`]); everything else crosses as JSON.
    let js_values: Vec<worker::wasm_bindgen::JsValue> = stmt
        .values
        .0
        .iter()
        .map(decide_bind)
        .map(|bind| match bind {
            Bind::Null => Ok(worker::wasm_bindgen::JsValue::NULL),
            Bind::Json(json) => worker::d1::serde_wasm_bindgen::to_value(&json),
            Bind::Bytes(bytes) => Ok(worker::js_sys::Uint8Array::from(bytes.as_slice()).into()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(worker::Error::SerdeWasmBindgenError)?;
    prepared.bind(&js_values)
}

fn sea_to_json(value: &SeaValue) -> serde_json::Value {
    match value {
        SeaValue::Bool(Some(v)) => serde_json::Value::Bool(*v),
        SeaValue::TinyInt(Some(v)) => (*v).into(),
        SeaValue::SmallInt(Some(v)) => (*v).into(),
        SeaValue::Int(Some(v)) => (*v).into(),
        SeaValue::BigInt(Some(v)) => (*v).into(),
        SeaValue::TinyUnsigned(Some(v)) => (*v).into(),
        SeaValue::SmallUnsigned(Some(v)) => (*v).into(),
        SeaValue::Unsigned(Some(v)) => (*v).into(),
        // u64 > JSON safe range is not representable; the portable subset
        // stores ids as TEXT, so this never triggers in practice.
        SeaValue::BigUnsigned(Some(v)) => (*v).into(),
        SeaValue::Float(Some(v)) => f64::from(*v).into(),
        SeaValue::Double(Some(v)) => (*v).into(),
        SeaValue::String(Some(v)) => v.as_str().into(),
        _ => serde_json::Value::Null,
    }
}

fn json_to_sea(value: &Json) -> SeaValue {
    match value {
        Json::Null => SeaValue::String(None),
        Json::Bool(v) => SeaValue::Bool(Some(*v)),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                SeaValue::BigInt(Some(i))
            } else {
                SeaValue::Double(Some(n.as_f64().unwrap_or_default()))
            }
        }
        Json::String(s) => SeaValue::String(Some(Box::new(s.clone()))),
        Json::Array(items) => match array_to_bytes(items) {
            Some(bytes) => SeaValue::Bytes(Some(Box::new(bytes))),
            // Should be unreachable: D1 is SQLite, and its read mapping
            // (NULL/INTEGER/REAL/TEXT/BLOB -> null/number/string/array)
            // means a JSON array in a result row can only be a BLOB, which
            // `array_to_bytes` accepts. If a future D1 ever returns a
            // non-byte array here, stringify rather than silently null the
            // column.
            None => SeaValue::String(Some(Box::from(value.to_string()))),
        },
        Json::Object(_) => SeaValue::String(Some(Box::from(value.to_string()))),
    }
}

/// A D1 BLOB reads back as a plain array of numbers, so an array of integers
/// in `0..=255` is bytes (an empty array is empty bytes). Anything else
/// (256, -1, 2.5, a nested array) is not a BLOB read.
fn array_to_bytes(items: &[Json]) -> Option<Vec<u8>> {
    items
        .iter()
        .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect()
}

fn d1_rows_to_rows(result: &worker::d1::D1Result) -> Result<Rows, DbError> {
    let values: Vec<Json> = result.results().map_err(|err| {
        log_d1(&err);
        DbError::Query(err.to_string())
    })?;
    let rows = values
        .into_iter()
        .map(|value| {
            let Json::Object(map) = value else {
                return Row::new(Vec::new());
            };
            Row::new(
                map.into_iter()
                    .map(|(column, value)| (column, json_to_sea(&value)))
                    .collect(),
            )
        })
        .collect();
    Ok(Rows::new(rows))
}

/// Logs a D1 error straight to `console_error!` before it becomes a
/// [`DbError`]. `install_tracing` is a no-op on wasm (installing a dispatcher
/// hangs the isolate), so the `tracing::error!` the harness emits when it maps
/// a `DbError` to a 500 is dropped on Workers; without this, a failed query or
/// write is an opaque `500` in `wrangler tail`. Errors are the exceptional
/// path, and D1's messages are structural (no row data), so logging them here
/// is safe.
fn log_d1(err: &worker::Error) {
    worker::console_error!("[d1] {err}");
}

#[async_trait]
impl Database for D1Database {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        let prepared = bind_statement(&self.0, stmt).map_err(|err| {
            log_d1(&err);
            DbError::Execute(err.to_string())
        })?;
        // Writes go through `batch` (single-statement): plain `.run()` /
        // `.all()` promises never resolve for writes under local
        // workerd/miniflare (verified empirically); batch resolves.
        let results = self
            .0
            .batch(vec![prepared])
            .into_send()
            .await
            .map_err(|err| {
                log_d1(&err);
                DbError::Execute(err.to_string())
            })?;
        let changed = results
            .first()
            .and_then(|result| result.meta().ok().flatten())
            .and_then(|meta| meta.changes)
            .unwrap_or_default();
        Ok(u64::try_from(changed).unwrap_or(u64::MAX))
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        let prepared = bind_statement(&self.0, stmt).map_err(|err| {
            log_d1(&err);
            DbError::Query(err.to_string())
        })?;
        let result = prepared.all().into_send().await.map_err(|err| {
            log_d1(&err);
            DbError::Query(err.to_string())
        })?;
        d1_rows_to_rows(&result)
    }

    /// D1 batches are atomic (single implicit transaction).
    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), DbError> {
        let mut prepared = Vec::with_capacity(stmts.len());
        for stmt in stmts {
            prepared.push(bind_statement(&self.0, stmt).map_err(|err| {
                log_d1(&err);
                DbError::Batch(err.to_string())
            })?);
        }
        self.0.batch(prepared).into_send().await.map_err(|err| {
            log_d1(&err);
            DbError::Batch(err.to_string())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte values a BLOB round trip must survive: NUL, the byte-255
    /// i64/i32-sign trap, and two bytes that are invalid UTF-8 on their own.
    fn hostile_payload() -> Vec<u8> {
        vec![0x00, 0x41, 0xFF, 0x80, 0xFE]
    }

    /// The row JSON workerd produces for a BLOB column: a plain array of
    /// numbers, as read back after the serde hop.
    fn blob_row(payload: &[u8]) -> Json {
        Json::Array(payload.iter().map(|byte| Json::from(*byte)).collect())
    }

    fn decoded(value: &Json) -> Vec<u8> {
        match json_to_sea(value) {
            SeaValue::Bytes(Some(bytes)) => *bytes,
            SeaValue::String(Some(text)) => panic!("stringified, not decoded: {text}"),
            other => panic!("unexpected sea value: {other:?}"),
        }
    }

    #[test]
    fn bind_sends_every_byte_of_a_blob() {
        let payload = hostile_payload();
        match decide_bind(&SeaValue::Bytes(Some(Box::new(payload.clone())))) {
            Bind::Bytes(bytes) => assert_eq!(bytes, payload),
            other => panic!("expected Bind::Bytes, got {other:?}"),
        }
    }

    #[test]
    fn bind_maps_bytes_none_to_null() {
        assert!(matches!(decide_bind(&SeaValue::Bytes(None)), Bind::Null));
    }

    #[test]
    fn decode_survives_nul_and_invalid_utf8() {
        let payload = hostile_payload();
        assert_eq!(decoded(&blob_row(&payload)), payload);
    }

    #[test]
    fn decode_empty_blob_to_empty_bytes() {
        assert_eq!(decoded(&blob_row(&[])), Vec::<u8>::new());
    }

    #[test]
    fn non_byte_arrays_are_not_blobs() {
        for row in [
            Json::Array(vec![Json::from(256)]),
            Json::Array(vec![Json::from(-1)]),
            Json::Array(vec![Json::from(2.5)]),
            Json::Array(vec![Json::from(1), Json::Array(vec![Json::from(2)])]),
        ] {
            match json_to_sea(&row) {
                SeaValue::String(Some(_)) => {}
                other => panic!("{row} decoded as {other:?}"),
            }
        }
    }

    #[test]
    fn non_blob_binds_are_unchanged() {
        for (sea, json) in [
            (SeaValue::Bool(Some(true)), Json::Bool(true)),
            (SeaValue::Int(Some(7)), Json::from(7)),
            (
                SeaValue::BigInt(Some(i64::from(i32::MAX))),
                Json::from(i64::from(i32::MAX)),
            ),
            (SeaValue::Double(Some(2.5)), Json::from(2.5)),
            (
                SeaValue::String(Some(Box::new("x".to_owned()))),
                Json::String("x".to_owned()),
            ),
        ] {
            match decide_bind(&sea) {
                Bind::Json(value) => assert_eq!(value, json),
                other => panic!("{sea:?} bound as {other:?}"),
            }
        }
    }

    #[test]
    fn non_blob_decodes_are_unchanged() {
        assert!(matches!(json_to_sea(&Json::Null), SeaValue::String(None)));
        assert!(matches!(
            json_to_sea(&Json::Bool(false)),
            SeaValue::Bool(Some(false))
        ));
        assert!(matches!(
            json_to_sea(&Json::from(7)),
            SeaValue::BigInt(Some(7))
        ));
        assert!(matches!(
            json_to_sea(&Json::from(2.5)),
            SeaValue::Double(Some(f)) if (f - 2.5).abs() < f64::EPSILON
        ));
        assert!(matches!(
            json_to_sea(&Json::String("x".to_owned())),
            SeaValue::String(Some(_))
        ));
        // A TEXT column holding the characters "[1,2]" returns as a string,
        // not an array, and must not be mistaken for a BLOB.
        assert!(matches!(
            json_to_sea(&Json::String("[1,2]".to_owned())),
            SeaValue::String(Some(_))
        ));
    }
}
