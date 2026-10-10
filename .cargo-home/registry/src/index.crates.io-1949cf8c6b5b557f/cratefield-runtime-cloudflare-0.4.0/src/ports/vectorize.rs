//! `VectorIndex` over a Cloudflare Vectorize index binding (issue #561,
//! ADR 0024). `worker` 0.8.5 ships no Vectorize wrappers, so the binding
//! is declared by hand below and held behind `worker::send::SendWrapper`
//! — which makes the port `Send + Sync` without an `unsafe` line; missing
//! bindings are an `Err`, never a panic.
//!
//! Vectorize's ids are unique across the whole index and `deleteByIds`
//! takes no namespace, while the port is per-namespace — so every record
//! is stored under hex `SHA-256(namespace + "\u{0}" + id)` (Vectorize's
//! 64-byte id limit), with the caller's id in the reserved `_cf_id`
//! metadata key, stripped on the way out; caller metadata using that key
//! is refused as `InvalidInput`. The namespace also rides through to
//! Vectorize, so filtering stays server-side. The calls go through the
//! [`VectorizeRunner`] seam, so everything but the JS handle tests
//! natively against a fake of Vectorize's semantics.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;
use worker::js_sys;
use worker::js_sys::futures::JsFuture;
use worker::send::{IntoSendFuture, SendWrapper};
use worker::{Env, EnvBinding};

use cratefield_core::{
    MAX_NAMESPACE_BYTES, VectorFilter, VectorIndex, VectorIndexError, VectorMatch, VectorNamespace,
    VectorRecord,
};

/// Vectorize's topK ceiling when metadata is returned (Vectorize limits).
const MAX_TOP_K: usize = 50;

/// Vectorize's per-call upsert batch limit on Workers (Vectorize limits).
const MAX_UPSERT_BATCH: usize = 1000;

/// Where the caller's id survives the round trip (see the module doc).
const ID_METADATA_KEY: &str = "_cf_id";

/// The derived storage id: lowercase hex of `SHA-256(namespace \0 id)`.
fn storage_id(namespace: &VectorNamespace, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_str().as_bytes());
    hasher.update([0u8]);
    hasher.update(id.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The namespace is within Vectorize's byte limit, whichever constructor
/// made it — `for_tenant` skips the check [`VectorNamespace::new`] does.
fn checked_namespace(namespace: &VectorNamespace) -> Result<(), VectorIndexError> {
    let bytes = namespace.as_str().len();
    if bytes > MAX_NAMESPACE_BYTES {
        return Err(VectorIndexError::InvalidInput(format!(
            "namespace is {bytes} bytes, over Vectorize's limit of {MAX_NAMESPACE_BYTES}"
        )));
    }
    Ok(())
}

/// The runner seam: one call to the binding, marshalled as JSON on both
/// sides. Errors are the provider's own text, carried raw here and
/// scrubbed by [`VectorIndexError::Operation`]'s `Display` on the way out.
#[async_trait]
trait VectorizeRunner: Send + Sync {
    async fn upsert(&self, vectors: Json) -> Result<Json, String>;
    async fn query(&self, vector: Json, options: Json) -> Result<Json, String>;
    async fn delete_by_ids(&self, ids: Vec<String>) -> Result<Json, String>;
}

/// The Vectorize index binding (`[[vectorize]]` in `wrangler.toml`).
#[wasm_bindgen]
extern "C" {
    type VectorizeIndex;
    #[wasm_bindgen(method, js_name = upsert)]
    fn upsert(this: &VectorizeIndex, vectors: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(method, js_name = query)]
    fn query(this: &VectorizeIndex, vector: JsValue, options: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(method, js_name = deleteByIds)]
    fn delete_by_ids(this: &VectorizeIndex, ids: JsValue) -> js_sys::Promise;
}

impl EnvBinding for VectorizeIndex {
    // workerd's binding class — src/cloudflare/internal/vectorize-api.ts — matched exactly.
    const TYPE_NAME: &'static str = "VectorizeIndexImpl";
}

/// The error text of a rejected `Promise`, as far as it is a string at all.
fn js_text(error: &JsValue) -> String {
    error.as_string().unwrap_or_else(|| format!("{error:?}"))
}

/// JSON into the isolate, through `JSON.parse` (all values sent are safe).
fn to_js(value: &Json) -> Result<JsValue, String> {
    let text = serde_json::to_string(value).map_err(|err| err.to_string())?;
    js_sys::JSON::parse(&text).map_err(|error| js_text(&error))
}

/// JSON out of the isolate, through `JSON.stringify`.
fn from_js(value: &JsValue) -> Result<Json, String> {
    let text = js_sys::JSON::stringify(value).map_err(|error| js_text(&error))?;
    serde_json::from_str(&String::from(text)).map_err(|err| err.to_string())
}

/// Awaits one binding call through `JsFuture` — the type carrying the
/// `Future` impl, which compiles off-wasm too — via `into_send`, because
/// a Workers isolate is single-threaded (ADR 0002).
async fn call(promise: js_sys::Promise) -> Result<Json, String> {
    from_js(
        &JsFuture::from(promise)
            .into_send()
            .await
            .map_err(|error| js_text(&error))?,
    )
}

/// The real runner: the `env.<binding>` Vectorize index.
struct VectorizeBinding(SendWrapper<VectorizeIndex>);

#[async_trait]
impl VectorizeRunner for VectorizeBinding {
    async fn upsert(&self, vectors: Json) -> Result<Json, String> {
        call(self.0.upsert(to_js(&vectors)?)).await
    }

    async fn query(&self, vector: Json, options: Json) -> Result<Json, String> {
        call(self.0.query(to_js(&vector)?, to_js(&options)?)).await
    }

    async fn delete_by_ids(&self, ids: Vec<String>) -> Result<Json, String> {
        call(self.0.delete_by_ids(to_js(&json!(ids))?)).await
    }
}

/// The [`VectorIndex`] port over a Vectorize index. Generic over the runner
/// so tests substitute the binding; production resolves through
/// [`vector_index_from_env`] and never names the parameter.
struct Vectorize<R: VectorizeRunner = VectorizeBinding> {
    runner: R,
}

/// The port resolved from `env` for the runtime builder: `None` — never a
/// panic — when the binding named in `.vector_index(..)` is missing from
/// this deployment or is not a Vectorize index.
pub(crate) fn vector_index_from_env(env: &Env, binding: &str) -> Option<Arc<dyn VectorIndex>> {
    let index = env.get_binding::<VectorizeIndex>(binding).ok()?;
    Some(Arc::new(Vectorize {
        runner: VectorizeBinding(SendWrapper::new(index)),
    }))
}

/// The caller's metadata, plus the caller's id under the reserved key —
/// refused if the caller already used it, or the id could not come back.
fn wire_metadata(record: &VectorRecord) -> Result<Json, VectorIndexError> {
    if record.metadata.contains_key(ID_METADATA_KEY) {
        return Err(VectorIndexError::InvalidInput(format!(
            "metadata key `{ID_METADATA_KEY}` is reserved by the Vectorize adapter \
             and cannot be stored"
        )));
    }
    let mut metadata = record.metadata.clone();
    metadata.insert(ID_METADATA_KEY.to_owned(), Json::String(record.id.clone()));
    Ok(Json::Object(metadata.into_iter().collect()))
}

/// One record as Vectorize stores it: derived id, namespace, values, and
/// the metadata carrying the caller's id.
fn wire_vector(
    namespace: &VectorNamespace,
    record: &VectorRecord,
) -> Result<Json, VectorIndexError> {
    if record.values.is_empty() {
        return Err(VectorIndexError::InvalidInput(format!(
            "vector for record `{}` is empty",
            record.id
        )));
    }
    let mut wire = serde_json::Map::new();
    wire.insert("id".into(), json!(storage_id(namespace, &record.id)));
    wire.insert("values".into(), json!(record.values));
    wire.insert("namespace".into(), json!(namespace.as_str()));
    wire.insert("metadata".into(), wire_metadata(record)?);
    Ok(Json::Object(wire))
}

/// One match as the port answers it: the caller's id back out of the
/// reserved key, the metadata without it, and the score.
fn match_from_wire(matched: &Json) -> Result<VectorMatch, VectorIndexError> {
    let mut metadata: BTreeMap<String, Json> = matched
        .get("metadata")
        .and_then(Json::as_object)
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    let caller_id = metadata
        .remove(ID_METADATA_KEY)
        .and_then(|id| id.as_str().map(str::to_owned));
    // Vectorize scores are JSON numbers; the port's `f32` loses only low
    // bits of the cosine similarity, never its ordering.
    #[allow(clippy::cast_possible_truncation)]
    let score =
        matched.get("score").and_then(Json::as_f64).ok_or_else(|| {
            VectorIndexError::Operation("vectorize match carries no score".to_owned())
        })? as f32;
    Ok(VectorMatch {
        id: caller_id.unwrap_or_else(|| {
            matched
                .get("id")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned()
        }),
        score,
        metadata,
    })
}

#[async_trait]
impl<R: VectorizeRunner> VectorIndex for Vectorize<R> {
    async fn upsert(
        &self,
        namespace: &VectorNamespace,
        records: &[VectorRecord],
    ) -> Result<(), VectorIndexError> {
        checked_namespace(namespace)?;
        if records.len() > MAX_UPSERT_BATCH {
            return Err(VectorIndexError::InvalidInput(format!(
                "upserting {} records is over Vectorize's batch limit of {MAX_UPSERT_BATCH}",
                records.len()
            )));
        }
        let vectors: Result<Vec<Json>, VectorIndexError> = records
            .iter()
            .map(|record| wire_vector(namespace, record))
            .collect();
        if vectors.as_ref().is_ok_and(Vec::is_empty) {
            return Ok(());
        }
        self.runner
            .upsert(Json::Array(vectors?))
            .await
            .map_err(VectorIndexError::Operation)
            .map(|_| ())
    }

    async fn query(
        &self,
        namespace: &VectorNamespace,
        vector: &[f32],
        k: usize,
        filter: &VectorFilter,
    ) -> Result<Vec<VectorMatch>, VectorIndexError> {
        checked_namespace(namespace)?;
        if vector.is_empty() {
            return Err(VectorIndexError::InvalidInput(
                "query vector is empty".to_owned(),
            ));
        }
        if k == 0 {
            return Ok(Vec::new());
        }
        // `k` is an at-most limit: Vectorize answers at most 50 with
        // metadata, so a larger ask is clamped, not rejected.
        let k = k.min(MAX_TOP_K);
        // The filter is Vectorize's implicit `$eq`, exactly what
        // `VectorFilter` means; empty is omitted, since Vectorize
        // requires a non-empty object. The reserved key is refused, as
        // it is in stored metadata.
        let filters = filter.filters();
        if filters.contains_key(ID_METADATA_KEY) {
            return Err(VectorIndexError::InvalidInput(format!(
                "filter key `{ID_METADATA_KEY}` is reserved by the Vectorize adapter"
            )));
        }
        let mut options = serde_json::Map::new();
        options.insert("topK".into(), json!(k));
        options.insert("namespace".into(), json!(namespace.as_str()));
        options.insert("returnMetadata".into(), json!("all"));
        if !filters.is_empty() {
            options.insert(
                "filter".into(),
                Json::Object(filters.clone().into_iter().collect()),
            );
        }
        let response = self
            .runner
            .query(json!(vector), Json::Object(options))
            .await
            .map_err(VectorIndexError::Operation)?;
        let matches = response
            .get("matches")
            .and_then(Json::as_array)
            .ok_or_else(|| {
                VectorIndexError::Operation(
                    "vectorize query response carries no matches array".to_owned(),
                )
            })?;
        matches.iter().map(match_from_wire).collect()
    }

    async fn delete(
        &self,
        namespace: &VectorNamespace,
        ids: &[String],
    ) -> Result<(), VectorIndexError> {
        checked_namespace(namespace)?;
        if ids.is_empty() {
            return Ok(());
        }
        // The derivation makes the delete namespace-safe: the wire ids
        // name this namespace's records, whatever else shares the caller's
        // ids across the index.
        let wire: Vec<String> = ids.iter().map(|id| storage_id(namespace, id)).collect();
        self.runner
            .delete_by_ids(wire)
            .await
            .map_err(VectorIndexError::Operation)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The fake's own corpus — adapter storage, not request state; the
    // allow follows the workspace `clippy.toml` policy.
    #[allow(clippy::disallowed_types)]
    type Guarded<T> = std::sync::Mutex<T>;

    /// One stored vector, as Vectorize holds it: values, `namespace`,
    /// metadata.
    type Stored = (Vec<f32>, String, BTreeMap<String, Json>);

    /// The wire, faked with Vectorize's own semantics: one flat map (ids
    /// unique across the whole index), a `namespace` field per vector,
    /// implicit-`$eq` filters, exact cosine ranking.
    struct FakeVectorize(Guarded<BTreeMap<String, Stored>>);

    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let norms = a.iter().map(|x| x * x).sum::<f32>().sqrt()
            * b.iter().map(|y| y * y).sum::<f32>().sqrt();
        if norms == 0.0 { 0.0 } else { dot / norms }
    }

    #[async_trait]
    impl VectorizeRunner for FakeVectorize {
        async fn upsert(&self, vectors: Json) -> Result<Json, String> {
            let mut index = self.0.lock().expect("fake lock");
            for vector in vectors.as_array().expect("vector array") {
                index.insert(
                    vector["id"].as_str().expect("wire id").to_owned(),
                    (
                        serde_json::from_value(vector["values"].clone()).expect("values"),
                        vector["namespace"].as_str().expect("namespace").to_owned(),
                        serde_json::from_value(vector["metadata"].clone()).expect("metadata"),
                    ),
                );
            }
            Ok(json!({}))
        }

        async fn query(&self, vector: Json, options: Json) -> Result<Json, String> {
            let vector: Vec<f32> = serde_json::from_value(vector).expect("query vector");
            let namespace = options["namespace"].as_str().expect("namespace");
            let top_k = usize::try_from(options["topK"].as_u64().expect("topK")).expect("topK");
            let filter = options.get("filter").cloned().unwrap_or_else(|| json!({}));
            let index = self.0.lock().expect("fake lock");
            let mut scored: Vec<(f32, &String, &BTreeMap<String, Json>)> = index
                .iter()
                .filter(|(_, (_, ns, _))| ns == namespace)
                .filter(|(_, (_, _, metadata))| {
                    filter
                        .as_object()
                        .expect("filter object")
                        .iter()
                        .all(|(key, value)| metadata.get(key) == Some(value))
                })
                .map(|(id, (values, _, metadata))| (cosine(&vector, values), id, metadata))
                .collect();
            scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            let matches: Vec<Json> = scored
                .into_iter()
                .take(top_k)
                .map(|(score, id, metadata)| {
                    json!({ "id": id, "score": score, "metadata": metadata })
                })
                .collect();
            Ok(json!({ "count": matches.len(), "matches": matches }))
        }

        async fn delete_by_ids(&self, ids: Vec<String>) -> Result<Json, String> {
            // Ids are index-global; a missing id is not an error.
            let mut index = self.0.lock().expect("fake lock");
            for id in ids {
                index.remove(&id);
            }
            Ok(json!({}))
        }
    }

    fn index() -> Vectorize<FakeVectorize> {
        Vectorize {
            runner: FakeVectorize(Guarded::new(BTreeMap::new())),
        }
    }

    #[test]
    fn the_adapter_passes_the_port_conformance_suite() {
        assert_eq!(
            <VectorizeIndex as EnvBinding>::TYPE_NAME,
            "VectorizeIndexImpl"
        );
        pollster::block_on(cratefield_testing::vector_index_conformance(&index()));
    }

    /// The seam the port exists for: the same caller id in two namespaces
    /// is two distinct, lowercase-hex wire ids, each carrying the caller's
    /// id back in the reserved key.
    #[test]
    fn caller_ids_are_derived_per_namespace_and_survive_in_metadata() {
        let index = index();
        let ours = VectorNamespace::new("tenant-a").expect("valid");
        let theirs = VectorNamespace::new("tenant-b").expect("valid");
        for namespace in [&ours, &theirs] {
            pollster::block_on(
                index.upsert(namespace, &[VectorRecord::new("shared", vec![1.0, 0.0])]),
            )
            .expect("upsert answers");
        }
        let stored = index.runner.0.lock().expect("fake lock");
        assert_eq!(stored.len(), 2, "the same caller id is two wire records");
        for (wire, (_, namespace, metadata)) in stored.iter() {
            // The caller's id survives in the reserved key, the derived id
            // fills Vectorize's 64-byte limit as lowercase hex, and the
            // namespace rides along.
            assert_eq!(metadata[ID_METADATA_KEY], json!("shared"));
            assert_eq!(wire.len(), 64);
            assert!(
                wire.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "the derived id is lowercase hex: {wire}"
            );
            assert!([ours.as_str(), theirs.as_str()].contains(&namespace.as_str()));
        }
        let ids: Vec<&String> = stored.keys().collect();
        assert_ne!(ids[0], ids[1], "two namespaces, two distinct wire ids");
    }

    /// Refusals this adapter makes before any provider is asked — and the
    /// one ask it clamps instead: `k` over Vectorize's topK ceiling.
    #[test]
    fn reserved_keys_and_over_limit_calls_are_invalid_input() {
        let invalid = |error: &VectorIndexError| {
            assert!(
                matches!(error, VectorIndexError::InvalidInput(_)),
                "{error}"
            );
        };
        let index = index();
        let ns = VectorNamespace::new("ns").expect("valid");
        let record =
            VectorRecord::new("r", vec![1.0, 0.0]).with_metadata(ID_METADATA_KEY, json!("forged"));
        let error = pollster::block_on(index.upsert(&ns, &[record])).unwrap_err();
        invalid(&error);
        assert!(error.to_string().contains("reserved"), "{error}");

        let error = pollster::block_on(index.query(
            &ns,
            &[1.0, 0.0],
            1,
            &VectorFilter::new().eq(ID_METADATA_KEY, json!("x")),
        ))
        .unwrap_err();
        invalid(&error);

        let matches =
            pollster::block_on(index.query(&ns, &[1.0, 0.0], MAX_TOP_K + 1, &VectorFilter::new()))
                .expect("an over-ceiling k is clamped, not rejected");
        assert!(matches.len() <= MAX_TOP_K);

        let batch: Vec<VectorRecord> = (0..=MAX_UPSERT_BATCH)
            .map(|n| VectorRecord::new(format!("r{n}"), vec![1.0, 0.0]))
            .collect();
        let error = pollster::block_on(index.upsert(&ns, &batch)).unwrap_err();
        invalid(&error);
    }
}
