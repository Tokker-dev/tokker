//! The `VectorIndex` port (issue #561, ADR 0024): similarity search over
//! embedding vectors, asked for by **namespace**, never by vendor (ADR
//! 0002). A module holds `Arc<dyn VectorIndex>` and never learns whether
//! the nearest neighbours came from Cloudflare Vectorize, Postgres, or the
//! in-process [`ExactVectorIndex`]; the vectors come from the
//! [`Embedder`](crate::Embedder) port, the sibling of this one.
//!
//! **One namespace per tenant, and a query never crosses namespaces** —
//! every call names a [`VectorNamespace`], the tenant-scoping rule a table
//! has (RECONCILIATION.md §2) expressed as a namespace. Scores are cosine
//! similarity, higher is closer. No outcome enum, as on
//! [`TextModel`](crate::TextModel): the unwired answer is
//! [`VectorIndexError::NotConfigured`], so a module that cannot degrade
//! without its index fails loudly.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use serde_json::Value;

use crate::tenant::TenantId;

// The guard over the index's own corpus — adapter storage, not request
// state; the allow follows the workspace `clippy.toml` policy.
#[allow(clippy::disallowed_types)]
type Guarded<T> = std::sync::Mutex<T>;

/// The longest namespace name accepted, in bytes: Cloudflare Vectorize's
/// limit, and so the port's.
pub const MAX_NAMESPACE_BYTES: usize = 64;

/// The search space one call sees: one tenant's slice of the index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VectorNamespace(String);

impl VectorNamespace {
    /// The namespace of a tenant: the tenant id itself — always under
    /// [`MAX_NAMESPACE_BYTES`], so this cannot fail.
    #[must_use]
    pub fn for_tenant(tenant: &TenantId) -> Self {
        Self(tenant.as_str().to_owned())
    }

    /// A namespace named directly, for tests and non-tenant corpora.
    ///
    /// # Errors
    /// [`VectorIndexError::InvalidInput`] when the name is empty or over
    /// [`MAX_NAMESPACE_BYTES`] bytes.
    pub fn new(namespace: impl Into<String>) -> Result<Self, VectorIndexError> {
        let namespace = namespace.into();
        let bytes = namespace.len();
        if bytes == 0 || bytes > MAX_NAMESPACE_BYTES {
            return Err(VectorIndexError::InvalidInput(format!(
                "namespace must be 1..={MAX_NAMESPACE_BYTES} bytes, got {bytes}"
            )));
        }
        Ok(Self(namespace))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VectorNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One stored vector: its id, its embedding, and the metadata a filter can
/// select on — carried back on every [`VectorMatch`].
#[derive(Debug, Clone, PartialEq)]
pub struct VectorRecord {
    pub id: String,
    pub values: Vec<f32>,
    pub metadata: BTreeMap<String, Value>,
}

impl VectorRecord {
    /// A record with the id and the embedding; metadata follows with
    /// [`VectorRecord::with_metadata`].
    #[must_use]
    pub fn new(id: impl Into<String>, values: Vec<f32>) -> Self {
        Self {
            id: id.into(),
            values,
            metadata: BTreeMap::new(),
        }
    }

    /// Attaches one metadata entry, chainable.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Equality on metadata: a record matches when its metadata holds **every**
/// key with an equal value; values compare as JSON, so `"1"` and `1`
/// differ. The default matches all. Hosted indexes may filter only on keys
/// pre-registered as metadata indexes; the exact index filters on all.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VectorFilter {
    eq: BTreeMap<String, Value>,
}

impl VectorFilter {
    /// The filter that matches everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires `metadata[key] == value`.
    #[must_use]
    pub fn eq(mut self, key: impl Into<String>, value: Value) -> Self {
        self.eq.insert(key.into(), value);
        self
    }

    /// The equality constraints, for an adapter to translate.
    #[must_use]
    pub fn filters(&self) -> &BTreeMap<String, Value> {
        &self.eq
    }

    /// Whether `metadata` satisfies this filter — the one definition of
    /// "matches".
    #[must_use]
    pub fn matches(&self, metadata: &BTreeMap<String, Value>) -> bool {
        self.eq
            .iter()
            .all(|(key, value)| metadata.get(key) == Some(value))
    }
}

/// One nearest neighbour: the record's id, its cosine similarity to the
/// query (higher is closer), and its metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct VectorMatch {
    pub id: String,
    pub score: f32,
    pub metadata: BTreeMap<String, Value>,
}

/// Vector-index failures. Provider-text variants are scrubbed in `Display`
/// (issue #235); `Debug` stays raw for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VectorIndexError {
    /// No vector index is wired — the venture did not provide one.
    NotConfigured,
    /// The request was malformed before any provider saw it. Not retryable.
    InvalidInput(String),
    /// The call failed against the provider (or on the way to it).
    Operation(String),
}

impl std::fmt::Display for VectorIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::NotConfigured => f.write_str("no vector index is wired"),
            Self::InvalidInput(message) => {
                write!(f, "vector index rejected the request: {}", scrub(message))
            }
            Self::Operation(message) => {
                write!(f, "vector index operation failed: {}", scrub(message))
            }
        }
    }
}

impl std::error::Error for VectorIndexError {}

/// Stores and ranks embedding vectors, within the namespace every call
/// names — the sibling of [`Embedder`](crate::Embedder), which makes the
/// vectors this one keeps and searches. Hosted adapters (Vectorize) are
/// eventually consistent — a write may take seconds to become queryable —
/// while [`ExactVectorIndex`] is immediate.
#[async_trait]
pub trait VectorIndex: Send + Sync {
    /// Writes every record into `namespace`, replacing any existing record
    /// with the same id — values and metadata both, never a merge.
    ///
    /// # Errors
    /// [`VectorIndexError::InvalidInput`] on an empty or wrong-width
    /// vector; [`VectorIndexError::NotConfigured`] when unwired;
    /// [`VectorIndexError::Operation`] when the call fails.
    async fn upsert(
        &self,
        namespace: &VectorNamespace,
        records: &[VectorRecord],
    ) -> Result<(), VectorIndexError>;

    /// The at-most-`k` nearest neighbours of `vector` in `namespace`,
    /// cosine similarity descending, every match satisfying `filter`.
    ///
    /// # Errors
    /// [`VectorIndexError::InvalidInput`] on an empty or wrong-width
    /// vector; [`VectorIndexError::NotConfigured`] when unwired;
    /// [`VectorIndexError::Operation`] when the call failed.
    async fn query(
        &self,
        namespace: &VectorNamespace,
        vector: &[f32],
        k: usize,
        filter: &VectorFilter,
    ) -> Result<Vec<VectorMatch>, VectorIndexError>;

    /// Removes the records named by `ids` from `namespace`. A missing id is
    /// not an error: the delete is idempotent.
    ///
    /// # Errors
    /// [`VectorIndexError::NotConfigured`] when unwired;
    /// [`VectorIndexError::Operation`] when the call fails.
    async fn delete(
        &self,
        namespace: &VectorNamespace,
        ids: &[String],
    ) -> Result<(), VectorIndexError>;
}

/// What an upsert leaves behind: the embedding and its metadata.
type Stored = (Vec<f32>, BTreeMap<String, Value>);

/// The native, in-process [`VectorIndex`]: exact (brute-force) cosine
/// ranking over an in-memory map — the true top-`k`, ties broken by id
/// ascending, so the same corpus and query always answer in the same
/// order. For development, tests, and small single-process corpora:
/// **data is not persisted**, and a restart starts empty.
pub struct ExactVectorIndex {
    dimensions: usize,
    // The index's own corpus — adapter storage, not request state
    // (clippy.toml), the way `adapter-sqlite` guards its connection.
    #[allow(clippy::disallowed_types)]
    namespaces: Guarded<HashMap<String, BTreeMap<String, Stored>>>,
}

impl ExactVectorIndex {
    /// An empty index whose vectors are all `dimensions` wide — the width
    /// of whatever [`Embedder`](crate::Embedder) is wired alongside it.
    #[must_use]
    pub fn new(dimensions: usize) -> Self {
        Self {
            dimensions,
            namespaces: Guarded::new(HashMap::new()),
        }
    }

    /// Rejects records a hosted index would refuse: an empty, wrong-width
    /// or non-finite vector, or metadata it cannot store.
    fn validate(&self, records: &[VectorRecord]) -> Result<(), VectorIndexError> {
        for record in records {
            if record.values.is_empty() {
                return Err(VectorIndexError::InvalidInput(format!(
                    "vector for record `{}` is empty",
                    record.id
                )));
            }
            if record.values.len() != self.dimensions {
                return Err(VectorIndexError::InvalidInput(format!(
                    "vector for record `{}` has {} dimensions, index expects {}",
                    record.id,
                    record.values.len(),
                    self.dimensions
                )));
            }
            if record.values.iter().any(|value| !value.is_finite()) {
                return Err(VectorIndexError::InvalidInput(format!(
                    "vector for record `{}` has a non-finite component",
                    record.id
                )));
            }
            if !vectorize_metadata(&record.metadata) {
                return Err(VectorIndexError::InvalidInput(format!(
                    "metadata of record `{}` holds a value Vectorize cannot store",
                    record.id
                )));
            }
        }
        Ok(())
    }
}

/// Whether every metadata value is one Vectorize stores and filters on —
/// a string, number, boolean, or array of strings — so dev fails like prod.
fn vectorize_metadata(metadata: &BTreeMap<String, Value>) -> bool {
    metadata.values().all(|value| match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) => true,
        Value::Array(items) => items.iter().all(Value::is_string),
        _ => false,
    })
}

/// Cosine similarity, the port's score; two zero vectors answer `0.0`.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norms =
        a.iter().map(|x| x * x).sum::<f32>().sqrt() * b.iter().map(|y| y * y).sum::<f32>().sqrt();
    if norms == 0.0 { 0.0 } else { dot / norms }
}

#[async_trait]
impl VectorIndex for ExactVectorIndex {
    async fn upsert(
        &self,
        namespace: &VectorNamespace,
        records: &[VectorRecord],
    ) -> Result<(), VectorIndexError> {
        self.validate(records)?;
        let mut namespaces = self.namespaces.lock().expect("lock uncontended");
        let index = namespaces.entry(namespace.as_str().to_owned()).or_default();
        for record in records {
            index.insert(
                record.id.clone(),
                (record.values.clone(), record.metadata.clone()),
            );
        }
        Ok(())
    }

    async fn query(
        &self,
        namespace: &VectorNamespace,
        vector: &[f32],
        k: usize,
        filter: &VectorFilter,
    ) -> Result<Vec<VectorMatch>, VectorIndexError> {
        if vector.is_empty() {
            return Err(VectorIndexError::InvalidInput(
                "query vector is empty".to_owned(),
            ));
        }
        if vector.len() != self.dimensions {
            return Err(VectorIndexError::InvalidInput(format!(
                "query vector has {} dimensions, index expects {}",
                vector.len(),
                self.dimensions
            )));
        }
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(VectorIndexError::InvalidInput(
                "query vector has a non-finite component".to_owned(),
            ));
        }
        if k == 0 {
            return Ok(Vec::new());
        }
        let namespaces = self.namespaces.lock().expect("lock uncontended");
        let Some(index) = namespaces.get(namespace.as_str()) else {
            return Ok(Vec::new());
        };
        // A `BTreeMap` iterates id-ascending and `sort_by` is stable, so
        // equal scores come out id-ascending — the deterministic order the
        // adapter promises.
        let mut scored: Vec<(f32, &Stored, &String)> = index
            .iter()
            .filter(|(_, (_, metadata))| filter.matches(metadata))
            .map(|(id, stored)| (cosine(vector, &stored.0), stored, id))
            .collect();
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        Ok(scored
            .into_iter()
            .take(k)
            .map(|(score, stored, id)| VectorMatch {
                id: id.clone(),
                score,
                metadata: stored.1.clone(),
            })
            .collect())
    }

    async fn delete(
        &self,
        namespace: &VectorNamespace,
        ids: &[String],
    ) -> Result<(), VectorIndexError> {
        let mut namespaces = self.namespaces.lock().expect("lock uncontended");
        if let Some(index) = namespaces.get_mut(namespace.as_str()) {
            for id in ids {
                index.remove(id);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_are_one_to_max_namespace_bytes() {
        assert!(VectorNamespace::new("").is_err());
        assert!(VectorNamespace::new("x".repeat(MAX_NAMESPACE_BYTES)).is_ok());
        assert!(VectorNamespace::new("x".repeat(MAX_NAMESPACE_BYTES + 1)).is_err());
        // Tenant ids are minted by core's resolution layer, well under the
        // limit, so `for_tenant` cannot fail.
        let tenant = crate::tenant::TenantId::new("tenant-1");
        assert_eq!(VectorNamespace::for_tenant(&tenant).as_str(), "tenant-1");
    }

    // Issue #235: provider text must not survive into a log line; `Debug`
    // stays raw for tests.
    #[test]
    fn error_display_scrubs_provider_text() {
        let error = VectorIndexError::Operation(
            "vectorize 500 at https://api.example.test?token=secret-abcdef".to_owned(),
        );
        let text = error.to_string();
        assert!(text.contains("vector index operation failed"), "{text}");
        assert!(!text.contains("secret-abcdef"), "{text}");
        assert!(format!("{error:?}").contains("secret-abcdef"));
        assert_eq!(
            VectorIndexError::NotConfigured.to_string(),
            "no vector index is wired"
        );
    }

    #[test]
    fn malformed_vectors_and_metadata_are_invalid_input() {
        let index = ExactVectorIndex::new(2);
        let ns = VectorNamespace::new("ns").expect("valid");
        let upsert = |values: &[f32]| {
            pollster::block_on(index.upsert(&ns, &[VectorRecord::new("r", values.to_owned())]))
                .unwrap_err()
        };
        let query = |vector: &[f32]| {
            pollster::block_on(index.query(&ns, vector, 5, &VectorFilter::default())).unwrap_err()
        };
        for (error, message) in [
            (upsert(&[1.0, 0.0, 0.0]), "3 dimensions"),
            (upsert(&[]), "is empty"),
            (upsert(&[f32::NAN, 1.0]), "non-finite"),
            (query(&[]), "is empty"),
            (query(&[1.0, 0.0, 0.0]), "3 dimensions"),
            (query(&[f32::INFINITY, 1.0]), "non-finite"),
        ] {
            assert!(
                matches!(error, VectorIndexError::InvalidInput(_)),
                "{error}"
            );
            assert!(error.to_string().contains(message), "{error}");
        }
        // Vectorize stores string | number | boolean | string[] metadata;
        // the exact index refuses the rest, so dev fails like prod.
        let error = pollster::block_on(
            index.upsert(
                &ns,
                &[VectorRecord::new("r", vec![1.0, 0.0])
                    .with_metadata("nested", serde_json::json!({ "a": 1 }))],
            ),
        )
        .unwrap_err();
        assert!(
            matches!(error, VectorIndexError::InvalidInput(_)),
            "{error}"
        );
        assert!(
            error.to_string().contains("Vectorize cannot store"),
            "{error}"
        );
    }
}
