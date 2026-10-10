//! The `Database` port: engine-agnostic statements and rows over
//! sea-query-rendered SQL (ADR 0004).

use async_trait::async_trait;
use sea_query::Value as SeaValue;

/// A rendered SQL statement: `(sql, values)` with `?` placeholders, produced
/// by rendering a sea-query query for a dialect. Modules build queries with
/// sea-query and render through the helpers on this type (or let adapters do
/// it); adapters bind `values` positionally.
#[derive(Debug, Clone)]
pub struct Statement {
    pub sql: String,
    pub values: sea_query::Values,
}

impl Statement {
    /// A parameterless statement (`SELECT 1`, DDL).
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            values: sea_query::Values(Vec::new()),
        }
    }

    /// A statement with positional `?` values.
    pub fn with_values(sql: impl Into<String>, values: Vec<SeaValue>) -> Self {
        Self {
            sql: sql.into(),
            values: sea_query::Values(values),
        }
    }

    /// Renders a sea-query statement (select/insert/update/delete) with the
    /// SQLite dialect. The portable subset renders identically for D1,
    /// rusqlite and (later) Postgres (ADR 0004).
    pub fn render(query: &impl sea_query::QueryStatementBuilder) -> Self {
        let (sql, values) = query.build_any(&sea_query::SqliteQueryBuilder);
        Self { sql, values }
    }
}

/// A small owned row model. No engine types leak past this point.
#[derive(Debug, Clone)]
pub struct Rows {
    pub rows: Vec<Row>,
}

impl Rows {
    pub fn new(rows: Vec<Row>) -> Self {
        Self { rows }
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn first(&self) -> Option<&Row> {
        self.rows.first()
    }
}

/// One result row: ordered `(column name, value)` pairs.
#[derive(Debug, Clone)]
pub struct Row {
    columns: Vec<(String, SeaValue)>,
}

impl Row {
    pub fn new(columns: Vec<(String, SeaValue)>) -> Self {
        Self { columns }
    }

    /// Column names in result order.
    pub fn column_names(&self) -> impl Iterator<Item = &str> {
        self.columns.iter().map(|(name, _)| name.as_str())
    }

    /// Every column, in result order, untyped.
    ///
    /// [`get`](Row::get) answers "is this column an `i64`" and returns `None`
    /// for a NULL, a missing column and an unrepresentable one alike — three
    /// different facts wearing one answer. A caller that must serialise a row
    /// it did not write, like a subject-access export, needs to tell them
    /// apart: reporting a value it could not read as `null` is a quiet claim
    /// that the database held nothing there.
    pub fn columns(&self) -> impl Iterator<Item = (&str, &SeaValue)> {
        self.columns
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Typed column access. `None` when the column is missing, `NULL`, or
    /// not representable as `T`.
    pub fn get<T: TryFromValue>(&self, column: &str) -> Option<T> {
        let value = self
            .columns
            .iter()
            .find(|(name, _)| name == column)
            .map(|(_, value)| value)?;
        T::try_from_value(value)
    }
}

/// Conversion from a sea-query [`SeaValue`] for typed row access.
pub trait TryFromValue: Sized {
    fn try_from_value(value: &SeaValue) -> Option<Self>;
}

fn text(value: &SeaValue) -> Option<String> {
    match value {
        SeaValue::String(Some(s)) => Some((**s).clone()),
        SeaValue::Char(Some(c)) => Some(c.to_string()),
        _ => None,
    }
}

macro_rules! impl_int {
    ($($t:ty),* $(,)?) => {
        $(
            impl TryFromValue for $t {
                fn try_from_value(value: &SeaValue) -> Option<Self> {
                    let i: i64 = match value {
                        SeaValue::TinyInt(Some(v)) => i64::from(*v),
                        SeaValue::SmallInt(Some(v)) => i64::from(*v),
                        SeaValue::Int(Some(v)) => i64::from(*v),
                        SeaValue::BigInt(Some(v)) => *v,
                        _ => return None,
                    };
                    <$t>::try_from(i).ok()
                }
            }
        )*
    };
}

impl_int!(i8, i16, i32, i64, u8, u16, u32, u64, usize);

impl TryFromValue for String {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        text(value)
    }
}

/// Blob columns. A `Database` that cannot return bytes cannot hold a
/// ciphertext, a wrapped key or a nonce (issue #39).
impl TryFromValue for Vec<u8> {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        match value {
            SeaValue::Bytes(Some(bytes)) => Some(bytes.as_ref().clone()),
            _ => None,
        }
    }
}

impl TryFromValue for bool {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        match value {
            SeaValue::Bool(Some(v)) => Some(*v),
            SeaValue::Int(Some(v)) => Some(*v != 0),
            _ => None,
        }
    }
}

impl TryFromValue for f64 {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        match value {
            SeaValue::Float(Some(v)) => Some(f64::from(*v)),
            SeaValue::Double(Some(v)) => Some(*v),
            _ => None,
        }
    }
}

impl TryFromValue for Option<String> {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        // In sea-query 0.32 a SQL NULL is the variant with `None` inside
        // (e.g. `Value::String(None)`); a type mismatch is our `None`.
        match value {
            SeaValue::String(inner) => Some(inner.as_deref().map(String::from)),
            _ => None,
        }
    }
}

impl TryFromValue for SeaValue {
    fn try_from_value(value: &SeaValue) -> Option<Self> {
        Some(value.clone())
    }
}

/// Database failures, sanitized for logs and problem details.
///
/// The adapters wrap the raw driver message (`sqlx`, D1, rusqlite), which
/// is **not** safe on its own: a Postgres unique violation quotes the
/// offending row in its `DETAIL:` line — an email address — and a connect
/// failure can echo the connection URL with its credentials. `Display`
/// therefore runs the message through [`crate::logging::scrub_text`]
/// (issue #135), so every `tracing` field, forwarded diagnostic or
/// `format!` that renders a `DbError` gets the sanitized text. `Debug`
/// still shows the raw string for tests; the logging formatters scrub
/// `{:?}` output too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    Execute(String),
    Query(String),
    Batch(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (label, message) = match self {
            Self::Execute(message) => ("execute failed", message),
            Self::Query(message) => ("query failed", message),
            Self::Batch(message) => ("batch failed", message),
        };
        write!(f, "{label}: {}", crate::logging::scrub_text(message))
    }
}

impl std::error::Error for DbError {}

/// Execute statements against the venture database. Implementations: D1
/// (Workers), rusqlite (tests, self-hosted), Postgres (phase 3).
///
/// `batch_atomic` is **all-or-nothing, on every adapter, without
/// exception** (issue #126). Either every statement commits or none does:
/// a failure part-way through leaves the database exactly as it was, as
/// if the batch never ran. This is a port contract, not an adapter
/// nicety — confirmation, position assignment and referral credit each
/// span several statements and are correct only if they commit together —
/// so an adapter that cannot honour it must not implement this trait,
/// and the testing kit's `assert_batch_is_atomic` enforces the
/// contract per engine in CI. Per-statement row counts are not reported;
/// a caller that needs to know whether a statement changed anything reads
/// the row back (see `module-waitlist`'s `confirm_entry`).
#[async_trait]
pub trait Database: Send + Sync {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError>;
    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError>;
    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), DbError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_sanitizes_the_driver_message() {
        // The finding: `DbError::Execute(err.to_string())` wraps the raw
        // driver error, and a Postgres unique violation quotes the row —
        // an email — in its DETAIL line.
        let error = DbError::Execute(
            "duplicate key value violates unique constraint \"subscribers_email_normalized_key\" \
             DETAIL:  Key (email_normalized)=(nick@example.com) already exists."
                .to_owned(),
        );
        let text = error.to_string();
        assert!(text.starts_with("execute failed: "), "{text}");
        assert!(!text.contains('@'), "{text}");
        assert!(!text.contains("nick"), "{text}");
        assert!(text.contains("[subject_hash:"), "{text}");

        // A connect failure echoing the URL must not disclose credentials.
        let error = DbError::Execute(
            "error connecting to postgres://venture:sup3r-s3cret@db.internal:5432/app".to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains("sup3r-s3cret"), "{text}");
        assert!(text.contains("postgres://[redacted]@db.internal"), "{text}");

        assert_eq!(
            DbError::Query("no such table: subscribers".to_owned()).to_string(),
            "query failed: no such table: subscribers"
        );
        assert_eq!(
            DbError::Batch("batch aborted".to_owned()).to_string(),
            "batch failed: batch aborted"
        );
    }
}
