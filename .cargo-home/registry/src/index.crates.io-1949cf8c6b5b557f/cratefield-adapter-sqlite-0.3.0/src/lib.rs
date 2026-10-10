//! `cratefield-adapter-sqlite`: the [`Database`] port over `rusqlite`
//! (bundled SQLite). Native only — never compiled to wasm. Used by every
//! module test and viable for a single-node self-hosted deployment
//! (ADR 0004).
//!
//! A `rusqlite::Connection` is `Send` but `!Sync`; the harness requires
//! `Arc<dyn Database>` to be `Send + Sync`, so the connection lives
//! behind a mutex. This is connection guarding, not request state; the
//! scoped clippy allow follows the policy documented in the workspace
//! `clippy.toml`.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use async_trait::async_trait;
use cratefield_core::{Database, DbError, Row, Rows, SqlMigration, Statement};
use rusqlite::types::Value as SqliteValue;
use rusqlite::{Connection, OptionalExtension};
use sea_query::Value as SeaValue;
// Connection guarding (see module docs) — not request state.
#[allow(clippy::disallowed_types)]
type Guarded<T> = std::sync::Mutex<T>;

/// An open SQLite database (file path or `:memory:`).
pub struct SqliteDatabase {
    // Connection guarding (see module docs) — not request state.
    #[allow(clippy::disallowed_types)]
    conn: Guarded<Connection>,
}

fn db_err(err: &rusqlite::Error) -> DbError {
    DbError::Query(err.to_string())
}

fn sea_to_sqlite(value: &SeaValue) -> SqliteValue {
    let null = SqliteValue::Null;
    match value {
        SeaValue::Bool(v) => v.map_or(null, |v| SqliteValue::Integer(i64::from(v))),
        SeaValue::TinyInt(v) => v.map_or(null, |v| SqliteValue::Integer(i64::from(v))),
        SeaValue::SmallInt(v) => v.map_or(null, |v| SqliteValue::Integer(i64::from(v))),
        SeaValue::Int(v) => v.map_or(null, |v| SqliteValue::Integer(i64::from(v))),
        SeaValue::BigInt(v) => v.map_or(null, SqliteValue::Integer),
        // sea-query renders `LIMIT n` and unsigned literals as unsigned
        // variants; SQLite has only INTEGER, so widen here.
        SeaValue::TinyUnsigned(v) => v.map_or(null, |v| SqliteValue::Integer(i64::from(v))),
        SeaValue::SmallUnsigned(v) => v.map_or(null, |v| SqliteValue::Integer(i64::from(v))),
        SeaValue::Unsigned(v) => v.map_or(null, |v| SqliteValue::Integer(i64::from(v))),
        SeaValue::BigUnsigned(v) => v.map_or(null, |v| {
            SqliteValue::Integer(i64::try_from(v).unwrap_or(i64::MAX))
        }),
        SeaValue::Float(v) => v.map_or(null, |v| SqliteValue::Real(f64::from(v))),
        SeaValue::Double(v) => v.map_or(null, SqliteValue::Real),
        SeaValue::String(v) => v
            .as_ref()
            .map_or(null, |v| SqliteValue::Text(v.to_string())),
        SeaValue::Char(v) => v.map_or(null, |v| SqliteValue::Text(v.to_string())),
        SeaValue::Bytes(v) => v
            .as_ref()
            .map_or(null, |v| SqliteValue::Blob((**v).clone())),
    }
}

fn sqlite_to_sea(value: SqliteValue) -> SeaValue {
    match value {
        SqliteValue::Null => SeaValue::String(None),
        SqliteValue::Integer(v) => SeaValue::BigInt(Some(v)),
        SqliteValue::Real(v) => SeaValue::Double(Some(v)),
        SqliteValue::Text(v) => SeaValue::String(Some(Box::new(v))),
        SqliteValue::Blob(v) => SeaValue::Bytes(Some(Box::new(v))),
    }
}

impl SqliteDatabase {
    /// Opens a database file; `:memory:` for an in-memory database.
    ///
    /// # Errors
    ///
    /// Propagates `rusqlite::Error` when the file cannot be opened.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        Ok(Self {
            conn: Guarded::new(Connection::open(path)?),
        })
    }

    /// An in-memory database (fresh per instance).
    ///
    /// # Errors
    ///
    /// Only if SQLite cannot allocate the in-memory handle.
    pub fn in_memory() -> rusqlite::Result<Self> {
        Ok(Self {
            conn: Guarded::new(Connection::open_in_memory()?),
        })
    }
}

impl SqliteDatabase {
    /// Applies a module's unapplied migrations in order, tracked under
    /// `<module>/<id>` in a `harness_migrations` table; each migration
    /// runs in its own transaction so a failure rolls back atomically and
    /// re-running is idempotent.
    ///
    /// # Errors
    ///
    /// `DbError::Batch` when a migration's SQL fails.
    ///
    /// # Panics
    ///
    /// Only if the connection mutex is poisoned by a prior panic.
    pub fn apply_migrations(
        &self,
        module: &str,
        migrations: &[SqlMigration],
    ) -> Result<(), DbError> {
        let conn = self.conn.lock().expect("sqlite lock uncontended");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS harness_migrations (
                 id TEXT PRIMARY KEY,
                 applied_at TEXT NOT NULL,
                 checksum TEXT
             );",
        )
        .map_err(|err| DbError::Batch(err.to_string()))?;
        // Databases migrated before checksums were recorded have the
        // two-column table. Add the column; their existing rows stay
        // NULL, which reads as "applied, cannot verify" rather than as a
        // mismatch — the honest answer for SQL nobody hashed.
        let has_checksum = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('harness_migrations') \
                 WHERE name = 'checksum'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count > 0)
            .map_err(|err| db_err(&err))?;
        if !has_checksum {
            conn.execute_batch("ALTER TABLE harness_migrations ADD COLUMN checksum TEXT;")
                .map_err(|err| DbError::Batch(err.to_string()))?;
        }

        for migration in migrations {
            let key = format!("{module}/{}", migration.id);
            let checksum = cratefield_core::migration_checksum(migration.sql);
            let recorded: Option<Option<String>> = conn
                .query_row(
                    "SELECT checksum FROM harness_migrations WHERE id = ?1",
                    [&key],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|err| db_err(&err))?;
            if let Some(recorded) = recorded {
                if let Some(recorded) = recorded.filter(|hash| hash != &checksum) {
                    return Err(DbError::Batch(cratefield_core::migration_edited(
                        &key, &recorded, &checksum,
                    )));
                }
                continue;
            }
            if !migration.transactional {
                // Runs alone, then the tracking row (RECONCILIATION.md §4).
                // The SQL must be idempotent: a crash between the two steps
                // re-runs it on the next boot.
                if !cratefield_core::is_idempotent_sql(migration.sql) {
                    return Err(DbError::Batch(cratefield_core::migration_missing_guard(
                        &key,
                    )));
                }
                conn.execute_batch(migration.sql)
                    .map_err(|err| DbError::Batch(err.to_string()))?;
                conn.execute(
                    "INSERT INTO harness_migrations (id, applied_at, checksum) VALUES (?1, ?2, ?3)",
                    rusqlite::params![key, iso_now(), checksum],
                )
                .map_err(|err| DbError::Batch(err.to_string()))?;
                continue;
            }
            let tx = conn
                .unchecked_transaction()
                .map_err(|err| DbError::Batch(err.to_string()))?;
            tx.execute_batch(migration.sql)
                .map_err(|err| DbError::Batch(err.to_string()))?;
            tx.execute(
                "INSERT INTO harness_migrations (id, applied_at, checksum) VALUES (?1, ?2, ?3)",
                rusqlite::params![key, iso_now(), checksum],
            )
            .map_err(|err| DbError::Batch(err.to_string()))?;
            tx.commit().map_err(|err| DbError::Batch(err.to_string()))?;
        }
        Ok(())
    }
}

fn iso_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[async_trait]
impl Database for SqliteDatabase {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        let conn = self.conn.lock().expect("sqlite lock uncontended");
        let params: Vec<SqliteValue> = stmt.values.0.iter().map(sea_to_sqlite).collect();
        let changed = conn
            .execute(&stmt.sql, rusqlite::params_from_iter(params))
            .map_err(|err| DbError::Execute(err.to_string()))?;
        Ok(u64::try_from(changed).unwrap_or(u64::MAX))
    }

    async fn query(&self, stmt: &Statement) -> Result<Rows, DbError> {
        let conn = self.conn.lock().expect("sqlite lock uncontended");
        let params: Vec<SqliteValue> = stmt.values.0.iter().map(sea_to_sqlite).collect();
        let mut prepared = conn
            .prepare(&stmt.sql)
            .map_err(|err| DbError::Query(err.to_string()))?;
        let column_names: Vec<String> = prepared
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut rows = prepared
            .query(rusqlite::params_from_iter(params))
            .map_err(|err| DbError::Query(err.to_string()))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|err| db_err(&err))? {
            let mut columns = Vec::with_capacity(column_names.len());
            for (index, name) in column_names.iter().enumerate() {
                let value: SqliteValue = row.get(index).map_err(|err| db_err(&err))?;
                columns.push((name.clone(), sqlite_to_sea(value)));
            }
            out.push(Row::new(columns));
        }
        Ok(Rows::new(out))
    }

    /// Runs all statements in one transaction (atomic on SQLite).
    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), DbError> {
        let conn = self.conn.lock().expect("sqlite lock uncontended");
        let tx = conn
            .unchecked_transaction()
            .map_err(|err| DbError::Batch(err.to_string()))?;
        for stmt in stmts {
            let params: Vec<SqliteValue> = stmt.values.0.iter().map(sea_to_sqlite).collect();
            tx.execute(&stmt.sql, rusqlite::params_from_iter(params))
                .map_err(|err| DbError::Batch(err.to_string()))?;
        }
        tx.commit().map_err(|err| DbError::Batch(err.to_string()))?;
        Ok(())
    }
}
