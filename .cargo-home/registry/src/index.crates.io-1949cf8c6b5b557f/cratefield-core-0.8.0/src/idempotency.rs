//! Idempotent event handling (issue #134): an **inbox** that records each
//! external event's id once, so a duplicate, replayed, concurrent or
//! out-of-order delivery applies its effects exactly once.
//!
//! Verifying a Stripe webhook's signature and timestamp authenticates a
//! *delivery* — it does not stop Stripe from delivering the same event twice
//! (it retries), or two workers from processing the same event at once. A
//! module wraps its handler in a claim: the primary key lets exactly one
//! caller record the event, so exactly one caller sees `true` and does the
//! work. When the effect is database writes, claim with
//! [`claim_with`](Inbox::claim_with) — or put
//! [`claim_statement`](Inbox::claim_statement) first in your own
//! `db.batch_atomic(..)`, the [`Outbox`](crate::Outbox) rule mirrored: the
//! claim and the effect commit together or not at all, so a worker that dies
//! mid-batch leaves the key unclaimed and the redelivery re-runs both.
//!
//! ```ignore
//! let inbox = Inbox::new("billing_inbox");
//! let event = payments.verify_webhook(sig, body).await?; // verified first
//! if inbox.claim_with(db, &event.id, &now, &grant_stmts).await? {
//!     // first time: the claim AND the effect just committed together
//! } // else: a duplicate delivery — already handled, do nothing
//! ```
//!
//! The owning module includes [`Inbox::create_table_sql`] as a migration (it
//! owns the table, per the module contract). Prune old rows on whatever horizon
//! the provider retries within; the inbox is a dedup ledger, not a record.

use crate::ports::{Database, DbError, Statement};
use sea_query::{Alias, Expr, InsertStatement, OnConflict, Query};

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// A dedup ledger over the `Database` port. Construct it with the table the
/// owning module declares (e.g. `"<module>_inbox"`).
#[derive(Debug, Clone)]
pub struct Inbox {
    table: String,
}

impl Inbox {
    #[must_use]
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
        }
    }

    /// The portable DDL for the inbox table. The owning module ships this as a
    /// forward-only migration (it renders identically on SQLite/D1 and
    /// Postgres, ADR 0004).
    #[must_use]
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             event_key TEXT PRIMARY KEY,\n    \
             seen_at TEXT NOT NULL\n);",
            table = self.table
        )
    }

    /// Records `event_key`, returning `true` the **first** time it is seen
    /// (proceed and apply the effect) and `false` for any later delivery of the
    /// same id (a duplicate/replay/concurrent race — skip).
    ///
    /// The insert is a single `ON CONFLICT DO NOTHING` statement, so it is
    /// atomic on both D1 and Postgres: under concurrent claims of the same key
    /// exactly one insert takes, and only that caller gets `true`. `seen_at` is
    /// an RFC 3339 timestamp the caller reads from the `Clock` port.
    ///
    /// The claim commits **on its own**: if the worker dies after this returns
    /// `true` but before the effect is applied, the redelivery sees the key and
    /// skips — the event is lost (at-most-once). When the effect is itself
    /// database writes, use [`claim_with`](Self::claim_with), or put
    /// [`claim_statement`](Self::claim_statement) first in the same
    /// `db.batch_atomic(..)` as the effect, so the two commit together.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the write fails.
    pub async fn claim(
        &self,
        db: &dyn Database,
        event_key: &str,
        seen_at: &str,
    ) -> Result<bool, DbError> {
        let mut insert = self.claim_insert(event_key, seen_at);
        insert.on_conflict(
            OnConflict::column(iden("event_key"))
                .do_nothing()
                .to_owned(),
        );
        let affected = db.execute(&Statement::render(&insert)).await?;
        Ok(affected == 1)
    }

    /// The bare claim insert both public paths render — [`claim`](Self::claim)
    /// extends it with `ON CONFLICT DO NOTHING`,
    /// [`claim_statement`](Self::claim_statement) renders it as-is. Shared so
    /// the two cannot drift.
    fn claim_insert(&self, event_key: &str, seen_at: &str) -> InsertStatement {
        let mut insert = Query::insert();
        insert
            .into_table(iden(&self.table))
            .columns(["event_key", "seen_at"])
            .values_panic([event_key.to_owned().into(), seen_at.to_owned().into()]);
        insert
    }

    /// The claim as a bare `INSERT` with **no** `ON CONFLICT` clause, to run
    /// as the first statement of the same `db.batch_atomic(..)` that carries
    /// the effect's statements (see [`claim_with`](Self::claim_with) for the
    /// ready-made wrapper).
    ///
    /// Inside the batch the primary key does the first-writer-wins work: a
    /// key that is already claimed fails the insert, and the whole batch —
    /// effect included — rolls back, so a duplicate delivery applies nothing
    /// a second time. The claim and the effect commit together or not at all:
    /// a worker that dies before the batch commits leaves the key unclaimed,
    /// and the redelivery re-runs both.
    #[must_use]
    pub fn claim_statement(&self, event_key: &str, seen_at: &str) -> Statement {
        Statement::render(&self.claim_insert(event_key, seen_at))
    }

    /// Claims `event_key` and applies `effect` in one atomic batch, returning
    /// `true` when **this** delivery committed them (the convention of
    /// [`claim`](Self::claim)) and `false` when the key was already claimed —
    /// a duplicate, a replay, or a concurrent delivery that won the race — so
    /// the effect did not run again.
    ///
    /// The [`claim_statement`](Self::claim_statement) goes first, then
    /// `effect`, all through [`batch_atomic`](Database::batch_atomic): either
    /// everything commits or nothing does, and a worker that dies mid-batch
    /// leaves the key unclaimed for the retry.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] when the batch fails and the key is *not* claimed
    /// afterwards: nothing committed and the effect did not apply — the caller
    /// (or its queue) retries the whole delivery. A batch that failed because
    /// a concurrent delivery claimed the key first is not an error; it returns
    /// `Ok(false)`, told apart by re-reading the key rather than parsing the
    /// engine's error text.
    pub async fn claim_with(
        &self,
        db: &dyn Database,
        event_key: &str,
        seen_at: &str,
        effect: &[Statement],
    ) -> Result<bool, DbError> {
        if self.seen(db, event_key).await? {
            return Ok(false);
        }
        let mut batch = Vec::with_capacity(effect.len() + 1);
        batch.push(self.claim_statement(event_key, seen_at));
        batch.extend_from_slice(effect);
        match db.batch_atomic(&batch).await {
            Ok(()) => Ok(true),
            Err(batch_error) => {
                // The failed batch committed nothing, but a concurrent
                // delivery may have claimed the key meanwhile — the re-check
                // is what tells the two apart (no port guarantees the shape
                // of the engine's error text). If the re-check itself fails,
                // surface the original batch error.
                match self.seen(db, event_key).await {
                    Ok(true) => Ok(false),
                    _ => Err(batch_error),
                }
            }
        }
    }

    /// Whether `event_key` has already been recorded (a read-only check; a
    /// handler still uses [`claim`](Self::claim) or
    /// [`claim_with`](Self::claim_with) to act, since only those are
    /// race-free).
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the read fails.
    pub async fn seen(&self, db: &dyn Database, event_key: &str) -> Result<bool, DbError> {
        let mut select = Query::select();
        select
            .expr(Expr::val(1))
            .from(iden(&self.table))
            .and_where(Expr::col(iden("event_key")).eq(event_key))
            .limit(1);
        let rows = db.query(&Statement::render(&select)).await?;
        Ok(!rows.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_sql_is_portable_ddl() {
        let sql = Inbox::new("billing_inbox").create_table_sql();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS billing_inbox"));
        assert!(sql.contains("event_key TEXT PRIMARY KEY"));
        assert!(sql.contains("seen_at TEXT NOT NULL"));
    }

    #[test]
    fn claim_renders_insert_on_conflict_do_nothing() {
        // Render the statement the claim issues, without a database, and assert
        // its shape: an insert into the table with the two columns and an
        // ON CONFLICT DO NOTHING clause (the atomic first-writer-wins).
        let inbox = Inbox::new("billing_inbox");
        let mut insert = Query::insert();
        insert
            .into_table(iden(&inbox.table))
            .columns(["event_key", "seen_at"])
            .values_panic([
                "evt_1".to_owned().into(),
                "2026-09-07T00:00:00Z".to_owned().into(),
            ])
            .on_conflict(
                OnConflict::column(iden("event_key"))
                    .do_nothing()
                    .to_owned(),
            );
        let stmt = Statement::render(&insert);
        assert!(stmt.sql.contains("INSERT INTO"));
        assert!(stmt.sql.contains("billing_inbox"));
        assert!(stmt.sql.to_uppercase().contains("ON CONFLICT"));
        assert!(stmt.sql.to_uppercase().contains("DO NOTHING"));
        assert_eq!(stmt.values.0.len(), 2);
    }

    #[test]
    fn claim_statement_renders_bare_insert_without_on_conflict() {
        // The in-batch claim must NOT carry ON CONFLICT DO NOTHING: inside
        // batch_atomic a duplicate key has to fail the insert so the whole
        // batch (claim + effect) rolls back together.
        let inbox = Inbox::new("billing_inbox");
        let stmt = inbox.claim_statement("evt_1", "2026-09-07T00:00:00Z");
        assert!(stmt.sql.contains("INSERT INTO"));
        assert!(stmt.sql.contains("billing_inbox"));
        assert!(stmt.sql.contains("event_key"));
        assert!(stmt.sql.contains("seen_at"));
        assert!(
            !stmt.sql.to_uppercase().contains("ON CONFLICT"),
            "a duplicate key must fail the batch, not be swallowed: {}",
            stmt.sql
        );
        assert_eq!(stmt.values.0.len(), 2);
    }
}
