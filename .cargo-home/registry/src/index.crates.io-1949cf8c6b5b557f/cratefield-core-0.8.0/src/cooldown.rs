//! Durable per-subject send cooldown (issue #133): the rate limiter is a
//! distributed counter whose transport can fail open, so a mail-triggering
//! route needs a **backstop the database enforces**: at most one send per
//! subject per window, race-free without a transaction.
//!
//! The claim is a guarded `UPDATE` (re-claim only once the window has
//! passed) followed by an `INSERT ... ON CONFLICT DO NOTHING` (first send
//! for a never-seen subject) — exactly one of the two statements reports
//! one affected row per window, on both SQLite/D1 and Postgres. Same
//! primitive the [`Inbox`] dedup ledger uses, with a time window added.
//!
//! ```ignore
//! let cooldown = SendCooldown::new("waitlist_send_cooldown");
//! if cooldown.try_acquire(&*db, &subject, &now, &cutoff).await? {
//!     // this request owns the window: send the mail
//! } // else: a concurrent or repeat request inside the window: skip the send
//! ```
//!
//! [`Inbox`]: crate::idempotency::Inbox

use crate::ports::{Database, DbError, Statement};
use sea_query::{Alias, Expr, OnConflict, Query};

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// A cooldown ledger over the `Database` port. Construct it with the table
/// the owning module declares (e.g. `"<module>_send_cooldown"`); the
/// owning module ships [`create_table_sql`](Self::create_table_sql) as a
/// migration.
///
/// Timestamps are RFC 3339 strings from the `Clock` port, the same shape
/// the house stores in `TEXT` columns everywhere: lexicographic order on
/// that format is chronological order, which is what the window compare
/// relies on.
#[derive(Debug, Clone)]
pub struct SendCooldown {
    table: String,
}

impl SendCooldown {
    #[must_use]
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
        }
    }

    /// The portable DDL for the cooldown table (renders identically on
    /// SQLite/D1 and Postgres, ADR 0004).
    #[must_use]
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             subject TEXT PRIMARY KEY,\n    \
             last_sent_at TEXT NOT NULL\n);",
            table = self.table
        )
    }

    /// Claims the send window for `subject`: `true` for the **one** caller
    /// whose claim lands, `false` for anyone inside the window.
    ///
    /// `now` is the RFC 3339 timestamp to record, `cutoff` the instant
    /// (`now - window`) after which an expired claim may be renewed. The
    /// update-then-insert pair is race-free: the guarded `UPDATE` can be
    /// won by exactly one writer, and the conflict-insert covers the row
    /// not existing (yet).
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if either write fails.
    pub async fn try_acquire(
        &self,
        db: &dyn Database,
        subject: &str,
        now: &str,
        cutoff: &str,
    ) -> Result<bool, DbError> {
        let mut renew = Query::update();
        renew
            .table(iden(&self.table))
            .value(iden("last_sent_at"), now)
            .and_where(Expr::col(iden("subject")).eq(subject))
            .and_where(Expr::col(iden("last_sent_at")).lt(cutoff));
        if db.execute(&Statement::render(&renew)).await? == 1 {
            return Ok(true);
        }
        let mut first = Query::insert();
        first
            .into_table(iden(&self.table))
            .columns(["subject", "last_sent_at"])
            .values_panic([subject.to_owned().into(), now.to_owned().into()])
            .on_conflict(OnConflict::column(iden("subject")).do_nothing().to_owned());
        Ok(db.execute(&Statement::render(&first)).await? == 1)
    }

    /// Releases a claim so the window is not consumed by a send that never
    /// started (e.g. the mailer port answered `NotConfigured`).
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the delete fails.
    pub async fn release(&self, db: &dyn Database, subject: &str) -> Result<(), DbError> {
        let mut delete = Query::delete();
        delete
            .from_table(iden(&self.table))
            .and_where(Expr::col(iden("subject")).eq(subject));
        db.execute(&Statement::render(&delete)).await?;
        Ok(())
    }

    /// Deletes claims older than `before` (rows whose window has closed
    /// anyway). Returns the number removed; a module calls this from its
    /// scheduled handler.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the delete fails.
    pub async fn prune(&self, db: &dyn Database, before: &str) -> Result<u64, DbError> {
        let mut delete = Query::delete();
        delete
            .from_table(iden(&self.table))
            .and_where(Expr::col(iden("last_sent_at")).lt(before));
        db.execute(&Statement::render(&delete)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_sql_is_portable_ddl() {
        let sql = SendCooldown::new("waitlist_send_cooldown").create_table_sql();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS waitlist_send_cooldown"));
        assert!(sql.contains("subject TEXT PRIMARY KEY"));
        assert!(sql.contains("last_sent_at TEXT NOT NULL"));
    }
}
