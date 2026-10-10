//! Durable outbox (issue #128): the pair of the [`Inbox`](crate::Inbox). Where
//! the inbox makes *inbound* effects exactly-once, the outbox makes *outbound*
//! work at-least-once even across a crash.
//!
//! `Defer` (Workers `wait_until`, native `tokio::spawn`) is an execution
//! *opportunity*, not durable delivery: a process exit, an execution deadline
//! or a downstream failure loses the confirmation mail or the cross-module
//! action after the database mutation already committed. The outbox closes that
//! gap:
//!
//! 1. A module writes an outbox row **inside the same batch** as its state
//!    change — [`enqueue_statement`](Outbox::enqueue_statement) returns a
//!    [`Statement`] the module appends to its own `db.batch_atomic(..)`, so the row
//!    commits atomically with the change or not at all.
//! 2. It then uses `Defer` only to *attempt* immediate delivery: lease due rows
//!    with [`claim_due`](Outbox::claim_due), deliver, and
//!    [`complete`](Outbox::complete) (delete) or [`retry_later`](Outbox::retry_later).
//! 3. The venture's scheduled entry point drains whatever immediate delivery
//!    missed, on the same lease + bounded-retry path —
//!    [`drain_within`](Outbox::drain_within) is that drain with a
//!    [`ScheduledBudget`] applied: at most N due items per tick, and a stop
//!    when the invocation's budget is spent.
//!
//! Leasing is race-free without a portable `RETURNING`: `claim_due` selects due
//! rows, then wins each one with a guarded `UPDATE … WHERE locked_until IS NULL
//! OR locked_until < now` (the same first-writer-wins the inbox uses), so two
//! drainers never deliver the same row. Consumers must still be idempotent
//! (pair the topic with an [`Inbox`](crate::Inbox) key) — the outbox guarantees
//! at-least-once, not exactly-once.

use crate::ports::{Clock, Database, DbError, Statement};
use crate::scheduled::ScheduledBudget;
use sea_query::{Alias, Expr, Order, Query};
use std::collections::VecDeque;
use std::future::Future;
use time::{Duration, OffsetDateTime};

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// The RFC 3339 spelling every outbox timestamp is stored with: to the
/// second, normalized to UTC, because lexicographic order on that spelling
/// is chronological order, and that is what the due and lease compares
/// rely on — and what makes a timestamp a handler produced in any offset
/// comparable with one the drain computed.
fn rfc3339(at: OffsetDateTime) -> String {
    use time::format_description::well_known::Rfc3339;
    let at = at.to_offset(time::UtcOffset::UTC);
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// A leased outbox record handed to a drainer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRecord {
    pub id: String,
    /// What kind of work this is (the module routes on it).
    pub topic: String,
    /// The opaque payload the module wrote (typically JSON).
    pub payload: String,
    /// How many delivery attempts have already failed.
    pub attempts: i64,
}

/// A durable work queue over the `Database` port. Construct it with the table
/// the owning module declares (e.g. `"<module>_outbox"`).
#[derive(Debug, Clone)]
pub struct Outbox {
    table: String,
}

impl Outbox {
    #[must_use]
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
        }
    }

    /// The portable DDL for the outbox table. The owning module ships this as a
    /// forward-only migration.
    #[must_use]
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             id TEXT PRIMARY KEY,\n    \
             topic TEXT NOT NULL,\n    \
             payload TEXT NOT NULL,\n    \
             subject TEXT,\n    \
             attempts INTEGER NOT NULL DEFAULT 0,\n    \
             next_attempt_at TEXT NOT NULL,\n    \
             locked_until TEXT,\n    \
             created_at TEXT NOT NULL\n);",
            table = self.table
        )
    }

    /// The `INSERT` that enqueues one unit of work. Return it into the module's
    /// **own** `db.batch_atomic(..)` alongside the state change, so the row is durable
    /// exactly when the change is. `id` is a caller-supplied ULID; `at` is an
    /// RFC 3339 timestamp used for both `created_at` and the initial
    /// `next_attempt_at` (deliver as soon as possible).
    ///
    /// `subject` is the person the work is for — an account id, a waitlist
    /// entry id — or `None` for work that names nobody. Writing it is what
    /// makes the queued row reachable for export and erasure (issue #266):
    /// the payload JSON is the module's own dialect and no predicate can
    /// match into it. Pass it for every per-person job even when it feels
    /// redundant with the payload; `None` rows drain identically but are
    /// returned for nobody's subject, so a forgotten `Some` is a silent
    /// hole in the erasure catalogue rather than an error.
    #[must_use]
    pub fn enqueue_statement(
        &self,
        id: &str,
        topic: &str,
        payload: &str,
        subject: Option<&str>,
        at: &str,
    ) -> Statement {
        let mut insert = Query::insert();
        insert
            .into_table(iden(&self.table))
            .columns([
                "id",
                "topic",
                "payload",
                "subject",
                "attempts",
                "next_attempt_at",
                "created_at",
            ])
            .values_panic([
                id.to_owned().into(),
                topic.to_owned().into(),
                payload.to_owned().into(),
                subject.map(str::to_owned).into(),
                0i64.into(),
                at.to_owned().into(),
                at.to_owned().into(),
            ]);
        Statement::render(&insert)
    }

    /// Leases up to `limit` records that are due (`next_attempt_at <= now`) and
    /// not already leased, marking each `locked_until = lease_until` so a
    /// concurrent drainer skips it. Returns only the rows this caller won.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if a read or lease write fails.
    pub async fn claim_due(
        &self,
        db: &dyn Database,
        now: &str,
        lease_until: &str,
        limit: u64,
    ) -> Result<Vec<OutboxRecord>, DbError> {
        let mut select = Query::select();
        select
            .columns([iden("id"), iden("topic"), iden("payload"), iden("attempts")])
            .from(iden(&self.table))
            .and_where(Expr::col(iden("next_attempt_at")).lte(now))
            .and_where(
                Expr::col(iden("locked_until"))
                    .is_null()
                    .or(Expr::col(iden("locked_until")).lt(now)),
            )
            .order_by(iden("next_attempt_at"), Order::Asc)
            .limit(limit);
        let rows = db.query(&Statement::render(&select)).await?;

        let mut leased = Vec::new();
        for row in &rows.rows {
            let id = row.get::<String>("id").unwrap_or_default();
            // Win the lease with a guarded update: exactly one drainer's write
            // takes, and only it processes the row.
            let mut lease = Query::update();
            lease
                .table(iden(&self.table))
                .value(iden("locked_until"), lease_until)
                .and_where(Expr::col(iden("id")).eq(id.as_str()))
                .and_where(
                    Expr::col(iden("locked_until"))
                        .is_null()
                        .or(Expr::col(iden("locked_until")).lt(now)),
                );
            if db.execute(&Statement::render(&lease)).await? == 1 {
                leased.push(OutboxRecord {
                    id,
                    topic: row.get::<String>("topic").unwrap_or_default(),
                    payload: row.get::<String>("payload").unwrap_or_default(),
                    attempts: row.get::<i64>("attempts").unwrap_or(0),
                });
            }
        }
        Ok(leased)
    }

    /// Removes a record after successful delivery.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the delete fails.
    pub async fn complete(&self, db: &dyn Database, id: &str) -> Result<(), DbError> {
        let mut delete = Query::delete();
        delete
            .from_table(iden(&self.table))
            .and_where(Expr::col(iden("id")).eq(id));
        db.execute(&Statement::render(&delete)).await?;
        Ok(())
    }

    /// Reschedules a record after a failed delivery: increments `attempts`,
    /// sets the next attempt time (the caller applies its own backoff), and
    /// clears the lease so a drainer can pick it up again.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the update fails.
    pub async fn retry_later(
        &self,
        db: &dyn Database,
        id: &str,
        next_attempt_at: &str,
    ) -> Result<(), DbError> {
        let mut update = Query::update();
        update
            .table(iden(&self.table))
            .value(iden("attempts"), Expr::col(iden("attempts")).add(1))
            .value(iden("next_attempt_at"), next_attempt_at)
            .value(iden("locked_until"), Option::<String>::None)
            .and_where(Expr::col(iden("id")).eq(id));
        db.execute(&Statement::render(&update)).await?;
        Ok(())
    }

    /// Reschedules a record **without** counting an attempt: sets the next
    /// attempt time and clears the lease. Two uses. First, the per-item
    /// cursor for recurring work — one outbox row per thing to poll,
    /// rescheduled by the handler to its next poll time, so "process N due
    /// items per tick" is just a bounded claim. Second, how
    /// [`drain_within`](Outbox::drain_within) releases claimed-but-unprocessed
    /// rows when the budget runs out: a release is not a failure and must
    /// not read as one.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the update fails.
    pub async fn reschedule(
        &self,
        db: &dyn Database,
        id: &str,
        next_attempt_at: &str,
    ) -> Result<(), DbError> {
        let mut update = Query::update();
        update
            .table(iden(&self.table))
            .value(iden("next_attempt_at"), next_attempt_at)
            .value(iden("locked_until"), Option::<String>::None)
            .and_where(Expr::col(iden("id")).eq(id));
        db.execute(&Statement::render(&update)).await?;
        Ok(())
    }

    /// Drains due records under a [`ScheduledBudget`]: process at most
    /// `opts.limit` items this tick, and fewer when the budget cannot carry
    /// them. This is the "N due items per tick" helper — a recurring poller
    /// writes one outbox row per thing to poll and returns
    /// [`Processed::NextAt`] with the row's next poll time, which
    /// [`reschedule`](Outbox::reschedule) applies **without** counting an
    /// attempt, so the row comes back due exactly when it should and a
    /// poll that keeps failing still counts toward the bounded retry the
    /// [`RetryAt`](Processed::RetryAt) path enforces.
    ///
    /// The budget is checked twice: the claim itself is capped at what the
    /// remaining subrequests can carry (`remaining /
    /// opts.subrequests_per_item`, uncapped when subrequests are unbounded
    /// or `subrequests_per_item` is `0`), and each record is checked again
    /// before its handler runs — a budget that runs out mid-batch releases
    /// that record and every claimed one after it through
    /// [`reschedule`](Outbox::reschedule), so they are immediately claimable
    /// on the next tick, and sets `stopped_by_budget` on the report.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] when a claim, complete or reschedule write
    /// fails. Records already handled before the failure are finished; the
    /// rest keep their lease until it lapses — at-least-once, as ever.
    pub async fn drain_within<F, Fut>(
        &self,
        db: &dyn Database,
        clock: &dyn Clock,
        budget: &ScheduledBudget,
        opts: DrainOptions,
        handle: F,
    ) -> Result<DrainReport, DbError>
    where
        F: FnMut(OutboxRecord) -> Fut,
        Fut: Future<Output = Processed>,
    {
        let mut handle = handle;
        let mut report = DrainReport::default();
        let now = clock.now();
        // A time-only drain (`subrequests_per_item == 0`) answers to the
        // wall half of the budget alone — the subrequest count never
        // applies to it.
        let out_of_budget = if opts.subrequests_per_item == 0 {
            budget.expired(now)
        } else {
            budget.exhausted(now)
        };
        if out_of_budget {
            report.stopped_by_budget = true;
            return Ok(report);
        }
        // Claim no more than the budget can carry, so a bounded invocation
        // does not lease rows it will only have to release. Divide first:
        // the cap is how many whole items fit in the remaining budget.
        let limit = match budget.remaining_subrequests() {
            Some(remaining) if opts.subrequests_per_item > 0 => {
                (u64::from(remaining) / u64::from(opts.subrequests_per_item)).min(opts.limit)
            }
            _ => opts.limit,
        };
        let capped_by_budget = limit < opts.limit;
        let now_iso = rfc3339(now);
        let lease_until = rfc3339(now.saturating_add(opts.lease));
        let mut queue: VecDeque<OutboxRecord> = self
            .claim_due(db, &now_iso, &lease_until, limit)
            .await?
            .into();
        // A cap below `limit` only means "the budget cut this tick short"
        // when the claim filled it; fewer rows than the cap were simply all
        // the rows there were.
        if capped_by_budget && queue.len() as u64 >= limit {
            report.stopped_by_budget = true;
        }
        while let Some(record) = queue.pop_front() {
            let now = clock.now();
            // With `subrequests_per_item == 0`, `try_spend` cannot refuse,
            // so this check is the expiry alone — matching the start.
            if budget.expired(now) || !budget.try_spend(opts.subrequests_per_item) {
                report.stopped_by_budget = true;
                // The budget ran out: this record and every claimed one
                // behind it go back, unleased and uncounted, due now.
                for unspent in &queue {
                    self.reschedule(db, &unspent.id, &now_iso).await?;
                    report.released += 1;
                }
                self.reschedule(db, &record.id, &now_iso).await?;
                report.released += 1;
                break;
            }
            // The handler takes the record; the row's id is all the
            // completion writes need of it afterwards.
            let id = record.id.clone();
            match handle(record).await {
                Processed::Done => self.complete(db, &id).await?,
                Processed::RetryAt(at) => {
                    self.retry_later(db, &id, &rfc3339(at)).await?;
                }
                Processed::NextAt(at) => {
                    self.reschedule(db, &id, &rfc3339(at)).await?;
                }
            }
            report.processed += 1;
        }
        Ok(report)
    }
}

/// How many items a [`drain_within`](Outbox::drain_within) may process in
/// one tick, under what lease, and what one item costs the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainOptions {
    /// At most this many records are claimed and handled per tick.
    pub limit: u64,
    /// How long a claimed record stays leased while its handler runs. A
    /// handler that overruns it hands the record to a concurrent drainer —
    /// at-least-once, so pair the topic with an [`Inbox`](crate::Inbox) key.
    pub lease: Duration,
    /// Subrequest-shaped steps one handled record costs the
    /// [`ScheduledBudget`]. `0` makes the budget time-only.
    pub subrequests_per_item: u32,
}

/// What the handler made of one record.
#[derive(Debug)]
pub enum Processed {
    /// Delivered: remove the record.
    Done,
    /// Failed: reschedule with `attempts` incremented — the caller applies
    /// its own backoff through the timestamp. Enough failures and the
    /// bounded-retry posture of the module applies.
    RetryAt(OffsetDateTime),
    /// Not due yet — recurring work: reschedule to `at` **without**
    /// counting an attempt. This is the per-item cursor: one row per thing
    /// to poll, moved to its next poll time.
    NextAt(OffsetDateTime),
}

/// What one [`drain_within`](Outbox::drain_within) pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DrainReport {
    /// Records handled to an outcome (`Done`, `RetryAt` or `NextAt`).
    pub processed: u64,
    /// Claimed records handed back unprocessed because the budget ran out.
    pub released: u64,
    /// The budget cut this tick short — at the start check, by the claim
    /// cap, or mid-batch — and more rows may still be due. `false` means
    /// every due row the budget allowed was handled and nothing waited
    /// behind the budget. Run again next tick either way.
    pub stopped_by_budget: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_sql_is_portable_ddl() {
        let sql = Outbox::new("mail_outbox").create_table_sql();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS mail_outbox"));
        assert!(sql.contains("next_attempt_at TEXT NOT NULL"));
        assert!(sql.contains("locked_until TEXT"));
        // Nullable, not NOT NULL: the migration story is ADD COLUMN on a
        // live table, and NOT NULL would force a backfill that cannot be
        // honest about rows whose payload never parsed.
        assert!(sql.contains("subject TEXT"));
    }

    #[test]
    fn enqueue_statement_inserts_the_row() {
        let stmt = Outbox::new("mail_outbox").enqueue_statement(
            "01J",
            "confirmation",
            "{\"to\":\"a@b\"}",
            Some("acct-1"),
            "2026-09-07T00:00:00Z",
        );
        assert!(stmt.sql.contains("INSERT INTO"));
        assert!(stmt.sql.contains("mail_outbox"));
        assert!(stmt.sql.contains("subject"));
        // id, topic, payload, subject, attempts, next_attempt_at, created_at
        assert_eq!(stmt.values.0.len(), 7);
        assert_eq!(stmt.values.0[3], "acct-1".into());
    }

    #[test]
    fn enqueue_statement_without_a_subject_binds_null() {
        // The shape a row written before the migration has: the column
        // exists, the value does not. The drain treats both the same.
        let stmt = Outbox::new("mail_outbox").enqueue_statement(
            "01J",
            "confirmation",
            "{\"to\":\"a@b\"}",
            None,
            "2026-09-07T00:00:00Z",
        );
        assert!(stmt.sql.contains("subject"));
        assert_eq!(
            stmt.values.0[3],
            sea_query::Value::from(Option::<String>::None)
        );
    }
}
