//! Usage metering (issue #588): a durable, race-free **allowance** counter —
//! "this account may send 1 000 mails this month" — as opposed to the
//! [`RateLimiter`](crate::RateLimiter), which throttles *attempts* over a
//! short window and may fail open.
//!
//! Admission and the increment are **one statement**, so concurrent callers
//! cannot both spend the last unit. [`Usage::consume_statement`] returns a
//! [`Statement`] for the module's own `db.batch_atomic(..)`, beside the work
//! it pays for; a spent allowance **fails** that statement (a `NOT NULL`
//! violation on `used`) rather than affecting zero rows, because
//! `batch_atomic` reports no counts and a silent zero would let the work
//! commit for free. [`Usage::consume`] runs the same upsert alone and answers
//! a [`Consumption`].
//!
//! Either way: **spend in the same transaction as the work**. Timestamps are
//! RFC 3339 UTC strings with nanoseconds stripped (lexicographic order is
//! chronological), and `used` is a signed 64-bit `BIGINT` on both engines, so
//! a counter tops out at `i64::MAX`.

use crate::ports::{Database, DbError, Statement};
use std::collections::HashMap;
use std::time::Duration as StdDuration;
use time::{Date, Month, OffsetDateTime, UtcOffset};

/// How many whole months one [`Period::Anchored`] period spans. Must be
/// non-zero; the arithmetic clamps a zero to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Months(pub u32);

/// How a period is cut. Every variant converts to UTC first, so an instant in
/// any offset names the same window as its UTC spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    /// The UTC calendar month.
    CalendarMonthUtc,
    /// A cycle anchored on a subscription's start: period *k* starts at
    /// `anchor + k * every` months, **recomputed from the anchor every time,
    /// never chained**, the day clamped to the target month's last day and the
    /// anchor's UTC time-of-day kept. An anchor on Jan 31 gives Feb 28 (Feb 29
    /// in a leap year), then Mar 31, then Apr 30 — each clamp remembered only
    /// for the month that needs it. A `now` before the anchor uses floor
    /// division (a negative *k*).
    Anchored {
        anchor: OffsetDateTime,
        every: Months,
    },
    /// The UTC calendar day.
    Day,
}

/// A half-open period `[start, end)`, both instants UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodWindow {
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
}

impl Period {
    /// The window containing `now`.
    #[must_use]
    pub fn window_at(self, now: OffsetDateTime) -> PeriodWindow {
        self.window_for(self.index_at(now))
    }

    /// The period index containing `now`: what [`window_for`](Period::window_for)
    /// inverts and what history and purge step over.
    #[must_use]
    pub fn index_at(self, now: OffsetDateTime) -> i64 {
        let now = now.to_offset(UtcOffset::UTC);
        match self {
            Self::CalendarMonthUtc => month_index(now.year(), now.month()),
            Self::Day => i64::from(now.date().to_julian_day()),
            Self::Anchored { anchor, every } => {
                let anchor = anchor.to_offset(UtcOffset::UTC);
                let every = i64::from(every.0.max(1));
                // The month difference ignores the day, so the estimate can
                // land one period either side of a boundary; walk it in.
                let diff = month_index(now.year(), now.month())
                    - month_index(anchor.year(), anchor.month());
                let mut index = diff.div_euclid(every);
                while anchored_start(anchor, every, index + 1) <= now {
                    index += 1;
                }
                while anchored_start(anchor, every, index) > now {
                    index -= 1;
                }
                index
            }
        }
    }

    /// The window with this index: `window_for(index_at(now)) == window_at(now)`.
    #[must_use]
    pub fn window_for(self, index: i64) -> PeriodWindow {
        match self {
            Self::CalendarMonthUtc => PeriodWindow {
                start: month_start(index),
                end: month_start(index + 1),
            },
            Self::Day => PeriodWindow {
                start: day_start(index),
                end: day_start(index + 1),
            },
            Self::Anchored { anchor, every } => {
                let every = i64::from(every.0.max(1));
                PeriodWindow {
                    start: anchored_start(anchor, every, index),
                    end: anchored_start(anchor, every, index + 1),
                }
            }
        }
    }
}

/// The month spine every calendar calculation counts in: `year * 12 +
/// (month - 1)`, so consecutive months differ by one across a year boundary.
fn month_index(year: i32, month: Month) -> i64 {
    i64::from(year) * 12 + i64::from(u8::from(month)) - 1
}

/// The first instant of absolute month `index`, UTC.
fn month_start(index: i64) -> OffsetDateTime {
    let year = i32::try_from(index.div_euclid(12)).expect("month index within time's year range");
    let month = month_from(index.rem_euclid(12) + 1);
    Date::from_calendar_date(year, month, 1)
        .expect("the first of a valid month is a valid date")
        .midnight()
        .assume_utc()
}

/// The first instant of the UTC day `index` julian days after the julian
/// epoch.
fn day_start(index: i64) -> OffsetDateTime {
    Date::from_julian_day(i32::try_from(index).expect("julian day within time's year range"))
        .expect("a valid julian day is a valid date")
        .midnight()
        .assume_utc()
}

/// The start of anchored period `index`: `anchor + index * every` months,
/// computed from the anchor each time, the day clamped to the target month's
/// last day and the anchor's UTC time-of-day kept.
fn anchored_start(anchor: OffsetDateTime, every: i64, index: i64) -> OffsetDateTime {
    let anchor = anchor.to_offset(UtcOffset::UTC);
    let target = month_index(anchor.year(), anchor.month()) + index * every;
    let year = i32::try_from(target.div_euclid(12)).expect("anchor month within time's year range");
    let month = month_from(target.rem_euclid(12) + 1);
    let day = anchor.day().min(days_in_month(year, month));
    Date::from_calendar_date(year, month, day)
        .expect("the clamped day is valid for its month")
        .with_hms(anchor.hour(), anchor.minute(), anchor.second())
        .expect("the anchor's time-of-day is valid")
        .assume_utc()
}

/// `1..=12` into a [`Month`]; the caller guarantees the range.
fn month_from(one_based: i64) -> Month {
    let number = u8::try_from(one_based).expect("1..=12 fits u8");
    Month::try_from(number).expect("1..=12 is a month")
}

/// The number of days in `month` of `year`, Gregorian — the clamping rule
/// needs the February 29 case.
fn days_in_month(year: i32, month: Month) -> u8 {
    match month {
        Month::February if is_leap_year(year) => 29,
        Month::February => 28,
        Month::April | Month::June | Month::September | Month::November => 30,
        _ => 31,
    }
}

/// The proleptic Gregorian leap rule.
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// The RFC 3339 UTC spelling the table stores: seconds resolution, any offset
/// normalized, so lexicographic order is chronological and a `period_start`
/// written in any offset compares against one computed here.
pub(crate) fn rfc3339(at: OffsetDateTime) -> String {
    use time::format_description::well_known::Rfc3339;
    let at = at.to_offset(UtcOffset::UTC);
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Clamps a counter to the range both engines hold. `used` is `BIGINT`;
/// Postgres **rejects** a `u64` above `i64::MAX` while SQLite clamps silently,
/// so an amount saturates here, where both agree.
fn counter(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The pause from `now` to `period_end`, floored at zero. What a 429 reports
/// as `Retry-After`.
fn retry_after(period_end: OffsetDateTime, now: OffsetDateTime) -> StdDuration {
    let millis = (period_end - now).whole_milliseconds().max(0);
    StdDuration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
}

/// A successful [`consume`](Usage::consume): the amount was counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Consumed {
    /// The total spent in this period after the increment (including it).
    pub used: u64,
    /// The allowance applied, or `None` for an unbounded meter.
    pub limit: Option<u64>,
    /// When the period ends and the allowance resets.
    pub period_end: OffsetDateTime,
}

/// A refused [`consume`](Usage::consume): the allowance could not carry the
/// amount, so nothing was counted and no work may proceed. An amount larger
/// than the whole allowance is refused as exhausted from the start — on an
/// empty meter, `used` is `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exhausted {
    /// The total already spent in this period.
    pub used: u64,
    /// The allowance that is spent.
    pub limit: u64,
    /// When the period ends and the allowance resets.
    pub period_end: OffsetDateTime,
    /// The pause from the instant of the call to `period_end`, what
    /// [`crate::allowance_exhausted`] reports as `Retry-After`.
    pub retry_after: StdDuration,
}

impl Exhausted {
    /// The refusal for a caller that found the allowance spent by **reading
    /// the meter back** — the batch shape's route to the 429, since
    /// [`consume_statement`](Usage::consume_statement) fails rather than
    /// affecting zero rows. `now` is the instant of the call.
    #[must_use]
    pub fn spent(used: u64, limit: u64, period: Period, now: OffsetDateTime) -> Self {
        let end = period.window_at(now).end;
        Self {
            used,
            limit,
            period_end: end,
            retry_after: retry_after(end, now),
        }
    }
}

/// The outcome of one [`consume`](Usage::consume): matched on directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consumption {
    Consumed(Consumed),
    Exhausted(Exhausted),
}

/// A usage-meter table over the `Database` port: durable per
/// `(subject, meter, period)` counters. Construct it with the table the module
/// declares (e.g. `"<module>_usage"`) and ship
/// [`create_table_sql`](Self::create_table_sql) as its migration. `subject` is
/// who the allowance belongs to; `meter` is which resource is counted, so one
/// table holds every meter.
#[derive(Debug, Clone)]
pub struct Usage {
    table: String,
}

impl Usage {
    #[must_use]
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
        }
    }

    /// The portable DDL for the usage table. `used` is `BIGINT`, a signed
    /// 64-bit counter on both SQLite and Postgres (ADR 0004).
    #[must_use]
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             subject TEXT NOT NULL,\n    \
             meter TEXT NOT NULL,\n    \
             period_start TEXT NOT NULL,\n    \
             used BIGINT NOT NULL,\n    \
             PRIMARY KEY (subject, meter, period_start)\n);",
            table = self.table
        )
    }

    /// The guarded upsert as a [`Statement`] for the module's **own**
    /// `db.batch_atomic(..)`, beside the work it pays for. With a `limit` it
    /// **fails** (a `NOT NULL` violation on `used`) when the allowance cannot
    /// carry `amount`, so the batch rolls back; read the meter back for the
    /// 429 ([`read`](Usage::read)). With `limit` `None`, counting only.
    #[must_use]
    pub fn consume_statement(
        &self,
        subject: &str,
        meter: &str,
        period: Period,
        now: OffsetDateTime,
        amount: u64,
        limit: Option<u64>,
    ) -> Statement {
        let start = rfc3339(period.window_at(now).start);
        match limit {
            Some(limit) => Statement::with_values(
                guard_sql(&self.table),
                vec![
                    subject.to_owned().into(),
                    meter.to_owned().into(),
                    start.into(),
                    counter(amount).into(),
                    counter(limit).into(),
                    counter(amount).into(),
                    counter(limit).into(),
                ],
            ),
            None => Statement::with_values(
                plain_sql(&self.table),
                vec![
                    subject.to_owned().into(),
                    meter.to_owned().into(),
                    start.into(),
                    counter(amount).into(),
                ],
            ),
        }
    }

    /// Spends `amount` against the allowance for `(subject, meter)` in the
    /// period containing `now`, atomically. Admission and the increment are
    /// one statement, so concurrent callers cannot overspend: the row lock
    /// serialises them and the guard is re-evaluated against the committed
    /// row. On admission the caller does the work; on refusal it must not.
    /// An `amount` above `limit` is refused as exhausted even on an empty
    /// meter (`used` `0`).
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the write or the read-back fails.
    // One over the limit: the shape mirrors [`consume_statement`](Self::consume_statement)
    // with the `db` handle added, so the two read alike at the call site.
    #[allow(clippy::too_many_arguments)]
    pub async fn consume(
        &self,
        db: &dyn Database,
        subject: &str,
        meter: &str,
        period: Period,
        now: OffsetDateTime,
        amount: u64,
        limit: Option<u64>,
    ) -> Result<Consumption, DbError> {
        let window = period.window_at(now);
        let start = rfc3339(window.start);
        // `INSERT ... SELECT ... WHERE amount <= limit`, the conflict update
        // guarded too: one row changes on admission, none when spent. With no
        // limit, the plain upsert counts without bounding.
        let (sql, values) = match limit {
            Some(limit) => (
                guarded_sql(&self.table),
                vec![
                    subject.to_owned().into(),
                    meter.to_owned().into(),
                    start.into(),
                    counter(amount).into(),
                    counter(amount).into(),
                    counter(limit).into(),
                    counter(limit).into(),
                ],
            ),
            None => (
                plain_sql(&self.table),
                vec![
                    subject.to_owned().into(),
                    meter.to_owned().into(),
                    start.into(),
                    counter(amount).into(),
                ],
            ),
        };
        let affected = db.execute(&Statement::with_values(sql, values)).await?;
        let used = self.read(db, subject, meter, period, now).await?;
        Ok(match limit {
            Some(limit) if affected == 0 => Consumption::Exhausted(Exhausted {
                used,
                limit,
                period_end: window.end,
                retry_after: retry_after(window.end, now),
            }),
            _ => Consumption::Consumed(Consumed {
                used,
                limit,
                period_end: window.end,
            }),
        })
    }

    /// Returns `amount` to the allowance, never below zero. A single guarded
    /// `UPDATE`, so it cannot race an increment into a lost update.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the update fails.
    pub async fn refund(
        &self,
        db: &dyn Database,
        subject: &str,
        meter: &str,
        period: Period,
        now: OffsetDateTime,
        amount: u64,
    ) -> Result<(), DbError> {
        let start = rfc3339(period.window_at(now).start);
        // `CASE`, not `MAX`/`GREATEST`: the engines disagree on the spelling,
        // and the scalar `max(a, b)` is SQLite-only.
        let stmt = Statement::with_values(
            format!(
                "UPDATE {table} SET used = CASE WHEN used > ? THEN used - ? ELSE 0 END\n\
                 WHERE subject = ? AND meter = ? AND period_start = ?",
                table = self.table
            ),
            vec![
                counter(amount).into(),
                counter(amount).into(),
                subject.to_owned().into(),
                meter.to_owned().into(),
                start.into(),
            ],
        );
        db.execute(&stmt).await?;
        Ok(())
    }

    /// How much `(subject, meter)` has spent in the period containing `now`;
    /// `0` when no row exists.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the read fails.
    pub async fn read(
        &self,
        db: &dyn Database,
        subject: &str,
        meter: &str,
        period: Period,
        now: OffsetDateTime,
    ) -> Result<u64, DbError> {
        let start = rfc3339(period.window_at(now).start);
        let rows = db
            .query(&Statement::with_values(
                format!(
                    "SELECT used FROM {table} WHERE subject = ? AND meter = ? AND period_start = ?",
                    table = self.table
                ),
                vec![
                    subject.to_owned().into(),
                    meter.to_owned().into(),
                    start.into(),
                ],
            ))
            .await?;
        Ok(rows
            .first()
            .and_then(|row| row.get::<u64>("used"))
            .unwrap_or(0))
    }

    /// The last `last_n_periods` windows and their spend, **most recent
    /// first** (the period containing `now` first), with periods that have no
    /// row reported as `0`. One `SELECT` over the span, zero-filled in Rust.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the read fails.
    pub async fn history(
        &self,
        db: &dyn Database,
        subject: &str,
        meter: &str,
        period: Period,
        now: OffsetDateTime,
        last_n_periods: u32,
    ) -> Result<Vec<(PeriodWindow, u64)>, DbError> {
        let n = i64::from(last_n_periods);
        if n == 0 {
            return Ok(Vec::new());
        }
        let current = period.index_at(now);
        let oldest = period.window_for(current - n + 1).start;
        let newest_end = period.window_for(current).end;
        let rows = db
            .query(&Statement::with_values(
                format!(
                    "SELECT period_start, used FROM {table} \
                     WHERE subject = ? AND meter = ? AND period_start >= ? AND period_start < ?",
                    table = self.table
                ),
                vec![
                    subject.to_owned().into(),
                    meter.to_owned().into(),
                    rfc3339(oldest).into(),
                    rfc3339(newest_end).into(),
                ],
            ))
            .await?;
        let mut spent: HashMap<String, u64> = HashMap::new();
        for row in &rows.rows {
            if let (Some(start), Some(used)) =
                (row.get::<String>("period_start"), row.get::<u64>("used"))
            {
                spent.insert(start, used);
            }
        }
        Ok((0..n)
            .map(|back| {
                let window = period.window_for(current - back);
                let used = spent.get(&rfc3339(window.start)).copied().unwrap_or(0);
                (window, used)
            })
            .collect())
    }

    /// Deletes every counter older than the `keep_periods` most recent
    /// windows, the one containing `now` included — the retention half of the
    /// meter. `keep_periods` of `0` deletes every row. Returns the rows
    /// removed.
    ///
    /// Core schedules nothing: the owning module calls this from its
    /// [`Module::scheduled`](crate::Module::scheduled) tick, the way
    /// `module-waitlist` calls [`SendCooldown::prune`](crate::SendCooldown::prune).
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] if the delete fails.
    pub async fn purge(
        &self,
        db: &dyn Database,
        period: Period,
        now: OffsetDateTime,
        keep_periods: u32,
    ) -> Result<u64, DbError> {
        let oldest_kept = period.index_at(now) - i64::from(keep_periods) + 1;
        let cutoff = rfc3339(period.window_for(oldest_kept).start);
        db.execute(&Statement::with_values(
            format!(
                "DELETE FROM {table} WHERE period_start < ?",
                table = self.table
            ),
            vec![cutoff.into()],
        ))
        .await
    }
}

/// The batch upsert when a limit applies: both the value and the conflict
/// update resolve to `NULL` when the allowance cannot carry `amount`, and the
/// `NOT NULL` on `used` aborts the statement — and the batch with it.
fn guard_sql(table: &str) -> String {
    format!(
        "INSERT INTO {table} (subject, meter, period_start, used)\n\
         VALUES (?, ?, ?, CASE WHEN ? <= ? THEN ? ELSE NULL END)\n\
         ON CONFLICT (subject, meter, period_start) DO UPDATE\n\
         SET used = CASE WHEN {table}.used + excluded.used <= ? \
         THEN {table}.used + excluded.used ELSE NULL END"
    )
}

/// The batch upsert with no limit: counted, unbounded.
fn plain_sql(table: &str) -> String {
    format!(
        "INSERT INTO {table} (subject, meter, period_start, used)\n\
         VALUES (?, ?, ?, ?)\n\
         ON CONFLICT (subject, meter, period_start) DO UPDATE\n\
         SET used = {table}.used + excluded.used"
    )
}

/// The single-call guarded upsert: `INSERT ... SELECT ... WHERE amount <=
/// limit` with the conflict update guarded too, so it affects exactly one row
/// on admission and zero when spent. The `SELECT`'s `WHERE` is also what lets
/// SQLite parse the upsert at all.
fn guarded_sql(table: &str) -> String {
    format!(
        "INSERT INTO {table} (subject, meter, period_start, used)\n\
         SELECT ?, ?, ?, ? WHERE ? <= ?\n\
         ON CONFLICT (subject, meter, period_start) DO UPDATE\n\
         SET used = {table}.used + excluded.used\n\
         WHERE {table}.used + excluded.used <= ?"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint_portable_sql;
    use time::format_description::well_known::Rfc3339;

    /// An instant spelled the way the tests read best; `Z` is UTC, and any
    /// other offset is a real input the window must normalize.
    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).expect("test instant parses")
    }

    fn window(start: &str, end: &str) -> PeriodWindow {
        PeriodWindow {
            start: at(start),
            end: at(end),
        }
    }

    #[test]
    fn create_table_sql_is_portable_ddl() {
        let sql = Usage::new("waitlist_usage").create_table_sql();
        assert!(sql.contains("used BIGINT NOT NULL"));
        assert_eq!(lint_portable_sql(&sql), vec![], "DDL must be portable");
    }

    #[test]
    fn the_statement_shapes_bind_seven_or_four_values() {
        let usage = Usage::new("waitlist_usage");
        let period = Period::CalendarMonthUtc;
        let now = at("2026-01-15T00:00:00Z");

        let guarded = usage.consume_statement("a", "mail", period, now, 1, Some(100));
        assert!(guarded.sql.contains("ELSE NULL END"));
        assert!(guarded.sql.contains("excluded.used"));
        // subject, meter, period_start, amount, limit, amount, limit
        assert_eq!(guarded.values.0.len(), 7);

        let unbounded = usage.consume_statement("a", "mail", period, now, 1, None);
        assert_eq!(unbounded.values.0.len(), 4);

        // A u64 above i64::MAX saturates rather than failing the Postgres bind.
        let huge = usage.consume_statement("a", "mail", period, now, u64::MAX, Some(u64::MAX));
        assert!(
            matches!(huge.values.0[3], sea_query::Value::BigInt(Some(v)) if v == i64::MAX),
            "amount must saturate to i64::MAX"
        );
    }

    #[test]
    fn calendar_and_day_windows_are_utc() {
        // December rolls into the next year.
        assert_eq!(
            Period::CalendarMonthUtc.window_at(at("2026-12-15T00:00:00Z")),
            window("2026-12-01T00:00:00Z", "2027-01-01T00:00:00Z")
        );
        // The day window is the UTC day, one second before midnight included.
        assert_eq!(
            Period::Day.window_at(at("2026-03-01T23:59:59Z")),
            window("2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z")
        );
        // A non-UTC offset names the same window as its UTC spelling: 00:30
        // on Mar 1 in +05:30 is 19:00 on Feb 28 UTC.
        let local = at("2026-03-01T00:30:00+05:30");
        assert_eq!(
            Period::Day.window_at(local),
            window("2026-02-28T00:00:00Z", "2026-03-01T00:00:00Z")
        );
        assert_eq!(
            Period::Day.window_at(local),
            Period::Day.window_at(local.to_offset(UtcOffset::UTC))
        );
    }

    #[test]
    fn anchored_periods_clamp_the_day_to_the_target_month() {
        // (anchor, every, now, expected window). The day is clamped to the
        // target month and recomputed from the anchor each period, never
        // chained — so a 31st anchor restores the 31st after February.
        let cases = [
            // 31st: February clamps to 28, then March restores the 31st.
            (
                "2026-01-31T09:30:00Z",
                1,
                "2026-02-28T10:00:00Z",
                "2026-02-28T09:30:00Z",
                "2026-03-31T09:30:00Z",
            ),
            // April clamps to the 30th.
            (
                "2026-01-31T09:30:00Z",
                1,
                "2026-04-05T00:00:00Z",
                "2026-03-31T09:30:00Z",
                "2026-04-30T09:30:00Z",
            ),
            // 30th: only February clamps.
            (
                "2026-01-30T09:00:00Z",
                1,
                "2026-02-10T00:00:00Z",
                "2026-01-30T09:00:00Z",
                "2026-02-28T09:00:00Z",
            ),
            (
                "2026-01-30T09:00:00Z",
                1,
                "2026-03-10T00:00:00Z",
                "2026-02-28T09:00:00Z",
                "2026-03-30T09:00:00Z",
            ),
            // 29th: February holds it in a leap year, clamps otherwise and
            // restores the 29th in March.
            (
                "2024-01-29T00:00:00Z",
                1,
                "2024-02-05T00:00:00Z",
                "2024-01-29T00:00:00Z",
                "2024-02-29T00:00:00Z",
            ),
            (
                "2025-01-29T00:00:00Z",
                1,
                "2025-02-28T00:00:00Z",
                "2025-02-28T00:00:00Z",
                "2025-03-29T00:00:00Z",
            ),
            // Every 3 months, still measured from the anchor.
            (
                "2026-01-31T00:00:00Z",
                3,
                "2026-02-15T00:00:00Z",
                "2026-01-31T00:00:00Z",
                "2026-04-30T00:00:00Z",
            ),
            (
                "2026-01-31T00:00:00Z",
                3,
                "2026-05-01T00:00:00Z",
                "2026-04-30T00:00:00Z",
                "2026-07-31T00:00:00Z",
            ),
        ];
        for (anchor, every, now, start, end) in cases {
            let period = Period::Anchored {
                anchor: at(anchor),
                every: Months(every),
            };
            assert_eq!(
                period.window_at(at(now)),
                window(start, end),
                "anchor {anchor}, every {every}, now {now}"
            );
        }

        // Before the anchor: floor division gives a negative index.
        let period = Period::Anchored {
            anchor: at("2026-03-15T08:00:00Z"),
            every: Months(1),
        };
        assert_eq!(
            period.window_at(at("2026-01-01T00:00:00Z")),
            window("2025-12-15T08:00:00Z", "2026-01-15T08:00:00Z")
        );
        assert_eq!(period.index_at(at("2026-01-01T00:00:00Z")), -3);
    }

    #[test]
    fn index_and_window_are_inverses() {
        for period in [
            Period::CalendarMonthUtc,
            Period::Day,
            Period::Anchored {
                anchor: at("2026-01-31T09:30:00Z"),
                every: Months(1),
            },
        ] {
            let now = at("2026-08-31T09:30:00Z");
            let index = period.index_at(now);
            assert_eq!(period.window_for(index), period.window_at(now));
            assert_eq!(
                period.window_for(index - 1).end,
                period.window_for(index).start,
                "consecutive windows abut"
            );
        }
    }
}
