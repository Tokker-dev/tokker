//! The cooperative budget a scheduled invocation runs under (issue #537).
//!
//! A Worker's scheduled event has a fixed CPU and subrequest allowance, and
//! `serve_scheduled` fans one event out to every module serially — so one
//! module polling many third-party accounts per tick can spend the whole
//! invocation before the last module runs. Two primitives close that gap:
//!
//! - [`ScheduledBudget`] — what one module may spend in one invocation. It
//!   is **cooperative**: the runtime never cancels a module's work, it hands
//!   the module (via `ModuleContext::scheduled`) and the [`Outbox`](crate::Outbox)
//!   drain a budget to check before each unit of work.
//! - [`ScheduledSplit`] — how a runtime divides one invocation's
//!   [`ScheduledLimits`] across the modules in order, with each module's
//!   unspent share rolling forward to the modules after it.
//!
//! The native runtime has no Workers allowance, so it hands every module an
//! unbounded budget: `ctx.scheduled` exists on every runtime and simply
//! never runs out off Workers.

use std::sync::atomic::{AtomicU32, Ordering};

use time::{Duration, OffsetDateTime};

/// What one module may spend in one scheduled invocation.
///
/// Cooperative by design: nothing here cancels or aborts work. A module
/// checks [`try_spend`](ScheduledBudget::try_spend) before each unit of
/// work (one subrequest-shaped step) and stops when it answers `false`; a
/// runtime hands a fresh budget to every module through
/// `ModuleContext::scheduled`. Outside a scheduled invocation the budget is
/// unbounded, so a module that checks it unconditionally pays nothing.
#[derive(Debug)]
pub struct ScheduledBudget {
    /// Wall-clock end of this module's share, if the invocation bounds time.
    deadline: Option<OffsetDateTime>,
    /// Subrequest-shaped steps this budget may spend in total, if bounded.
    subrequests: Option<u32>,
    /// Steps already spent (see [`try_spend`](ScheduledBudget::try_spend)).
    spent: AtomicU32,
}

impl ScheduledBudget {
    /// A budget that never runs out: no deadline, no subrequest cap. This is
    /// what a module sees outside `Module::scheduled` and on runtimes with
    /// no invocation limits.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            deadline: None,
            subrequests: None,
            spent: AtomicU32::new(0),
        }
    }

    /// A budget ending at `deadline` (if bounded) after `subrequests`
    /// steps (if bounded). Either bound may be absent.
    #[must_use]
    pub const fn new(deadline: Option<OffsetDateTime>, subrequests: Option<u32>) -> Self {
        Self {
            deadline,
            subrequests,
            spent: AtomicU32::new(0),
        }
    }

    /// The wall-clock end of this budget, if the invocation bounds time.
    #[must_use]
    pub fn deadline(&self) -> Option<OffsetDateTime> {
        self.deadline
    }

    /// Steps this budget still has, or `None` when unbounded.
    #[must_use]
    pub fn remaining_subrequests(&self) -> Option<u32> {
        self.subrequests.map(|cap| cap.saturating_sub(self.spent()))
    }

    /// Steps spent so far. Never decreases.
    #[must_use]
    pub fn spent(&self) -> u32 {
        self.spent.load(Ordering::Relaxed)
    }

    /// Spends `n` steps and answers `true`, or spends nothing and answers
    /// `false` when fewer than `n` remain. The one call a module needs
    /// around each unit of work:
    ///
    /// ```ignore
    /// while let Some(account) = next_account() {
    ///     if !ctx.scheduled.try_spend(1) { break; }
    ///     poll(account).await;
    /// }
    /// ```
    pub fn try_spend(&self, n: u32) -> bool {
        let Some(cap) = self.subrequests else {
            self.spent.fetch_add(n, Ordering::Relaxed);
            return true;
        };
        let mut seen = self.spent.load(Ordering::Relaxed);
        loop {
            let Some(next) = seen.checked_add(n) else {
                return false;
            };
            if next > cap {
                return false;
            }
            match self
                .spent
                .compare_exchange_weak(seen, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                // The budget is module-private and single-tasked, so a
                // lost race cannot happen today; the loop keeps `try_spend`
                // honest anyway if that ever changes.
                Ok(_) => return true,
                Err(now_seen) => seen = now_seen,
            }
        }
    }

    /// `true` once `now` has passed this budget's deadline. Unbounded is
    /// never expired.
    #[must_use]
    pub fn expired(&self, now: OffsetDateTime) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// `true` when the budget has nothing left: past the deadline, or zero
    /// subrequests remaining. The check the runtime and
    /// [`Outbox`](crate::Outbox) drains make before each unit of work.
    #[must_use]
    pub fn exhausted(&self, now: OffsetDateTime) -> bool {
        self.expired(now) || self.remaining_subrequests() == Some(0)
    }
}

impl Default for ScheduledBudget {
    fn default() -> Self {
        Self::unbounded()
    }
}

/// The limits one scheduled invocation may spend in total: how long it may
/// run, and how many subrequest-shaped steps it may make. `None` is
/// unbounded, which is the only value the native runtime needs —
/// [`UNBOUNDED`](ScheduledLimits::UNBOUNDED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledLimits {
    /// Wall-clock length of the whole invocation.
    pub wall: Option<Duration>,
    /// Subrequest-shaped steps the whole invocation may make.
    pub subrequests: Option<u32>,
}

impl ScheduledLimits {
    /// No limits at all: what the native cron fan-out runs with.
    pub const UNBOUNDED: Self = Self {
        wall: None,
        subrequests: None,
    };
}

/// Divides one invocation's [`ScheduledLimits`] across its modules, in
/// order, with every module's unspent share rolling forward to the ones
/// after it.
///
/// The split is even *by construction, not by outcome*: module `n` of `m`
/// gets the wall time that is left divided by the modules still to run, and
/// the subrequests still left divided the same way (rounded up). The
/// invariant is on **spend**, not on the shares: shares overlap, because an
/// unspent share rolls forward and is granted again to the modules after
/// it, but every subrequest a module actually spends is subtracted from the
/// pool at [`settle`](ScheduledSplit::settle) — so cumulative spend never
/// passes the limit. A module that spends nothing simply leaves its share
/// in the pool for the next module.
#[derive(Debug)]
pub struct ScheduledSplit {
    /// When the whole invocation must end, if bounded.
    end: Option<OffsetDateTime>,
    /// Subrequests still unclaimed by any module, if bounded.
    subrequests_left: Option<u32>,
    /// Modules still waiting for a budget.
    modules_left: usize,
}

impl ScheduledSplit {
    /// A split of `limits` across `modules` modules, starting at `now`.
    /// `now` is read only when `limits` bounds wall time.
    #[must_use]
    pub fn new(limits: ScheduledLimits, now: OffsetDateTime, modules: usize) -> Self {
        Self {
            end: limits.wall.map(|wall| now.saturating_add(wall)),
            subrequests_left: limits.subrequests,
            modules_left: modules,
        }
    }

    /// The budget for the next module: the time left divided by the modules
    /// still to run, and the subrequests left divided the same way (rounded
    /// up, so a share never names more steps than the pool holds, and the
    /// last module is left with at least what remains). Called once per
    /// module, in order.
    #[must_use]
    pub fn next(&mut self, now: OffsetDateTime) -> ScheduledBudget {
        if self.modules_left == 0 {
            // More `next` calls than modules: a caller bug, answered with a
            // budget that is already out rather than a silently unbounded one.
            return ScheduledBudget::new(Some(now), Some(0));
        }
        let deadline = self.end.map(|end| {
            let remaining = (end - now).max(Duration::ZERO);
            let share = i32::try_from(self.modules_left).unwrap_or(i32::MAX);
            now.saturating_add(remaining / share)
        });
        let subrequests = self.subrequests_left.map(|left| {
            let modules = u32::try_from(self.modules_left).unwrap_or(u32::MAX);
            left.div_ceil(modules)
        });
        ScheduledBudget::new(deadline, subrequests)
    }

    /// Accounts for the module that just ran: its unspent subrequests roll
    /// back into the pool for the modules still to come, and one fewer
    /// module is waiting. Unspent wall time needs no accounting — the next
    /// [`next`](ScheduledSplit::next) recomputes it from the clock.
    pub fn settle(&mut self, budget: &ScheduledBudget) {
        self.modules_left = self.modules_left.saturating_sub(1);
        if let Some(left) = self.subrequests_left {
            self.subrequests_left = Some(left.saturating_sub(budget.spent()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(epoch_secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(epoch_secs).expect("in range")
    }

    #[test]
    fn try_spend_spends_only_what_fits() {
        let budget = ScheduledBudget::new(None, Some(3));
        assert!(budget.try_spend(2));
        assert_eq!(budget.spent(), 2);
        assert!(!budget.try_spend(2), "a spend past the cap spends nothing");
        assert_eq!(budget.spent(), 2, "a refused spend leaves no trace");
        assert!(budget.try_spend(1));
        assert_eq!(budget.remaining_subrequests(), Some(0));
        assert!(!budget.try_spend(1), "an empty budget refuses");
    }

    #[test]
    fn an_unbounded_budget_never_refuses_or_exhausts() {
        let budget = ScheduledBudget::unbounded();
        assert!(budget.try_spend(10_000));
        assert_eq!(budget.remaining_subrequests(), None);
        assert!(!budget.expired(at(1_000_000_000)));
        assert!(!budget.exhausted(at(1_000_000_000)));
    }

    #[test]
    fn expiry_is_the_deadline_and_exhaustion_is_either_bound() {
        let timed = ScheduledBudget::new(Some(at(100)), Some(10));
        assert!(!timed.expired(at(99)));
        assert!(timed.expired(at(100)), "the deadline itself is past it");
        assert!(!timed.exhausted(at(99)));
        assert!(timed.exhausted(at(100)));

        let counted = ScheduledBudget::new(None, Some(1));
        assert!(!counted.exhausted(at(0)));
        assert!(counted.try_spend(1));
        assert!(
            counted.exhausted(at(0)),
            "zero subrequests left is exhausted without a deadline"
        );
    }

    #[test]
    fn an_unspent_share_rolls_forward_to_the_later_modules() {
        let start = at(0);
        let mut split = ScheduledSplit::new(
            ScheduledLimits {
                wall: None,
                subrequests: Some(7),
            },
            start,
            3,
        );
        let first = split.next(start);
        assert_eq!(
            first.remaining_subrequests(),
            Some(3),
            "a third, rounded up"
        );
        split.settle(&first); // spent nothing
        let second = split.next(start);
        assert_eq!(
            second.remaining_subrequests(),
            Some(4),
            "the share that rolled forward, over two modules"
        );
        split.settle(&second); // spent nothing either
        let third = split.next(start);
        assert_eq!(
            third.remaining_subrequests(),
            Some(7),
            "the last module gets everything left"
        );
    }

    #[test]
    fn settled_spending_shrinks_the_later_shares() {
        let start = at(0);
        let mut split = ScheduledSplit::new(
            ScheduledLimits {
                wall: None,
                subrequests: Some(4),
            },
            start,
            2,
        );
        let first = split.next(start);
        assert_eq!(first.remaining_subrequests(), Some(2));
        assert!(
            !first.try_spend(3),
            "a module cannot spend past its own share"
        );
        assert!(first.try_spend(2));
        split.settle(&first);
        let second = split.next(start);
        assert_eq!(
            second.remaining_subrequests(),
            Some(2),
            "what the first module left"
        );
    }

    #[test]
    fn the_wall_split_never_schedules_past_the_end() {
        let start = at(0);
        let mut split = ScheduledSplit::new(
            ScheduledLimits {
                wall: Some(Duration::seconds(30)),
                subrequests: None,
            },
            start,
            3,
        );
        let first = split.next(start);
        assert_eq!(first.deadline(), Some(at(10)));
        split.settle(&first);
        // Module 1 actually ran for 9s: module 2 gets half of the 21s left —
        // 10.5s, exact — computed from the clock, not an even third of the
        // original wall.
        let second = split.next(at(9));
        assert_eq!(
            second.deadline(),
            Some(start + Duration::milliseconds(19_500))
        );
        split.settle(&second);
        let third = split.next(at(19));
        assert_eq!(
            third.deadline(),
            Some(at(30)),
            "the last module runs to the end"
        );
    }

    #[test]
    fn unbounded_limits_give_unbounded_budgets() {
        let start = at(0);
        let mut split = ScheduledSplit::new(ScheduledLimits::UNBOUNDED, start, 2);
        let budget = split.next(start);
        assert_eq!(budget.deadline(), None);
        assert_eq!(budget.remaining_subrequests(), None);
        assert!(!budget.exhausted(at(1_000_000)));
        split.settle(&budget);
    }
}
