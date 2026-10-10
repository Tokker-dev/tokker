//! What a classifier call costs (issue #457): who answered
//! ([`AdapterId`]), under which question ids ([`QuestionKind`]), how many
//! tokens it spent ([`Tokens`]), what those tokens cost ([`PriceSheet`],
//! [`Cost`]), and the ledger that totals it ([`CostLedger`]).
//!
//! **Tokens are estimated.** The [`Classifier`](crate::Classifier) port
//! reports no usage — an [`Answer`] carries a value and probabilities, not
//! a bill — so every [`CallRecord`] carries [`Tokens`] tagged
//! [`TokenSource::Estimated`]: about four chars per token over what was
//! sent and what came back (see [`Tokens::estimate`]). The estimate is
//! good enough to compare two adapters asked the same questions, and it
//! is not an invoice.
//!
//! **Money is an integer.** [`Price`] is pico-USD (10^-12 USD) per token,
//! so a vendor's `$X.YZ per million tokens` written in micro-USD is the
//! same integer ([`Price::per_million_tokens`]). [`Cost`] saturates rather
//! than wraps, and [`LedgerTotals::pico_usd`] is a `u128` so a lifetime
//! total cannot saturate where one call would not.
//!
//! **An adapter with no price is unknown, not free.**
//! [`PriceSheet::cost_of`] answers `None` for it, and totals count those
//! calls in [`LedgerTotals::unpriced_calls`] instead of summing a zero:
//! a cheap-vs-expensive argument built on a silent zero is the mistake
//! this module exists to prevent.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::ports::{Answer, AnswerValue, ClassifierProfile, Question};

/// Pico-USD in one USD.
const PICO_PER_USD: u64 = 1_000_000_000_000;

/// Chars per token the estimate assumes — the same rule of thumb
/// [`DEFAULT_MAX_STATE_CHARS`](crate::DEFAULT_MAX_STATE_CHARS) is sized by.
const CHARS_PER_TOKEN: usize = 4;

/// The name a venture wires a classifier adapter under — the key prices,
/// thresholds and agreement evidence are kept by. The port does not name
/// its adapters, so the wiring does.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AdapterId(String);

impl AdapterId {
    /// An id from its name.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AdapterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The id a question is asked under — the key of the map
/// [`Classifier::ask`](crate::Classifier::ask) takes. A venture asks the
/// same kind of question under the same id, so agreement is measured and
/// routing is decided per id: a classifier reliable on one kind is not
/// therefore reliable on the next.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct QuestionKind(String);

impl QuestionKind {
    /// A kind from the question id.
    #[must_use]
    pub fn new(kind: impl Into<String>) -> Self {
        Self(kind.into())
    }

    /// The kind as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for QuestionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a token count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenSource {
    /// Counted from the text by [`Tokens::estimate`], because the port
    /// reports no usage. The only source today; a provider-reported count
    /// would be a second variant.
    Estimated,
}

/// The tokens one call spent, and where the count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tokens {
    pub input: u64,
    pub output: u64,
    pub source: TokenSource,
}

impl Tokens {
    /// Estimates one call at `ceil(chars / 4)` per side.
    ///
    /// Input is the `state` **as the adapter sends it** — truncated by
    /// `profile` the way the adapter truncates it, so an over-long state
    /// is not billed for text that never left — plus every question's id,
    /// instructions and criteria or levels (names and meanings). Output is
    /// the answers rendered as id, value and every probability label with
    /// its number to two places; `None` (a failed call) is zero output.
    ///
    /// An estimate, tagged [`TokenSource::Estimated`]: each adapter wraps
    /// the text in its own prompt and tokenizes it its own way. It compares
    /// adapters asked the same questions fairly, and it is not what the
    /// vendor will invoice.
    #[must_use]
    pub fn estimate(
        profile: &ClassifierProfile,
        state: &str,
        questions: &BTreeMap<String, Question>,
        answers: Option<&BTreeMap<String, Answer>>,
    ) -> Self {
        let (sent, _) = profile.truncate(state);
        let mut input = sent.chars().count();
        for (id, question) in questions {
            input += id.chars().count() + question.instructions().chars().count();
            let options: Vec<(&String, &String)> = match question {
                Question::Choice { criteria, .. } => criteria.iter().collect(),
                Question::Score { levels, .. } => levels.iter().map(|(n, m)| (n, m)).collect(),
                Question::Noul { .. } => Vec::new(),
            };
            for (name, meaning) in options {
                input += name.chars().count() + meaning.chars().count();
            }
        }
        let output = answers.map_or(0, |answers| {
            answers
                .iter()
                .map(|(id, answer)| {
                    let probabilities: usize = answer
                        .probabilities
                        .iter()
                        .map(|(label, p)| label.chars().count() + format!("{p:.2}").len())
                        .sum();
                    id.chars().count() + value_text(&answer.value).chars().count() + probabilities
                })
                .sum()
        });
        Self {
            input: tokens_for(input),
            output: tokens_for(output),
            source: TokenSource::Estimated,
        }
    }
}

/// `ceil(chars / 4)`, saturating into a `u64`.
fn tokens_for(chars: usize) -> u64 {
    u64::try_from(chars.div_ceil(CHARS_PER_TOKEN)).unwrap_or(u64::MAX)
}

/// An answer's value as text: the label, the score, or `true`/`false`.
pub(crate) fn value_text(value: &AnswerValue) -> String {
    match value {
        AnswerValue::Choice(label) => label.clone(),
        AnswerValue::Score(score) => score.to_string(),
        AnswerValue::Noul(verdict) => verdict.to_string(),
    }
}

/// What one token costs on one adapter, in pico-USD, per side. Pricing is
/// config, pasted off the vendor's page through
/// [`Price::per_million_tokens`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Price {
    pub input_pico_usd_per_token: u64,
    pub output_pico_usd_per_token: u64,
}

impl Price {
    /// A **known** zero, such as a self-hosted model — not the same thing
    /// as an adapter missing from the sheet.
    pub const FREE: Price = Price::per_million_tokens(0, 0);

    /// A vendor's published prices: `$3.00 per million input tokens` is
    /// `per_million_tokens(3_000_000, ..)`, because micro-USD per million
    /// tokens is numerically pico-USD per token.
    #[must_use]
    pub const fn per_million_tokens(input_micro_usd: u64, output_micro_usd: u64) -> Price {
        Price {
            input_pico_usd_per_token: input_micro_usd,
            output_pico_usd_per_token: output_micro_usd,
        }
    }

    /// The cost of `tokens`, saturating rather than wrapping.
    #[must_use]
    pub const fn cost(&self, tokens: &Tokens) -> Cost {
        Cost(
            tokens
                .input
                .saturating_mul(self.input_pico_usd_per_token)
                .saturating_add(tokens.output.saturating_mul(self.output_pico_usd_per_token)),
        )
    }
}

/// The pico-USD cost of one call: a `u64`, saturating near $18.4 million,
/// which no single classification spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Cost(u64);

impl Cost {
    /// What a known-free adapter spends.
    pub const ZERO: Cost = Cost(0);

    /// Wraps a raw pico-USD amount.
    #[must_use]
    pub const fn from_pico_usd(pico_usd: u64) -> Cost {
        Cost(pico_usd)
    }

    /// The raw amount in pico-USD.
    #[must_use]
    pub const fn pico_usd(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Cost {
    /// All twelve decimals: fewer would round a small call to `$0.00`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "${}.{:012}",
            self.0 / PICO_PER_USD,
            self.0 % PICO_PER_USD
        )
    }
}

/// What each adapter costs, wired once where the adapters are wired.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PriceSheet(BTreeMap<AdapterId, Price>);

impl PriceSheet {
    /// An empty sheet: every adapter unpriced.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prices `adapter`, replacing any price it had.
    #[must_use]
    pub fn with(mut self, adapter: AdapterId, price: Price) -> Self {
        self.0.insert(adapter, price);
        self
    }

    /// What `tokens` cost on `adapter` — `None` when the adapter has no
    /// price: unknown, never free.
    #[must_use]
    pub fn cost_of(&self, adapter: &AdapterId, tokens: &Tokens) -> Option<Cost> {
        self.0.get(adapter).map(|price| price.cost(tokens))
    }
}

/// Which side of a routing decision a recorded call was on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallRole {
    /// At least one of its answers was accepted to serve, or its error
    /// reached the caller.
    Served,
    /// Asked only to compare: the cheap half of shadow mode, or either
    /// half of a [`measure_agreement`](crate::measure_agreement) run.
    Shadow,
    /// Asked to serve, and none of its answers was accepted: every one
    /// escalated, or the call failed. The ledger's
    /// [`InMemoryLedger::role_totals`] row for this role is what routing
    /// paid for nothing.
    ///
    /// A role is set when the call returns and is recorded then, so a
    /// caller that drops the future later loses no cost. A cheap call
    /// recorded as `Served` stays so even if the expensive escalation that
    /// follows fails and its answers never reach the caller.
    Discarded,
}

/// How a recorded call ended. A failed call is recorded too: a cheap
/// adapter that fails often is not cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallOutcome {
    Ok,
    Failed,
}

/// One classifier call as the ledger receives it.
///
/// `cost` is `None` when the adapter has no price on the sheet, and for a
/// failed call — whether a vendor bills a failed request is its own
/// business, so the router does not guess.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallRecord {
    pub adapter: AdapterId,
    /// Every question id the call carried, in order.
    pub kinds: Vec<QuestionKind>,
    pub tokens: Tokens,
    pub cost: Option<Cost>,
    pub role: CallRole,
    pub outcome: CallOutcome,
}

/// Sinks what classifier calls cost.
///
/// Sync and infallible on purpose: recording what a decision cost must not
/// be able to fail the decision or add a network hop. A durable sink
/// buffers and flushes on its own schedule.
pub trait CostLedger: Send + Sync {
    /// Records one call. Must not block on I/O or fail.
    fn record(&self, record: CallRecord);
}

/// The price sheet and the ledger every call is recorded to — what the
/// router, the shadow classifier and the corpus runner are all given, so
/// no classifier call through them goes unrecorded.
#[derive(Clone)]
pub struct Accounting {
    prices: PriceSheet,
    ledger: Arc<dyn CostLedger>,
}

impl Accounting {
    /// Prices calls off `prices` and records them to `ledger`.
    #[must_use]
    pub fn new(prices: PriceSheet, ledger: Arc<dyn CostLedger>) -> Self {
        Self { prices, ledger }
    }

    /// Records one call: estimated tokens, priced when it answered.
    pub(crate) fn record(
        &self,
        adapter: &AdapterId,
        profile: &ClassifierProfile,
        state: &str,
        questions: &BTreeMap<String, Question>,
        answers: Option<&BTreeMap<String, Answer>>,
        role: CallRole,
    ) {
        let tokens = Tokens::estimate(profile, state, questions, answers);
        self.ledger.record(CallRecord {
            adapter: adapter.clone(),
            kinds: questions.keys().map(QuestionKind::new).collect(),
            tokens,
            cost: answers.and_then(|_| self.prices.cost_of(adapter, &tokens)),
            role,
            outcome: if answers.is_some() {
                CallOutcome::Ok
            } else {
                CallOutcome::Failed
            },
        });
    }
}

impl fmt::Debug for Accounting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accounting")
            .field("prices", &self.prices)
            .finish_non_exhaustive()
    }
}

/// Totals over a set of records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LedgerTotals {
    pub calls: u64,
    /// Estimated, like every count in [`Tokens`].
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Sum of the known costs only.
    pub pico_usd: u128,
    /// Answered calls the sheet could not price — a wiring gap. Zero is
    /// the only healthy value.
    pub unpriced_calls: u64,
    /// Calls the adapter errored on. Not a wiring gap, so not counted in
    /// `unpriced_calls`.
    pub failed_calls: u64,
}

impl LedgerTotals {
    fn add(&mut self, record: &CallRecord) {
        self.calls = self.calls.saturating_add(1);
        self.input_tokens = self.input_tokens.saturating_add(record.tokens.input);
        self.output_tokens = self.output_tokens.saturating_add(record.tokens.output);
        match (record.cost, record.outcome) {
            (Some(cost), _) => {
                self.pico_usd = self.pico_usd.saturating_add(u128::from(cost.pico_usd()));
            }
            (None, CallOutcome::Ok) => self.unpriced_calls = self.unpriced_calls.saturating_add(1),
            (None, CallOutcome::Failed) => {}
        }
        if record.outcome == CallOutcome::Failed {
            self.failed_calls = self.failed_calls.saturating_add(1);
        }
    }
}

/// A [`CostLedger`] that keeps every record in memory, oldest first.
/// Process-local — one isolate's view on Workers — which suits a
/// measurement window and is not a billing system.
#[derive(Debug, Default)]
pub struct InMemoryLedger {
    #[expect(
        clippy::disallowed_types,
        reason = "the ledger is an explicitly wired recording cell, not ambient request state (ADR 0007)"
    )]
    records: std::sync::Mutex<Vec<CallRecord>>,
}

impl InMemoryLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Recovers from a poison: throwing away every record because one
    /// append panicked would be the dishonest choice for a ledger.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<CallRecord>> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every record so far, oldest first.
    #[must_use]
    pub fn records(&self) -> Vec<CallRecord> {
        self.lock().clone()
    }

    /// Totals per adapter.
    #[must_use]
    pub fn totals(&self) -> BTreeMap<AdapterId, LedgerTotals> {
        let mut totals: BTreeMap<AdapterId, LedgerTotals> = BTreeMap::new();
        for record in self.lock().iter() {
            totals
                .entry(record.adapter.clone())
                .or_default()
                .add(record);
        }
        totals
    }

    /// Totals per [`CallRole`]: the `Discarded` row is what escalation
    /// wasted, the `Shadow` row what measuring cost.
    #[must_use]
    pub fn role_totals(&self) -> BTreeMap<CallRole, LedgerTotals> {
        let mut totals: BTreeMap<CallRole, LedgerTotals> = BTreeMap::new();
        for record in self.lock().iter() {
            totals.entry(record.role).or_default().add(record);
        }
        totals
    }
}

impl CostLedger for InMemoryLedger {
    fn record(&self, record: CallRecord) {
        self.lock().push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::Calibration;

    fn tokens(input: u64, output: u64) -> Tokens {
        Tokens {
            input,
            output,
            source: TokenSource::Estimated,
        }
    }

    #[test]
    fn a_published_price_maps_one_to_one_and_displays_every_pico_usd() {
        let price = Price::per_million_tokens(3_000_000, 15_000_000);
        assert_eq!(
            price.cost(&tokens(1_000_000, 0)).to_string(),
            "$3.000000000000"
        );
        assert_eq!(
            price.cost(&tokens(1_000_000, 1_000_000)).pico_usd(),
            18 * PICO_PER_USD
        );
        assert_eq!(Cost::from_pico_usd(1).to_string(), "$0.000000000001");
        assert_eq!(
            Price::per_million_tokens(u64::MAX, u64::MAX)
                .cost(&tokens(u64::MAX, u64::MAX))
                .pico_usd(),
            u64::MAX,
            "saturates, never wraps into a credit"
        );
    }

    #[test]
    fn an_unpriced_adapter_is_unknown_and_a_free_one_is_zero() {
        let free = AdapterId::new("self-hosted");
        let sheet = PriceSheet::new().with(free.clone(), Price::FREE);
        assert_eq!(sheet.cost_of(&free, &tokens(10, 10)), Some(Cost::ZERO));
        assert_eq!(
            sheet.cost_of(&AdapterId::new("mystery"), &tokens(10, 10)),
            None
        );
    }

    #[test]
    fn tokens_are_estimated_from_the_truncated_state_the_questions_and_the_answers() {
        let questions = BTreeMap::from([(
            "ok".to_owned(),
            Question::Choice {
                instructions: "pick".to_owned(),
                criteria: BTreeMap::from([
                    ("a".to_owned(), "yes".to_owned()),
                    ("b".to_owned(), "no".to_owned()),
                ]),
            },
        )]);
        let profile = ClassifierProfile::new(Calibration::Classifier, 8);
        // 8 state chars kept of 20 + "ok" + "pick" + "a"+"yes" + "b"+"no" = 22 chars.
        let asked = Tokens::estimate(&profile, &"x".repeat(20), &questions, None);
        assert_eq!(
            asked,
            tokens(6, 0),
            "ceil(22 / 4), and no output for a failed call"
        );

        let answers = BTreeMap::from([(
            "ok".to_owned(),
            Answer::choice(
                "a",
                BTreeMap::from([("a".to_owned(), 0.9), ("b".to_owned(), 0.1)]),
            ),
        )]);
        // "ok" + "a" + "a0.90" + "b0.10" = 13 chars.
        let answered = Tokens::estimate(&profile, "", &questions, Some(&answers));
        assert_eq!(answered.output, 4);
        assert_eq!(answered.source, TokenSource::Estimated);
    }

    fn record(
        adapter: &str,
        cost: Option<Cost>,
        role: CallRole,
        outcome: CallOutcome,
    ) -> CallRecord {
        CallRecord {
            adapter: AdapterId::new(adapter),
            kinds: vec![QuestionKind::new("topic")],
            tokens: tokens(100, 10),
            cost,
            role,
            outcome,
        }
    }

    #[test]
    fn totals_separate_unpriced_from_failed_and_do_not_saturate_at_one_calls_ceiling() {
        let ledger = InMemoryLedger::new();
        let huge = Some(Cost::from_pico_usd(u64::MAX));
        ledger.record(record("cheap", huge, CallRole::Served, CallOutcome::Ok));
        ledger.record(record("cheap", huge, CallRole::Discarded, CallOutcome::Ok));
        ledger.record(record("cheap", None, CallRole::Served, CallOutcome::Ok));
        ledger.record(record("cheap", None, CallRole::Shadow, CallOutcome::Failed));

        let cheap = ledger.totals()[&AdapterId::new("cheap")];
        assert_eq!(cheap.calls, 4);
        assert_eq!(cheap.pico_usd, u128::from(u64::MAX) * 2);
        assert_eq!(
            cheap.unpriced_calls, 1,
            "only the answered, unpriced call is a gap"
        );
        assert_eq!(cheap.failed_calls, 1);
        assert_eq!(cheap.input_tokens, 400);

        let roles = ledger.role_totals();
        assert_eq!(roles[&CallRole::Discarded].calls, 1);
        assert_eq!(roles[&CallRole::Served].calls, 2);
        assert_eq!(ledger.records()[3].role, CallRole::Shadow, "oldest first");
    }
}
