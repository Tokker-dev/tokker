//! The `Classifier` port (issue #456): a typed, calibrated decision —
//! "which of these is it, and how sure are you" — asked of whichever
//! adapter the venture wired, the way [`TextModel`] is a completion asked
//! of whichever provider serves a tier. A module holds
//! `Arc<dyn Classifier>` and never learns who answered.
//!
//! Questions are asked **as a set**, not in a loop. The provider
//! evaluates the questions of one `ask` call against one `state` in
//! parallel — the expensive part of the call is carrying the state, not
//! answering — so the trait takes a `BTreeMap<String, Question>` and
//! hands back the answers keyed the same way, and an adapter can batch
//! what it serves. A loop of one-question calls is possible but is the
//! wrong shape: it pays for the state once per question and serialises
//! what the provider would have run concurrently.
//!
//! **Confidence is not comparable across adapters.** Calibration is a
//! property of the family of numbers an adapter's probabilities come from
//! ([`Calibration`]): a `0.8` from a purpose-trained classifier and a
//! `0.8` elicited from a general language model are different numbers,
//! and a threshold tuned against one is wrong against the other. A module
//! that thresholds on [`Answer::confidence`] says so in its own docs, as
//! a per-adapter threshold.
//!
//! **`state` is truncated by the adapter** when it exceeds
//! [`ClassifierProfile::max_state_chars`] — deterministically, on a char
//! boundary, with a log line. A silently trimmed state is the worst
//! failure mode a classifier has: the answer comes back confident and
//! wrong. [`DEFAULT_MAX_STATE_CHARS`] is the ceiling a conservative
//! adapter starts from.
//!
//! There is no outcome enum on this port, unlike [`Mailer`](crate::Mailer)
//! and [`Push`](crate::Push), and that is deliberate, as on
//! [`TextModel`]: a decision has no "delivered but not configured" middle
//! state — either an answer came back or nothing did. The unwired answer
//! is therefore [`ClassifierError::NotConfigured`], an error variant the
//! caller can match, so a module that cannot degrade without its
//! classifier fails loudly instead of silently producing nothing.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Chars of `state` a conservative adapter will send before it truncates:
/// roughly 4 chars per token against the 32k-token window Workers AI
/// documents, which leaves room in that window for the questions and the
/// answer. An adapter whose provider has a different budget reports its
/// own limit through [`ClassifierProfile::max_state_chars`] — this is the
/// default, not a law.
pub const DEFAULT_MAX_STATE_CHARS: usize = 96_000;

/// Which family of numbers an adapter's probabilities come from.
///
/// Calibration is **not portable**: a `0.8` from a purpose-trained
/// classifier and a `0.8` elicited from a general language model are
/// different numbers, and a threshold tuned against one is wrong against
/// the other. A module that thresholds on [`Answer::confidence`] states in
/// its own docs which [`Calibration`] its threshold was tuned against —
/// swapping the adapter re-tunes every threshold downstream of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Calibration {
    /// Numbers from a model trained to classify: the probabilities are the
    /// model's own outputs, tuned on labelled data.
    Classifier,
    /// Numbers elicited from a general language model — asked to rate its
    /// own certainty, or read off token log-probs. A different sharpness
    /// at the same number than [`Calibration::Classifier`], and it drifts
    /// with the model version.
    LanguageModel,
}

impl Calibration {
    /// The name used in errors and logs.
    pub fn name(&self) -> &'static str {
        match self {
            Calibration::Classifier => "classifier",
            Calibration::LanguageModel => "language_model",
        }
    }
}

impl std::fmt::Display for Calibration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What a caller can learn about the adapter answering, short of its
/// identity: the family its `confidence` comes from, and how much `state`
/// it will carry before it truncates.
///
/// `#[non_exhaustive]`: what an adapter can report about itself grows, and
/// it should not be a breaking change for every caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClassifierProfile {
    /// The family the adapter's `confidence` numbers come from. See
    /// [`Calibration`] — not comparable across families.
    pub calibration: Calibration,
    /// Chars of `state` this adapter will send before it truncates.
    /// Measured as the state's UTF-8 byte length, so multi-byte text can
    /// trim slightly under the limit — never mid-char.
    pub max_state_chars: usize,
}

impl ClassifierProfile {
    /// A profile with the calibration and the state ceiling given.
    #[must_use]
    pub fn new(calibration: Calibration, max_state_chars: usize) -> Self {
        Self {
            calibration,
            max_state_chars,
        }
    }

    /// Truncate `state` to `max_state_chars`, deterministically and on a
    /// char boundary: the same `state` and profile always produce the
    /// same prefix. Returns the slice to send and whether anything was
    /// dropped.
    ///
    /// An adapter calls this as it builds its request, and **logs when the
    /// second element is `true`**: a silently trimmed state produces a
    /// confident wrong answer, and a log line is the only chance a
    /// maintainer has of connecting the two.
    #[must_use]
    pub fn truncate<'a>(&self, state: &'a str) -> (&'a str, bool) {
        if state.len() <= self.max_state_chars {
            return (state, false);
        }
        let mut end = self.max_state_chars;
        while end > 0 && !state.is_char_boundary(end) {
            end -= 1;
        }
        (&state[..end], true)
    }
}

/// One question asked of `state`. Three shapes, because a classifier is
/// asked three kinds of thing: pick one of a named set
/// ([`Question::Choice`]), place on an ordered scale
/// ([`Question::Score`]), or answer yes or no ([`Question::Noul`]).
///
/// Not `#[non_exhaustive]`: an adapter matches on this exhaustively to
/// render each shape into its provider's request, and a new shape should
/// be a compile error in every adapter until it is handled, not a silent
/// fallthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Question {
    /// Pick one of the named criteria. The map is `criterion name -> what
    /// that criterion means`, because the provider only sees the words it
    /// is given; the keys are also the labels the answer's probabilities
    /// are keyed by.
    Choice {
        instructions: String,
        criteria: BTreeMap<String, String>,
    },
    /// Place `state` on an ordered scale, in order: each level is
    /// `(name, what that level means)`. The level names are the labels
    /// the answer's probabilities are keyed by.
    Score {
        instructions: String,
        levels: Vec<(String, String)>,
    },
    /// A yes/no question, answered as `true` or `false`.
    Noul { instructions: String },
}

impl Question {
    /// The instruction every shape carries — the part the adapter turns
    /// into its provider's prompt or class descriptions.
    #[must_use]
    pub fn instructions(&self) -> &str {
        match self {
            Question::Choice { instructions, .. }
            | Question::Score { instructions, .. }
            | Question::Noul { instructions } => instructions,
        }
    }

    /// Which shape this is, named for logs and provider payloads:
    /// `"choice"`, `"score"` or `"noul"`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Question::Choice { .. } => "choice",
            Question::Score { .. } => "score",
            Question::Noul { .. } => "noul",
        }
    }

    /// The labels an answer to this question is keyed by: the criteria
    /// names, the level names, or `["true", "false"]`.
    /// [`Answer::probabilities`] and [`Answer::confidence`] are per these.
    #[must_use]
    pub fn labels(&self) -> Vec<&str> {
        match self {
            Question::Choice { criteria, .. } => criteria.keys().map(String::as_str).collect(),
            Question::Score { levels, .. } => {
                levels.iter().map(|(name, _)| name.as_str()).collect()
            }
            Question::Noul { .. } => vec!["true", "false"],
        }
    }
}

/// The decided value of one [`Question`], shaped to match it.
#[derive(Debug, Clone, PartialEq)]
pub enum AnswerValue {
    /// The criterion chosen — one of [`Question::Choice`]'s keys.
    Choice(String),
    /// The score decided, on [`Question::Score`]'s scale.
    Score(f32),
    /// The yes/no verdict for a [`Question::Noul`].
    Noul(bool),
}

/// One answer: the value decided, the probability mass per label, and the
/// probability of the value that came back.
///
/// `#[non_exhaustive]`, so an adapter builds one with [`Answer::new`] or
/// the three conveniences rather than a struct literal, and a field added
/// later is not a breaking change for every adapter.
///
/// [`Answer::confidence`] is **not comparable across adapters** — see
/// [`Calibration`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Answer {
    /// The value decided, matching the shape of the [`Question`] asked.
    pub value: AnswerValue,
    /// Probability mass per label, keyed as [`Question::labels`] names
    /// them. The port does not require the masses to sum to one: some
    /// providers report only a top-1.
    pub probabilities: BTreeMap<String, f32>,
    /// Probability of the label in `value`. See [`Calibration`] — not
    /// comparable across adapters.
    pub confidence: f32,
    /// The vendor-reported model version that produced this answer, when
    /// the adapter knows it. An alias (`jev-latest`) can move under an
    /// unchanged request, and a threshold was tuned against a specific
    /// version's numbers — the version that actually answered is how a
    /// drifted answer is traced back to its cause. `None` when the adapter
    /// does not know (or its port has no such report); set with
    /// [`Answer::with_model`].
    pub model: Option<String>,
}

impl Answer {
    /// An answer with the value, probabilities and confidence given. The
    /// conveniences below are the usual way in: they pick `confidence`
    /// out of `probabilities` themselves.
    #[must_use]
    pub fn new(value: AnswerValue, probabilities: BTreeMap<String, f32>, confidence: f32) -> Self {
        Self {
            value,
            probabilities,
            confidence,
            model: None,
        }
    }

    /// Records the vendor-reported model version that produced this
    /// answer, for the adapters whose vendor reports one. Chainable on
    /// any constructor:
    /// `Answer::noul(..).with_model("jev-1.13.0")`.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// An answer to a [`Question::Choice`]: `label` is one of its
    /// criteria, and `confidence` is looked up in `probabilities` under
    /// it — 0.0 when the label is absent.
    #[must_use]
    pub fn choice(label: impl Into<String>, probabilities: BTreeMap<String, f32>) -> Self {
        let label = label.into();
        let confidence = probabilities.get(&label).copied().unwrap_or(0.0);
        Self {
            value: AnswerValue::Choice(label),
            probabilities,
            confidence,
            model: None,
        }
    }

    /// An answer to a [`Question::Score`]: `value` is on the scale, and
    /// `confidence` is looked up in `probabilities` under the score's own
    /// name — the convention when a scale's levels are named for their
    /// scores (`"1"`..`"5"`). A provider that reports confidence another
    /// way builds the answer with [`Answer::new`] instead. 0.0 when the
    /// label is absent.
    #[must_use]
    pub fn score(value: f32, probabilities: BTreeMap<String, f32>) -> Self {
        let confidence = probabilities
            .get(&value.to_string())
            .copied()
            .unwrap_or(0.0);
        Self {
            value: AnswerValue::Score(value),
            probabilities,
            confidence,
            model: None,
        }
    }

    /// An answer to a [`Question::Noul`]: `confidence` is looked up in
    /// `probabilities` under `"true"` or `"false"` — 0.0 when the label
    /// is absent.
    #[must_use]
    pub fn noul(value: bool, probabilities: BTreeMap<String, f32>) -> Self {
        let label = if value { "true" } else { "false" };
        let confidence = probabilities.get(label).copied().unwrap_or(0.0);
        Self {
            value: AnswerValue::Noul(value),
            probabilities,
            confidence,
            model: None,
        }
    }
}

/// Classification failures.
///
/// [`NotConfigured`](Self::NotConfigured) sits on the **error** enum here,
/// unlike [`SendOutcome::NotConfigured`](crate::SendOutcome) and
/// [`PushOutcome::NotConfigured`](crate::PushOutcome): a decision has no
/// "delivered but not configured" middle state, so an unwired port is an
/// error the caller matches, not an outcome it inspects.
///
/// `Transient` deliberately carries **only** `retry_after`, where
/// [`PushError::Transient`](crate::PushError) also carries a message: with
/// no provider text of its own there is nothing to scrub, and provider
/// text belongs on [`Rejected`](Self::Rejected) and
/// [`Transport`](Self::Transport).
///
/// The two variants that carry provider text are sanitized in `Display`,
/// the same way [`TextModelError`](crate::TextModelError)'s,
/// [`PushError`](crate::PushError)'s and [`MailError`](crate::MailError)'s
/// are (issue #235). What an adapter wraps is the provider's own words,
/// and `state` is exactly the kind of value that rides back in them — a
/// triage module sends a customer's note, and the provider's `4xx` quotes
/// it straight back. `Display` therefore runs it through
/// [`crate::logging::scrub_text`]; `Debug` still shows the raw string for
/// tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifierError {
    /// The port has no adapter — the venture did not wire it. Nothing is
    /// wrong with the questions: a module may degrade, the way it degrades
    /// on a `NotConfigured` mailer or text model.
    NotConfigured,
    /// The provider refused the request (a `4xx`), or the adapter refused
    /// the question set — [`validate_questions`] exists so that a
    /// malformed set lands here and never on a panic. Not retryable
    /// without a change.
    Rejected(String),
    /// A transient failure (a `5xx`, a `429`, a transport error): retry
    /// later, and not before `retry_after` when the provider named one.
    /// Carries no message — provider text belongs on
    /// [`Rejected`](Self::Rejected) and [`Transport`](Self::Transport).
    Transient { retry_after: Option<Duration> },
    /// The request never completed as a decision — the adapter could not
    /// reach the provider, or the answer did not survive the hop.
    Transport(String),
}

impl std::fmt::Display for ClassifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::NotConfigured => f.write_str("no classifier is wired for this venture"),
            Self::Rejected(message) => write!(f, "classification rejected: {}", scrub(message)),
            Self::Transient { .. } => f.write_str("classification failed, retryable"),
            Self::Transport(message) => {
                write!(f, "classification transport failed: {}", scrub(message))
            }
        }
    }
}

impl std::error::Error for ClassifierError {}

impl ClassifierError {
    /// How long the provider asked the caller to wait, where it said.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            ClassifierError::Transient { retry_after } => *retry_after,
            _ => None,
        }
    }
}

/// Checks a question set before an adapter renders it, so a malformed set
/// is [`ClassifierError::Rejected`] and never a panic anywhere: every
/// adapter calls this first, and every caller knows the shapes it hands
/// the provider are whole.
///
/// # Errors
/// [`ClassifierError::Rejected`] when the set is empty, an id is blank,
/// instructions are blank, a [`Question::Choice`] has fewer than two
/// criteria, or a [`Question::Score`] has fewer than two levels.
pub fn validate_questions(questions: &BTreeMap<String, Question>) -> Result<(), ClassifierError> {
    if questions.is_empty() {
        return Err(ClassifierError::Rejected(
            "a question set must not be empty".to_owned(),
        ));
    }
    for (id, question) in questions {
        if id.trim().is_empty() {
            return Err(ClassifierError::Rejected(format!(
                "question id must not be blank, got {id:?}"
            )));
        }
        if question.instructions().trim().is_empty() {
            return Err(ClassifierError::Rejected(format!(
                "question {id:?} has blank instructions"
            )));
        }
        match question {
            Question::Choice { criteria, .. } if criteria.len() < 2 => {
                return Err(ClassifierError::Rejected(format!(
                    "choice question {id:?} needs at least two criteria, got {}",
                    criteria.len()
                )));
            }
            Question::Score { levels, .. } if levels.len() < 2 => {
                return Err(ClassifierError::Rejected(format!(
                    "score question {id:?} needs at least two levels, got {}",
                    levels.len()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Answers a set of typed questions about a `state`, over whichever
/// classifier the venture wired. The sibling of `TextModel`: a module
/// asks "which of these is it, and how sure are you" and holds
/// `Arc<dyn Classifier>` without learning who answered.
///
/// # Confidence is per-adapter
///
/// [`Answer::confidence`] is not comparable across adapters. It comes
/// from the family [`ClassifierProfile::calibration`] names, and a `0.8`
/// from one family is not a `0.8` from the other — see [`Calibration`].
/// A module that thresholds on it must say in its own docs that the
/// threshold is per-adapter: swapping the adapter re-tunes every
/// threshold downstream of it.
///
/// # `state` is truncated by the adapter
///
/// When `state` is longer than [`ClassifierProfile::max_state_chars`] the
/// adapter truncates it — deterministically, on a char boundary, with a
/// log line. It has to be the adapter that does it: only the adapter
/// knows its provider's budget. A silently trimmed state is the worst
/// failure mode a classifier has, because the answer comes back
/// confident and wrong.
#[async_trait]
pub trait Classifier: Send + Sync {
    /// What family of numbers this adapter's `confidence` comes from, and
    /// how much `state` it will carry.
    fn profile(&self) -> ClassifierProfile;

    /// Answers every question in `questions` about `state`, keyed the
    /// same way.
    ///
    /// `questions` is a set, not a loop: the provider evaluates the
    /// questions of one call against one `state` in parallel, and the
    /// expensive part is carrying the state, not answering. An adapter
    /// validates the set with [`validate_questions`] and answers
    /// [`ClassifierError::Rejected`] rather than panicking on a
    /// malformed one.
    ///
    /// # Errors
    /// [`ClassifierError::NotConfigured`] when no adapter is wired;
    /// [`ClassifierError::Rejected`] when the provider or
    /// [`validate_questions`] refused the request;
    /// [`ClassifierError::Transient`] when the call is retryable, with
    /// the provider's back-off where it named one;
    /// [`ClassifierError::Transport`] when the call never completed as a
    /// decision.
    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Calibration

    #[test]
    fn a_calibration_names_itself_and_round_trips_through_json() {
        for calibration in [Calibration::Classifier, Calibration::LanguageModel] {
            let json = serde_json::to_string(&calibration).expect("serialises");
            let back: Calibration = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(calibration, back);
        }
        // The point of `rename_all`: the persisted name is the prose name,
        // so a config file reads `"language_model"`, not `"LanguageModel"`.
        assert_eq!(
            serde_json::to_value(Calibration::LanguageModel).unwrap(),
            "language_model"
        );
        assert_eq!(Calibration::Classifier.name(), "classifier");
        assert_eq!(Calibration::LanguageModel.to_string(), "language_model");
    }

    // -----------------------------------------------------------------
    // ClassifierProfile::truncate

    #[test]
    fn truncate_is_a_no_op_under_the_limit() {
        assert_eq!(DEFAULT_MAX_STATE_CHARS, 96_000);
        let profile = ClassifierProfile::new(Calibration::Classifier, DEFAULT_MAX_STATE_CHARS);
        let state = "a state well under the ceiling";
        let (sent, dropped) = profile.truncate(state);
        assert_eq!(sent, state);
        assert!(!dropped);
    }

    #[test]
    fn truncate_trims_deterministically_over_the_limit() {
        let profile = ClassifierProfile::new(Calibration::Classifier, 16);
        let state = "the same state, asked twice, over the limit";
        let (first, dropped) = profile.truncate(state);
        let (second, dropped_again) = profile.truncate(state);
        assert!(dropped);
        assert!(dropped_again);
        assert_eq!(first, second, "the same state always trims the same way");
        assert_eq!(first.len(), 16, "the prefix spends the whole budget");
        assert!(state.starts_with(first), "the prefix is a prefix");
    }

    #[test]
    fn truncate_never_splits_a_multi_byte_char() {
        // Four 3-byte chars, twelve bytes; a budget of seven lands in the
        // middle of the third. The floor boundary is byte six, so the
        // last whole char is kept and the slice is still valid UTF-8.
        let state = "漢字漢字";
        let profile = ClassifierProfile::new(Calibration::LanguageModel, 7);
        let (sent, dropped) = profile.truncate(state);
        assert!(dropped);
        assert_eq!(sent, "漢字");
        assert_eq!(sent.chars().count(), 2);
    }

    #[test]
    fn a_zero_limit_keeps_nothing_but_stays_on_a_boundary() {
        let profile = ClassifierProfile::new(Calibration::Classifier, 0);
        let (sent, dropped) = profile.truncate("漢字");
        assert_eq!(sent, "");
        assert!(dropped);
    }

    // -----------------------------------------------------------------
    // Question

    #[test]
    fn a_question_names_its_shape_and_labels() {
        let choice = Question::Choice {
            instructions: "Pick.".to_owned(),
            criteria: BTreeMap::from([
                ("billing".to_owned(), "money and invoices".to_owned()),
                ("bugs".to_owned(), "something is broken".to_owned()),
            ]),
        };
        assert_eq!(choice.kind(), "choice");
        assert_eq!(choice.instructions(), "Pick.");
        assert_eq!(choice.labels(), vec!["billing", "bugs"]);

        let score = Question::Score {
            instructions: "Rate.".to_owned(),
            levels: vec![
                ("1".to_owned(), "low".to_owned()),
                ("5".to_owned(), "high".to_owned()),
            ],
        };
        assert_eq!(score.kind(), "score");
        assert_eq!(score.labels(), vec!["1", "5"]);

        let noul = Question::Noul {
            instructions: "Yes or no?".to_owned(),
        };
        assert_eq!(noul.kind(), "noul");
        assert_eq!(noul.instructions(), "Yes or no?");
        assert_eq!(noul.labels(), vec!["true", "false"]);
    }

    // -----------------------------------------------------------------
    // Answer constructors

    #[test]
    fn answer_conveniences_pick_confidence_from_the_probabilities() {
        let criteria = BTreeMap::from([("spam".to_owned(), 0.9_f32), ("ham".to_owned(), 0.1_f32)]);
        let answer = Answer::choice("spam", criteria.clone());
        assert_eq!(answer.value, AnswerValue::Choice("spam".to_owned()));
        assert_eq!(answer.probabilities, criteria);
        assert!((answer.confidence - 0.9).abs() < f32::EPSILON);

        // A scale whose levels are named for their scores is the case
        // `score` looks confidence up for.
        let levels = BTreeMap::from([("1".to_owned(), 0.25_f32), ("2".to_owned(), 0.75_f32)]);
        let answer = Answer::score(2.0, levels);
        assert_eq!(answer.value, AnswerValue::Score(2.0));
        assert!((answer.confidence - 0.75).abs() < f32::EPSILON);

        let verdicts =
            BTreeMap::from([("true".to_owned(), 0.7_f32), ("false".to_owned(), 0.3_f32)]);
        let answer = Answer::noul(true, verdicts);
        assert_eq!(answer.value, AnswerValue::Noul(true));
        assert!((answer.confidence - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn an_absent_label_yields_zero_confidence() {
        // Compared with a tolerance, not `==`: a float that was looked up
        // is still a float (and clippy::float_cmp has a point).
        let verdicts = BTreeMap::from([("true".to_owned(), 1.0_f32)]);
        assert!(
            Answer::noul(false, verdicts).confidence.abs() < f32::EPSILON,
            "an absent label answers 0.0"
        );
        let confidence = Answer::choice(
            "unheard-of",
            BTreeMap::from([("known".to_owned(), 1.0_f32)]),
        )
        .confidence;
        assert!(
            confidence.abs() < f32::EPSILON,
            "an absent label answers 0.0"
        );
        assert!(
            Answer::score(3.5, BTreeMap::new()).confidence.abs() < f32::EPSILON,
            "an absent label answers 0.0"
        );

        // `new` is the escape hatch: the caller states the confidence
        // rather than looking it up by label.
        let answer = Answer::new(AnswerValue::Score(4.0), BTreeMap::new(), 0.5);
        assert!((answer.confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn with_model_records_the_reporting_version_and_defaults_to_none() {
        // The constructors do not invent a vendor they do not have; only
        // an adapter that knows sets it.
        let answer = Answer::noul(true, BTreeMap::new());
        assert_eq!(answer.model, None);
        assert_eq!(
            Answer::choice("spam", BTreeMap::new())
                .with_model("jev-1.13.0")
                .model
                .as_deref(),
            Some("jev-1.13.0")
        );
        assert_eq!(
            Answer::score(3.0, BTreeMap::new()).with_model("v2").model,
            Some("v2".to_owned())
        );
    }

    // -----------------------------------------------------------------
    // validate_questions

    fn good_set() -> BTreeMap<String, Question> {
        BTreeMap::from([
            (
                "topic".to_owned(),
                Question::Choice {
                    instructions: "Which topic does the note belong to?".to_owned(),
                    criteria: BTreeMap::from([
                        ("billing".to_owned(), "money, invoices".to_owned()),
                        ("bugs".to_owned(), "something is broken".to_owned()),
                    ]),
                },
            ),
            (
                "severity".to_owned(),
                Question::Score {
                    instructions: "How severe is the note?".to_owned(),
                    levels: vec![
                        ("1".to_owned(), "a typo".to_owned()),
                        ("5".to_owned(), "data loss".to_owned()),
                    ],
                },
            ),
            (
                "angry".to_owned(),
                Question::Noul {
                    instructions: "Is the writer angry?".to_owned(),
                },
            ),
        ])
    }

    #[test]
    fn a_good_set_is_accepted() {
        assert_eq!(validate_questions(&good_set()), Ok(()));
    }

    #[test]
    fn an_empty_set_is_rejected() {
        let error = validate_questions(&BTreeMap::new()).unwrap_err();
        assert!(matches!(error, ClassifierError::Rejected(_)));
    }

    #[test]
    fn a_blank_id_is_rejected() {
        let mut questions = good_set();
        questions.insert("   ".to_owned(), questions["topic"].clone());
        let error = validate_questions(&questions).unwrap_err();
        assert!(matches!(error, ClassifierError::Rejected(_)));
    }

    #[test]
    fn blank_instructions_are_rejected() {
        let questions = BTreeMap::from([(
            "topic".to_owned(),
            Question::Noul {
                instructions: "   ".to_owned(),
            },
        )]);
        assert!(matches!(
            validate_questions(&questions),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_choice_with_one_criterion_is_rejected() {
        let mut questions = good_set();
        questions.insert(
            "solo".to_owned(),
            Question::Choice {
                instructions: "Pick one.".to_owned(),
                criteria: BTreeMap::from([("only".to_owned(), "the only one".to_owned())]),
            },
        );
        assert!(matches!(
            validate_questions(&questions),
            Err(ClassifierError::Rejected(_))
        ));
    }

    #[test]
    fn a_score_with_one_level_is_rejected() {
        let mut questions = good_set();
        questions.insert(
            "one-note".to_owned(),
            Question::Score {
                instructions: "Rate it.".to_owned(),
                levels: vec![("3".to_owned(), "middling".to_owned())],
            },
        );
        assert!(matches!(
            validate_questions(&questions),
            Err(ClassifierError::Rejected(_))
        ));
    }

    // -----------------------------------------------------------------
    // ClassifierError

    #[test]
    fn display_sanitizes_the_provider_text() {
        // Issue #235. The text an adapter wraps is the provider's own
        // words, and `state` is often whatever a user wrote: what the
        // provider echoes back must not survive into a log line or a
        // dead-letter row carrying its URLs, tokens or addresses.
        let error = ClassifierError::Rejected(
            "provider 400 for https://api.example.test/v1/classify?token=secret-abcdef".to_owned(),
        );
        let text = error.to_string();
        assert!(text.contains("classification rejected"), "{text}");
        assert!(!text.contains("secret-abcdef"), "{text}");
        assert!(text.contains("?[redacted]"), "{text}");

        let error = ClassifierError::Transport("timeout quoting alice@example.test".to_owned());
        let text = error.to_string();
        assert!(text.contains("classification transport failed"), "{text}");
        assert!(!text.contains('@'), "{text}");

        // `Debug` still shows the raw string for a failing test to read.
        assert!(format!("{error:?}").contains("alice@example.test"));
    }

    #[test]
    fn transient_says_retryable_and_carries_no_text_to_scrub() {
        // `Transient` has no message field on purpose — the fixed sentence
        // is the whole `Display`, and a provider's words would be an
        // unsanitised leak by construction.
        let error = ClassifierError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert_eq!(error.to_string(), "classification failed, retryable");
    }

    #[test]
    fn not_configured_names_the_missing_wiring_and_carries_no_back_off() {
        assert_eq!(
            ClassifierError::NotConfigured.to_string(),
            "no classifier is wired for this venture"
        );
        assert_eq!(ClassifierError::NotConfigured.retry_after(), None);
        assert_eq!(
            ClassifierError::Rejected("422".to_owned()).retry_after(),
            None,
            "a rejection is not a back-off"
        );
        assert_eq!(
            ClassifierError::Transport("timed out".to_owned()).retry_after(),
            None
        );
        let throttled = ClassifierError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
    }
}
