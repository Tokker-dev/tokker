//! Does a cheap classifier answer like the expensive one, per kind of
//! question? (issue #457). [`measure_agreement`] runs a labelled corpus
//! through both; [`ShadowClassifier`](crate::ShadowClassifier) feeds the
//! same [`AgreementLog`] from live traffic. The [`AgreementReport`] is the
//! evidence [`RoutingClassifier`](crate::RoutingClassifier) routes on.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cost::{Accounting, AdapterId, CallRole, QuestionKind, value_text};
use crate::ports::{Answer, AnswerValue, Classifier, Question};

/// Whether two answer values are the same answer.
///
/// - `Choice`: the same label.
/// - `Noul`: the same verdict.
/// - `Score`: the same whole level once rounded (`3.2` and `2.9` agree,
///   `3.4` and `3.6` do not) — the `"1"`..`"5"` convention
///   [`Answer::score`] documents. Rounding makes this an equivalence, so
///   two disagreeing answers can never both match the ground truth. A
///   non-finite score agrees with nothing.
/// - Different shapes never agree.
///
/// Ground truth is matched by the same rule.
#[must_use]
pub fn values_agree(a: &AnswerValue, b: &AnswerValue) -> bool {
    match (a, b) {
        (AnswerValue::Choice(a), AnswerValue::Choice(b)) => a == b,
        (AnswerValue::Noul(a), AnswerValue::Noul(b)) => a == b,
        (AnswerValue::Score(a), AnswerValue::Score(b)) => {
            a.is_finite() && b.is_finite() && (a.round() - b.round()).abs() < 0.5
        }
        _ => false,
    }
}

/// How narrowly the answer won: the top probability minus the runner-up,
/// never negative.
///
/// The runner-up is the larger of the second reported probability and the
/// mass nobody reported (`1 - sum`, at least zero): a provider reporting
/// only `{"true": 0.55}` has left 0.45 on the other side, so its margin is
/// 0.10, not 0.55. With no probabilities at all the top is
/// [`Answer::confidence`] and the rest of the mass is the runner-up, so the
/// margin is `2 * confidence - 1`.
///
/// A NaN among the numbers it is computed from gives a NaN, which clears
/// no threshold and is stored as absent, rather than a made-up zero.
#[must_use]
pub fn answer_margin(answer: &Answer) -> f32 {
    let mut top = [None::<f32>; 2];
    for &p in answer.probabilities.values() {
        if top[0].is_none_or(|first| p > first) {
            top = [Some(p), top[0]];
        } else if top[1].is_none_or(|second| p > second) {
            top[1] = Some(p);
        }
    }
    let (first, second) = match top {
        [Some(first), second] => (first, second.unwrap_or(0.0)),
        [None, _] => (answer.confidence, 0.0),
    };
    let unreported = if answer.probabilities.is_empty() {
        1.0 - answer.confidence
    } else {
        1.0 - answer.probabilities.values().sum::<f32>()
    };
    if [first, second, unreported].iter().any(|v| v.is_nan()) {
        return f32::NAN;
    }
    (first - second.max(unreported).max(0.0)).max(0.0)
}

/// `value` if it is a number a report can carry: `serde_json` writes a NaN
/// or an infinity as `null`, which would not load back as an `f32`.
fn finite(value: f32) -> Option<f32> {
    value.is_finite().then_some(value)
}

/// One labelled corpus item: a state, the questions asked of it in one
/// batch, and the gold answer for whichever ids have one (a missing id is
/// ungraded).
#[derive(Debug, Clone, PartialEq)]
pub struct CorpusItem {
    pub state: String,
    pub questions: BTreeMap<String, Question>,
    pub expected: BTreeMap<String, AnswerValue>,
}

/// Which adapter the ground truth sided with when the two disagreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundTruth {
    Ungraded,
    Cheap,
    Expensive,
    Neither,
}

/// One question the two adapters answered differently. Values only, never
/// the state: a report is safe to paste into a ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disagreement {
    /// Index into the corpus; `None` for live shadow traffic.
    pub item: Option<usize>,
    pub cheap: String,
    pub expensive: String,
    pub expected: Option<String>,
    pub right: GroundTruth,
}

/// The cheap adapter's confidence and margin on one compared question,
/// and how it went — the evidence a [`Thresholds`](crate::Thresholds) is
/// checked against. Only the cheap side is kept: its confidence is what
/// routing reads, and it is not comparable with the expensive one's.
///
/// A non-finite confidence or margin is kept as `None`, so a report always
/// loads back from JSON, and `None` never clears a threshold.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CalibrationPoint {
    pub confidence: Option<f32>,
    pub margin: Option<f32>,
    pub agreed: bool,
    /// `None` when ungraded.
    pub cheap_right: Option<bool>,
}

/// Agreement on one [`QuestionKind`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KindAgreement {
    /// Questions both adapters answered.
    pub questions: usize,
    pub agreed: usize,
    /// Questions with a gold answer, and how many each adapter got right.
    pub graded: usize,
    pub cheap_right: usize,
    pub expensive_right: usize,
    /// Questions that could not be compared: either adapter failed or left
    /// the id out of its answers.
    pub skipped: usize,
    pub disagreements: Vec<Disagreement>,
    pub calibration: Vec<CalibrationPoint>,
}

/// The slice of a kind's evidence the cheap adapter would have been
/// trusted on at some thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgreementAt {
    pub questions: usize,
    pub agreed: usize,
}

impl AgreementAt {
    /// Share of those questions answered differently; `None` for none.
    #[must_use]
    pub fn disagreement_rate(&self) -> Option<f64> {
        rate(self.questions - self.agreed, self.questions)
    }
}

impl KindAgreement {
    /// Share of compared questions answered alike; `None` when nothing was
    /// compared — unmeasured, which is not the same as zero.
    #[must_use]
    pub fn agreement_rate(&self) -> Option<f64> {
        rate(self.agreed, self.questions)
    }

    /// The evidence restricted to questions the cheap adapter answered with
    /// at least `min_confidence` and `min_margin` — what it would have
    /// served under those thresholds. Written in the positive, and an
    /// absent (non-finite) value never passes.
    #[must_use]
    pub fn agreement_at(&self, min_confidence: f32, min_margin: f32) -> AgreementAt {
        let kept = self.calibration.iter().filter(|p| {
            p.confidence.is_some_and(|c| c >= min_confidence)
                && p.margin.is_some_and(|m| m >= min_margin)
        });
        let (questions, agreed) = kept.fold((0, 0), |(n, a), p| (n + 1, a + usize::from(p.agreed)));
        AgreementAt { questions, agreed }
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "counts of classifier calls stay far below 2^52"
)]
fn rate(part: usize, whole: usize) -> Option<f64> {
    (whole > 0).then(|| part as f64 / whole as f64)
}

/// Agreement between two named adapters, per question kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgreementReport {
    pub cheap: AdapterId,
    pub expensive: AdapterId,
    pub kinds: BTreeMap<QuestionKind, KindAgreement>,
}

impl fmt::Display for AgreementReport {
    /// One line per kind; `n/a` where nothing was compared or graded.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} vs {}", self.cheap, self.expensive)?;
        for (kind, k) in &self.kinds {
            let agree = k
                .agreement_rate()
                .map_or_else(|| "n/a".to_owned(), |r| format!("{:.1}%", r * 100.0));
            let graded = if k.graded == 0 {
                "n/a".to_owned()
            } else {
                format!(
                    "{}/{} vs {}/{}",
                    k.cheap_right, k.graded, k.expensive_right, k.graded
                )
            };
            writeln!(
                f,
                "{kind}: {agree} agree over {} (skipped {}); right: {graded}",
                k.questions, k.skipped
            )?;
        }
        Ok(())
    }
}

/// Accumulates an [`AgreementReport`] one compared answer at a time.
#[derive(Debug)]
pub struct AgreementLog {
    #[expect(
        clippy::disallowed_types,
        reason = "an explicitly wired measurement cell, not ambient request state (ADR 0007)"
    )]
    report: std::sync::Mutex<AgreementReport>,
}

impl AgreementLog {
    /// An empty log comparing `cheap` against `expensive`.
    #[must_use]
    pub fn new(cheap: AdapterId, expensive: AdapterId) -> Self {
        Self {
            report: AgreementReport {
                cheap,
                expensive,
                kinds: BTreeMap::new(),
            }
            .into(),
        }
    }

    fn with_kind(&self, kind: &QuestionKind, f: impl FnOnce(&mut KindAgreement)) {
        let mut report = self
            .report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(report.kinds.entry(kind.clone()).or_default());
    }

    /// Records one question both adapters answered, graded against
    /// `expected` when there is one. `item` is the corpus index, if any.
    pub fn observe(
        &self,
        kind: &QuestionKind,
        cheap: &Answer,
        expensive: &Answer,
        expected: Option<&AnswerValue>,
        item: Option<usize>,
    ) {
        let agreed = values_agree(&cheap.value, &expensive.value);
        let cheap_right = expected.map(|gold| values_agree(&cheap.value, gold));
        let expensive_right = expected.map(|gold| values_agree(&expensive.value, gold));
        self.with_kind(kind, |k| {
            k.questions += 1;
            k.agreed += usize::from(agreed);
            if let (Some(c), Some(e)) = (cheap_right, expensive_right) {
                k.graded += 1;
                k.cheap_right += usize::from(c);
                k.expensive_right += usize::from(e);
            }
            k.calibration.push(CalibrationPoint {
                confidence: finite(cheap.confidence),
                margin: finite(answer_margin(cheap)),
                agreed,
                cheap_right,
            });
            if !agreed {
                k.disagreements.push(Disagreement {
                    item,
                    cheap: value_text(&cheap.value),
                    expensive: value_text(&expensive.value),
                    expected: expected.map(value_text),
                    right: match (cheap_right, expensive_right) {
                        (Some(true), _) => GroundTruth::Cheap,
                        (_, Some(true)) => GroundTruth::Expensive,
                        (Some(false), _) => GroundTruth::Neither,
                        (None, _) => GroundTruth::Ungraded,
                    },
                });
            }
        });
    }

    /// Records a question that could not be compared.
    pub(crate) fn skip(&self, kind: &QuestionKind) {
        self.with_kind(kind, |k| k.skipped += 1);
    }

    /// The evidence so far.
    #[must_use]
    pub fn report(&self) -> AgreementReport {
        self.report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Asks both adapters every corpus item — one batch per item, cheap first,
/// expensive only when cheap answered — and reports agreement per kind.
/// Every call is recorded to `accounting` as [`CallRole::Shadow`]. An
/// adapter error skips the item's questions rather than aborting the run:
/// a failure rate is evidence too.
pub async fn measure_agreement(
    cheap: &(AdapterId, Arc<dyn Classifier>),
    expensive: &(AdapterId, Arc<dyn Classifier>),
    corpus: &[CorpusItem],
    accounting: &Accounting,
) -> AgreementReport {
    let log = AgreementLog::new(cheap.0.clone(), expensive.0.clone());
    for (index, item) in corpus.iter().enumerate() {
        let (state, questions) = (item.state.as_str(), &item.questions);
        let cheap_answers = cheap.1.ask(state, questions).await;
        accounting.record(
            &cheap.0,
            &cheap.1.profile(),
            state,
            questions,
            cheap_answers.as_ref().ok(),
            CallRole::Shadow,
        );
        let expensive_answers = match &cheap_answers {
            Ok(_) => {
                let answers = expensive.1.ask(state, questions).await;
                accounting.record(
                    &expensive.0,
                    &expensive.1.profile(),
                    state,
                    questions,
                    answers.as_ref().ok(),
                    CallRole::Shadow,
                );
                answers.ok()
            }
            Err(_) => None,
        };
        compare(
            &log,
            questions,
            cheap_answers.as_ref().ok(),
            expensive_answers.as_ref(),
            &item.expected,
            Some(index),
        );
    }
    log.report()
}

/// Observes every question both answer maps hold, and skips the rest (all
/// of them when either call failed, `None`).
pub(crate) fn compare(
    log: &AgreementLog,
    questions: &BTreeMap<String, Question>,
    cheap: Option<&BTreeMap<String, Answer>>,
    expensive: Option<&BTreeMap<String, Answer>>,
    expected: &BTreeMap<String, AnswerValue>,
    item: Option<usize>,
) {
    for id in questions.keys() {
        let kind = QuestionKind::new(id.as_str());
        match cheap
            .and_then(|c| c.get(id))
            .zip(expensive.and_then(|e| e.get(id)))
        {
            Some((c, e)) => log.observe(&kind, c, e, expected.get(id), item),
            None => log.skip(&kind),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probs(pairs: &[(&str, f32)]) -> BTreeMap<String, f32> {
        pairs.iter().map(|(l, p)| ((*l).to_owned(), *p)).collect()
    }

    #[test]
    fn agreement_is_defined_per_answer_shape() {
        use AnswerValue::{Choice, Noul, Score};
        assert!(values_agree(&Choice("a".into()), &Choice("a".into())));
        assert!(!values_agree(&Choice("a".into()), &Choice("b".into())));
        assert!(values_agree(&Noul(true), &Noul(true)));
        assert!(!values_agree(&Noul(true), &Noul(false)));
        assert!(values_agree(&Score(3.2), &Score(2.9)), "same whole level");
        assert!(!values_agree(&Score(3.4), &Score(3.6)));
        assert!(!values_agree(&Score(f32::NAN), &Score(f32::NAN)));
        assert!(
            !values_agree(&Choice("true".into()), &Noul(true)),
            "shapes never agree"
        );
    }

    #[test]
    fn margin_counts_unreported_mass_as_the_runner_up() {
        let close = |a: &Answer, want: f32| (answer_margin(a) - want).abs() < 1e-6;
        let rising = probs(&[("a", 0.1), ("b", 0.3), ("c", 0.6)]);
        assert!(close(&Answer::choice("c", rising), 0.3));
        let falling = probs(&[("a", 0.6), ("b", 0.3), ("c", 0.1)]);
        assert!(close(&Answer::choice("a", falling), 0.3));
        let top_one = Answer::noul(true, probs(&[("true", 0.55)]));
        assert!(close(&top_one, 0.1), "0.45 unreported is the runner-up");
        let bare = Answer::new(AnswerValue::Noul(true), BTreeMap::new(), 0.8);
        assert!(close(&bare, 0.6), "no probabilities: 2 * confidence - 1");
        let unsure = Answer::new(AnswerValue::Noul(true), BTreeMap::new(), 0.3);
        assert!(close(&unsure, 0.0), "never negative");
    }

    #[test]
    fn a_non_finite_confidence_is_absent_and_the_report_round_trips() {
        let log = AgreementLog::new(AdapterId::new("cheap"), AdapterId::new("dear"));
        let kind = QuestionKind::new("lang");
        let nan = Answer::new(AnswerValue::Choice("en".into()), BTreeMap::new(), f32::NAN);
        log.observe(&kind, &nan, &nan, None, None);
        let report = log.report();
        let point = report.kinds[&kind].calibration[0];
        assert_eq!((point.confidence, point.margin), (None, None));
        assert_eq!(report.kinds[&kind].agreement_at(0.0, 0.0).questions, 0);
        let json = serde_json::to_string(&report).expect("serialises");
        let loaded: AgreementReport = serde_json::from_str(&json).expect("loads back");
        assert_eq!(loaded, report);
    }

    #[test]
    fn evidence_is_graded_sliced_by_thresholds_and_unmeasured_is_not_zero() {
        let log = AgreementLog::new(AdapterId::new("cheap"), AdapterId::new("dear"));
        let kind = QuestionKind::new("lang");
        let sure = Answer::choice("en", probs(&[("en", 0.9), ("de", 0.1)]));
        let unsure = Answer::choice("de", probs(&[("de", 0.5), ("en", 0.4)]));
        let en = AnswerValue::Choice("en".into());
        log.observe(&kind, &sure, &sure, Some(&en), Some(0));
        log.observe(&kind, &unsure, &sure, Some(&en), Some(1));
        log.skip(&kind);

        let report = log.report();
        let k = &report.kinds[&kind];
        assert_eq!(
            (
                k.questions,
                k.agreed,
                k.graded,
                k.cheap_right,
                k.expensive_right,
                k.skipped
            ),
            (2, 1, 2, 1, 2, 1)
        );
        assert_eq!(k.disagreements[0].right, GroundTruth::Expensive);
        assert_eq!(
            k.agreement_at(0.8, 0.0),
            AgreementAt {
                questions: 1,
                agreed: 1
            }
        );
        assert_eq!(k.agreement_at(0.8, 0.0).disagreement_rate(), Some(0.0));
        assert_eq!(k.agreement_at(f32::NAN, 0.0).questions, 0);
        assert_eq!(KindAgreement::default().agreement_rate(), None);
        assert!(
            report
                .to_string()
                .contains("lang: 50.0% agree over 2 (skipped 1); right: 1/2 vs 2/2")
        );
    }
}
