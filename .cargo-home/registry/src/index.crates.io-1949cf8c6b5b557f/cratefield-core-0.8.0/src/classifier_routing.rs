//! Two wrappers over a cheap and an expensive [`Classifier`] (issue #457):
//! [`ShadowClassifier`] serves the expensive answers and measures the cheap
//! one alongside, and [`RoutingClassifier`] serves the cheap answers only
//! for question kinds where that measurement earned it.
//!
//! **Thresholds are per adapter.** [`Answer::confidence`] means a different
//! thing per adapter: a trained classifier's calibrated probability, or a
//! language model's token probability, which runs high whether or not it
//! is right (see [`Calibration`]). A 0.8 from one is not a 0.8 from the
//! other, so one threshold shared across adapters would be wrong for at
//! least one of them. Each [`Thresholds`] names the [`Calibration`] it was
//! tuned under, and [`RoutingClassifier::new`] refuses a threshold whose
//! adapter reports a different one.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::task::Poll;

use async_trait::async_trait;

use crate::classifier_agreement::{AgreementLog, AgreementReport, answer_margin, compare};
use crate::cost::{Accounting, AdapterId, CallRole, QuestionKind};
use crate::ports::{
    Answer, Calibration, Classifier, ClassifierError, ClassifierProfile, Question,
    validate_questions,
};

/// When the cheap adapter's answer is good enough to serve: at least
/// `min_confidence` and a top-two margin of at least `min_margin`, under
/// the [`Calibration`] these numbers were tuned for.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub calibration: Calibration,
    pub min_confidence: f32,
    pub min_margin: f32,
}

/// Whether routing happens at all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RoutingMode {
    /// Every question to the expensive adapter — the default.
    #[default]
    Off,
    /// Every question to the named adapter, no escalation.
    Pinned(AdapterId),
    /// Per kind, on the policy's evidence.
    Measured,
}

/// How [`RoutingClassifier`] decides. Defaults to [`RoutingMode::Off`]:
/// a cheaper adapter is earned by measurement, never assumed.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingPolicy {
    mode: RoutingMode,
    evidence: Option<AgreementReport>,
    thresholds: BTreeMap<AdapterId, Thresholds>,
    min_questions: usize,
    max_disagreement_rate: f64,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self::off()
    }
}

impl RoutingPolicy {
    /// Everything to the expensive adapter.
    #[must_use]
    pub fn off() -> Self {
        Self {
            mode: RoutingMode::Off,
            evidence: None,
            thresholds: BTreeMap::new(),
            min_questions: 20,
            max_disagreement_rate: 0.05,
        }
    }

    /// Everything to `adapter`, which must be one the router holds.
    #[must_use]
    pub fn pinned(adapter: AdapterId) -> Self {
        Self {
            mode: RoutingMode::Pinned(adapter),
            ..Self::off()
        }
    }

    /// Route per kind on `evidence`, which must compare the router's two
    /// adapters.
    #[must_use]
    pub fn measured(evidence: AgreementReport) -> Self {
        Self {
            mode: RoutingMode::Measured,
            evidence: Some(evidence),
            ..Self::off()
        }
    }

    /// The thresholds for `adapter`. Without thresholds for the cheap
    /// adapter nothing is routed to it.
    #[must_use]
    pub fn thresholds(mut self, adapter: AdapterId, thresholds: Thresholds) -> Self {
        self.thresholds.insert(adapter, thresholds);
        self
    }

    /// How many measured questions a kind needs, at the thresholds, before
    /// the cheap adapter may answer it. Default 20.
    #[must_use]
    pub const fn min_questions(mut self, n: usize) -> Self {
        self.min_questions = n;
        self
    }

    /// The most disagreement a kind may show, at the thresholds, and still
    /// go to the cheap adapter; equal to the cap passes. Default 0.05.
    #[must_use]
    pub const fn max_disagreement_rate(mut self, rate: f64) -> Self {
        self.max_disagreement_rate = rate;
        self
    }

    /// Why a kind is or is not trusted to the cheap adapter; `None` means
    /// trusted.
    fn distrust(
        &self,
        kind: &QuestionKind,
        thresholds: Option<&Thresholds>,
    ) -> Option<RouteReason> {
        let Some(t) = thresholds else {
            return Some(RouteReason::NoCalibration);
        };
        let Some(k) = self.evidence.as_ref().and_then(|e| e.kinds.get(kind)) else {
            return Some(RouteReason::NoMeasurement);
        };
        let at = k.agreement_at(t.min_confidence, t.min_margin);
        if at.questions < self.min_questions {
            return Some(RouteReason::NotMeasuredEnough);
        }
        match at.disagreement_rate() {
            Some(rate) if rate <= self.max_disagreement_rate => None,
            _ => Some(RouteReason::DisagreementTooHigh),
        }
    }
}

/// Refusals from [`RoutingClassifier::new`]: a policy that cannot mean what
/// it says for these adapters is rejected at wiring time, not at the first
/// question.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoutingError {
    /// Thresholds tuned under one calibration, for an adapter that reports
    /// another: its confidence does not mean what the numbers assume.
    #[error(
        "thresholds for {adapter} declare {declared:?} calibration, the adapter reports {reported:?}"
    )]
    CalibrationMismatch {
        adapter: AdapterId,
        declared: Calibration,
        reported: Calibration,
    },
    /// A pin or a threshold names an adapter the router does not hold.
    #[error("the policy names {0}, which this router does not hold")]
    UnknownAdapter(AdapterId),
    /// Measured evidence about a different pair of adapters.
    #[error("the evidence compares {cheap} with {expensive}, not this router's adapters")]
    EvidenceForOtherAdapters {
        cheap: AdapterId,
        expensive: AdapterId,
    },
}

/// Why a question went where it went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteReason {
    /// [`RoutingMode::Off`].
    RoutingOff,
    /// [`RoutingMode::Pinned`].
    Pinned,
    /// No [`Thresholds`] for the cheap adapter.
    NoCalibration,
    /// The evidence has no such kind.
    NoMeasurement,
    /// Fewer measured questions than `min_questions` at the thresholds.
    NotMeasuredEnough,
    /// Measured disagreement above `max_disagreement_rate`.
    DisagreementTooHigh,
    /// Trusted, and the cheap answer cleared the thresholds.
    CheapAccepted,
    /// Trusted, but the cheap answer's confidence was below the minimum.
    EscalatedLowConfidence,
    /// Trusted, but the cheap answer's top-two margin was below the minimum.
    EscalatedNarrowMargin,
    /// Trusted, but the cheap adapter failed or left the question out.
    EscalatedCheapFailed,
}

/// One answer, with who gave it and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Routed {
    pub adapter: AdapterId,
    pub reason: RouteReason,
    pub answer: Answer,
}

/// Serves the expensive adapter's answers, unchanged, and asks the cheap
/// one the same questions to measure agreement. The cheap adapter cannot
/// change or fail a result: its errors are logged, recorded and counted as
/// skipped.
///
/// Both adapters are asked concurrently, on the caller's task, and the call
/// returns when both have: its latency is the slower of the two, not the
/// sum. A cheap call that stalls still holds the shadowed call, so the
/// cheap adapter must enforce its own deadline. When the expensive adapter
/// fails, its error is the call's; the cheap call is still recorded.
///
/// [`profile`](Classifier::profile) is the expensive adapter's: every
/// answer returned is its.
pub struct ShadowClassifier {
    cheap: (AdapterId, Arc<dyn Classifier>),
    expensive: (AdapterId, Arc<dyn Classifier>),
    accounting: Accounting,
    log: AgreementLog,
}

impl ShadowClassifier {
    /// A shadow measuring `cheap` against `expensive`.
    #[must_use]
    pub fn new(
        cheap: (AdapterId, Arc<dyn Classifier>),
        expensive: (AdapterId, Arc<dyn Classifier>),
        accounting: Accounting,
    ) -> Self {
        let log = AgreementLog::new(cheap.0.clone(), expensive.0.clone());
        Self {
            cheap,
            expensive,
            accounting,
            log,
        }
    }

    /// The agreement measured so far — ungraded, since live traffic has no
    /// ground truth.
    #[must_use]
    pub fn report(&self) -> AgreementReport {
        self.log.report()
    }
}

/// Drives both futures on the caller's task until both finish — core
/// cannot spawn — so the pair takes as long as the slower of the two.
async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (std::pin::pin!(a), std::pin::pin!(b));
    let (mut done_a, mut done_b) = (None, None);
    std::future::poll_fn(|cx| {
        if done_a.is_none()
            && let Poll::Ready(out) = a.as_mut().poll(cx)
        {
            done_a = Some(out);
        }
        if done_b.is_none()
            && let Poll::Ready(out) = b.as_mut().poll(cx)
        {
            done_b = Some(out);
        }
        match (done_a.take(), done_b.take()) {
            (Some(a), Some(b)) => Poll::Ready((a, b)),
            (a, b) => {
                (done_a, done_b) = (a, b);
                Poll::Pending
            }
        }
    })
    .await
}

#[async_trait]
impl Classifier for ShadowClassifier {
    fn profile(&self) -> ClassifierProfile {
        self.expensive.1.profile()
    }

    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        let (dear_id, dear) = &self.expensive;
        let (cheap_id, cheap) = &self.cheap;
        let serve = async {
            let answers = dear.ask(state, questions).await;
            let answered = answers.as_ref().ok();
            let profile = dear.profile();
            self.accounting.record(
                dear_id,
                &profile,
                state,
                questions,
                answered,
                CallRole::Served,
            );
            answers
        };
        let measure = async {
            let answers = cheap.ask(state, questions).await;
            let answered = answers.as_ref().ok();
            let profile = cheap.profile();
            self.accounting.record(
                cheap_id,
                &profile,
                state,
                questions,
                answered,
                CallRole::Shadow,
            );
            answers
        };
        let (served, shadow) = join(serve, measure).await;
        if let Err(err) = &shadow {
            tracing::debug!(adapter = %cheap_id, error = %err, "shadow classifier failed");
        }
        let served = match served {
            Ok(answers) => answers,
            Err(err) => {
                compare(&self.log, questions, None, None, &BTreeMap::new(), None);
                return Err(err);
            }
        };
        compare(
            &self.log,
            questions,
            shadow.as_ref().ok(),
            Some(&served),
            &BTreeMap::new(),
            None,
        );
        Ok(served)
    }
}

/// Sends each question to the cheap adapter when its kind has earned it
/// and to the expensive adapter otherwise; see [`RoutingPolicy`].
///
/// Under [`RoutingMode::Measured`], one call:
///
/// 1. asks the cheap adapter the trusted kinds, in one batch;
/// 2. accepts each cheap answer that clears its [`Thresholds`];
/// 3. asks the expensive adapter, in one second batch, the untrusted kinds
///    plus every cheap answer that did not clear — or all the trusted ones
///    if the cheap adapter failed;
/// 4. merges both under the ids asked.
///
/// An empty or malformed question set is rejected first, as the adapters
/// reject it. An expensive failure is the call's error.
/// [`ask_routed`](Self::ask_routed) says who answered each question and
/// why; [`ask`](Classifier::ask) returns the answers alone.
///
/// **Measured answers mix confidence scales.** In measured mode one call's
/// answers can come from both adapters, and each answer's
/// [`Answer::confidence`] is on its own adapter's scale. A caller that
/// thresholds confidence must use [`ask_routed`](Self::ask_routed) and
/// threshold per [`Routed::adapter`], not the merged map `ask` returns.
///
/// [`profile`](Classifier::profile): off, the expensive adapter's; pinned,
/// the pinned adapter's; measured, the expensive adapter's
/// [`Calibration`] — a cheap answer is only served where it was measured
/// to agree with the expensive one — and the smaller of the two
/// `max_state_chars`, the least state any answer may have seen. In
/// measured mode that calibration describes the expensive answers only;
/// see above.
pub struct RoutingClassifier {
    cheap: (AdapterId, Arc<dyn Classifier>),
    expensive: (AdapterId, Arc<dyn Classifier>),
    policy: RoutingPolicy,
    accounting: Accounting,
}

impl RoutingClassifier {
    /// A router over `cheap` and `expensive`.
    ///
    /// # Errors
    ///
    /// [`RoutingError`] when the policy pins or thresholds an adapter the
    /// router does not hold, declares a calibration an adapter does not
    /// report, or (measured) carries evidence about other adapters.
    pub fn new(
        cheap: (AdapterId, Arc<dyn Classifier>),
        expensive: (AdapterId, Arc<dyn Classifier>),
        policy: RoutingPolicy,
        accounting: Accounting,
    ) -> Result<Self, RoutingError> {
        let held = |id: &AdapterId| {
            [&cheap, &expensive]
                .into_iter()
                .find(|(held, _)| held == id)
        };
        if let RoutingMode::Pinned(id) = &policy.mode
            && held(id).is_none()
        {
            return Err(RoutingError::UnknownAdapter(id.clone()));
        }
        for (id, t) in &policy.thresholds {
            let (_, adapter) = held(id).ok_or_else(|| RoutingError::UnknownAdapter(id.clone()))?;
            let reported = adapter.profile().calibration;
            if reported != t.calibration {
                return Err(RoutingError::CalibrationMismatch {
                    adapter: id.clone(),
                    declared: t.calibration,
                    reported,
                });
            }
        }
        if policy.mode == RoutingMode::Measured
            && let Some(e) = &policy.evidence
            && (e.cheap != cheap.0 || e.expensive != expensive.0)
        {
            return Err(RoutingError::EvidenceForOtherAdapters {
                cheap: e.cheap.clone(),
                expensive: e.expensive.clone(),
            });
        }
        Ok(Self {
            cheap,
            expensive,
            policy,
            accounting,
        })
    }

    /// Asks `questions` and says, per answer, which adapter gave it and why.
    ///
    /// # Errors
    ///
    /// The serving adapter's [`ClassifierError`]: the expensive one's, the
    /// pinned one's, or the expensive escalation's. A cheap failure under
    /// [`RoutingMode::Measured`] escalates instead.
    pub async fn ask_routed(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Routed>, ClassifierError> {
        let (target, reason) = match &self.policy.mode {
            RoutingMode::Measured => return self.ask_measured(state, questions).await,
            RoutingMode::Off => (&self.expensive, RouteReason::RoutingOff),
            RoutingMode::Pinned(id) if *id == self.cheap.0 => (&self.cheap, RouteReason::Pinned),
            RoutingMode::Pinned(_) => (&self.expensive, RouteReason::Pinned),
        };
        let answers = target.1.ask(state, questions).await;
        self.accounting.record(
            &target.0,
            &target.1.profile(),
            state,
            questions,
            answers.as_ref().ok(),
            CallRole::Served,
        );
        Ok(answers?
            .into_iter()
            .map(|(id, answer)| {
                (
                    id,
                    Routed {
                        adapter: target.0.clone(),
                        reason,
                        answer,
                    },
                )
            })
            .collect())
    }

    async fn ask_measured(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Routed>, ClassifierError> {
        validate_questions(questions)?;
        let (cheap_id, cheap) = &self.cheap;
        let (dear_id, dear) = &self.expensive;
        let thresholds = self.policy.thresholds.get(cheap_id);

        let mut to_cheap = BTreeMap::new();
        let mut to_dear = BTreeMap::new();
        let mut reasons = BTreeMap::new();
        for (id, question) in questions {
            let kind = QuestionKind::new(id.as_str());
            if let Some(reason) = self.policy.distrust(&kind, thresholds) {
                reasons.insert(id.clone(), reason);
                to_dear.insert(id.clone(), question.clone());
            } else {
                to_cheap.insert(id.clone(), question.clone());
            }
        }

        let mut routed = BTreeMap::new();
        if let Some(t) = thresholds.filter(|_| !to_cheap.is_empty()) {
            let answers = cheap.ask(state, &to_cheap).await;
            if let Err(err) = &answers {
                tracing::debug!(adapter = %cheap_id, error = %err, "cheap classifier failed; escalating");
            }
            for (id, question) in &to_cheap {
                let answer = answers.as_ref().ok().and_then(|a| a.get(id));
                match (judge(answer, t), answer) {
                    (RouteReason::CheapAccepted, Some(answer)) => {
                        let reason = RouteReason::CheapAccepted;
                        let adapter = cheap_id.clone();
                        let answer = answer.clone();
                        routed.insert(
                            id.clone(),
                            Routed {
                                adapter,
                                reason,
                                answer,
                            },
                        );
                    }
                    (reason, _) => {
                        reasons.insert(id.clone(), reason);
                        to_dear.insert(id.clone(), question.clone());
                    }
                }
            }
            // Recorded as soon as it returns, so a caller that drops the
            // future during the escalation does not lose what it cost.
            let role = if routed.is_empty() {
                CallRole::Discarded
            } else {
                CallRole::Served
            };
            let answered = answers.as_ref().ok();
            let profile = cheap.profile();
            self.accounting
                .record(cheap_id, &profile, state, &to_cheap, answered, role);
        }

        if !to_dear.is_empty() {
            let answers = dear.ask(state, &to_dear).await;
            self.accounting.record(
                dear_id,
                &dear.profile(),
                state,
                &to_dear,
                answers.as_ref().ok(),
                CallRole::Served,
            );
            for (id, answer) in answers? {
                if let Some(&reason) = reasons.get(&id) {
                    let adapter = dear_id.clone();
                    routed.insert(
                        id,
                        Routed {
                            adapter,
                            reason,
                            answer,
                        },
                    );
                }
            }
        }
        Ok(routed)
    }
}

/// Whether a trusted kind's cheap answer is served, or why it escalates.
/// The comparisons are in the positive, so a NaN never clears.
fn judge(answer: Option<&Answer>, t: &Thresholds) -> RouteReason {
    let Some(answer) = answer else {
        return RouteReason::EscalatedCheapFailed;
    };
    let confident = answer.confidence >= t.min_confidence;
    let decisive = answer_margin(answer) >= t.min_margin;
    if !confident {
        RouteReason::EscalatedLowConfidence
    } else if !decisive {
        RouteReason::EscalatedNarrowMargin
    } else {
        RouteReason::CheapAccepted
    }
}

#[async_trait]
impl Classifier for RoutingClassifier {
    /// See [`RoutingClassifier`]: in measured mode the calibration is the
    /// expensive adapter's, and cheap answers are on the cheap adapter's
    /// scale.
    fn profile(&self) -> ClassifierProfile {
        match &self.policy.mode {
            RoutingMode::Pinned(id) if *id == self.cheap.0 => self.cheap.1.profile(),
            RoutingMode::Off | RoutingMode::Pinned(_) => self.expensive.1.profile(),
            RoutingMode::Measured => {
                let (cheap, dear) = (self.cheap.1.profile(), self.expensive.1.profile());
                ClassifierProfile::new(
                    dear.calibration,
                    cheap.max_state_chars.min(dear.max_state_chars),
                )
            }
        }
    }

    /// The answers of [`ask_routed`](RoutingClassifier::ask_routed) without
    /// who gave them. In measured mode they mix adapters' confidence
    /// scales: threshold confidence through `ask_routed`, per adapter.
    async fn ask(
        &self,
        state: &str,
        questions: &BTreeMap<String, Question>,
    ) -> Result<BTreeMap<String, Answer>, ClassifierError> {
        let routed = self.ask_routed(state, questions).await?;
        Ok(routed.into_iter().map(|(id, r)| (id, r.answer)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_noul_probability_escalates_on_its_unreported_complement() {
        // {"true": 0.55} leaves 0.45 unreported: the margin is 0.10, not
        // 0.55, so a 0.3 minimum margin escalates it.
        let answer = Answer::noul(true, BTreeMap::from([("true".to_owned(), 0.55)]));
        let t = Thresholds {
            calibration: Calibration::Classifier,
            min_confidence: 0.5,
            min_margin: 0.3,
        };
        assert_eq!(judge(Some(&answer), &t), RouteReason::EscalatedNarrowMargin);
        let lenient = Thresholds {
            min_margin: 0.05,
            ..t
        };
        assert_eq!(judge(Some(&answer), &lenient), RouteReason::CheapAccepted);
        assert_eq!(judge(None, &t), RouteReason::EscalatedCheapFailed);
    }
}
