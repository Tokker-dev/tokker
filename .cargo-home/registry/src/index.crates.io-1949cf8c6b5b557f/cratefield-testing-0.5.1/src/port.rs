//! Port-only conformance helpers (issue #201): checks over a single port
//! trait that need nothing beyond `cratefield-core`. Gated behind the
//! light `port-conformance` feature so an adapter whose whole use of the
//! kit is one free function does not pay for the harness, the router or
//! a database adapter.
//!
//! The helpers that grew heavier stayed in [`crate::conformance`]
//! (behind `harness`): the module suite needs the `TestHarness`, and the
//! fakes were left there too because `FakeHttpClient` reads axum bodies.

use std::collections::BTreeMap;

use cratefield_core::{
    Answer, AnswerValue, Classifier, ClassifierError, ImageLimit, ImageMediaType,
    MAX_IMAGE_ENCODED_BYTES, MAX_PROMPT_IMAGE_ENCODED_BYTES, MAX_PROMPT_IMAGES, ModelTier, Part,
    Prompt, PushError, Question, TextModel, TextModelError, encoded_image_len, validate_questions,
};

/// The three recipients an adapter can be handed, one per transport.
///
/// Every `Recipient` variant appears here, so a new transport added to the
/// port makes this list — and therefore every adapter's conformance run —
/// fail to compile until it is decided what the existing adapters answer.
fn every_recipient() -> Vec<cratefield_core::Recipient> {
    let all = [
        cratefield_core::Recipient::apns("conformance-device-token"),
        cratefield_core::Recipient::fcm("conformance-registration-token"),
        cratefield_core::Recipient::web_push(
            "https://push.example.test/conformance",
            "BConformanceP256dhKey",
            "ConformanceAuthKey",
        ),
    ];
    for recipient in &all {
        // Exhaustive by construction: adding a variant breaks this match.
        match recipient {
            cratefield_core::Recipient::Apns { .. }
            | cratefield_core::Recipient::Fcm { .. }
            | cratefield_core::Recipient::WebPush { .. } => {}
        }
    }
    all.to_vec()
}

/// Runs a [`Push`](cratefield_core::Push) adapter against **every**
/// [`Recipient`](cratefield_core::Recipient) variant and asserts the port's
/// contract for transports it does not serve (issue #177): a clean
/// [`PushError::Rejected`](cratefield_core::PushError::Rejected) naming the
/// recipient as unsupported — never a panic, never a silent success, and
/// never a `Transient` that an outbox would retry forever.
///
/// `serves` lists the transports this adapter does speak; those must answer
/// something other than an unsupported-recipient rejection.
///
/// ```rust,ignore
/// // The APNs adapter serves iOS and nothing else.
/// push_recipient_conformance(&apns, &[Platform::Ios]).await;
/// ```
///
/// # Panics
///
/// Panics with the failing recipient named when the contract is broken.
pub async fn push_recipient_conformance(
    push: &dyn cratefield_core::Push,
    serves: &[cratefield_core::Platform],
) {
    let notification = cratefield_core::Notification::new("conformance", "probe");
    for recipient in every_recipient() {
        let platform = recipient.platform();
        let result = push.send(&recipient, &notification).await;
        let unsupported = matches!(
            &result,
            Err(PushError::Rejected(message)) if message.contains("unsupported recipient")
        );
        if serves.contains(&platform) {
            assert!(
                !unsupported,
                "adapter claims to serve {platform} but rejected its recipient as unsupported"
            );
        } else {
            assert!(
                unsupported,
                "adapter does not serve {platform}: the port's answer is \
                 PushError::Rejected(\"unsupported recipient…\"), got {result:?}"
            );
        }
    }
}

/// Asserts the named crate's normal dependency tree carries none of the
/// dependencies a wasm module must never see: `worker`, `wasm-bindgen`,
/// `tokio`, `reqwest`. Shell-out check (`cargo tree --edges normal`) so
/// the assertion is made against the graph cargo actually resolves, not
/// a copy of it that could drift.
///
/// # Panics
///
/// Panics when a forbidden dependency is found or cargo fails.
pub fn assert_wasm_safe_deps(module_crate: &str) {
    let output =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["tree", "-p", module_crate, "--edges", "normal"])
            .output()
            .unwrap_or_else(|err| panic!("cargo tree failed: {err}"));
    assert!(
        output.status.success(),
        "cargo tree failed for {module_crate}"
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    for forbidden in ["worker v", "wasm-bindgen v", "tokio v", "reqwest v"] {
        assert!(
            !tree.contains(forbidden),
            "{module_crate} pulls forbidden dependency `{}`:\n{tree}",
            forbidden.trim_end_matches(" v")
        );
    }
}

// ---------------------------------------------------------------------------
// The `Classifier` port suite (issue #456)

/// How far a reported `confidence` may sit from the probability the same
/// answer reports for its own chosen label and still count as agreeing
/// (`f32` arithmetic across an adapter's normalisation is not exact).
const CONFIDENCE_TOLERANCE: f32 = 1e-4;

/// The canonical question set the conformance suite asks: one
/// [`Question::Choice`], one [`Question::Score`], one [`Question::Noul`],
/// so every shape of the port is exercised once. The ids are fixed —
/// `topic`, `severity`, `urgent` — and an adapter test scripts its
/// transport to answer **exactly these** before running the suite.
#[must_use]
pub fn classifier_conformance_questions() -> BTreeMap<String, Question> {
    BTreeMap::from([
        (
            "topic".to_owned(),
            Question::Choice {
                instructions: "Which topic does the state belong to?".to_owned(),
                criteria: BTreeMap::from([
                    ("billing".to_owned(), "money, invoices".to_owned()),
                    ("bugs".to_owned(), "something is broken".to_owned()),
                ]),
            },
        ),
        (
            "severity".to_owned(),
            Question::Score {
                instructions: "How severe is the state?".to_owned(),
                levels: vec![
                    ("1".to_owned(), "a typo".to_owned()),
                    ("5".to_owned(), "data loss".to_owned()),
                ],
            },
        ),
        (
            "urgent".to_owned(),
            Question::Noul {
                instructions: "Does the state need attention now?".to_owned(),
            },
        ),
    ])
}

/// The state the conformance suite asks about: short and fixed, so a
/// scripted transport can match it.
#[must_use]
pub fn classifier_conformance_state() -> &'static str {
    "cratefield classifier conformance state"
}

/// Asserts one answer agrees with the question it answers. The rules are
/// numbered as `classifier_conformance` documents them, and every panic
/// names the rule it caught.
fn assert_answer_conforms(id: &str, question: &Question, answer: &Answer) {
    let labels = question.labels();

    // Rule 2: the value's variant matches the question's kind.
    let chosen: Option<String> = match (question, &answer.value) {
        (Question::Choice { .. }, AnswerValue::Choice(label)) => {
            // Rule 3: the chosen label is one the question offered.
            assert!(
                labels.contains(&label.as_str()),
                "rule 3 (a choice is of an offered label): question {id:?} offers {labels:?}, \
                 the answer chose {label:?}"
            );
            Some(label.clone())
        }
        (Question::Score { .. }, AnswerValue::Score(value)) => {
            // Rule 3, as far as the port can express it: a score whose
            // value names one of the levels names it as its label. A
            // provider that interpolates (`3.5` on a `"1"`/`"5"` scale)
            // states its confidence through `Answer::new` instead, and no
            // chosen label is assertable there.
            let label = value.to_string();
            if labels.contains(&label.as_str()) {
                Some(label)
            } else {
                None
            }
        }
        (Question::Noul { .. }, AnswerValue::Noul(verdict)) => {
            Some(if *verdict { "true" } else { "false" }.to_owned())
        }
        (kind, value) => panic!(
            "rule 2 (the answer's shape matches the question's): question {id:?} is {}, \
             the answer carried {value:?}",
            kind.kind()
        ),
    };

    // Rule 4: every probability is keyed by an offered label, and is a
    // finite number within 0.0..=1.0. Keys are a subset on purpose: the
    // port allows a provider that reports only a top-1.
    for (label, probability) in &answer.probabilities {
        assert!(
            labels.contains(&label.as_str()),
            "rule 4 (probabilities are keyed by offered labels): question {id:?} offers \
             {labels:?}, the answer reported {label:?}"
        );
        assert!(
            probability.is_finite() && (0.0..=1.0).contains(probability),
            "rule 4 (a probability is finite and within 0.0..=1.0): question {id:?} reported \
             {label:?} = {probability}"
        );
    }

    // Rule 5: `confidence` is finite, within 0.0..=1.0, and agrees with
    // the probability the same answer reports for its own chosen label.
    assert!(
        answer.confidence.is_finite() && (0.0..=1.0).contains(&answer.confidence),
        "rule 5 (a confidence is finite and within 0.0..=1.0): question {id:?} reported \
         confidence {}",
        answer.confidence
    );
    if let Some(label) = chosen {
        match answer.probabilities.get(&label) {
            Some(probability) => assert!(
                (answer.confidence - probability).abs() <= CONFIDENCE_TOLERANCE,
                "rule 5 (confidence agrees with the distribution for the chosen label): \
                 question {id:?} chose {label:?} at {probability} but reported confidence {}",
                answer.confidence
            ),
            // An absent label is the port constructors' 0.0: consistent
            // only when the confidence says the same.
            None => assert!(
                answer.confidence.abs() <= CONFIDENCE_TOLERANCE,
                "rule 5 (confidence agrees with the distribution for the chosen label): \
                 question {id:?} chose {label:?}, which its probabilities omit, so the only \
                 agreeing confidence is 0.0, got {}",
                answer.confidence
            ),
        }
    }
}

/// Asserts the `Classifier` trait contract against a classifier whose
/// transport is already scripted to answer
/// [`classifier_conformance_questions`] about
/// [`classifier_conformance_state`]. The suite makes **exactly one**
/// `ask` call — script that one request and no other.
///
/// Asserted, each panic naming the rule it caught:
///
/// 1. the answer map's keys are **exactly** the asked question ids;
/// 2. each answer's `value` variant matches its question's kind;
/// 3. a choice's chosen label, a noul's verdict label, and (where the
///    value names one) a score's level are labels the question offered;
/// 4. every key of `probabilities` is an offered label and every value is
///    finite within `0.0..=1.0` — keys may omit labels (a top-1 provider
///    is legal), they may never invent one;
/// 5. `confidence` is finite within `0.0..=1.0` and agrees with the
///    probability the same answer reports for its own chosen label,
///    within an explicit tolerance — the invariant that keeps an adapter
///    from reporting a confidence its own distribution contradicts;
/// 6. `profile().max_state_chars` is above zero, and `truncate` of an
///    over-limit state returns something no longer than the limit.
///
/// What the suite deliberately does **not** assert: that `confidence`
/// means the same number on two adapters. Calibration is not portable —
/// a `0.8` from a purpose-trained classifier and a `0.8` elicited from a
/// general language model are different numbers — so no assertion here
/// compares confidence values between adapters, and a threshold tuned
/// against one stays per-adapter (see `cratefield_core::Calibration`).
///
/// ```rust,ignore
/// // In the adapter's own test, after scripting its transport:
/// classifier_conformance(&adapter).await;
/// ```
///
/// # Panics
///
/// Panics naming the broken rule when the contract is violated, and when
/// the scripted ask fails.
pub async fn classifier_conformance(classifier: &dyn Classifier) {
    // Rule 6: the profile is usable and `truncate` honours its own limit,
    // in both directions. Needs no transport.
    let profile = classifier.profile();
    assert!(
        profile.max_state_chars > 0,
        "rule 6 (the state ceiling is above zero): max_state_chars is {}",
        profile.max_state_chars
    );
    let over_limit = "x".repeat(profile.max_state_chars + 1);
    let (sent, dropped) = profile.truncate(&over_limit);
    assert!(
        dropped,
        "rule 6 (truncate reports what it dropped): a state over the limit came back \
         with dropped = false"
    );
    assert!(
        sent.len() <= profile.max_state_chars,
        "rule 6 (truncate honours the limit): a state of {} chars came back as {} over a \
         limit of {}",
        over_limit.len(),
        sent.len(),
        profile.max_state_chars
    );
    let (untouched, dropped) = profile.truncate(classifier_conformance_state());
    assert!(
        !dropped && untouched == classifier_conformance_state(),
        "rule 6 (truncate is a no-op under the limit): the canonical state was trimmed"
    );

    // The one ask the suite makes.
    let questions = classifier_conformance_questions();
    let answers = classifier
        .ask(classifier_conformance_state(), &questions)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "the scripted ask failed — script the transport to answer \
                 classifier_conformance_questions() about classifier_conformance_state(): \
                 {error:?}"
            )
        });

    // Rule 1: the keys are exactly the asked ids — no missing, no extra.
    let missing: Vec<&String> = questions
        .keys()
        .filter(|id| !answers.contains_key(*id))
        .collect();
    let extra: Vec<&String> = answers
        .keys()
        .filter(|id| !questions.contains_key(*id))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "rule 1 (the answers are keyed exactly as the questions were asked): missing \
         {missing:?}, extra {extra:?}"
    );

    // Rules 2-5, per question.
    for (id, question) in &questions {
        assert_answer_conforms(id, question, &answers[id]);
    }
}

/// Asserts the contract that needs no transport: a malformed question set
/// — empty, blank id, blank instructions, a one-criterion choice, a
/// one-level score — comes back as
/// [`ClassifierError::Rejected`](cratefield_core::ClassifierError::Rejected)
/// and never panics. Safe to run against an unconfigured adapter: the
/// set is refused before any provider is reached.
///
/// # Panics
///
/// Panics when a malformed set is answered, or refused as anything but
/// `Rejected`.
pub async fn classifier_rejects_malformed_questions(classifier: &dyn Classifier) {
    let malformed: [BTreeMap<String, Question>; 5] = [
        BTreeMap::new(),
        BTreeMap::from([(
            "   ".to_owned(),
            Question::Noul {
                instructions: "A blank id is malformed.".to_owned(),
            },
        )]),
        BTreeMap::from([(
            "blank-instructions".to_owned(),
            Question::Noul {
                instructions: "  ".to_owned(),
            },
        )]),
        BTreeMap::from([(
            "one-criterion".to_owned(),
            Question::Choice {
                instructions: "A choice needs two criteria.".to_owned(),
                criteria: BTreeMap::from([("only".to_owned(), "the only one".to_owned())]),
            },
        )]),
        BTreeMap::from([(
            "one-level".to_owned(),
            Question::Score {
                instructions: "A score needs two levels.".to_owned(),
                levels: vec![("3".to_owned(), "middling".to_owned())],
            },
        )]),
    ];
    for questions in &malformed {
        // The port's own validator refuses these five; if it ever stops
        // to, this suite's list has to change with it — the guard keeps
        // the check from passing vacuously.
        assert!(
            validate_questions(questions).is_err(),
            "the suite's malformed sets stopped being malformed — update this suite \
             alongside cratefield_core::validate_questions"
        );
        let result = classifier
            .ask(classifier_conformance_state(), questions)
            .await;
        assert!(
            matches!(result, Err(ClassifierError::Rejected(_))),
            "a malformed question set is Rejected, never a panic and never an answer: got \
             {result:?}"
        );
    }
}

/// Asserts an adapter with no key, binding or model behind it answers
/// [`ClassifierError::NotConfigured`](cratefield_core::ClassifierError::NotConfigured)
/// rather than panicking — the unwired port is an error the caller
/// matches, so a module can degrade on it.
///
/// # Panics
///
/// Panics when the ask succeeds or fails as anything but `NotConfigured`.
pub async fn classifier_not_configured(classifier: &dyn Classifier) {
    let result = classifier
        .ask(
            classifier_conformance_state(),
            &classifier_conformance_questions(),
        )
        .await;
    assert_eq!(
        result.err(),
        Some(ClassifierError::NotConfigured),
        "an adapter with no key/binding/model answers NotConfigured"
    );
}

// ---------------------------------------------------------------------------
// The `VectorIndex` port suite (issue #561)

/// How far a reported `score` may sit from the exact cosine similarity and
/// still count as agreeing (`f32` arithmetic differs across adapters).
const SCORE_TOLERANCE: f32 = 1.0e-3;

use cratefield_core::{VectorFilter, VectorMatch, VectorNamespace, VectorRecord};

/// Asserts the [`VectorIndex`](cratefield_core::VectorIndex) contract
/// against an adapter, over small three-dimensional vectors (issue #561):
///
/// 1. ranking is cosine similarity descending, and a vector is most
///    similar to itself;
/// 2. `k` is a limit, not a target — at most `k` matches, none for `k = 0`;
/// 3. an equality filter keeps only the records whose metadata equals it
///    on **every** key, and metadata round-trips byte for byte;
/// 4. namespaces are isolated: the same id upserted into two namespaces
///    stays two records, and a delete in one cannot touch the other;
/// 5. an upsert replaces the whole record — values and metadata, no merge;
/// 6. a delete removes, and deleting a missing id answers `Ok`.
///
/// Writes into the namespaces `conformance` and `conformance-other` and
/// deletes what it wrote, so run it against a fresh or disposable index.
///
/// # Panics
///
/// Panics naming the broken rule when the contract is violated.
pub async fn vector_index_conformance(index: &dyn cratefield_core::VectorIndex) {
    let ns = VectorNamespace::new("conformance").expect("the suite namespace is valid");
    let other = VectorNamespace::new("conformance-other").expect("the other namespace is valid");
    vector_orders_filters_and_limits(index, &ns).await;
    vector_isolates_replaces_and_deletes(index, &ns, &other).await;
}

/// The suite's `query`, asserted to answer.
async fn vector_matches(
    index: &dyn cratefield_core::VectorIndex,
    ns: &VectorNamespace,
    vector: &[f32],
    k: usize,
    filter: &VectorFilter,
) -> Vec<VectorMatch> {
    index
        .query(ns, vector, k, filter)
        .await
        .expect("the scripted query answers")
}

/// Rules 1-3: nearest-first ordering, `k` as a limit, the every-key
/// equality filter, and a byte-for-byte metadata round trip.
async fn vector_orders_filters_and_limits(
    index: &dyn cratefield_core::VectorIndex,
    ns: &VectorNamespace,
) {
    let all = VectorFilter::new();
    index
        .upsert(
            ns,
            &[
                VectorRecord::new("east", vec![1.0, 0.0, 0.0]),
                VectorRecord::new("north", vec![0.0, 1.0, 0.0]),
                VectorRecord::new("diagonal", vec![1.0, 1.0, 0.0]),
            ],
        )
        .await
        .expect("the scripted upsert answers");
    let ranked = vector_matches(index, ns, &[1.0, 0.0, 0.0], 3, &all).await;
    assert_eq!(
        ranked.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        ["east", "diagonal", "north"],
        "rule 1 (nearest first): cosine similarity must rank descending"
    );
    assert!(
        (ranked[0].score - 1.0).abs() < SCORE_TOLERANCE,
        "rule 1 (a vector is most similar to itself): got {}",
        ranked[0].score
    );
    assert_eq!(
        vector_matches(index, ns, &[1.0, 0.0, 0.0], 1, &all)
            .await
            .len(),
        1,
        "rule 2 (at most k)"
    );
    assert!(
        vector_matches(index, ns, &[1.0, 0.0, 0.0], 0, &all)
            .await
            .is_empty(),
        "rule 2 (k = 0 answers nothing)"
    );
    // `chat` is the nearer neighbour, so only the filter keeps it out.
    let doc = VectorRecord::new("doc", vec![0.9, 0.1, 0.0])
        .with_metadata("kind", serde_json::json!("doc"))
        .with_metadata("lang", serde_json::json!("en"));
    index
        .upsert(
            ns,
            &[
                doc.clone(),
                VectorRecord::new("chat", vec![0.95, 0.05, 0.0])
                    .with_metadata("kind", serde_json::json!("chat")),
            ],
        )
        .await
        .expect("the scripted upsert answers");
    let kind_doc = VectorFilter::new().eq("kind", serde_json::json!("doc"));
    let filtered = vector_matches(index, ns, &[1.0, 0.0, 0.0], 5, &kind_doc).await;
    assert_eq!(
        filtered.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        ["doc"],
        "rule 3 (the filter keeps only equality matches)"
    );
    assert_eq!(
        filtered[0].metadata, doc.metadata,
        "rule 3 (metadata round-trips byte for byte)"
    );
    assert_eq!(
        vector_matches(
            index,
            ns,
            &[1.0, 0.0, 0.0],
            5,
            &kind_doc.clone().eq("lang", serde_json::json!("en")),
        )
        .await
        .len(),
        1,
        "rule 3 (every key of the filter must match)"
    );
    assert!(
        vector_matches(
            index,
            ns,
            &[1.0, 0.0, 0.0],
            5,
            &kind_doc.eq("lang", serde_json::json!("fr")),
        )
        .await
        .is_empty(),
        "rule 3 (one mismatching key keeps nothing)"
    );
}

/// Rules 4-6: namespace isolation with the *same* id on both sides, an
/// upsert that replaces instead of merging, and idempotent deletes.
async fn vector_isolates_replaces_and_deletes(
    index: &dyn cratefield_core::VectorIndex,
    ns: &VectorNamespace,
    other: &VectorNamespace,
) {
    let all = VectorFilter::new();
    let theirs = VectorRecord::new("east", vec![0.0, 0.0, 1.0])
        .with_metadata("owner", serde_json::json!("other"));
    index
        .upsert(other, &[theirs])
        .await
        .expect("the scripted upsert answers");
    let owners_other = VectorFilter::new().eq("owner", serde_json::json!("other"));
    assert_eq!(
        vector_matches(index, other, &[0.0, 0.0, 1.0], 5, &owners_other)
            .await
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        ["east"],
        "rule 4 (the other namespace holds its own `east`)"
    );
    assert!(
        vector_matches(index, ns, &[0.0, 0.0, 1.0], 5, &owners_other)
            .await
            .is_empty(),
        "rule 4 (a query never crosses namespaces)"
    );
    index
        .upsert(
            ns,
            &[VectorRecord::new("swap", vec![1.0, 0.0, 0.0])
                .with_metadata("version", serde_json::json!(1))],
        )
        .await
        .expect("the scripted upsert answers");
    index
        .upsert(
            ns,
            &[VectorRecord::new("swap", vec![0.6, 0.8, 0.0])
                .with_metadata("version", serde_json::json!(2))],
        )
        .await
        .expect("the scripted upsert answers");
    let swap = vector_matches(index, ns, &[0.6, 0.8, 0.0], 5, &all)
        .await
        .into_iter()
        .find(|m| m.id == "swap")
        .expect("rule 5 (the replaced record is still there)");
    assert!(
        (swap.score - 1.0).abs() < SCORE_TOLERANCE,
        "rule 5 (the upsert replaced the values): got {}",
        swap.score
    );
    assert_eq!(
        swap.metadata["version"],
        serde_json::json!(2),
        "rule 5 (the upsert replaced the metadata)"
    );
    assert!(
        vector_matches(
            index,
            ns,
            &[1.0, 0.0, 0.0],
            5,
            &VectorFilter::new().eq("version", serde_json::json!(1)),
        )
        .await
        .is_empty(),
        "rule 5 (the old metadata is gone, not merged)"
    );
    index
        .delete(other, &["east".to_owned(), "never-there".to_owned()])
        .await
        .expect("rule 6 (deleting a missing id answers Ok)");
    assert!(
        vector_matches(index, other, &[0.0, 0.0, 1.0], 5, &all)
            .await
            .is_empty(),
        "rule 6 (the delete removed the record)"
    );
    assert!(
        vector_matches(index, ns, &[1.0, 0.0, 0.0], 5, &all)
            .await
            .iter()
            .any(|m| m.id == "east"),
        "rule 4 (a delete in one namespace cannot touch the other)"
    );
    // The doc's promise: every id the suite wrote, in both namespaces,
    // deleted — so a second run against a persistent index starts clean.
    let ours: Vec<String> = ["east", "north", "diagonal", "doc", "chat", "swap"]
        .into_iter()
        .map(String::from)
        .collect();
    index
        .delete(ns, &ours)
        .await
        .expect("the scripted cleanup answers");
    index
        .delete(other, &["east".to_owned()])
        .await
        .expect("the scripted cleanup answers");
}
/// Asserts that asking with a `state` longer than
/// `profile().max_state_chars` still succeeds — truncation is the
/// adapter's job, so an over-limit state must never surface as an error
/// to the caller.
///
/// A separate, opt-in check because it asks a **second** time: an
/// adapter test whose transport matches one scripted request exactly can
/// run `classifier_conformance` alone, and add this when its mock can
/// take the second call.
///
/// # Panics
///
/// Panics when the over-limit ask fails or its answers break the same
/// per-answer rules `classifier_conformance` asserts.
pub async fn classifier_truncates_long_state(classifier: &dyn Classifier) {
    let questions = classifier_conformance_questions();
    let profile = classifier.profile();
    let long_state = classifier_conformance_state().repeat(profile.max_state_chars + 1);

    let answers = classifier
        .ask(&long_state, &questions)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "an over-limit state still gets answers — truncation is the adapter's job, not \
             the caller's: {error:?}"
            )
        });
    for (id, question) in &questions {
        let answer = answers.get(id).unwrap_or_else(|| {
            panic!(
                "rule 1 (the answers are keyed exactly as the questions were asked): the \
                 over-limit ask dropped {id:?}"
            )
        });
        assert_answer_conforms(id, question, answer);
    }
}

// ---------------------------------------------------------------------------
// The `TextModel` port suite (issue #560)

/// The canonical reply the conformance suite expects, verbatim: short and
/// fixed, so an adapter test can script its transport to answer **exactly
/// this** in its vendor's wire shape.
pub const TEXT_MODEL_CONFORMANCE_REPLY: &str = "cratefield text model conformance reply";

/// The canonical input-token count: the total prompt tokens the scripted
/// transport reports. Every `TextModel` completion reports usage, so the
/// suite asserts this count exactly — an adapter whose vendor omits a
/// usage block fails here, not silently in a caller's cost accounting.
pub const TEXT_MODEL_CONFORMANCE_INPUT_TOKENS: u64 = 17;

/// The canonical output-token count the scripted transport reports.
pub const TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS: u64 = 5;

/// The canonical cached-input count: the subset of
/// [`TEXT_MODEL_CONFORMANCE_INPUT_TOKENS`] the scripted transport reports
/// serving from its vendor's prompt cache. Must stay within the input
/// count — the suite asserts that, so the script has to satisfy it.
pub const TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS: u64 = 9;

/// The canonical prompt the suite asks: one user turn, no system prompt,
/// no schema, the default token ceiling. An adapter test scripts its
/// transport to answer [`TEXT_MODEL_CONFORMANCE_REPLY`] with the canonical
/// counts ([`TEXT_MODEL_CONFORMANCE_INPUT_TOKENS`],
/// [`TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS`],
/// [`TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS`]) for this prompt.
#[must_use]
pub fn text_model_conformance_prompt() -> Prompt {
    Prompt::new(ModelTier::Fast).user("Reply with the conformance reply, exactly.")
}

/// Asserts the [`TextModel`] trait contract against a text model whose
/// transport is already scripted to complete
/// [`text_model_conformance_prompt`] with
/// [`TEXT_MODEL_CONFORMANCE_REPLY`] and the canonical counts in its
/// vendor's wire shape. The suite makes **exactly one** `complete` call —
/// script that one request and no other.
///
/// Asserted, each panic naming the rule it caught:
///
/// 1. `text` is the canonical reply, verbatim — no greeting, no chit-chat,
///    no markdown fence around it;
/// 2. `model` is non-empty — a completion names what answered, for the
///    log line;
/// 3. usage is reported on **every** completion: `input_tokens` and
///    `output_tokens` equal the scripted counts;
/// 4. `cached_input_tokens` is the scripted cache read, and never exceeds
///    `input_tokens` — the cached subset of a total cannot be larger than
///    the total;
/// 5. the prompt carried no schema, so `json` is `None`.
///
/// ```rust,ignore
/// // In the adapter's own test, after scripting its transport:
/// text_model_conformance(&model).await;
/// ```
///
/// # Panics
///
/// Panics with the failing rule named when the contract is violated, and
/// when the scripted completion fails.
pub async fn text_model_conformance(model: &dyn TextModel) {
    let prompt = text_model_conformance_prompt();
    let completion = model.complete(&prompt).await.unwrap_or_else(|error| {
        panic!(
            "the scripted completion failed — script the transport to answer \
             text_model_conformance_prompt() with TEXT_MODEL_CONFORMANCE_REPLY and the \
             canonical token counts: {error:?}"
        )
    });

    assert_eq!(
        completion.text, TEXT_MODEL_CONFORMANCE_REPLY,
        "rule 1 (the text is the scripted reply, verbatim): got {:?}",
        completion.text
    );
    assert!(
        !completion.model.is_empty(),
        "rule 2 (the completion names the model that answered): model is empty"
    );
    assert!(
        completion.input_tokens == TEXT_MODEL_CONFORMANCE_INPUT_TOKENS
            && completion.output_tokens == TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS,
        "rule 3 (every completion reports its token usage): got input {}, output {}, \
         expected {TEXT_MODEL_CONFORMANCE_INPUT_TOKENS}/{TEXT_MODEL_CONFORMANCE_OUTPUT_TOKENS}",
        completion.input_tokens,
        completion.output_tokens
    );
    assert_eq!(
        completion.cached_input_tokens,
        Some(TEXT_MODEL_CONFORMANCE_CACHED_INPUT_TOKENS),
        "rule 4 (the cached subset is reported where the vendor reports one)"
    );
    if let Some(cached) = completion.cached_input_tokens {
        assert!(
            cached <= completion.input_tokens,
            "rule 4 (the cached subset never exceeds the total it is a subset of): cached \
             {cached} over input {}",
            completion.input_tokens
        );
    }
    assert!(
        completion.json.is_none(),
        "rule 5 (a prompt that asked for no schema comes back without a parsed value): got \
         {:?}",
        completion.json
    );
}

/// Asserts an adapter with no key behind it answers
/// [`TextModelError::NotConfigured`] rather than panicking — the unwired
/// port is an error the caller matches, so a module can degrade on it.
///
/// # Panics
///
/// Panics when the completion succeeds or fails as anything but
/// `NotConfigured`.
pub async fn text_model_conformance_not_configured(model: &dyn TextModel) {
    let result = model.complete(&text_model_conformance_prompt()).await;
    assert_eq!(
        result.err(),
        Some(TextModelError::NotConfigured),
        "an adapter with no key answers NotConfigured"
    );
}

/// Asserts a [`TextModel`] adapter refuses an over-limit image prompt
/// (issue #628) **before any network call**: too many images, one image
/// over [`MAX_IMAGE_ENCODED_BYTES`], or images together over
/// [`MAX_PROMPT_IMAGE_ENCODED_BYTES`], each refused with the matching
/// [`TextModelError::ImageLimit`].
///
/// Run it over a transport that answers nothing, so a pass proves the
/// refusal happened locally rather than at the provider.
///
/// ```rust,ignore
/// text_model_image_bounds_conformance(&model).await;
/// ```
///
/// # Panics
///
/// Panics, naming the rule it caught, when a prompt over a bound is not
/// refused with exactly the expected [`ImageLimit`].
pub async fn text_model_image_bounds_conformance(model: &dyn TextModel) {
    // More images than a prompt may carry.
    let too_many = Prompt::new(ModelTier::Fast)
        .user_parts((0..=MAX_PROMPT_IMAGES).map(|_| Part::image(ImageMediaType::Png, vec![0u8])));
    assert_eq!(
        model.complete(&too_many).await.err(),
        Some(TextModelError::ImageLimit(ImageLimit::TooMany {
            count: MAX_PROMPT_IMAGES + 1,
        })),
        "more than {MAX_PROMPT_IMAGES} images is refused with TooMany, before any network call"
    );

    // One image encoding to one base64 group over the per-image ceiling.
    let over = MAX_IMAGE_ENCODED_BYTES + 4;
    let over_raw = raw_len_for_encoded(over);
    assert_eq!(encoded_image_len(over_raw), over);
    let too_large = Prompt::new(ModelTier::Fast).user_parts([
        Part::text("a caption"),
        Part::image(ImageMediaType::Png, vec![0u8; over_raw]),
    ]);
    assert_eq!(
        model.complete(&too_large).await.err(),
        Some(TextModelError::ImageLimit(ImageLimit::ImageTooLarge {
            index: 0,
            encoded_bytes: over,
        })),
        "an image over the per-image ceiling is refused with ImageTooLarge, before any network call"
    );

    // Two images just under the per-image ceiling, together over the total.
    let each = MAX_IMAGE_ENCODED_BYTES - 4;
    let each_raw = raw_len_for_encoded(each);
    assert!(2 * each > MAX_PROMPT_IMAGE_ENCODED_BYTES);
    let too_total = Prompt::new(ModelTier::Fast).user_parts([
        Part::image(ImageMediaType::Png, vec![0u8; each_raw]),
        Part::image(ImageMediaType::Jpeg, vec![0u8; each_raw]),
    ]);
    assert_eq!(
        model.complete(&too_total).await.err(),
        Some(TextModelError::ImageLimit(ImageLimit::TotalTooLarge {
            encoded_bytes: 2 * each,
        })),
        "images together over the prompt total are refused with TotalTooLarge, before any network \
         call"
    );
}

/// A raw byte length whose standard, padded base64 encoding is exactly
/// `encoded`, for `encoded` a multiple of four.
fn raw_len_for_encoded(encoded: usize) -> usize {
    (encoded / 4) * 3
}
