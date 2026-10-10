//! Integration test: runs the Rust token math against the same JSON
//! vectors as the TypeScript twin in `tools/math.ts` (issue #13).
//!
//! The vectors live in `tests/vectors/token-math.json` at the repository
//! root; assumption profiles live in `data/profiles/<profile>.json`. Both
//! are read here, in the test only — the library itself does no I/O.
//!
//! Numbers are compared with a 1e-9 absolute tolerance for safety, but the
//! vectors are generated from the same f64 operation order, so they are
//! expected to match exactly. `"unknown"` and `null` compare as `None`.

use std::collections::BTreeMap;
use std::fs;

use serde::Deserialize;
use tokker_math::{Estimate, NumOrUnknown, PlanInput, Profile, Window, estimate_for_plan};

/// The shared vectors, embedded at compile time.
const VECTORS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/vectors/token-math.json"
));

/// Directory holding the assumption profiles the vectors reference.
const PROFILES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/profiles");

/// Absolute tolerance for number comparisons (see crate docs: the ops are
/// identical, so exact equality is expected; this is belt and braces).
const TOLERANCE: f64 = 1e-9;

#[derive(Deserialize)]
struct VectorsFile {
    vectors: Vec<Vector>,
}

/// One vector: a plan, the profile to run it against, the expected result.
///
/// `notes`, `$comment` and any dataset extras are ignored.
#[derive(Deserialize)]
struct Vector {
    name: String,
    profile: String,
    plan: PlanInput,
    expected: Expected,
}

/// The expected estimate, with `"unknown"`/`null` where the dataset does
/// not publish a number.
#[derive(Deserialize)]
struct Expected {
    est_tokens_per_month: NumOrUnknown,
    #[serde(rename = "est_usd_per_mtok_at_full_use")]
    est_usd_per_mtok: NumOrUnknown,
    binding_window: Option<Window>,
    tokens_per_window: Option<NumOrUnknown>,
    tokens_per_week: Option<NumOrUnknown>,
}

#[test]
fn vectors_match_the_typescript_implementation() {
    let file: VectorsFile =
        serde_json::from_str(VECTORS_JSON).expect("tests/vectors/token-math.json must parse");
    assert!(
        !file.vectors.is_empty(),
        "the vectors file holds no vectors"
    );

    let mut profiles: BTreeMap<String, Profile> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();

    for vector in &file.vectors {
        let profile = profiles
            .entry(vector.profile.clone())
            .or_insert_with(|| load_profile(&vector.profile));
        assert_eq!(
            profile.id, vector.profile,
            "profile {} must carry its file name as id",
            vector.profile,
        );

        let computed = estimate_for_plan(&vector.plan, profile);
        let expected = &vector.expected;

        check(
            &mut failures,
            &vector.name,
            "est_tokens_per_month",
            computed.est_tokens_per_month,
            expected.est_tokens_per_month.number(),
        );
        check(
            &mut failures,
            &vector.name,
            "est_usd_per_mtok_at_full_use",
            computed.est_usd_per_mtok_at_full_use,
            expected.est_usd_per_mtok.number(),
        );
        check(
            &mut failures,
            &vector.name,
            "tokens_per_window",
            computed.tokens_per_window,
            expected.tokens_per_window.and_then(NumOrUnknown::number),
        );
        check(
            &mut failures,
            &vector.name,
            "tokens_per_week",
            computed.tokens_per_week,
            expected.tokens_per_week.and_then(NumOrUnknown::number),
        );
        if computed.binding_window != expected.binding_window {
            failures.push(format!(
                "{}: binding_window computed {:?} != expected {:?}",
                vector.name, computed.binding_window, expected.binding_window
            ));
        }
        consistency_check(
            &mut failures,
            &vector.name,
            &computed,
            vector.plan.price_usd_per_month,
        );
    }

    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n{}",
        failures.len(),
        file.vectors.len(),
        failures.join("\n")
    );
}

/// Records one failed field as a one-line summary.
fn check(
    failures: &mut Vec<String>,
    name: &str,
    field: &str,
    computed: Option<f64>,
    expected: Option<f64>,
) {
    let ok = match (computed, expected) {
        (Some(computed), Some(expected)) => (computed - expected).abs() <= TOLERANCE,
        (None, None) => true,
        _ => false,
    };
    if !ok {
        failures.push(format!(
            "{name}: {field} computed {computed:?} != expected {expected:?}"
        ));
    }
}

/// Cross-checks `est_usd_per_mtok_at_full_use` against
/// `round4(price / est_tokens_per_month * 1e6)` for computable vectors.
///
/// The library derives the value from the *unrounded* token minimum while
/// this recomputation has only the rounded one, so allow a single
/// fourth-decimal step of slack (1.5e-4) instead of the exact 1e-9.
fn consistency_check(
    failures: &mut Vec<String>,
    name: &str,
    computed: &Estimate,
    price: NumOrUnknown,
) {
    let (Some(tokens), Some(usd)) = (
        computed.est_tokens_per_month,
        computed.est_usd_per_mtok_at_full_use,
    ) else {
        return;
    };
    let Some(price) = price.number() else {
        return;
    };
    let implied = ((price / tokens * 1e6) * 10_000.0).round() / 10_000.0;
    if (usd - implied).abs() > 1.5e-4 {
        failures.push(format!(
            "{name}: consistency computed {usd} != implied {implied} \
             (round4(price / est_tokens_per_month * 1e6))"
        ));
    }
}

/// Reads and parses one profile from `data/profiles/<name>.json`.
fn load_profile(name: &str) -> Profile {
    let path = format!("{PROFILES_DIR}/{name}.json");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read profile {path}: {error}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("cannot parse profile {path}: {error}"))
}
