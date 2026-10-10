//! Subscription token math for Tokker (issue #13).
//!
//! This crate turns a subscription plan's published limits — "N requests
//! per 5 hours", "M credits a month", "$X a month" — into:
//!
//! * an estimated monthly token budget at full use
//!   ([`Estimate::est_tokens_per_month`]), and
//! * the implied USD price per million tokens at that use level
//!   ([`Estimate::est_usd_per_mtok_at_full_use`]).
//!
//! It is the pure Rust twin of `tools/math.ts`: both sides run the same
//! formulas **in the same f64 operation order** and are tested against the
//! same vectors in `tests/vectors/token-math.json`. The operation order in
//! [`profile_cost_per_call`] and the estimate path is load-bearing — do not
//! "simplify" it, or the two implementations drift apart.
//!
//! # The "unknown" policy
//!
//! The product is trust (`CLAUDE.md`, data rule 1): a vendor that publishes
//! no cap yields no number, never an invented one. Wherever the dataset says
//! `"unknown"` (or `null`), every estimate field is [`None`] — [`Estimate`]
//! documents the mapping per field. Plans labelled
//! `confidence: "secondary"` are never estimated at all. Off-peak
//! multipliers are never applied.
//!
//! # Inputs
//!
//! A [`Profile`] is a published, versioned assumption profile (the default
//! is `agentic-coding-v1`) that converts published prompts, requests,
//! messages or credits into tokens. Profiles are immutable inputs: nothing
//! in this crate mutates them, derives new profile values, or caches into
//! them.
//!
//! The crate is pure — no I/O, no clock, no global state, no dependencies
//! beyond `serde` — so it runs unchanged on wasm32 in the Worker and the
//! website.
//!
//! # Example
//!
//! ```
//! use tokker_math::{estimate_for_plan, Call, LimitEntry, NumOrUnknown, PlanInput};
//! use tokker_math::{Profile, ReferencePricing, Unit, Window, Windows};
//!
//! let profile = Profile {
//!     id: "example-v1".to_owned(),
//!     call: Call {
//!         tokens_per_call: 40_000.0,
//!         input_tokens: 10_000.0,
//!         cached_input_tokens: 2_000.0,
//!         output_tokens: 30_000.0,
//!     },
//!     windows: Windows {
//!         five_hour_windows_per_day: 4.0,
//!         days_per_week: 7.0,
//!         days_per_month: 30.0,
//!     },
//!     reference_pricing: ReferencePricing {
//!         input_per_mtok: 3.0,
//!         cached_input_per_mtok: 0.3,
//!         output_per_mtok: 15.0,
//!     },
//! };
//! let plan = PlanInput {
//!     price_usd_per_month: NumOrUnknown::Num(200.0),
//!     confidence: None,
//!     limits: vec![LimitEntry {
//!         window: Window::Monthly,
//!         unit: Unit::Usd,
//!         amount: NumOrUnknown::Num(474.6),
//!     }],
//!     conversions: None,
//! };
//!
//! let estimate = estimate_for_plan(&plan, &profile);
//! assert_eq!(estimate.binding_window, Some(Window::Monthly));
//! // $474.6 buys 1000 calls of 40k tokens: ~40M tokens/month.
//! assert!((estimate.est_tokens_per_month.unwrap() - 40_000_000.0).abs() < 1e-3);
//! ```

#![forbid(unsafe_code)]

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

/// A dataset number the source may or may not publish.
///
/// The dataset writes the literal string `"unknown"` where a vendor
/// publishes no value, `null` where a value is not applicable, and a JSON
/// number otherwise (CLAUDE.md data rule 1). All three deserialize into
/// this enum; only [`NumOrUnknown::Num`] carries a usable value, and
/// `null` counts as unknown.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumOrUnknown {
    /// A value the source actually publishes.
    Num(f64),
    /// `"unknown"` or `null`: the source publishes no usable value.
    Unknown,
}

impl NumOrUnknown {
    /// The published number, or [`None`] when the source publishes none.
    pub fn number(self) -> Option<f64> {
        match self {
            NumOrUnknown::Num(number) => Some(number),
            NumOrUnknown::Unknown => None,
        }
    }
}

impl Serialize for NumOrUnknown {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            NumOrUnknown::Num(number) => serializer.serialize_f64(number),
            NumOrUnknown::Unknown => serializer.serialize_str("unknown"),
        }
    }
}

impl<'de> Deserialize<'de> for NumOrUnknown {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match RawNum::deserialize(deserializer)? {
            RawNum::Num(number) => Ok(NumOrUnknown::Num(number)),
            RawNum::Unknown(text) if text == "unknown" => Ok(NumOrUnknown::Unknown),
            RawNum::Unknown(other) => Err(de::Error::custom(format!(
                "expected a number, null or \"unknown\", got {other:?}"
            ))),
            RawNum::Null => Ok(NumOrUnknown::Unknown),
        }
    }
}

/// Serde's untagged view of a dataset number: number, `"unknown"` or null.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawNum {
    /// A JSON number (integers widen losslessly through serde's f64 visit).
    Num(f64),
    /// A JSON string; only the exact text `"unknown"` is accepted.
    Unknown(String),
    /// JSON `null` — not applicable, treated as unknown.
    Null,
}

/// Which rolling window a published limit counts against.
///
/// The variants rename to the dataset strings: `"5h_rolling"`, `"daily"`,
/// `"weekly"`, `"monthly"`, `"per_request"`, `"unspecified"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Window {
    /// Rolling five-hour window (`"5h_rolling"`).
    #[serde(rename = "5h_rolling")]
    FiveHourRolling,
    /// Calendar day (`"daily"`).
    #[serde(rename = "daily")]
    Daily,
    /// Calendar week (`"weekly"`).
    #[serde(rename = "weekly")]
    Weekly,
    /// Calendar month (`"monthly"`).
    #[serde(rename = "monthly")]
    Monthly,
    /// Every single request (`"per_request"`) — never counts toward the
    /// monthly estimate.
    #[serde(rename = "per_request")]
    PerRequest,
    /// The source names no window (`"unspecified"`) — never counts.
    #[serde(rename = "unspecified")]
    Unspecified,
}

/// What a published limit counts.
///
/// The variants rename to the dataset strings: `"tokens"`, `"requests"`,
/// `"prompts"`, `"messages"`, `"credits"`, `"usd"`, `"unspecified"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Unit {
    /// Tokens directly (`"tokens"`) — already tokens, multiplier 1.
    #[serde(rename = "tokens")]
    Tokens,
    /// Requests (`"requests"`) — one request is one profile call.
    #[serde(rename = "requests")]
    Requests,
    /// Prompts (`"prompts"`) — one prompt is one profile call.
    #[serde(rename = "prompts")]
    Prompts,
    /// Messages (`"messages"`) — one message is one profile call.
    #[serde(rename = "messages")]
    Messages,
    /// Credits (`"credits"`) — needs a `credits_per_call` or
    /// `usd_per_credit` conversion.
    #[serde(rename = "credits")]
    Credits,
    /// US dollars (`"usd"`) — divided by the profile cost per call.
    #[serde(rename = "usd")]
    Usd,
    /// The source names no unit (`"unspecified"`) — not convertible.
    #[serde(rename = "unspecified")]
    Unspecified,
}

/// A published limit line: `amount` of `unit` per `window`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LimitEntry {
    /// Which window the cap applies to.
    pub window: Window,
    /// What the cap counts.
    pub unit: Unit,
    /// The published cap, or unknown when the source publishes none.
    pub amount: NumOrUnknown,
}

/// Plan-specific unit conversions published by the source.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Conversions {
    /// Credits per assumed profile call (`q`), if published.
    #[serde(default)]
    pub credits_per_call: Option<f64>,
    /// US dollars per credit (`p`), if published.
    #[serde(default)]
    pub usd_per_credit: Option<f64>,
}

/// The reference call a profile assumes: how many tokens one call costs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Call {
    /// Tokens per assumed call (`T`); must equal `input_tokens +
    /// output_tokens`.
    pub tokens_per_call: f64,
    /// Input tokens per assumed call (`I`).
    pub input_tokens: f64,
    /// Cached input tokens per assumed call (`c`); never above
    /// `input_tokens`.
    pub cached_input_tokens: f64,
    /// Output tokens per assumed call (`o`).
    pub output_tokens: f64,
}

/// Window conversions published with a profile.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Windows {
    /// Rolling five-hour windows in a day (`W`; 4 in `agentic-coding-v1`).
    pub five_hour_windows_per_day: f64,
    /// Days in a week.
    pub days_per_week: f64,
    /// Days in a month (`D`; 30 in `agentic-coding-v1`).
    pub days_per_month: f64,
}

/// Reference API pricing, in USD per million tokens.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ReferencePricing {
    /// Uncached input rate (`r_in`).
    pub input_per_mtok: f64,
    /// Cached input rate (`r_cached`).
    pub cached_input_per_mtok: f64,
    /// Output rate (`r_out`).
    pub output_per_mtok: f64,
}

/// A published, versioned assumption profile (default
/// `agentic-coding-v1`).
///
/// Profiles are immutable inputs: callers own them, and nothing here
/// mutates or caches into them. Mirrors `data/profiles/<id>.json` exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Profile id, e.g. `"agentic-coding-v1"`.
    pub id: String,
    /// The reference call the profile assumes.
    pub call: Call,
    /// Window and day conversions.
    pub windows: Windows,
    /// Reference USD-per-Mtok rates.
    pub reference_pricing: ReferencePricing,
}

/// A subscription plan, as fed to [`estimate_for_plan`].
///
/// Mirrors the vector plans in `tests/vectors/token-math.json`; dataset
/// fields that the math does not need (quotes, names, provenance) are
/// ignored by the deserializer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanInput {
    /// Monthly plan price in USD — a number, `"unknown"` or `null`.
    pub price_usd_per_month: NumOrUnknown,
    /// Dataset confidence for the plan; the literal `"secondary"` means the
    /// plan is never estimated.
    #[serde(default)]
    pub confidence: Option<String>,
    /// The published limits.
    #[serde(default)]
    pub limits: Vec<LimitEntry>,
    /// Unit conversions for credit-denominated limits, if any.
    #[serde(default)]
    pub conversions: Option<Conversions>,
}

/// The subscription token math result for one plan.
///
/// `None` is the dataset's `"unknown"`: the source publishes no usable
/// number, and per CLAUDE.md data rule 1 none is invented. Field by field:
///
/// * `est_tokens_per_month` — [`None`] when no usable limit exists;
/// * `est_usd_per_mtok_at_full_use` — [`None`] when the estimate or the
///   plan price is unknown (a price of `0` is a number, not unknown);
/// * `binding_window` — [`None`] when the estimate is unknown;
/// * `tokens_per_window` / `tokens_per_week` — [`None`] when no usable
///   five-hour / weekly limit exists (the weekly value falls back to the
///   five-hour window scaled by `W * 7`).
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct Estimate {
    /// Estimated tokens per month at full use, rounded to a whole token.
    pub est_tokens_per_month: Option<f64>,
    /// Implied USD per million tokens at full use, rounded to 4 decimals.
    pub est_usd_per_mtok_at_full_use: Option<f64>,
    /// The window whose cap binds the estimate.
    pub binding_window: Option<Window>,
    /// Tokens in one five-hour window at full use.
    pub tokens_per_window: Option<f64>,
    /// Tokens in one week at full use.
    pub tokens_per_week: Option<f64>,
}

/// Windows from coarsest to finest. Iterating candidates in this order and
/// keeping the strict minimum makes exact ties resolve to the coarser
/// window: [`Monthly`](Window::Monthly) over [`Weekly`](Window::Weekly)
/// over [`Daily`](Window::Daily) over
/// [`FiveHourRolling`](Window::FiveHourRolling).
const COARSEST_FIRST: [Window; 4] = [
    Window::Monthly,
    Window::Weekly,
    Window::Daily,
    Window::FiveHourRolling,
];

/// The cost in USD of one assumed profile call: `K = ((I - c) * r_in +
/// c * r_cached + o * r_out) / 1e6`.
///
/// The f64 operation order mirrors `tools/math.ts` bit-for-bit. Debug
/// builds assert the profile invariants (`tokens_per_call == input +
/// output`, `cached <= input`).
pub fn profile_cost_per_call(profile: &Profile) -> f64 {
    let call = profile.call;
    debug_assert!(
        (call.tokens_per_call - (call.input_tokens + call.output_tokens)).abs() < 1e-9,
        "profile {}: tokens_per_call must equal input_tokens + output_tokens",
        profile.id,
    );
    debug_assert!(
        call.cached_input_tokens <= call.input_tokens,
        "profile {}: cached_input_tokens must not exceed input_tokens",
        profile.id,
    );
    let rates = profile.reference_pricing;
    ((call.input_tokens - call.cached_input_tokens) * rates.input_per_mtok
        + call.cached_input_tokens * rates.cached_input_per_mtok
        + call.output_tokens * rates.output_per_mtok)
        / 1e6
}

/// Estimate one plan against one profile.
///
/// A limit entry counts only when its amount is a published number, its
/// window is one of the four rolling windows (`PerRequest` and
/// `Unspecified` never count), its unit is convertible — credit limits
/// need a `credits_per_call` or `usd_per_credit` conversion — and the plan
/// is not labelled `confidence: "secondary"`. The estimate is the minimum
/// of the usable candidates, with exact ties preferring the coarser
/// window. Off-peak multipliers are never applied.
pub fn estimate_for_plan(plan: &PlanInput, profile: &Profile) -> Estimate {
    if plan.confidence.as_deref() == Some("secondary") {
        return Estimate::default();
    }

    let cost_per_call = profile_cost_per_call(profile);
    let tokens_per_call = profile.call.tokens_per_call;
    let conversions = plan.conversions.unwrap_or_default();

    let mut best: Option<(f64, Window)> = None;
    for window in COARSEST_FIRST {
        for &entry in &plan.limits {
            if entry.window != window || !usable(entry, conversions) {
                continue;
            }
            let amount = entry.amount.number().unwrap_or_default();
            let Some(scaled) = monthly_units(window, amount, profile.windows) else {
                continue;
            };
            let Some(candidate) =
                candidate_tokens(entry, scaled, cost_per_call, tokens_per_call, conversions)
            else {
                continue;
            };
            if best.is_none_or(|(minimum, _)| candidate < minimum) {
                best = Some((candidate, window));
            }
        }
    }

    let Some((tokens_minimum, binding)) = best else {
        return Estimate::default();
    };

    let tokens_per_window = min_raw_tokens(
        plan,
        conversions,
        cost_per_call,
        tokens_per_call,
        Window::FiveHourRolling,
    );
    let tokens_per_week = min_raw_tokens(
        plan,
        conversions,
        cost_per_call,
        tokens_per_call,
        Window::Weekly,
    )
    .or_else(|| {
        tokens_per_window.map(|tokens| {
            tokens * (profile.windows.five_hour_windows_per_day * profile.windows.days_per_week)
        })
    });

    Estimate {
        est_tokens_per_month: Some(tokens_minimum.round()),
        est_usd_per_mtok_at_full_use: plan
            .price_usd_per_month
            .number()
            .map(|price| round4(price / tokens_minimum * 1e6)),
        binding_window: Some(binding),
        tokens_per_window,
        tokens_per_week,
    }
}

/// Scales one published `amount` to units per month, in exactly the f64
/// operation order of `tools/math.ts`: 5h caps multiply by `W * D`, daily
/// caps by `D`, weekly caps go through `(amount * D) / days_per_week`,
/// monthly caps stand as published.
fn monthly_units(window: Window, amount: f64, windows: Windows) -> Option<f64> {
    match window {
        Window::FiveHourRolling => {
            Some(amount * (windows.five_hour_windows_per_day * windows.days_per_month))
        }
        Window::Daily => Some(amount * windows.days_per_month),
        Window::Weekly => Some((amount * windows.days_per_month) / windows.days_per_week),
        Window::Monthly => Some(amount),
        Window::PerRequest | Window::Unspecified => None,
    }
}

/// Converts scaled monthly units into a token candidate.
///
/// Per-unit multipliers per `tools/math.ts`: a vendor-quoted token count
/// (`Unit::Tokens`) already is tokens — multiplier 1, no `* T` — while
/// requests, prompts and messages multiply by `tokens_per_call`; credits
/// divide by `credits_per_call` (or, when only a dollar value per credit
/// is published, `units * usd_per_credit` dollars divide by the call
/// cost) before multiplying by `tokens_per_call`; dollars divide by the
/// profile cost per call, then multiply by `tokens_per_call`.
fn candidate_tokens(
    entry: LimitEntry,
    scaled: f64,
    cost_per_call: f64,
    tokens_per_call: f64,
    conversions: Conversions,
) -> Option<f64> {
    match entry.unit {
        Unit::Tokens => Some(scaled),
        Unit::Requests | Unit::Prompts | Unit::Messages => Some(scaled * tokens_per_call),
        Unit::Credits => {
            if let Some(credits_per_call) = conversions.credits_per_call {
                Some((scaled / credits_per_call) * tokens_per_call)
            } else {
                let usd_per_credit = conversions.usd_per_credit?;
                Some(((scaled * usd_per_credit) / cost_per_call) * tokens_per_call)
            }
        }
        Unit::Usd => Some((scaled / cost_per_call) * tokens_per_call),
        Unit::Unspecified => None,
    }
}

/// Whether an entry can take part in the estimate at all: a counting
/// window, a numeric amount, a convertible unit.
fn usable(entry: LimitEntry, conversions: Conversions) -> bool {
    if !matches!(
        entry.window,
        Window::FiveHourRolling | Window::Daily | Window::Weekly | Window::Monthly
    ) {
        return false;
    }
    if entry.amount == NumOrUnknown::Unknown {
        return false;
    }
    match entry.unit {
        Unit::Tokens | Unit::Requests | Unit::Prompts | Unit::Messages | Unit::Usd => true,
        Unit::Credits => {
            conversions.credits_per_call.is_some() || conversions.usd_per_credit.is_some()
        }
        Unit::Unspecified => false,
    }
}

/// The smallest raw window candidate (`amount / divisor * T`, never
/// month-scaled) among the usable entries of one window.
fn min_raw_tokens(
    plan: &PlanInput,
    conversions: Conversions,
    cost_per_call: f64,
    tokens_per_call: f64,
    window: Window,
) -> Option<f64> {
    let mut minimum: Option<f64> = None;
    for &entry in &plan.limits {
        if entry.window != window || !usable(entry, conversions) {
            continue;
        }
        let amount = entry.amount.number().unwrap_or_default();
        let Some(candidate) =
            candidate_tokens(entry, amount, cost_per_call, tokens_per_call, conversions)
        else {
            continue;
        };
        if minimum.is_none_or(|current| candidate < current) {
            minimum = Some(candidate);
        }
    }
    minimum
}

/// Rounds to four decimals, as `tools/math.ts` does:
/// `round4(x) = (x * 10000).round() / 10000`.
fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::{Call, Conversions, Estimate, estimate_for_plan, profile_cost_per_call, round4};
    use super::{
        LimitEntry, NumOrUnknown, PlanInput, Profile, ReferencePricing, Unit, Window, Windows,
    };

    /// The worked example from the crate docs: `K = 0.4746`, `T = 40_000`.
    fn profile() -> Profile {
        Profile {
            id: "test-v1".to_owned(),
            call: Call {
                tokens_per_call: 40_000.0,
                input_tokens: 10_000.0,
                cached_input_tokens: 2_000.0,
                output_tokens: 30_000.0,
            },
            windows: Windows {
                five_hour_windows_per_day: 4.0,
                days_per_week: 7.0,
                days_per_month: 30.0,
            },
            reference_pricing: ReferencePricing {
                input_per_mtok: 3.0,
                cached_input_per_mtok: 0.3,
                output_per_mtok: 15.0,
            },
        }
    }

    fn limit(window: Window, unit: Unit, amount: f64) -> LimitEntry {
        LimitEntry {
            window,
            unit,
            amount: NumOrUnknown::Num(amount),
        }
    }

    fn plan(limits: Vec<LimitEntry>, price: NumOrUnknown) -> PlanInput {
        PlanInput {
            price_usd_per_month: price,
            confidence: None,
            limits,
            conversions: None,
        }
    }

    #[test]
    fn cost_per_call_matches_reference_arithmetic() {
        // (8000 * 3 + 2000 * 0.3 + 30000 * 15) / 1e6
        let expected = (8_000.0 * 3.0 + 2_000.0 * 0.3 + 30_000.0 * 15.0) / 1e6;
        assert_eq!(profile_cost_per_call(&profile()), expected);
    }

    #[test]
    fn monthly_usd_cap_binds_and_prices_per_mtok() {
        let estimate = estimate_for_plan(
            &plan(
                vec![limit(Window::Monthly, Unit::Usd, 474.6)],
                NumOrUnknown::Num(200.0),
            ),
            &profile(),
        );
        let tokens = estimate.est_tokens_per_month.unwrap();
        assert_eq!(estimate.binding_window, Some(Window::Monthly));
        assert!((tokens - 40_000_000.0).abs() < 1.0, "got {tokens}");
        // 200 / 40M * 1e6 = 5.0 (within rounding of the unrounded tokens).
        let usd = estimate.est_usd_per_mtok_at_full_use.unwrap();
        assert!((usd - 5.0).abs() < 1e-3, "got {usd}");
    }

    #[test]
    fn unknown_amount_and_unusable_units_are_skipped() {
        let unknown = LimitEntry {
            window: Window::Monthly,
            unit: Unit::Usd,
            amount: NumOrUnknown::Unknown,
        };
        let per_request = LimitEntry {
            window: Window::PerRequest,
            unit: Unit::Tokens,
            amount: NumOrUnknown::Num(999_999_999.0),
        };
        let no_conversion = LimitEntry {
            window: Window::Monthly,
            unit: Unit::Credits,
            amount: NumOrUnknown::Num(1_000.0),
        };
        let estimate = estimate_for_plan(
            &plan(
                vec![unknown, per_request, no_conversion],
                NumOrUnknown::Num(50.0),
            ),
            &profile(),
        );
        assert_eq!(estimate, Estimate::default());
    }

    #[test]
    fn secondary_confidence_is_never_estimated() {
        let mut plan = plan(
            vec![limit(Window::Monthly, Unit::Usd, 474.6)],
            NumOrUnknown::Num(200.0),
        );
        plan.confidence = Some("secondary".to_owned());
        assert_eq!(estimate_for_plan(&plan, &profile()), Estimate::default());
    }

    #[test]
    fn credits_convert_through_credits_per_call() {
        let mut plan = plan(
            vec![limit(Window::Monthly, Unit::Credits, 1_000.0)],
            NumOrUnknown::Unknown,
        );
        plan.conversions = Some(Conversions {
            credits_per_call: Some(10.0),
            usd_per_credit: None,
        });
        let estimate = estimate_for_plan(&plan, &profile());
        // (1000 / 10) * 40_000
        assert_eq!(estimate.est_tokens_per_month, Some(4_000_000.0));
        // Price unknown: no $/Mtok, but the estimate stands.
        assert_eq!(estimate.est_usd_per_mtok_at_full_use, None);
    }

    #[test]
    fn credits_fall_back_to_usd_per_credit() {
        let mut plan = plan(
            vec![limit(Window::Monthly, Unit::Credits, 1_000.0)],
            NumOrUnknown::Num(200.0),
        );
        plan.conversions = Some(Conversions {
            credits_per_call: None,
            usd_per_credit: Some(0.4746),
        });
        let estimate = estimate_for_plan(&plan, &profile());
        // ((1000 * 0.4746) / 0.4746) * 40_000 ~= 40M
        let tokens = estimate.est_tokens_per_month.unwrap();
        assert!((tokens - 40_000_000.0).abs() < 1.0, "got {tokens}");
    }

    #[test]
    fn minimum_wins_and_exact_ties_prefer_the_coarser_window() {
        // Monthly 1200 tokens and weekly 280 tokens both give
        // 1200 candidates ((280 * 30) / 7 == 1200): Monthly must bind.
        let estimate = estimate_for_plan(
            &plan(
                vec![
                    limit(Window::Monthly, Unit::Tokens, 1_200.0),
                    limit(Window::Weekly, Unit::Tokens, 280.0),
                ],
                NumOrUnknown::Num(10.0),
            ),
            &profile(),
        );
        assert_eq!(estimate.binding_window, Some(Window::Monthly));
        // Token caps are already tokens: no multiplication by T.
        assert_eq!(estimate.est_tokens_per_month, Some(1_200.0));
    }

    #[test]
    fn weekly_and_five_hour_side_outputs() {
        let estimate = estimate_for_plan(
            &plan(
                vec![limit(Window::FiveHourRolling, Unit::Usd, 4.746)],
                NumOrUnknown::Num(10.0),
            ),
            &profile(),
        );
        // One window: 4.746 / 0.4746 = 10 calls = 400_000 tokens.
        let per_window = estimate.tokens_per_window.unwrap();
        assert!((per_window - 400_000.0).abs() < 1e-6, "got {per_window}");
        // A week is W * 7 = 28 windows.
        let per_week = estimate.tokens_per_week.unwrap();
        assert!((per_week - 400_000.0 * 28.0).abs() < 1e-6, "got {per_week}");
        // 120 windows a month: 48_000_000 tokens.
        let monthly = estimate.est_tokens_per_month.unwrap();
        assert!((monthly - 48_000_000.0).abs() < 1.0, "got {monthly}");
        assert_eq!(estimate.binding_window, Some(Window::FiveHourRolling));
    }

    #[test]
    fn round4_rounds_half_away_from_zero() {
        assert_eq!(round4(1.000_05), 1.000_1);
        assert_eq!(round4(0.0), 0.0);
        assert_eq!(round4(5.0), 5.0);
    }
}
