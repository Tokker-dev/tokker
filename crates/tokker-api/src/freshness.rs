//! Freshness SLAs (docs/plan.md §4.5): is a row stale as of a date?
//!
//! The rules live in `data/rules/freshness.json`: classes with an `sla_days`
//! budget, matched first by row type (a subscription stays on the subscription
//! SLA whatever its volatility), then by `fetch_recipe.volatility`, first rule
//! wins. The build stamps `stale`/`stale_since` in, but data keeps ageing
//! after a merge — so the Worker calls [`staleness`] at read time with the
//! request date and the same rules. Both implementations must agree on every
//! vector in `tests/vectors/staleness.json`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use serde::Deserialize;

const RULES_JSON: &str = include_str!("../../../data/rules/freshness.json");

static RULES: LazyLock<Rules> =
    LazyLock::new(|| serde_json::from_str(RULES_JSON).expect("data/rules/freshness.json parses"));

#[derive(Deserialize)]
struct Rules {
    classes: BTreeMap<String, SlaClass>,
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
struct SlaClass {
    sla_days: u32,
}

#[derive(Deserialize)]
struct Rule {
    row_type: Option<String>,
    volatility: Option<String>,
    class: String,
}

/// Which array a row came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowType {
    /// A row of `api_offers[]`.
    ApiOffer,
    /// A row of `subscriptions[]`.
    Subscription,
}

impl RowType {
    fn as_str(self) -> &'static str {
        match self {
            RowType::ApiOffer => "api_offer",
            RowType::Subscription => "subscription",
        }
    }
}

/// The staleness verdict for one row, as of the requested date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staleness {
    /// The freshness class the rules matched.
    pub class: String,
    /// The class's SLA, in whole days.
    pub sla_days: u32,
    /// True once more whole days than the SLA separate the verified date from today.
    pub stale: bool,
    /// The first day the row was stale (`YYYY-MM-DD`); `None` while fresh.
    pub stale_since: Option<String>,
}

/// Why staleness could not be computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A date is not a real calendar `YYYY-MM-DD`.
    BadDate(String),
    /// The rules file has no matching rule, or names an undefined class.
    Rules(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadDate(value) => write!(f, "not a real calendar YYYY-MM-DD date: {value}"),
            Error::Rules(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

/// The first matching rule wins; an absent rule key matches any value.
fn classify(row_type: RowType, volatility: Option<&str>) -> Result<(&'static str, u32), Error> {
    for rule in &RULES.rules {
        if rule
            .row_type
            .as_deref()
            .is_some_and(|t| t != row_type.as_str())
        {
            continue;
        }
        if rule
            .volatility
            .as_deref()
            .is_some_and(|v| Some(v) != volatility)
        {
            continue;
        }
        let sla_days = RULES
            .classes
            .get(&rule.class)
            .map(|class| class.sla_days)
            .ok_or_else(|| {
                Error::Rules(format!("freshness rule names undefined class '{}'", rule.class))
            })?;
        return Ok((rule.class.as_str(), sla_days));
    }
    Err(Error::Rules(format!(
        "no freshness rule matches row_type '{}' volatility '{}'",
        row_type.as_str(),
        volatility.unwrap_or("any")
    )))
}

/// Staleness for one row as of `today`. Age is whole UTC days from the
/// `last_verified_at` date part (so an ISO date-time works) to `today`; stale
/// means `age > sla_days` — age == SLA is still fresh, and a row verified today
/// or in the future never is. `stale_since` is the first stale day. A malformed
/// date is an error, never a silently fresh row.
///
/// # Errors
/// The rules file has no matching rule, or a date is not a real calendar
/// `YYYY-MM-DD`.
pub fn staleness(
    row_type: RowType,
    volatility: Option<&str>,
    last_verified_at: &str,
    today: &str,
) -> Result<Staleness, Error> {
    let (class, sla_days) = classify(row_type, volatility)?;
    let verified = parse_date(last_verified_at)?;
    let now = parse_date(today)?;
    let stale = now - verified > i64::from(sla_days);
    Ok(Staleness {
        class: class.to_string(),
        sla_days,
        stale,
        stale_since: stale.then(|| format_date(verified + i64::from(sla_days) + 1)),
    })
}

/// The date part (first 10 characters, so an ISO date-time works) as a day
/// serial since 1970-01-01.
fn parse_date(value: &str) -> Result<i64, Error> {
    let bad = || Error::BadDate(value.into());
    let date = value.get(..10).ok_or_else(bad)?;
    let bytes = date.as_bytes();
    let shaped = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && (0..10).all(|i| i == 4 || i == 7 || bytes[i].is_ascii_digit());
    if !shaped {
        return Err(bad());
    }
    let year: i64 = date[..4].parse().map_err(|_| bad())?;
    let month: u32 = date[5..7].parse().map_err(|_| bad())?;
    let day: u32 = date[8..10].parse().map_err(|_| bad())?;
    if month == 0 || month > 12 || day == 0 || day > days_in_month(year, month) {
        return Err(bad());
    }
    Ok(days_from_civil(year, month, day))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        _ => 28, // month 2 (the caller rejects anything else first)
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days since 1970-01-01 for a proleptic-Gregorian date
/// (Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(month) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The `(year, month, day)` for a day serial (the inverse of `days_from_civil`).
fn civil_from_days(serial: i64) -> (i64, u32, u32) {
    let z = serial + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).expect("month in 1..=12"),
        u32::try_from(day).expect("day in 1..=31"),
    )
}

/// `YYYY-MM-DD` for a day serial.
fn format_date(serial: i64) -> String {
    let (year, month, day) = civil_from_days(serial);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS_JSON: &str = include_str!("../../../tests/vectors/staleness.json");

    #[derive(Deserialize)]
    struct VectorFile {
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        row_type: String,
        volatility: Option<String>,
        last_verified_at: String,
        today: String,
        expect: Expected,
    }

    #[derive(Deserialize)]
    struct Expected {
        class: String,
        sla_days: u32,
        stale: bool,
        stale_since: Option<String>,
    }

    fn row_type(name: &str) -> RowType {
        match name {
            "api_offer" => RowType::ApiOffer,
            "subscription" => RowType::Subscription,
            other => panic!("unknown row_type {other}"),
        }
    }

    /// The build (tools/freshness.mjs) runs the same file; agreement here is
    /// the Worker/build contract.
    #[test]
    fn matches_every_shared_vector() {
        let file: VectorFile = serde_json::from_str(VECTORS_JSON).expect("vectors parse");
        assert!(!file.vectors.is_empty(), "no shared vectors");
        for vector in &file.vectors {
            let got = staleness(
                row_type(&vector.row_type),
                vector.volatility.as_deref(),
                &vector.last_verified_at,
                &vector.today,
            )
            .unwrap_or_else(|e| panic!("{}: {e}", vector.name));
            assert_eq!(got.class, vector.expect.class, "{}", vector.name);
            assert_eq!(got.sla_days, vector.expect.sla_days, "{}", vector.name);
            assert_eq!(got.stale, vector.expect.stale, "{}", vector.name);
            assert_eq!(
                got.stale_since, vector.expect.stale_since,
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn a_malformed_date_is_an_error_not_fresh() {
        assert_eq!(
            staleness(RowType::ApiOffer, Some("high"), "2026-02-30", "2026-10-05"),
            Err(Error::BadDate("2026-02-30".into()))
        );
        assert_eq!(
            staleness(RowType::ApiOffer, Some("high"), "2026-10-05", "01-01-2026"),
            Err(Error::BadDate("01-01-2026".into()))
        );
        assert_eq!(
            staleness(
                RowType::Subscription,
                Some("high"),
                "2026-10-05",
                "2026-10-1"
            ),
            Err(Error::BadDate("2026-10-1".into()))
        );
    }
}
