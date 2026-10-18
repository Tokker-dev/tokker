//! Pure query layer for `/v1/offers` (issue #19): parsing and validating the
//! filter string into a normalised form, the canonical string that keys the
//! KV cache, the opaque cursor codec, and the keyset-position comparison
//! pagination rests on. No I/O here — everything is unit-testable.

/// The sort orders. Default is `Blended`: the 3:1 input:output blend the
/// product ranks on, with the raw columns always present in the row itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sort {
    /// `usd_blended_3to1` — the default ranking.
    #[default]
    Blended,
    /// `usd_input_per_mtok`.
    Input,
    /// `usd_output_per_mtok`.
    Output,
}

impl Sort {
    /// The wire name, also stored in a cursor and checked on the way back.
    pub fn as_str(self) -> &'static str {
        match self {
            Sort::Blended => "blended",
            Sort::Input => "input",
            Sort::Output => "output",
        }
    }

    /// The `offers` column this order sorts by (a fixed whitelist — never
    /// user input, so interpolating it into SQL is safe).
    fn column(self) -> &'static str {
        match self {
            Sort::Blended => "usd_blended_3to1",
            Sort::Input => "usd_input_per_mtok",
            Sort::Output => "usd_output_per_mtok",
        }
    }
}

/// The largest accepted `limit`.
pub const MAX_LIMIT: u32 = 200;
/// The `limit` used when the parameter is absent.
pub const DEFAULT_LIMIT: u32 = 50;

/// A validated `GET /v1/offers` query. Empty parameter values are already
/// normalised away (treated as absent); values are canonical (`currency`
/// upper-cased, decimals as `f64`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NormalisedQuery {
    /// `model` — the canonical model slug (`offers.model_id`).
    pub model: Option<String>,
    /// `provider` — `offers.provider_id`.
    pub provider: Option<String>,
    /// `creator` — `offers.creator`.
    pub creator: Option<String>,
    /// `provider_type` — one of the schema's CHECK values.
    pub provider_type: Option<String>,
    /// `open_weights` — `true` | `false` | `unknown`.
    pub open_weights: Option<String>,
    /// `currency` — ISO 4217, upper-cased.
    pub currency: Option<String>,
    /// `max_input` — USD, `usd_input_per_mtok <= value`.
    pub max_input: Option<f64>,
    /// `max_output` — USD, `usd_output_per_mtok <= value`.
    pub max_output: Option<f64>,
    /// `stale` — filter on the read-time staleness verdict.
    pub stale: Option<bool>,
    /// `sort` — defaults to blended.
    pub sort: Sort,
    /// `limit` — `1..=MAX_LIMIT`, defaults to `DEFAULT_LIMIT`.
    pub limit: u32,
    /// `cursor` — the opaque `next_cursor` of a previous page.
    pub cursor: Option<String>,
}

impl NormalisedQuery {
    /// The sort column this query orders by.
    pub fn sort_column(&self) -> &'static str {
        self.sort.column()
    }

    /// The canonical string form: fixed key order, defaults filled in, absent
    /// filters as empty values. Two requests the API answers identically
    /// produce the same string — that is the KV cache key. Inputs that differ
    /// but mean the same thing (`usd`/`USD`, `1.50`/`1.5`) normalise equal.
    pub fn canonical(&self) -> String {
        let fields: [(&str, String); 11] = [
            ("creator", self.creator.clone().unwrap_or_default()),
            ("currency", self.currency.clone().unwrap_or_default()),
            ("cursor", self.cursor.clone().unwrap_or_default()),
            (
                "max_input",
                self.max_input.map(|v| v.to_string()).unwrap_or_default(),
            ),
            (
                "max_output",
                self.max_output.map(|v| v.to_string()).unwrap_or_default(),
            ),
            ("model", self.model.clone().unwrap_or_default()),
            (
                "open_weights",
                self.open_weights.clone().unwrap_or_default(),
            ),
            ("provider", self.provider.clone().unwrap_or_default()),
            (
                "provider_type",
                self.provider_type.clone().unwrap_or_default(),
            ),
            ("sort", self.sort.as_str().to_string()),
            (
                "stale",
                self.stale.map(|v| v.to_string()).unwrap_or_default(),
            ),
        ];
        let mut out = format!("limit={}", self.limit);
        for (name, value) in fields {
            out.push('&');
            out.push_str(name);
            out.push('=');
            out.push_str(&value);
        }
        out
    }
}

/// One rejected parameter: the full message (already names the parameter)
/// plus the bare name for the problem's `parameter` extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidParam {
    /// The offending parameter's name.
    pub name: String,
    /// The full human-readable reason.
    pub message: String,
}

/// Builds an [`InvalidParam`]: the message already names the parameter.
pub fn param_error(name: &str, message: impl Into<String>) -> InvalidParam {
    InvalidParam {
        name: name.to_string(),
        message: format!("`{name}` {}", message.into()),
    }
}

fn invalid(name: &str, message: impl Into<String>) -> InvalidParam {
    param_error(name, message)
}

/// Parses a raw query string (`a=1&b=2`, percent-encoded). Unknown names,
/// repeated parameters and invalid values are errors; empty values are
/// treated as absent.
///
/// # Errors
///
/// [`InvalidParam`] naming the first parameter that failed validation.
pub fn parse_query(raw: Option<&str>) -> Result<NormalisedQuery, InvalidParam> {
    let mut query = NormalisedQuery {
        limit: DEFAULT_LIMIT,
        ..NormalisedQuery::default()
    };
    let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
        return Ok(query);
    };
    let mut seen: Vec<String> = Vec::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name_raw, value_raw) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(name_raw);
        let value = percent_decode(value_raw);
        if seen.contains(&name) {
            return Err(invalid(&name, "appears more than once"));
        }
        seen.push(name.clone());
        match name.as_str() {
            "model" => query.model = slug(&name, &value)?,
            "provider" => query.provider = slug(&name, &value)?,
            "creator" => query.creator = slug(&name, &value)?,
            "provider_type" => {
                query.provider_type = one_of(
                    &name,
                    &value,
                    &["first_party", "aggregator", "inference_host", "cloud"],
                )?;
            }
            "open_weights" => {
                query.open_weights = one_of(&name, &value, &["true", "false", "unknown"])?;
            }
            "currency" => query.currency = currency(&name, &value)?,
            "max_input" => query.max_input = decimal(&name, &value)?,
            "max_output" => query.max_output = decimal(&name, &value)?,
            "stale" => {
                query.stale = match value.as_str() {
                    "" => None,
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => return Err(invalid(&name, "must be true or false")),
                };
            }
            "sort" => {
                query.sort = match value.as_str() {
                    "" | "blended" => Sort::Blended,
                    "input" => Sort::Input,
                    "output" => Sort::Output,
                    _ => return Err(invalid(&name, "must be blended, input or output")),
                };
            }
            "limit" => {
                if !value.is_empty() {
                    let limit: u32 = value
                        .parse()
                        .map_err(|_| invalid(&name, "must be an integer between 1 and 200"))?;
                    if limit == 0 || limit > MAX_LIMIT {
                        return Err(invalid(&name, "must be an integer between 1 and 200"));
                    }
                    query.limit = limit;
                }
            }
            "cursor" => {
                query.cursor = match value.as_str() {
                    "" => None,
                    v if v
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
                    {
                        Some(v.to_string())
                    }
                    _ => {
                        return Err(invalid(
                            &name,
                            "must be the opaque cursor a previous page returned",
                        ));
                    }
                };
            }
            other => return Err(invalid(other, "is not a parameter this endpoint accepts")),
        }
    }
    Ok(query)
}

/// Whether `value` is a slug: the charset ([a-z0-9._-]) every provider id,
/// model slug and creator in `data/pricing.json` uses.
pub fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        })
}

/// A slug-shaped value; empty means absent.
fn slug(name: &str, value: &str) -> Result<Option<String>, InvalidParam> {
    if value.is_empty() {
        return Ok(None);
    }
    if valid_slug(value) {
        Ok(Some(value.to_string()))
    } else {
        Err(invalid(name, "must be a lowercase slug ([a-z0-9._-])"))
    }
}

fn one_of(name: &str, value: &str, allowed: &[&str]) -> Result<Option<String>, InvalidParam> {
    if value.is_empty() {
        return Ok(None);
    }
    if allowed.contains(&value) {
        Ok(Some(value.to_string()))
    } else {
        Err(invalid(
            name,
            format!("must be one of {}", allowed.join(", ")),
        ))
    }
}

fn currency(name: &str, value: &str) -> Result<Option<String>, InvalidParam> {
    if value.is_empty() {
        return Ok(None);
    }
    let three_letters = value.len() == 3 && value.bytes().all(|b| b.is_ascii_alphabetic());
    if three_letters {
        Ok(Some(value.to_ascii_uppercase()))
    } else {
        Err(invalid(name, "must be a 3-letter ISO 4217 code"))
    }
}

fn decimal(name: &str, value: &str) -> Result<Option<f64>, InvalidParam> {
    if value.is_empty() {
        return Ok(None);
    }
    let parsed: f64 = value
        .parse()
        .map_err(|_| invalid(name, "must be a number"))?;
    if parsed.is_finite() && parsed >= 0.0 {
        Ok(Some(parsed))
    } else {
        Err(invalid(name, "must be a finite number of at least 0"))
    }
}

/// `%XX`-decoding with `+` as space (the `x-www-form-urlencoded` query
/// convention). A stray `%` that starts no valid escape is kept literal —
/// the value then fails its own validation, which names the parameter.
fn percent_decode(input: &str) -> String {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex);
                let low = bytes.get(index + 2).copied().and_then(hex);
                if let (Some(high), Some(low)) = (high, low) {
                    out.push(high * 16 + low);
                    index += 3;
                } else {
                    // A stray `%` is kept literally.
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The keyset position of one row in the SQL order: NULLs last, then the
/// sort value, then the id (the tiebreak that makes the order total).
#[derive(Clone, Debug, PartialEq)]
pub struct Position {
    /// True when the row's sort column is NULL (an unpriced offer).
    pub is_null: bool,
    /// The sort value; meaningless when `is_null`.
    pub value: f64,
    /// The row id.
    pub id: String,
}

/// True when `a` sits at or before `b` in the sort order — the comparison
/// pagination skips rows with.
// Exact `==` on purpose: both sides are the same stored column (the cursor
// round-trips the f64 exactly), so this mirrors SQL `=`, not arithmetic
// that would need an error margin.
#[allow(clippy::float_cmp)]
pub fn not_after(a: &Position, b: &Position) -> bool {
    match (a.is_null, b.is_null) {
        (false, false) => a.value < b.value || (a.value == b.value && a.id <= b.id),
        // A non-NULL row always sorts before the NULL block.
        (false, true) => true,
        (true, false) => false,
        (true, true) => a.id <= b.id,
    }
}

/// The cursor payload a page's last row mints. Small keys on purpose:
/// cursors ride in query strings.
#[derive(Clone, Debug, PartialEq)]
pub struct Cursor {
    /// The sort the cursor was minted under.
    pub sort: Sort,
    /// The last row's sort value (`None` when NULL).
    pub value: Option<f64>,
    /// The last row's id.
    pub id: String,
}

/// Encodes a cursor as unpadded base64url of its JSON form.
///
/// # Panics
///
/// Never: `serde_json::to_string` on three scalar fields cannot fail.
pub fn encode_cursor(cursor: &Cursor) -> String {
    let payload = serde_json::json!({
        "s": cursor.sort.as_str(),
        "v": cursor.value,
        "i": cursor.id,
    });
    base64url_encode(&serde_json::to_vec(&payload).expect("three scalars serialise"))
}

/// Decodes a cursor minted by [`encode_cursor`].
///
/// # Errors
///
/// [`InvalidParam`] naming `cursor` when the string is not valid base64url,
/// not the expected JSON shape, or carries a non-finite value.
pub fn decode_cursor(raw: &str) -> Result<Cursor, InvalidParam> {
    let bad = || invalid("cursor", "does not decode to a valid cursor for this sort");
    let bytes = base64url_decode(raw).ok_or_else(bad)?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| bad())?;
    let sort = match payload.get("s").and_then(serde_json::Value::as_str) {
        Some("blended") => Sort::Blended,
        Some("input") => Sort::Input,
        Some("output") => Sort::Output,
        _ => return Err(bad()),
    };
    let value = match payload.get("v") {
        Some(serde_json::Value::Null) => None,
        Some(value) => {
            let number = value.as_f64().filter(|v| v.is_finite());
            if payload.get("v").is_some_and(serde_json::Value::is_number) && number.is_some() {
                number
            } else {
                return Err(bad());
            }
        }
        None => return Err(bad()),
    };
    let id = payload
        .get("i")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(bad)?
        .to_string();
    Ok(Cursor { sort, value, id })
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let triple = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let bits =
            (u32::from(triple[0]) << 16) | (u32::from(triple[1]) << 8) | u32::from(triple[2]);
        out.push(char::from(
            BASE64URL[usize::try_from(bits >> 18).unwrap_or(0) & 63],
        ));
        out.push(char::from(
            BASE64URL[usize::try_from(bits >> 12).unwrap_or(0) & 63],
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                BASE64URL[usize::try_from(bits >> 6).unwrap_or(0) & 63],
            ));
        }
        if chunk.len() > 2 {
            out.push(char::from(
                BASE64URL[usize::try_from(bits).unwrap_or(0) & 63],
            ));
        }
    }
    out
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    if input.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut bits = 0_u32;
    let mut pending = 0_u32;
    for byte in input.bytes() {
        let sextet = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | sextet;
        pending += 6;
        if pending >= 8 {
            pending -= 8;
            out.push(u8::try_from((bits >> pending) & 0xff).expect("masked to eight bits"));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_and_empty_queries_are_the_defaults() {
        for raw in [None, Some(""), Some("model=&sort=&limit=&cursor=")] {
            let query = parse_query(raw).unwrap();
            assert_eq!(query.model, None);
            assert_eq!(query.sort, Sort::Blended);
            assert_eq!(query.limit, DEFAULT_LIMIT);
            assert_eq!(query.cursor, None);
        }
    }

    #[test]
    fn every_parameter_parses_and_normalises() {
        let query = parse_query(Some(
            "model=gpt-5.1&provider=openrouter&creator=openai&provider_type=aggregator\
             &open_weights=false&currency=usd&max_input=1.50&max_output=10&stale=true&sort=input\
             &limit=200&cursor=abcDEF-_9",
        ))
        .unwrap();
        assert_eq!(query.model.as_deref(), Some("gpt-5.1"));
        assert_eq!(query.provider.as_deref(), Some("openrouter"));
        assert_eq!(query.creator.as_deref(), Some("openai"));
        assert_eq!(query.provider_type.as_deref(), Some("aggregator"));
        assert_eq!(query.open_weights.as_deref(), Some("false"));
        assert_eq!(query.currency.as_deref(), Some("USD"));
        assert_eq!(query.max_input, Some(1.5));
        assert_eq!(query.max_output, Some(10.0));
        assert_eq!(query.stale, Some(true));
        assert_eq!(query.sort, Sort::Input);
        assert_eq!(query.limit, 200);
        assert_eq!(query.cursor.as_deref(), Some("abcDEF-_9"));
        assert_eq!(query.sort_column(), "usd_input_per_mtok");
    }

    #[test]
    fn values_are_percent_decoded() {
        let query = parse_query(Some("model=gpt%2D5.1&currency=eur")).unwrap();
        assert_eq!(query.model.as_deref(), Some("gpt-5.1"));
        assert_eq!(query.currency.as_deref(), Some("EUR"));
        // `+` is a space, which no slug accepts.
        assert_eq!(
            parse_query(Some("creator=open+ai")).unwrap_err().name,
            "creator"
        );
    }

    #[test]
    fn invalid_values_name_their_parameter() {
        // Unknown names, repeats and limit/cursor bounds are covered by the
        // route tests; this loop is the parse-level value space.
        for raw in [
            "model=GPT-5",
            "provider=open/router",
            "creator=OpenAI",
            "provider_type=party",
            "open_weights=yes",
            "currency=US",
            "currency=USDD",
            "stale=True",
            "sort=price",
            "max_input=-1",
            "max_input=nan",
            "max_input=inf",
            "max_output=abc",
        ] {
            let error = parse_query(Some(raw)).expect_err(&format!("`{raw}` should not parse"));
            assert!(raw.starts_with(&error.name), "{raw} named {}", error.name);
        }
    }

    #[test]
    fn canonical_forms_are_stable_and_meaning_equivalent() {
        let base = parse_query(None).unwrap().canonical();
        assert_eq!(
            base,
            "limit=50&creator=&currency=&cursor=&max_input=&max_output=&model=&open_weights=&provider=&provider_type=&sort=blended&stale="
        );
        // Same meaning, different spelling: same cache key.
        let a = parse_query(Some("currency=usd&max_input=1.50")).unwrap();
        let b = parse_query(Some("max_input=1.5&currency=USD")).unwrap();
        assert_eq!(a.canonical(), b.canonical());
        // A different sort or cursor is a different key.
        let c = parse_query(Some("sort=input")).unwrap();
        assert_ne!(base, c.canonical());
        let d = parse_query(Some("cursor=Zm9v")).unwrap();
        assert_ne!(base, d.canonical());
    }

    #[test]
    fn not_after_orders_nulls_last_then_value_then_id() {
        let row = |is_null, value: f64, id: &str| Position {
            is_null,
            value,
            id: id.to_string(),
        };
        let a = row(false, 1.0, "a/x");
        let same = row(false, 1.0, "a/x");
        let later_id = row(false, 1.0, "b/x");
        let bigger = row(false, 2.0, "a/x");
        let null_a = row(true, 0.0, "a/x");
        let null_z = row(true, 0.0, "z/x");
        assert!(not_after(&a, &same));
        assert!(not_after(&a, &later_id));
        assert!(!not_after(&later_id, &a));
        assert!(not_after(&a, &bigger));
        assert!(not_after(&bigger, &null_a));
        assert!(not_after(&null_a, &null_z));
        assert!(!not_after(&null_z, &null_a));
    }

    #[test]
    fn cursors_round_trip_and_reject_garbage() {
        let cursor = Cursor {
            sort: Sort::Blended,
            value: Some(21.5),
            id: "openrouter/claude-fable-5-1".to_string(),
        };
        assert_eq!(decode_cursor(&encode_cursor(&cursor)).unwrap(), cursor);
        let null_cursor = Cursor {
            sort: Sort::Output,
            value: None,
            id: "groq/llama-4-maverick".to_string(),
        };
        assert_eq!(
            decode_cursor(&encode_cursor(&null_cursor)).unwrap(),
            null_cursor
        );
        for garbage in ["", "!!!!", "%%%%", "a b"] {
            assert!(decode_cursor(garbage).is_err(), "`{garbage}`");
        }
        // A payload that decodes but is not a cursor still fails.
        let not_json = base64url_encode(b"{}");
        assert!(decode_cursor(&not_json).is_err());
        let wrong_shape = base64url_encode(br#"{"s":"blended","v":"lots"}"#);
        assert!(decode_cursor(&wrong_shape).is_err());
    }

    #[test]
    fn base64url_survives_every_byte_and_rejects_pad_characters() {
        let bytes: Vec<u8> = (0..=u8::MAX).collect();
        let encoded = base64url_encode(&bytes);
        assert!(!encoded.contains('='));
        assert_eq!(base64url_decode(&encoded).unwrap(), bytes);
        assert_eq!(base64url_decode("aGVsbG8").unwrap(), b"hello");
        assert!(
            base64url_decode("aGVsbG8=").is_none(),
            "padding is rejected"
        );
        assert!(base64url_decode("a").is_none(), "length 4k+1 is impossible");
    }

    #[test]
    fn percent_decode_keeps_stray_escapes_literal() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%41%42%43"), "ABC");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
