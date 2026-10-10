//! AWS Signature Version 4 for the `Blob` port (issue #622).
//!
//! A presigned URL carries its own authorization: the harness hands out a URL
//! granting one method on one object until it expires, without exposing the
//! secret key. S3 and every S3-compatible store (R2, `MinIO`, B2) speak the
//! same query-string form; a `Blob` adapter supplies only the host, region and
//! service. The module is pure — the caller passes the [`OffsetDateTime`] it
//! read from [`Clock`](crate::Clock) — so it builds for `wasm32` with core.
//!
//! [`authorization_header`] signs an ordinary request, [`presign`] returns a
//! `https://…` URL, and [`verify_presigned`] recomputes the signature and
//! refuses a URL that is malformed, expired or signed for another request.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

/// The algorithm name in `X-Amz-Algorithm` and the `Authorization` header.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The payload hash a presigned URL declares: the body is not known when the URL
/// is minted, so it is signed as this and the store does not check it.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// An access key pair. [`fmt::Debug`] prints the access key id — it is not a
/// secret, it rides in every presigned URL — but never the secret key.
#[derive(Clone)]
pub struct Credentials {
    /// The public key id (`AKIA…`).
    pub access_key_id: String,
    /// The secret key used to derive the signing key. Never logged.
    pub secret_access_key: String,
}

impl Credentials {
    /// A pair from its two parts.
    #[must_use]
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
        }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[redacted]")
            .finish()
    }
}

/// Why a presigned URL was refused by [`verify_presigned`] (issue #622).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SigV4Error {
    /// Not a well-formed presigned URL, or a required `X-Amz-*` parameter is
    /// missing or malformed.
    #[error("malformed presigned URL: {0}")]
    Malformed(String),
    /// `X-Amz-Date + X-Amz-Expires` is in the past.
    #[error("presigned URL has expired")]
    Expired,
    /// The signature does not match: the URL was tampered with, or names other
    /// credentials, region or service, or a different signed header value.
    #[error("presigned URL signature does not match")]
    BadSignature,
}

/// The parts of a request `SigV4` canonicalises. [`authorization_header`] signs
/// the body hash the caller supplies; [`presign`] always signs
/// [`UNSIGNED_PAYLOAD`] and adds the `X-Amz-*` parameters.
#[derive(Debug, Clone)]
pub struct SignableRequest<'a> {
    /// The uppercase HTTP method, e.g. `"GET"` or `"PUT"`.
    pub method: &'a str,
    /// The host, with no scheme and no port unless it is non-default.
    pub host: &'a str,
    /// The URI path, already encoded; [`s3_key_path`] builds one from a key.
    pub path: &'a str,
    /// Query parameters beyond the `X-Amz-*` set [`presign`] appends.
    pub query: &'a [(String, String)],
    /// Headers to sign beyond `host`, which is always signed.
    pub headers: &'a [(String, String)],
}

/// Encodes an S3 object key into an absolute URI path for [`presign`]: each
/// segment percent-encoded once, `/` separators kept. Not double-encoded — a
/// key containing `%20` means a literal `%20`, not a space.
///
/// ```
/// # use cratefield_core::sigv4::s3_key_path;
/// assert_eq!(s3_key_path("cms/avatars/foo bar.png"), "/cms/avatars/foo%20bar.png");
/// ```
#[must_use]
pub fn s3_key_path(key: &str) -> String {
    format!("/{}", uri_encode(key, false))
}

/// Signs `request` and returns the `Authorization` header value. `payload_hash`
/// is the lowercase hex SHA-256 of the body ([`sha256_hex`]); `host` and
/// `x-amz-date` (from `now`) are always signed, and any the caller put in
/// `request.headers` are dropped so exactly one of each is signed.
#[must_use]
pub fn authorization_header(
    credentials: &Credentials,
    region: &str,
    service: &str,
    request: &SignableRequest<'_>,
    payload_hash: &str,
    now: OffsetDateTime,
) -> String {
    let amz_date = amz_date(now);
    let headers = signable_headers(request.host, request.headers, Some(&amz_date));
    let (canonical, signed) = canonical_request(
        request.method,
        request.path,
        request.query,
        &headers,
        payload_hash,
    );
    let signature = sign(credentials, &amz_date, region, service, &canonical);
    let scope = credential_scope(&amz_date[..8], region, service);
    format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        credentials.access_key_id
    )
}

/// Returns a presigned `https://` URL granting `request.method` on
/// `request.host`+`request.path` for `expires_secs` seconds from `now`: the
/// `X-Amz-*` parameters plus any in `request.query`. `host` is always signed;
/// `request.headers` (e.g. `content-type`) are signed too, and the client must
/// then send them with exactly those values. The payload is signed as
/// [`UNSIGNED_PAYLOAD`]. **Never log the URL's query string**: until it expires
/// it is a bearer credential.
#[must_use]
pub fn presign(
    credentials: &Credentials,
    region: &str,
    service: &str,
    request: &SignableRequest<'_>,
    expires_secs: u64,
    now: OffsetDateTime,
) -> String {
    let amz_date = amz_date(now);
    let headers = signable_headers(request.host, request.headers, None);
    let scope = credential_scope(&amz_date[..8], region, service);

    let mut query: Vec<(String, String)> = request.query.to_vec();
    query.push(("X-Amz-Algorithm".to_owned(), ALGORITHM.to_owned()));
    query.push(("X-Amz-Date".to_owned(), amz_date.clone()));
    query.push(("X-Amz-Expires".to_owned(), expires_secs.to_string()));
    query.push((
        "X-Amz-SignedHeaders".to_owned(),
        signed_header_names(&headers),
    ));
    query.push((
        "X-Amz-Credential".to_owned(),
        format!("{}/{scope}", credentials.access_key_id),
    ));

    let (canonical, _) = canonical_request(
        request.method,
        request.path,
        &query,
        &headers,
        UNSIGNED_PAYLOAD,
    );
    let signature = sign(credentials, &amz_date, region, service, &canonical);
    format!(
        "https://{}{}?{}&X-Amz-Signature={signature}",
        request.host,
        request.path,
        canonical_query_string(&query),
    )
}

/// Verifies a URL from [`presign`], recomputing the signature in constant time.
/// Every header named in `X-Amz-SignedHeaders` other than `host` must appear in
/// `headers` with the value it was presigned with.
///
/// # Errors
///
/// [`SigV4Error`] as documented on its variants, never a panic.
pub fn verify_presigned(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    credentials: &Credentials,
    region: &str,
    service: &str,
    now: OffsetDateTime,
) -> Result<(), SigV4Error> {
    let (host, path, query) = split_url(url)?;
    let param = |name: &str| {
        query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if param("X-Amz-Algorithm") != Some(ALGORITHM) {
        return Err(malformed("unexpected X-Amz-Algorithm"));
    }
    let amz_date = param("X-Amz-Date").ok_or_else(|| malformed("missing X-Amz-Date"))?;
    let signed_headers =
        param("X-Amz-SignedHeaders").ok_or_else(|| malformed("missing headers"))?;
    let provided = param("X-Amz-Signature").ok_or_else(|| malformed("missing signature"))?;

    // The credential must name exactly the key, date, region and service in
    // force here; otherwise the signature could never match anyway, but a clear
    // refusal beats a confusing one.
    let date = amz_date
        .get(..8)
        .ok_or_else(|| malformed("X-Amz-Date is too short"))?;
    let credential = param("X-Amz-Credential").ok_or_else(|| malformed("missing credential"))?;
    let scope = credential_scope(date, region, service);
    if credential != format!("{}/{scope}", credentials.access_key_id) {
        return Err(SigV4Error::BadSignature);
    }

    let signed_at =
        parse_amz_date(amz_date).ok_or_else(|| malformed("X-Amz-Date is not a timestamp"))?;
    let expires: u64 = param("X-Amz-Expires")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| malformed("bad X-Amz-Expires"))?;
    let expires = i64::try_from(expires).map_err(|_| malformed("X-Amz-Expires is out of range"))?;
    // Checked: an absurd `X-Amz-Expires` must refuse, not overflow the date
    // type and panic — which would break the "never a panic" contract before
    // the signature is even checked.
    let deadline = signed_at
        .checked_add(time::Duration::seconds(expires))
        .ok_or_else(|| malformed("X-Amz-Expires is out of range"))?;
    if deadline < now {
        return Err(SigV4Error::Expired);
    }

    let mut canonical_headers = Vec::with_capacity(signed_headers.len());
    for name in signed_headers.split(';') {
        let value = if name == "host" {
            host.clone()
        } else {
            header_value(headers, name)
                .ok_or_else(|| malformed("a signed header the client did not send"))?
        };
        canonical_headers.push((name.to_owned(), value));
    }

    let query: Vec<(String, String)> = query
        .iter()
        .filter(|(key, _)| key != "X-Amz-Signature")
        .cloned()
        .collect();
    let (canonical, _) =
        canonical_request(method, &path, &query, &canonical_headers, UNSIGNED_PAYLOAD);
    let expected = sign(credentials, amz_date, region, service, &canonical);
    if bool::from(expected.as_bytes().ct_eq(provided.as_bytes())) {
        Ok(())
    } else {
        Err(SigV4Error::BadSignature)
    }
}

/// Lowercase hex SHA-256 of `bytes`, the payload hash [`authorization_header`]
/// takes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// A URL split into `(host, path, decoded query pairs)`.
type UrlParts = (String, String, Vec<(String, String)>);

/// The parts of `url`, or a malformed refusal.
fn split_url(url: &str) -> Result<UrlParts, SigV4Error> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| malformed("not an absolute URL"))?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let (host, tail) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
    // A presigned URL never carries userinfo; a host with an `@` is not a host.
    if scheme.is_empty() || host.is_empty() || host.contains('@') {
        return Err(malformed("missing host"));
    }
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((percent_decode(name)?, percent_decode(value)?))
        })
        .collect::<Result<_, SigV4Error>>()?;
    Ok((
        host.to_owned(),
        if path.is_empty() { "/" } else { path }.to_owned(),
        query,
    ))
}

/// Percent-decodes `value`; a stray `%` or a non-UTF-8 byte is malformed.
fn percent_decode(value: &str) -> Result<String, SigV4Error> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let digit = |at: usize| bytes.get(at).and_then(|byte| (*byte as char).to_digit(16));
        let (Some(high), Some(low)) = (digit(i + 1), digit(i + 2)) else {
            return Err(malformed("bad percent-encoding"));
        };
        out.push(u8::try_from(high << 4 | low).expect("two hex digits fit in a byte"));
        i += 3;
    }
    String::from_utf8(out).map_err(|_| malformed("query is not UTF-8"))
}

fn malformed(why: &str) -> SigV4Error {
    SigV4Error::Malformed(why.to_owned())
}

/// Whitespace-collapsed, the form `SigV4` canonicalises a header value to.
fn collapse(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The first value of header `name` (case-insensitively), whitespace-collapsed.
fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| collapse(value))
}

/// The headers to sign: the caller's (minus any `host`/`x-amz-date`, supplied
/// here so there is exactly one of each), plus `host` and, when given,
/// `x-amz-date`.
fn signable_headers(
    host: &str,
    headers: &[(String, String)],
    amz_date: Option<&str>,
) -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("host") && !name.eq_ignore_ascii_case("x-amz-date")
        })
        .cloned()
        .collect();
    all.push(("host".to_owned(), host.to_owned()));
    all.extend(amz_date.map(|date| ("x-amz-date".to_owned(), date.to_owned())));
    all
}

/// The `;`-joined, lowercase, sorted, de-duplicated names of `headers`.
fn signed_header_names(headers: &[(String, String)]) -> String {
    let mut names: Vec<String> = headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    names.join(";")
}

/// The canonical request and its signed-header list, per the `SigV4` spec.
fn canonical_request(
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    payload_hash: &str,
) -> (String, String) {
    use std::fmt::Write as _;
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), collapse(value)))
        .collect();
    sorted.sort();
    let mut block = String::new();
    for (name, value) in &sorted {
        let _ = writeln!(block, "{name}:{value}");
    }
    let signed = sorted
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{method}\n{path}\n{}\n{block}\n{signed}\n{payload_hash}",
        canonical_query_string(query),
    );
    (canonical, signed)
}

/// The canonical query string: each key and value percent-encoded once, the
/// pairs sorted by encoded key then encoded value, joined with `&`.
fn canonical_query_string(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(key, value)| (uri_encode(key, true), uri_encode(value, true)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `SigV4` URI encoding: unreserved bytes (`A-Za-z0-9-._~`) survive, everything
/// else becomes uppercase `%XX`. `/` survives only when `encode_slash` is false.
fn uri_encode(value: &str, encode_slash: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || (byte == b'/' && !encode_slash);
        if keep {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `{date}/{region}/{service}/aws4_request`, the credential scope.
fn credential_scope(date: &str, region: &str, service: &str) -> String {
    format!("{date}/{region}/{service}/aws4_request")
}

/// The hex signature over `canonical` for a request stamped `amz_date`, in
/// `region`/`service`.
fn sign(
    credentials: &Credentials,
    amz_date: &str,
    region: &str,
    service: &str,
    canonical: &str,
) -> String {
    let date = &amz_date[..8];
    let scope = credential_scope(date, region, service);
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let mut key = hmac(
        format!("AWS4{}", credentials.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    for part in [region, service] {
        key = hmac(&key, part.as_bytes());
    }
    let key = hmac(&key, b"aws4_request");
    hex(&hmac(&key, string_to_sign.as_bytes()))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Lowercase hex, the encoding `SigV4` uses for every digest.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// `YYYYMMDDTHHMMSSZ`, the `X-Amz-Date` stamp, read in UTC.
fn amz_date(now: OffsetDateTime) -> String {
    let now = now.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    )
}

/// Parses `YYYYMMDDTHHMMSSZ` as UTC; `None` on anything else.
fn parse_amz_date(value: &str) -> Option<OffsetDateTime> {
    if value.len() != 16 || value.as_bytes()[8] != b'T' || value.as_bytes()[15] != b'Z' {
        return None;
    }
    let at = |range: std::ops::Range<usize>| value.get(range)?.parse::<u8>().ok();
    let year = value.get(0..4)?.parse::<i32>().ok()?;
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(at(4..6)?).ok()?, at(6..8)?)
            .ok()?;
    let at = time::Time::from_hms(at(9..11)?, at(11..13)?, at(13..15)?).ok()?;
    Some(time::PrimitiveDateTime::new(date, at).assume_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The suite's published signatures for `get-vanilla`,
    /// `get-vanilla-query-order-key-case` and `post-vanilla`.
    const VANILLA: &str = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
    const QUERY: &str = "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500";
    const POST: &str = "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b";
    /// The SHA-256 of the empty body every suite vector signs.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// A UTC timestamp — 20150830T123600Z is the suite's stamp, 20130524T000000Z
    /// the S3 documentation example's.
    fn at(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> OffsetDateTime {
        let date =
            time::Date::from_calendar_date(year, time::Month::try_from(month).expect("month"), day)
                .expect("a valid test date");
        let time = time::Time::from_hms(hour, minute, second).expect("a valid test time");
        time::PrimitiveDateTime::new(date, time).assume_utc()
    }

    /// AKIDEXAMPLE / wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY — the suite pair.
    fn suite() -> Credentials {
        Credentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    }

    /// The `Authorization` header the suite's vectors expect, given a signature.
    fn expected(signature: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature={signature}"
        )
    }

    /// The suite's `method /` header for `query`, at the suite's stamp.
    fn suite_header(method: &str, query: &[(String, String)]) -> String {
        authorization_header(
            &suite(),
            "us-east-1",
            "service",
            &SignableRequest {
                method,
                host: "example.amazonaws.com",
                path: "/",
                query,
                headers: &[],
            },
            EMPTY,
            at(2015, 8, 30, 12, 36, 0),
        )
    }

    /// A request on the harness-style bucket, the fixture the verify tests use.
    fn bucket(method: &str) -> SignableRequest<'_> {
        SignableRequest {
            method,
            host: "bucket.example.com",
            path: "/cms/clip.mp3",
            query: &[],
            headers: &[],
        }
    }

    /// `verify_presigned` for `url` as `method`, region `auto`, service `s3`.
    fn verify(
        url: &str,
        method: &str,
        creds: &Credentials,
        now: OffsetDateTime,
    ) -> Result<(), SigV4Error> {
        verify_presigned(url, method, &[], creds, "auto", "s3", now)
    }

    #[test]
    fn published_vectors() {
        // get-vanilla, get-vanilla-query-order-key-case (canonicalised to
        // Param1=value1&Param2=value2) and post-vanilla.
        let ordered = [
            ("Param2".to_owned(), "value2".to_owned()),
            ("Param1".to_owned(), "value1".to_owned()),
        ];
        assert_eq!(suite_header("GET", &[]), expected(VANILLA));
        assert_eq!(suite_header("POST", &[]), expected(POST));
        assert_eq!(suite_header("GET", &ordered), expected(QUERY));

        // The S3 documentation's presigned-URL example, byte for byte.
        let credentials = Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        let request = SignableRequest {
            method: "GET",
            host: "examplebucket.s3.amazonaws.com",
            path: "/test.txt",
            query: &[],
            headers: &[],
        };
        let url = presign(
            &credentials,
            "us-east-1",
            "s3",
            &request,
            86400,
            at(2013, 5, 24, 0, 0, 0),
        );
        assert_eq!(
            url,
            "https://examplebucket.s3.amazonaws.com/test.txt\
             ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z\
             &X-Amz-Expires=86400\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    #[test]
    fn presign_round_trips_and_refuses_tampering_or_wrong_scope() {
        let credentials = suite();
        let other = Credentials::new("AKIDOTHER", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let now = at(2026, 1, 1, 0, 0, 0);
        let url = presign(&credentials, "auto", "s3", &bucket("GET"), 3600, now);
        verify(&url, "GET", &credentials, now).expect("the URL verifies against the request");

        // Tampered signature and path, another key, another region: all refused.
        let sig = url.replace("X-Amz-Signature=", "X-Amz-Signature=0");
        let path = url.replace("/cms/clip.mp3", "/cms/other.mp3");
        let bad = Err(SigV4Error::BadSignature);
        assert_eq!(verify(&sig, "GET", &credentials, now), bad);
        assert_eq!(verify(&path, "GET", &credentials, now), bad);
        assert_eq!(verify(&url, "GET", &other, now), bad);
        let region = verify_presigned(&url, "GET", &[], &credentials, "us-east-1", "s3", now);
        assert_eq!(region, bad);

        // A URL that signed `content-type` must be verified with that value.
        let put = bucket("PUT");
        let put = SignableRequest {
            headers: &[("content-type".to_owned(), "audio/mpeg".to_owned())],
            ..put
        };
        let ct = presign(&credentials, "auto", "s3", &put, 3600, now);
        let wrong = [("content-type".to_owned(), "image/png".to_owned())];
        let mismatch = verify_presigned(&ct, "PUT", &wrong, &credentials, "auto", "s3", now);
        assert_eq!(mismatch, bad);
    }

    #[test]
    fn verify_refuses_expiry_and_malformed_urls() {
        let credentials = suite();
        let now = at(2026, 1, 1, 0, 0, 0);
        let url = presign(&credentials, "auto", "s3", &bucket("GET"), 3600, now);
        // One second past X-Amz-Date + X-Amz-Expires; the deadline itself is valid.
        let past = at(2026, 1, 1, 1, 0, 1);
        let deadline = at(2026, 1, 1, 1, 0, 0);
        assert_eq!(
            verify(&url, "GET", &credentials, past),
            Err(SigV4Error::Expired)
        );
        verify(&url, "GET", &credentials, deadline).expect("the deadline is valid");
        // An `X-Amz-Expires` too large to add must refuse, not panic.
        let huge = url.replace("X-Amz-Expires=3600", "X-Amz-Expires=9223372036854775807");
        assert!(matches!(
            verify(&huge, "GET", &credentials, now),
            Err(SigV4Error::Malformed(_))
        ));
        for url in [
            "not a url",
            "https://bucket.example.com/key.mp3",
            "https://bucket.example.com/key.mp3?X-Amz-Algorithm=AWS4-HMAC-SHA256",
        ] {
            let result = verify(url, "GET", &credentials, now);
            assert!(matches!(result, Err(SigV4Error::Malformed(_))), "{url}");
        }
    }

    #[test]
    fn s3_key_path_and_debug_redaction() {
        assert_eq!(s3_key_path("CMS/clip.mp3"), "/CMS/clip.mp3");
        // A space is encoded; the separator is not; `+` is not a space.
        assert_eq!(s3_key_path("cms/avatar 1.png"), "/cms/avatar%201.png");
        assert_eq!(s3_key_path("a/b+c"), "/a/b%2Bc");
        let debug = format!("{:?}", suite());
        assert!(debug.contains("AKIDEXAMPLE"), "{debug}");
        assert!(!debug.contains("wJalrXUtnFEMI"), "{debug}");
    }
}
