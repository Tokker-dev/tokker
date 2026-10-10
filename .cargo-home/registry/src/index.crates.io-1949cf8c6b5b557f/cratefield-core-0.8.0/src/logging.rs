//! Log-field redaction shared by every runtime (architecture section
//! 11, issue #13): field names matching `(?i)secret|token|key|
//! authorization|password` never reach output, and email-ish values are
//! logged only as a 12-hex `subject_hash` pseudonym — a keyed HMAC when
//! a runtime installed [`set_log_pseudonym_key`], and a fixed placeholder
//! when it has not: never a bare digest, even misconfigured (issue #135).
//!
//! Field **names** are only half the story (issue #135): a secret riding
//! inside a generic `uri`, `message` or `error` value is invisible to a
//! name rule. Every value that is not redacted by name therefore also
//! passes [`scrub_text`], which rewrites emails, signed tokens, URL query
//! strings, URL credentials and `Bearer` values wherever they appear.
//!
//! The tracing **formatter** lives in each runtime; the redaction rules
//! live here so Workers and native logs cannot drift apart.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use tracing::field::{Field, Visit};

/// A process-wide key that turns a logged email pseudonym into a keyed HMAC
/// rather than a bare hash. See [`set_log_pseudonym_key`].
static LOG_PSEUDONYM_KEY: OnceLock<Vec<u8>> = OnceLock::new();

/// Domain-separates the pseudonym HMAC from the signer's use of the same
/// secret, and versions it so the scheme can change without silently
/// colliding.
const PSEUDONYM_DOMAIN: &[u8] = b"cratefield/log-pseudonym/v1\x00";

/// The value [`subject_hash`] emits when no pseudonym key is installed: a
/// fixed placeholder, never a function of the input (issue #135, fail-closed).
/// The unkeyed path is reachable in production — a runtime that finds
/// `HARNESS_SECRET` missing or too short only warns and keeps serving, so a
/// misconfigured deployment must still not emit a truncated bare SHA-256
/// (deterministic, unkeyed, dictionary-reversible for low-entropy emails).
/// All-zero hex is obviously-not-a-pseudonym in a log grep, lies outside the
/// range any real HMAC prefix occupies, and keeps the `subject_hash:<12 hex>`
/// output shape that [`scrub_text`]'s idempotence and the runtime formatters
/// depend on, so nothing downstream changes.
const UNKEYED_PSEUDONYM: &str = "000000000000";

/// Installs the key that [`subject_hash`] uses to pseudonymise email values in
/// logs (issue #135). A bare SHA-256 of a low-entropy email is
/// dictionary-reversible, so a runtime derives this from `HARNESS_SECRET` and
/// installs it once at startup; `subject_hash` then emits `HMAC(key, email)`
/// instead. Unset (tests, or a runtime whose `HARNESS_SECRET` failed
/// validation) makes `subject_hash` emit a fixed all-zero `000000000000`
/// placeholder — fail-closed; no digest of the address ever reaches a sink.
/// Boot-time infrastructure, not request state (ADR 0007); first-install-wins.
pub fn set_log_pseudonym_key(key: &[u8]) {
    let _ = LOG_PSEUDONYM_KEY.set(key.to_vec());
}

/// Whether a field name marks a secret: matches
/// `(?i)secret|token|key|authorization|password`.
#[must_use]
pub fn is_secret_field(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    ["secret", "token", "key", "authorization", "password"]
        .iter()
        .any(|needle| lowered.contains(needle))
}

/// Whether a field is expected to carry an email address.
#[must_use]
pub fn is_email_field(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    lowered.contains("email") || lowered == "subject"
}

/// The redacted form of an email-ish value: a 12-hex pseudonym, no `@` ever
/// reaching the logs. When a [pseudonym key](set_log_pseudonym_key) is
/// installed it is `HMAC-SHA256(key, domain ‖ value)` (a keyed pseudonym,
/// resistant to dictionary reversal); when it is not, a fixed all-zero
/// placeholder — correlation is lost, but a bare digest never leaks
/// (issue #135, fail-closed).
#[must_use]
pub fn subject_hash(value: &str) -> String {
    pseudonym_hex(LOG_PSEUDONYM_KEY.get().map(Vec::as_slice), value)
}

/// The pseudonym decision of [`subject_hash`], pure in `key` so both arms
/// are testable without touching the process-wide `OnceLock` (which is
/// first-install-wins and already set by `tests/log_pseudonym.rs`).
fn pseudonym_hex(key: Option<&[u8]>, value: &str) -> String {
    use std::fmt::Write as _;
    // The redaction path never panics: HMAC accepts any key length, and
    // the `.ok()` arm covers the impossible error without unwrapping it —
    // a key that fails to install is treated as no key at all (fail-closed).
    let digest = key.and_then(|secret| {
        Hmac::<Sha256>::new_from_slice(secret).ok().map(|mut mac| {
            mac.update(PSEUDONYM_DOMAIN);
            mac.update(value.as_bytes());
            mac.finalize().into_bytes()
        })
    });
    let Some(digest) = digest else {
        return UNKEYED_PSEUDONYM.to_owned();
    };
    let mut hex = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// How one recorded field is stored: `[redacted]` for secrets, the hash
/// for emails, the value passed through [`scrub_text`] otherwise (issue
/// #135: a secret inside a generic `uri`/`message`/`error` value is
/// invisible to the field-name rules alone).
#[must_use]
pub fn redacted_value(name: &str, value: &str) -> String {
    if is_secret_field(name) {
        "[redacted]".to_owned()
    } else if is_email_field(name) && value.contains('@') {
        format!("subject_hash:{}", subject_hash(value))
    } else {
        scrub_text(value)
    }
}

// ---------------------------------------------------------------------------
// Value-level scrubbing (issue #135)

/// The marker [`scrub_text`] leaves in place of redacted material.
const REDACTED: &str = "[redacted]";

/// The parameter names whose value is an `AWS SigV4` credential (issue #622):
/// the signature, credential scope and STS session token of a presigned URL's
/// query, or the bare `Credential=`/`Signature=` of an
/// `Authorization: AWS4-HMAC-SHA256 …` header. `X-Amz-Signature=` contains
/// `Signature=`; the earliest match wins, so the longer name is the one
/// redacted.
const SIGV4_SECRET_NAMES: [&str; 5] = [
    "X-Amz-Signature=",
    "X-Amz-Credential=",
    "X-Amz-Security-Token=",
    "Credential=",
    "Signature=",
];

/// Where a `SigV4` parameter's value ends: at the next `&` or `,` (query and
/// header separators) or any whitespace. `[` is deliberately not one, so
/// re-scrubbing `X-Amz-Signature=[redacted]` redacts `[redacted]` to itself
/// and stays idempotent.
fn sigv4_value_end(c: char) -> bool {
    c.is_ascii_whitespace() || c == '&' || c == ','
}

/// Bytes that may appear inside a URL run in log text. Whitespace and the
/// delimiters a URL is typically wrapped in (`"`, `'`, `(`, `<`, …) end
/// the run, so a URL embedded in prose or `{:?}` output is matched whole.
/// `[` and `]` stay inside the run so a re-scrub of an already-redacted
/// `?[redacted]` query is a no-op: the scrubber is idempotent.
fn url_body_byte(b: u8) -> bool {
    !matches!(
        b,
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b'"'
            | b'\''
            | b'<'
            | b'>'
            | b'`'
            | b','
            | b';'
            | b')'
            | b'}'
            | b'\\'
            | b'|'
    )
}

fn base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn email_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'.' | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

fn email_domain_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

/// Scrubs secrets out of a free-text **value** (issue #135).
///
/// Field-name redaction ([`redacted_value`]) cannot see a secret riding
/// inside a generic field — an `error` carrying a driver's `DETAIL:` line
/// that quotes a row, a `message` carrying a confirmation URL, a `uri`
/// carrying `?token=…`. Every value that is not redacted by name goes
/// through here:
///
/// - an email address becomes `[subject_hash:<pseudonym>]` — the same
///   keyed pseudonym the email fields use, so correlation survives;
/// - a signed token or JWT (`eyJ…`, dot-separated base64url runs) becomes
///   `[redacted]` — the signer's payload is base64url JSON, which always
///   starts with `eyJ`;
/// - a GitHub token (`ghs_…`, `ghu_…`, `gho_…`, `ghp_…`, `ghr_…` or a
///   `github_pat_…` fine-grained PAT) becomes `[redacted]` — a leaked
///   token grants API access for its whole lifetime;
/// - a PEM private-key block (`-----BEGIN … PRIVATE KEY-----` through
///   `-----END … PRIVATE KEY-----`) becomes `[redacted]` whole;
/// - an `AWS SigV4` credential (`X-Amz-Signature=…`, `X-Amz-Credential=…`, or
///   the `Authorization: AWS4-HMAC-SHA256 Credential=…, Signature=…` header
///   form) becomes `…=[redacted]` (issue #622);
/// - the query of a URL (`scheme://…?…`) or of a path-shaped value
///   (`/v1/…?…`) becomes `?[redacted]` — confirmation, unsubscribe and
///   status tokens ride in the query;
/// - URL userinfo (`scheme://user:pass@host`) becomes
///   `scheme://[redacted]@host` — a connect failure must not disclose
///   database credentials;
/// - `Bearer <credential>` becomes `Bearer [redacted]`.
///
/// The rules are heuristics tuned for log values and deliberately
/// over-redact: losing a query string costs debugging convenience,
/// leaking a token or an address costs users. Idempotent — scrubbing
/// already-scrubbed text changes nothing. Never panics.
#[must_use]
pub fn scrub_text(value: &str) -> String {
    let pem = scrub_pem_private_keys(value);
    let urls = scrub_urls(&pem);
    let paths = scrub_path_queries(&urls);
    let tokens = scrub_dotted_tokens(&paths);
    let github = scrub_github_tokens(&tokens);
    let bearer = scrub_bearer(&github);
    let sigv4 = scrub_sigv4(&bearer);
    scrub_emails(&sigv4)
}

/// Cuts one **known** request URL back to its origin everywhere it appears
/// in `message`, and redacts that request's bare target as well (issues
/// #228, #229).
///
/// [`scrub_text`] cannot express this, and no general rule could. It
/// redacts what is recognisably a secret — a query string, userinfo, a
/// signed token, an address — and a URL *path* is none of those. On this
/// harness some paths are the entire credential:
/// `https://api.push.apple.com/3/device/<device token>` addresses a device
/// *by* its token, and a Web Push endpoint's path is a bearer capability —
/// whoever holds it can push to that browser indefinitely. Only the caller
/// knows which URL it just sent to, so only the caller can say "this path
/// is a secret"; this function is that knowledge applied to a message.
///
/// What survives is the origin — scheme, host and port, never userinfo —
/// which is what keeps a transport failure diagnosable at all ("could not
/// reach api.push.apple.com" answers most of them) and is the line `fz push
/// inspect-subscription` already draws when it prints the `aud` and
/// withholds the path.
///
/// It is a pass, not a replacement: an error message is free to quote
/// things this call knows nothing about, so callers run [`scrub_text`] over
/// the result too — this pass knows one URL, that one knows every shape of
/// secret.
///
/// A `url` that is not absolute (`scheme://host…`) leaves `message`
/// untouched, so an empty or unparsed value can never become a degenerate
/// replacement. Never panics.
///
/// ```
/// # use cratefield_core::scrub_request_url;
/// let url = "https://api.push.apple.com/3/device/DEVICETOKEN";
/// let safe = scrub_request_url(&format!("Fetch API cannot load: {url}."), url);
/// assert_eq!(safe, "Fetch API cannot load: https://api.push.apple.com.");
/// ```
#[must_use]
pub fn scrub_request_url(message: &str, url: &str) -> String {
    let Some((origin, target)) = origin_and_target(url) else {
        return message.to_owned();
    };
    let reduced = message.replace(url, &origin);
    // `/` alone carries nothing and is in half the prose there is.
    if target.len() > 1 {
        reduced.replace(target, REDACTED)
    } else {
        reduced
    }
}

/// Splits an absolute URL into the origin that may be logged and the
/// request target that may not. `None` when `url` is not absolute, which
/// is what makes [`scrub_request_url`] a no-op rather than a hazard.
fn origin_and_target(url: &str) -> Option<(String, &str)> {
    let colon = url.find("://")?;
    let scheme = &url[..colon];
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let rest = &url[colon + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, target) = rest.split_at(end);
    // Userinfo is a credential in its own right, so it never reaches the
    // origin: `scheme://user:pass@host` is logged as `scheme://host`.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty() {
        return None;
    }
    Some((format!("{scheme}://{host}"), target))
}

/// The URL pass of [`scrub_text`]: query and userinfo redaction for every
/// absolute URL (`scheme://…`) in the value.
fn scrub_urls(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find("://") {
        let colon = search + relative;
        let mut scheme_start = colon;
        while scheme_start > processed {
            let b = bytes[scheme_start - 1];
            if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.') {
                scheme_start -= 1;
            } else {
                break;
            }
        }
        if scheme_start == colon {
            // "://" with no scheme in front of it is not a URL.
            search = colon + 3;
            continue;
        }
        let mut end = colon + 3;
        while end < bytes.len() && url_body_byte(bytes[end]) {
            end += 1;
        }
        out.push_str(&value[processed..scheme_start]);
        out.push_str(&scrub_one_url(&value[scheme_start..end]));
        processed = end;
        search = end;
    }
    out.push_str(&value[processed..]);
    out
}

fn scrub_one_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let mut out = String::with_capacity(url.len());
    out.push_str(scheme);
    out.push_str("://");
    match authority.rfind('@') {
        Some(at) => {
            out.push_str(REDACTED);
            out.push_str(&authority[at..]);
        }
        None => out.push_str(authority),
    }
    match tail.find('?') {
        Some(query) => {
            out.push_str(&tail[..query]);
            out.push('?');
            out.push_str(REDACTED);
        }
        None => out.push_str(tail),
    }
    out
}

/// The path pass of [`scrub_text`]: a whitespace-delimited word that is
/// itself a path — a `uri` field, a redirect target inside a message —
/// loses its query: "/v1/waitlist/status?token=…".
fn scrub_path_queries(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while !rest.is_empty() {
        let lead = rest
            .find(|c: char| !c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        out.push_str(&rest[..lead]);
        let word_end = rest[lead..]
            .find(|c: char| c.is_ascii_whitespace())
            .map_or(rest.len(), |offset| lead + offset);
        let word = &rest[lead..word_end];
        match word.strip_prefix('/') {
            Some(_) => match word.find('?') {
                Some(query) => {
                    out.push_str(&word[..query]);
                    out.push('?');
                    out.push_str(REDACTED);
                }
                None => out.push_str(word),
            },
            None => out.push_str(word),
        }
        rest = &rest[word_end..];
    }
    out
}

/// The signed-token pass of [`scrub_text`]: a run of dot-separated
/// base64url segments, each at least 8 chars, starting with `eyJ`.
fn scrub_dotted_tokens(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find("eyJ") {
        let start = search + relative;
        if start > processed && (base64url_byte(bytes[start - 1]) || bytes[start - 1] == b'.') {
            // A mid-run hit inside a longer token or word, not its start.
            search = start + 3;
            continue;
        }
        let mut end = start;
        let mut segments = 0;
        let mut all_segments_long = true;
        loop {
            let segment_start = end;
            while end < bytes.len() && base64url_byte(bytes[end]) {
                end += 1;
            }
            segments += 1;
            if end - segment_start < 8 {
                all_segments_long = false;
            }
            if end + 1 < bytes.len() && bytes[end] == b'.' && base64url_byte(bytes[end + 1]) {
                end += 1;
                continue;
            }
            break;
        }
        if segments >= 2 && all_segments_long {
            out.push_str(&value[processed..start]);
            out.push_str(REDACTED);
            processed = end;
        }
        search = end.max(start + 3);
    }
    out.push_str(&value[processed..]);
    out
}

/// The `Bearer`-credential pass of [`scrub_text`].
fn scrub_bearer(value: &str) -> String {
    const LABEL: &str = "Bearer ";
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find(LABEL) {
        let label_end = search + relative + LABEL.len();
        let mut end = label_end;
        while end < bytes.len()
            && (base64url_byte(bytes[end])
                || matches!(bytes[end], b'.' | b'+' | b'/' | b'=' | b'~'))
        {
            end += 1;
        }
        if end - label_end >= 8 {
            out.push_str(&value[processed..label_end]);
            out.push_str(REDACTED);
            processed = end;
        }
        search = label_end.max(processed);
    }
    out.push_str(&value[processed..]);
    out
}

/// The `SigV4` pass of [`scrub_text`]: the credential-bearing parameters of a
/// presigned URL — or of the `Authorization: AWS4-HMAC-SHA256 …` header form
/// — lose their values (issue #622). The URL pass already drops the whole
/// query of an absolute URL; this catches a bare query string, or a header
/// value, which have neither a scheme nor a secret field name around them.
fn scrub_sigv4(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    loop {
        let found = SIGV4_SECRET_NAMES
            .iter()
            .filter_map(|name| rest.find(name).map(|at| (at, *name)))
            .min_by_key(|(at, _)| *at);
        let Some((at, name)) = found else {
            out.push_str(rest);
            return out;
        };
        let value_start = at + name.len();
        out.push_str(&rest[..value_start]);
        let end = rest[value_start..]
            .find(sigv4_value_end)
            .map_or(rest.len(), |offset| value_start + offset);
        out.push_str(REDACTED);
        rest = &rest[end..];
    }
}

/// The GitHub-token pass of [`scrub_text`] (issue #623): a GitHub token —
/// installation (`ghs_`), user-to-server (`ghu_`), OAuth (`gho_`),
/// personal (`ghp_`), refresh (`ghr_`), or a `github_pat_` fine-grained
/// PAT — becomes `[redacted]` wherever it appears.
///
/// A GitHub token is opaque and high-entropy, with no internal structure
/// beyond its prefix and body alphabet; a leaked one grants API access for
/// its whole lifetime, and it turns up in a log line as readily as in a
/// `uri` or an `error` (a request that echoed `Authorization: token
/// ghp_…`). The body must be at least [`MIN_GITHUB_TOKEN_BODY`] chars — a
/// real token's is 36 or more — so ordinary values that merely begin with
/// the prefix's letters (`ghost_town`, a bare `ghs`) survive, and a prefix
/// only counted when it starts a token (the `ghs_` in `highs_levels` does
/// not).
fn scrub_github_tokens(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some((start, body_start)) = github_token_at(bytes, search) {
        let mut end = body_start;
        while end < bytes.len() && token_body_byte(bytes[end]) {
            end += 1;
        }
        if end - body_start >= MIN_GITHUB_TOKEN_BODY {
            out.push_str(&value[processed..start]);
            out.push_str(REDACTED);
            processed = end;
            search = end;
        } else {
            // Too short to be a token: resume after the prefix rather than
            // the body, so a later, real token cannot be skipped.
            search = body_start;
        }
    }
    out.push_str(&value[processed..]);
    out
}

/// The prefixes GitHub puts on its tokens, longest first so a prefix that
/// is a tail of a longer one cannot shadow it.
const GITHUB_TOKEN_PREFIXES: [&str; 6] = ["github_pat_", "ghs_", "ghu_", "gho_", "ghp_", "ghr_"];

/// Shortest body the scrubber will call a GitHub token. Real bodies are 36
/// chars and up; the floor keeps ordinary words out of the redactor.
const MIN_GITHUB_TOKEN_BODY: usize = 20;

/// A byte GitHub's token body alphabet allows: `[A-Za-z0-9_]`.
fn token_body_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The first GitHub token prefix at or after `from`, as `(prefix_start,
/// body_start)`; `None` when there is none. A prefix is only counted when
/// it starts a token, and the left boundary is **alphanumeric**, not the
/// whole token-body alphabet: `_` ends a word as a space does, so
/// `prefix_ghp_…` is a token while the `ghs_` inside `highs_levels` is not
/// (the `i` before it is alphanumeric).
fn github_token_at(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut at = from;
    while at < bytes.len() {
        let starts_token = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        if starts_token {
            for prefix in GITHUB_TOKEN_PREFIXES {
                if bytes[at..].starts_with(prefix.as_bytes()) {
                    return Some((at, at + prefix.len()));
                }
            }
        }
        at += 1;
    }
    None
}

/// The PEM private-key pass of [`scrub_text`] (issue #623): a
/// `-----BEGIN … PRIVATE KEY-----` … `-----END … PRIVATE KEY-----` block
/// becomes `[redacted]` whole.
///
/// A private key pasted into a config error or a `message` is the most
/// damaging value a log can carry; headers, base64 body and footer are
/// replaced together, so no partial key survives. Public-key and
/// certificate blocks (`BEGIN PUBLIC KEY`, `BEGIN CERTIFICATE`) do not
/// carry `PRIVATE KEY` and are left alone. A block with no readable
/// footer runs to the end of the value and is redacted in full rather
/// than half.
fn scrub_pem_private_keys(value: &str) -> String {
    const BEGIN: &str = "-----BEGIN ";
    const END: &str = "-----END ";
    const PRIVATE_KEY: &str = " PRIVATE KEY-----";
    // Longest PEM header lookahead. A `-----BEGIN …-----` line is well
    // under this; bounding the scan keeps the pass linear when one long
    // line holds many `-----BEGIN ` candidates — searching to the newline
    // (or the end) for each would rescan the tail and go quadratic.
    const MAX_HEADER_LEN: usize = 128;
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find(BEGIN) {
        let start = search + relative;
        // The `-----BEGIN …-----` line ends at the next newline, within
        // the bound.
        let header_end = header_line_end(value, start, MAX_HEADER_LEN);
        if !value[start..header_end].contains(PRIVATE_KEY) {
            search = start + BEGIN.len();
            continue;
        }
        let block_end = value[header_end..]
            .find(END)
            .and_then(|rel| {
                let at = header_end + rel;
                let line_end = header_line_end(value, at, MAX_HEADER_LEN);
                let line = &value[at..line_end];
                if !line.contains(PRIVATE_KEY) {
                    return None;
                }
                // Stop after the footer's closing `-----`, not at the end
                // of the line: text may follow the footer on the same line
                // and is not part of the key.
                Some(line.rfind("-----").map_or(line_end, |o| at + o + 5))
            })
            .unwrap_or(value.len());
        out.push_str(&value[processed..start]);
        out.push_str(REDACTED);
        processed = block_end;
        search = block_end;
    }
    out.push_str(&value[processed..]);
    out
}

/// Where the line beginning at `start` ends — the next newline, or the end
/// of the value — looked at over at most `max_len` bytes, snapped forward
/// to a char boundary. The bound is what keeps [`scrub_pem_private_keys`]
/// linear: a line that never ends is read once per candidate, not once per
/// candidate to the end of the value.
fn header_line_end(value: &str, start: usize, max_len: usize) -> usize {
    let mut window_end = start.saturating_add(max_len).min(value.len());
    while window_end < value.len() && !value.is_char_boundary(window_end) {
        window_end += 1;
    }
    value[start..window_end]
        .find('\n')
        .map_or(window_end, |offset| start + offset)
}

/// The email pass of [`scrub_text`]: RFC-ish local part, dotted domain
/// whose last label is alphabetic — conservative enough that dependency
/// specs (`crate@1.0.0`) and versions survive, strict enough that every
/// address the harness itself accepts ([`crate::email::is_valid`]) is
/// caught.
fn scrub_emails(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut processed = 0;
    let mut search = 0;
    while let Some(relative) = value[search..].find('@') {
        let at = search + relative;
        let mut start = at;
        while start > processed && email_local_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = at + 1;
        while end < bytes.len() && email_domain_byte(bytes[end]) {
            end += 1;
        }
        let local = &value[start..at];
        let domain = &value[at + 1..end];
        if email_shape_ok(local, domain) {
            out.push_str(&value[processed..start]);
            out.push_str("[subject_hash:");
            out.push_str(&subject_hash(&value[start..end]));
            out.push(']');
            processed = end;
        }
        search = (at + 1).max(processed);
    }
    out.push_str(&value[processed..]);
    out
}

fn email_shape_ok(local: &str, domain: &str) -> bool {
    if local.is_empty() || local.len() > crate::email::MAX_LOCAL_BYTES {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') {
        return false;
    }
    if domain.is_empty() || !domain.contains('.') {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }
    if domain.len() > crate::email::MAX_EMAIL_BYTES {
        return false;
    }
    domain
        .split('.')
        .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
        && domain
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
}

/// A `tracing` field visitor that records `(name, redacted value)` pairs
/// into a map. Runtimes use it in their formatters; tests use it to
/// prove the redaction rules.
#[derive(Debug, Default)]
pub struct RedactingVisitor {
    pub fields: BTreeMap<String, String>,
}

impl RedactingVisitor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&mut self, name: &str, value: &str) {
        self.fields
            .insert(name.to_owned(), redacted_value(name, value));
    }
}

impl Visit for RedactingVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field.name(), &format!("{value:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 12-hex truncation of `bytes`, same as `pseudonym_hex` does.
    fn hex_prefix(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(12);
        for byte in bytes.iter().take(6) {
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    #[test]
    fn secret_names_are_detected_case_insensitively() {
        for name in [
            "authorization",
            "Authorization",
            "api_token",
            "captchaToken",
            "HARNESS_SECRET",
            "CF_SAAS_API_TOKEN",
            "kid_key",
            "password",
        ] {
            assert!(is_secret_field(name), "{name}");
        }
        assert!(!is_secret_field("outcome"));
        // Deliberately over-broad: `idempotency_key` matches too, so the
        // mailer-outcome logs name the field `idempotency` (issue #14).
        assert!(is_secret_field("idempotency_key"));
        // And the field-name rule is what actually hides the value: a
        // custom-hostnames API token field never reaches a sink.
        assert_eq!(redacted_value("api_token", "cf-abcdef"), "[redacted]");
    }

    #[test]
    fn subject_hash_without_a_key_is_the_fixed_placeholder() {
        // This binary never installs the process-wide `LOG_PSEUDONYM_KEY`,
        // so the public entry point exercises the fail-closed arm: the
        // output shape survives, the input sensitivity does not.
        let hash = subject_hash("nick@example.com");
        assert_eq!(hash, UNKEYED_PSEUDONYM, "no key, no digest");
        assert_eq!(hash.len(), 12);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!hash.contains('@'));
        assert_eq!(
            hash,
            subject_hash("nick2@example.com"),
            "unkeyed output must not vary with the address"
        );
    }

    #[test]
    fn pseudonym_hex_without_a_key_is_constant_and_not_a_bare_digest() {
        // The fail-open regression (issue #135): with no key the old code
        // emitted the first 12 hex of a bare SHA-256 — deterministic and
        // dictionary-attackable. Every unkeyed pseudonym must be the fixed
        // placeholder instead, and never a digest prefix of its input.
        use sha2::Digest as _;
        for value in ["a@x.com", "b@x.com", "nick@example.com", ""] {
            assert_eq!(pseudonym_hex(None, value), UNKEYED_PSEUDONYM, "{value}");
            let digest: [u8; 32] = Sha256::digest(value.as_bytes()).into();
            assert_ne!(
                hex_prefix(&digest),
                pseudonym_hex(None, value),
                "the placeholder must not be a SHA-256 prefix of {value}"
            );
        }
        assert_eq!(
            pseudonym_hex(None, "a@x.com"),
            pseudonym_hex(None, "b@x.com"),
            "input-independent"
        );
    }

    #[test]
    fn pseudonym_hex_with_a_key_is_the_input_sensitive_hmac_form() {
        let key: &[u8] = b"harness-secret-long-enough-for-this-test-0123456789";
        let a = pseudonym_hex(Some(key), "a@x.com");
        assert_eq!(a.len(), 12, "keyed pseudonym keeps the shape: {a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, UNKEYED_PSEUDONYM, "keyed output is not the placeholder");
        assert_eq!(
            a,
            pseudonym_hex(Some(key), "a@x.com"),
            "stable under one key"
        );
        assert_ne!(
            a,
            pseudonym_hex(Some(key), "b@x.com"),
            "keyed pseudonym stays input-sensitive"
        );
        // Byte-for-byte the same scheme as before the fail-closed change:
        // HMAC-SHA256(key, PSEUDONYM_DOMAIN ‖ value), first 6 bytes as hex.
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(PSEUDONYM_DOMAIN);
        mac.update(b"a@x.com");
        assert_eq!(a, hex_prefix(&mac.finalize().into_bytes()));
    }

    #[test]
    fn visitor_rules_match_redacted_value() {
        for (name, value) in [
            ("authorization", "Bearer super-secret-token"),
            ("token", "captcha-value"),
            ("email", "nick@example.com"),
            ("subject", "nick@example.com"),
            ("outcome", "sent"),
        ] {
            let stored = redacted_value(name, value);
            if is_secret_field(name) {
                assert_eq!(stored, "[redacted]", "{name}");
            } else if is_email_field(name) && value.contains('@') {
                assert!(stored.starts_with("subject_hash:"), "{name}: {stored}");
                assert!(!stored.contains('@'));
            } else {
                assert_eq!(stored, value, "{name}");
            }
        }
    }

    #[test]
    fn non_email_values_in_email_fields_pass_through() {
        assert_eq!(
            redacted_value("email_domain", "factory0.ventures"),
            "factory0.ventures"
        );
    }

    /// The leak the field-name rules miss (issue #135): a Postgres unique
    /// violation quotes the offending row — an email — in a generic
    /// `error` field, and the raw driver text must never reach the logs.
    #[test]
    fn scrub_text_pseudonymises_emails_inside_generic_values() {
        let driver = "duplicate key value violates unique constraint \
             \"subscribers_email_normalized_key\"\n\
             DETAIL:  Key (email_normalized)=(nick@example.com) already exists.";
        let scrubbed = scrub_text(driver);
        assert!(!scrubbed.contains('@'), "{scrubbed}");
        assert!(!scrubbed.contains("nick"), "{scrubbed}");
        assert!(scrubbed.contains("[subject_hash:"), "{scrubbed}");
        assert!(
            scrubbed.contains(&subject_hash("nick@example.com")),
            "the pseudonym is the same one the email fields use: {scrubbed}"
        );
        assert!(
            scrubbed.contains("duplicate key value violates unique constraint"),
            "the diagnostic itself survives: {scrubbed}"
        );

        assert_eq!(
            redacted_value("message", "mailer rejected bob@example.com"),
            format!(
                "mailer rejected [subject_hash:{}]",
                subject_hash("bob@example.com")
            )
        );
    }

    #[test]
    fn scrub_text_drops_query_strings_from_urls_and_paths() {
        let message = "GET https://api.factory0.ventures/v1/email-signup/confirm?token=abc \
             redirected to /v1/waitlist/status?token=def";
        let scrubbed = scrub_text(message);
        assert!(!scrubbed.contains("token=abc"), "{scrubbed}");
        assert!(!scrubbed.contains("token=def"), "{scrubbed}");
        assert!(
            scrubbed.contains("https://api.factory0.ventures/v1/email-signup/confirm?[redacted]"),
            "{scrubbed}"
        );
        assert!(
            scrubbed.contains("redirected to /v1/waitlist/status?[redacted]"),
            "{scrubbed}"
        );

        let uri = scrub_text("/ui/waitlist/status?token=01J.secret");
        assert_eq!(uri, "/ui/waitlist/status?[redacted]");

        assert_eq!(
            scrub_text("/v1/email-signup/confirm"),
            "/v1/email-signup/confirm",
            "a path without a query is untouched"
        );
    }

    #[test]
    fn scrub_text_redacts_url_credentials() {
        let connect = "error connecting to postgres://venture:sup3r-s3cret@db.internal:5432/app";
        let scrubbed = scrub_text(connect);
        assert!(!scrubbed.contains("sup3r-s3cret"), "{scrubbed}");
        assert!(!scrubbed.contains("venture:"), "{scrubbed}");
        assert!(
            scrubbed.contains("postgres://[redacted]@db.internal:5432/app"),
            "{scrubbed}"
        );
    }

    #[test]
    fn scrub_text_redacts_signed_tokens_wherever_they_appear() {
        use crate::ports::signer::{Kid, Payload, Signer};
        use crate::signer::HmacSigner;

        let signer = HmacSigner::new("0".repeat(crate::signer::MIN_SECRET_BYTES), None)
            .expect("test secret is long enough");
        let token = signer.sign(&Payload {
            purpose: "email-signup.confirm".to_owned(),
            subject: "01J0000000000000000000000A".to_owned(),
            exp: None,
            kid: Kid::Cur,
        });
        assert!(token.starts_with("eyJ"), "test premise: {token}");

        let scrubbed = scrub_text(&format!("confirm token {token} was rejected"));
        assert!(!scrubbed.contains(&token), "{scrubbed}");
        assert!(!scrubbed.contains("eyJ"), "{scrubbed}");
        assert!(scrubbed.contains(REDACTED), "{scrubbed}");
        assert!(
            scrubbed.contains("confirm token") && scrubbed.contains("was rejected"),
            "surrounding words survive: {scrubbed}"
        );

        // Inside a URL the query rule already dropped it; no `eyJ` survives
        // either way.
        let in_url = scrub_text(&format!("https://x.example/confirm?token={token}"));
        assert!(!in_url.contains("eyJ"), "{in_url}");

        // A JWT-shaped three-segment token is caught too.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIwMUoifQ.c2lnbmF0dXJlLXJ1bg";
        assert!(!scrub_text(jwt).contains("eyJ"));

        // Short dotted runs that merely start with eyJ are left alone.
        assert_eq!(scrub_text("eyJhYi.短"), "eyJhYi.短");
    }

    #[test]
    fn scrub_text_redacts_bearer_credentials() {
        let scrubbed = scrub_text("request carried Authorization: Bearer 01Jsupersecretvalue");
        assert!(!scrubbed.contains("01Jsupersecretvalue"), "{scrubbed}");
        assert!(scrubbed.contains("Bearer [redacted]"), "{scrubbed}");
    }

    #[test]
    fn scrub_text_redacts_every_github_token_shape() {
        // One body long enough for the token floor, per prefix.
        let body = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // 36 chars
        for prefix in ["ghs_", "ghu_", "gho_", "ghp_", "ghr_", "github_pat_"] {
            let token = format!("{prefix}{body}");
            let scrubbed = scrub_text(&format!(
                "request failed: sent Authorization: token {token}"
            ));
            assert!(!scrubbed.contains(&token), "{prefix}: {scrubbed}");
            assert!(
                !scrubbed.contains(body),
                "{prefix}: token body survived: {scrubbed}"
            );
            assert!(scrubbed.contains(REDACTED), "{prefix}: {scrubbed}");
            assert!(
                scrubbed.contains("request failed") && scrubbed.contains("Authorization"),
                "{prefix}: surrounding words should survive: {scrubbed}"
            );
            // Idempotent.
            assert_eq!(scrub_text(&scrubbed), scrubbed, "{prefix}");
        }
        // The token can be the whole value, and one value may hold several.
        assert_eq!(scrub_text(&format!("ghp_{body}")), REDACTED);
        let two = scrub_text(&format!("ghp_{body} and ghs_{body}"));
        assert!(!two.contains(body), "{two}");

        // A token glued after an underscore is still a token: `_` ends a
        // word just as a space does, so the `_` before the prefix must not
        // shield it (issue #623 review).
        for (glued, leading) in [
            (format!("prefix_ghp_{body}"), "prefix_"),
            (format!("x_ghs_{body}"), "x_"),
            (format!("KEY_github_pat_{body}"), "KEY_"),
        ] {
            let scrubbed = scrub_text(&glued);
            assert!(!scrubbed.contains(body), "glued: {scrubbed}");
            assert!(scrubbed.contains(REDACTED), "glued: {scrubbed}");
            assert!(
                scrubbed.contains(leading),
                "leading word survives: {scrubbed}"
            );
            assert!(
                !scrubbed.contains("ghp_")
                    && !scrubbed.contains("ghs_")
                    && !scrubbed.contains("github_pat_"),
                "no prefix survives: {scrubbed}"
            );
        }
    }

    #[test]
    fn scrub_text_leaves_github_prefix_lookalikes_alone() {
        for value in [
            // The prefix's letters, but no `_` after them.
            "ghost_town",
            "ghs",
            "ghp",
            // `ghs_` inside a longer word is not the start of a token.
            "highs_levels_of_the_thing",
            // Prefixed, but far too short to be a token.
            "ghp_short",
            "ghs_1234",
            "github_pat_shortish",
        ] {
            assert_eq!(scrub_text(value), value, "over-redacted: {value}");
        }
    }

    #[test]
    fn scrub_text_redacts_pem_private_key_blocks() {
        let block = "-----BEGIN RSA PRIVATE KEY-----\n\
             MIIEpAIBAAKCAQEAtqo1ZXcvbnmlkjihgfedcba0987654321\n\
             c2FtcGxlLXNlY3JldC1rZXktbWF0ZXJpYWwtZ29lcy1oZXJl\n\
             -----END RSA PRIVATE KEY-----";
        let message = format!("failed to load signing key: {block} (from /etc/key.pem)");
        let scrubbed = scrub_text(&message);
        assert!(!scrubbed.contains("-----BEGIN"), "{scrubbed}");
        assert!(!scrubbed.contains("PRIVATE KEY"), "{scrubbed}");
        assert!(!scrubbed.contains("c2FtcGxlLXNlY3JldC"), "{scrubbed}");
        assert!(scrubbed.contains(REDACTED), "{scrubbed}");
        assert!(
            scrubbed.contains("failed to load signing key")
                && scrubbed.contains("(from /etc/key.pem)"),
            "surrounding words survive: {scrubbed}"
        );
        assert_eq!(scrub_text(&scrubbed), scrubbed, "idempotent");

        // A public key is not a private key and is left alone.
        let public = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----";
        assert_eq!(scrub_text(public), public);

        // A block with no readable footer is redacted whole, not half.
        let unterminated = "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWJvZHk=\nmore";
        let half = scrub_text(unterminated);
        assert!(!half.contains("c2VjcmV0LWJvZHk="), "{half}");
        assert!(half.contains(REDACTED), "{half}");
    }

    #[test]
    fn scrub_text_handles_a_very_long_line_of_begin_markers() {
        // A single line holding many `-----BEGIN ` candidates, none a
        // `PRIVATE KEY` header: the pass must leave it untouched. The bound
        // on the header lookahead is what keeps this from rescanning the
        // tail once per candidate (issue #623 review).
        let value = "-----BEGIN ".repeat(10_000);
        assert_eq!(scrub_text(&value), value);
    }

    #[test]
    fn scrub_text_leaves_ordinary_log_values_alone() {
        for value in [
            "sent",
            "not_configured",
            "01J8Z4QWERTYUIOPASDFGH",
            "/v1/email-signup/confirm",
            "factory0.ventures",
            "cratefield-core@0.1.0",
            "database did not answer within 2 s",
            "[redacted]",
        ] {
            assert_eq!(scrub_text(value), value, "{value}");
        }
    }

    #[test]
    fn scrub_text_is_idempotent() {
        let nasty = "failed for nick@example.com with Bearer abcdefgh12345 at \
             https://x.example/v1/confirm?token=eyJ and postgres://u:p@h/db; \
             X-Amz-Credential=AKID%2F20260101%2Fauto%2Fs3%2Faws4_request \
             Authorization: AWS4-HMAC-SHA256 Credential=AKID/20260101/auto/s3/aws4_request, \
             Signature=abcdef";
        let once = scrub_text(nasty);
        assert_eq!(scrub_text(&once), once, "{once}");
    }

    /// The disclosure [`scrub_request_url`] exists for, and the one
    /// [`scrub_text`] provably cannot stop on its own: APNs addresses a
    /// device by *path*, and a path is not a shape any general rule can
    /// call a secret.
    #[test]
    fn scrub_request_url_removes_a_credential_path_scrub_text_cannot_see() {
        const TOKEN: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
        let url = &format!("https://api.push.apple.com/3/device/{TOKEN}");

        assert!(
            scrub_text(url).contains(TOKEN),
            "if scrub_text ever learns to do this, this pass can go"
        );

        // Both shapes a layer below is free to quote: the whole URL, and
        // the bare request target on its own.
        let message = format!("Fetch API cannot load: {url}. sending POST /3/device/{TOKEN}");
        let safe = scrub_request_url(&message, url);
        assert!(!safe.contains(TOKEN), "{safe}");
        assert!(!safe.contains("/3/device"), "{safe}");
        assert!(safe.contains("https://api.push.apple.com"), "{safe}");
        // Still an error somebody can act on.
        assert!(safe.contains("Fetch API cannot load"), "{safe}");
        assert!(safe.contains(REDACTED), "{safe}");
    }

    #[test]
    fn scrub_request_url_keeps_the_port_and_never_the_userinfo() {
        let url = "http://user:pw@127.0.0.1:8787/3/device/tok";
        let safe = scrub_request_url(&format!("connect failed: {url}"), url);
        assert_eq!(safe, "connect failed: http://127.0.0.1:8787");
    }

    #[test]
    fn scrub_request_url_ignores_anything_that_is_not_an_absolute_url() {
        // An empty needle would otherwise splice the marker between every
        // character of the message, and a bare path has no origin to keep.
        for url in ["", "/3/device/tok", "api.push.apple.com", "://no-scheme/x"] {
            let message = "the message is not the place to find out";
            assert_eq!(scrub_request_url(message, url), message, "{url:?}");
        }
    }

    #[test]
    fn scrub_request_url_leaves_a_root_target_alone() {
        // "/" is in half the prose there is; redacting it would make every
        // message worse and hide nothing.
        let safe = scrub_request_url("GET / failed at https://x.example/", "https://x.example/");
        assert_eq!(safe, "GET / failed at https://x.example");
    }

    /// A `SigV4` credential in any of the forms a value can carry it — a
    /// presigned URL's query, a bare query string, or the
    /// `Authorization: AWS4-HMAC-SHA256 …` header — loses its value
    /// (issue #622).
    #[test]
    fn scrub_text_redacts_sigv4_credentials() {
        // An absolute URL: the URL pass drops the whole query, and the same
        // URL as a generic field value (a `uri`) is scrubbed before storage.
        const URL: &str = "https://examplebucket.s3.amazonaws.com/test.txt\
             ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z\
             &X-Amz-Expires=86400\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
        assert_eq!(
            scrub_text(URL),
            "https://examplebucket.s3.amazonaws.com/test.txt?[redacted]"
        );
        assert_eq!(redacted_value("uri", URL), scrub_text(URL));

        // A bare query has no scheme for the URL pass to anchor on, so the
        // `SigV4` names themselves are what the rule catches.
        assert_eq!(
            scrub_text(
                "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=AKID%2F20260101%2Fauto%2Fs3%2Faws4_request\
                 &X-Amz-Date=20260101T000000Z\
                 &X-Amz-Signature=abcd0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
            ),
            "X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=[redacted]\
             &X-Amz-Date=20260101T000000Z\
             &X-Amz-Signature=[redacted]"
        );

        // The `Authorization` header form, with no query around it.
        assert_eq!(
            scrub_text(
                "Authorization: AWS4-HMAC-SHA256 \
                 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
                 SignedHeaders=host;x-amz-date, \
                 Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
            ),
            "Authorization: AWS4-HMAC-SHA256 \
             Credential=[redacted], \
             SignedHeaders=host;x-amz-date, \
             Signature=[redacted]"
        );

        // An STS session token (`X-Amz-Security-Token=`) is a credential too:
        // it accompanies temporary credentials, so it is redacted as well, and
        // re-scrubbing the result is a no-op.
        assert_eq!(
            scrub_text(
                "X-Amz-Security-Token=IQoJb3JpZ2luX2VjECTEMP\
                 &X-Amz-Signature=abcd0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
            ),
            "X-Amz-Security-Token=[redacted]&X-Amz-Signature=[redacted]"
        );
        assert_eq!(
            scrub_text("X-Amz-Security-Token=[redacted]&X-Amz-Signature=[redacted]"),
            "X-Amz-Security-Token=[redacted]&X-Amz-Signature=[redacted]"
        );
    }
}

// ---------------------------------------------------------------------------
// Control-event forwarder (issue #107; widened to every boot-time control
// event by issue #441)

/// A process-wide sink for internal-error diagnostics, installed by the
/// runtime. See [`set_error_forwarder`].
type ErrorForwarder = fn(&str);

static ERROR_FORWARDER: OnceLock<ErrorForwarder> = OnceLock::new();

/// How severe a forwarded control event is (issue #441).
///
/// On `wasm32` no tracing dispatcher can be installed (it hangs the
/// workerd isolate), so the accountability `tracing` carries — the
/// `HARNESS_ALLOW_UNPROTECTED_WRITES` acceptance, the production-readiness
/// refusal, a gateway secret that would not load, the secret-access audit —
/// went nowhere, exactly as the 500-mapped internal errors of issue #107
/// did. Those events ride the same forwarder as the errors now, but they
/// are not all failures: the level travels with the line so Workers Logs
/// shows an acceptance as a warning and an audit record as information,
/// rather than everything as an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlLevel {
    Info,
    Warn,
    Error,
}

impl ControlLevel {
    /// The lowercase tag prefixed onto a forwarded line (`"[warn] …"`),
    /// matching the level string the native subscriber writes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ControlLevel::Info => "info",
            ControlLevel::Warn => "warn",
            ControlLevel::Error => "error",
        }
    }
}

/// Installs a process-wide forwarder for internal-error diagnostics
/// (architecture section 11).
///
/// On `wasm32` a tracing dispatcher cannot be installed — it hangs the
/// workerd/miniflare isolate — so every `tracing::error!` core emits when it
/// maps an internal failure to a 500 is dropped, and a Workers 500 becomes a
/// black box (issue #107). The Cloudflare runtime therefore points this
/// forwarder at `worker::console_error!`, and core calls it alongside its
/// `tracing::error!` so the same one-line diagnostic reaches Workers Logs.
/// Since issue #441 the same sink also carries boot-time **control events**
/// at their own level — see [`forward_control_event`].
///
/// Native runs leave it unset and rely on the tracing subscriber. This is
/// boot-time infrastructure installed before the first response, not request
/// state (ADR 0007); the first installation wins and later calls are ignored.
pub fn set_error_forwarder(forwarder: ErrorForwarder) {
    let _ = ERROR_FORWARDER.set(forwarder);
}

/// Forwards a one-line boot-time control event to the installed sink at its
/// own level (issue #441); a no-op when none is installed (native, tests).
///
/// The same escape hatch the crate-internal `forward_internal_error`
/// opens, extended past the internal errors mapped to a 500 (issue #107)
/// to the boot-time control events a wasm target's absent tracing
/// dispatcher would otherwise swallow (issue #441). Call sites forward
/// *in addition to* — never instead of — their `tracing::*` event, so
/// native keeps the structured fields and Workers keeps the fact.
/// The payload passes [`scrub_text`] (issue #135) and is prefixed second:
/// the level tag is ours, and must not be scrubbed with what it carries.
pub fn forward_control_event(level: ControlLevel, line: &str) {
    if let Some(forwarder) = ERROR_FORWARDER.get() {
        forwarder(&format!("[{}] {}", level.as_str(), scrub_text(line)));
    }
}

/// Forwards a one-line internal-error diagnostic to the installed sink, if
/// any; a no-op when none is installed (native, tests). The line is a
/// pre-formatted string, so the structured-field rules ([`redacted_value`])
/// never see it; it passes [`scrub_text`] (issue #135), which is idempotent
/// for callers that already scrubbed what they formatted in. This is a
/// [`ControlLevel::Error`] event, and delegates to
/// [`forward_control_event`] (issue #441).
pub(crate) fn forward_internal_error(line: &str) {
    forward_control_event(ControlLevel::Error, line);
}

#[cfg(test)]
#[allow(clippy::disallowed_types)] // test-only capture of the forwarded line
mod forwarder_tests {
    use super::*;
    use std::sync::Mutex;

    static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static INSTALL: std::sync::Once = std::sync::Once::new();

    fn capture(line: &str) {
        CAPTURED.lock().unwrap().push(line.to_owned());
    }

    /// Installs the capture sink once per test binary.
    ///
    /// **Process-global on purpose.** The first version of this captured
    /// `tracing` through `with_default`, which is *thread-local*: it held
    /// locally and failed on CI, because a report emitted on any thread but
    /// the one running the closure is simply not seen. The sink
    /// `set_error_forwarder` installs is global and `Mutex`-guarded, so it
    /// cannot miss a line for scheduling reasons.
    ///
    /// Being global means every test writes into one buffer, so an assertion
    /// has to name something only its own test produces — hence the unique
    /// needle per test below, rather than counting a shared phrase.
    fn install_sink() {
        INSTALL.call_once(|| set_error_forwarder(capture));
    }

    #[test]
    fn an_installed_forwarder_receives_the_line() {
        install_sink();
        forward_internal_error("database error mapped to internal problem: forwarder-107-boom");
        assert!(
            CAPTURED
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.contains("forwarder-107-boom")),
            "the installed forwarder should have received the diagnostic"
        );

        // The forwarded line is a pre-formatted string the structured-field
        // rules never see, so the forwarder itself scrubs it (issue #135):
        // a driver DETAIL quoting a row, or a redirect target with a token,
        // must not reach Workers Logs verbatim.
        forward_internal_error(
            "database error: DETAIL: Key (email)=(nick@example.com) already exists",
        );
        forward_internal_error("redirect to /v1/waitlist/status?token=eyJhYmNkZWZnaA.mac failed");
        let captured = CAPTURED.lock().unwrap();
        let joined = captured.join("\n");
        assert!(!joined.contains('@'), "email reached the sink: {joined}");
        assert!(
            !joined.contains("token=eyJ"),
            "token reached the sink: {joined}"
        );
        assert!(
            joined.contains("[subject_hash:"),
            "the pseudonym should survive for correlation: {joined}"
        );
    }

    #[test]
    fn control_events_reach_the_sink_prefixed_with_their_level() {
        install_sink();
        // One line per level, each with a needle no other test produces: the
        // sink is shared, so an assertion must find *its own* line.
        forward_control_event(
            ControlLevel::Info,
            "secret access forwarder-441-info store global read allowed",
        );
        forward_control_event(
            ControlLevel::Warn,
            "forwarder-441-warn serving guarded routes unprotected on an acceptance",
        );
        forward_control_event(
            ControlLevel::Error,
            "forwarder-441-error refusing guarded routes",
        );
        let captured = CAPTURED.lock().unwrap();
        for (level, needle) in [
            ("info", "forwarder-441-info"),
            ("warn", "forwarder-441-warn"),
            ("error", "forwarder-441-error"),
        ] {
            let line = captured
                .iter()
                .find(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("no forwarded line carried {needle}"));
            let prefix = format!("[{level}] ");
            assert!(
                line.starts_with(&prefix),
                "the {needle} line should be prefixed {prefix:?}: {line}"
            );
        }
    }

    #[test]
    fn the_internal_error_still_scrubs_and_now_carries_the_error_prefix() {
        install_sink();
        forward_internal_error(
            "forwarder-441-scrub database error: DETAIL: Key (email)=(nick@example.com) \
             already exists",
        );
        let captured = CAPTURED.lock().unwrap();
        // The plain-text needle survives the scrub; the email must not.
        let line = captured
            .iter()
            .find(|line| line.contains("forwarder-441-scrub"))
            .expect("the internal error should reach the sink");
        assert!(line.starts_with("[error] "), "{line}");
        assert!(!line.contains('@'), "email reached the sink: {line}");
        assert!(
            line.contains("[subject_hash:"),
            "the pseudonym should survive for correlation: {line}"
        );
    }

    #[test]
    fn forwarding_without_a_sink_is_a_noop() {
        // No panic when nothing is installed. Other tests in this binary may
        // already have installed the shared sink, so nothing is asserted
        // about output; this asserts only that the call is safe regardless
        // of ordering.
        forward_control_event(
            ControlLevel::Warn,
            "ignored when no sink or captured when set",
        );
        forward_internal_error("ignored when no sink or captured when set");
    }
}
