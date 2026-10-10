//! `HttpClient` over `worker::Fetch`.
//!
//! # A failure message here never carries the request URL
//!
//! This is the production path for every venture on this harness, and the
//! runtime whose errors reach Workers Logs through `console_error!`. A
//! `worker::Error` is not safe to stringify: `Error::JsError(s)` and
//! `Error::UnknownJsError { .. }` carry workerd's own message, and workerd
//! names the destination it could not reach — "Fetch API cannot load:
//! `<the whole URL>`".
//!
//! For some callers that URL *is* the credential. An APNs request path is
//! the device token (`/3/device/<token>`) and a Web Push endpoint is a
//! bearer capability — whoever holds it can push to that browser
//! indefinitely, which is why [`cratefield_core::Recipient`] prints
//! fingerprints and says the value must appear "never in a log, an event
//! payload, or an error body". A transport failure would otherwise write
//! that credential into Workers Logs while the caller two lines away is
//! carefully printing a fingerprint (issue #229; the native port was the
//! same leak, issue #228).
//!
//! So no error is ever stringified whole here. Every failure goes through
//! [`transport`], which keeps the destination's origin, drops its path, and
//! then hands the result to [`cratefield_core::scrub_text`] for every other
//! shape of secret a layer below might have quoted.

use std::fmt::Write as _;

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::{HttpClient, HttpError, HttpPolicy, scrub_request_url, scrub_text};
use worker::send::IntoSendFuture;
use worker::{Fetch, Headers, Method, Request as WorkerRequest, RequestInit};

/// The Workers implementation of the [`HttpClient`] port: one `fetch` per
/// send, through the isolate's own stack.
pub struct FetchClient;

#[async_trait]
impl HttpClient for FetchClient {
    async fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let policy = HttpPolicy::of_request(&request);
        let (parts, body) = request.into_parts();
        // Kept for the whole exchange: it is what every failure below is
        // scrubbed against, and the only thing here that knows which parts
        // of a message are this request's URL.
        let url = parts.uri.to_string();
        let mut init = RequestInit::new();
        init.method = Method::from(parts.method.as_str().to_string());
        let headers = Headers::new();
        for (name, value) in &parts.headers {
            let _ = headers.set(name.as_str(), value.to_str().unwrap_or_default());
        }
        init.headers = headers;

        // A body is attached only when there is one. The Fetch spec refuses
        // to construct a Request whose method is GET or HEAD and whose body
        // is non-null, and an empty JS string is not null: setting it
        // unconditionally makes every GET through this port throw a
        // TypeError before it leaves the isolate.
        //
        // Nothing caught it because every adapter shipped so far POSTs
        // (Resend, Turnstile). The first GET consumer is OpenID Connect
        // discovery in the `auth-oidc` crate, which fetches a configuration
        // document and a JWKS.
        if !body.is_empty() {
            // The port's adapters send JSON bodies; non-UTF-8 is a hard
            // error rather than a lossy corruption.
            let body_text =
                String::from_utf8(body.to_vec()).map_err(|err| transport(&err, &url))?;
            init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body_text)));
        }
        let worker_request =
            WorkerRequest::new_with_init(&url, &init).map_err(|err| transport(&err, &url))?;

        let mut response = Fetch::Request(worker_request)
            .send()
            .into_send()
            .await
            .map_err(|err| transport(&err, &url))?;

        // `bytes()` buffers the whole body, so refuse a declared body the
        // cap has already out before allocating it (issue #136).
        let declared = response
            .headers()
            .get("content-length")
            .ok()
            .flatten()
            .and_then(|length| length.trim().parse::<usize>().ok());
        if declared.is_some_and(|declared| declared > policy.max_response_bytes) {
            return Err(HttpError::ResponseTooLarge {
                limit: policy.max_response_bytes,
            });
        }

        let mut builder = http::Response::builder().status(response.status_code());
        let response_headers = response.headers();
        if let Some(headers) = builder.headers_mut() {
            for (name, value) in response_headers {
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::try_from(name.as_str()),
                    http::HeaderValue::try_from(value.as_str()),
                ) {
                    headers.insert(name, value);
                }
            }
        }
        let bytes = response
            .bytes()
            .into_send()
            .await
            .map_err(|err| transport(&err, &url))?;
        builder
            .body(Bytes::from(bytes))
            .map_err(|err| transport(&err, &url))
    }
}

/// The only place in this module that builds an [`HttpError::Transport`],
/// so a sixth failure site cannot be added that reports a raw error string
/// — which is exactly how the first five came to (issue #229).
fn transport(err: &dyn std::error::Error, url: &str) -> HttpError {
    HttpError::Transport(safe_message(err, url))
}

/// An error as a message this crate may hand on — to [`HttpError`], and
/// from there to `console_error!`, a dead-letter row and an operator's
/// terminal.
///
/// Three things happen here, and the last two are why this is not
/// `err.to_string()`:
///
/// 1. **The causes go in.** `worker::Error`'s `Display` is deliberately
///    thin for every variant that wraps another error — `Error::Io` prints
///    "I/O error", `Error::Http` prints "HTTP error" — because the crate
///    expects consumers to walk `source()`, which it implements for the
///    wrapped Rust errors *and* for a JS error's `cause` chain. Asking
///    `Display` alone therefore throws away the half that says what went
///    wrong. This is the same thing the native port learned about
///    `reqwest::Error` (issue #228), and it means redaction makes these
///    messages more diagnosable, not less.
/// 2. **The URL comes out.** With the chain in, a workerd fetch failure
///    reads "Fetch API cannot load: `<the whole URL>`", path and query
///    included — see the module note for why that is a disclosure and not
///    a detail. [`cratefield_core::scrub_request_url`] cuts it back to the
///    origin, and redacts the bare request target a cause is free to quote
///    on its own.
/// 3. **Everything else is scrubbed too.** A cause may quote a `Bearer`
///    credential, a signed token or an address that has nothing to do with
///    this request's URL, so the result goes through
///    [`cratefield_core::scrub_text`] — the same pass every log field takes
///    (issue #135).
fn safe_message(err: &dyn std::error::Error, url: &str) -> String {
    let mut message = err.to_string();
    let mut cause = err.source();
    while let Some(current) = cause {
        let _ = write!(message, ": {current}");
        cause = current.source();
    }
    scrub_text(&scrub_request_url(&message, url))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The APNs shape, because it is the worst case: the device token is
    /// the request *path*, so a message that quotes the URL publishes the
    /// credential.
    const TOKEN: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff";

    fn apns_url() -> String {
        format!("https://api.push.apple.com/3/device/{TOKEN}")
    }

    fn assert_safe(message: &str) {
        assert!(
            !message.contains(TOKEN),
            "the device token leaked: {message}"
        );
        assert!(
            !message.contains("/3/device"),
            "the request path leaked: {message}"
        );
    }

    /// What workerd actually throws when a fetch cannot be completed: a
    /// `TypeError` whose message names the destination in full. Arriving
    /// as `Error::JsError` (a thrown string) or inside `UnknownJsError`'s
    /// message, it is the same disclosure either way.
    #[test]
    fn a_workerd_fetch_failure_names_the_origin_and_never_the_request_path() {
        let url = apns_url();
        let err = worker::Error::JsError(format!("TypeError: Fetch API cannot load: {url}."));

        let message = safe_message(&err, &url);

        assert_safe(&message);
        // And it is still an error somebody can act on: which host, and
        // what the runtime actually said.
        assert!(
            message.contains("https://api.push.apple.com"),
            "the destination is named: {message}"
        );
        assert!(
            message.contains("Fetch API cannot load"),
            "the cause survives the redaction: {message}"
        );
    }

    /// The property the native port found and this one had to be checked
    /// for separately: `Display` is nearly empty for the variants that
    /// wrap another error, and the detail lives in `source()`. Walking the
    /// chain is what makes the redacted message *better* than the leaky
    /// one — and a cause quotes whatever it was handed, so it is scrubbed
    /// too.
    #[test]
    fn the_cause_chain_is_walked_and_scrubbed() {
        let url = apns_url();
        let inner =
            std::io::Error::other(format!("connection refused sending to /3/device/{TOKEN}"));
        let err = worker::Error::Io(inner);

        assert_eq!(
            err.to_string(),
            "I/O error",
            "if `Display` ever carries the cause, this pass can stop appending it"
        );

        let message = safe_message(&err, &url);

        assert_safe(&message);
        assert!(
            message.contains("connection refused"),
            "the cause is what makes this diagnosable: {message}"
        );
    }

    /// `scrub_text`'s own rules still apply on top: a cause is free to
    /// quote a credential that has nothing to do with this request's URL.
    #[test]
    fn a_secret_a_cause_quotes_is_scrubbed_even_when_it_is_not_the_url() {
        let url = apns_url();
        let err = worker::Error::JsError(
            "rejected the Authorization: Bearer abcdefghijklmnop12345 we sent".to_owned(),
        );

        let message = safe_message(&err, &url);

        assert!(
            !message.contains("abcdefghijklmnop12345"),
            "scrub_text is the second net: {message}"
        );
    }

    /// Every failure site in `send` hands a different error type to
    /// [`transport`], and each one is a `Transport` variant whose message
    /// has been through the redaction — including the two that are not
    /// `worker::Error` at all.
    #[test]
    fn every_error_type_a_failure_site_produces_is_redacted() {
        let url = apns_url();
        let quoting = |what: &str| format!("{what} at {url}");

        // 1. A non-UTF-8 request body (`String::from_utf8`).
        let utf8 = String::from_utf8(vec![0xff, 0xfe]).expect_err("not UTF-8");
        // 2-4. Request construction, `Fetch::send`, and reading the body,
        //      all of which fail as `worker::Error` — as a thrown JS
        //      string, and as a wrapped Rust error with a cause.
        let js = worker::Error::JsError(quoting("TypeError: Fetch API cannot load:"));
        let rust = worker::Error::RustError(quoting("could not construct a request"));
        let io = worker::Error::Io(std::io::Error::other(quoting("network connection lost")));
        // 5. Building the `http::Response` back (`http::Error`).
        let http_err = http::Response::builder()
            .status(200)
            .header("x-\u{0}bad", "v")
            .body(())
            .expect_err("an invalid header name is a builder error");

        let sites: [&dyn std::error::Error; 5] = [&utf8, &js, &rust, &io, &http_err];
        for err in sites {
            let HttpError::Transport(message) = transport(err, &url) else {
                panic!("every site reports a transport failure");
            };
            assert_safe(&message);
        }
    }

    /// The five sites were five copies of `err.to_string()`, which is how
    /// one leak became five. Only one of them may build the error now, so
    /// a sixth site added later cannot quietly reintroduce the pattern:
    /// the module has exactly one `HttpError::Transport(` in it, in
    /// [`transport`].
    #[test]
    fn only_one_place_in_this_module_builds_a_transport_error() {
        let source = include_str!("http.rs");
        let module = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);

        assert_eq!(
            module.matches("HttpError::Transport(").count(),
            1,
            "a failure site must call `transport`, not build the error itself"
        );
    }
}
