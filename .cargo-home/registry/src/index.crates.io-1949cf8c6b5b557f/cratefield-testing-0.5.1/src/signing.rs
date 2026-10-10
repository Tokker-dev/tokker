//! Signing a webhook delivery the way a provider does (issue #666):
//! [`sign_stripe_style`] and [`sign_provider_scheme`] mint the headers a
//! [`WebhookVerifier`](cratefield_core::WebhookVerifier) accepts, so a
//! test drives a signed-webhook route end to end without a real provider
//! and without re-deriving the scheme by hand.
//!
//! The HMAC is computed here — with the `hmac` crates directly, never
//! through core's `expected_signature` — so a test that signs and verifies
//! crosses two independent implementations rather than checking one
//! against itself. A scheme whose key derivation or payload layout drifts
//! stops verifying, which is the point.
//!
//! Neither function logs or `Debug`-prints the secret: it is taken as a
//! `&str` and never stored.
//!
//! ```
//! use cratefield_core::{StripeStyle, WebhookVerifier};
//! use cratefield_testing::sign_stripe_style;
//!
//! let body = b"{}";
//! let headers = sign_stripe_style("Stripe-Signature", "whsec_dummy", 1_800_000_000, body);
//! assert!(WebhookVerifier::new(StripeStyle::default())
//!     .verify("whsec_dummy", &headers, body, 1_800_000_000));
//! ```

// These helpers `expect` on a header name or value a test literal always
// has; per-function `# Panics` sections would only add noise.
#![allow(clippy::missing_panics_doc)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use http::{HeaderMap, HeaderName, HeaderValue};
use sha2::Sha256;

use cratefield_core::{ProviderScheme, SignatureEncoding};

type HmacSha256 = Hmac<Sha256>;

/// A lowercase hex string, two digits per byte — the encoding
/// [`StripeStyle`](cratefield_core::StripeStyle) and a hex
/// [`SignatureEncoding`] carry on the wire.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `HMAC-SHA256(key, payload)` as bytes. HMAC accepts a key of any length,
/// so the constructor cannot fail.
fn hmac_sha256(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

/// A one-header [`HeaderMap`]; the map a signer returns, before a scheme
/// that names a timestamp header adds its own.
fn header_map(name: &str, value: &str) -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert(
        HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
        HeaderValue::from_str(value).expect("valid header value"),
    );
    map
}

/// The delivery headers Stripe sends for `body` signed at `t`: one header
/// named `header`, holding `t=<t>,v1=<hex>`, the hex being
/// `HMAC-SHA256(secret, "{t}.{body}")`. The exact inverse of
/// [`StripeStyle`](cratefield_core::StripeStyle)'s extraction — feed the
/// result straight to `WebhookVerifier::verify` with `now_unix == t`.
///
/// The key is the trimmed secret's own bytes, which is the default
/// [`secret_key`](cratefield_core::SignatureScheme::secret_key) — so a
/// change to how core derives the key stops the pair matching.
#[must_use]
pub fn sign_stripe_style(header: &str, secret: &str, t: i64, body: &[u8]) -> HeaderMap {
    let digest = hmac_sha256(
        secret.trim().as_bytes(),
        &[t.to_string().as_bytes(), b".", body].concat(),
    );
    header_map(header, &format!("t={t},v1={}", hex_encode(&digest)))
}

/// The headers a configured [`ProviderScheme`] reads for `body` signed at
/// `t`: the signature header carrying one entry — the scheme's `prefix`
/// then the hex or base64 of `HMAC-SHA256(secret, payload)` — and, when
/// the scheme names a timestamp header, that header set to `t`. The
/// payload is `"{t}.{body}"` when the scheme carries a timestamp and the
/// raw `body` otherwise; a scheme with no timestamp header ignores `t`.
///
/// The exact inverse of [`ProviderScheme`]'s extraction. `ProviderScheme`
/// always signs SHA-256, so there is no digest to pass.
#[must_use]
pub fn sign_provider_scheme(
    scheme: &ProviderScheme,
    secret: &str,
    t: i64,
    body: &[u8],
) -> HeaderMap {
    let payload = if scheme.timestamp.is_some() {
        [t.to_string().as_bytes(), b".", body].concat()
    } else {
        body.to_vec()
    };
    let digest = hmac_sha256(secret.trim().as_bytes(), &payload);
    let encoded = match scheme.encoding {
        SignatureEncoding::Hex => hex_encode(&digest),
        SignatureEncoding::Base64 => STANDARD.encode(&digest),
    };
    let mut map = header_map(
        scheme.signature,
        &format!("{}{encoded}", scheme.prefix.unwrap_or("")),
    );
    if let Some(name) = scheme.timestamp {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
            HeaderValue::from_str(&t.to_string()).expect("valid header value"),
        );
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::{DEFAULT_TOLERANCE_SECS, StripeStyle, WebhookVerifier};

    const SECRET: &str = "whsec_endpoint-secret-dummy";
    const NOW: i64 = 1_800_000_000;

    #[test]
    fn a_stripe_style_signature_verifies() {
        let body = br#"{"type":"checkout.session.completed"}"#;
        let got = sign_stripe_style("Stripe-Signature", SECRET, NOW, body);
        assert!(WebhookVerifier::new(StripeStyle::default()).verify(SECRET, &got, body, NOW));
        // The header name is the caller's: the same signature satisfies a
        // verifier expecting it under another name.
        let renamed = sign_stripe_style("X-Signature", SECRET, NOW, body);
        let layout = StripeStyle {
            header: "X-Signature",
        };
        assert!(WebhookVerifier::new(layout).verify(SECRET, &renamed, body, NOW));
    }

    #[test]
    fn a_stripe_style_signature_refuses_a_tampered_body_wrong_secret_or_stale_time() {
        let body = b"{}";
        let got = sign_stripe_style("Stripe-Signature", SECRET, NOW, body);
        let verifier = WebhookVerifier::new(StripeStyle::default());
        assert!(!verifier.verify(SECRET, &got, b"x", NOW));
        assert!(!verifier.verify("another-secret-dummy", &got, body, NOW));
        // The signature is still perfect; the timestamp is what refuses it.
        let stale = NOW - DEFAULT_TOLERANCE_SECS - 1;
        assert!(!verifier.verify(SECRET, &got, body, stale));
        assert!(!verifier.verify("", &got, body, NOW));
    }

    #[test]
    fn a_hex_prefixed_provider_signature_verifies() {
        let body = br#"{"event":"order.created"}"#;
        let scheme = ProviderScheme {
            signature: "X-Signature",
            encoding: SignatureEncoding::Hex,
            prefix: Some("sha256="),
            timestamp: Some("X-At"),
        };
        let got = sign_provider_scheme(&scheme, SECRET, NOW, body);
        // The prefix rides the signature header; the timestamp header
        // carries `t`; both are what the verifier reads.
        assert!(
            got["X-Signature"]
                .to_str()
                .expect("hex header is utf-8")
                .starts_with("sha256=")
        );
        assert_eq!(
            got["X-At"].to_str().expect("timestamp is utf-8"),
            NOW.to_string()
        );
        assert!(WebhookVerifier::new(scheme).verify(SECRET, &got, body, NOW));
        // A tampered body, another endpoint's secret, and a time outside
        // the tolerance all refuse.
        assert!(!WebhookVerifier::new(scheme).verify(SECRET, &got, b"x", NOW));
        assert!(!WebhookVerifier::new(scheme).verify("other-secret-dummy", &got, body, NOW));
        let stale = NOW - DEFAULT_TOLERANCE_SECS - 1;
        assert!(!WebhookVerifier::new(scheme).verify(SECRET, &got, body, stale));
    }

    #[test]
    fn a_base64_timestamp_free_provider_signature_verifies() {
        let body = br#"{"event":"order.created"}"#;
        let scheme = ProviderScheme {
            signature: "X-Signature",
            encoding: SignatureEncoding::Base64,
            prefix: None,
            timestamp: None,
        };
        let got = sign_provider_scheme(&scheme, SECRET, NOW, body);
        // No timestamp header is named, so `t` plays no part: the payload
        // is the raw body and any "now" is accepted.
        assert_eq!(got.len(), 1, "only the signature header is set");
        assert!(WebhookVerifier::new(scheme).verify(SECRET, &got, body, NOW));
        assert!(WebhookVerifier::new(scheme).verify(SECRET, &got, body, NOW + 10_000));
        assert!(!WebhookVerifier::new(scheme).verify(SECRET, &got, b"x", NOW));
        assert!(!WebhookVerifier::new(scheme).verify("other-secret-dummy", &got, body, NOW));
    }
}
