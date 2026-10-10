//! Generic webhook signature verification (issue #533, extended by #625).
//!
//! [`RoutePolicy::Signature`](crate::route_policy::RoutePolicy::Signature)
//! used to mean exactly one verifier: `Payments::verify_webhook`, so a
//! venture receiving **signed** webhooks from a provider that never takes a
//! payment had no policy it could declare honestly. This module is the other
//! half: one HMAC core ([`WebhookVerifier`]) with pluggable header schemes
//! ([`SignatureScheme`]) — Svix ([`Svix`], also what Resend signs with),
//! Stripe-style ([`StripeStyle`]), GitHub ([`Github`]), Vercel ([`Vercel`],
//! HMAC-SHA1) and a configured provider layout ([`ProviderScheme`]) — plus a
//! shared-**token** scheme ([`SharedTokenScheme`], and GitLab ([`Gitlab`]) in
//! particular) whose header carries the secret itself rather than a signature
//! of it.
//!
//! Verification always runs over the **raw body bytes** — the handler must
//! read the body before anything parses it — and every path fails closed.
//!
//! # SHA-1 and replay
//!
//! A scheme picks its HMAC digest through [`SignatureScheme::digest`]:
//! SHA-256 by default, or SHA-1, which Vercel signs with. SHA-1 is
//! acceptable here because the construction is an **HMAC**, a message
//! authentication code: its security rests on the secret key and the hash's
//! behaviour as a PRF, not on collision resistance, so SHA-1's collisions
//! are not exploitable against it. It is never used as a collision-sensitive
//! hash. A shared-token scheme runs no hash at all.
//!
//! Neither [`Vercel`] nor the token schemes ([`SharedTokenScheme`],
//! [`Gitlab`]) cover a timestamp — Vercel's header is a bare body MAC,
//! GitLab's is the secret verbatim — so none of them stops a replay by
//! itself. The handler must claim each delivery's event id through the
//! [`Inbox`](crate::idempotency::Inbox) dedup ledger.

use std::borrow::Cow;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use http::HeaderMap;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// How far a delivery's timestamp may be from now, in seconds, either way —
/// Svix's and Stripe's own tolerance, and the [`WebhookVerifier`] default.
/// The signature stays valid forever; the timestamp is what stops replays.
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;

/// What a [`SignatureScheme`] read out of one delivery: the bytes the
/// provider signed, the candidate signatures to compare, the timestamp the
/// replay tolerance runs on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDelivery {
    /// Exactly the bytes the scheme's MAC ran over — the raw body, or a
    /// `{timestamp}.{body}` / `{id}.{timestamp}.{body}` layout. Empty for a
    /// shared-token scheme, which signs nothing.
    pub signed_payload: Vec<u8>,
    /// Every candidate the delivery carried, decoded; empty refuses.
    pub candidates: Vec<Vec<u8>>,
    /// The Unix seconds the provider says it sent the delivery. `None`
    /// skips the replay tolerance — the scheme is then only as replay-safe
    /// as the provider makes it.
    pub timestamp: Option<i64>,
}

/// How a provider puts its signature material on the wire. Implement this
/// for a provider none of the built-in schemes speak; the verification core
/// is [`WebhookVerifier`]'s either way. Fail closed: `None` for a delivery
/// whose headers cannot be read in full, never a guess.
pub trait SignatureScheme: Send + Sync {
    /// Reads one delivery's signature material out of the request headers
    /// and the raw body bytes. `None` on any input the scheme cannot fully
    /// read; an empty candidate list counts as unreadable.
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery>;

    /// The key bytes the HMAC runs over: the trimmed secret's own bytes,
    /// unless the scheme's providers hand out encoded secrets (Svix's
    /// base64 `whsec_…`), which decode here. `None` refuses.
    fn secret_key<'a>(&self, secret: &'a str) -> Option<Cow<'a, [u8]>> {
        let trimmed = secret.trim();
        (!trimmed.is_empty()).then_some(Cow::Borrowed(trimmed.as_bytes()))
    }

    /// The digest the scheme's HMAC runs on. SHA-256 unless a provider
    /// signs with SHA-1 (Vercel today). Ignored by a shared-token scheme,
    /// which hashes nothing.
    fn digest(&self) -> Digest {
        Digest::Sha256
    }

    /// The signature bytes a matching delivery must carry, given the
    /// derived `key` and the bytes the scheme signed. The default is
    /// `HMAC(self.digest(), key, signed_payload)`; a **shared-token** scheme
    /// overrides this to return the key's own bytes, because for it the
    /// header *is* the secret and there is nothing to compute.
    ///
    /// The verifier compares the result against every candidate in constant
    /// time — the one comparison both paths share.
    fn expected_signature(&self, key: &[u8], signed_payload: &[u8]) -> Vec<u8> {
        hmac_bytes(self.digest(), key, signed_payload)
    }
}

/// The hash an HMAC scheme runs on. SHA-256 everywhere it is not otherwise
/// named; SHA-1 only where a provider signs with it ([`Vercel`]).
///
/// SHA-1 is safe in this position because HMAC is a **MAC**: its security
/// depends on the secret key and the hash's PRF behaviour, not on collision
/// resistance. It is not collision-sensitive use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Digest {
    /// HMAC-SHA256 — the default, and every scheme before Vercel.
    #[default]
    Sha256,
    /// HMAC-SHA1 — Vercel's `x-vercel-signature`.
    Sha1,
}

/// `HMAC(digest, key, payload)` as bytes. HMAC accepts a key of any length,
/// so the constructor cannot fail.
fn hmac_bytes(digest: Digest, key: &[u8], payload: &[u8]) -> Vec<u8> {
    match digest {
        Digest::Sha256 => {
            let mut mac =
                <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(payload);
            mac.finalize().into_bytes().to_vec()
        }
        Digest::Sha1 => {
            let mut mac =
                <HmacSha1 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(payload);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// The signature core every scheme shares: compute what a matching delivery
/// must carry — an HMAC (SHA-256 or SHA-1) over the scheme's signed payload,
/// or, for a token scheme, the secret itself — compare it against **every**
/// candidate in constant time with no early exit, and hold the delivery to
/// its timestamp.
#[derive(Clone)]
pub struct WebhookVerifier {
    scheme: Arc<dyn SignatureScheme>,
    tolerance_secs: i64,
}

impl WebhookVerifier {
    /// A verifier with the default tolerance ([`DEFAULT_TOLERANCE_SECS`]).
    ///
    /// ```
    /// use cratefield_core::{Svix, WebhookVerifier};
    /// use http::HeaderMap;
    ///
    /// let verifier = WebhookVerifier::new(Svix);
    /// // `raw` is the body exactly as it arrived, before any parsing; the
    /// // empty secret here means the delivery is refused, never guessed at.
    /// assert!(!verifier.verify("", &HeaderMap::new(), b"{}", 0));
    /// ```
    #[must_use]
    pub fn new(scheme: impl SignatureScheme + 'static) -> Self {
        Self {
            scheme: Arc::new(scheme),
            tolerance_secs: DEFAULT_TOLERANCE_SECS,
        }
    }

    /// Overrides the replay tolerance, in seconds, in both directions.
    #[must_use]
    pub const fn tolerance_secs(mut self, secs: i64) -> Self {
        self.tolerance_secs = secs;
        self
    }

    /// Whether `body` really was signed for this delivery with `secret`.
    /// Fails closed on every unreadable input; a timestamp in the future
    /// counts against the tolerance exactly as a stale one does.
    ///
    /// # Panics
    ///
    /// Only if the HMAC refused the derived key — which it cannot: HMAC
    /// accepts keys of any length.
    #[must_use]
    pub fn verify(&self, secret: &str, headers: &HeaderMap, body: &[u8], now_unix: i64) -> bool {
        if secret.trim().is_empty() {
            return false; // an empty secret is not a key
        }
        let Some(delivery) = self.scheme.extract(headers, body) else {
            return false;
        };
        if let Some(sent) = delivery.timestamp
            && now_unix
                .saturating_sub(sent)
                .checked_abs()
                .is_none_or(|delta| delta > self.tolerance_secs)
        {
            return false; // a clock this far out is out of tolerance
        }
        let Some(key) = self.scheme.secret_key(secret) else {
            return false;
        };
        // The scheme says what a matching delivery must carry: an HMAC over
        // the signed payload, or — for a shared-token scheme — the secret
        // itself. Either way the comparison below is the only one, and it is
        // constant time.
        let expected = self
            .scheme
            .expected_signature(&key, &delivery.signed_payload);
        // No early exit: every candidate is compared and the results OR-ed,
        // so timing says nothing about how much of a wrong signature was
        // right — nor which candidate (if any) matched.
        let mut matched = false;
        for candidate in &delivery.candidates {
            matched |= bool::from(candidate.as_slice().ct_eq(expected.as_slice()));
        }
        matched
    }
}

impl std::fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookVerifier")
            .field("tolerance_secs", &self.tolerance_secs)
            .finish_non_exhaustive()
    }
}

/// Svix's scheme — the one Resend, Clerk and a growing list of providers
/// sign with. Headers `svix-id` / `svix-timestamp` / `svix-signature` (the
/// `webhook-*` aliases are accepted too); payload `{id}.{timestamp}.{body}`;
/// signature header a space-separated list of `<version>,<base64>` pairs of
/// which only `v1` is read — how an endpoint survives a secret rotation.
#[derive(Debug, Clone, Copy, Default)]
pub struct Svix;

/// The Svix signing headers: canonical names and `webhook-*` aliases.
const SVIX_HEADERS: [(&str, &str, &str); 2] = [
    ("svix-id", "svix-timestamp", "svix-signature"),
    ("webhook-id", "webhook-timestamp", "webhook-signature"),
];

impl SignatureScheme for Svix {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery> {
        let (id, timestamp, signatures) = SVIX_HEADERS.iter().find_map(|(id, at, sig)| {
            Some((
                header(headers, id)?,
                header(headers, at)?,
                header(headers, sig)?,
            ))
        })?;
        let sent = timestamp.trim().parse::<i64>().ok()?;
        let mut candidates = Vec::new();
        for entry in signatures.split_whitespace() {
            let Some((version, value)) = entry.split_once(',') else {
                continue;
            };
            // Only `v1` is understood; unknown versions are ignored, the way
            // an endpoint survives a provider adding one.
            if version == "v1"
                && let Ok(bytes) = STANDARD.decode(value)
            {
                candidates.push(bytes);
            }
        }
        if candidates.is_empty() {
            return None;
        }
        Some(SignedDelivery {
            signed_payload: [id.as_bytes(), b".", timestamp.as_bytes(), b".", body].concat(),
            candidates,
            timestamp: Some(sent),
        })
    }

    fn secret_key<'a>(&self, secret: &'a str) -> Option<Cow<'a, [u8]>> {
        svix_secret_key(secret).map(Cow::Owned)
    }
}

/// An Svix endpoint secret's key bytes: base64, with or without the
/// `whsec_` prefix Svix writes it with. `None` when it does not decode.
#[must_use]
pub fn svix_secret_key(secret: &str) -> Option<Vec<u8>> {
    let trimmed = secret.trim();
    let encoded = trimmed.strip_prefix("whsec_").unwrap_or(trimmed);
    STANDARD.decode(encoded).ok().filter(|key| !key.is_empty())
}

/// Stripe's scheme, the shape `adapter-stripe` verifies: one header of
/// `t=<unix>,v1=<hex>[,v1=<hex>…]`, payload `{t}.{body}`. The header name is
/// configurable because other providers use the same layout under their own
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripeStyle {
    /// The header carrying `t=…,v1=…`.
    pub header: &'static str,
}

impl Default for StripeStyle {
    fn default() -> Self {
        Self {
            header: "Stripe-Signature",
        }
    }
}

impl SignatureScheme for StripeStyle {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery> {
        let raw = header(headers, self.header)?;
        let mut timestamp = None;
        let mut candidates = Vec::new();
        for part in raw.split(',') {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            match key.trim() {
                "t" => timestamp = value.trim().parse::<i64>().ok(),
                "v1" => {
                    if let Some(bytes) = hex_decode(value.trim()) {
                        candidates.push(bytes);
                    }
                }
                _ => {} // unknown keys are ignored, as the adapter ignores them
            }
        }
        let sent = timestamp?;
        if candidates.is_empty() {
            return None;
        }
        Some(SignedDelivery {
            signed_payload: [sent.to_string().as_bytes(), b".", body].concat(),
            candidates,
            timestamp: Some(sent),
        })
    }
}

/// A provider-specific scheme, configured rather than coded. Entries are
/// separated by commas or spaces, so a provider may send several — for
/// instance during a secret rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderScheme {
    /// The header carrying the signature (or several).
    pub signature: &'static str,
    /// How each entry is encoded in the header.
    pub encoding: SignatureEncoding,
    /// A literal prefix stripped from each entry before decoding (`sha256=`).
    pub prefix: Option<&'static str>,
    /// The header carrying a Unix-seconds timestamp the provider signs.
    /// When set, the payload is `{timestamp}.{body}` and the replay
    /// tolerance applies; when `None`, the payload is the raw body.
    pub timestamp: Option<&'static str>,
}

impl SignatureScheme for ProviderScheme {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery> {
        let raw = header(headers, self.signature)?;
        // A configured timestamp header that is missing or unreadable
        // refuses; it never downgrades to "no tolerance".
        let timestamp = match self.timestamp {
            Some(name) => Some(header(headers, name)?.trim().parse::<i64>().ok()?),
            None => None,
        };
        let mut candidates = Vec::new();
        for entry in raw.split([',', ' ']) {
            let Some(entry) = entry.strip_prefix(self.prefix.unwrap_or("")) else {
                continue;
            };
            let decoded = match self.encoding {
                SignatureEncoding::Hex => hex_decode(entry),
                SignatureEncoding::Base64 => STANDARD.decode(entry).ok(),
            };
            if let Some(bytes) = decoded {
                candidates.push(bytes);
            }
        }
        if candidates.is_empty() {
            return None;
        }
        Some(SignedDelivery {
            signed_payload: match timestamp {
                Some(sent) => [sent.to_string().as_bytes(), b".", body].concat(),
                None => body.to_vec(),
            },
            candidates,
            timestamp,
        })
    }
}

/// GitHub's scheme (`X-Hub-Signature-256`), the shape GitHub App and
/// repository webhook deliveries carry: one header, `sha256=<hex>`, over the
/// **raw body alone**. A named scheme so ventures declaring a GitHub
/// delivery do not re-type the equivalent [`ProviderScheme`] fields.
///
/// GitHub deliveries carry **no timestamp** — only the HMAC — so this
/// scheme offers no replay protection of its own, and
/// [`WebhookVerifier::verify`]'s tolerance never applies. A replayed
/// delivery is rejected by claiming the `X-GitHub-Delivery` id through the
/// [`Inbox`](crate::idempotency::Inbox) dedup ledger, which is what makes
/// each delivery apply its effects exactly once.
#[derive(Debug, Clone, Copy, Default)]
pub struct Github;

/// The [`ProviderScheme`] GitHub's header layout expands to — kept beside
/// [`Github`]'s [`SignatureScheme`] impl so the two cannot drift.
const GITHUB_SCHEME: ProviderScheme = ProviderScheme {
    signature: "X-Hub-Signature-256",
    encoding: SignatureEncoding::Hex,
    prefix: Some("sha256="),
    timestamp: None,
};

impl SignatureScheme for Github {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery> {
        GITHUB_SCHEME.extract(headers, body)
    }
}

/// How a provider encodes signature bytes in its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureEncoding {
    /// Hexadecimal, upper- or lowercase, two digits per byte.
    Hex,
    /// Standard base64, with padding.
    Base64,
}

/// The `x-vercel-signature` header Vercel signs with.
const VERCEL_SIGNATURE_HEADER: &str = "x-vercel-signature";
/// An HMAC-SHA1 tag, the only length [`Vercel`] accepts.
const SHA1_TAG_LEN: usize = 20;

/// Vercel's scheme: header `x-vercel-signature`, a lowercase hex
/// HMAC-SHA1 over the raw body — no prefix, no timestamp header. The digest
/// is SHA-1 but the construction is HMAC, so SHA-1's collisions do not
/// apply (see the module docs); with no timestamp, replay defence is the
/// [`Inbox`](crate::idempotency::Inbox) dedup ledger's job.
#[derive(Debug, Clone, Copy, Default)]
pub struct Vercel;

impl SignatureScheme for Vercel {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery> {
        let raw = header(headers, VERCEL_SIGNATURE_HEADER)?;
        let candidate = hex_decode(raw.trim())?;
        // Not the 20 bytes of an HMAC-SHA1 tag: malformed, refuse rather
        // than let a truncated or padded value near the comparison.
        if candidate.len() != SHA1_TAG_LEN {
            return None;
        }
        Some(SignedDelivery {
            signed_payload: body.to_vec(),
            candidates: vec![candidate],
            timestamp: None,
        })
    }

    fn digest(&self) -> Digest {
        Digest::Sha1
    }
}

/// GitLab's `X-Gitlab-Token` header, whose value is the shared secret.
const GITLAB_TOKEN_HEADER: &str = "X-Gitlab-Token";

/// A shared-**token** scheme: the header carries the secret itself, in the
/// clear, and a value equal to the secret is what proves the delivery —
/// there is no signature over the body, so `body` is ignored entirely. The
/// comparison is the verifier's constant-time one (the same helper the HMAC
/// path uses); a missing, empty or non-UTF-8 token refuses. Nothing here is
/// bound to time, so a captured token replays: claim each delivery's event
/// id through the [`Inbox`](crate::idempotency::Inbox) ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedTokenScheme {
    /// The header carrying the token.
    pub header: &'static str,
}

impl SignatureScheme for SharedTokenScheme {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery> {
        // `body` is deliberately unread: a token proves the sender, not the
        // bytes.
        let _ = body;
        let token = header(headers, self.header)?;
        if token.is_empty() {
            return None; // an absent token cannot equal a non-empty secret
        }
        Some(SignedDelivery {
            signed_payload: Vec::new(),
            candidates: vec![token.as_bytes().to_vec()],
            timestamp: None,
        })
    }

    fn expected_signature(&self, key: &[u8], signed_payload: &[u8]) -> Vec<u8> {
        let _ = signed_payload;
        key.to_vec()
    }
}

/// GitLab's scheme: header `X-Gitlab-Token` carrying the shared secret
/// verbatim. Exactly [`SharedTokenScheme`] with that header fixed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gitlab;

/// The one configured instance [`Gitlab`] delegates to.
const GITLAB_TOKEN: SharedTokenScheme = SharedTokenScheme {
    header: GITLAB_TOKEN_HEADER,
};

impl SignatureScheme for Gitlab {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<SignedDelivery> {
        GITLAB_TOKEN.extract(headers, body)
    }

    fn expected_signature(&self, key: &[u8], signed_payload: &[u8]) -> Vec<u8> {
        GITLAB_TOKEN.expected_signature(key, signed_payload)
    }
}

/// The first header value, as a string; non-UTF-8 is unreadable, and
/// unreadable is refused.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// Hex, any case, an even number of digits; `None` otherwise.
fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::SignatureEncoding::{Base64, Hex};
    use super::*;

    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const WRONG: &str = "whsec_AAAAAAAA"; // a different, decodable secret
    const ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const NOW: i64 = 1_800_000_000;
    const STRIPE_SECRET: &str = "stripe-endpoint-secret-dummy";
    const PROVIDER_SECRET: &str = "provider-endpoint-secret-dummy";
    const VERCEL_SECRET: &str = "vercel-webhook-secret-dummy";
    const GITLAB_SECRET: &str = "gitlab-shared-token-dummy";
    /// A Vercel-shaped deployment webhook, the body the documented example
    /// signs.
    const VERCEL_BODY: &[u8] =
        br#"{"type":"deployment.succeeded","payload":{"deployment":{"id":"dpl_1"}}}"#;

    /// `HMAC-SHA1(key, parts)`, the tag Vercel sends.
    fn mac_sha1(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac =
            <HmacSha1 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| {
                let name = name
                    .parse::<http::header::HeaderName>()
                    .expect("test header name");
                (name, value.parse().expect("test header value"))
            })
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    fn mac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }

    /// The `svix-signature` header a provider would send for this body.
    fn svix_sign(secret: &str, id: &str, at: i64, body: &[u8]) -> String {
        let key = svix_secret_key(secret).expect("the fixture secret decodes");
        let ts = at.to_string();
        let payload = [id.as_bytes(), b".", ts.as_bytes(), b".", body];
        format!("v1,{}", STANDARD.encode(mac(&key, &payload)))
    }

    fn svix_headers(at: &str, sigs: &str) -> HeaderMap {
        headers(&[
            ("svix-id", ID),
            ("svix-timestamp", at),
            ("svix-signature", sigs),
        ])
    }

    /// Whether an Svix delivery with these header values verifies.
    fn svix_verifies(secret: &str, at: &str, sigs: &str, body: &[u8], now: i64) -> bool {
        WebhookVerifier::new(Svix).verify(secret, &svix_headers(at, sigs), body, now)
    }

    /// The `t=,v1=` header Stripe would send for this body.
    fn stripe_sign(secret: &str, at: i64, body: &[u8]) -> String {
        let ts = at.to_string();
        let payload = [ts.as_bytes(), b".", body];
        let digest = hex(&mac(secret.as_bytes(), &payload));
        format!("t={at},v1={digest}")
    }

    /// Whether a Stripe delivery with this header value verifies.
    fn stripe_verifies(secret: &str, header: &str, body: &[u8], now: i64) -> bool {
        let got = headers(&[("Stripe-Signature", header)]);
        WebhookVerifier::new(StripeStyle::default()).verify(secret, &got, body, now)
    }

    fn provider(
        enc: SignatureEncoding,
        prefix: Option<&'static str>,
        at: Option<&'static str>,
    ) -> WebhookVerifier {
        WebhookVerifier::new(ProviderScheme {
            signature: "X-Signature",
            encoding: enc,
            prefix,
            timestamp: at,
        })
    }

    /// The bare hex signature a hex `ProviderScheme` reads.
    fn provider_sign(at: Option<i64>, body: &[u8]) -> String {
        let key = PROVIDER_SECRET.as_bytes();
        let digest = match at {
            Some(sent) => mac(key, &[sent.to_string().as_bytes(), b".", body]),
            None => mac(key, &[body]),
        };
        hex(&digest)
    }

    #[test]
    fn an_svix_delivery_verifies() {
        let body = br#"{"type":"pos.order.created"}"#;
        let header = svix_sign(SECRET, ID, NOW, body);
        assert!(svix_verifies(SECRET, "1800000000", &header, body, NOW));
        // `webhook-*` aliases, and the secret without its `whsec_` prefix.
        let aliased = headers(&[
            ("webhook-id", ID),
            ("webhook-timestamp", "1800000000"),
            ("webhook-signature", &header),
        ]);
        assert!(WebhookVerifier::new(Svix).verify(SECRET, &aliased, body, NOW));
        let bare = SECRET.strip_prefix("whsec_").expect("prefixed");
        assert!(svix_verifies(bare, "1800000000", &header, body, NOW));
    }

    #[test]
    fn a_tampered_delivery_or_wrong_secret_refuses_but_a_rotation_matches() {
        let body = b"{}";
        let header = svix_sign(SECRET, ID, NOW, body);
        let old = svix_sign(WRONG, ID, NOW, body);
        let tampered = br#"{"changed":true}"#;
        assert!(!svix_verifies(SECRET, "1800000000", &header, tampered, NOW));
        assert!(!svix_verifies(WRONG, "1800000000", &header, body, NOW));
        // The id is part of what is signed, so it cannot be swapped either.
        let swapped = svix_sign(SECRET, "msg_another", NOW, body);
        assert!(!svix_verifies(SECRET, "1800000000", &swapped, body, NOW));
        // A rotation: the provider signs with both secrets for the overlap,
        // an unknown version among them is ignored, and a header holding
        // only unknown versions refuses.
        let both = format!("{old} v0,AAAA {header}");
        assert!(svix_verifies(SECRET, "1800000000", &both, body, NOW));
        assert!(!svix_verifies(SECRET, "1800000000", "v0,AAAA", body, NOW));
    }

    #[test]
    fn a_delivery_outside_the_tolerance_is_refused() {
        let body = b"{}";
        let sent = NOW - DEFAULT_TOLERANCE_SECS - 1;
        let stale = svix_sign(SECRET, ID, sent, body);
        // The signature stays perfectly valid; the timestamp is what stops
        // it being replayed forever — in either direction.
        assert!(svix_verifies(SECRET, &sent.to_string(), &stale, body, sent));
        assert!(!svix_verifies(SECRET, &sent.to_string(), &stale, body, NOW));
        let future = NOW + DEFAULT_TOLERANCE_SECS + 1;
        let late = svix_sign(SECRET, ID, future, body);
        assert!(!svix_verifies(
            SECRET,
            &future.to_string(),
            &late,
            body,
            NOW
        ));
        // The tolerance is configurable.
        let wide = WebhookVerifier::new(Svix).tolerance_secs(DEFAULT_TOLERANCE_SECS * 2);
        assert!(wide.verify(SECRET, &svix_headers(&sent.to_string(), &stale), body, NOW));
    }

    #[test]
    fn unreadable_svix_input_refuses() {
        let body = b"{}";
        let header = svix_sign(SECRET, ID, NOW, body);
        // Missing headers entirely; a timestamp that is not a number; a
        // signature list with no readable entry.
        assert!(!WebhookVerifier::new(Svix).verify(SECRET, &headers(&[]), body, NOW));
        assert!(!svix_verifies(SECRET, "recently", &header, body, NOW));
        assert!(!svix_verifies(SECRET, "1800000000", "garbage", body, NOW));
        // A secret that does not decode is a misconfiguration, not a
        // fallback; an empty secret is not a key.
        assert!(!svix_verifies(
            "whsec_!!!!",
            "1800000000",
            &header,
            body,
            NOW
        ));
        assert!(!svix_verifies("", "1800000000", &header, body, NOW));
    }

    #[test]
    fn a_stripe_delivery_verifies_and_malformed_ones_refuse() {
        let body = b"{}";
        let header = stripe_sign(STRIPE_SECRET, NOW, body);
        assert!(stripe_verifies(STRIPE_SECRET, &header, body, NOW));
        // The header name is configurable: the same layout under another.
        let renamed = WebhookVerifier::new(StripeStyle {
            header: "X-Signature",
        });
        let under = headers(&[("X-Signature", &header)]);
        assert!(renamed.verify(STRIPE_SECRET, &under, body, NOW));
        // Body changed; another endpoint's secret.
        assert!(!stripe_verifies(STRIPE_SECRET, &header, b"x", NOW));
        assert!(!stripe_verifies("another-secret-dummy", &header, body, NOW));
        // No `t=` (nothing to hold the tolerance to), a `t=` that is not a
        // number, and no `v1=` at all.
        let digest = hex(&mac(
            STRIPE_SECRET.as_bytes(),
            &[NOW.to_string().as_bytes(), b".", body],
        ));
        assert!(!stripe_verifies(
            STRIPE_SECRET,
            &format!("v1={digest}"),
            body,
            NOW
        ));
        assert!(!stripe_verifies(
            STRIPE_SECRET,
            &format!("t=recently,v1={digest}"),
            body,
            NOW
        ));
        assert!(!stripe_verifies(STRIPE_SECRET, "t=1800000000", body, NOW));
        // The timestamp carries the replay tolerance here too.
        let sent = NOW - DEFAULT_TOLERANCE_SECS - 1;
        let stale = stripe_sign(STRIPE_SECRET, sent, body);
        assert!(!stripe_verifies(STRIPE_SECRET, &stale, body, NOW));
    }

    #[test]
    fn a_provider_scheme_verifies_raw_and_timestamped_deliveries() {
        let body = br#"{"event":"order.created"}"#;
        let raw = provider(Hex, None, None);
        let got = headers(&[("X-Signature", &provider_sign(None, body))]);
        // No timestamp header: the payload is the raw body and the
        // tolerance does not apply — "now" is whatever the caller says.
        assert!(raw.verify(PROVIDER_SECRET, &got, body, NOW));
        assert!(raw.verify(PROVIDER_SECRET, &got, body, NOW + 10_000));
        assert!(!raw.verify(PROVIDER_SECRET, &got, b"x", NOW));
        assert!(!raw.verify("other", &got, body, NOW));
        assert!(
            !raw.verify("", &got, body, NOW),
            "an empty secret is not a key"
        );
        // With a timestamp header the payload is `{timestamp}.{body}`, a
        // configured header that is not sent refuses instead of silently
        // downgrading, and a prefixed entry is stripped before decoding.
        let stamped = provider(Hex, Some("sha256="), Some("X-At"));
        let header = format!("sha256={}", provider_sign(Some(NOW), body));
        let with_at = headers(&[("X-Signature", &header), ("X-At", "1800000000")]);
        assert!(stamped.verify(PROVIDER_SECRET, &with_at, body, NOW));
        let no_at = headers(&[("X-Signature", &header)]);
        assert!(!stamped.verify(PROVIDER_SECRET, &no_at, body, NOW));
        let no_sig = headers(&[("X-At", "1800000000")]);
        assert!(!stamped.verify(PROVIDER_SECRET, &no_sig, body, NOW));
        // Base64 encoding works too; an entry that does not decode is
        // skipped rather than fatal.
        let b64 = provider(Base64, None, None);
        let encoded = STANDARD.encode(mac(PROVIDER_SECRET.as_bytes(), &[body]));
        let b64hdr = headers(&[("X-Signature", &encoded)]);
        assert!(b64.verify(PROVIDER_SECRET, &b64hdr, body, NOW));
        let junk = headers(&[("X-Signature", "!!!!")]);
        assert!(!b64.verify(PROVIDER_SECRET, &junk, body, NOW));
    }

    /// GitHub's own example from "Validating webhook deliveries": secret
    /// `It's a Secret to Everybody`, body `Hello, World!`, and the
    /// `sha256=` header GitHub documents.
    #[test]
    fn a_github_delivery_verifies() {
        const GITHUB_SECRET: &str = "It's a Secret to Everybody";
        const GITHUB_BODY: &[u8] = b"Hello, World!";
        const GITHUB_SIGNATURE: &str =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        let got = headers(&[("X-Hub-Signature-256", GITHUB_SIGNATURE)]);
        let verifier = WebhookVerifier::new(Github);
        // No timestamp rides the delivery, so the tolerance never applies:
        // "now" is whatever the caller says.
        assert!(verifier.verify(GITHUB_SECRET, &got, GITHUB_BODY, NOW));
        assert!(verifier.verify(GITHUB_SECRET, &got, GITHUB_BODY, NOW + 10_000));
    }

    #[test]
    fn a_tampered_github_delivery_or_wrong_secret_refuses() {
        const GITHUB_SECRET: &str = "It's a Secret to Everybody";
        const GITHUB_BODY: &[u8] = b"Hello, World!";
        const GITHUB_SIGNATURE: &str =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        let verifier = WebhookVerifier::new(Github);
        let got = headers(&[("X-Hub-Signature-256", GITHUB_SIGNATURE)]);
        assert!(!verifier.verify(GITHUB_SECRET, &got, b"Hello, World?", NOW));
        assert!(!verifier.verify("another-secret-dummy", &got, GITHUB_BODY, NOW));
        assert!(
            !verifier.verify("", &got, GITHUB_BODY, NOW),
            "an empty secret is not a key"
        );
    }

    #[test]
    fn unreadable_github_input_refuses() {
        const GITHUB_SECRET: &str = "It's a Secret to Everybody";
        const GITHUB_BODY: &[u8] = b"Hello, World!";
        const GITHUB_SIGNATURE: &str =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        let verifier = WebhookVerifier::new(Github);
        // No header at all; the legacy sha1 header; a header with no
        // `sha256=` prefix; and a prefix with a body that is not hex.
        assert!(!verifier.verify(GITHUB_SECRET, &headers(&[]), GITHUB_BODY, NOW));
        assert!(!verifier.verify(
            GITHUB_SECRET,
            &headers(&[("X-Hub-Signature", "sha1=deadbeef")]),
            GITHUB_BODY,
            NOW
        ));
        assert!(!verifier.verify(
            GITHUB_SECRET,
            &headers(&[("X-Hub-Signature-256", "deadbeef")]),
            GITHUB_BODY,
            NOW
        ));
        let unprefixed = GITHUB_SIGNATURE.strip_prefix("sha256=").expect("prefixed");
        assert!(!verifier.verify(
            GITHUB_SECRET,
            &headers(&[("X-Hub-Signature-256", unprefixed)]),
            GITHUB_BODY,
            NOW
        ));
    }

    /// Whether a Vercel delivery with this header value verifies.
    fn vercel_verifies(secret: &str, signature: &str, body: &[u8], now: i64) -> bool {
        let got = headers(&[("x-vercel-signature", signature)]);
        WebhookVerifier::new(Vercel).verify(secret, &got, body, now)
    }

    #[test]
    fn hmac_sha1_matches_the_rfc_2202_vector() {
        // RFC 2202, HMAC-SHA1 test case 2 — the same value `openssl dgst
        // -sha1 -hmac Jefe` prints — anchors the SHA-1 path independently
        // of anything this crate computes.
        let tag = hex(&mac_sha1(b"Jefe", &[b"what do ya want for nothing?"]));
        assert_eq!(tag, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    #[test]
    fn a_vercel_delivery_verifies_and_tampered_ones_refuse() {
        // The documented example: lowercase hex HMAC-SHA1 over a raw,
        // Vercel-shaped deployment body.
        let signature = hex(&mac_sha1(VERCEL_SECRET.as_bytes(), &[VERCEL_BODY]));
        assert_eq!(signature, "d6543f159dfdf17c47130f1019ba14ed71bd4ca5");
        assert!(vercel_verifies(VERCEL_SECRET, &signature, VERCEL_BODY, NOW));
        // No timestamp, so "now" does not enter the answer.
        assert!(vercel_verifies(
            VERCEL_SECRET,
            &signature,
            VERCEL_BODY,
            NOW + 10_000
        ));
        // One byte of the body changed; another endpoint's secret.
        let tampered =
            br#"{"type":"deployment.succeeded","payload":{"deployment":{"id":"dpl_2"}}}"#;
        assert!(!vercel_verifies(VERCEL_SECRET, &signature, tampered, NOW));
        assert!(!vercel_verifies(
            "another-secret-dummy",
            &signature,
            VERCEL_BODY,
            NOW
        ));
        // An empty secret is not a key.
        assert!(!vercel_verifies("", &signature, VERCEL_BODY, NOW));
    }

    #[test]
    fn unreadable_vercel_input_refuses() {
        // Missing header entirely.
        assert!(!WebhookVerifier::new(Vercel).verify(
            VERCEL_SECRET,
            &headers(&[]),
            VERCEL_BODY,
            NOW
        ));
        // An odd digit count, a non-hex pair, and an even but wrong length
        // (not the 20 bytes of an HMAC-SHA1 tag) all refuse before the
        // comparison — no truncated or padded value is ever compared.
        assert!(!vercel_verifies(
            VERCEL_SECRET,
            &"a".repeat(39),
            VERCEL_BODY,
            NOW
        ));
        assert!(!vercel_verifies(
            VERCEL_SECRET,
            "not-hex!!",
            VERCEL_BODY,
            NOW
        ));
        assert!(!vercel_verifies(VERCEL_SECRET, "zzzz", VERCEL_BODY, NOW));
        assert!(!vercel_verifies(VERCEL_SECRET, "abcd", VERCEL_BODY, NOW));
        assert!(!vercel_verifies(
            VERCEL_SECRET,
            &"a".repeat(41),
            VERCEL_BODY,
            NOW
        ));
    }

    /// Whether a GitLab delivery with this token header value verifies.
    fn gitlab_verifies(secret: &str, token: &str, body: &[u8], now: i64) -> bool {
        let got = headers(&[("X-Gitlab-Token", token)]);
        WebhookVerifier::new(Gitlab).verify(secret, &got, body, now)
    }

    #[test]
    fn a_gitlab_shared_token_verifies_and_ignores_the_body() {
        let body = br#"{"object_kind":"push"}"#;
        assert!(gitlab_verifies(GITLAB_SECRET, GITLAB_SECRET, body, NOW));
        // The body plays no part: a different body, or none, still matches.
        assert!(gitlab_verifies(GITLAB_SECRET, GITLAB_SECRET, b"", NOW));
        assert!(gitlab_verifies(
            GITLAB_SECRET,
            GITLAB_SECRET,
            b"a wholly different body",
            NOW + 10_000
        ));
        // Header lookup is case-insensitive, as http::HeaderMap always is.
        let lower = headers(&[("x-gitlab-token", GITLAB_SECRET)]);
        assert!(WebhookVerifier::new(Gitlab).verify(GITLAB_SECRET, &lower, body, NOW));
    }

    #[test]
    fn wrong_or_unreadable_gitlab_tokens_refuse() {
        let body = b"{}";
        // The wrong token, and one of a different length — the comparison
        // fails either way, and length is not secret.
        assert!(!gitlab_verifies(
            GITLAB_SECRET,
            "other-token-dummy",
            body,
            NOW
        ));
        assert!(!gitlab_verifies(
            GITLAB_SECRET,
            "gitlab-shared-token-dummy-plus",
            body,
            NOW
        ));
        // Missing header; empty token; empty secret.
        assert!(!WebhookVerifier::new(Gitlab).verify(GITLAB_SECRET, &headers(&[]), body, NOW));
        assert!(!gitlab_verifies(GITLAB_SECRET, "", body, NOW));
        assert!(!gitlab_verifies("", GITLAB_SECRET, body, NOW));
        // A non-UTF-8 header value is unreadable, and unreadable refuses.
        let mut raw = HeaderMap::new();
        raw.insert(
            "X-Gitlab-Token",
            http::HeaderValue::from_bytes(&[0xff, 0xfe, 0x80]).expect("opaque header value"),
        );
        assert!(!WebhookVerifier::new(Gitlab).verify(GITLAB_SECRET, &raw, body, NOW));
        // The generic scheme honours its own header name.
        let custom = WebhookVerifier::new(SharedTokenScheme {
            header: "X-Custom-Token",
        });
        assert!(custom.verify(
            GITLAB_SECRET,
            &headers(&[("X-Custom-Token", GITLAB_SECRET)]),
            body,
            NOW
        ));
        assert!(!custom.verify(
            GITLAB_SECRET,
            &headers(&[("X-Gitlab-Token", GITLAB_SECRET)]),
            body,
            NOW
        ));
    }
}
