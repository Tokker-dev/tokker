//! The Web Push test vectors the workspace shares.
//!
//! These are not decorative constants. [`RFC8291_UA_PUBLIC`] and
//! [`RFC8291_AUTH_SECRET`] are RFC 8291 Appendix A's user agent: a real
//! point on the P-256 curve and a real 16-byte auth secret, so a
//! subscription built from them is one the adapter accepts and a body
//! encrypted to them can be opened again with [`RFC8291_UA_PRIVATE`]. A
//! made-up `p256dh` is refused — which is the point of the checks that use
//! them, and the reason a test cannot simply invent a value.
//!
//! They used to be copied into `crates/adapter-webpush`,
//! `crates/adapter-apns`, `crates/cli` and `crates/cli-acceptance`, each
//! with a comment saying it was "the same one" another crate used and
//! nothing making that true. `crates/cli-acceptance/tests/vector_guard.rs`
//! now fails the build if any source outside this module writes one of
//! them down again.

/// RFC 8291 Appendix A: the user agent's public key — the `p256dh` a
/// browser puts in `subscription.keys`, base64url of the 65-byte
/// uncompressed P-256 point.
pub const RFC8291_UA_PUBLIC: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";

/// RFC 8291 Appendix A: the user agent's private key. Only a test has
/// this — it is what lets the decrypt side of a round trip exist.
pub const RFC8291_UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";

/// RFC 8291 Appendix A: the subscription's 16-byte `auth` secret.
pub const RFC8291_AUTH_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";

/// RFC 8291 §5: the plaintext the published example encrypts.
pub const RFC8291_PLAINTEXT: &str = "When I grow up, I want to be a watermelon";

/// The push service origin of [`WEB_PUSH_ENDPOINT`] — what a VAPID token
/// claims as its `aud`, and the most a report may print of an endpoint.
pub const WEB_PUSH_ORIGIN: &str = "https://updates.push.services.mozilla.com";

/// The subscription-specific part of [`WEB_PUSH_ENDPOINT`]'s path: the
/// bearer capability, and so the string a test asserts is **absent** from
/// output. Distinctive on purpose — it cannot be matched by accident.
pub const WEB_PUSH_ENDPOINT_CAPABILITY: &str = "gAAAAABsubscriptionCapability";

/// A Web Push endpoint of the shape a browser hands over: an origin plus a
/// long, subscription-specific path. Whoever holds the whole thing can
/// push to that browser, which is what makes it credential material.
pub const WEB_PUSH_ENDPOINT: &str =
    "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABsubscriptionCapability";

/// A throwaway P-256 private key in PKCS#8 PEM, generated for these tests
/// only — **not** an Apple, Google or Mozilla key.
///
/// Shared for the suites that already read from here. It is older than
/// this module (`cratefield-push-auth` mints with it, and the APNs suite
/// asserts bytes from it), so unlike the Web Push vectors above it is not
/// guarded as the only copy — see
/// `crates/cli-acceptance/tests/vector_guard.rs`.
pub const TEST_P256_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcXMgRpW+eLn7ZvCx\nIuTdd8csWMZ69azlRzS0dy2FN6GhRANCAATJ6GazR2lhWcC3JYsazLR0uWOyDKrC\nmeP4HPWghRmfoa4z3Ux7mG3Ylz+auRaBukKGicSdSvVG+jGeQwr3fNag\n-----END PRIVATE KEY-----";

/// A `mailto:` VAPID subject (RFC 8292 §2.1).
pub const TEST_VAPID_SUBJECT: &str = "mailto:ops@example.test";

/// The subscription exactly as `JSON.stringify(subscription)` gives it —
/// the shape an operator pastes into `fz push send --recipient`.
#[must_use]
pub fn web_push_subscription_json() -> String {
    format!(
        "{{\"endpoint\":\"{WEB_PUSH_ENDPOINT}\",\"expirationTime\":null,\
         \"keys\":{{\"p256dh\":\"{RFC8291_UA_PUBLIC}\",\"auth\":\"{RFC8291_AUTH_SECRET}\"}}}}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_is_its_origin_and_its_capability() {
        assert_eq!(
            WEB_PUSH_ENDPOINT,
            format!("{WEB_PUSH_ORIGIN}/wpush/v2/{WEB_PUSH_ENDPOINT_CAPABILITY}"),
            "the three have to be one endpoint, or a test asserting the capability is absent \
             asserts nothing"
        );
    }

    #[test]
    fn the_subscription_json_carries_the_vectors() {
        let json = web_push_subscription_json();
        for part in [WEB_PUSH_ENDPOINT, RFC8291_UA_PUBLIC, RFC8291_AUTH_SECRET] {
            assert!(json.contains(part), "{part} is missing from {json}");
        }
    }
}
