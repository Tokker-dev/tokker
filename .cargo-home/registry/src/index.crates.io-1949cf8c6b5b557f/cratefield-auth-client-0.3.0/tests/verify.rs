//! Issue #11 acceptance.
//!
//! Every test here is a token that must be refused, because a client
//! crate earns its place by refusing things a hand-written check would
//! wave through. The one accepting test exists to prove the others are
//! not passing vacuously.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use bytes::Bytes;
use cratefield_auth_client::{AuthClient, VerifyError};
use cratefield_core::{Clock, HttpClient, HttpError};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{self, Signature};
use serde_json::{Value, json};
use time::OffsetDateTime;

const ISSUER: &str = "https://auth.factory0.ventures";
const CLIENT: &str = "client-kontinuum";
const OTHER_CLIENT: &str = "client-undercover";
const NOW: i64 = 1_800_000_000;

/// A clock frozen at [`NOW`], through the port — no `std::time`.
struct FrozenClock;

impl Clock for FrozenClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(NOW).expect("in range")
    }
}

/// An `HttpClient` that answers with one canned JWKS body and counts
/// how many times it was asked.
struct FakeJwks {
    body: RwLock<String>,
    calls: RwLock<usize>,
}

impl FakeJwks {
    fn new(body: String) -> Arc<Self> {
        Arc::new(Self {
            body: RwLock::new(body),
            calls: RwLock::new(0),
        })
    }
    fn calls(&self) -> usize {
        *self.calls.read().expect("uncontended")
    }
}

#[async_trait]
impl HttpClient for FakeJwks {
    async fn send(
        &self,
        _request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        *self.calls.write().expect("uncontended") += 1;
        let body = self.body.read().expect("uncontended").clone();
        Ok(http::Response::builder()
            .status(200)
            .body(Bytes::from(body))
            .expect("response"))
    }
}

/// A throwaway P-256 keypair, generated in the test.
fn key(seed: u8) -> (ecdsa::SigningKey, Value) {
    let mut bytes = [seed.max(1); 32];
    bytes[0] = seed.max(1);
    let secret = p256::SecretKey::from_slice(&bytes).expect("scalar");
    let signing = ecdsa::SigningKey::from(&secret);
    // Uncompressed SEC1 is 0x04 || X || Y; the JWK carries X and Y.
    let point = signing.verifying_key().to_sec1_point(false);
    let sec1 = point.as_bytes();
    assert_eq!(sec1.len(), 65, "uncompressed point");
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": format!("k{seed}"),
        "x": Base64UrlUnpadded::encode_string(&sec1[1..33]),
        "y": Base64UrlUnpadded::encode_string(&sec1[33..65]),
    });
    (signing, jwk)
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Mints a token the way the auth service does.
fn mint(signing: &ecdsa::SigningKey, header: &Value, claims: &Value) -> String {
    let signing_input = format!(
        "{}.{}",
        b64(serde_json::to_string(header).expect("header").as_bytes()),
        b64(serde_json::to_string(claims).expect("claims").as_bytes())
    );
    let signature: Signature = signing.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64(&signature.to_bytes()))
}

fn claims(aud: &str, iss: &str, exp: i64) -> Value {
    json!({
        "sub": "user-1", "aud": aud, "iss": iss, "sid": "session-1",
        "exp": exp, "iat": NOW - 10, "email": "a@example.com",
        "email_verified": true, "amr": ["passkey"],
    })
}

fn client(http: Arc<dyn HttpClient>) -> AuthClient {
    AuthClient::new(http, Arc::new(FrozenClock), ISSUER, CLIENT)
}

fn jwks_body(jwks: &[Value]) -> String {
    json!({ "keys": jwks }).to_string()
}

/// The control: a well-formed token for this client verifies, and the
/// claims come back intact. Without this the refusals below could all
/// be passing for the wrong reason.
#[pollster::test]
async fn a_valid_token_verifies_and_yields_its_claims() {
    let (signing, jwk) = key(1);
    let http = FakeJwks::new(jwks_body(&[jwk]));
    let auth = client(http);
    let token = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );

    let verified = auth.verify(&token).await.expect("verifies");
    assert_eq!(verified.sub, "user-1");
    assert_eq!(verified.sid, "session-1");
    assert_eq!(verified.amr, vec!["passkey".to_owned()]);
}

/// The check hand-written verifiers forget. This token is signed by the
/// right issuer with the right key and is entirely valid — for another
/// venture. Accepting it would let any Factory Zero client use its own
/// token against every other one.
#[pollster::test]
async fn a_token_for_another_client_is_refused() {
    let (signing, jwk) = key(1);
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));
    let token = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(OTHER_CLIENT, ISSUER, NOW + 600),
    );

    assert_eq!(
        auth.verify(&token).await,
        Err(VerifyError::Audience {
            got: OTHER_CLIENT.to_owned(),
            want: CLIENT.to_owned()
        })
    );
}

/// A token from a different auth service entirely.
#[pollster::test]
async fn a_token_from_another_issuer_is_refused() {
    let (signing, jwk) = key(1);
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));
    let token = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(CLIENT, "https://evil.example", NOW + 600),
    );

    assert!(matches!(
        auth.verify(&token).await,
        Err(VerifyError::Issuer { .. })
    ));
}

#[pollster::test]
async fn an_expired_token_is_refused() {
    let (signing, jwk) = key(1);
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));
    let token = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(CLIENT, ISSUER, NOW - 3600),
    );

    assert_eq!(auth.verify(&token).await, Err(VerifyError::Expired));
}

/// `alg: none` is the oldest JWT attack: strip the signature and claim
/// none was needed. It is refused before a key is even looked up.
#[pollster::test]
async fn the_none_algorithm_is_refused() {
    let (_signing, jwk) = key(1);
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));
    let header = b64(json!({"alg": "none", "kid": "k1"}).to_string().as_bytes());
    let payload = b64(claims(CLIENT, ISSUER, NOW + 600).to_string().as_bytes());
    let token = format!("{header}.{payload}.");

    assert_eq!(
        auth.verify(&token).await,
        Err(VerifyError::Algorithm("none".to_owned()))
    );
}

/// Algorithm confusion: ask us to verify with HMAC so the public key
/// becomes the shared secret. Refused on the header alone.
#[pollster::test]
async fn an_hmac_algorithm_is_refused() {
    let (signing, jwk) = key(1);
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));
    let token = mint(
        &signing,
        &json!({"alg": "HS256", "kid": "k1"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );

    assert_eq!(
        auth.verify(&token).await,
        Err(VerifyError::Algorithm("HS256".to_owned()))
    );
}

/// Signed by a key the issuer does not publish: correct shape, correct
/// claims, wrong signer.
#[pollster::test]
async fn a_token_signed_by_an_unpublished_key_is_refused() {
    let (_published, jwk) = key(1);
    let (attacker, _) = key(9);
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));
    // Names the published kid, but is signed with a different key.
    let token = mint(
        &attacker,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );

    assert_eq!(auth.verify(&token).await, Err(VerifyError::Signature));
}

/// A tampered payload invalidates the signature over it.
#[pollster::test]
async fn a_tampered_payload_is_refused() {
    let (signing, jwk) = key(1);
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));
    let token = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );
    let mut parts: Vec<&str> = token.split('.').collect();
    let swapped = b64(claims("client-elevated", ISSUER, NOW + 600)
        .to_string()
        .as_bytes());
    parts[1] = &swapped;
    let tampered = parts.join(".");

    assert_eq!(auth.verify(&tampered).await, Err(VerifyError::Signature));
}

/// The key set is fetched once and then cached: a busy app must not
/// hammer the auth service on every request.
#[pollster::test]
async fn the_key_set_is_cached_across_verifications() {
    let (signing, jwk) = key(1);
    let http = FakeJwks::new(jwks_body(&[jwk]));
    let auth = client(Arc::clone(&http) as Arc<dyn HttpClient>);
    let token = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );

    for _ in 0..5 {
        auth.verify(&token).await.expect("verifies");
    }
    assert_eq!(http.calls(), 1, "one fetch serves every verification");
}

/// A token naming a key we do not hold triggers exactly one forced
/// refetch — that is what makes rotation invisible — and no more,
/// however many such tokens arrive. Otherwise anyone could use invented
/// key ids to drive traffic at the auth service.
#[pollster::test]
async fn an_unknown_key_forces_one_refetch_and_is_then_rate_limited() {
    let (_signing, jwk) = key(1);
    let (attacker, _) = key(9);
    let http = FakeJwks::new(jwks_body(&[jwk]));
    let auth = client(Arc::clone(&http) as Arc<dyn HttpClient>);
    let token = mint(
        &attacker,
        &json!({"alg": "ES256", "kid": "k-not-published"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );

    for _ in 0..10 {
        assert!(matches!(
            auth.verify(&token).await,
            Err(VerifyError::UnknownKey(_))
        ));
    }
    assert_eq!(
        http.calls(),
        2,
        "one initial fetch plus one forced refetch, not ten"
    );
}

/// An issuer that mistakenly publishes a private key must not turn that
/// bug into a client vulnerability: the key is skipped, not used.
#[pollster::test]
async fn a_private_key_in_the_published_set_is_ignored() {
    let (signing, mut jwk) = key(1);
    jwk["d"] = json!("dGhpcy1pcy1ub3QtYS1yZWFsLXByaXZhdGUta2V5");
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));
    let token = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );

    assert!(
        matches!(auth.verify(&token).await, Err(VerifyError::UnknownKey(_))),
        "a key carrying `d` is refused, so the token cannot verify"
    );
}

/// An unreachable auth service must not invalidate a running app's
/// sessions: the previously fetched keys keep working.
#[pollster::test]
async fn a_failed_refetch_keeps_the_previous_keys() {
    struct FailsAfterFirst {
        body: String,
        calls: RwLock<usize>,
    }
    #[async_trait]
    impl HttpClient for FailsAfterFirst {
        async fn send(
            &self,
            _request: http::Request<Bytes>,
        ) -> Result<http::Response<Bytes>, HttpError> {
            let mut calls = self.calls.write().expect("uncontended");
            *calls += 1;
            if *calls == 1 {
                Ok(http::Response::builder()
                    .status(200)
                    .body(Bytes::from(self.body.clone()))
                    .expect("response"))
            } else {
                Ok(http::Response::builder()
                    .status(503)
                    .body(Bytes::new())
                    .expect("response"))
            }
        }
    }

    let (signing, jwk) = key(1);
    let http = Arc::new(FailsAfterFirst {
        body: jwks_body(&[jwk]),
        calls: RwLock::new(0),
    });
    let auth = client(Arc::clone(&http) as Arc<dyn HttpClient>);
    let good = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k1"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );
    let unknown = mint(
        &signing,
        &json!({"alg": "ES256", "kid": "k-missing"}),
        &claims(CLIENT, ISSUER, NOW + 600),
    );

    auth.verify(&good).await.expect("first verification");
    // Forces a refetch, which now fails.
    let _ = auth.verify(&unknown).await;
    // The original key must still verify.
    auth.verify(&good)
        .await
        .expect("a failed refetch keeps the previous keys");
}

/// Garbage in the header, the segments, or the base64 is refused
/// without panicking — this crate parses attacker-controlled input.
#[pollster::test]
async fn malformed_tokens_are_refused_without_panicking() {
    let (_signing, jwk) = key(1);
    let auth = client(FakeJwks::new(jwks_body(&[jwk])));

    for token in [
        "",
        "not-a-token",
        "a.b",
        "a.b.c.d",
        "!!!.###.$$$",
        "eyJhbGciOiJFUzI1NiJ9",
    ] {
        assert!(
            auth.verify(token).await.is_err(),
            "{token:?} must be refused"
        );
    }
}
