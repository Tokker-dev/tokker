//! Token verification: header, signature, then claims.
//!
//! The order matters. Nothing inside a token is trusted until its
//! signature verifies, so the claim checks run last, on a payload that
//! has already been proven to come from a key we hold.

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{ALGORITHM, LEEWAY_SECS};

/// Why a token was refused.
///
/// The variants exist to be logged, not to be shown to a caller: a
/// client that learns *why* its token failed learns something about the
/// verifier. Handlers turn every one of these into the same 401.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("token is not three base64url segments")]
    Malformed,
    #[error("header is not JSON, or omits alg/kid")]
    BadHeader,
    #[error("algorithm {0} is not accepted; only {ALGORITHM} is")]
    Algorithm(String),
    #[error("no key with id {0} is published by the issuer")]
    UnknownKey(String),
    #[error("signature does not verify")]
    Signature,
    #[error("payload is not JSON, or omits a required claim")]
    BadPayload,
    #[error("issuer is {got}, expected {want}")]
    Issuer { got: String, want: String },
    #[error("audience is {got}, expected {want}")]
    Audience { got: String, want: String },
    #[error("token expired")]
    Expired,
    #[error("token is not valid yet")]
    NotYetValid,
}

/// The claims a verified access token carries.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// The user this token speaks for.
    pub sub: String,
    /// The client the token was minted for; checked against ours.
    pub aud: String,
    /// The issuing service.
    pub iss: String,
    /// The session behind the token. A consuming app that needs
    /// instant revocation asks the auth service about this id; see the
    /// crate docs for why that is the exception rather than the rule.
    pub sid: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Authentication methods used at login (RFC 8176).
    #[serde(default)]
    pub amr: Vec<String>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
}

/// The `kid` a token names, without verifying anything.
///
/// Used only to decide whether a forced JWKS refetch might help. A
/// caller must never act on this: it is attacker-controlled until the
/// signature verifies.
pub(crate) fn peek_kid(token: &str) -> Option<String> {
    let header = decode_header(token).ok()?;
    (header.alg == ALGORITHM).then_some(header.kid)
}

fn decode_header(token: &str) -> Result<Header, VerifyError> {
    let encoded = token.split('.').next().ok_or(VerifyError::Malformed)?;
    let bytes = Base64UrlUnpadded::decode_vec(encoded).map_err(|_| VerifyError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|_| VerifyError::BadHeader)
}

/// Verifies one token against the keys we hold.
///
/// `keys` maps `kid` to the public key published for it.
pub(crate) fn verify_with(
    token: &str,
    keys: &[(String, VerifyingKey)],
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<Claims, VerifyError> {
    let mut parts = token.split('.');
    let (Some(encoded_header), Some(encoded_payload), Some(encoded_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VerifyError::Malformed);
    };

    let header: Header = {
        let bytes =
            Base64UrlUnpadded::decode_vec(encoded_header).map_err(|_| VerifyError::Malformed)?;
        serde_json::from_slice(&bytes).map_err(|_| VerifyError::BadHeader)?
    };

    // Algorithm first, before a key is even looked up: `none` and the
    // HMAC families are refused here rather than deeper in, so a token
    // asking us to verify it with the public key as a shared secret
    // never gets the chance.
    if header.alg != ALGORITHM {
        return Err(VerifyError::Algorithm(header.alg));
    }

    let key = keys
        .iter()
        .find(|(kid, _)| *kid == header.kid)
        .map(|(_, key)| key)
        .ok_or_else(|| VerifyError::UnknownKey(header.kid.clone()))?;

    let signature_bytes =
        Base64UrlUnpadded::decode_vec(encoded_signature).map_err(|_| VerifyError::Malformed)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| VerifyError::Signature)?;
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| VerifyError::Signature)?;

    // Only now is anything in the payload worth reading.
    let payload_bytes =
        Base64UrlUnpadded::decode_vec(encoded_payload).map_err(|_| VerifyError::Malformed)?;
    let claims: Claims =
        serde_json::from_slice(&payload_bytes).map_err(|_| VerifyError::BadPayload)?;

    if claims.iss != issuer {
        return Err(VerifyError::Issuer {
            got: claims.iss,
            want: issuer.to_owned(),
        });
    }
    // The check every hand-rolled verifier forgets: a token minted for
    // another venture is signed by the same issuer with the same key,
    // and is valid in every respect except that it is not ours.
    if claims.aud != audience {
        return Err(VerifyError::Audience {
            got: claims.aud,
            want: audience.to_owned(),
        });
    }
    if now - LEEWAY_SECS >= claims.exp {
        return Err(VerifyError::Expired);
    }
    if claims.iat - LEEWAY_SECS > now {
        return Err(VerifyError::NotYetValid);
    }
    Ok(claims)
}

/// The SHA-256 of a token, for logging a token without logging it.
#[must_use]
pub fn token_fingerprint(token: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().take(6).fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
