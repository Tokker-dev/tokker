//! Admin endpoint authentication (architecture section 11, issue #13 —
//! landed with issue #10 because the first admin endpoint needs it).
//!
//! `ADMIN_TOKEN` is read from the [`Config`] (a Workers secret in
//! production). While it is unset, every admin route is **disabled** and
//! answers `401 admin-unauthorized`. A presented-but-wrong token is `403`.
//! Comparison digests both sides with SHA-256 first so the `subtle`
//! constant-time compare runs over fixed-length buffers regardless of the
//! presented length, and the token never appears in tracing fields.

use axum::http::{HeaderMap, header};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::problem::Problem;
use crate::problems::SLUGS;

/// Extracts the bearer token from `Authorization: Bearer <token>`.
#[must_use]
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let rest = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    if rest.is_empty() { None } else { Some(rest) }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Constant-time equality of two secrets, via fixed-length digests so
/// timing does not leak the configured token's length.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(sha256(a).ct_eq(&sha256(b)))
}

/// Checks `Authorization: Bearer <ADMIN_TOKEN>` for one admin request.
///
/// - `ADMIN_TOKEN` unset → `Err(401 admin-unauthorized)`: the route is
///   disabled, same answer as a missing header, so probing cannot tell
///   whether admin is switched on.
/// - Missing/malformed header → `Err(401 admin-unauthorized)`.
/// - Wrong token → `Err(403 admin-forbidden)`.
///
/// # Errors
///
/// The [`Problem`] described above; carry it straight into the handler's
/// `Err`.
pub fn require_admin(config: &dyn Config, headers: &HeaderMap) -> Result<(), Problem> {
    let Some(configured) = config.get("ADMIN_TOKEN").filter(|token| !token.is_empty()) else {
        return Err(Problem::new(&SLUGS.admin_unauthorized));
    };
    let Some(presented) = bearer_token(headers) else {
        return Err(Problem::new(&SLUGS.admin_unauthorized));
    };
    if constant_time_eq(presented.as_bytes(), configured.as_bytes()) {
        Ok(())
    } else {
        Err(Problem::new(&SLUGS.admin_forbidden))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MapConfig;

    fn headers(token: Option<&str>) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Some(token) = token {
            map.insert(
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&format!("Bearer {token}")).expect("header builds"),
            );
        }
        map
    }

    fn config(token: Option<&str>) -> MapConfig {
        MapConfig::from_pairs(token.map(|t| ("ADMIN_TOKEN", t)))
    }

    // A dummy, never-real token: obviously fake, long enough to be realistic.
    const DUMMY: &str = "test-admin-token-0123456789abcdef";

    #[test]
    fn unset_token_disables_admin() {
        let err = require_admin(&config(None), &headers(Some(DUMMY))).expect_err("disabled");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.slug, "admin-unauthorized");
    }

    #[test]
    fn missing_header_is_unauthorized() {
        let err = require_admin(&config(Some(DUMMY)), &headers(None)).expect_err("no header");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn wrong_token_is_forbidden() {
        let err =
            require_admin(&config(Some(DUMMY)), &headers(Some("wrong"))).expect_err("wrong token");
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(err.slug, "admin-forbidden");
    }

    #[test]
    fn correct_token_passes() {
        require_admin(&config(Some(DUMMY)), &headers(Some(DUMMY))).expect("authorized");
    }

    #[test]
    fn empty_bearer_is_unauthorized() {
        let mut map = HeaderMap::new();
        map.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer "),
        );
        let err = require_admin(&config(Some(DUMMY)), &map).expect_err("empty bearer");
        assert_eq!(err.status, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdef-longer"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
    }
}
