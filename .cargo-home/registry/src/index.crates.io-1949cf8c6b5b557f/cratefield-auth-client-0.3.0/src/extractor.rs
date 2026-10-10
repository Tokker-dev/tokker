//! The axum extractor a consuming app's handlers use.
//!
//! A handler that takes [`Authenticated`] cannot run for an unverified
//! request: there is no way to obtain the claims except through
//! verification. That is the point — it makes "did I remember to check
//! the token here?" a question the compiler answers.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use cratefield_core::Problem;

use crate::jwks::AuthClient;
use crate::verify::{Claims, token_fingerprint};

/// Router state carrying the verifier.
///
/// A consuming app either uses this as its state or implements
/// `FromRef` so the extractor can reach the client.
#[derive(Clone)]
pub struct AuthState(pub Arc<AuthClient>);

/// A verified caller.
///
/// ```ignore
/// async fn me(Authenticated(claims): Authenticated) -> String {
///     claims.sub
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Authenticated(pub Claims);

impl<S> FromRequestParts<S> for Authenticated
where
    AuthState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthState(client) = axum::extract::FromRef::from_ref(state);
        let token = bearer(parts).ok_or_else(unauthorized)?;
        match client.verify(token).await {
            Ok(claims) => Ok(Self(claims)),
            Err(err) => {
                // The reason is logged, never returned: telling a caller
                // which check failed tells them how to get closer.
                tracing::info!(
                    reason = %err,
                    token = %token_fingerprint(token),
                    "rejected a bearer token"
                );
                Err(unauthorized())
            }
        }
    }
}

/// The `Authorization: Bearer` value, if the header is well formed.
fn bearer(parts: &Parts) -> Option<&str> {
    let value = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let rest = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    (!rest.is_empty()).then_some(rest)
}

/// The one refusal this crate ever returns.
///
/// Missing header, malformed token, unknown key, wrong audience,
/// expired: all the same. A caller learns that it is not authenticated
/// and nothing else, because each distinguishable answer is a hint
/// about how to get closer.
pub const UNAUTHENTICATED: cratefield_core::ProblemDef = cratefield_core::SLUGS.unauthenticated;

fn unauthorized() -> Problem {
    Problem::new(&UNAUTHENTICATED)
}
