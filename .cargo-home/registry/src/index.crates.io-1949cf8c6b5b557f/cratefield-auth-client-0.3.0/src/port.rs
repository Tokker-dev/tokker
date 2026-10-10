//! [`AuthClient`] as the harness's [`Auth`] port (issue #153).
//!
//! The extractor in this crate needs `AuthState` in the router's state,
//! and a module's state is an `Arc<ModuleContext>` — so a module could
//! not use it, and a module serving somebody's rows had no way to learn
//! whose they were. Implementing the port is what makes this verifier
//! reachable from a module that declared `Port::Auth`.

use async_trait::async_trait;
use cratefield_core::{Auth, AuthError, Caller, Subject};
use http::HeaderMap;

use crate::jwks::AuthClient;
use crate::verify::token_fingerprint;

#[async_trait]
impl Auth for AuthClient {
    /// Identifies the caller from an `Authorization: Bearer` header.
    ///
    /// No header is [`Caller::Anonymous`]. A header that is present and
    /// does not verify is [`AuthError::NotVerified`] — never anonymity,
    /// which would let an expired token read a public table and tell its
    /// holder nothing was wrong.
    ///
    /// [`AuthError::Unavailable`] is never returned here, and that is a
    /// property of the verifier rather than an omission: a JWKS fetch
    /// that fails leaves the previously fetched keys in place, so an
    /// unreachable auth service does not invalidate a running app's
    /// sessions. The one case it cannot cover is a cold start that has
    /// never fetched a key set, where every token is an unknown key and
    /// so a refusal.
    async fn identify(&self, headers: &HeaderMap) -> Result<Caller, AuthError> {
        let Some(presented) = headers.get(http::header::AUTHORIZATION) else {
            return Ok(Caller::Anonymous);
        };
        let Some(token) = bearer(presented) else {
            // Present and not a bearer token: a different scheme, an
            // empty value, non-ASCII bytes. The caller meant to
            // authenticate and did not, which is a refusal — reading it
            // as anonymous would serve a public route to someone whose
            // credentials are broken and tell them nothing is wrong.
            tracing::info!("rejected an Authorization header that is not a bearer token");
            return Err(AuthError::NotVerified);
        };
        match self.verify(token).await {
            Ok(claims) => Ok(Caller::Subject(
                Subject::new(claims.sub).session(claims.sid).email(
                    // Only an address the issuer says it verified.
                    claims
                        .email
                        .filter(|_| claims.email_verified.unwrap_or(false)),
                ),
            )),
            Err(err) => {
                // The reason is logged and never returned, for the reason
                // the extractor gives: each answer a caller can tell apart
                // is a hint about how to get closer.
                tracing::info!(
                    reason = %err,
                    token = %token_fingerprint(token),
                    "rejected a bearer token"
                );
                Err(AuthError::NotVerified)
            }
        }
    }
}

/// The token inside an `Authorization: Bearer` value, if it is one.
///
/// `None` means the header is present and is not a bearer token, which
/// the caller turns into a refusal rather than into anonymity.
fn bearer(presented: &http::HeaderValue) -> Option<&str> {
    let value = presented.to_str().ok()?;
    let rest = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    (!rest.is_empty()).then_some(rest)
}
