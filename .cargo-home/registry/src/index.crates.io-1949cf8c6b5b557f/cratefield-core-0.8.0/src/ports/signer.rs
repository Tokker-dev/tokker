//! The `Signer` port and the signed-token payload (ADR 0006, amended by
//! ADR 0014). The HMAC reference implementation — a bounded key ring with
//! explicit signing / verification-only / revoked states — lives in
//! `cratefield-core::signer` (issue #3, issue #137).

/// Which key in the [`crate::KeyRing`] a token was signed with. Tokens
/// name their key so rotation never breaks links in flight.
///
/// The two positional names are what the environment-derived runtimes
/// wire (`HARNESS_SECRET` is `Cur`, `HARNESS_SECRET_PREVIOUS` is `Prev`);
/// legacy tokens from the flat current/previous scheme carry exactly these
/// names (issue #137). A ring built programmatically can give its keys
/// stable [`Kid::Named`] labels instead, so an entry keeps its identity as
/// it moves from signing to verification-only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kid {
    /// The current signing key.
    Cur,
    /// The previous key (verification-only unless explicitly revoked).
    Prev,
    /// A stable, operator-chosen key label (kebab-case or short slug; the
    /// reference signer caps the wire form at [`MAX_KID_NAME`] characters).
    Named(String),
}

impl Kid {
    /// A stable operator-chosen key id for a programmatically built ring.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named(name.into())
    }
}

/// The longest accepted `Kid::Named` wire name. Key ids ride inside every
/// token; the bound keeps a hostile payload from claiming arbitrary
/// storage.
pub const MAX_KID_NAME: usize = 32;

/// The signed payload: `{ purpose, subject, exp?, kid }`.
///
/// `purpose` scopes a token to one use (`email-signup.confirm`,
/// `waitlist.status`, ...) and must be module-qualified: the module part
/// *is* the module binding (ADR 0014, issue #137) — a token minted by one
/// module can never verify for another because the full purpose is
/// compared. `exp` is a Unix timestamp in seconds. Every purpose carries
/// an explicit lifetime: the reference signer clamps over-long or missing
/// expiries to its [`crate::TokenPolicy`] (issue #137), so a non-expiring
/// token is a deliberate policy decision, never an omission. Venture and
/// environment binding is stamped and enforced by the signer itself, not
/// carried here: modules hand the same payload shape to every runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub purpose: String,
    pub subject: String,
    pub exp: Option<u64>,
    pub kid: Kid,
}

/// Failures surfaced by `verify` beyond "the token is simply invalid",
/// which is reported as `None`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("token payload is not valid UTF-8/JSON")]
    Malformed,
    #[error("token is expired")]
    Expired,
    #[error("token purpose {actual:?} does not match expected {expected:?}")]
    WrongPurpose { actual: String, expected: String },
    #[error("token was minted for another venture or environment (issue #137)")]
    WrongScope,
    #[error("token names a revoked key (issue #137)")]
    RevokedKey,
}

/// Produces and verifies `base64url(json).base64url(mac)` tokens where the
/// MAC is computed over the **encoded** payload string, so a token has
/// exactly one valid encoding (ADR 0006).
///
/// The reference implementation keeps a bounded ring of keys (ADR 0014,
/// issue #137): one in the *signing* state, any number in
/// *verification-only*, and revoked keys whose tokens are refused.
/// Verification tries every live key's MAC in constant time; a token
/// naming a revoked key, minted for another venture/environment binding,
/// expired past its policy lifetime, or carrying the wrong purpose
/// verifies as `None`.
pub trait Signer: Send + Sync {
    fn sign(&self, payload: &Payload) -> String;
    /// `None` for malformed input, tampering, expiry, wrong purpose, a
    /// revoked key id, or a venture/environment binding mismatch; never
    /// panics on malformed input.
    fn verify(&self, token: &str, expected_purpose: &str) -> Option<Payload>;
}
