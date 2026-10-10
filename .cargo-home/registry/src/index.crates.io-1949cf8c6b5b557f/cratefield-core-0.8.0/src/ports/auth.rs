//! Who is making this request (issue #153).
//!
//! A module that serves a row belonging to somebody has to know who is
//! asking. Nothing in the harness could answer that: the verifier lives
//! in `cratefield-auth-client`, whose extractor needs `AuthState` in the
//! router state, and a module's state is an `Arc<ModuleContext>`. So a
//! module could check an admin token or nothing at all.
//!
//! This is the port that closes it. A deployment wires one; a module
//! declares [`Port::Auth`](super::Port::Auth) and gets it, and a module
//! that declares it cannot be composed into a deployment that has none —
//! which is the guarantee worth having. A venture declaring a table whose
//! access is `owner` composes a module that requires this port, so the
//! deployment refuses to boot rather than serving that table to everyone.
//!
//! # An unverified credential is not anonymity
//!
//! [`Auth::identify`] answers `Ok(Caller::Anonymous)` only when the
//! request carried no credential at all. A credential that was presented
//! and did not verify is an error, always, even for a route that would
//! have served an anonymous caller.
//!
//! The alternative — folding a bad token into "anonymous" — is a hole
//! with no floor. An expired token reading a `public-read` table would
//! succeed, so nothing would tell the caller their session had ended;
//! and the first handler written to fall back to anonymous on error
//! would hand anonymous access to anybody presenting a forged token. The
//! distinction has to survive as far as the handler, so it is in the
//! type.

use std::sync::Arc;

use async_trait::async_trait;
use http::HeaderMap;

/// The person a verified credential speaks for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Subject {
    /// The stable subject identifier — the value a table's privacy
    /// declaration names as its subject column matches against.
    pub id: String,
    /// The session behind the credential. A deployment that needs
    /// instant revocation asks the auth service about this id.
    pub session: String,
    /// Present only when the credential carried a verified address.
    pub email: Option<String>,
}

impl Subject {
    /// A subject with only an id, for a verifier that carries no more.
    ///
    /// Built rather than written as a literal because the struct is
    /// `#[non_exhaustive]`: an adapter outside this crate cannot name
    /// every field, which is what lets a later field be added without
    /// breaking every adapter. The builders are the way in.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            session: String::new(),
            email: None,
        }
    }

    /// The session behind the credential.
    #[must_use]
    pub fn session(mut self, session: impl Into<String>) -> Self {
        self.session = session.into();
        self
    }

    /// A **verified** address. A verifier that holds an unverified one
    /// passes `None`: an unverified address is a string the user typed,
    /// and a table matching on it would be matching on a claim its own
    /// subject controls.
    #[must_use]
    pub fn email(mut self, email: Option<String>) -> Self {
        self.email = email;
        self
    }
}

/// Who the request is from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Caller {
    /// No credential was presented. Not "a credential that failed" — see
    /// the module docs for why those must not be the same answer.
    Anonymous,
    /// A credential was presented and verified.
    Subject(Subject),
}

impl Caller {
    /// The subject, when there is one.
    #[must_use]
    pub fn subject(&self) -> Option<&Subject> {
        match self {
            Self::Subject(subject) => Some(subject),
            Self::Anonymous => None,
        }
    }

    /// The subject's id, when there is one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.subject().map(|subject| subject.id.as_str())
    }
}

/// Why a caller could not be identified.
///
/// Two cases and they are not the same refusal: one is the caller's
/// problem and one is the deployment's, so one is a 401 and the other a
/// 503. Collapsing them would tell a user to sign in again while the auth
/// service is down, and they would, and it would not help.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// A credential was presented and did not verify — malformed,
    /// expired, wrong audience, unknown key. One variant on purpose: each
    /// answer a caller can tell apart is a hint about how to get closer.
    NotVerified,
    /// The verifier could not be reached or could not answer.
    ///
    /// The message is an adapter's, so it can carry a connection URL
    /// with credentials in it, or an address. `Display` runs it through
    /// [`crate::logging::scrub_text`] for the reason `DbError` does
    /// (#135): "this never reaches a caller" is a promise about every
    /// call site rather than about this type, and four credential leaks
    /// in this codebase had exactly that shape. `Debug` keeps the raw
    /// string, and the logging formatters scrub `{:?}` too.
    Unavailable(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotVerified => f.write_str("the credential did not verify"),
            Self::Unavailable(detail) => write!(
                f,
                "the verifier could not answer: {}",
                crate::logging::scrub_text(detail)
            ),
        }
    }
}

impl std::error::Error for AuthError {}

/// Turns a request's headers into the caller they speak for.
///
/// Headers rather than an extractor so the port is object-safe and can be
/// exercised without an HTTP stack; the extractor is built on top.
#[async_trait]
pub trait Auth: Send + Sync {
    /// Identifies the caller.
    ///
    /// # Errors
    ///
    /// [`AuthError::NotVerified`] when a credential was presented and did
    /// not verify, and [`AuthError::Unavailable`] when the verifier could
    /// not answer. A request with no credential is
    /// `Ok(Caller::Anonymous)`, never an error.
    async fn identify(&self, headers: &HeaderMap) -> Result<Caller, AuthError>;
}

#[async_trait]
impl<T: Auth + ?Sized> Auth for Arc<T> {
    async fn identify(&self, headers: &HeaderMap) -> Result<Caller, AuthError> {
        (**self).identify(headers).await
    }
}

/// The verifier a deployment gets when it asked for one from the
/// environment and the environment did not have it.
///
/// A **provided port that verifies nothing**, the same shape
/// `push_from_env` uses for a push router with no transports configured:
/// on Workers the `Env` exists per request, so a runtime cannot know at
/// compose time whether the issuer is set, and refusing to provide the
/// port would make every such deployment fail to boot — including the
/// ones whose tables are all public and never need it.
///
/// What it answers is chosen so nothing reads as working:
///
/// - **no credential** is [`Caller::Anonymous`], so a `public-read` table
///   still serves and a deployment that only publishes is unaffected;
/// - **a credential** is [`AuthError::Unavailable`], never `NotVerified`
///   — the token may be perfectly good and nothing here can tell, so
///   saying it did not verify would be a claim this has not established.
///
/// A table whose access needs a caller therefore answers 401 to an
/// anonymous request and 503 to a signed-in one, and the boot warning
/// naming the missing variables is in the log either way.
pub struct Unconfigured {
    /// What is missing, for the log and for the 503's detail.
    why: String,
}

impl Unconfigured {
    /// A verifier that cannot verify, and says why.
    #[must_use]
    pub fn new(why: impl Into<String>) -> Self {
        Self { why: why.into() }
    }
}

#[async_trait]
impl Auth for Unconfigured {
    async fn identify(&self, headers: &HeaderMap) -> Result<Caller, AuthError> {
        if headers.get(http::header::AUTHORIZATION).is_none() {
            return Ok(Caller::Anonymous);
        }
        Err(AuthError::Unavailable(self.why.clone()))
    }
}
