//! The `Captcha` port. The Turnstile adapter is the reference
//! implementation (issue #7).

use async_trait::async_trait;
use thiserror::Error;

/// A captcha verification verdict. `ok: false` with a `reason` from the
/// provider's `error-codes`; transport-level unavailability surfaces as
/// `ok: false, reason: "unavailable"` unless the adapter is configured
/// fail-open (staging only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub ok: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Error)]
pub enum CaptchaError {
    #[error("captcha transport error: {0}")]
    Transport(String),
}

/// What a captcha adapter is actually bound to (issue #133). The harness
/// reads this at build time to decide whether a production venture's
/// [`HumanForm`] routes can really be verified — providing the port is
/// not the same as configuring it.
///
/// [`HumanForm`]: crate::route_policy::RoutePolicy::HumanForm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptchaBinding {
    /// Response hostnames are checked against the venture's own host.
    /// Without this, a token minted on any site using the same widget
    /// verifies here (Turnstile's hostname check is the site's job).
    pub hostname_bound: bool,
    /// The expected Turnstile `action` is configured and checked, so a
    /// widget embedded for some other flow on the same site does not
    /// authorize this one.
    pub action_bound: bool,
    /// Transport failures verify as OK. A staging-only posture: an
    /// adapter left fail-open cannot support a production form write.
    pub fail_open: bool,
}

#[async_trait]
pub trait Captcha: Send + Sync {
    async fn verify(&self, token: &str, remote_ip: Option<&str>) -> Result<Verdict, CaptchaError>;
    /// What this adapter is bound to, as far as it can say. `None` (the
    /// default) means the adapter does not report: the harness treats it
    /// as effective when the port is present, and the adapter carries the
    /// duty to fail closed per request. Adapters that *can* report should
    /// override this so `HarnessBuilder::build` can refuse a production
    /// venture that would boot with verification silently unavailable.
    #[must_use]
    fn binding(&self) -> Option<CaptchaBinding> {
        None
    }
}
