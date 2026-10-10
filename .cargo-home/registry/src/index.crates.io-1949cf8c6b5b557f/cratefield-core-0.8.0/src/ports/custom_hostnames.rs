//! The `CustomHostnames` port (issue #590): serving a venture on a hostname
//! the customer owns — `share.acme.com` `CNAMEd` at the venture. The venture
//! holds `Arc<dyn CustomHostnames>` and never learns that the provider
//! behind it is Cloudflare for `SaaS`; the claim, its certificate and the DNS
//! record the customer has to publish all travel as values from this
//! module.
//!
//! A hostname the provider will not serve is a **recorded failure**, not a
//! pending state: [`HostnameRefusal`] is checked before any request leaves
//! the process, exactly as the dashboard's domains screen records its own
//! refusals, and a provider that answers [`ProviderStatus::Failed`] says so
//! rather than leaving a claim that merely looks unfinished.
//!
//! Out of scope, named so the boundary reads as a decision: **apex
//! hostnames**. [`check_hostname`] refuses anything under three labels
//! because the flow hands the customer a `CNAME`, which an apex cannot
//! carry; Cloudflare's apex paths (Custom Nameservers, pre-validation) are
//! a product decision this port does not guess at.

use async_trait::async_trait;

/// How the provider proves the customer controls the hostname: over HTTP
/// (the provider fetches a token) or a `TXT` record the customer
/// publishes. Cloudflare for `SaaS` defaults to HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationMethod {
    #[default]
    Http,
    Txt,
}

impl ValidationMethod {
    /// The stable token recorded and sent to the provider.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Txt => "txt",
        }
    }
}

/// A hostname a customer wants served, and how they will prove they own
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameClaim {
    pub hostname: String,
    pub method: ValidationMethod,
}

impl HostnameClaim {
    /// A claim for `hostname`, validated over HTTP — the provider's
    /// default.
    #[must_use]
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            method: ValidationMethod::Http,
        }
    }

    /// The same claim, proved another way.
    #[must_use]
    pub fn with_method(mut self, method: ValidationMethod) -> Self {
        self.method = method;
        self
    }
}

/// The DNS record type a [`Validation`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    Txt,
    Cname,
}

impl DnsRecordType {
    /// The token as it is written into DNS.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Txt => "TXT",
            Self::Cname => "CNAME",
        }
    }
}

/// One DNS record the customer has to publish for validation — a `TXT`
/// pre-validation record (DCV), or a `CNAME` pointing the name here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    pub record_type: DnsRecordType,
    pub name: String,
    pub value: String,
}

/// The hostname's own state at the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    /// Registered; the customer's records have not been seen yet.
    Pending,
    /// Serving.
    Active,
    /// A step failed. `reason` is the provider's own wording, handed over
    /// by the adapter already scrubbed with [`crate::logging::scrub_text`].
    Failed { reason: String },
}

/// The edge certificate's state — separate from [`ProviderStatus`], since
/// a hostname can be validated while its certificate is still issuing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateStatus {
    /// Issuing.
    Pending,
    /// Issued and being served.
    Active,
    /// Issuance failed. `reason` is the provider's wording, handed over by
    /// the adapter already scrubbed with [`crate::logging::scrub_text`].
    Failed { reason: String },
}

/// A hostname as the provider sees it: its id, its state, its certificate
/// and the DNS records the customer must publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomHostname {
    pub id: String,
    pub hostname: String,
    pub status: ProviderStatus,
    pub certificate: CertificateStatus,
    pub validation: Vec<Validation>,
}

impl CustomHostname {
    /// Whether the name is actually serving: validated **and** holding an
    /// active certificate. Either half alone is not enough.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self.status, ProviderStatus::Active)
            && matches!(self.certificate, CertificateStatus::Active)
    }
}

/// Why a hostname was refused before it ever reached the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameRefusal {
    /// No name was given.
    Empty,
    /// Longer than the DNS wire limit of 253 characters.
    TooLong,
    /// Not a DNS name: a bad label, an empty label, a stray character.
    Malformed,
    /// An address literal, not a hostname a customer can point here.
    IpLiteral,
    /// `*.example.com`: the provider certifies one name at a time.
    Wildcard,
    /// An apex (`example.com`): the flow hands the customer a `CNAME`,
    /// which an apex cannot carry.
    Apex,
    /// Inside the deployment's own zone — the venture already answers
    /// here.
    OwnZone,
}

impl std::fmt::Display for HostnameRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("the hostname is empty"),
            Self::TooLong => f.write_str("the hostname is longer than 253 characters"),
            Self::Malformed => f.write_str("the hostname is not a valid DNS name"),
            Self::IpLiteral => {
                f.write_str("an IP address is not a hostname a customer can point here")
            }
            Self::Wildcard => f.write_str("wildcard hostnames are not supported"),
            Self::Apex => f.write_str("an apex hostname cannot serve a venture; claim a subdomain"),
            Self::OwnZone => f.write_str("that hostname is inside this deployment's own zone"),
        }
    }
}

/// Custom-hostname failures. Every variant that carries the provider's own
/// text is scrubbed in `Display` (issue #235), the same way
/// [`MailError`](crate::MailError)'s is; `Debug` stays raw for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomHostnameError {
    /// No zone or token is configured — answered before any request.
    NotConfigured,
    /// The hostname failed [`check_hostname`]; it was never sent to the
    /// provider.
    Refused(HostnameRefusal),
    /// The provider has no such hostname.
    NotFound,
    /// The hostname is already claimed at the provider.
    AlreadyExists,
    /// The token was rejected or lacks permission.
    Unauthorized,
    /// Too many requests; retry later.
    RateLimited,
    /// The provider refused the request (a 4xx with a message).
    Rejected(String),
    /// The provider failed on its side (a 5xx, an unparseable envelope).
    Provider(String),
    /// The request never got an answer: a socket, a DNS failure, a
    /// timeout.
    Transport(String),
}

impl std::fmt::Display for CustomHostnameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::NotConfigured => f.write_str("no custom-hostnames provider is configured"),
            Self::Refused(refusal) => write!(f, "hostname refused: {refusal}"),
            Self::NotFound => f.write_str("no such custom hostname at the provider"),
            Self::AlreadyExists => f.write_str("the hostname is already claimed at the provider"),
            Self::Unauthorized => f.write_str(
                "custom hostnames provider rejected the request as unauthorized \
                 (check the API token)",
            ),
            Self::RateLimited => f.write_str("custom hostnames provider rate limited the request"),
            Self::Rejected(message) => write!(
                f,
                "custom hostnames provider rejected the request: {}",
                scrub(message)
            ),
            Self::Provider(message) => {
                write!(f, "custom hostnames provider error: {}", scrub(message))
            }
            Self::Transport(message) => {
                write!(f, "custom hostnames transport error: {}", scrub(message))
            }
        }
    }
}

impl std::error::Error for CustomHostnameError {}

/// Claims, reads and releases custom hostnames at whichever provider the
/// venture wired.
#[async_trait]
pub trait CustomHostnames: Send + Sync {
    /// Claims `claim.hostname` with the provider and starts DV validation.
    ///
    /// # Errors
    /// [`CustomHostnameError::NotConfigured`] when no provider is wired;
    /// [`CustomHostnameError::Refused`] when the hostname fails
    /// [`check_hostname`]; [`CustomHostnameError::AlreadyExists`] when the
    /// name is already claimed; and the provider's own failures.
    async fn create(&self, claim: &HostnameClaim) -> Result<CustomHostname, CustomHostnameError>;

    /// Reads the claim; `Ok(None)` when the provider has no such hostname.
    ///
    /// # Errors
    /// [`CustomHostnameError::NotConfigured`], or the provider's own
    /// failures.
    async fn get(&self, hostname: &str) -> Result<Option<CustomHostname>, CustomHostnameError>;

    /// Releases the claim; deleting a hostname that is not there is `Ok`
    /// (idempotent).
    ///
    /// # Errors
    /// [`CustomHostnameError::NotConfigured`], or the provider's own
    /// failures.
    async fn delete(&self, hostname: &str) -> Result<(), CustomHostnameError>;

    /// Asks the provider to re-run validation now and returns the fresh
    /// state.
    ///
    /// # Errors
    /// [`CustomHostnameError::NotFound`] when the provider has no such
    /// hostname, [`CustomHostnameError::NotConfigured`], or the provider's
    /// own failures.
    async fn refresh(&self, hostname: &str) -> Result<CustomHostname, CustomHostnameError>;
}

/// Validation helper, called by adapters **before** any provider call:
/// normalises `hostname` (trimmed, lowercased, one trailing root dot
/// stripped) or says why it cannot serve.
///
/// The rules, in the order they bite: empty; longer than 253 characters; a
/// wildcard; an address literal; labels that are not `1..=63` characters
/// of `[a-z0-9-]` and neither empty nor hyphen-edged; a name inside
/// `own_zone`; and finally fewer than three labels.
///
/// The apex check counts labels and holds no public-suffix list, so
/// `acme.co.uk` — a registrable name with three labels — is not caught
/// here. The provider and the product decision own those.
///
/// # Errors
/// Every [`HostnameRefusal`], in the order above.
pub fn check_hostname(hostname: &str, own_zone: &str) -> Result<String, HostnameRefusal> {
    let trimmed = hostname.trim();
    let name = trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if name.is_empty() {
        return Err(HostnameRefusal::Empty);
    }
    if name.len() > 253 {
        return Err(HostnameRefusal::TooLong);
    }
    if name.contains('*') {
        return Err(HostnameRefusal::Wildcard);
    }
    // `[::1]` is the bracketed form a URL carries; the address is the same.
    let address = name
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(&name);
    if address.parse::<std::net::IpAddr>().is_ok() {
        return Err(HostnameRefusal::IpLiteral);
    }

    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(HostnameRefusal::Malformed);
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || !label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(HostnameRefusal::Malformed);
        }
    }

    let zone = own_zone
        .trim()
        .strip_suffix('.')
        .unwrap_or(own_zone.trim())
        .to_ascii_lowercase();
    if !zone.is_empty() && (name == zone || name.ends_with(&format!(".{zone}"))) {
        return Err(HostnameRefusal::OwnZone);
    }

    if labels.len() < 3 {
        return Err(HostnameRefusal::Apex);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_normalised_and_accepted() {
        assert_eq!(
            check_hostname("Share.Acme.COM.", "cratefield.app").as_deref(),
            Ok("share.acme.com")
        );
        assert_eq!(
            check_hostname("  share.acme.com  ", "cratefield.app").as_deref(),
            Ok("share.acme.com")
        );
    }

    #[test]
    fn an_apex_is_refused() {
        assert_eq!(
            check_hostname("acme.com", "cratefield.app"),
            Err(HostnameRefusal::Apex)
        );
    }

    #[test]
    fn addresses_are_refused() {
        for raw in ["192.0.2.1", "2001:db8::1", "[::1]"] {
            assert_eq!(
                check_hostname(raw, "cratefield.app"),
                Err(HostnameRefusal::IpLiteral),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_wildcard_is_refused() {
        assert_eq!(
            check_hostname("*.acme.com", "cratefield.app"),
            Err(HostnameRefusal::Wildcard)
        );
        assert_eq!(
            check_hostname("share.*.acme.com", "cratefield.app"),
            Err(HostnameRefusal::Wildcard)
        );
    }

    #[test]
    fn the_deployments_own_zone_is_refused() {
        assert_eq!(
            check_hostname("acme.com", "acme.com"),
            Err(HostnameRefusal::OwnZone),
            "the zone itself"
        );
        assert_eq!(
            check_hostname("share.acme.com", "acme.com"),
            Err(HostnameRefusal::OwnZone),
            "a subdomain of the zone"
        );
        assert_eq!(
            check_hostname("share.acme.com", "Acme.COM."),
            Err(HostnameRefusal::OwnZone),
            "the zone is normalised the same way"
        );
    }

    #[test]
    fn a_name_over_253_characters_is_refused() {
        let long = "a".repeat(254);
        assert_eq!(
            check_hostname(&long, "cratefield.app"),
            Err(HostnameRefusal::TooLong)
        );
    }

    #[test]
    fn malformed_names_are_refused() {
        for raw in [
            "-leading.acme.com",
            "share..acme.com",
            "share_acme.acme.com",
            "",
        ] {
            assert!(
                matches!(
                    check_hostname(raw, "cratefield.app"),
                    Err(HostnameRefusal::Malformed | HostnameRefusal::Empty)
                ),
                "{raw:?}"
            );
        }
        assert_eq!(
            check_hostname("share.acme.com.", "cratefield.app").as_deref(),
            Ok("share.acme.com"),
            "a trailing root dot is the same name, not an empty label"
        );
    }

    #[test]
    fn display_never_leaks_a_bearer_token() {
        // A provider body echoing the request's credential must not reach
        // a log line or a problem detail through `Display`.
        let error = CustomHostnameError::Provider(
            "the provider said Bearer abcdefgh1234 is not a valid token".to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains("abcdefgh1234"), "{text}");
        assert!(text.contains("Bearer [redacted]"), "{text}");
        // `Debug` keeps the raw text for tests.
        assert!(format!("{error:?}").contains("abcdefgh1234"));
    }
}
