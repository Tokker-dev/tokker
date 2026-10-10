//! The `Mailer` port (architecture section 5). The Resend adapter is the
//! reference implementation (issue #6).

use async_trait::async_trait;
use std::time::Duration;

/// An outbound mail. `text` is always sent alongside `html`.
///
/// `#[non_exhaustive]`: build one with [`Message::new`] and the builder
/// methods rather than a struct literal. A channel that has to set a
/// header — RFC 8058 one-click unsubscribe, say — should not be a
/// breaking change for every other caller, and before this it was.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Message {
    pub to: String,
    pub from: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub html: String,
    pub text: String,
    /// Passed through as an `Idempotency-Key` where the provider supports it.
    pub idempotency_key: Option<String>,
    pub tags: Vec<String>,
    /// Extra RFC 5322 headers, in order.
    ///
    /// For headers the shape of `Message` does not name and should not:
    /// `List-Unsubscribe` and `List-Unsubscribe-Post` are the reason this
    /// exists, because Gmail and Yahoo have required one-click
    /// unsubscribe of bulk senders since 2024. An adapter that cannot
    /// send custom headers must say so rather than drop them silently.
    pub headers: Vec<(String, String)>,
}

impl Message {
    /// The five parts every mail has. Everything else is a builder method.
    #[must_use]
    pub fn new(
        to: impl Into<String>,
        from: impl Into<String>,
        subject: impl Into<String>,
        text: impl Into<String>,
        html: impl Into<String>,
    ) -> Self {
        Self {
            to: to.into(),
            from: from.into(),
            reply_to: None,
            subject: subject.into(),
            html: html.into(),
            text: text.into(),
            idempotency_key: None,
            tags: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Where a reply goes, when it is not `from`.
    #[must_use]
    pub fn reply_to(mut self, address: impl Into<String>) -> Self {
        self.reply_to = Some(address.into());
        self
    }

    /// The key a provider that supports it uses to collapse a retry.
    #[must_use]
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Labels for the provider's own reporting.
    #[must_use]
    pub fn tags<I, T>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// One extra RFC 5322 header. Repeatable; order is preserved.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Result of a send attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Sent; carries the provider message id.
    Sent { id: String },
    /// The adapter is not configured (no API key / unverified sending
    /// domain). The endpoint reports `503 mail-not-configured` so forms can
    /// degrade instead of breaking.
    NotConfigured,
}

/// Mailer failures, mapped by the adapter from provider responses.
///
/// Every variant that carries provider text is sanitized in `Display`,
/// the same way [`DbError`](crate::DbError)'s is (issue #235). "Never
/// includes the API key" was too weak a promise: the text an adapter
/// wraps is the provider's own response, and a `422` from Resend quotes
/// the field it objected to — which for a send is the **recipient
/// address**. `Display` therefore runs it through
/// [`crate::logging::scrub_text`], so every `tracing` field, problem
/// detail, report line and `format!` that renders a `MailError` gets the
/// sanitized text rather than each call site remembering to. `Debug`
/// still shows the raw string for tests; the logging formatters scrub
/// `{:?}` output too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailError {
    /// The API key is missing, wrong or revoked.
    Unauthorized,
    /// The sending domain is not verified with the provider, so nothing
    /// from it will be accepted until somebody adds the DNS records.
    DomainNotVerified { domain: String },
    /// The provider refused the message itself. `detail` is **its**
    /// wording, so it can quote the recipient — see the type docs.
    Invalid { detail: String },
    /// Too many sends; retry no earlier than `retry_after` when the
    /// provider named one.
    RateLimited { retry_after: Option<Duration> },
    /// The provider failed on its side (a `5xx`, an unparseable body).
    Upstream(String),
    /// The request never got an answer: a socket, a DNS failure, a
    /// timeout.
    Transport(String),
}

impl std::fmt::Display for MailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::Unauthorized => {
                f.write_str("mailer rejected the request as unauthorized (check the API key)")
            }
            Self::DomainNotVerified { domain } => write!(
                f,
                "sending domain {:?} is not verified with the mailer",
                scrub(domain)
            ),
            Self::Invalid { detail } => {
                write!(
                    f,
                    "mailer rejected the message as invalid: {}",
                    scrub(detail)
                )
            }
            Self::RateLimited { retry_after } => write!(
                f,
                "mailer rate limited the request; retry after {retry_after:?}"
            ),
            Self::Upstream(message) => write!(f, "mailer upstream error: {}", scrub(message)),
            Self::Transport(message) => write!(f, "mailer transport error: {}", scrub(message)),
        }
    }
}

impl std::error::Error for MailError {}

#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, message: Message) -> Result<SendOutcome, MailError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_sanitizes_the_provider_text() {
        // The finding (issue #235): `Invalid { detail }` is set from the
        // provider's own response — and Resend's 422 quotes the field it
        // objected to, which for a send is the recipient address. The
        // adapter's fallback is `body.to_string()`, the whole body.
        let error = MailError::Invalid {
            detail: "validation_error: `to` must be a valid address: alice@example.test".to_owned(),
        };
        let text = error.to_string();
        assert!(!text.contains('@'), "{text}");
        assert!(!text.contains("alice"), "{text}");
        assert!(text.contains("[subject_hash:"), "{text}");

        // An upstream body echoing the request URL must not disclose the
        // query it carried.
        let error = MailError::Upstream(
            "POST https://api.resend.com/emails?key=live-abcdef failed".to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains("live-abcdef"), "{text}");
        assert!(text.contains("?[redacted]"), "{text}");

        // The variants with nothing to hide read exactly as before.
        assert_eq!(
            MailError::Unauthorized.to_string(),
            "mailer rejected the request as unauthorized (check the API key)"
        );
        assert_eq!(
            MailError::RateLimited { retry_after: None }.to_string(),
            "mailer rate limited the request; retry after None"
        );

        // `Debug` still shows the raw string, which is what a failing
        // test needs to be readable; the log formatters scrub `{:?}` too.
        assert!(format!("{error:?}").contains("live-abcdef"));
    }

    #[test]
    fn a_domain_that_is_an_address_is_still_scrubbed() {
        // `DomainNotVerified` looks safe — a sending domain is not
        // personal data — but adapters set it from whatever the provider
        // named, and Resend names the whole `from` when it objects.
        let error = MailError::DomainNotVerified {
            domain: "no-reply@send.example.test".to_owned(),
        };
        let text = error.to_string();
        assert!(!text.contains('@'), "{text}");
        assert!(text.contains("[subject_hash:"), "{text}");
    }
}
