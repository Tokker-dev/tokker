//! Email normalisation and validation shared by every module that stores an
//! address (issue #10: normalisation belongs in core, never module-to-module).
//!
//! [`normalize`] is trim, Unicode NFC, then lowercase; [`validate`] is a
//! deliberately conservative RFC-ish check with a 254-byte cap — it rejects
//! exotic-but-legal addresses rather than trying to accept every valid one.

use crate::problem::Problem;
use crate::problems::SLUGS;

/// The maximum accepted address length in bytes (RFC 5321 "forward-path").
pub const MAX_EMAIL_BYTES: usize = 254;

/// The maximum local-part length in bytes (RFC 5321).
pub const MAX_LOCAL_BYTES: usize = 64;

/// Trim, Unicode NFC normalise, then lowercase. Idempotent.
#[must_use]
pub fn normalize(email: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    email.trim().nfc().flat_map(char::to_lowercase).collect()
}

/// A conservative validator: non-empty, one `@`, sane lengths, an ASCII
/// local part from the unreserved set, and a dot-separated alphanumeric
/// domain with no empty or hyphen-edge labels.
#[must_use]
pub fn is_valid(email: &str) -> bool {
    validation_error(email).is_none()
}

/// The reason an address is rejected, for problem `detail`s.
#[must_use]
pub fn validation_error(email: &str) -> Option<&'static str> {
    if email.len() > MAX_EMAIL_BYTES {
        return Some("email is longer than 254 bytes");
    }
    let Some((local, domain)) = email.split_once('@') else {
        return Some("email must contain exactly one @");
    };
    if email.matches('@').count() != 1 {
        return Some("email must contain exactly one @");
    }
    if local.is_empty() {
        return Some("email local part is empty");
    }
    if local.len() > MAX_LOCAL_BYTES {
        return Some("email local part is longer than 64 bytes");
    }
    if !local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&b))
    {
        return Some("email local part contains unsupported characters");
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Some("email local part has a misplaced dot");
    }
    if domain.is_empty() {
        return Some("email domain is empty");
    }
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Some("email domain contains unsupported characters");
    }
    if !domain.contains('.') {
        return Some("email domain must contain at least one dot");
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Some("email domain has an empty label");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some("email domain label starts or ends with a hyphen");
        }
    }
    None
}

/// A `400 validation-failed` problem for a rejected address.
#[must_use]
pub fn invalid_email_problem(reason: &str) -> Problem {
    Problem::new(&SLUGS.validation_failed).with_detail(format!("email: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_folds_and_nfcs() {
        assert_eq!(normalize("  Nick@Example.COM "), "nick@example.com");
        // "é" as e + combining accent normalises to the single code point.
        assert_eq!(normalize("cafe\u{301}@example.com"), "café@example.com");
        assert_eq!(normalize(&normalize(" A@B.CO ")), "a@b.co");
    }

    #[test]
    fn accepts_plain_addresses() {
        for good in [
            "nick@example.com",
            "first.last+tag@sub.example.co",
            "a@b.cd",
            "o'brien@example.com",
        ] {
            assert_eq!(validation_error(good), None, "{good} must be valid");
        }
    }

    #[test]
    fn rejects_the_obvious() {
        for bad in [
            "",
            "no-at-sign",
            "two@ats@here",
            "@nodomain.com",
            "nolocal@",
            "no@dot",
            "no@empty..label",
            ".lead.dot@example.com",
            "trail.dot.@example.com",
            "two..dots@example.com",
            "sp ace@example.com",
            "ünïcode@example.com",
        ] {
            assert!(validation_error(bad).is_some(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn rejects_over_long_addresses() {
        let local = "a".repeat(65);
        assert!(validation_error(&format!("{local}@example.com")).is_some());
        let long = format!("{}@{}", "a".repeat(64), "b".repeat(240));
        assert!(validation_error(&long).is_some());
    }
}
