//! One `origin_of`, so a Content-Security-Policy and a VAPID `aud` agree
//! on what an origin is (issue #215).
//!
//! There were two. The strict one — RFC 6454 via `url::Url::origin()` —
//! minted the `aud` of a VAPID token, where getting it wrong earns a `401`
//! from every push service that checks. The loose one split on `"://"` and
//! took everything up to the first `/`, and it was the one deciding which
//! origins a page may load stylesheets from.
//!
//! That asymmetry is the wrong way round. A CSP builder is exactly the
//! place where "close enough to an origin" stops being close enough:
//!
//! - any scheme before `://` was accepted, so a configured `theme_css` of
//!   `javascript://x/` produced a `style-src` entry a URL parser would
//!   have refused;
//! - userinfo was kept, so `https://a@evil.test/x` became
//!   `https://a@evil.test` — not an origin, and not what CSP matches;
//! - the port was not normalised, so `https://x:443` and `https://x` were
//!   two different entries for the same origin;
//! - the host was neither lowercased nor punycoded, so one differing only
//!   in case or encoding silently failed to match at render time.
//!
//! None of those was reachable from request input — `theme_css` is venture
//! configuration — which is why this was an issue rather than an incident.

/// Why a string is not an origin this harness will name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginError {
    /// Not a URL at all, with the parser's reason.
    NotAUrl(String),
    /// A scheme other than `http` or `https`.
    Scheme(String),
    /// A URL whose origin is opaque (`data:`, `blob:`, a `file:` URL):
    /// RFC 6454 gives it no tuple, and neither CSP nor a VAPID `aud` can
    /// name one.
    Opaque,
}

impl std::fmt::Display for OriginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAUrl(why) => write!(f, "{why}"),
            Self::Scheme(scheme) => write!(f, "scheme {scheme:?} is not http or https"),
            Self::Opaque => f.write_str("opaque origin"),
        }
    }
}

impl std::error::Error for OriginError {}

/// The RFC 6454 origin of `url`: scheme, host and non-default port, ASCII
/// serialized.
///
/// Never the path, the query, the fragment or the userinfo. The default
/// port is dropped and a non-default one kept, the host is lowercased and
/// punycoded, and an opaque origin is refused rather than guessed at —
/// all of which `url::Url::origin` does, and none of which string
/// splitting does.
///
/// `http` is allowed alongside `https` because a self-hosted UnifiedPush
/// distributor is routinely reached over plain HTTP on a private network,
/// and the Web Push adapter exists partly to serve that case. It is an
/// allowance, not an endorsement; `crates/adapter-webpush/src/vapid.rs`
/// carries the full argument for what travels in cleartext when it is
/// taken.
///
/// # Errors
///
/// [`OriginError`], one variant per way the string is not an origin.
pub fn origin_of(url: &str) -> Result<String, OriginError> {
    let parsed = url::Url::parse(url).map_err(|err| OriginError::NotAUrl(err.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(OriginError::Scheme(parsed.scheme().to_owned()));
    }
    let origin = parsed.origin();
    if !origin.is_tuple() {
        return Err(OriginError::Opaque);
    }
    Ok(origin.ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::{OriginError, origin_of};

    #[test]
    fn an_ordinary_url_keeps_its_origin_and_loses_everything_else() {
        assert_eq!(
            origin_of("https://cdn.example/theme/dark.css?v=2#top").unwrap(),
            "https://cdn.example"
        );
    }

    #[test]
    fn a_non_default_port_stays_and_a_default_one_goes() {
        // `https://x:443` and `https://x` are one origin; emitting both as
        // separate `style-src` entries is how a CSP quietly stops matching.
        assert_eq!(
            origin_of("https://x.example:443/a").unwrap(),
            "https://x.example"
        );
        assert_eq!(
            origin_of("http://x.example:80/a").unwrap(),
            "http://x.example"
        );
        assert_eq!(
            origin_of("https://x.example:8443/a").unwrap(),
            "https://x.example:8443"
        );
    }

    #[test]
    fn userinfo_never_reaches_the_output() {
        // The loose version produced `https://a@evil.test`, which is not an
        // origin and is not what a browser matches a stylesheet against.
        assert_eq!(
            origin_of("https://a:b@evil.test/x.css").unwrap(),
            "https://evil.test"
        );
    }

    #[test]
    fn the_host_is_lowercased_and_punycoded() {
        assert_eq!(
            origin_of("https://EXAMPLE.TEST/a").unwrap(),
            "https://example.test"
        );
        assert_eq!(
            origin_of("https://münchen.test/a").unwrap(),
            "https://xn--mnchen-3ya.test"
        );
    }

    #[test]
    fn a_scheme_that_is_not_http_is_refused() {
        // The one that mattered: the loose version accepted anything before
        // `://` and spliced it into `style-src`.
        assert_eq!(
            origin_of("javascript://x/"),
            Err(OriginError::Scheme("javascript".to_owned()))
        );
        assert!(matches!(
            origin_of("file:///etc/passwd"),
            Err(OriginError::Scheme(_))
        ));
    }

    #[test]
    fn an_opaque_origin_is_refused_rather_than_named() {
        assert!(matches!(
            origin_of("data:text/css,body{}"),
            Err(OriginError::Scheme(_) | OriginError::Opaque)
        ));
    }

    #[test]
    fn a_relative_url_is_not_an_origin() {
        assert!(matches!(
            origin_of("/theme.css"),
            Err(OriginError::NotAUrl(_))
        ));
        assert!(matches!(origin_of(""), Err(OriginError::NotAUrl(_))));
    }
}
