//! The `Push` port (issues #104, #177): a notification to a device, whatever
//! carries it. Mail reaches an inbox through [`Mailer`](crate::Mailer);
//! nothing else reached a device until this. APNs today, FCM and Web Push
//! next (ADR 0015).
//!
//! A recipient is a [`Recipient`], not a token string: a Web Push
//! subscription is `{ endpoint, p256dh, auth }` and never fits in one opaque
//! string, and JSON-in-a-string would make every adapter parse and every
//! mistake silent. [`Notification`] is transport-neutral — each adapter maps
//! the fields its protocol has and documents what it drops.
//!
//! The device-token registry is venture code — each venture decides what a
//! recipient belongs to — but the port defines the [`PushError::Unregistered`]
//! contract so a module knows when to prune a dead one.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The transport a [`Recipient`] is reached over, which is **not** a
/// statement about the device: a UnifiedPush endpoint is
/// [`Platform::Web`] on an Android phone (ADR 0015).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Apple Push Notification service.
    Ios,
    /// Firebase Cloud Messaging.
    Android,
    /// Web Push (RFC 8030), browser or UnifiedPush.
    Web,
}

impl Platform {
    /// The name used in errors and logs.
    pub fn name(&self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
            Platform::Web => "web",
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a notification is sent. One variant per push transport, because the
/// three do not share a shape: APNs and FCM take an opaque token, Web Push
/// takes a subscription of three parts (RFC 8291).
///
/// **Every variant holds credential material.** A device token and an FCM
/// registration token address one device; a Web Push `endpoint` is a bearer
/// capability URL (whoever holds it can push to that browser) and `auth` is
/// the RFC 8291 shared secret the payload is encrypted under. Hence the
/// hand-written [`Debug`](#impl-Debug-for-Recipient), which prints
/// fingerprints and never the values: core's log redaction keys off the
/// *field name* ([`is_secret_field`](crate::is_secret_field)) and cannot see
/// inside a `{:?}` of this enum.
///
/// [`Serialize`]/[`Deserialize`] stay, because a subscription has to be
/// persisted and read back — but a serialised `Recipient` **is** the
/// credential: store it where secrets go, never in a log, an event payload,
/// or an error body.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recipient {
    /// An APNs device token (hex, from `application:didRegister...`).
    Apns { device_token: String },
    /// An FCM registration token.
    Fcm { registration_token: String },
    /// A Web Push subscription: the push service URL plus the two RFC 8291
    /// keys, both base64url as the browser hands them over.
    WebPush {
        endpoint: String,
        p256dh: String,
        auth: String,
    },
}

impl Recipient {
    /// An APNs recipient.
    pub fn apns(device_token: impl Into<String>) -> Self {
        Recipient::Apns {
            device_token: device_token.into(),
        }
    }

    /// An FCM recipient.
    pub fn fcm(registration_token: impl Into<String>) -> Self {
        Recipient::Fcm {
            registration_token: registration_token.into(),
        }
    }

    /// A Web Push recipient (RFC 8291 keys, base64url).
    pub fn web_push(
        endpoint: impl Into<String>,
        p256dh: impl Into<String>,
        auth: impl Into<String>,
    ) -> Self {
        Recipient::WebPush {
            endpoint: endpoint.into(),
            p256dh: p256dh.into(),
            auth: auth.into(),
        }
    }

    /// The transport this recipient is reached over. A *transport* fact, not
    /// a device fact (ADR 0015).
    pub fn platform(&self) -> Platform {
        match self {
            Recipient::Apns { .. } => Platform::Ios,
            Recipient::Fcm { .. } => Platform::Android,
            Recipient::WebPush { .. } => Platform::Web,
        }
    }
}

/// A short, non-reversible stand-in for credential material in `Debug`
/// output: the first six bytes of its SHA-256, hex. Enough to tell two log
/// lines about the same recipient apart, useless for reaching a device — the
/// inputs (a 32-byte device token, a random endpoint path, a 16-byte auth
/// secret) have far too much entropy to guess back through a digest.
fn fingerprint(value: &str) -> String {
    use sha2::{Digest as _, Sha256};
    use std::fmt::Write as _;

    let digest = Sha256::digest(value.as_bytes());
    let mut hex = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Prints the transport and a short fingerprint of each part, never the parts
/// themselves — the same rule `Es256Signer`, `Rs256Signer` and `CachedToken`
/// follow in `cratefield-push-auth`. The RFC 8291 `auth` secret is not even
/// fingerprinted: nothing about it is safe to correlate on.
impl std::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Recipient::Apns { device_token } => write!(
                f,
                "Recipient::Apns {{ device_token: fp:{} }}",
                fingerprint(device_token)
            ),
            Recipient::Fcm { registration_token } => write!(
                f,
                "Recipient::Fcm {{ registration_token: fp:{} }}",
                fingerprint(registration_token)
            ),
            // The endpoint is fingerprinted whole, host included: a
            // self-hosted UnifiedPush host is itself identifying.
            Recipient::WebPush {
                endpoint, p256dh, ..
            } => write!(
                f,
                "Recipient::WebPush {{ endpoint: fp:{}, p256dh: fp:{}, auth: [redacted] }}",
                fingerprint(endpoint),
                fingerprint(p256dh)
            ),
        }
    }
}

/// How urgently the notification should be delivered. Maps to APNs priority
/// `10` (deliver now, may wake the device) and `5` (deliver to save power);
/// to `android.priority` `HIGH`/`NORMAL`; to the Web Push `Urgency` header
/// `high`/`normal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Deliver immediately.
    #[default]
    Immediate,
    /// Deliver when convenient, to conserve power.
    Conserve,
}

/// Native localisation keys. The strings are looked up in the app's own
/// catalogue by the operating system, so a notification can be localised
/// without the server knowing the device's language. Reserved here and
/// mapped by the adapters; rendering is the i18n child's job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocKeys {
    /// Key for the title (`aps.alert.title-loc-key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_loc_key: Option<String>,
    /// Substitutions for the title key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub title_loc_args: Vec<String>,
    /// Key for the body (`aps.alert.loc-key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_loc_key: Option<String>,
    /// Substitutions for the body key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_loc_args: Vec<String>,
}

/// One notification, in transport-neutral terms. `data` is the custom
/// key-value payload the app reads; `collapse_id` coalesces notifications the
/// user has not seen yet.
///
/// Every optional field is a *request*: an adapter maps what its protocol
/// has and documents what it drops (APNs has no `icon`, Web Push has no
/// `badge`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub title: String,
    pub body: String,
    /// The notification category (an app-defined action group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Groups related notifications in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    /// Custom payload the app reads; merged alongside the `aps` block.
    #[serde(default)]
    pub data: Value,
    /// Coalesces with any undelivered notification carrying the same id.
    /// `apns-collapse-id` / `android.collapse_key` / the Web Push `Topic`
    /// header (≤32 URL-safe characters, so a Web Push adapter shortens it
    /// and documents how).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapse_id: Option<String>,
    #[serde(default)]
    pub priority: Priority,
    /// An icon for the notification (Web Push `icon`; ignored by APNs, which
    /// takes its icon from the app bundle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// Where a tap should take the user: the Web Push click target, FCM's
    /// `click_action`, and a top-level `url` in the APNs payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How long the push service may hold the notification while the device
    /// is offline. Serialised as whole seconds, through [`ttl_secs`].
    ///
    /// Note the wire forms differ: `apns-expiration` is an **absolute** UNIX
    /// epoch, so the APNs adapter sends `now + ttl`; `android.ttl` is
    /// `"<s>s"`; Web Push `TTL` is seconds. A zero TTL means "deliver now or
    /// drop" in all three.
    ///
    /// **Sub-second TTLs round up to one second**, on the wire and in every
    /// adapter: `Duration::from_millis(900)` is a request to hold the
    /// notification *briefly*, and truncating it to `0` would turn it into
    /// the opposite instruction — drop it the moment the device is offline —
    /// silently, and again on every serde round trip. Only
    /// `Duration::ZERO` means "drop if undeliverable now".
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "duration_secs"
    )]
    pub ttl: Option<Duration>,
    /// The badge number to show on the app icon (iOS). Ignored elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub badge: Option<u32>,
    /// A data-only notification: nothing is shown, the app is woken to do
    /// work (`content-available` / FCM data message).
    #[serde(default, skip_serializing_if = "is_false")]
    pub silent: bool,
    /// Native localisation keys, in place of `title`/`body`, where the
    /// platform supports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loc: Option<LocKeys>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if shape
fn is_false(value: &bool) -> bool {
    !*value
}

/// A [`Notification::ttl`] as the whole seconds every push protocol takes.
///
/// A non-zero TTL shorter than a second rounds **up** to one. Truncating it
/// would say "deliver now or drop" — the opposite of what a caller asking
/// for 900 ms meant — and would do so silently, including across a serde
/// round trip, which is why the rounding lives here and is applied by the
/// serialiser as well as by each adapter. `Duration::ZERO` is left alone:
/// that one really does mean "drop if undeliverable now".
#[must_use]
pub fn ttl_secs(ttl: Duration) -> u64 {
    match ttl.as_secs() {
        0 if !ttl.is_zero() => 1,
        secs => secs,
    }
}

/// The header name, so no caller spells it.
const RETRY_AFTER: &str = "retry-after";

/// The IMF-fixdate description, parsed once.
///
/// Version 2 of the format-description syntax, pinned explicitly: `parse`
/// without a version is deprecated precisely because the unversioned
/// form's meaning can shift under a `time` upgrade.
///
/// Built once rather than per call. `Retry-After` is read on the
/// throttling path, which by definition fires in bursts, so re-parsing a
/// fixed description on every throttled send is work done once per process
/// here instead.
static IMF_FIXDATE: std::sync::LazyLock<
    Vec<time::format_description::BorrowedFormatItem<'static>>,
> = std::sync::LazyLock::new(|| {
    time::format_description::parse_borrowed::<2>(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT",
    )
    .expect("a format description that is a literal in this file")
});

/// An IMF-fixdate, the one form RFC 9110 §5.6.7 allows a sender to
/// generate: `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// The two obsolete forms (RFC 850 and asctime) are deliberately not
/// parsed. A recipient is required to accept them, but nothing in front of
/// a push service or a mail API emits them, and mis-reading a two-digit
/// year is worse than falling back to the caller's own schedule.
fn parse_http_date(value: &str) -> Option<time::OffsetDateTime> {
    time::PrimitiveDateTime::parse(value, IMF_FIXDATE.as_slice())
        .ok()
        .map(time::PrimitiveDateTime::assume_utc)
}

/// `Retry-After` (RFC 9110 §10.2.3) as a duration, so a caller can honour
/// what a provider asked for.
///
/// **Both forms are read**, which is the point of it living here. The
/// delta-seconds form is the common one; the HTTP-date form is equally
/// legal and is what CDNs in front of a provider emit. Ignoring the date
/// form turns "come back in an hour" into an immediate retry, straight
/// back into the rate limiter that sent it.
///
/// This replaces four independent parsers — APNs, Resend, the LinkedIn
/// client and Web Push — of which only the last read the date form, so the
/// bug was live in three (issue #214). The APNs copy's own comment said
/// the date form "needs a parsed clock the port does not promise";
/// [`Clock`](crate::Clock)
/// is a port every one of those callers already holds, which is what makes
/// one parser possible.
///
/// A date already in the past is [`Duration::ZERO`] — "retry now" — and
/// not `None`. The two mean different things to a caller: `None` is "no
/// delay was stated", and falling back to a default schedule for a header
/// that said "now" would be slower than the provider asked for.
///
/// Returns `None` when the header is absent, unreadable, or in neither
/// form.
#[must_use]
pub fn retry_after(headers: &http::HeaderMap, clock: &dyn crate::Clock) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let when = parse_http_date(value)?;
    let delta = when - clock.now();
    if delta.is_negative() {
        return Some(Duration::ZERO);
    }
    Duration::try_from(delta).ok()
}

/// `Option<Duration>` on the wire as whole seconds, so a notification
/// round-trips as `{"ttl": 3600}` and not serde's `{"secs":…,"nanos":…}`.
mod duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    // serde's `with` module fixes this signature; `Option<&Duration>` does
    // not compile as a serializer here.
    #[allow(clippy::ref_option)]
    pub(crate) fn serialize<S: Serializer>(
        value: &Option<Duration>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            // `ttl_secs`, not `as_secs`: a sub-second TTL must not round-trip
            // into `Duration::ZERO`, which means the opposite thing.
            Some(duration) => serializer.serialize_some(&super::ttl_secs(*duration)),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Duration>, D::Error> {
        Ok(Option::<u64>::deserialize(deserializer)?.map(Duration::from_secs))
    }
}

impl Notification {
    /// A minimal notification with a title and body.
    #[must_use]
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            category: None,
            thread_id: None,
            data: Value::Null,
            collapse_id: None,
            priority: Priority::Immediate,
            icon: None,
            url: None,
            ttl: None,
            badge: None,
            silent: false,
            loc: None,
        }
    }
}

/// The result of a send that the provider accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Accepted; carries the provider's id where it gives one (`apns-id`).
    Delivered { id: Option<String> },
    /// The adapter is not configured (no key / unverified). The caller can
    /// degrade rather than treating it as a failure, the same way
    /// [`SendOutcome::NotConfigured`](crate::SendOutcome) works for mail.
    /// [`RoutingPush`] also answers this for a recipient no adapter serves.
    NotConfigured,
}

/// Push failures. `Unregistered` is separated because the caller must act on
/// it — the recipient is dead and should be pruned — where the others are
/// transient or a bad request.
///
/// The two variants that carry provider text are sanitized in `Display`,
/// the same way [`DbError`](crate::DbError)'s and
/// [`MailError`](crate::MailError)'s are (issue #235). What an adapter
/// wraps is the provider's own words, and a push endpoint or a device
/// token is exactly the kind of value that rides in them. `Display`
/// therefore runs it through [`crate::logging::scrub_text`]; `Debug`
/// still shows the raw string for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    /// The provider says the recipient is no longer valid (APNs `410`, Web
    /// Push `410`, FCM `UNREGISTERED`): delete it.
    ///
    /// This is a **delete instruction**, not a failed send, and an adapter
    /// should map only a status whose sole meaning is "gone" onto it. A
    /// status a misrouted proxy can also produce — Web Push `404`, which
    /// RFC 8030 never defines as gone — belongs in
    /// [`Transient`](Self::Transient): the cost of a wrong `Transient` is
    /// some wasted sends, and a wrongly-pruned Web Push subscription cannot
    /// be recreated server-side at all, only by the browser subscribing
    /// again.
    Unregistered,
    /// The provider rejected the request (a `4xx` that is not `410`), or the
    /// adapter does not serve this recipient's transport; not retryable
    /// without a change.
    Rejected(String),
    /// A transient failure (a `5xx`, a `429`, a transport error): retry
    /// later, and not before `retry_after` when the provider named one
    /// (APNs `429`, FCM `RESOURCE_EXHAUSTED`/`UNAVAILABLE`, Web Push
    /// `429`/`503` — all carry `Retry-After`).
    Transient {
        message: String,
        retry_after: Option<Duration>,
    },
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scrub = crate::logging::scrub_text;
        match self {
            Self::Unregistered => f.write_str("device token is no longer registered; delete it"),
            Self::Rejected(message) => write!(f, "push rejected: {}", scrub(message)),
            Self::Transient { message, .. } => {
                write!(f, "push failed, retryable: {}", scrub(message))
            }
        }
    }
}

impl std::error::Error for PushError {}

impl PushError {
    /// A retryable failure with no provider-supplied delay.
    pub fn transient(message: impl Into<String>) -> Self {
        PushError::Transient {
            message: message.into(),
            retry_after: None,
        }
    }

    /// A retryable failure the provider asked us to hold off on.
    pub fn transient_after(message: impl Into<String>, retry_after: Option<Duration>) -> Self {
        PushError::Transient {
            message: message.into(),
            retry_after,
        }
    }

    /// The rejection an adapter returns for a transport it does not serve.
    /// [`RoutingPush`] exists so a venture never has to see this.
    pub fn unsupported_recipient(recipient: &Recipient) -> Self {
        PushError::Rejected(format!(
            "unsupported recipient: this adapter does not serve {}",
            recipient.platform()
        ))
    }

    /// How long the provider asked the caller to wait, where it said.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            PushError::Transient { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// Sends notifications to a device, over whichever transport the
/// [`Recipient`] names. An adapter serves one transport and returns
/// [`PushError::unsupported_recipient`] for the rest; [`RoutingPush`] fans a
/// mixed set of recipients out across the adapters a venture configured.
#[async_trait]
pub trait Push: Send + Sync {
    /// Sends `notification` to `to`.
    async fn send(
        &self,
        to: &Recipient,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError>;
}

/// Dispatches by [`Recipient`] variant to the adapter a venture configured
/// for that transport, so venture code holds one `Arc<dyn Push>` and never
/// matches on the transport itself (ADR 0015).
///
/// A recipient whose transport has no adapter is
/// [`PushOutcome::NotConfigured`] — the same answer an unconfigured adapter
/// gives, and deliberately not [`PushError::Rejected`]: nothing is wrong with
/// the recipient, the venture simply did not wire that transport.
#[derive(Default, Clone)]
pub struct RoutingPush {
    apns: Option<Arc<dyn Push>>,
    fcm: Option<Arc<dyn Push>>,
    web_push: Option<Arc<dyn Push>>,
}

impl RoutingPush {
    /// A router with no adapters: every recipient is `NotConfigured`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The adapter for [`Recipient::Apns`].
    #[must_use]
    pub fn apns(mut self, push: Arc<dyn Push>) -> Self {
        self.apns = Some(push);
        self
    }

    /// The adapter for [`Recipient::Fcm`].
    #[must_use]
    pub fn fcm(mut self, push: Arc<dyn Push>) -> Self {
        self.fcm = Some(push);
        self
    }

    /// The adapter for [`Recipient::WebPush`].
    #[must_use]
    pub fn web_push(mut self, push: Arc<dyn Push>) -> Self {
        self.web_push = Some(push);
        self
    }

    /// The adapter that serves `recipient`, if one is configured.
    #[must_use]
    pub fn route_for(&self, recipient: &Recipient) -> Option<&Arc<dyn Push>> {
        match recipient {
            Recipient::Apns { .. } => self.apns.as_ref(),
            Recipient::Fcm { .. } => self.fcm.as_ref(),
            Recipient::WebPush { .. } => self.web_push.as_ref(),
        }
    }
}

impl std::fmt::Debug for RoutingPush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingPush")
            .field("apns", &self.apns.is_some())
            .field("fcm", &self.fcm.is_some())
            .field("web_push", &self.web_push.is_some())
            .finish()
    }
}

#[async_trait]
impl Push for RoutingPush {
    async fn send(
        &self,
        to: &Recipient,
        notification: &Notification,
    ) -> Result<PushOutcome, PushError> {
        match self.route_for(to) {
            Some(push) => push.send(to, notification).await,
            None => Ok(PushOutcome::NotConfigured),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recipient_round_trips_through_json() {
        for recipient in [
            Recipient::apns("devicetoken"),
            Recipient::fcm("registration"),
            Recipient::web_push("https://fcm.googleapis.com/wp/x", "p256dh-key", "auth-key"),
        ] {
            let json = serde_json::to_string(&recipient).expect("serialises");
            let back: Recipient = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(recipient, back);
        }
    }

    #[test]
    fn the_recipient_tag_is_the_transport_name() {
        let json = serde_json::to_value(Recipient::web_push("https://e", "p", "a")).unwrap();
        assert_eq!(json["web_push"]["endpoint"], "https://e");
        assert_eq!(json["web_push"]["p256dh"], "p");
        assert_eq!(json["web_push"]["auth"], "a");
    }

    #[test]
    fn debug_prints_no_credential_material() {
        // The Web Push `auth` secret, the endpoint capability URL and the
        // device token must never reach a log through `{:?}` — core's
        // redaction is by field name and cannot see inside this enum.
        let web = Recipient::web_push(
            "https://fcm.googleapis.com/wp/cAPABILITYtokenPATH",
            "BP256dhPublicKeyValue",
            "AuthSecretValue",
        );
        let printed = format!("{web:?}");
        assert!(printed.contains("WebPush"), "{printed}");
        assert!(!printed.contains("AuthSecretValue"), "{printed}");
        assert!(!printed.contains("cAPABILITYtokenPATH"), "{printed}");
        assert!(!printed.contains("fcm.googleapis.com"), "{printed}");
        assert!(!printed.contains("BP256dhPublicKeyValue"), "{printed}");

        let apns = format!("{:?}", Recipient::apns("deadbeefDEVICEtoken"));
        assert!(apns.contains("Apns"), "{apns}");
        assert!(!apns.contains("deadbeefDEVICEtoken"), "{apns}");

        let fcm = format!("{:?}", Recipient::fcm("REGISTRATIONtokenValue"));
        assert!(fcm.contains("Fcm"), "{fcm}");
        assert!(!fcm.contains("REGISTRATIONtokenValue"), "{fcm}");

        // A fingerprint still correlates: same recipient, same line.
        assert_eq!(printed, format!("{web:?}"));
        assert_ne!(
            printed,
            format!("{:?}", Recipient::web_push("https://other", "p", "a"))
        );
    }

    #[test]
    fn a_recipient_inside_a_struct_is_redacted_too() {
        // The realistic leak: `tracing::error!(?recipient)` on a struct that
        // merely contains one, where the derived Debug delegates to ours.
        #[derive(Debug)]
        struct Row {
            recipient: Recipient,
        }
        let row = Row {
            recipient: Recipient::apns("deadbeefDEVICEtoken"),
        };
        let printed = format!("{row:?}");
        assert!(!printed.contains("deadbeefDEVICEtoken"), "{printed}");
        assert_eq!(row.recipient.platform(), Platform::Ios);
    }

    #[test]
    fn platform_is_a_transport_fact() {
        assert_eq!(Recipient::apns("t").platform(), Platform::Ios);
        assert_eq!(Recipient::fcm("t").platform(), Platform::Android);
        // A UnifiedPush endpoint on an Android phone is still Web Push.
        assert_eq!(
            Recipient::web_push("https://ntfy.sh/x", "p", "a").platform(),
            Platform::Web
        );
    }

    #[test]
    fn a_minimal_notification_serialises_to_title_body_data_priority() {
        let json = serde_json::to_value(Notification::new("Hi", "there")).unwrap();
        let object = json.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["body", "data", "priority", "title"]);
    }

    #[test]
    fn a_full_notification_round_trips_and_ttl_is_seconds() {
        let mut notification = Notification::new("Room starting", "Yoga in 10 min");
        notification.category = Some("SESSION".to_owned());
        notification.thread_id = Some("room-42".to_owned());
        notification.data = serde_json::json!({ "room_id": "42" });
        notification.collapse_id = Some("room-42".to_owned());
        notification.priority = Priority::Conserve;
        notification.icon = Some("https://example.test/icon.png".to_owned());
        notification.url = Some("https://example.test/rooms/42".to_owned());
        notification.ttl = Some(Duration::from_secs(3_600));
        notification.badge = Some(3);
        notification.silent = true;
        notification.loc = Some(LocKeys {
            title_loc_key: Some("ROOM_STARTING".to_owned()),
            title_loc_args: vec!["Yoga".to_owned()],
            body_loc_key: Some("ROOM_BODY".to_owned()),
            body_loc_args: vec!["10".to_owned()],
        });

        let json = serde_json::to_value(&notification).unwrap();
        assert_eq!(json["ttl"], 3_600, "a TTL is whole seconds on the wire");
        assert_eq!(json["silent"], true);
        assert_eq!(json["loc"]["title_loc_key"], "ROOM_STARTING");

        let back: Notification = serde_json::from_value(json).unwrap();
        assert_eq!(back, notification);
    }

    #[test]
    fn a_notification_from_the_pre_recipient_wire_form_still_parses() {
        // Every field #177 added is optional, so a payload written against
        // the old shape (an outbox row, say) still deserialises.
        let old = serde_json::json!({
            "title": "Hi",
            "body": "there",
            "data": {},
            "priority": "immediate"
        });
        let notification: Notification = serde_json::from_value(old).unwrap();
        assert_eq!(notification.title, "Hi");
        assert_eq!(notification.ttl, None);
        assert!(!notification.silent);
    }

    #[test]
    fn a_sub_second_ttl_rounds_up_and_never_becomes_drop_now() {
        // 900ms is "hold it briefly", not "drop it the moment the device is
        // offline" — and truncating to 0 would silently say the latter, on
        // the wire and on every round trip through it.
        assert_eq!(ttl_secs(Duration::from_millis(900)), 1);
        assert_eq!(ttl_secs(Duration::from_nanos(1)), 1);
        assert_eq!(ttl_secs(Duration::ZERO), 0, "zero is the deliberate drop");
        assert_eq!(ttl_secs(Duration::from_secs(3_600)), 3_600);
        assert_eq!(
            ttl_secs(Duration::from_millis(1_900)),
            1,
            "whole seconds otherwise truncate, as every protocol does"
        );

        let mut notification = Notification::new("a", "b");
        notification.ttl = Some(Duration::from_millis(900));
        let json = serde_json::to_value(&notification).unwrap();
        assert_eq!(json["ttl"], 1, "sub-second serialises as one second");
        let back: Notification = serde_json::from_value(json).unwrap();
        assert_eq!(
            back.ttl,
            Some(Duration::from_secs(1)),
            "and comes back meaning one second, not Duration::ZERO"
        );

        let mut zero = Notification::new("a", "b");
        zero.ttl = Some(Duration::ZERO);
        let json = serde_json::to_value(&zero).unwrap();
        assert_eq!(json["ttl"], 0);
        let back: Notification = serde_json::from_value(json).unwrap();
        assert_eq!(back.ttl, Some(Duration::ZERO));
    }

    #[test]
    fn transient_carries_an_optional_retry_after() {
        let plain = PushError::transient("apns 503");
        assert_eq!(plain.retry_after(), None);
        let throttled = PushError::transient_after("apns 429", Some(Duration::from_secs(30)));
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(PushError::Unregistered.retry_after(), None);
    }

    #[test]
    fn an_unsupported_recipient_names_the_transport() {
        let error = PushError::unsupported_recipient(&Recipient::fcm("t"));
        let message = error.to_string();
        assert!(message.contains("unsupported recipient"), "{message}");
        assert!(message.contains("android"), "{message}");
    }

    // -----------------------------------------------------------------
    // RoutingPush

    struct Recording {
        label: &'static str,
        seen: std::sync::atomic::AtomicUsize,
    }

    impl Recording {
        fn new(label: &'static str) -> Arc<Self> {
            Arc::new(Self {
                label,
                seen: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn count(&self) -> usize {
            self.seen.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Push for Recording {
        async fn send(
            &self,
            _to: &Recipient,
            _notification: &Notification,
        ) -> Result<PushOutcome, PushError> {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(PushOutcome::Delivered {
                id: Some(self.label.to_owned()),
            })
        }
    }

    #[test]
    fn the_router_dispatches_by_variant() {
        let apns = Recording::new("apns");
        let web = Recording::new("web");
        let router = RoutingPush::new().apns(apns.clone()).web_push(web.clone());
        let notification = Notification::new("a", "b");

        let outcome =
            pollster::block_on(router.send(&Recipient::apns("t"), &notification)).unwrap();
        assert_eq!(
            outcome,
            PushOutcome::Delivered {
                id: Some("apns".to_owned())
            }
        );
        let outcome = pollster::block_on(
            router.send(&Recipient::web_push("https://e", "p", "a"), &notification),
        )
        .unwrap();
        assert_eq!(
            outcome,
            PushOutcome::Delivered {
                id: Some("web".to_owned())
            }
        );
        assert_eq!(apns.count(), 1);
        assert_eq!(web.count(), 1);
    }

    #[test]
    fn a_transport_with_no_adapter_is_not_configured_not_rejected() {
        let router = RoutingPush::new().apns(Recording::new("apns"));
        let outcome =
            pollster::block_on(router.send(&Recipient::fcm("t"), &Notification::new("a", "b")))
                .unwrap();
        assert_eq!(outcome, PushOutcome::NotConfigured);
    }

    #[test]
    fn an_empty_router_is_not_configured_for_every_transport() {
        let router = RoutingPush::new();
        for recipient in [
            Recipient::apns("t"),
            Recipient::fcm("t"),
            Recipient::web_push("https://e", "p", "a"),
        ] {
            let outcome =
                pollster::block_on(router.send(&recipient, &Notification::new("a", "b"))).unwrap();
            assert_eq!(outcome, PushOutcome::NotConfigured);
            assert!(router.route_for(&recipient).is_none());
        }
    }

    #[test]
    fn display_sanitizes_the_provider_text() {
        // Issue #235. The text an adapter wraps is the push service's own
        // words, and a Web Push endpoint is a bearer capability URL: the
        // token it carries in its query must not survive into a log line
        // or a dead-letter row.
        let error = PushError::Rejected(
            "web push 400 for https://push.example.test/wp/alice?auth=cap-abcdef".to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains("cap-abcdef"), "{text}");
        assert!(text.contains("?[redacted]"), "{text}");

        // A provider that quotes the account it bounced on quotes an
        // address, and `Transient` carries provider text just as
        // `Rejected` does.
        let error = PushError::transient("fcm 503 for alice@example.test");
        let text = error.to_string();
        assert!(!text.contains('@'), "{text}");
        assert!(text.contains("[subject_hash:"), "{text}");

        assert_eq!(
            PushError::Unregistered.to_string(),
            "device token is no longer registered; delete it"
        );

        // `Debug` still shows the raw string for a failing test to read.
        assert!(format!("{error:?}").contains("alice@example.test"));
    }
}

#[cfg(test)]
mod retry_after_tests {
    use super::{parse_http_date, retry_after};
    use crate::Clock;
    use std::time::Duration;

    /// Fixed at `Sun, 06 Nov 1994 08:49:37 GMT`, so a date in the header
    /// is a known distance away rather than a race against the wall clock.
    struct FixedClock(time::OffsetDateTime);

    #[async_trait::async_trait]
    impl Clock for FixedClock {
        fn now(&self) -> time::OffsetDateTime {
            self.0
        }
    }

    fn at(unix: i64) -> FixedClock {
        FixedClock(time::OffsetDateTime::from_unix_timestamp(unix).expect("a valid instant"))
    }

    fn headers(value: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert("retry-after", value.parse().expect("a header value"));
        headers
    }

    #[test]
    fn an_http_date_parses_and_a_nonsense_one_does_not() {
        // Moved here with the parser it tests (issue #214); the two
        // obsolete forms stay unparsed on purpose.
        let parsed = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").expect("IMF-fixdate");
        assert_eq!(parsed.unix_timestamp(), 784_111_777);
        assert!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").is_none());
        assert!(parse_http_date("tomorrow").is_none());
    }

    #[test]
    fn the_delta_seconds_form_is_read() {
        assert_eq!(
            retry_after(&headers("120"), &at(0)),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            retry_after(&headers("  30  "), &at(0)),
            Some(Duration::from_secs(30)),
            "surrounding space is not a parse failure"
        );
    }

    #[test]
    fn the_http_date_form_is_read_too() {
        // The whole point of consolidating: three of the four copies read
        // only the delta-seconds form, so a CDN's date turned an hour's
        // wait into an immediate retry.
        let an_hour_before = 784_111_777 - 3_600;
        assert_eq!(
            retry_after(
                &headers("Sun, 06 Nov 1994 08:49:37 GMT"),
                &at(an_hour_before)
            ),
            Some(Duration::from_secs(3_600))
        );
    }

    #[test]
    fn a_date_already_past_means_retry_now_not_no_delay() {
        // `Duration::ZERO` and `None` say different things to a caller:
        // "now" versus "nothing was stated, use your own schedule".
        assert_eq!(
            retry_after(
                &headers("Sun, 06 Nov 1994 08:49:37 GMT"),
                &at(784_111_777 + 60)
            ),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn an_absent_or_unparseable_header_states_no_delay() {
        assert_eq!(retry_after(&http::HeaderMap::new(), &at(0)), None);
        assert_eq!(retry_after(&headers("soon"), &at(0)), None);
        assert_eq!(
            retry_after(&headers("-5"), &at(0)),
            None,
            "a negative delta is not a duration"
        );
    }
}
