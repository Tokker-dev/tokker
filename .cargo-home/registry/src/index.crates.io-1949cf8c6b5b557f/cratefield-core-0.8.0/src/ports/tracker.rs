//! The `Tracker` port (issue #431): filing a ticket into *someone else's*
//! tracker — a GitHub repo, a Jira site, a Linear team, a Zendesk subdomain,
//! a Freshdesk portal, Intercom, a Salesforce instance, `HubSpot`, a Slack
//! channel, a Colonizer repository, or a plain webhook — and asking how that
//! ticket is doing afterwards.
//!
//! The reason this is a port and not a module detail is the deployment
//! shape: one hosted Worker serves many customer companies, and each
//! company files into *its own* tracker under *its own* API token. The
//! destinations and the credentials are therefore tenant data, resolved per
//! request — which is why every [`Tracker`] method takes a
//! [`Destination`] and a [`Credential`] rather than the adapter holding
//! either at construction (see the trait's docs for why that differs from
//! the Resend/Stripe adapter shape).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::webhook_signature::WebhookVerifier;

/// Where a ticket is filed. One variant per supported tracker, because the
/// eleven do not share a shape: a GitHub destination is an owner and repo, a
/// webhook is a URL, and Intercom and `HubSpot` address nothing but the
/// credential — the workspace/portal the token belongs to *is* the
/// destination, so those variants carry no fields at all.
///
/// The fields name *where* to file, not *who may file*: an owner, a repo, a
/// site, a channel are routing facts a venture may reasonably hold, log and
/// persist. Most variants therefore hold no secret — `Webhook` is the
/// exception, because its URL routinely carries a bearer token in its path
/// or query — so the hand-written [`Debug`](#impl-Debug-for-Destination)
/// renders a webhook URL as `[redacted]`, following the
/// [`Recipient`](crate::Recipient) precedent: core's log redaction keys off
/// the *field name* ([`is_secret_field`](crate::is_secret_field)) and
/// cannot see inside a `{:?}` of this enum.
///
/// [`Serialize`]/[`Deserialize`] stay, because a destination has to be
/// persisted and read back — it is tenant configuration (the credential
/// proper is [`Credential`], which refuses both) — and `Serialize`
/// deliberately does **not** redact, because round-tripping tenant
/// configuration has to work. The consequence: a serialised
/// `Destination::Webhook` **is** the credential — store it where secrets
/// go, never in a log, an event payload, or an error body.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// A repository on GitHub (or GitHub Enterprise).
    GitHub {
        /// The repository's owner (a user or organisation).
        owner: String,
        /// The repository name.
        repo: String,
    },
    /// A project on a Jira site.
    Jira {
        /// The Jira site's bare hostname (`acme.atlassian.net`) — never a
        /// scheme or path, so the Basic credential cannot be moved off the
        /// host it names.
        site: String,
        /// The project key tickets are filed under (`PROJ`).
        project: String,
    },
    /// A team on Linear.
    Linear {
        /// The team tickets are filed under.
        team: String,
    },
    /// A Zendesk subdomain.
    Zendesk {
        /// The subdomain (`acme` for `acme.zendesk.com`).
        subdomain: String,
    },
    /// A Freshdesk portal.
    Freshdesk {
        /// The portal's domain (`acme.freshdesk.com`).
        domain: String,
    },
    /// Intercom. The workspace is identified by the credential.
    Intercom,
    /// A Salesforce instance.
    Salesforce {
        /// The instance's hostname (`acme.my.salesforce.com`).
        instance: String,
    },
    /// `HubSpot`. The portal is identified by the credential.
    HubSpot,
    /// A Slack channel.
    Slack {
        /// The channel ID tickets are filed into (`C0123456789`).
        channel: String,
    },
    /// A generic webhook. **The URL is credential material**: it is the
    /// bearer capability that lets anyone holding it file tickets, so it is
    /// redacted in `Debug` and adapters must treat it like a token.
    Webhook {
        /// The URL to `POST` the ticket to.
        url: String,
    },
    /// A repository on the Colonizer automation. The repository is a routing
    /// fact, not a secret — it names where tickets land — so it prints in
    /// `Debug`, exactly as a GitHub repository does.
    Colonizer {
        /// The repository to file into.
        repo: String,
    },
}

impl Destination {
    /// The kind of tracker this destination names, for logs, metrics and
    /// error messages: `"github"`, `"jira"`, `"linear"`, `"zendesk"`,
    /// `"freshdesk"`, `"intercom"`, `"salesforce"`, `"hubspot"`, `"slack"`,
    /// `"webhook"`, `"colonizer"`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Destination::GitHub { .. } => "github",
            Destination::Jira { .. } => "jira",
            Destination::Linear { .. } => "linear",
            Destination::Zendesk { .. } => "zendesk",
            Destination::Freshdesk { .. } => "freshdesk",
            Destination::Intercom => "intercom",
            Destination::Salesforce { .. } => "salesforce",
            Destination::HubSpot => "hubspot",
            Destination::Slack { .. } => "slack",
            Destination::Webhook { .. } => "webhook",
            Destination::Colonizer { .. } => "colonizer",
        }
    }
}

/// Prints the variant and its non-secret fields, never a webhook URL — a
/// webhook endpoint is a bearer capability, and the token it carries in its
/// path or query must not survive into a log line.
impl std::fmt::Debug for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Destination::GitHub { owner, repo } => write!(
                f,
                "Destination::GitHub {{ owner: {owner:?}, repo: {repo:?} }}"
            ),
            Destination::Jira { site, project } => write!(
                f,
                "Destination::Jira {{ site: {site:?}, project: {project:?} }}"
            ),
            Destination::Linear { team } => {
                write!(f, "Destination::Linear {{ team: {team:?} }}")
            }
            Destination::Zendesk { subdomain } => {
                write!(f, "Destination::Zendesk {{ subdomain: {subdomain:?} }}")
            }
            Destination::Freshdesk { domain } => {
                write!(f, "Destination::Freshdesk {{ domain: {domain:?} }}")
            }
            Destination::Intercom => f.write_str("Destination::Intercom"),
            Destination::Salesforce { instance } => {
                write!(f, "Destination::Salesforce {{ instance: {instance:?} }}")
            }
            Destination::HubSpot => f.write_str("Destination::HubSpot"),
            Destination::Slack { channel } => {
                write!(f, "Destination::Slack {{ channel: {channel:?} }}")
            }
            // The whole URL is withheld, host included: a webhook endpoint
            // is itself the capability.
            Destination::Webhook { .. } => f.write_str("Destination::Webhook { url: [redacted] }"),
            Destination::Colonizer { repo } => {
                write!(f, "Destination::Colonizer {{ repo: {repo:?} }}")
            }
        }
    }
}

/// The API credential the destination's tracker expects — the customer
/// company's token, decrypted from `cratefield-secrets` immediately before
/// the call and never stored anywhere else.
///
/// The bytes are zeroised on drop ([`Zeroizing`]), and the type implements
/// neither `Display`, `Serialize`, `Deserialize` nor `PartialEq`: a secret
/// that can be formatted, serialised or compared is a secret that ends up
/// in a log line, a JSON body, or a database row nobody clears. `Debug` is
/// implemented, and redacts:
///
/// ```
/// # use cratefield_core::Credential;
/// let cred = Credential::new("ghp_AAAAnobodyshouldseethis");
/// assert_eq!(format!("{cred:?}"), "Credential([redacted])");
/// ```
///
/// [`Clone`] stays: a copy is a second *buffer* holding the same secret —
/// `Zeroizing`'s `Clone` clones the inner `String`, which allocates fresh —
/// and each buffer is zeroised when its own handle drops. So no copy
/// outlives unzeroised, but every clone is one more live copy of the
/// secret to clear; clone deliberately.
#[derive(Clone)]
pub struct Credential(Zeroizing<String>);

impl Credential {
    /// Wraps a credential.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self(Zeroizing::new(secret.into()))
    }

    /// The credential. Named `expose` so a reader has to notice — the same
    /// rule `SecretBytes` in `cratefield-secrets` follows. Every use is
    /// deliberate and auditable: an adapter reaches it once, to build the
    /// one `Authorization` header the call needs, and nothing else in the
    /// harness ever should.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential([redacted])")
    }
}

/// How urgently the ticket should be attended to. Adapters map this onto
/// whatever their tracker has — a GitHub label, a Jira priority, a Slack
/// `Notification-Alert` — and document what they drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Worth knowing. A note, not a page.
    Info,
    /// Wrong, and someone should look soon.
    Warning,
    /// Broken for users; file it and act on it today.
    Error,
    /// Data loss, security, or everything down; wake someone up.
    Critical,
}

impl Severity {
    /// The name used in errors, logs and labels.
    pub fn name(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A ticket to file, in tracker-neutral terms: every adapter maps the
/// fields its protocol has and documents what it drops. `title` and
/// `body_markdown` are the only content every tracker takes; `labels` and
/// `environment` are requests an adapter may flatten into the body, a
/// label list, or nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketDraft {
    /// Makes the file idempotent under retries; the caller owns its shape.
    /// A tracker that has already accepted this key answers with the
    /// existing ticket instead of a duplicate (an adapter may also enforce
    /// it with an idempotency header where the API has one).
    pub idempotency_key: String,
    /// The ticket's title, one line.
    pub title: String,
    /// The ticket's body, Markdown. Adapters translate or quote it
    /// verbatim per their tracker's format and say which.
    pub body_markdown: String,
    /// How urgent the ticket is.
    pub severity: Severity,
    /// Free-form labels. A tracker without labels carries them in the body.
    pub labels: Vec<String>,
    /// The deployment the ticket is about (`"production"`, `"eu-1"`), when
    /// the caller knows one.
    pub environment: Option<String>,
}

impl TicketDraft {
    /// A minimal draft: the idempotency key, a title, a body and a
    /// severity. Labels and environment are added by the chaining setters.
    #[must_use]
    pub fn new(
        idempotency_key: impl Into<String>,
        title: impl Into<String>,
        body_markdown: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            idempotency_key: idempotency_key.into(),
            title: title.into(),
            body_markdown: body_markdown.into(),
            severity,
            labels: Vec::new(),
            environment: None,
        }
    }

    /// Sets the labels.
    #[must_use]
    pub fn labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    /// Sets the environment the ticket is about.
    #[must_use]
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }
}

/// The result of a file that the tracker accepted: its id in the external
/// tracker (persist it — [`Tracker::status`] is keyed by it) and the
/// ticket's human-readable URL, where the tracker has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filed {
    /// The ticket's id in the tracker it was filed into (`OWNER/REPO#42`,
    /// `PROJ-7`, a webhook's delivery id).
    pub external_id: String,
    /// The ticket's URL, when the tracker renders one.
    pub url: String,
}

/// A note added to an existing ticket — e.g. linking a duplicate report to
/// the ticket it duplicates. Adapters map the fields their tracker has and
/// document what they drop; `body_markdown` is the only content every
/// tracker takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketComment {
    /// Makes the note idempotent under retries; the caller owns its shape,
    /// exactly as [`TicketDraft::idempotency_key`] does for the file.
    pub idempotency_key: String,
    /// The note's body, Markdown. Adapters translate or quote it verbatim
    /// per their tracker's format and say which.
    pub body_markdown: String,
    /// A URL the note points at — typically the duplicate report this
    /// comment links into the existing ticket.
    pub link: Option<String>,
}

impl TicketComment {
    /// A bare note: the idempotency key and a body. The link is added by
    /// the chaining setter.
    #[must_use]
    pub fn new(idempotency_key: impl Into<String>, body_markdown: impl Into<String>) -> Self {
        Self {
            idempotency_key: idempotency_key.into(),
            body_markdown: body_markdown.into(),
            link: None,
        }
    }

    /// Sets the URL the note links to.
    #[must_use]
    pub fn with_link(mut self, url: impl Into<String>) -> Self {
        self.link = Some(url.into());
        self
    }
}

/// A ticket's state as the tracker last reported it. Adapters map their
/// tracker's workflow states onto these five, and onto
/// [`TicketState::Unknown`] anything they cannot name — they never invent
/// a sixth state, and a caller that needs the tracker's own raw state name
/// asks the tracker's API by `external_id`.
///
/// `Serialize`/`Deserialize` (snake case, the [`Severity`] precedent):
/// a state arriving on an inbound status webhook crosses the same wire a
/// `Severity` does leaving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketState {
    /// Filed, nobody has picked it up.
    Open,
    /// Someone is working on it.
    InProgress,
    /// The tracker reports it fixed or answered; the caller may want to
    /// verify and close it.
    Resolved,
    /// Done, closed, will not be reopened.
    Closed,
    /// The tracker reported a state this port cannot name.
    Unknown,
}

/// A ticket's current state and, where the tracker renders one, its URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketStatus {
    /// The ticket's id in the tracker it was filed into.
    pub external_id: String,
    /// The state the tracker reports.
    pub state: TicketState,
    /// The ticket's URL, when the tracker renders one.
    pub url: Option<String>,
}

/// Tracker failures.
///
/// [`NotConfigured`](Self::NotConfigured) is an **error**, not an outcome:
/// unlike `Push` — where "not configured" is a
/// [`PushOutcome`](crate::PushOutcome) a caller can degrade around —
/// `Tracker` answers `Result<Filed, TrackerError>`, and the venture code
/// that files a ticket needs to know nobody is listening rather than be
/// told it succeeded. [`PaymentsError::NotConfigured`](crate::PaymentsError)
/// is the precedent.
///
/// The two variants that carry a message are sanitized in `Display` the
/// way [`PushError`](crate::PushError)'s are (issue #235): what an adapter
/// wraps is the tracker's own words, and a webhook URL or a workspace name
/// is exactly the kind of value that rides in them. `Display` therefore
/// runs it through [`crate::logging::scrub_text`]; `Debug` still shows the
/// raw string for tests.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TrackerError {
    /// No tracker adapter is configured for this destination, or the
    /// adapter has no credential: the caller should degrade, not fail.
    #[error("tracker is not configured")]
    NotConfigured,
    /// The tracker refused the **credential**: the per-tenant token was
    /// wrong, expired, or lacked the scope the call needed (`401`/`403`),
    /// so no retry and no redraft helps — a new credential has to be
    /// issued. Distinct from [`Rejected`](Self::Rejected), which is the
    /// tracker refusing the *ticket* (a `4xx` about the request, not
    /// about who made it); conflating the two either pages on a bad draft
    /// or files nothing while a tenant's token sits expired.
    #[error("tracker refused the credential")]
    Unauthorized,
    /// The tracker refused the call — the destination was wrong, the
    /// draft was rejected (`4xx`), or the adapter does not serve this
    /// destination; not retryable without a change.
    #[error("tracker rejected the request: {scrubbed}", scrubbed = crate::logging::scrub_text(.0))]
    Rejected(String),
    /// A transient failure (a `5xx`, a `429`, a transport error): retry
    /// later, and not before `retry_after` when the provider named a
    /// delay.
    #[error(
        "tracker request failed, retryable: {delay}",
        delay = retry_after_description(.retry_after)
    )]
    Transient {
        /// How long the provider asked the caller to wait, where it said.
        retry_after: Option<Duration>,
    },
}

impl TrackerError {
    /// The rejection an adapter returns for a destination kind it does not
    /// serve. [`RoutingTracker`] exists so a venture never has to see this.
    #[must_use]
    pub fn unsupported_destination(dest: &Destination) -> Self {
        TrackerError::Rejected(format!(
            "unsupported destination: this adapter does not serve {}",
            dest.kind()
        ))
    }

    /// How long the provider asked the caller to wait, where it said.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            TrackerError::Transient { retry_after } => *retry_after,
            _ => None,
        }
    }
}

/// `TrackerError::Transient`'s `Display` tail: what the provider asked
/// for, or the honest "nothing was stated" — `None` and a zero delay mean
/// different things to a caller scheduling a retry.
// thiserror's `#[error(…, arg = expr(.field))]` passes the matched field
// by reference, so the signature is not ours to choose — the same reason
// `push.rs`'s `duration_secs` carries this allow.
#[allow(clippy::ref_option)]
fn retry_after_description(retry_after: &Option<Duration>) -> String {
    match retry_after {
        Some(after) => format!("retry after {}s", after.as_secs()),
        None => "no delay was stated".to_owned(),
    }
}

/// Files tickets into a tracker and reports their status.
///
/// **Why the credential is a per-call parameter, and not adapter
/// construction state.** Every other adapter in this workspace is built
/// once with its vendor's own key — the Resend `Mailer` holds the Resend
/// API key, the Stripe `Payments` holds the Stripe secret, because on this
/// harness the vendor account belongs to the *platform*. A tracker is the
/// opposite: one hosted Worker serves many customer companies, each filing
/// into **its own** tracker under **its own** token. Those per-tenant
/// credentials live encrypted in `cratefield-secrets`, are decrypted for
/// exactly one call, and are dropped — so the credential arrives with the
/// call, and an adapter holds nothing between calls that a tenant change
/// could leak. This is the one deliberate deviation from the
/// Resend/Stripe adapter shape.
///
/// `dest` is a parameter for the same reason: which tracker to file into
/// is tenant configuration, not deployment configuration.
#[async_trait]
pub trait Tracker: Send + Sync {
    /// Files `draft` into `dest`, authenticating as the company `cred`
    /// speaks for. Idempotent on `draft.idempotency_key` where the tracker
    /// allows it.
    ///
    /// # Errors
    ///
    /// [`TrackerError::NotConfigured`] when no adapter is wired,
    /// [`TrackerError::Unauthorized`] when the tracker refuses the
    /// credential, [`TrackerError::Rejected`] when the tracker refuses
    /// the call, and [`TrackerError::Transient`] with the provider's
    /// delay, where it gave one, when the call can be retried.
    async fn file(
        &self,
        dest: &Destination,
        cred: &Credential,
        draft: &TicketDraft,
    ) -> Result<Filed, TrackerError>;

    /// Reads one ticket's current state from `dest`.
    ///
    /// # Errors
    ///
    /// The same four as [`Tracker::file`].
    async fn status(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
    ) -> Result<TicketStatus, TrackerError>;

    /// Adds `comment` to the existing ticket `external_id` in `dest` —
    /// e.g. linking a duplicate report to the ticket it duplicates, so the
    /// tracker holds one ticket per defect rather than one per report.
    ///
    /// The default impl refuses: a tracker that cannot take notes says so
    /// by name — the way the webhook tracker adapter refuses `status` —
    /// rather than silently dropping the note. Adapters whose tracker has
    /// a comment API override this.
    ///
    /// # Errors
    ///
    /// The same four as [`Tracker::file`], plus the default
    /// [`TrackerError::Rejected`] when the adapter does not serve notes.
    async fn comment(
        &self,
        dest: &Destination,
        _cred: &Credential,
        _external_id: &str,
        _comment: &TicketComment,
    ) -> Result<(), TrackerError> {
        Err(TrackerError::Rejected(format!(
            "this adapter does not support comments on {} tickets",
            dest.kind()
        )))
    }
}

/// Dispatches by [`Destination`] variant to the adapter a venture
/// configured for that tracker, so venture code holds one
/// `Arc<dyn Tracker>` and never matches on the destination itself.
///
/// A destination whose tracker has no adapter is
/// [`TrackerError::NotConfigured`] — the same answer an unconfigured
/// adapter gives, and deliberately an *error* rather than a silent success:
/// a ticket that was never filed must look like a failure to the code that
/// needed it filed (see [`TrackerError::NotConfigured`]).
#[derive(Default, Clone)]
pub struct RoutingTracker {
    github: Option<Arc<dyn Tracker>>,
    jira: Option<Arc<dyn Tracker>>,
    linear: Option<Arc<dyn Tracker>>,
    zendesk: Option<Arc<dyn Tracker>>,
    freshdesk: Option<Arc<dyn Tracker>>,
    intercom: Option<Arc<dyn Tracker>>,
    salesforce: Option<Arc<dyn Tracker>>,
    hubspot: Option<Arc<dyn Tracker>>,
    slack: Option<Arc<dyn Tracker>>,
    webhook: Option<Arc<dyn Tracker>>,
    colonizer: Option<Arc<dyn Tracker>>,
}

impl RoutingTracker {
    /// A router with no adapters: every destination is `NotConfigured`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The adapter for [`Destination::GitHub`].
    #[must_use]
    pub fn github(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.github = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Jira`].
    #[must_use]
    pub fn jira(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.jira = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Linear`].
    #[must_use]
    pub fn linear(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.linear = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Zendesk`].
    #[must_use]
    pub fn zendesk(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.zendesk = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Freshdesk`].
    #[must_use]
    pub fn freshdesk(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.freshdesk = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Intercom`].
    #[must_use]
    pub fn intercom(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.intercom = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Salesforce`].
    #[must_use]
    pub fn salesforce(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.salesforce = Some(tracker);
        self
    }

    /// The adapter for [`Destination::HubSpot`].
    #[must_use]
    pub fn hubspot(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.hubspot = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Slack`].
    #[must_use]
    pub fn slack(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.slack = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Webhook`].
    #[must_use]
    pub fn webhook(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.webhook = Some(tracker);
        self
    }

    /// The adapter for [`Destination::Colonizer`].
    #[must_use]
    pub fn colonizer(mut self, tracker: Arc<dyn Tracker>) -> Self {
        self.colonizer = Some(tracker);
        self
    }

    /// The adapter that serves `destination`, if one is configured.
    #[must_use]
    pub fn route_for(&self, destination: &Destination) -> Option<&Arc<dyn Tracker>> {
        match destination {
            Destination::GitHub { .. } => self.github.as_ref(),
            Destination::Jira { .. } => self.jira.as_ref(),
            Destination::Linear { .. } => self.linear.as_ref(),
            Destination::Zendesk { .. } => self.zendesk.as_ref(),
            Destination::Freshdesk { .. } => self.freshdesk.as_ref(),
            Destination::Intercom => self.intercom.as_ref(),
            Destination::Salesforce { .. } => self.salesforce.as_ref(),
            Destination::HubSpot => self.hubspot.as_ref(),
            Destination::Slack { .. } => self.slack.as_ref(),
            Destination::Webhook { .. } => self.webhook.as_ref(),
            Destination::Colonizer { .. } => self.colonizer.as_ref(),
        }
    }
}

impl std::fmt::Debug for RoutingTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingTracker")
            .field("github", &self.github.is_some())
            .field("jira", &self.jira.is_some())
            .field("linear", &self.linear.is_some())
            .field("zendesk", &self.zendesk.is_some())
            .field("freshdesk", &self.freshdesk.is_some())
            .field("intercom", &self.intercom.is_some())
            .field("salesforce", &self.salesforce.is_some())
            .field("hubspot", &self.hubspot.is_some())
            .field("slack", &self.slack.is_some())
            .field("webhook", &self.webhook.is_some())
            .field("colonizer", &self.colonizer.is_some())
            .finish()
    }
}

#[async_trait]
impl Tracker for RoutingTracker {
    async fn file(
        &self,
        dest: &Destination,
        cred: &Credential,
        draft: &TicketDraft,
    ) -> Result<Filed, TrackerError> {
        match self.route_for(dest) {
            Some(tracker) => tracker.file(dest, cred, draft).await,
            None => Err(TrackerError::NotConfigured),
        }
    }

    async fn status(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
    ) -> Result<TicketStatus, TrackerError> {
        match self.route_for(dest) {
            Some(tracker) => tracker.status(dest, cred, external_id).await,
            None => Err(TrackerError::NotConfigured),
        }
    }

    async fn comment(
        &self,
        dest: &Destination,
        cred: &Credential,
        external_id: &str,
        comment: &TicketComment,
    ) -> Result<(), TrackerError> {
        match self.route_for(dest) {
            Some(tracker) => tracker.comment(dest, cred, external_id, comment).await,
            None => Err(TrackerError::NotConfigured),
        }
    }
}

// ---------------------------------------------------------------------------
// Inbound status webhooks: ticket state flowing back the other way.

/// A ticket-state change a tracker reported on its inbound status webhook:
/// the same shape [`Tracker::status`] answers with, pushed instead of
/// pulled. `Ok(None)` from a parse means a verified event that carries no
/// status change (a comment, a ping) — not an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusUpdate {
    /// The ticket's id in the tracker it was filed into, as the vendor's
    /// payload names it.
    pub external_id: String,
    /// The state the vendor reports, mapped onto the port's five.
    pub state: TicketState,
    /// The ticket's URL, when the vendor's payload carries one.
    pub url: Option<String>,
}

/// A tracker's inbound status webhook, implemented per vendor by adapter
/// crates: how to verify a delivery's signature and how to read a state
/// change out of the verified body.
///
/// Verification is **not** reimplemented here: [`verifier`](Self::verifier)
/// returns core's [`WebhookVerifier`] — constant-time compare, fail-closed
/// on unreadable input and replay tolerance are inherited, never re-derived.
/// The signature scheme a vendor signs with is expressed as one of core's
/// [`SignatureScheme`](crate::SignatureScheme)s (`Svix`,
/// [`StripeStyle`](crate::StripeStyle), or a configured
/// [`ProviderScheme`](crate::ProviderScheme)); Jira Cloud, whose
/// `X-Hub-Signature: sha256=<hex>` HMAC covers the raw body with no
/// timestamp header, is
/// `ProviderScheme { signature: "X-Hub-Signature", encoding: SignatureEncoding::Hex, prefix: Some("sha256="), timestamp: None }`.
pub trait StatusWebhook: Send + Sync {
    /// The vendor this webhook speaks for, for logs and metrics — the same
    /// name [`Destination::kind`] uses for the outbound direction.
    fn kind(&self) -> &'static str;

    /// The verifier deliveries must pass before [`parse`](Self::parse) is
    /// ever reached. Returned per call so an adapter may hold its config
    /// without holding a verifier per tenant — the secret is a parameter
    /// of [`receive_status`], never of the hook.
    fn verifier(&self) -> WebhookVerifier;

    /// Reads one **verified** body. `Ok(None)` for an event that carries
    /// no status change; [`InboundStatusError::Malformed`] for one that
    /// should have carried one and does not parse.
    ///
    /// # Errors
    ///
    /// [`InboundStatusError::Malformed`] when the verified body is not an
    /// event this vendor sends. Never [`InboundStatusError::Signature`] —
    /// that answer belongs to [`receive_status`], before bytes are parsed.
    fn parse(&self, body: &[u8]) -> Result<Option<StatusUpdate>, InboundStatusError>;
}

/// A status-webhook failure. The `Signature` variant carries no provider
/// text: [`WebhookVerifier::verify`] answers a boolean — fail closed with
/// no detail to leak — and the port keeps that property rather than
/// inventing prose a log could leak. `Malformed` carries the adapter's own
/// description, scrubbed in `Display` the way [`TrackerError::Rejected`]
/// scrubs the tracker's words.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InboundStatusError {
    /// The delivery's signature did not verify (or could not be read). The
    /// body is never parsed, and the caller should answer `4xx` without
    /// saying which part failed.
    #[error("status webhook signature verification failed")]
    Signature,
    /// The delivery verified, but its body is not an event this vendor
    /// sends. `Display` scrubs the text — a payload can quote tenant data.
    #[error("status webhook body is malformed: {scrubbed}", scrubbed = crate::logging::scrub_text(.0))]
    Malformed(String),
}

/// Verifies a webhook delivery against `hook`'s verifier, and only then
/// parses it: `parse` never sees unverified bytes. The parameter shapes are
/// [`WebhookVerifier::verify`]'s — the endpoint's per-tenant `secret`, the
/// request's `headers`, the **raw** `body` bytes (before anything parsed
/// them) and the current `now_unix` for the replay tolerance, where the
/// vendor's scheme carries a timestamp.
///
/// # Errors
///
/// [`InboundStatusError::Signature`] when the delivery does not verify;
/// [`InboundStatusError::Malformed`] when it verifies but [`StatusWebhook::parse`]
/// cannot read a status change out of it. `Ok(None)` is a verified event
/// that carries no status change.
pub fn receive_status(
    hook: &dyn StatusWebhook,
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
    now_unix: i64,
) -> Result<Option<StatusUpdate>, InboundStatusError> {
    if !hook.verifier().verify(secret, headers, body, now_unix) {
        return Err(InboundStatusError::Signature);
    }
    hook.parse(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook_signature::{ProviderScheme, SignatureEncoding};

    // -----------------------------------------------------------------
    // Destination

    #[test]
    fn a_destination_round_trips_through_json() {
        for dest in all_destinations() {
            let json = serde_json::to_string(&dest).expect("serialises");
            let back: Destination = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(dest, back);
        }
    }

    /// Every variant, so a test that must cover all eleven cannot forget one.
    fn all_destinations() -> Vec<Destination> {
        vec![
            Destination::GitHub {
                owner: "acme".to_owned(),
                repo: "api".to_owned(),
            },
            Destination::Jira {
                site: "acme".to_owned(),
                project: "PROJ".to_owned(),
            },
            Destination::Linear {
                team: "Platform".to_owned(),
            },
            Destination::Zendesk {
                subdomain: "acme".to_owned(),
            },
            Destination::Freshdesk {
                domain: "acme.freshdesk.com".to_owned(),
            },
            Destination::Intercom,
            Destination::Salesforce {
                instance: "acme.my.salesforce.com".to_owned(),
            },
            Destination::HubSpot,
            Destination::Slack {
                channel: "C0123456789".to_owned(),
            },
            Destination::Webhook {
                url: "https://hooks.example.test/services/TOKEN/SECRET".to_owned(),
            },
            Destination::Colonizer {
                repo: "acme/owlpost".to_owned(),
            },
        ]
    }

    #[test]
    fn every_destination_kind_names_itself() {
        let kinds: Vec<&'static str> = all_destinations().iter().map(Destination::kind).collect();
        assert_eq!(
            kinds,
            [
                "github",
                "jira",
                "linear",
                "zendesk",
                "freshdesk",
                "intercom",
                "salesforce",
                "hubspot",
                "slack",
                "webhook",
                "colonizer",
            ]
        );
    }

    #[test]
    fn the_webhook_debug_prints_no_url() {
        // A destination inside a struct is redacted too: the derived Debug
        // of a holder delegates to ours.
        #[derive(Debug)]
        struct Row {
            dest: Destination,
        }

        // A webhook endpoint is a bearer capability: the token it carries
        // in its path (Slack's do, CI services' do) must never reach a log
        // through `{:?}` — core's redaction is by field name and cannot
        // see inside this enum.
        let row = Row {
            dest: Destination::Webhook {
                url: "https://hooks.example.test/services/TOKEN/SECRET".to_owned(),
            },
        };
        let printed = format!("{row:?}");
        assert!(printed.contains("Webhook"), "{printed}");
        assert!(printed.contains("[redacted]"), "{printed}");
        assert!(!printed.contains("hooks.example.test"), "{printed}");
        assert!(!printed.contains("TOKEN"), "{printed}");
        assert!(!printed.contains("SECRET"), "{printed}");
        assert!(!printed.contains("https"), "{printed}");
        assert!(matches!(row.dest, Destination::Webhook { .. }));
    }

    #[test]
    fn the_other_destinations_debug_print_their_routing_fields() {
        // The non-secret fields are the point of the hand-written Debug:
        // "which repo did this go to" must stay answerable.
        let printed = format!(
            "{:?}",
            Destination::GitHub {
                owner: "acme".to_owned(),
                repo: "api".to_owned(),
            }
        );
        assert!(printed.contains("acme"), "{printed}");
        assert!(printed.contains("api"), "{printed}");

        let printed = format!("{:?}", Destination::Intercom);
        assert_eq!(printed, "Destination::Intercom");
        let printed = format!("{:?}", Destination::HubSpot);
        assert_eq!(printed, "Destination::HubSpot");

        // Freshdesk's domain is a routing fact, not a secret: it prints.
        let printed = format!(
            "{:?}",
            Destination::Freshdesk {
                domain: "acme.freshdesk.com".to_owned(),
            }
        );
        assert!(printed.contains("acme.freshdesk.com"), "{printed}");
    }

    #[test]
    fn a_colonizer_destination_round_trips_and_prints_its_repo() {
        // The repo is a routing fact, not a secret: it survives a serde
        // round-trip under the snake_case `colonizer` key, names its kind,
        // and — like a GitHub repo — prints in `Debug`, so "which repo did
        // this go to" stays answerable.
        let dest = Destination::Colonizer {
            repo: "acme/owlpost".to_owned(),
        };

        let json = serde_json::to_value(&dest).expect("serialises");
        assert_eq!(
            json,
            serde_json::json!({ "colonizer": { "repo": "acme/owlpost" } })
        );
        let back: Destination = serde_json::from_value(json).expect("deserialises");
        assert_eq!(back, dest);

        assert_eq!(dest.kind(), "colonizer");
        assert_eq!(
            format!("{dest:?}"),
            r#"Destination::Colonizer { repo: "acme/owlpost" }"#
        );
    }

    // -----------------------------------------------------------------
    // Credential

    #[test]
    fn the_credential_debug_prints_nothing_but_redacted() {
        // Inside a holder, the derived Debug delegates to ours.
        #[derive(Debug)]
        struct Row {
            cred: Credential,
        }

        // The realistic token an adapter would be handed. Neither the
        // secret text nor any fragment of it may survive `{:?}`.
        let row = Row {
            cred: Credential::new("ghp_4a1b2c3d4e5fREALtokenVALUEnobodyshouldsee"),
        };
        let printed = format!("{row:?}");
        assert!(!printed.contains("ghp_"), "{printed}");
        assert!(!printed.contains("REALtokenVALUE"), "{printed}");
        assert!(printed.contains("Credential([redacted])"), "{printed}");
        assert_eq!(
            row.cred.expose(),
            "ghp_4a1b2c3d4e5fREALtokenVALUEnobodyshouldsee"
        );
    }

    #[test]
    fn the_credential_exposes_its_text_once_wrapped() {
        let cred = Credential::new("token-from-secrets");
        assert_eq!(cred.expose(), "token-from-secrets");
        // Cloning is a second buffer with the same secret; each is
        // zeroised when its own handle drops.
        let copy = cred.clone();
        assert_eq!(copy.expose(), "token-from-secrets");
    }

    // -----------------------------------------------------------------
    // TicketDraft and Severity

    #[test]
    fn a_draft_builds_through_the_chaining_setters() {
        let draft = TicketDraft::new(
            "outbox-42",
            "Checkout failing",
            "Stripe 500s on `/v1/charges`.",
            Severity::Error,
        )
        .labels(vec!["billing".to_owned(), "incident".to_owned()])
        .environment("production");

        assert_eq!(draft.idempotency_key, "outbox-42");
        assert_eq!(draft.title, "Checkout failing");
        assert_eq!(draft.severity, Severity::Error);
        assert_eq!(draft.labels, ["billing", "incident"]);
        assert_eq!(draft.environment.as_deref(), Some("production"));
    }

    #[test]
    fn a_minimal_draft_has_no_labels_or_environment() {
        let draft = TicketDraft::new("k", "t", "b", Severity::Info);
        assert!(draft.labels.is_empty());
        assert_eq!(draft.environment, None);
    }

    #[test]
    fn severity_names_are_snake_case_on_the_wire_and_in_display() {
        for (severity, name) in [
            (Severity::Info, "info"),
            (Severity::Warning, "warning"),
            (Severity::Error, "error"),
            (Severity::Critical, "critical"),
        ] {
            assert_eq!(severity.name(), name);
            assert_eq!(severity.to_string(), name);
            let json = serde_json::to_value(severity).unwrap();
            assert_eq!(json, name);
            let back: Severity = serde_json::from_value(json).unwrap();
            assert_eq!(back, severity);
        }
    }

    // -----------------------------------------------------------------
    // TrackerError

    #[test]
    fn transient_carries_an_optional_retry_after() {
        let plain = TrackerError::Transient { retry_after: None };
        assert_eq!(plain.retry_after(), None);
        let throttled = TrackerError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        assert_eq!(throttled.retry_after(), Some(Duration::from_secs(30)));
        // Only `Transient` can name a delay.
        assert_eq!(TrackerError::NotConfigured.retry_after(), None);
        assert_eq!(TrackerError::Unauthorized.retry_after(), None);
        assert_eq!(
            TrackerError::Rejected("jira 401".to_owned()).retry_after(),
            None
        );
    }

    #[test]
    fn the_transient_display_states_the_delay_where_one_was_given() {
        let error = TrackerError::Transient {
            retry_after: Some(Duration::from_secs(30)),
        };
        let text = error.to_string();
        assert!(text.contains("retryable"), "{text}");
        assert!(text.contains("30s"), "{text}");

        let text = TrackerError::Transient { retry_after: None }.to_string();
        assert!(text.contains("retryable"), "{text}");
        assert!(text.contains("no delay"), "{text}");
    }

    #[test]
    fn display_sanitizes_the_rejection_text() {
        // The text an adapter wraps is the tracker's own words, and a
        // webhook endpoint is a bearer capability URL: the token it
        // carries in its query must not survive into a log line or a
        // dead-letter row (issue #235's rule, same as `PushError`).
        let error = TrackerError::Rejected(
            "webhook 400 for https://hooks.example.test/services/TOKEN?token=SECRET".to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains("SECRET"), "{text}");
        assert!(text.contains("?[redacted]"), "{text}");

        // A tracker that quotes the account it bounced on quotes an
        // address, and that is scrubbed too.
        let error = TrackerError::Rejected("jira 403 for devops@acme.test".to_owned());
        let text = error.to_string();
        assert!(!text.contains('@'), "{text}");
        assert!(text.contains("[subject_hash:"), "{text}");

        // `Debug` still shows the raw string for a failing test to read.
        assert!(format!("{error:?}").contains("devops@acme.test"));

        assert_eq!(
            TrackerError::NotConfigured.to_string(),
            "tracker is not configured"
        );
    }

    #[test]
    fn an_unsupported_destination_names_the_kind() {
        let error = TrackerError::unsupported_destination(&Destination::Slack {
            channel: "C0123456789".to_owned(),
        });
        let message = error.to_string();
        assert!(message.contains("unsupported destination"), "{message}");
        assert!(message.contains("slack"), "{message}");
    }

    #[test]
    fn an_unauthorized_credential_is_distinct_from_a_rejected_ticket() {
        // Issue #431's fourth variant: the per-tenant credential was
        // refused — wrong, expired, or lacking the scope the call needed —
        // which says something about *who* called, where `Rejected` is the
        // tracker refusing the *ticket* itself.
        let error = TrackerError::Unauthorized;
        assert_eq!(error.to_string(), "tracker refused the credential");
        assert_eq!(error.retry_after(), None, "an auth failure names no delay");
        assert_ne!(error, TrackerError::Rejected("401".to_owned()));
        // `Debug` names the variant, so a failing test can tell the two
        // apart.
        assert!(format!("{error:?}").contains("Unauthorized"));
    }

    // -----------------------------------------------------------------
    // RoutingTracker

    struct Recording {
        seen: std::sync::atomic::AtomicUsize,
        noted: std::sync::atomic::AtomicUsize,
    }

    impl Recording {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: std::sync::atomic::AtomicUsize::new(0),
                noted: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn count(&self) -> usize {
            self.seen.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn note_count(&self) -> usize {
            self.noted.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl Tracker for Recording {
        async fn file(
            &self,
            _dest: &Destination,
            _cred: &Credential,
            _draft: &TicketDraft,
        ) -> Result<Filed, TrackerError> {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Filed {
                external_id: "PROJ-7".to_owned(),
                url: "https://tracker.example.test/browse/PROJ-7".to_owned(),
            })
        }

        async fn status(
            &self,
            _dest: &Destination,
            _cred: &Credential,
            external_id: &str,
        ) -> Result<TicketStatus, TrackerError> {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(TicketStatus {
                external_id: external_id.to_owned(),
                state: TicketState::InProgress,
                url: None,
            })
        }

        async fn comment(
            &self,
            _dest: &Destination,
            _cred: &Credential,
            _external_id: &str,
            _comment: &TicketComment,
        ) -> Result<(), TrackerError> {
            self.noted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    /// An adapter that serves `file`/`status` only and never overrides
    /// `comment` — the shape the existing adapters compile with, so every
    /// call reaches the trait's default impl.
    struct FileOnly;

    #[async_trait]
    impl Tracker for FileOnly {
        async fn file(
            &self,
            _: &Destination,
            _: &Credential,
            _: &TicketDraft,
        ) -> Result<Filed, TrackerError> {
            Err(TrackerError::NotConfigured)
        }

        async fn status(
            &self,
            _: &Destination,
            _: &Credential,
            _: &str,
        ) -> Result<TicketStatus, TrackerError> {
            Err(TrackerError::NotConfigured)
        }
    }

    fn a_draft() -> TicketDraft {
        TicketDraft::new("k", "t", "b", Severity::Info)
    }

    fn a_comment() -> TicketComment {
        TicketComment::new("outbox-43", "Duplicate of the checkout 500s.")
            .with_link("https://reports.example.test/43")
    }

    fn a_freshdesk() -> Destination {
        Destination::Freshdesk {
            domain: "acme.freshdesk.com".to_owned(),
        }
    }

    #[test]
    fn the_default_comment_impl_refuses_by_name() {
        let error = pollster::block_on(FileOnly.comment(
            &a_freshdesk(),
            &Credential::new("t"),
            "PROJ-7",
            &a_comment(),
        ))
        .unwrap_err();
        assert!(matches!(error, TrackerError::Rejected(_)));
        let text = error.to_string();
        assert!(text.contains("does not support comments"), "{text}");
        assert!(text.contains("freshdesk"), "{text}");
    }

    #[test]
    fn a_wired_router_forwards_comment_and_an_empty_slot_refuses() {
        let freshdesk = Recording::new();
        let router = RoutingTracker::new().freshdesk(freshdesk.clone());
        pollster::block_on(router.comment(
            &a_freshdesk(),
            &Credential::new("t"),
            "PROJ-7",
            &a_comment(),
        ))
        .expect("the wired adapter answers");
        assert_eq!(freshdesk.note_count(), 1);

        // A *different* destination on the same router is still
        // NotConfigured, and reaches nothing.
        let other = Destination::Zendesk {
            subdomain: "acme".to_owned(),
        };
        let error = pollster::block_on(router.comment(
            &other,
            &Credential::new("t"),
            "PROJ-7",
            &a_comment(),
        ))
        .unwrap_err();
        assert_eq!(error, TrackerError::NotConfigured);
        assert_eq!(
            freshdesk.note_count(),
            1,
            "the wired adapter was not called"
        );
    }

    #[test]
    fn an_empty_router_is_not_configured_for_every_destination() {
        let router = RoutingTracker::new();
        for dest in all_destinations() {
            let filed = pollster::block_on(router.file(&dest, &Credential::new("t"), &a_draft()));
            assert_eq!(filed.unwrap_err(), TrackerError::NotConfigured, "{dest:?}");
            let status = pollster::block_on(router.status(&dest, &Credential::new("t"), "PROJ-7"));
            assert_eq!(status.unwrap_err(), TrackerError::NotConfigured, "{dest:?}");
            let noted = pollster::block_on(router.comment(
                &dest,
                &Credential::new("t"),
                "PROJ-7",
                &a_comment(),
            ));
            assert_eq!(noted.unwrap_err(), TrackerError::NotConfigured, "{dest:?}");
            assert!(router.route_for(&dest).is_none());
        }
    }

    #[test]
    fn a_wired_slot_reaches_its_adapter_and_the_rest_stay_not_configured() {
        let github = Recording::new();
        let router = RoutingTracker::new().github(github.clone());

        let dest = Destination::GitHub {
            owner: "acme".to_owned(),
            repo: "api".to_owned(),
        };
        let filed = pollster::block_on(router.file(&dest, &Credential::new("t"), &a_draft()))
            .expect("the wired adapter answers");
        assert_eq!(filed.external_id, "PROJ-7");
        let status = pollster::block_on(router.status(&dest, &Credential::new("t"), "PROJ-7"))
            .expect("the wired adapter answers");
        assert_eq!(status.state, TicketState::InProgress);
        assert_eq!(github.count(), 2);
        assert!(router.route_for(&dest).is_some());

        // A *different* destination on the same router is still
        // NotConfigured, and reaches nothing.
        let other = Destination::Slack {
            channel: "C0123456789".to_owned(),
        };
        let error =
            pollster::block_on(router.file(&other, &Credential::new("t"), &a_draft())).unwrap_err();
        assert_eq!(error, TrackerError::NotConfigured);
        assert_eq!(github.count(), 2, "the wired adapter was not called");
        assert!(router.route_for(&other).is_none());
    }

    #[test]
    fn every_destination_dispatches_to_the_adapter_wired_for_its_slot() {
        // A transposition is the one bug the tests above cannot see: the
        // empty router answers NotConfigured under any permutation of
        // `route_for`'s eleven arms, and the wiring test pins a single arm.
        // A hand-written eleven-way match is exactly where a swapped arm
        // hides, so this wires a distinct adapter into every slot and
        // requires each destination to reach *its own* adapter — the
        // identity assert names the pair, and a swap shows up as one
        // adapter at 0 and another at 2.
        let github = Recording::new();
        let jira = Recording::new();
        let linear = Recording::new();
        let zendesk = Recording::new();
        let freshdesk = Recording::new();
        let intercom = Recording::new();
        let salesforce = Recording::new();
        let hubspot = Recording::new();
        let slack = Recording::new();
        let webhook = Recording::new();
        let colonizer = Recording::new();

        let router = RoutingTracker::new()
            .github(github.clone())
            .jira(jira.clone())
            .linear(linear.clone())
            .zendesk(zendesk.clone())
            .freshdesk(freshdesk.clone())
            .intercom(intercom.clone())
            .salesforce(salesforce.clone())
            .hubspot(hubspot.clone())
            .slack(slack.clone())
            .webhook(webhook.clone())
            .colonizer(colonizer.clone());

        // In `all_destinations()`'s order; the identity assert below fails
        // loudly if that helper's order and this list ever drift apart.
        let slots = [
            github, jira, linear, zendesk, freshdesk, intercom, salesforce, hubspot, slack,
            webhook, colonizer,
        ];

        for (dest, adapter) in all_destinations().into_iter().zip(slots) {
            // Identity, not mere presence: `route_for` must hand back this
            // exact adapter, so a destination cannot quietly borrow a
            // neighbour's slot.
            let wired: Arc<dyn Tracker> = adapter.clone();
            assert!(
                Arc::ptr_eq(router.route_for(&dest).expect("wired"), &wired),
                "{dest:?} routed to the wrong slot",
            );

            pollster::block_on(router.file(&dest, &Credential::new("t"), &a_draft()))
                .expect("the wired adapter answers");
            assert_eq!(adapter.count(), 1, "{dest:?} reached the wrong adapter");
            pollster::block_on(router.status(&dest, &Credential::new("t"), "PROJ-7"))
                .expect("the wired adapter answers");
            assert_eq!(adapter.count(), 2, "status did not reuse the slot");
        }
    }

    #[test]
    fn the_router_debug_prints_only_wiring_not_adapters() {
        let router = RoutingTracker::new().jira(Recording::new());
        let printed = format!("{router:?}");
        assert!(printed.contains("RoutingTracker"), "{printed}");
        assert!(printed.contains("jira: true"), "{printed}");
        assert!(printed.contains("github: false"), "{printed}");
        assert!(printed.contains("webhook: false"), "{printed}");
    }

    // -----------------------------------------------------------------
    // Inbound status webhooks

    /// A Jira-Cloud-shaped hook, written with a plain `ProviderScheme` to
    /// prove a vendor whose signature needs **no timestamp header** is
    /// expressible without any new scheme code: `X-Hub-Signature:
    /// sha256=<hex>`, HMAC-SHA256 over the raw body.
    struct JiraHook {
        parse_saw_bytes: std::sync::atomic::AtomicBool,
    }

    impl StatusWebhook for JiraHook {
        fn kind(&self) -> &'static str {
            "jira"
        }

        fn verifier(&self) -> WebhookVerifier {
            WebhookVerifier::new(ProviderScheme {
                signature: "X-Hub-Signature",
                encoding: SignatureEncoding::Hex,
                prefix: Some("sha256="),
                timestamp: None,
            })
        }

        fn parse(&self, body: &[u8]) -> Result<Option<StatusUpdate>, InboundStatusError> {
            self.parse_saw_bytes
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let event: serde_json::Value = serde_json::from_slice(body)
                .map_err(|error| InboundStatusError::Malformed(error.to_string()))?;
            let Some(status) = event.get("status").and_then(serde_json::Value::as_str) else {
                // A verified event with no status in it — a ping, a
                // comment — is a no-op, not an error.
                return Ok(None);
            };
            Ok(Some(StatusUpdate {
                external_id: event["ticket"].as_str().unwrap_or_default().to_owned(),
                state: if status == "done" {
                    TicketState::Closed
                } else {
                    TicketState::Unknown
                },
                url: event["url"].as_str().map(ToOwned::to_owned),
            }))
        }
    }

    /// The `sha256=<hex>` signature Jira Cloud would send for this body.
    fn jira_signature(secret: &str, body: &[u8]) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        use std::fmt::Write as _;

        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("any key length");
        mac.update(body);
        mac.finalize()
            .into_bytes()
            .iter()
            .fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    fn sig_headers(name: &str, value: &str) -> HeaderMap {
        [(
            name.parse::<http::header::HeaderName>()
                .expect("test header name"),
            value
                .parse::<http::HeaderValue>()
                .expect("test header value"),
        )]
        .into_iter()
        .collect()
    }

    #[test]
    fn receive_status_refuses_a_bad_signature_without_parsing() {
        let hook = JiraHook {
            parse_saw_bytes: std::sync::atomic::AtomicBool::new(false),
        };
        let body = br#"{"ticket":"PROJ-7","status":"done"}"#;
        let signed = sig_headers(
            "X-Hub-Signature",
            &format!("sha256={}", jira_signature("right-secret", body)),
        );

        // A wrong secret, a tampered body, an unreadable header — all
        // `Signature`, and `parse` never ran on any of them.
        assert_eq!(
            receive_status(&hook, "wrong-secret", &signed, body, 0).unwrap_err(),
            InboundStatusError::Signature
        );
        let tampered = receive_status(&hook, "right-secret", &signed, b"{}", 0).unwrap_err();
        assert_eq!(tampered, InboundStatusError::Signature);
        let unsigned =
            receive_status(&hook, "right-secret", &HeaderMap::new(), body, 0).unwrap_err();
        assert_eq!(unsigned, InboundStatusError::Signature);
        assert!(
            !hook
                .parse_saw_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
        );
    }

    #[test]
    fn receive_status_parses_a_verified_state_change() {
        let hook = JiraHook {
            parse_saw_bytes: std::sync::atomic::AtomicBool::new(false),
        };
        let body = br#"{"ticket":"PROJ-7","status":"done","url":"https://jira.example.test/browse/PROJ-7"}"#;
        let signed = sig_headers(
            "X-Hub-Signature",
            &format!("sha256={}", jira_signature("right-secret", body)),
        );
        let update = receive_status(&hook, "right-secret", &signed, body, 0)
            .expect("the signature verifies");
        assert_eq!(
            update,
            Some(StatusUpdate {
                external_id: "PROJ-7".to_owned(),
                state: TicketState::Closed,
                url: Some("https://jira.example.test/browse/PROJ-7".to_owned()),
            })
        );
        assert!(
            hook.parse_saw_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
        );

        // A verified event carrying no status change is `Ok(None)`.
        let ping = br#"{"kind":"ping"}"#;
        let pinged = sig_headers(
            "X-Hub-Signature",
            &format!("sha256={}", jira_signature("right-secret", ping)),
        );
        assert_eq!(
            receive_status(&hook, "right-secret", &pinged, ping, 0).expect("verified"),
            None
        );
    }

    #[test]
    fn receive_status_maps_a_verified_but_unreadable_body_to_malformed() {
        let hook = JiraHook {
            parse_saw_bytes: std::sync::atomic::AtomicBool::new(false),
        };
        let body = br"not json at all - https://hooks.example.test/TOKEN?token=SECRET";
        let signed = sig_headers(
            "X-Hub-Signature",
            &format!("sha256={}", jira_signature("right-secret", body)),
        );
        let error = receive_status(&hook, "right-secret", &signed, body, 0).unwrap_err();
        assert!(matches!(error, InboundStatusError::Malformed(_)));
        assert!(error.to_string().contains("malformed"));

        // The text an adapter wraps can quote the payload it could not
        // read — a webhook URL's token, a tenant name — so `Display`
        // scrubs it the way `TrackerError::Rejected` does, and `Debug`
        // keeps the raw string for a failing test.
        let error = InboundStatusError::Malformed(
            "vendor said: https://hooks.example.test/TOKEN?token=SECRET".to_owned(),
        );
        let text = error.to_string();
        assert!(!text.contains("SECRET"), "{text}");
        assert!(format!("{error:?}").contains("SECRET"));
    }
}
