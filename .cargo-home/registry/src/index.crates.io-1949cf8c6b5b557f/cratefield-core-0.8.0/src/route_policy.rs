//! Route protection policies and the production abuse gate (issue #133).
//!
//! Every declared write route carries an explicit [`RoutePolicy`]: it is
//! open, protected by a human-form CAPTCHA, or protected by a machine
//! signature (a provider webhook). The old shape — a bare `captcha: bool`
//! plus the module-level `public_writes()` flag consulted only by
//! `fz doctor` — let a webhook satisfy "has captcha" while simultaneously
//! getting a captcha widget rendered on it, and left production booting
//! with no verification at all as long as nobody ran the doctor.
//!
//! [`WriteGuards::collect`] reads the composed modules and says what the
//! venture demands; [`production_readiness`] turns that plus what the
//! runtime can actually do into build errors. `HarnessBuilder::build`
//! calls it — enforcement moved from a CLI report to runtime
//! initialization — and `fz doctor` keeps calling the same function as an
//! advisory re-check, the way it re-checks `harness_api` (issue #17).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::harness::Runtime;
use crate::module::Module;
use crate::ports::{Captcha, Port};
use crate::problem::Problem;
use crate::problems::SLUGS;
use crate::surface::{Action, Audience, Surface};
use crate::venture::VentureEnv;

/// How a request to a declared route proves it is legitimate.
///
/// The variants are mutually exclusive by construction: a route is
/// protected by a human proof, a machine signature, an artifact this
/// service issued, or nothing — never two of them, and never by
/// whichever check the module happened to wire up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RoutePolicy {
    /// No gateway-level protection. The default, and correct for reads
    /// and for anything the handler authenticates itself.
    #[default]
    Open,
    /// A public form submission from a browser. The handler verifies the
    /// `captchaToken` the renderer supplies through the `Captcha` port,
    /// and `Harness::build` refuses to boot a production venture whose
    /// runtime cannot actually do that ([`captcha_effective`]).
    HumanForm,
    /// An authenticated machine caller — a provider webhook. The handler
    /// proves the delivery with the module's declared verifier
    /// ([`SignatureVerification`]: `Payments::verify_webhook` by default,
    /// or a `webhook_signature` scheme) plus the [`Inbox`] dedup ledger. A
    /// CAPTCHA is meaningless here (the caller has no browser) and must
    /// never be rendered or required on such a route.
    ///
    /// [`Payments::verify_webhook`]: crate::ports::Payments::verify_webhook
    /// [`Inbox`]: crate::idempotency::Inbox
    Signature,
    /// A public write whose proof is a single-use, purpose-bound
    /// artifact **this service issued**: a magic link, a passkey or OAuth
    /// challenge, an unsubscribe link (issue #143). The caller presents
    /// something only a prior request of ours could have produced, so the
    /// gate is the [`Signer`] key ring (issue #137), not a widget.
    ///
    /// This variant exists because the auth login methods had nowhere
    /// honest to sit. They are public writers with no ADR 0010 surface,
    /// so [`WriteGuards::collect`]'s conservative fallback filed them
    /// under CAPTCHA — and a passkey challenge will never render one. A
    /// production venture composing only auth modules therefore could not
    /// boot at all except through `fz doctor --allow-no-captcha`, an
    /// override the code itself documents as previews-only. This is not
    /// an exemption: it carries its own production requirement, a
    /// usable [`Signer`], because without one there is nothing to issue
    /// or verify the artifact with.
    ///
    /// [`Signer`]: crate::ports::Signer
    SignedLink,
    /// An authenticated developer caller (issue #532): the request
    /// presents `Authorization: Bearer <api key>` and the handler gates
    /// it through [`require_api_key`], which verifies the key's hash and
    /// checks one scope. A CAPTCHA is meaningless here (the caller is a
    /// machine) and must never be rendered or required on such a route —
    /// the same rule as [`RoutePolicy::Signature`].
    ///
    /// This variant carries no scope on purpose: a `RoutePolicy` is
    /// `Copy` + serde and travels through surface documents, so it
    /// cannot hold a per-action string. The route policy says *how* the
    /// route is guarded; the scope is the handler's per-request argument
    /// to `require_api_key`.
    ///
    /// [`require_api_key`]: crate::api_key::require_api_key
    ApiKey,
}

impl RoutePolicy {
    /// Whether this policy is a protection (as opposed to [`RoutePolicy::Open`]).
    #[must_use]
    pub fn is_guarded(self) -> bool {
        self != Self::Open
    }
}

/// Which verifier proves a module's [`RoutePolicy::Signature`] deliveries
/// (issue #533): the `Payments` port — the default every existing module was
/// built against — or the core `webhook_signature` HMAC scheme keyed by the
/// module's own config secret. The production gate demands whichever the
/// module named, never both and never neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerification {
    /// `Payments::verify_webhook` — the default; production requires an
    /// effective `Payments` port.
    Payments,
    /// A `webhook_signature` scheme keyed by a module-scoped config secret:
    /// `secret` is a [`ModuleConfig`](crate::config::ModuleConfig)
    /// **suffix**, read as `{MODULE}_{SECRET}` (`"WEBHOOK_SECRET"` on module
    /// `pos` is `POS_WEBHOOK_SECRET`). Production requires that key — see
    /// [`webhook_secret_readiness`] — and no `Payments` port.
    Hmac {
        /// The module-scoped config key suffix holding the shared secret.
        secret: &'static str,
    },
}

/// What the composed modules demand of the runtime, module by module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteGuards {
    /// Modules with a [`RoutePolicy::HumanForm`]-guarded write (or the
    /// conservative fallback: [`public_writes`] and no declared policy at all).
    ///
    /// [`public_writes`]: Module::public_writes
    pub captcha_modules: Vec<String>,
    /// Modules with a [`RoutePolicy::Signature`]-guarded write (webhooks),
    /// however they verify them.
    pub signature_modules: Vec<String>,
    /// The signature modules that prove their deliveries through
    /// `Payments::verify_webhook` — the default [`SignatureVerification`].
    pub payments_signature_modules: Vec<String>,
    /// The signature modules proving their deliveries with a
    /// `webhook_signature` scheme (issue #533), paired with the
    /// [`ModuleConfig`](crate::config::ModuleConfig) **suffix** of the key
    /// holding each secret; [`Self::hmac_signature_secrets`] composes the
    /// full keys.
    pub hmac_signature_modules: Vec<(String, &'static str)>,
    /// Modules whose public writes are proved by an artifact this service
    /// issued ([`RoutePolicy::SignedLink`], issue #143).
    pub signed_link_modules: Vec<String>,
    /// Whether the composition exposes any **public write** at all
    /// (issue #437): a declared guarded action of any kind — a captcha
    /// form, a webhook, a signed link — or the module-level
    /// [`public_writes`] flag for modules that predate surfaces. Broader
    /// than the three lists above by design: a webhook is an
    /// unauthenticated endpoint too, and the rate-limiter leg of
    /// [`production_readiness`] cares that *something* is writable, not
    /// by which proof. A [`RoutePolicy::ApiKey`] write demands no
    /// `RateLimiter` here: per-key limiting happens only where a handler
    /// calls `check_rate_limit` with
    /// [`ApiKeyPrincipal::rate_limit_key`] and a limiter is wired.
    ///
    /// [`public_writes`]: Module::public_writes
    /// [`ApiKeyPrincipal::rate_limit_key`]: crate::api_key::ApiKeyPrincipal::rate_limit_key
    pub has_public_writes: bool,
    /// Whether any declared action is the **admin plane** (issue #437):
    /// an [`Audience::Admin`] action, or any path under `/admin`. An
    /// admin route's bearer token is guessed rather than submitted, so
    /// it needs a budget even when the venture has no public writes —
    /// which is why this is its own answer and not a byproduct of
    /// [`Self::has_public_writes`].
    pub has_admin_routes: bool,
    /// Modules that **declare** `Port::RateLimiter` — in `requires()` or
    /// `optional()` — and expose public routes, each paired with those
    /// routes named `METHOD /v1/<module><path>` (issue #562). A module
    /// saying it throttles is a claim about the routes it publishes, so
    /// the readiness gate reads both halves: the declaration from the
    /// module, the routes from its surface. Public here is
    /// [`Surface::public`](crate::surface::Surface::public)'s renderer
    /// answer minus `Audience::Subject` — reachable without an
    /// authenticated principal, the admin plane excluded
    /// (`has_admin_routes` already speaks for it), webhooks and API-key
    /// routes excluded (`has_public_writes` already speaks for the
    /// webhook, and an API-key route's budget is the per-key hook).
    /// Empty for sidecar surfaces ([`Self::from_surface`]): a merged
    /// document carries no `requires()`/`optional()` to read, and its
    /// public writes and admin routes stay under the two legs above.
    pub rate_limiter_modules: Vec<(String, Vec<String>)>,
    /// Every declared [`RoutePolicy::Signature`] route, named the way the
    /// readiness error names it (`METHOD /v1/<module><path>`), with the
    /// verifier it resolved to (issue #595) — the action's own
    /// [`verification`](crate::surface::Action::verification) when it
    /// names one, else the module's
    /// [`signature_verification`](Module::signature_verification). The
    /// production gate and `fz doctor` read this to name the exact route a
    /// missing `Payments` port or HMAC secret blocks, instead of blaming
    /// the whole module. A module that reached the signature gate through
    /// the surface-less fallback declares no route and contributes none.
    pub signature_routes: Vec<(String, String, SignatureVerification)>,
}

impl WriteGuards {
    /// Reads each module's declared surface. A module whose surface has
    /// no policy-guarded write but still sets [`public_writes`] counts as
    /// needing a CAPTCHA — the undeclared-public-writer fallback keeps
    /// out-of-tree and surface-less modules (the auth crates predate
    /// ADR 0010 surfaces) under the same gate instead of silently
    /// exempting them.
    ///
    /// [`public_writes`]: Module::public_writes
    #[must_use]
    pub fn collect(modules: &[Arc<dyn Module>]) -> Self {
        let mut guards = Self::default();
        for module in modules {
            let surface: Surface = module.surface();
            let (mut form, mut signature) = Self::surface_flags(&surface);
            let mut signed_link = surface
                .actions
                .iter()
                .any(|action| action.policy == RoutePolicy::SignedLink);
            // The undeclared-public-writer fallback only applies when
            // nothing in the surface is guarded. What it falls back *to*
            // is the module's own answer (issue #143): a surface-less
            // module has no action to hang a policy on, so this is the
            // only place it can say what protects its writes. The default
            // is still `HumanForm`, so saying nothing changes nothing.
            if !form && !signature && !signed_link && module.public_writes() {
                match module.public_write_policy() {
                    RoutePolicy::Signature => signature = true,
                    RoutePolicy::SignedLink => signed_link = true,
                    // An API-key writer (issue #532) is guarded — it is
                    // never pulled into the captcha fallback — but it
                    // demands no runtime port (the key store is the
                    // app's) and no production-legible decision: its
                    // budget is the per-key limiter hook, not a boot
                    // gate.
                    RoutePolicy::ApiKey => {}
                    RoutePolicy::HumanForm | RoutePolicy::Open => form = true,
                }
            }
            if form {
                guards.captcha_modules.push(module.name().to_owned());
            }
            if signature {
                guards.signature_modules.push(module.name().to_owned());
                // Resolve each Signature route's verifier (issue #595): the
                // action's own, else the module-level default. A module
                // with no declared Signature route — the surface-less
                // fallback above — resolves through the default alone and
                // has no route to name.
                let declared: Vec<(String, SignatureVerification)> = surface
                    .actions
                    .iter()
                    .filter(|action| action.policy == RoutePolicy::Signature)
                    .map(|action| {
                        (
                            Self::mounted_route(module.name(), action),
                            action
                                .verification
                                .unwrap_or_else(|| module.signature_verification()),
                        )
                    })
                    .collect();
                let routes = if declared.is_empty() {
                    vec![(String::new(), module.signature_verification())]
                } else {
                    declared
                };
                let mut wants_payments = false;
                for (route, verifier) in routes {
                    match verifier {
                        SignatureVerification::Payments => wants_payments = true,
                        // Dedupe on `(module, suffix)`: one module may
                        // name the same secret on several routes.
                        SignatureVerification::Hmac { secret } => {
                            if !guards
                                .hmac_signature_modules
                                .iter()
                                .any(|(m, s)| m == module.name() && *s == secret)
                            {
                                guards
                                    .hmac_signature_modules
                                    .push((module.name().to_owned(), secret));
                            }
                        }
                    }
                    if !route.is_empty() {
                        guards
                            .signature_routes
                            .push((module.name().to_owned(), route, verifier));
                    }
                }
                if wants_payments {
                    guards
                        .payments_signature_modules
                        .push(module.name().to_owned());
                }
            }
            if signed_link {
                guards.signed_link_modules.push(module.name().to_owned());
            }
            // The limiter leg (issue #437) asks two broader questions
            // than the per-policy lists: is anything writable publicly
            // at all, and is there an admin plane to brute-force. The
            // path check is the surface validation rule (`Audience::Admin`
            // lives under `/admin`), applied in both directions so an
            // undeclared admin path is caught even when the audience is
            // missing.
            if form || signature || signed_link || module.public_writes() {
                guards.has_public_writes = true;
            }
            if Self::declares_admin_routes(&surface) {
                guards.has_admin_routes = true;
            }
            // The declaration-keyed half of the limiter leg (issue #562):
            // a module that declares `Port::RateLimiter` claims it
            // throttles its public routes, and the readiness gate holds
            // the composition to that claim even when nothing here is a
            // public *write* — a public search endpoint is throttled
            // surface all the same. Routes ride along so the error can
            // name what runs unlimited.
            if module.requires().contains(&Port::RateLimiter)
                || module.optional().contains(&Port::RateLimiter)
            {
                let routes = Self::public_limiter_routes(module.name(), &surface);
                if !routes.is_empty() {
                    guards
                        .rate_limiter_modules
                        .push((module.name().to_owned(), routes));
                }
            }
        }
        guards
    }

    /// The guards a **declared surface** demands (issue #131). A sidecar's
    /// merged surface is not a [`Module`] this process can ask
    /// [`public_writes`](Module::public_writes) or
    /// [`signature_verification`](Module::signature_verification) of, so
    /// whatever the document declares is exactly what it needs, and a
    /// signature route that names no verifier verifies through `Payments`,
    /// the default (issues #533, #595). Same per-action reading as
    /// [`Self::collect`]
    /// through the one [`Action::demands_captcha`] predicate and the one
    /// `declares_admin_routes` predicate — a sidecar's admin plane needs
    /// the limiter floor as much as an in-process module's.
    ///
    /// [`Action::demands_captcha`]: crate::surface::Action::demands_captcha
    #[must_use]
    pub fn from_surface(module: &str, surface: &Surface) -> Self {
        let (form, signature) = Self::surface_flags(surface);
        let signed_link = surface
            .actions
            .iter()
            .any(|action| action.policy == RoutePolicy::SignedLink);
        // A sidecar cannot ask a module for its default, so an action that
        // names no verifier verifies through `Payments` — the pre-#533
        // behaviour, now resolved per route (issue #595).
        let mut payments = false;
        let mut hmac_signature_modules: Vec<(String, &'static str)> = Vec::new();
        let mut signature_routes = Vec::new();
        for action in &surface.actions {
            if action.policy != RoutePolicy::Signature {
                continue;
            }
            let verifier = action
                .verification
                .unwrap_or(SignatureVerification::Payments);
            signature_routes.push((
                module.to_owned(),
                Self::mounted_route(module, action),
                verifier,
            ));
            match verifier {
                SignatureVerification::Payments => payments = true,
                SignatureVerification::Hmac { secret } => {
                    if !hmac_signature_modules.iter().any(|(_, s)| *s == secret) {
                        hmac_signature_modules.push((module.to_owned(), secret));
                    }
                }
            }
        }
        Self {
            captcha_modules: form.then(|| module.to_owned()).into_iter().collect(),
            signature_modules: signature.then(|| module.to_owned()).into_iter().collect(),
            payments_signature_modules: payments.then(|| module.to_owned()).into_iter().collect(),
            hmac_signature_modules,
            signed_link_modules: signed_link.then(|| module.to_owned()).into_iter().collect(),
            has_public_writes: form || signature || signed_link,
            has_admin_routes: Self::declares_admin_routes(surface),
            // No declaration to read (see `rate_limiter_modules`): a
            // sidecar's public writes and admin routes stay under the
            // two legs above.
            rate_limiter_modules: Vec::new(),
            signature_routes,
        }
    }

    /// Whether any action needs a captcha and whether any is a signature
    /// route. The `Open`-with-`captcha` legacy mirror resolves inside
    /// [`Action::demands_captcha`].
    fn surface_flags(surface: &Surface) -> (bool, bool) {
        let mut form = false;
        let mut signature = false;
        for action in &surface.actions {
            if action.demands_captcha() {
                form = true;
            }
            if action.policy == RoutePolicy::Signature {
                signature = true;
            }
        }
        (form, signature)
    }

    /// Whether the surface declares the admin plane: an
    /// [`Audience::Admin`](crate::surface::Audience::Admin) action, or any
    /// path under `/admin`. Both spellings, so an action whose audience was
    /// forgotten is still counted by where it sits — the same rule
    /// [`Surface::validate`] enforces, read here instead of trusted.
    ///
    /// [`Surface::validate`]: crate::surface::Surface::validate
    fn declares_admin_routes(surface: &Surface) -> bool {
        surface.actions.iter().any(|action| {
            action.audience == Audience::Admin
                || action.path == "/admin"
                || action.path.starts_with("/admin/")
        })
    }

    /// Whether any module proves a public write with an artifact this
    /// service issued, and so needs a usable [`Signer`] (issue #143).
    ///
    /// [`Signer`]: crate::ports::Signer
    #[must_use]
    pub fn needs_signer(&self) -> bool {
        !self.signed_link_modules.is_empty()
    }

    /// Whether any module needs the `Captcha` port.
    #[must_use]
    pub fn needs_captcha(&self) -> bool {
        !self.captcha_modules.is_empty()
    }

    /// Whether any module proves a public write with
    /// [`Payments::verify_webhook`](crate::ports::Payments). Since issue
    /// #533 this is no longer "some module receives signed webhooks": a
    /// module may declare [`SignatureVerification::Hmac`] and verify with
    /// the core `webhook_signature` scheme instead, and this answers
    /// `false` for it — its production requirement is its secret key, not a
    /// port (see [`webhook_secret_readiness`]). The `STRIPE_WEBHOOK_SECRET`
    /// doctor rule is keyed on this, correctly.
    #[must_use]
    pub fn needs_payments(&self) -> bool {
        !self.payments_signature_modules.is_empty()
    }

    /// The HMAC-verified signature modules and the **full** config key each
    /// reads its secret from, composed through
    /// [`ModuleConfig`](crate::config::ModuleConfig)'s `{MODULE}_{SUFFIX}`
    /// rule — the one place the prefix logic lives (issue #533).
    #[must_use]
    pub fn hmac_signature_secrets(&self) -> Vec<(String, String)> {
        self.hmac_signature_modules
            .iter()
            .map(|(module, suffix)| {
                let key = crate::config::ModuleConfig::new(module, &crate::config::EmptyConfig)
                    .key(suffix);
                (module.clone(), key)
            })
            .collect()
    }

    /// The HMAC-verified signature modules, the **full** config key each
    /// reads its secret from, and the `METHOD /v1/<module><path>` routes
    /// that read it (issue #595) — the shape `webhook_secret_readiness`
    /// and `fz doctor` name a missing secret by, so a module with a Stripe
    /// route and a `RevenueCat` route says which one the unset key blocks.
    #[must_use]
    pub fn hmac_signature_routes(&self) -> Vec<(String, String, Vec<String>)> {
        self.hmac_signature_secrets()
            .into_iter()
            .zip(&self.hmac_signature_modules)
            .map(|((module, key), (_, secret))| {
                let routes =
                    self.signature_routes_for(&module, SignatureVerification::Hmac { secret });
                (module, key, routes)
            })
            .collect()
    }

    /// The routes `module` verifies with `verifier`, named
    /// `METHOD /v1/<module><path>` (issue #595), so a readiness error can
    /// point at the route instead of the whole module. Empty when the
    /// module declared no surface route (the surface-less fallback).
    #[must_use]
    pub fn signature_routes_for(
        &self,
        module: &str,
        verifier: SignatureVerification,
    ) -> Vec<String> {
        self.signature_routes
            .iter()
            .filter(|(m, _, v)| m == module && *v == verifier)
            .map(|(_, route, _)| route.clone())
            .collect()
    }

    /// `module (METHOD /v1/<module><path>, ...)`, or the bare module name
    /// when it declared no route (the surface-less fallback) — the way the boot
    /// gate and `fz doctor` name a signature module in a message
    /// (issue #595).
    #[must_use]
    pub fn signature_module_named(&self, module: &str, verifier: SignatureVerification) -> String {
        let routes = self.signature_routes_for(module, verifier);
        if routes.is_empty() {
            module.to_owned()
        } else {
            format!("{module} ({})", routes.join(", "))
        }
    }

    /// One action named the way a readiness error names it:
    /// `METHOD /v1/<module><path>` (issues #562, #595). The surface stores
    /// paths relative to the module's mount, so the mount is composed back
    /// on here — an error should name the URL that runs, not a
    /// surface-internal fragment. The index action is declared `/`, and the
    /// mounted URL has no trailing slash to name.
    fn mounted_route(module: &str, action: &Action) -> String {
        let path = action.path.trim_end_matches('/');
        if path.is_empty() {
            format!("{} /v1/{module}", action.method)
        } else {
            format!("{} /v1/{module}{path}", action.method)
        }
    }

    /// The module's public routes, named the way the readiness error names
    /// them: `METHOD /v1/<module><path>` (issue #562).
    fn public_limiter_routes(module: &str, surface: &Surface) -> Vec<String> {
        surface
            .actions
            .iter()
            .filter(|action| {
                action.audience != Audience::Admin
                    && action.audience != Audience::Subject
                    && action.policy != RoutePolicy::Signature
                    && action.policy != RoutePolicy::ApiKey
            })
            .map(|action| Self::mounted_route(module, action))
            .collect()
    }

    /// Whether any route in the composition needs a limiter sitting in
    /// front of it (issues #437, #562): a public write, an admin route,
    /// or a module that declares `Port::RateLimiter` over public routes.
    /// The admin plane is enough on its own — a bearer token is guessed,
    /// not submitted, so a venture that publishes nothing still needs the
    /// budget before its `/admin/*` routes — and a module declaring the
    /// port is a claim to throttle that the gate holds the venture to
    /// even when nothing it publishes is a write.
    #[must_use]
    pub fn needs_rate_limiter(&self) -> bool {
        self.has_public_writes || self.has_admin_routes || !self.rate_limiter_modules.is_empty()
    }
}

/// Whether the runtime's `Captcha` port can really verify a token in
/// production: the port is provided **and**, when the adapter reports,
/// hostname-bound and not fail-open. An adapter that does not report
/// ([`Captcha::binding`] = `None`) counts as effective — presence is all
/// the harness can know about a third-party implementation; the adapter
/// contract carries the duty to fail closed per request.
///
/// [`Captcha::binding`]: crate::ports::Captcha::binding
#[must_use]
pub fn captcha_effective(runtime: Option<&Arc<dyn Runtime>>) -> bool {
    runtime.is_some_and(|runtime| runtime.effectively_configured(Port::Captcha))
}

/// Whether the runtime can verify webhook signatures for the
/// [`RoutePolicy::Signature`]-guarded routes whose modules verify through
/// `Payments` (the default): signature verification is the adapter's
/// per-request duty (`verify_webhook` + `Inbox`), and which secret it
/// checks against is deploy configuration. A module that declared
/// [`SignatureVerification::Hmac`] is not this function's business — its
/// production requirement is its secret key, checked by
/// [`webhook_secret_readiness`].
#[must_use]
pub fn payments_effective(runtime: Option<&Arc<dyn Runtime>>) -> bool {
    runtime.is_some_and(|runtime| runtime.effectively_configured(Port::Payments))
}

/// The boot-time leg for HMAC-verified signature modules (issue #533): in
/// production, each one's configured secret key must be present and
/// non-blank, or the module's handler refuses every delivery. The errors
/// name the module and the config key, never the value, and there is no
/// waiver: an operator who wants the endpoint unverified removes the
/// route, which is a build-time decision. Run by the boot gate
/// ([`Harness::router`](crate::Harness::router)'s readiness re-check),
/// which holds the deployment config; the build-time gate has none, so it
/// skips this leg — the same split as the overrides there.
#[must_use]
pub fn webhook_secret_readiness(
    env: VentureEnv,
    guards: &WriteGuards,
    config: &dyn crate::config::Config,
) -> Vec<String> {
    if env != VentureEnv::Production {
        return Vec::new();
    }
    guards
        .hmac_signature_routes()
        .into_iter()
        .filter(|(_, key, _)| config.get(key).is_none_or(|value| value.trim().is_empty()))
        .map(|(module, key, routes)| {
            // Name the route(s) the unset key blocks (issue #595): a
            // module may verify one webhook with `Payments` and another
            // with this secret, so blaming the whole module would not say
            // which endpoint refuses every delivery.
            let on = if routes.is_empty() {
                String::new()
            } else {
                format!(" on {}", routes.join(", "))
            };
            format!(
                "production venture verifies `{module}` webhook signatures with the \
                 webhook_signature HMAC scheme but `{key}` is not set — its handler refuses \
                 every delivery{on} until the provider's signing secret is configured"
            )
        })
        .collect()
}

/// The operator's reason, if they actually gave one.
///
/// `docs/SECURITY.md` puts it in four words — "A blank reason is not an
/// acceptance" — and `unprotected_writes_override` already enforced it
/// for `HARNESS_ALLOW_UNPROTECTED_WRITES`. The `fz doctor` flag reached
/// the same gate without it: `--allow-no-captcha ""` arrives as
/// `Some("")`, which waived a production abuse control and recorded an
/// empty reason for it. A waiver with nothing to answer for is the
/// silent default the gate exists to remove.
///
/// One function, so the two ways to the same waiver cannot disagree
/// again.
#[must_use]
pub fn stated_reason(reason: Option<&str>) -> Option<&str> {
    reason.map(str::trim).filter(|reason| !reason.is_empty())
}

/// Config key holding an operator's explicit, recorded acceptance that
/// this deployment serves guarded routes it cannot fully protect
/// (issue #143).
///
/// The value is the **reason**, and an empty one does not count: an
/// override with nothing to answer for is the silent default this issue
/// exists to remove. It is recorded through `tracing` on every boot, so
/// it appears wherever the operator ships logs, and `fz doctor` reports
/// it. It exists because the gate landed on ventures that had already
/// been serving unprotected for months — refusing their traffic outright
/// on the next deploy would trade a quiet hole for a loud outage without
/// anyone choosing it. Wire the missing port and delete the key.
pub const ALLOW_UNPROTECTED_WRITES: &str = "HARNESS_ALLOW_UNPROTECTED_WRITES";

/// The operator's recorded reason for serving guarded routes unprotected,
/// if they set one (issue #143).
#[must_use]
pub fn unprotected_writes_override(config: &dyn crate::config::Config) -> Option<String> {
    config
        .get(ALLOW_UNPROTECTED_WRITES)
        .and_then(|raw| stated_reason(Some(raw.as_str())).map(str::to_owned))
}

/// Config key holding an operator's explicit, recorded acceptance that
/// this deployment serves its public writes and admin routes with **no
/// resolved rate limiter** (issue #437). Same contract as
/// [`ALLOW_UNPROTECTED_WRITES`]: the value is the **reason**, and a blank
/// one does not count; the boot gate records it once, wherever the
/// operator ships logs. It exists because the limiter was opt-in — a
/// runtime that failed to resolve its binding degraded to no limiter and
/// served — and because the escape from that must be as deliberate as the
/// gap it accepts. Resolve the binding and delete the key.
pub const ALLOW_UNLIMITED_PUBLIC_ROUTES: &str = "HARNESS_ALLOW_UNLIMITED_PUBLIC_ROUTES";

/// The operator's recorded reason for serving public writes and admin
/// routes unlimited, if they set one (issue #437).
#[must_use]
pub fn unlimited_public_routes_override(config: &dyn crate::config::Config) -> Option<String> {
    config
        .get(ALLOW_UNLIMITED_PUBLIC_ROUTES)
        .and_then(|raw| stated_reason(Some(raw.as_str())).map(str::to_owned))
}

/// The environment this **deployment** runs in (issue #143).
///
/// A venture carries a compiled [`VentureEnv`] — a builder default the
/// operator cannot change without a rebuild — and a deployment carries
/// an `ENV` binding it can. Every production-only rule used to read the
/// compiled one alone, so a Worker deployed with `ENV = "production"`
/// over a venture that never called [`Venture::env`] ran with all of
/// them switched off. Neither source may downgrade the other: if either
/// says `Production`, this is production.
///
/// [`Venture::env`]: crate::venture::Venture::env
#[must_use]
pub fn deployed_env(compiled: VentureEnv, config: &dyn crate::config::Config) -> VentureEnv {
    let declared = config
        .get("ENV")
        .as_deref()
        .and_then(VentureEnv::parse)
        .unwrap_or_default();
    compiled.strictest(declared)
}

/// Whether the deployment's environment contradicts the compiled one
/// (issue #143). Not an error by itself — the stricter answer wins — but
/// it means the build-time gate ran against the wrong environment, so
/// the caller re-checks and says so.
#[must_use]
pub fn env_disagreement(compiled: VentureEnv, deployed: VentureEnv) -> Option<String> {
    (compiled != deployed).then(|| {
        format!(
            "this deployment declares ENV={} but the venture was compiled with \
             VentureEnv::{compiled:?}: the production readiness gate at build time ran \
             against the wrong environment. Treating it as {} — call \
             `.env(VentureEnv::{deployed:?})` on the venture so the build refuses what \
             the deployment cannot serve (issue #143)",
            deployed.as_str(),
            deployed.as_str(),
        )
    })
}

/// Whether the runtime can issue and verify the artifacts a
/// [`RoutePolicy::SignedLink`] route rests on (issue #143).
///
/// Like [`rate_limiter_effective`], the runtime's own, provisional
/// answer: the native and Cloudflare runtimes advertise [`Port::Signer`]
/// unconditionally and leave `ports.signer == None` with only a warning
/// when the harness configuration does not parse (issue #478). The boot
/// gate re-checks against the resolved port — [`production_readiness`]
/// takes it as its `signer_ready` parameter.
#[must_use]
pub fn signer_effective(runtime: Option<&Arc<dyn Runtime>>) -> bool {
    runtime.is_some_and(|runtime| runtime.effectively_configured(Port::Signer))
}

/// Whether the runtime has a limiter it can actually consult (issue #437).
///
/// This is the **runtime's own answer**, and a provisional one: it is all
/// the build-time gate and `fz doctor` can know, because neither holds the
/// resolved [`Ports`](crate::ports::Ports). A Cloudflare binding that is
/// named but fails to resolve still reports `true` here — the adapter
/// degrades to `ports.rate_limiter == None` with only a warning — so the
/// boot gate re-checks against the port the runtime actually handed over:
/// [`production_readiness`] takes that resolved answer as its
/// `rate_limiter_ready` parameter and never computes it from this.
#[must_use]
pub fn rate_limiter_effective(runtime: Option<&Arc<dyn Runtime>>) -> bool {
    runtime.is_some_and(|runtime| runtime.effectively_configured(Port::RateLimiter))
}

/// The production abuse-control gate (issue #133), as collected error
/// strings (the [`ConfigError`] convention: report every problem at
/// once). Empty for anything but `Production`.
///
/// The two overrides are deliberate, independent, recorded decisions:
/// `allow_no_captcha` (the `fz doctor` flag, and
/// `HARNESS_ALLOW_UNPROTECTED_WRITES` at the boot gate) downgrades only
/// the CAPTCHA refusal, and `allow_unlimited`
/// ([`ALLOW_UNLIMITED_PUBLIC_ROUTES`]) downgrades only the
/// rate-limiter refusal (issue #437). One key waiving two controls is how
/// the second stays unwired after the first is fixed.
///
/// The limiter leg is keyed on `rate_limiter_ready`, the **resolved**
/// answer, and never inferred from [`Runtime::provides`]: the Cloudflare
/// runtime reports [`Port::RateLimiter`] from a configured binding *name*,
/// and a binding that fails to resolve degrades to
/// `ports.rate_limiter == None` with only a `warn_once`. Callers holding
/// ports pass `ports.rate_limiter.is_some()`; the build-time gate and
/// `fz doctor` pass [`rate_limiter_effective`], the runtime's own answer.
/// The leg is additive on declarations (issue #562): a module whose
/// `requires()`/`optional()` names [`Port::RateLimiter`] and that exposes
/// public routes makes the leg fire on its own, and the message names each
/// declaring module with its routes instead of the undeclared-writer text.
///
/// The signer leg is keyed the same way on `signer_ready` (issue #478):
/// the runtimes advertise [`Port::Signer`] yet leave `ports.signer ==
/// None` when the harness configuration fails to parse. Callers holding
/// ports pass `ports.signer.is_some()`; the build-time gate passes
/// [`signer_effective`].
///
/// [`ConfigError`]: crate::config::ConfigError
#[must_use]
pub fn production_readiness(
    env: VentureEnv,
    guards: &WriteGuards,
    runtime: Option<&Arc<dyn Runtime>>,
    rate_limiter_ready: bool,
    signer_ready: bool,
    allow_no_captcha: Option<&str>,
    allow_unlimited: Option<&str>,
) -> Vec<String> {
    if env != VentureEnv::Production {
        return Vec::new();
    }
    let mut errors = Vec::new();
    if guards.needs_captcha()
        && !captcha_effective(runtime)
        && stated_reason(allow_no_captcha).is_none()
    {
        errors.push(format!(
            "production venture has captcha-guarded public writes from [{}] but the Captcha \
             port is not effectively configured: provide it on the runtime with a bound \
             adapter (Turnstile needs its secret and expected hostname) — `fz doctor \
             --allow-no-captcha <reason>` overrides this check for previews only, and \
             {ALLOW_UNPROTECTED_WRITES} records the acceptance in a serving deployment",
            guards.captcha_modules.join(", ")
        ));
    }
    if guards.needs_signer() && !signer_ready {
        errors.push(format!(
            "production venture has signed-link public writes from [{}] but the Signer port \
             is not provided — the magic links, challenges and unsubscribe links those \
             routes verify cannot be issued or checked without one (issue #143)",
            guards.signed_link_modules.join(", ")
        ));
    }
    if guards.needs_payments() && !payments_effective(runtime) {
        // Name each module with the routes that verify through Payments
        // (issue #595): a module may verify its Stripe webhook this way
        // and another provider's with an HMAC secret, and the operator
        // needs to see which endpoint the missing port blocks.
        let named = guards
            .payments_signature_modules
            .iter()
            .map(|module| guards.signature_module_named(module, SignatureVerification::Payments))
            .collect::<Vec<_>>()
            .join(", ");
        errors.push(format!(
            "production venture has signature-guarded routes from [{named}] that verify through \
             Payments but the Payments port is not provided — those webhook deliveries cannot \
             be verified (see the Inbox dedup ledger and the STRIPE_WEBHOOK_SECRET doctor \
             rule; modules verifying with the webhook_signature HMAC scheme instead are \
             gated on their own secret key, not this port)",
        ));
    }
    if guards.needs_rate_limiter()
        && !rate_limiter_ready
        && stated_reason(allow_unlimited).is_none()
    {
        // When a module *declares* the port (issue #562), name it and the
        // routes it publishes unlimited — the captcha leg's convention:
        // the operator should be able to fix the named thing, not go
        // hunting for which route made the gate fire.
        if guards.rate_limiter_modules.is_empty() {
            errors.push(format!(
                "production venture takes public writes or admin routes but the RateLimiter \
                 port is not resolved: admin bearer routes have no brute-force backstop behind \
                 the limiter (the fail-closed rule the sidecar forward runs) and every public \
                 write runs without a budget — resolve the binding so the runtime actually \
                 hands over a limiter, or set {ALLOW_UNLIMITED_PUBLIC_ROUTES} to a reason to \
                 serve unlimited (issue #437)"
            ));
        } else {
            let declared = guards
                .rate_limiter_modules
                .iter()
                .map(|(module, routes)| format!("{module} ({})", routes.join(", ")))
                .collect::<Vec<_>>()
                .join(", ");
            errors.push(format!(
                "production venture declares RateLimiter for public routes from [{declared}] \
                 but the RateLimiter port is not resolved: those routes — and any public write \
                 or admin route beside them — run without a budget — resolve the binding so \
                 the runtime actually hands over a limiter, or set \
                 {ALLOW_UNLIMITED_PUBLIC_ROUTES} to a reason to serve unlimited \
                 (issues #437, #562)"
            ));
        }
    }
    errors
}

/// The shared CAPTCHA gate for `HumanForm` handlers (issue #133): the
/// single place a module asks "is this form submission a human?".
///
/// Fail-closed rules, in order:
///
/// - the port is present: the token must exist and verify — any
///   non-`ok` verdict or transport error is a `captcha-failed` problem;
/// - the port is absent in **production**: `captcha-failed` as well.
///   `Harness::build` refuses that composition, so reaching this branch
///   means a runtime lied about its binding — refuse rather than wave
///   the request through. **Unless** `accepted_unprotected`: an operator
///   has recorded that this deployment serves without the port
///   (`HARNESS_ALLOW_UNPROTECTED_WRITES`, issue #143), the boot gate
///   honoured that and served, and refusing here would be the same
///   outage the acceptance exists to avoid, with a different status
///   code. The record is the accountability, not this branch;
/// - the port is absent in development/staging: allow, so a staging
///   deploy can drive the form without a live Turnstile.
///
/// # Errors
///
/// A `captcha-failed` problem when the submission is not proven human.
pub async fn verify_human_form(
    captcha: Option<&Arc<dyn Captcha>>,
    env: VentureEnv,
    accepted_unprotected: bool,
    token: Option<&str>,
    remote_ip: Option<&str>,
    instance: &str,
) -> Result<(), Problem> {
    let refused = || Problem::new(&SLUGS.captcha_failed).instance(instance);
    match captcha {
        Some(captcha) => {
            let Some(token) = token else {
                return Err(refused());
            };
            match captcha.verify(token, remote_ip).await {
                Ok(verdict) if verdict.ok => Ok(()),
                _ => Err(refused()),
            }
        }
        // No port, in production, with nobody having accepted that: the
        // composition `Harness::build` refuses is somehow serving, so
        // refuse the request rather than wave it through.
        None if env == VentureEnv::Production && !accepted_unprotected => Err(refused()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Migrations;
    use crate::ports::{CaptchaError, Verdict};
    use crate::surface::Action;
    use async_trait::async_trait;

    struct StubCaptcha {
        ok: bool,
        transport_error: bool,
    }

    #[async_trait]
    impl Captcha for StubCaptcha {
        async fn verify(
            &self,
            _token: &str,
            _remote_ip: Option<&str>,
        ) -> Result<Verdict, CaptchaError> {
            if self.transport_error {
                return Err(CaptchaError::Transport("down".to_owned()));
            }
            Ok(Verdict {
                ok: self.ok,
                reason: None,
            })
        }
    }

    fn port(ok: bool, transport_error: bool) -> Arc<dyn Captcha> {
        Arc::new(StubCaptcha {
            ok,
            transport_error,
        })
    }

    #[pollster::test]
    async fn verified_tokens_pass_in_every_environment() {
        for env in [
            VentureEnv::Development,
            VentureEnv::Staging,
            VentureEnv::Production,
        ] {
            verify_human_form(
                Some(&port(true, false)),
                env,
                false,
                Some("token"),
                Some("203.0.113.7"),
                "request-1",
            )
            .await
            .expect("a verified token passes");
        }
    }

    #[pollster::test]
    async fn refused_missing_or_unreachable_verifications_fail_closed() {
        let good = port(true, false);
        let refused = port(false, false);
        let unreachable = port(true, true);
        for env in [VentureEnv::Development, VentureEnv::Production] {
            assert!(
                verify_human_form(Some(&refused), env, false, Some("t"), None, "r")
                    .await
                    .is_err()
            );
            assert!(
                verify_human_form(Some(&unreachable), env, false, Some("t"), None, "r")
                    .await
                    .is_err()
            );
            assert!(
                verify_human_form(Some(&good), env, false, None, None, "r")
                    .await
                    .is_err()
            );
        }
    }

    #[pollster::test]
    async fn absent_port_refuses_production_and_allows_lower_envs() {
        assert!(
            verify_human_form(None, VentureEnv::Production, false, Some("t"), None, "r")
                .await
                .is_err()
        );
        for env in [VentureEnv::Development, VentureEnv::Staging] {
            assert!(
                verify_human_form(None, env, false, Some("t"), None, "r")
                    .await
                    .is_ok()
            );
        }
    }

    struct Guarded {
        name: &'static str,
        surface: Surface,
        public_writes: bool,
        public_write_policy: RoutePolicy,
        verification: SignatureVerification,
    }

    impl Module for Guarded {
        fn name(&self) -> &'static str {
            self.name
        }
        fn version(&self) -> &'static str {
            "0.0.0-test"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn public_writes(&self) -> bool {
            self.public_writes
        }
        fn public_write_policy(&self) -> RoutePolicy {
            self.public_write_policy
        }
        fn signature_verification(&self) -> SignatureVerification {
            self.verification
        }
        fn migrations(&self) -> Migrations {
            Migrations::default()
        }
        fn validate_config(
            &self,
            _: &dyn crate::config::Config,
        ) -> Result<(), crate::config::ConfigError> {
            Ok(())
        }
        fn surface(&self) -> Surface {
            self.surface.clone()
        }
        fn router(&self, _: crate::ModuleContext) -> axum::Router {
            axum::Router::new()
        }
    }

    fn module(name: &'static str, actions: Vec<Action>, public_writes: bool) -> Arc<dyn Module> {
        Arc::new(Guarded {
            name,
            surface: Surface {
                actions,
                views: vec![],
            },
            public_writes,
            public_write_policy: RoutePolicy::HumanForm,
            verification: SignatureVerification::Payments,
        })
    }

    /// A surface-less public writer that declares what really guards it.
    fn declaring(name: &'static str, policy: RoutePolicy) -> Arc<dyn Module> {
        Arc::new(Guarded {
            name,
            surface: Surface {
                actions: vec![],
                views: vec![],
            },
            public_writes: true,
            public_write_policy: policy,
            verification: SignatureVerification::Payments,
        })
    }

    #[test]
    fn human_form_action_requires_captcha() {
        let guards = WriteGuards::collect(&[module(
            "forms",
            vec![Action::post("join", "/").policy(RoutePolicy::HumanForm)],
            false,
        )]);
        assert_eq!(guards.captcha_modules, vec!["forms".to_owned()]);
        assert!(!guards.needs_payments());
    }

    #[test]
    fn signature_action_never_requires_captcha() {
        // The old bug: a webhook counted as "protected", so a captcha
        // config problem passed unnoticed AND the widget rendered on the
        // webhook. A Signature-only module must ask for Payments only.
        let guards = WriteGuards::collect(&[module(
            "billing",
            vec![Action::post("webhook", "/webhook").policy(RoutePolicy::Signature)],
            true, // even with the legacy flag set, the declared policy wins
        )]);
        assert!(guards.captcha_modules.is_empty());
        assert_eq!(guards.signature_modules, vec!["billing".to_owned()]);
    }

    #[test]
    fn undeclared_public_writer_falls_back_to_captcha() {
        let guards = WriteGuards::collect(&[module("auth", Vec::new(), true)]);
        assert_eq!(guards.captcha_modules, vec!["auth".to_owned()]);
    }

    #[test]
    fn legacy_captcha_flag_alias_still_guards() {
        // Pre-#133 declaration shapes — a bare `captcha: true` without a
        // policy — must still pull the module into the captcha gate.
        let mut action = Action::post("join", "/");
        action.captcha = true;
        let guards = WriteGuards::collect(&[module("forms", vec![action], false)]);
        assert_eq!(guards.captcha_modules, vec!["forms".to_owned()]);
    }

    #[test]
    fn guarded_surface_does_not_need_the_fallback() {
        // A module with declared policies is read as declared: `public_writes`
        // adds nothing on top (a form writer declares HumanForm; the
        // fallback exists for modules that predate surfaces).
        let guards = WriteGuards::collect(&[module(
            "waitlist",
            vec![
                Action::post("join", "/").captcha(),
                Action::post("webhook", "/webhook").policy(RoutePolicy::Signature),
            ],
            true,
        )]);
        assert_eq!(guards.captcha_modules, vec!["waitlist".to_owned()]);
        assert_eq!(guards.signature_modules, vec!["waitlist".to_owned()]);
    }

    #[test]
    fn development_venture_needs_nothing() {
        let guards = WriteGuards::collect(&[module("forms", Vec::new(), true)]);
        for env in [VentureEnv::Development, VentureEnv::Staging] {
            assert!(
                production_readiness(env, &guards, None, true, false, None, None).is_empty(),
                "{env:?} must not gate"
            );
        }
    }

    #[test]
    fn production_without_runtime_refuses_captcha_writes() {
        let guards = WriteGuards::collect(&[module(
            "forms",
            vec![Action::post("join", "/").captcha()],
            false,
        )]);
        // The limiter leg is held aside (`rate_limiter_ready = true`) so
        // this test stays about the captcha leg; #437's own tests are
        // below.
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            true,
            false,
            None,
            None,
        );
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("forms"));
        assert!(errors[0].contains("Captcha"));
        // The override exists for `fz doctor` previews only.
        assert!(
            production_readiness(
                VentureEnv::Production,
                &guards,
                None,
                true,
                false,
                Some("preview"),
                None
            )
            .is_empty()
        );
        // And it is the *reason* that overrides, not the flag. `fz
        // doctor --allow-no-captcha ""` hands this `Some("")`, and an
        // override with nothing to answer for is the silent default
        // `ALLOW_UNPROTECTED_WRITES` already refuses to be — its
        // `unprotected_writes_override` trims and drops an empty one.
        // Two ways to the same waiver, and only one of them asked for a
        // reason.
        for nothing in ["", "   ", "\t\n"] {
            assert_eq!(
                production_readiness(
                    VentureEnv::Production,
                    &guards,
                    None,
                    true,
                    false,
                    Some(nothing),
                    None
                )
                .len(),
                1,
                "an empty reason waived the captcha gate: {nothing:?}"
            );
        }
    }

    #[test]
    fn production_signature_without_payments_refuses() {
        let guards = WriteGuards::collect(&[module(
            "billing",
            vec![Action::post("webhook", "/webhook").policy(RoutePolicy::Signature)],
            false,
        )]);
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            true,
            false,
            None,
            None,
        );
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("billing"));
        assert!(errors[0].contains("Payments"));
        // No override for the payments leg — webhooks cannot be "previewed"
        // unverified without shipping unsigned money events.
        assert_eq!(
            production_readiness(
                VentureEnv::Production,
                &guards,
                None,
                true,
                false,
                Some("preview"),
                None
            )
            .len(),
            1
        );
    }

    // ------------------------------------------------ issue #533

    use crate::config::MapConfig;

    /// A webhook receiver verifying with the core HMAC scheme, holding its
    /// secret under `{MODULE}_WEBHOOK_SECRET`.
    fn hmac_module(name: &'static str) -> Arc<dyn Module> {
        Arc::new(Guarded {
            name,
            surface: Surface {
                actions: vec![Action::post("webhook", "/webhook").policy(RoutePolicy::Signature)],
                views: vec![],
            },
            public_writes: false,
            public_write_policy: RoutePolicy::HumanForm,
            verification: SignatureVerification::Hmac {
                secret: "WEBHOOK_SECRET",
            },
        })
    }

    #[test]
    fn an_hmac_signature_writer_needs_no_payments_and_names_its_secret_key() {
        let guards = WriteGuards::collect(&[hmac_module("pos")]);
        assert_eq!(guards.signature_modules, ["pos"]);
        assert!(!guards.needs_payments());
        assert_eq!(
            guards.hmac_signature_secrets(),
            vec![("pos".to_owned(), "POS_WEBHOOK_SECRET".to_owned())],
            "the full key is composed through ModuleConfig's prefix rule"
        );
    }

    #[test]
    fn the_webhook_secret_gate_is_production_only() {
        let guards = WriteGuards::collect(&[hmac_module("pos")]);
        // No runtime at all — no Payments port anywhere — and production is
        // clean once the secret is set.
        let set = MapConfig::from_pairs([("POS_WEBHOOK_SECRET", "whsec-test-dummy")]);
        assert!(
            production_readiness(
                VentureEnv::Production,
                &guards,
                None,
                true,
                false,
                None,
                None
            )
            .is_empty()
        );
        assert!(webhook_secret_readiness(VentureEnv::Production, &guards, &set).is_empty());
        // Missing or blank refuses in production, naming the module and the
        // key; staging demands nothing (the handler refuses every delivery
        // per request anyway).
        for config in [
            MapConfig::default(),
            MapConfig::from_pairs([("POS_WEBHOOK_SECRET", "   ")]),
        ] {
            let errors = webhook_secret_readiness(VentureEnv::Production, &guards, &config);
            assert_eq!(errors.len(), 1, "{errors:?}");
            assert!(
                errors[0].contains("pos") && errors[0].contains("POS_WEBHOOK_SECRET"),
                "{}",
                errors[0]
            );
        }
        assert!(
            webhook_secret_readiness(VentureEnv::Staging, &guards, &MapConfig::default())
                .is_empty()
        );
    }

    #[test]
    fn a_mixed_venture_gates_payments_only_for_the_module_that_names_it() {
        // A sidecar document cannot name a verifier, so it keeps the
        // pre-#533 behaviour: the Payments gate.
        let surface = Surface {
            actions: vec![Action::post("webhook", "/webhook").policy(RoutePolicy::Signature)],
            views: vec![],
        };
        assert!(WriteGuards::from_surface("remote", &surface).needs_payments());
        // A mixed venture still demands Payments for exactly the module
        // that verifies through it.
        let guards = WriteGuards::collect(&[
            hmac_module("pos"),
            declaring("billing", RoutePolicy::Signature),
        ]);
        assert!(guards.needs_payments());
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            true,
            false,
            None,
            None,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("billing") && !errors[0].contains("pos"),
            "{}",
            errors[0]
        );
    }

    // ------------------------------------------------ issue #595

    /// A billing module with two webhooks and two verifiers: the Stripe
    /// route keeps the module default (`Payments`), the `RevenueCat` route
    /// names its own HMAC secret.
    fn two_verifier_billing() -> Arc<dyn Module> {
        module(
            "billing",
            vec![
                Action::post("webhook-stripe", "/webhooks/stripe").policy(RoutePolicy::Signature),
                Action::post("webhook-revenuecat", "/webhooks/revenuecat")
                    .policy(RoutePolicy::Signature)
                    .verification(SignatureVerification::Hmac {
                        secret: "REVENUECAT_WEBHOOK_SECRET",
                    }),
            ],
            false,
        )
    }

    #[test]
    fn a_two_verifier_module_composes_and_gates_each_verifier_by_route() {
        struct ProvidesPayments;
        impl Runtime for ProvidesPayments {
            fn provides(&self) -> Vec<Port> {
                vec![Port::Payments]
            }
        }
        let guards = WriteGuards::collect(&[two_verifier_billing()]);
        // One module in both lists, each exactly once (issue #595).
        assert_eq!(guards.signature_modules, ["billing"]);
        assert_eq!(guards.payments_signature_modules, ["billing"]);
        assert_eq!(
            guards.hmac_signature_secrets(),
            vec![(
                "billing".to_owned(),
                "BILLING_REVENUECAT_WEBHOOK_SECRET".to_owned()
            )]
        );

        // The Payments leg fires for the Stripe route only, and names it.
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            true,
            false,
            None,
            None,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("POST /v1/billing/webhooks/stripe"),
            "{}",
            errors[0]
        );
        assert!(
            !errors[0].contains("POST /v1/billing/webhooks/revenuecat"),
            "{}",
            errors[0]
        );

        // The HMAC leg fires for the RevenueCat route only, naming the key
        // and the route.
        let missing =
            webhook_secret_readiness(VentureEnv::Production, &guards, &MapConfig::default());
        assert_eq!(missing.len(), 1, "{missing:?}");
        assert!(
            missing[0].contains("BILLING_REVENUECAT_WEBHOOK_SECRET")
                && missing[0].contains("POST /v1/billing/webhooks/revenuecat"),
            "{}",
            missing[0]
        );

        // Both verifiers satisfied: a runtime with an effective Payments
        // port and the secret set is clean.
        let runtime: Arc<dyn Runtime> = Arc::new(ProvidesPayments);
        let set = MapConfig::from_pairs([("BILLING_REVENUECAT_WEBHOOK_SECRET", "whsec-dummy")]);
        assert!(
            production_readiness(
                VentureEnv::Production,
                &guards,
                Some(&runtime),
                true,
                false,
                None,
                None,
            )
            .is_empty()
        );
        assert!(webhook_secret_readiness(VentureEnv::Production, &guards, &set).is_empty());
    }

    #[test]
    fn from_surface_honours_a_route_verifier_on_an_in_process_surface() {
        // `verification` is `#[serde(skip)]`, so a sidecar document cannot
        // carry it: this builds the `Surface` in process to exercise the
        // `from_surface` branch. It cannot ask a module for its default, so
        // a route that names `Hmac` gets it — the `Payments` default is the
        // #533 test above (issue #595).
        let surface = Surface {
            actions: vec![
                Action::post("revenuecat", "/webhooks/revenuecat")
                    .policy(RoutePolicy::Signature)
                    .verification(SignatureVerification::Hmac {
                        secret: "REVENUECAT_WEBHOOK_SECRET",
                    }),
            ],
            views: vec![],
        };
        let guards = WriteGuards::from_surface("billing", &surface);
        assert!(!guards.needs_payments());
        assert_eq!(
            guards.hmac_signature_secrets(),
            vec![(
                "billing".to_owned(),
                "BILLING_REVENUECAT_WEBHOOK_SECRET".to_owned()
            )]
        );
    }

    // ------------------------------------------------ issue #143

    #[test]
    fn the_deployment_environment_is_the_stricter_of_the_two() {
        // The bug: `ventures/cratefield-waitlist` ships ENV="production"
        // and never calls `.env()`, so every production rule read the
        // compiled `Development` and did not apply in production.
        let deployed = MapConfig::from_pairs([("ENV", "production")]);
        assert_eq!(
            deployed_env(VentureEnv::Development, &deployed),
            VentureEnv::Production,
        );
        // And the other way: a binding must not be able to switch the
        // protections off for a venture compiled as production.
        let downgrade = MapConfig::from_pairs([("ENV", "development")]);
        assert_eq!(
            deployed_env(VentureEnv::Production, &downgrade),
            VentureEnv::Production,
        );
        // No binding at all leaves the compiled answer standing.
        assert_eq!(
            deployed_env(VentureEnv::Staging, &MapConfig::default()),
            VentureEnv::Staging,
        );
        // Agreement is not a disagreement.
        assert!(env_disagreement(VentureEnv::Production, VentureEnv::Production).is_none());
        let note = env_disagreement(VentureEnv::Development, VentureEnv::Production)
            .expect("a compiled-vs-deployed mismatch is reported");
        assert!(note.contains("ENV=production"), "{note}");
        // The literal is split across lines; it renders as one sentence (issue #477).
        assert!(!note.contains("  "), "{note}");
        assert!(
            note.contains("compiled with VentureEnv::Development: the production readiness gate"),
            "{note}"
        );
    }

    #[test]
    fn a_surface_less_writer_declares_what_actually_guards_it() {
        // Saying nothing is unchanged: still the conservative CAPTCHA
        // fallback, so no existing module moves.
        let guards = WriteGuards::collect(&[module("legacy", vec![], true)]);
        assert_eq!(guards.captcha_modules, ["legacy"]);
        assert!(!guards.needs_signer());

        // A passkey ceremony or an OAuth callback is proved by an artifact
        // this service issued, and will never render a widget.
        let guards = WriteGuards::collect(&[declaring("passkeys", RoutePolicy::SignedLink)]);
        assert!(
            guards.captcha_modules.is_empty(),
            "a signed-link writer must not demand a captcha it never renders"
        );
        assert_eq!(guards.signed_link_modules, ["passkeys"]);
        assert!(guards.needs_signer());
    }

    #[test]
    fn a_signed_link_writer_still_has_a_production_requirement_of_its_own() {
        // Not an exemption: without a Signer there is nothing to issue or
        // verify the artifact with, so production still refuses.
        let guards = WriteGuards::collect(&[declaring("passkeys", RoutePolicy::SignedLink)]);
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            true,
            false,
            None,
            None,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("signed-link"), "{}", errors[0]);
        assert!(errors[0].contains("passkeys"), "{}", errors[0]);

        // And nothing is demanded outside production.
        assert!(
            production_readiness(VentureEnv::Staging, &guards, None, true, false, None, None)
                .is_empty()
        );
    }

    #[test]
    fn a_production_venture_needs_a_resolved_signer() {
        // Issue #478: the runtime advertises the Signer port, but a
        // harness configuration that fails to parse (a bad `ENV`, a short
        // `ADMIN_TOKEN`) leaves `ports.signer == None`. Advertised is not
        // resolved, so the caller's answer decides the leg.
        struct Advertises;
        impl Runtime for Advertises {
            fn provides(&self) -> Vec<Port> {
                vec![Port::Signer]
            }
        }
        let runtime: Arc<dyn Runtime> = Arc::new(Advertises);
        let guards = WriteGuards::collect(&[declaring("passkeys", RoutePolicy::SignedLink)]);
        let check = |env, signer_ready| {
            production_readiness(env, &guards, Some(&runtime), true, signer_ready, None, None)
        };

        let errors = check(VentureEnv::Production, false);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("Signer"), "{}", errors[0]);
        // The literal is split across lines; it renders as one sentence, the
        // same fix #511 made to the ENV warning (#512 made this reachable at boot).
        assert!(!errors[0].contains("  "), "{}", errors[0]);
        assert!(
            errors[0].contains("but the Signer port is not provided"),
            "{}",
            errors[0]
        );
        assert!(check(VentureEnv::Production, true).is_empty());
        assert!(check(VentureEnv::Development, false).is_empty());
    }

    #[test]
    fn a_declared_policy_on_an_action_still_wins_over_the_fallback() {
        // The fallback applies only when the surface declares nothing —
        // a module with a guarded action is untouched by #143.
        let guards = WriteGuards::collect(&[Arc::new(Guarded {
            name: "mixed",
            surface: Surface {
                actions: vec![Action::post("join", "/join").policy(RoutePolicy::HumanForm)],
                views: vec![],
            },
            public_writes: true,
            public_write_policy: RoutePolicy::SignedLink,
            verification: SignatureVerification::Payments,
        })]);
        assert_eq!(guards.captcha_modules, ["mixed"]);
        assert!(
            guards.signed_link_modules.is_empty(),
            "the module-level fallback must not override a declared action"
        );
    }

    // ------------------------------------------------ issue #437

    #[test]
    fn admin_and_public_writes_are_recorded_on_the_guards() {
        // An admin action alone is enough: the bearer token is guessed,
        // not submitted, so the budget question is not a corollary of the
        // public-write one.
        let guards = WriteGuards::collect(&[module(
            "exports",
            vec![Action::post("export", "/admin/export").audience(Audience::Admin)],
            false,
        )]);
        assert!(guards.has_admin_routes);
        assert!(!guards.has_public_writes);
        assert!(guards.needs_rate_limiter());

        // The path half of the predicate, for an action whose audience
        // was never declared.
        let guards = WriteGuards::collect(&[module(
            "landing",
            vec![Action::get("console", "/admin/console")],
            false,
        )]);
        assert!(guards.has_admin_routes);

        // The module-level fallback flag counts as a public write, the
        // way the captcha fallback does.
        let guards = WriteGuards::collect(&[module("legacy", Vec::new(), true)]);
        assert!(guards.has_public_writes);
        assert!(!guards.has_admin_routes);

        // And a webhook is an unauthenticated endpoint: it counts for the
        // limiter leg even though it asks nothing of the captcha one.
        let guards = WriteGuards::collect(&[module(
            "billing",
            vec![Action::post("webhook", "/webhook").policy(RoutePolicy::Signature)],
            false,
        )]);
        assert!(guards.has_public_writes);
    }

    #[test]
    fn a_production_venture_needs_a_resolved_rate_limiter() {
        let guards = WriteGuards::collect(&[module(
            "forms",
            vec![Action::post("join", "/").captcha()],
            false,
        )]);

        // Advertised is not resolved: the Cloudflare runtime reports the
        // port from a configured binding name and still hands over `None`
        // when the binding fails to resolve. The caller says which
        // happened, and the captcha waiver next door does not reach this
        // leg.
        let unlimited = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            false,
            false,
            Some("preview"),
            None,
        );
        assert_eq!(unlimited.len(), 1, "{unlimited:?}");
        assert!(unlimited[0].contains("RateLimiter"), "{}", unlimited[0]);
        assert!(
            unlimited[0].contains(ALLOW_UNLIMITED_PUBLIC_ROUTES),
            "{}",
            unlimited[0]
        );

        // Resolved: the leg passes.
        assert!(
            production_readiness(
                VentureEnv::Production,
                &guards,
                None,
                true,
                false,
                Some("preview"),
                None
            )
            .is_empty()
        );

        // Waived with a reason it passes; waived with a blank one it does
        // not — the same "a blank reason is not an acceptance" rule the
        // captcha override runs on.
        assert!(
            production_readiness(
                VentureEnv::Production,
                &guards,
                None,
                false,
                false,
                Some("preview"),
                Some("issue #437: between pivots"),
            )
            .is_empty()
        );
        for nothing in ["", "   "] {
            assert_eq!(
                production_readiness(
                    VentureEnv::Production,
                    &guards,
                    None,
                    false,
                    false,
                    Some("preview"),
                    Some(nothing),
                )
                .len(),
                1,
                "an empty reason waived the limiter gate: {nothing:?}"
            );
        }
    }

    #[test]
    fn a_module_with_only_admin_routes_still_needs_the_limiter() {
        let guards = WriteGuards::collect(&[module(
            "exports",
            vec![Action::post("export", "/admin/export").audience(Audience::Admin)],
            false,
        )]);
        assert!(guards.captcha_modules.is_empty());
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            false,
            false,
            None,
            None,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("RateLimiter"), "{}", errors[0]);
        assert!(
            errors[0].contains(ALLOW_UNLIMITED_PUBLIC_ROUTES),
            "{}",
            errors[0]
        );
    }

    // ------------------------------------------------ issue #562

    /// A module that declares `Port::RateLimiter` (optional, the common
    /// shape — the waitlist and auth modules all declare it there) and
    /// publishes public routes.
    struct DeclaresLimiter {
        name: &'static str,
        surface: Surface,
    }

    impl Module for DeclaresLimiter {
        fn name(&self) -> &'static str {
            self.name
        }
        fn version(&self) -> &'static str {
            "0.0.0-test"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn optional(&self) -> &'static [Port] {
            &[Port::RateLimiter]
        }
        fn migrations(&self) -> Migrations {
            Migrations::default()
        }
        fn validate_config(
            &self,
            _: &dyn crate::config::Config,
        ) -> Result<(), crate::config::ConfigError> {
            Ok(())
        }
        fn surface(&self) -> Surface {
            self.surface.clone()
        }
        fn router(&self, _: crate::ModuleContext) -> axum::Router {
            axum::Router::new()
        }
    }

    #[test]
    fn a_declared_limiter_over_public_reads_needs_one_resolved() {
        // A public search endpoint is not a write and not the admin
        // plane, so the #437 triggers stay silent — but the module says
        // it throttles, and the gate holds the venture to that claim
        // (issue #562).
        let guards = WriteGuards::collect(&[Arc::new(DeclaresLimiter {
            name: "search",
            surface: Surface {
                actions: vec![
                    Action::get("query", "/search").audience(Audience::Public),
                    Action::get("suggest", "/suggest").audience(Audience::Public),
                ],
                views: vec![],
            },
        })]);
        assert!(guards.captcha_modules.is_empty());
        assert!(!guards.has_public_writes);
        assert!(!guards.has_admin_routes);
        assert_eq!(
            guards.rate_limiter_modules,
            vec![(
                "search".to_owned(),
                vec![
                    "GET /v1/search/search".to_owned(),
                    "GET /v1/search/suggest".to_owned(),
                ]
            )]
        );
        assert!(guards.needs_rate_limiter());

        // Unresolved: the error names the module and its routes.
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            false,
            false,
            None,
            None,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("search"), "{}", errors[0]);
        assert!(errors[0].contains("GET /v1/search/search"), "{}", errors[0]);

        // Resolved: the leg passes.
        assert!(
            production_readiness(
                VentureEnv::Production,
                &guards,
                None,
                true,
                false,
                None,
                None
            )
            .is_empty()
        );

        // The waiver still waives, and non-production never gates.
        assert!(
            production_readiness(
                VentureEnv::Production,
                &guards,
                None,
                false,
                false,
                None,
                Some("issue #562: binding pending"),
            )
            .is_empty()
        );
        for env in [VentureEnv::Development, VentureEnv::Staging] {
            assert!(
                production_readiness(env, &guards, None, false, false, None, None).is_empty(),
                "{env:?} must not gate"
            );
        }
    }

    #[test]
    fn a_declared_limiter_error_names_each_module_and_its_routes() {
        // Two declaring modules, and a module declaring the port with no
        // public route to hang it on contributes nothing to the list.
        let guards = WriteGuards::collect(&[
            Arc::new(DeclaresLimiter {
                name: "waitlist",
                surface: Surface {
                    actions: vec![Action::post("join", "/").captcha()],
                    views: vec![],
                },
            }),
            Arc::new(DeclaresLimiter {
                name: "quiet",
                surface: Surface {
                    actions: vec![
                        Action::post("export", "/admin/export").audience(Audience::Admin),
                    ],
                    views: vec![],
                },
            }),
        ]);
        assert_eq!(
            guards.rate_limiter_modules,
            vec![("waitlist".to_owned(), vec!["POST /v1/waitlist".to_owned()])]
        );
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            false,
            false,
            Some("preview"),
            None,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("waitlist (POST /v1/waitlist)"));
    }

    #[test]
    fn the_undeclared_limiter_error_keeps_its_own_message() {
        // Without a declaring module the leg keeps the #437 message —
        // there is nothing to name, and existing operators read that
        // text in their doctor output and logs.
        let guards = WriteGuards::collect(&[module(
            "forms",
            vec![Action::post("join", "/").captcha()],
            false,
        )]);
        assert!(guards.rate_limiter_modules.is_empty());
        // The captcha leg is waived aside so the assertion stays about
        // which limiter message fired (the captcha waiver never reaches
        // this leg — see the #437 test above).
        let errors = production_readiness(
            VentureEnv::Production,
            &guards,
            None,
            false,
            false,
            Some("preview"),
            None,
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains("takes public writes or admin routes"),
            "{}",
            errors[0]
        );
        assert!(!errors[0].contains("declares RateLimiter"));
    }

    // ------------------------------------------------ issue #532

    #[test]
    fn an_api_key_policy_serializes_as_api_key_and_guards() {
        assert_eq!(
            serde_json::to_string(&RoutePolicy::ApiKey).expect("serializes"),
            "\"api-key\""
        );
        let policy: RoutePolicy = serde_json::from_str("\"api-key\"").expect("deserializes");
        assert_eq!(policy, RoutePolicy::ApiKey);
        assert!(policy.is_guarded());
    }

    #[test]
    fn an_api_key_writer_demands_no_captcha_and_no_port() {
        // A declared api-key action is read as declared: no captcha (a
        // developer machine cannot fill one), no Signer, no Payments —
        // and not the public-write leg either, because its budget is the
        // per-key limiter hook, not a boot gate.
        let guards = WriteGuards::collect(&[module(
            "devapi",
            vec![Action::post("sync", "/sync").policy(RoutePolicy::ApiKey)],
            false,
        )]);
        assert!(guards.captcha_modules.is_empty());
        assert!(guards.signature_modules.is_empty());
        assert!(guards.signed_link_modules.is_empty());
        assert!(!guards.has_public_writes);
        assert!(!guards.needs_rate_limiter());

        // The surface-less fallback is the same: guarded, never pulled
        // into the captcha gate.
        let guards = WriteGuards::collect(&[declaring("devapi", RoutePolicy::ApiKey)]);
        assert!(
            guards.captcha_modules.is_empty(),
            "an api-key writer must not demand a captcha it never renders"
        );
        assert!(!guards.needs_signer());
        assert!(!guards.needs_payments());
    }
}
