//! The UI surface (ADR 0010, issue #70). A module declares the actions it
//! serves and the views that compose them; `Harness::build` validates the
//! declaration and `GET /__surface` serves the composed document.
//!
//! An axum `Router` is opaque, so nothing here is discovered: a module says
//! what it offers, and the input schema of each action is derived with
//! `schemars` from the same serde type the handler deserializes, which is
//! what keeps the declaration from drifting. An action whose outcome is
//! `Json` may also publish an output schema, the shape of what it answers.
//!
//! UI hints ride on the schema as `x-cf-*` extension keywords set with
//! `#[schemars(extend("x-cf-label" = "Email"))]` on a field. The keywords
//! the renderer understands are listed in [`HINT_KEYWORDS`].

use std::collections::{BTreeSet, HashSet};

use http::Method;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::ConfigError;
use crate::module::{HARNESS_API, Module};
use crate::venture::Venture;

/// Contract version of the surface document, independent of
/// [`HARNESS_API`]: a renderer or the control plane checks it before
/// reading the document.
pub const SURFACE_API: u32 = 1;

/// Largest sidecar surface document the host will merge (issue #131). A
/// whole module's declaration is a few kilobytes; anything approaching
/// this cap is hostile or accidental, and parsing it costs the host.
pub const MAX_SIDECAR_SURFACE_BYTES: usize = 256 * 1024;
/// Largest action list a merged sidecar surface may declare (issue #131).
pub const MAX_SIDECAR_ACTIONS: usize = 64;
/// Largest view list a merged sidecar surface may declare (issue #131).
pub const MAX_SIDECAR_VIEWS: usize = 64;

/// The `x-cf-*` extension keywords the renderer understands on a field
/// schema. Anything else under `x-cf-` is ignored, never an error, so a
/// module can target a newer renderer than the one that serves it.
///
/// | Keyword | Value | Meaning |
/// |---|---|---|
/// | `x-cf-label` | string | Field label; defaults to the field name |
/// | `x-cf-placeholder` | string | Input placeholder |
/// | `x-cf-help` | string | Help text under the input |
/// | `x-cf-widget` | `"text"`, `"email"`, `"select"`, `"textarea"`, `"checkbox"`, `"hidden"` | Input widget; inferred from the schema when absent |
/// | `x-cf-hidden` | bool | Never rendered; the renderer supplies it (`captchaToken`) or omits it |
/// | `x-cf-options` | array of `{value, label}` | Choices for a `select`, when `enum` on the schema is not enough |
pub const HINT_KEYWORDS: &[&str] = &[
    "x-cf-label",
    "x-cf-placeholder",
    "x-cf-help",
    "x-cf-widget",
    "x-cf-hidden",
    "x-cf-options",
];

/// Who an action is for. Drives the public/admin split of `/__surface`
/// and, in the renderer, which pages need the admin session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Audience {
    /// Anyone; the action is the venture's public face (`join`,
    /// `subscribe`).
    Public,
    /// Needs `Authorization: Bearer <ADMIN_TOKEN>`; path must be under
    /// `/admin/`.
    Admin,
    /// Reached only through a signed link the module minted (`confirm`,
    /// `unsubscribe`, `status`); rendered as a landing page, never as a
    /// form.
    Link,
    /// Needs a signed-in caller — any of them, unless the level refuses
    /// everyone (issue #153, #385): on a deployment whose tenants come
    /// from a registry, a `tenant-members` table answers `500` to every
    /// caller, signed in or not.
    ///
    /// The vocabulary had `Public`, `Admin` and `Link` and no word for
    /// "somebody, and the route decides which rows they see". A declared
    /// table whose access is `owner` or `tenant-members` is exactly that,
    /// and calling it `Public` would publish a form for rows the caller
    /// cannot reach while calling it `Admin` would hide it from the
    /// person whose rows they are.
    ///
    /// It says a credential is needed and nothing more. **Which** rows
    /// the caller reaches is the table's access level, decided per
    /// request against the caller's own id; a surface cannot say that and
    /// should not pretend to.
    Subject,
}

/// What the browser should do with a successful response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Outcome {
    /// The module answers `202` (or `200`) with nothing the user needs to
    /// see; show `message`.
    Accepted { message: String },
    /// The module answers with a redirect the browser follows.
    Redirect,
    /// The module answers with a JSON body the view renders (`status`).
    Json,
}

/// One route the module serves, described for a renderer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    /// Kebab-case, unique within the module (`join`, `confirm`,
    /// `export-csv`).
    pub name: String,
    /// HTTP method, serialized as its upper-case name.
    #[serde(with = "method_serde")]
    pub method: Method,
    /// Path relative to `/v1/<module>`, always starting with `/`.
    pub path: String,
    pub audience: Audience,
    /// JSON Schema of the request body (or of the query for a `GET`).
    /// `None` for an action that takes nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Schema>,
    /// JSON Schema of the body a [`Json`](Outcome::Json) outcome answers
    /// with, so a consumer knows the shape of a read before calling it.
    /// `None` when the module does not say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Schema>,
    pub outcome: Outcome,
    /// The explicit protection this route demands (issue #133). Kept in
    /// sync with [`captcha`](Self::captcha) by the builders and asserted
    /// consistent by [`Surface::validate`]: `true` ⟺ [`HumanForm`].
    /// Deliberately not serialized: the surface document's wire shape is
    /// unchanged (`captcha` carries the human-route signal; machine
    /// routes never reach the public subset), so existing consumers and
    /// the compatibility-doc example are unaffected.
    ///
    /// [`HumanForm`]: crate::route_policy::RoutePolicy::HumanForm
    #[serde(skip)]
    pub policy: crate::route_policy::RoutePolicy,
    /// Whether the module verifies a captcha token on this action and the
    /// renderer includes the widget. A legacy mirror of `policy ==
    /// HumanForm` — the surface JSON keeps the `captcha` key for existing
    /// consumers; new code declares a `policy`.
    pub captcha: bool,
    /// How this **route** proves a signature delivery (issue #595),
    /// overriding the module-level
    /// [`signature_verification`](Module::signature_verification) default.
    /// Valid only on a [`Signature`] action — [`Surface::validate`]
    /// refuses it anywhere else. Deliberately not serialized, like
    /// [`policy`](Self::policy): the surface document's wire shape is
    /// unchanged. A billing module can name `Payments` on
    /// `POST /webhooks/stripe` and `Hmac` on `POST /webhooks/revenuecat`.
    ///
    /// [`Signature`]: crate::route_policy::RoutePolicy::Signature
    #[serde(skip)]
    pub verification: Option<crate::route_policy::SignatureVerification>,
}

impl Action {
    /// A public `POST` that answers `202`, the common case for a signup
    /// form. Add `.input::<Body>()`, `.captcha()` and friends.
    #[must_use]
    pub fn post(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self::new(name, Method::POST, path)
    }

    /// A `GET`. Audience defaults to `Link` because a module's `GET`s are
    /// the signed-link landings; call `.audience(..)` otherwise.
    #[must_use]
    pub fn get(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self::new(name, Method::GET, path)
            .audience(Audience::Link)
            .outcome(Outcome::Redirect)
    }

    /// A `DELETE`, admin by default.
    #[must_use]
    pub fn delete(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self::new(name, Method::DELETE, path)
            .audience(Audience::Admin)
            .outcome(Outcome::Json)
    }

    #[must_use]
    pub fn new(name: impl Into<String>, method: Method, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            method,
            path: path.into(),
            audience: Audience::Public,
            input: None,
            output: None,
            outcome: Outcome::Accepted {
                message: "Thanks, you're in.".to_owned(),
            },
            policy: crate::route_policy::RoutePolicy::default(),
            captcha: false,
            verification: None,
        }
    }

    #[must_use]
    pub fn audience(mut self, audience: Audience) -> Self {
        self.audience = audience;
        self
    }

    /// Derives the input schema from the handler's own body type.
    #[must_use]
    pub fn input<T: JsonSchema>(mut self) -> Self {
        self.input = Some(schema_for::<T>());
        self
    }

    /// Supplies a schema built by hand or adjusted after derivation (a
    /// `select` whose options come from runtime settings).
    #[must_use]
    pub fn input_schema(mut self, schema: Schema) -> Self {
        self.input = Some(schema);
        self
    }

    /// Derives the output schema from the type the handler answers with.
    #[must_use]
    pub fn output<T: JsonSchema>(mut self) -> Self {
        self.output = Some(schema_for::<T>());
        self
    }

    /// Supplies an output schema built by hand (a row shape declared at
    /// runtime rather than by a Rust type).
    #[must_use]
    pub fn output_schema(mut self, schema: Schema) -> Self {
        self.output = Some(schema);
        self
    }

    #[must_use]
    pub fn outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Shorthand for `.outcome(Outcome::Accepted { message })`.
    #[must_use]
    pub fn accepted(self, message: impl Into<String>) -> Self {
        self.outcome(Outcome::Accepted {
            message: message.into(),
        })
    }

    /// Shorthand for `.policy(RoutePolicy::HumanForm)` (issue #133).
    #[must_use]
    pub fn captcha(mut self) -> Self {
        self.policy = crate::route_policy::RoutePolicy::HumanForm;
        self.captcha = true;
        self
    }

    /// Declares how this route proves its requests are legitimate
    /// (issue #133). A payments webhook is `.policy(RoutePolicy::Signature)`
    /// — never `.captcha()`, which would render a widget a machine cannot
    /// fill and let the route be counted as captcha-protected.
    #[must_use]
    pub fn policy(mut self, policy: crate::route_policy::RoutePolicy) -> Self {
        self.policy = policy;
        self.captcha = policy == crate::route_policy::RoutePolicy::HumanForm;
        self
    }

    /// Names the verifier this route proves its signature deliveries with
    /// (issue #595), overriding the module's
    /// [`signature_verification`](Module::signature_verification). Only
    /// meaningful on a [`Signature`] route — [`Surface::validate`] refuses
    /// it on any other policy — so a module with one billing webhook per
    /// provider can declare `Payments` for Stripe and `Hmac` for the rest.
    ///
    /// [`Signature`]: crate::route_policy::RoutePolicy::Signature
    #[must_use]
    pub fn verification(
        mut self,
        verification: crate::route_policy::SignatureVerification,
    ) -> Self {
        self.verification = Some(verification);
        self
    }

    /// Whether this route needs the human-form gate: the declared
    /// [`HumanForm`] policy, or the legacy `captcha: true` mirror on an
    /// otherwise-`Open` route. The one place that alias is resolved, so
    /// the [`WriteGuards`] audit, the sidecar merge (issue #131) and the
    /// UI dispatch all check the same predicate.
    ///
    /// [`HumanForm`]: crate::route_policy::RoutePolicy::HumanForm
    /// [`WriteGuards`]: crate::route_policy::WriteGuards
    #[must_use]
    pub fn demands_captcha(&self) -> bool {
        self.policy == crate::route_policy::RoutePolicy::HumanForm || self.captcha
    }
}

/// A column of a [`View::Table`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Column {
    /// Field name in each row (the CSV header or JSON key).
    pub key: String,
    pub label: String,
}

impl Column {
    #[must_use]
    pub fn new(key: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
        }
    }
}

/// How actions compose into something to render.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum View {
    /// A form for one action.
    Form { action: String },
    /// A page that reads a `Json` action (the waitlist status).
    Status { action: String },
    /// A table over an action that returns rows (an admin export).
    Table {
        source: String,
        columns: Vec<Column>,
    },
}

impl View {
    #[must_use]
    pub fn form(action: impl Into<String>) -> Self {
        View::Form {
            action: action.into(),
        }
    }

    #[must_use]
    pub fn status(action: impl Into<String>) -> Self {
        View::Status {
            action: action.into(),
        }
    }

    #[must_use]
    pub fn table(source: impl Into<String>, columns: Vec<Column>) -> Self {
        View::Table {
            source: source.into(),
            columns,
        }
    }

    fn action_names(&self) -> Vec<&str> {
        match self {
            View::Form { action } | View::Status { action } => vec![action],
            View::Table { source, .. } => vec![source],
        }
    }
}

/// What a module declares from [`Module::surface`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Surface {
    pub actions: Vec<Action>,
    pub views: Vec<View>,
}

impl Surface {
    /// A module with no UI. The default of [`Module::surface`].
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    #[must_use]
    pub fn view(mut self, view: View) -> Self {
        self.views.push(view);
        self
    }

    /// `true` when nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.views.is_empty()
    }

    /// Validates the declaration for `module` into `errors`, collecting
    /// every problem (the `Harness::build` convention): duplicate or
    /// malformed action names, paths not starting with `/`, an `Admin`
    /// action outside `/admin/` (or a non-admin one inside it), an input
    /// or output schema that is not an object, an output on an action whose
    /// outcome is not `Json`, and views naming unknown actions.
    pub fn validate(&self, module: &str, errors: &mut ConfigError) {
        let mut seen: HashSet<&str> = HashSet::new();
        for action in &self.actions {
            let name = action.name.as_str();
            if !is_kebab(name) {
                errors.push(format!(
                    "module `{module}` surface action `{name}` must be kebab-case"
                ));
            }
            if !seen.insert(name) {
                errors.push(format!(
                    "module `{module}` surface declares action `{name}` twice"
                ));
            }
            if !action.path.starts_with('/') {
                errors.push(format!(
                    "module `{module}` surface action `{name}` path `{}` must start with '/' \
                     (relative to /v1/{module})",
                    action.path
                ));
            }
            if action.path.split('/').any(|segment| segment == "..") {
                errors.push(format!(
                    "module `{module}` surface action `{name}` path `{}` must not contain '..' \
                     segments (an action stays inside its module's mount)",
                    action.path
                ));
            }
            let under_admin = action.path == "/admin" || action.path.starts_with("/admin/");
            match action.audience {
                Audience::Admin if !under_admin => errors.push(format!(
                    "module `{module}` surface action `{name}` is admin but its path `{}` \
                     is not under /admin/",
                    action.path
                )),
                Audience::Public | Audience::Link | Audience::Subject if under_admin => {
                    errors.push(format!(
                        "module `{module}` surface action `{name}` is under /admin/ but its \
                         audience is not admin",
                    ));
                }
                _ => {}
            }
            if let Some(schema) = &action.input
                && !is_object_schema(schema)
            {
                errors.push(format!(
                    "module `{module}` surface action `{name}` input schema must describe an \
                     object (a struct with named fields), so a renderer can lay out fields"
                ));
            }
            if let Some(schema) = &action.output {
                if !is_object_schema(schema) {
                    errors.push(format!(
                        "module `{module}` surface action `{name}` output schema must describe \
                         an object, the JSON body the action answers with"
                    ));
                }
                if action.outcome != Outcome::Json {
                    errors.push(format!(
                        "module `{module}` surface action `{name}` declares an output schema \
                         but its outcome is not json; only a JSON body has a shape to publish"
                    ));
                }
            }
            match action.policy {
                crate::route_policy::RoutePolicy::HumanForm if !action.captcha => {
                    errors.push(format!(
                        "module `{module}` surface action `{name}` declares policy=HumanForm \
                         but captcha=false; the renderer would omit the widget the policy \
                         demands — declare protection with `.captcha()` (issue #133)",
                    ));
                }
                crate::route_policy::RoutePolicy::Signature if action.captcha => {
                    errors.push(format!(
                        "module `{module}` surface action `{name}` declares policy=Signature \
                         (a machine caller) but captcha=true; a captcha cannot protect a \
                         webhook — drop `.captcha()` (issue #133)",
                    ));
                }
                crate::route_policy::RoutePolicy::ApiKey if action.captcha => {
                    errors.push(format!(
                        "module `{module}` surface action `{name}` declares policy=ApiKey \
                         (a machine caller) but captcha=true; a captcha cannot protect an \
                         API-key route — drop `.captcha()` (issue #532)",
                    ));
                }
                // `Open` accepts either: `captcha: true` is the legacy
                // pre-#133 mirror (WriteGuards treats it as HumanForm),
                // and an Open unprotected route is the default.
                _ => {}
            }
            validate_verifier(module, name, action, errors);
        }
        for view in &self.views {
            for referenced in view.action_names() {
                if !seen.contains(referenced) {
                    errors.push(format!(
                        "module `{module}` surface view references action `{referenced}` \
                         which the module does not declare"
                    ));
                }
            }
        }
    }

    /// The subset a renderer may show without the admin session: every
    /// non-admin action that is not a machine route, and every view that
    /// references only those. [`Signature`](crate::route_policy::RoutePolicy::Signature)
    /// actions (webhooks) are called by providers, never by browsers —
    /// exposing them in the public surface was part of the issue #133
    /// confusion (a captcha widget rendered on a route no human submits).
    /// [`ApiKey`](crate::route_policy::RoutePolicy::ApiKey) actions
    /// (issue #532) are called by developer machines carrying a bearer
    /// key no browser has, so they stay out of the rendered surface for
    /// the same reason.
    #[must_use]
    pub fn public(&self) -> Surface {
        let actions: Vec<Action> = self
            .actions
            .iter()
            .filter(|action| {
                action.audience != Audience::Admin
                    && action.policy != crate::route_policy::RoutePolicy::Signature
                    && action.policy != crate::route_policy::RoutePolicy::ApiKey
            })
            .cloned()
            .collect();
        let names: BTreeSet<&str> = actions.iter().map(|a| a.name.as_str()).collect();
        let views = self
            .views
            .iter()
            .filter(|view| view.action_names().iter().all(|n| names.contains(n)))
            .cloned()
            .collect();
        Surface { actions, views }
    }
}

/// One module's entry in the composed document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSurface {
    pub name: String,
    pub version: String,
    #[serde(flatten)]
    pub surface: Surface,
}

/// The venture identity a renderer needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VentureSurface {
    pub name: String,
    pub public_url: String,
}

/// The document `GET /__surface` serves: composed at `Harness::build`, one
/// entry per module in mount order, modules with an empty surface omitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceDocument {
    pub surface_api: u32,
    pub harness_api: u32,
    pub venture: VentureSurface,
    pub modules: Vec<ModuleSurface>,
    /// The mounted renderer's build-time configuration (`UiMount::describe`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui: Option<serde_json::Value>,
}

impl SurfaceDocument {
    /// Composes the full document (admin actions included).
    #[must_use]
    pub fn compose(venture: &Venture, modules: &[std::sync::Arc<dyn Module>]) -> Self {
        let modules = modules
            .iter()
            .map(|module| ModuleSurface {
                name: module.name().to_owned(),
                version: module.version().to_owned(),
                surface: module.surface(),
            })
            .filter(|entry| !entry.surface.is_empty())
            .collect();
        Self {
            surface_api: SURFACE_API,
            harness_api: HARNESS_API,
            venture: VentureSurface {
                name: venture.name.clone(),
                public_url: venture.public_url.clone(),
            },
            modules,
            ui: None,
        }
    }

    /// The public subset: admin actions and the views over them removed,
    /// modules left with nothing omitted.
    #[must_use]
    pub fn public(&self) -> Self {
        Self {
            surface_api: self.surface_api,
            harness_api: self.harness_api,
            venture: self.venture.clone(),
            modules: self
                .modules
                .iter()
                .map(|entry| ModuleSurface {
                    name: entry.name.clone(),
                    version: entry.version.clone(),
                    surface: entry.surface.public(),
                })
                .filter(|entry| !entry.surface.is_empty())
                .collect(),
            ui: self.ui.clone(),
        }
    }
}

/// Validates a sidecar's `/__surface` answer against the mount it is
/// served from, and returns the single public entry to merge (issue #131).
/// A sidecar speaks for exactly one module and only its public part ever
/// merges — its admin actions stay behind its own token — so anything
/// else in the document is rejected wholesale rather than filtered:
/// a wrong contract version, a missing or duplicated mount entry, or a
/// surface that fails [`Surface::validate`] or exceeds the declaration
/// caps. `Ok(empty)` means the sidecar declared no surface for the mount,
/// which contributes nothing and is not a failure.
pub(crate) fn sanitize_sidecar_document(
    document: &SurfaceDocument,
    mount: &str,
) -> Result<Vec<ModuleSurface>, Vec<String>> {
    let mut errors = Vec::new();
    if document.surface_api != SURFACE_API {
        errors.push(format!(
            "surface contract {} is not {SURFACE_API}",
            document.surface_api
        ));
    }
    if document.harness_api != HARNESS_API {
        errors.push(format!(
            "harness contract {} is not {HARNESS_API}",
            document.harness_api
        ));
    }
    let named: Vec<&ModuleSurface> = document
        .modules
        .iter()
        .filter(|entry| entry.name == mount)
        .collect();
    match named.len() {
        0 => {
            if !document.modules.is_empty() {
                let others: Vec<&str> = document.modules.iter().map(|m| m.name.as_str()).collect();
                errors.push(format!(
                    "declares no surface for the mounted module `{mount}` (it names [{}] instead)",
                    others.join(", ")
                ));
            }
        }
        1 => {}
        count => errors.push(format!("declares module `{mount}` {count} times")),
    }
    if let Some(entry) = named.first() {
        if entry.surface.actions.len() > MAX_SIDECAR_ACTIONS {
            errors.push(format!(
                "declares {} actions, more than the {MAX_SIDECAR_ACTIONS} a merged surface allows",
                entry.surface.actions.len()
            ));
        }
        if entry.surface.views.len() > MAX_SIDECAR_VIEWS {
            errors.push(format!(
                "declares {} views, more than the {MAX_SIDECAR_VIEWS} a merged surface allows",
                entry.surface.views.len()
            ));
        }
        let mut validation = ConfigError::default();
        entry.surface.validate(mount, &mut validation);
        errors.extend(validation.problems);
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(named
        .into_iter()
        .map(|entry| ModuleSurface {
            name: entry.name.clone(),
            version: entry.version.clone(),
            surface: entry.surface.public(),
        })
        .collect())
}

/// Removes every action that demands the human-form gate, and the views
/// left dangling by it, returning how many actions were dropped (issue
/// #131). A production host with no `Captcha` port cannot render or
/// verify a captcha widget for a merged sidecar action, so the honest
/// answer is that the action is not publicly offered here — the same
/// refusal [`crate::route_policy::production_readiness`] makes at boot
/// for in-process modules, enforced at merge time because a sidecar's
/// declaration is not known then.
pub(crate) fn strip_unguarded_captcha_actions(surface: &mut Surface) -> usize {
    let kept: Vec<Action> = surface
        .actions
        .iter()
        .filter(|action| !action.demands_captcha())
        .cloned()
        .collect();
    let dropped = surface.actions.len() - kept.len();
    if dropped > 0 {
        let names: std::collections::BTreeSet<&str> =
            kept.iter().map(|a| a.name.as_str()).collect();
        surface
            .views
            .retain(|view| view.action_names().iter().all(|n| names.contains(n)));
        surface.actions = kept;
    }
    dropped
}

/// Where the current surface comes from (issue #76). With no sidecar
/// mounted this is the document composed at build; with sidecars, each
/// call fetches every mounted sidecar's `/__surface` (public part) and
/// merges it in, so a sidecar redeploy is seen on the next request
/// (ADR 0009). An unreachable sidecar contributes nothing and is logged.
#[async_trait::async_trait]
pub trait SurfaceSource: Send + Sync {
    /// The full document: admin actions of in-process modules included,
    /// sidecar modules appended.
    async fn current(&self) -> std::sync::Arc<SurfaceDocument>;
    /// The build-time document alone, for checks that must not wait on a
    /// network (a `UiSpec` validated against what the artifact ships).
    fn built(&self) -> std::sync::Arc<SurfaceDocument>;
    /// A prerendered build-time document (admin variant when `admin`),
    /// if the source keeps one; `None` means render the current document.
    fn rendered(&self, admin: bool) -> Option<&RenderedSurface> {
        let _ = admin;
        None
    }
}

/// What a UI renderer gets from the harness (ADR 0010). Built by
/// `Harness::router` for every router it assembles.
pub struct UiContext {
    /// The composed surface, admin actions included; the renderer applies
    /// its own audience rules per page. Sidecar modules arrive through
    /// [`SurfaceSource::current`].
    pub surface: std::sync::Arc<dyn SurfaceSource>,
    /// The `/v1` API router, for in-process dispatch: a form post becomes
    /// the JSON request the module accepts and is sent through this
    /// service, so every module layer runs and nothing leaves the process.
    /// The request must carry the caller's [`crate::Scope`] in its
    /// extensions, because the scope layer sits above `/v1`.
    pub api: axum::Router,
    pub config: std::sync::Arc<dyn crate::config::Config>,
    pub venture: std::sync::Arc<Venture>,
    /// Whether the `Captcha` port is configured, so the renderer knows to
    /// include the widget on actions that declare `captcha`.
    pub captcha_configured: bool,
    /// The `Signer`, for the admin session cookie (issue #74). Absent
    /// means no admin UI, the way an unset `ADMIN_TOKEN` does.
    pub signer: Option<std::sync::Arc<dyn crate::ports::Signer>>,
    /// The `RateLimiter`, for the admin login form.
    pub rate_limiter: Option<std::sync::Arc<dyn crate::ports::RateLimiter>>,
}

/// A renderer the venture mounts at `/ui` with `HarnessBuilder::ui`
/// (ADR 0010). Core defines the seam; `cratefield-ui` is the implementation,
/// kept out of core so a venture without a UI carries no `maud`.
pub trait UiMount: Send + Sync + 'static {
    /// The router nested at `/ui`, built per `Harness::router` call.
    fn router(&self, ctx: UiContext) -> axum::Router;
    /// Build-time check of whatever the renderer was configured with (a
    /// `UiSpec`) against the composed surface; problems go into the same
    /// list as every other build error.
    fn validate(&self, surface: &SurfaceDocument, errors: &mut ConfigError) {
        let _ = (surface, errors);
    }
    /// The renderer's build-time configuration as JSON, published in the
    /// surface document as `ui` so tooling can read the copy and theme a
    /// venture ships with.
    fn describe(&self) -> Option<serde_json::Value> {
        None
    }
}

/// A document serialized once, with the strong `ETag` clients revalidate
/// against. Built at `Harness::build` for both the public and the admin
/// variant.
#[derive(Debug, Clone)]
pub struct RenderedSurface {
    pub json: String,
    /// Quoted strong validator: `"<first 32 hex of sha256(json)>"`.
    pub etag: String,
}

impl RenderedSurface {
    #[must_use]
    pub fn render(document: &SurfaceDocument) -> Self {
        let json = serde_json::to_string(document).unwrap_or_else(|_| "{}".to_owned());
        let digest = Sha256::digest(json.as_bytes());
        let mut hex = String::with_capacity(32);
        for byte in &digest[..16] {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Self {
            json,
            etag: format!("\"{hex}\""),
        }
    }
}

/// Generates the schema for `T` the way every action does: draft 2020-12,
/// definitions inlined so a renderer never has to resolve `$ref`.
#[must_use]
pub fn schema_for<T: JsonSchema>() -> Schema {
    let mut settings = schemars::generate::SchemaSettings::draft2020_12();
    settings.inline_subschemas = true;
    SchemaGenerator::new(settings).into_root_schema_for::<T>()
}

/// Sets one `x-cf-*` (or any) keyword on a field of an object schema after
/// derivation, for hints that only exist at runtime: a `select` whose
/// options are the configured product list. Unknown fields are ignored so
/// a rename in the body type cannot panic at build.
pub fn hint_field(schema: &mut Schema, field: &str, key: &str, value: serde_json::Value) {
    if let Some(properties) = schema
        .as_object_mut()
        .and_then(|root| root.get_mut("properties"))
        .and_then(serde_json::Value::as_object_mut)
        && let Some(property) = properties
            .get_mut(field)
            .and_then(serde_json::Value::as_object_mut)
    {
        property.insert(key.to_owned(), value);
    }
}

fn is_object_schema(schema: &Schema) -> bool {
    let value = schema.as_value();
    match value.get("type") {
        Some(serde_json::Value::String(t)) => t == "object",
        Some(serde_json::Value::Array(types)) => types.iter().any(|t| t == "object"),
        _ => value.get("properties").is_some(),
    }
}

/// A per-route verifier describes how a webhook proves a delivery, so it
/// belongs only on a [`Signature`] policy route (issue #595).
///
/// [`Signature`]: crate::route_policy::RoutePolicy::Signature
fn validate_verifier(module: &str, name: &str, action: &Action, errors: &mut ConfigError) {
    if action.verification.is_some() && action.policy != crate::route_policy::RoutePolicy::Signature
    {
        errors.push(format!(
            "module `{module}` surface action `{name}` names a signature verifier but its \
             policy is not Signature; only a webhook route can say how it verifies deliveries \
             — drop `.verification(..)` or declare `.policy(RoutePolicy::Signature)` \
             (issue #595)",
        ));
    }
}

fn is_kebab(name: &str) -> bool {
    !name.is_empty()
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

mod method_serde {
    use http::Method;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        method: &Method,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        method.as_str().serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Method, D::Error> {
        let text = String::deserialize(deserializer)?;
        Method::from_bytes(text.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(JsonSchema)]
    #[allow(dead_code)]
    struct JoinBody {
        #[schemars(extend("x-cf-label" = "Email", "x-cf-widget" = "email"))]
        email: String,
        product: String,
        #[schemars(extend("x-cf-hidden" = true))]
        #[serde(rename = "captchaToken")]
        captcha_token: Option<String>,
    }

    fn join() -> Action {
        Action::post("join", "/").input::<JoinBody>().captcha()
    }

    fn errors_of(surface: &Surface) -> Vec<String> {
        let mut errors = ConfigError::default();
        surface.validate("waitlist", &mut errors);
        match errors.into_result() {
            Ok(()) => Vec::new(),
            Err(err) => err.to_string().lines().skip(1).map(str::to_owned).collect(),
        }
    }

    #[test]
    fn schema_carries_hints_and_is_inlined() {
        let schema = schema_for::<JoinBody>();
        let value = schema.as_value();
        assert_eq!(value["type"], "object");
        assert_eq!(value["properties"]["email"]["x-cf-label"], "Email");
        assert_eq!(value["properties"]["email"]["x-cf-widget"], "email");
        assert_eq!(value["properties"]["captchaToken"]["x-cf-hidden"], true);
        assert!(value.get("$defs").is_none(), "subschemas must be inlined");
    }

    #[test]
    fn hint_field_sets_a_keyword_and_ignores_unknown_fields() {
        let mut schema = schema_for::<JoinBody>();
        hint_field(
            &mut schema,
            "product",
            "enum",
            serde_json::json!(["a", "b"]),
        );
        hint_field(&mut schema, "missing", "x-cf-label", serde_json::json!("x"));
        let value = schema.as_value();
        assert_eq!(
            value["properties"]["product"]["enum"],
            serde_json::json!(["a", "b"])
        );
        assert!(value["properties"].get("missing").is_none());
    }

    #[test]
    fn valid_surface_has_no_errors() {
        let surface = Surface::new()
            .action(join())
            .action(Action::get("confirm", "/confirm"))
            .action(
                Action::get("export", "/admin/export.csv")
                    .audience(Audience::Admin)
                    .outcome(Outcome::Json)
                    .output::<JoinBody>(),
            )
            .view(View::form("join"))
            .view(View::table("export", vec![Column::new("email", "Email")]));
        assert!(errors_of(&surface).is_empty());
    }

    #[test]
    fn every_validation_rule_names_the_module_and_action() {
        #[derive(JsonSchema)]
        #[allow(dead_code)]
        struct NotAnObject(Vec<String>);

        let surface = Surface::new()
            .action(join())
            .action(join())
            .action(Action::post("Bad Name", "no-slash"))
            .action(Action::post("hidden", "/admin/thing"))
            .action(Action::delete("wipe", "/wipe"))
            .action(Action::post("list", "/list").input::<NotAnObject>())
            .action(
                Action::get("rows", "/rows")
                    .outcome(Outcome::Json)
                    .output::<NotAnObject>(),
            )
            .action(Action::post("send", "/send").output::<JoinBody>())
            .view(View::form("missing"));
        let errors = errors_of(&surface);
        let joined = errors.join("\n");
        for needle in [
            "declares action `join` twice",
            "action `Bad Name` must be kebab-case",
            "path `no-slash` must start with '/'",
            "action `hidden` is under /admin/ but its audience is not admin",
            "action `wipe` is admin but its path `/wipe` is not under /admin/",
            "action `list` input schema must describe an object",
            "action `rows` output schema must describe an object",
            "action `send` declares an output schema but its outcome is not json",
            "view references action `missing`",
        ] {
            assert!(joined.contains(needle), "missing `{needle}` in:\n{joined}");
        }
        assert!(joined.lines().all(|l| l.contains("`waitlist`")), "{joined}");
    }

    #[test]
    fn public_subset_drops_admin_actions_and_their_views() {
        let surface = Surface::new()
            .action(join())
            .action(
                Action::get("export", "/admin/export.csv")
                    .audience(Audience::Admin)
                    .outcome(Outcome::Json),
            )
            .view(View::form("join"))
            .view(View::table("export", vec![]));
        let public = surface.public();
        assert_eq!(public.actions.len(), 1);
        assert_eq!(public.views.len(), 1);
        assert!(matches!(public.views[0], View::Form { .. }));
    }

    #[test]
    fn rendered_surface_etag_is_stable_and_differs_per_variant() {
        let doc = SurfaceDocument {
            surface_api: SURFACE_API,
            harness_api: HARNESS_API,
            venture: VentureSurface {
                name: "v".into(),
                public_url: "https://v.test".into(),
            },
            modules: vec![ModuleSurface {
                name: "waitlist".into(),
                version: "0.1.0".into(),
                surface: Surface::new()
                    .action(join())
                    .action(Action::delete("wipe", "/admin/wipe")),
            }],
            ui: None,
        };
        let full = RenderedSurface::render(&doc);
        let again = RenderedSurface::render(&doc);
        let public = RenderedSurface::render(&doc.public());
        assert_eq!(full.etag, again.etag);
        assert_ne!(full.etag, public.etag);
        assert!(full.etag.starts_with('"') && full.etag.ends_with('"'));
        assert_eq!(full.etag.len(), 34);
        let parsed: serde_json::Value = serde_json::from_str(&full.json).unwrap();
        assert_eq!(parsed["modules"][0]["actions"][0]["method"], "POST");
        assert_eq!(parsed["modules"][0]["actions"][1]["audience"], "admin");
        assert_eq!(parsed["surface_api"], SURFACE_API);
    }

    #[test]
    fn document_omits_modules_without_a_surface() {
        struct Silent;
        impl Module for Silent {
            fn name(&self) -> &'static str {
                "silent"
            }
            fn version(&self) -> &'static str {
                "0.0.0"
            }
            fn requires(&self) -> &'static [crate::ports::Port] {
                &[]
            }
            fn migrations(&self) -> crate::module::Migrations {
                crate::module::Migrations::EMPTY
            }
            fn validate_config(&self, _: &dyn crate::config::Config) -> Result<(), ConfigError> {
                Ok(())
            }
            fn router(&self, _: crate::module::ModuleContext) -> axum::Router {
                axum::Router::new()
            }
        }
        let venture = Venture::new("v", "v.test");
        let modules: Vec<std::sync::Arc<dyn Module>> = vec![std::sync::Arc::new(Silent)];
        let doc = SurfaceDocument::compose(&venture, &modules);
        assert!(doc.modules.is_empty());
    }

    #[test]
    fn an_api_key_action_refuses_a_captcha_and_hides_from_the_public_surface() {
        // A renderer-side document can still carry the impossible pair
        // (policy=ApiKey, captcha=true) — the validator refuses it, the
        // same rule a Signature webhook runs under (issue #532).
        let mut action =
            Action::post("sync", "/sync").policy(crate::route_policy::RoutePolicy::ApiKey);
        action.captcha = true;
        let errors = errors_of(&Surface::new().action(action));
        assert!(
            errors.iter().any(|error| error.contains("policy=ApiKey")),
            "{errors:?}"
        );

        // And the rendered public surface never shows an api-key action:
        // a browser has no key to present, so a form on one is the same
        // issue-#133 confusion a webhook widget was.
        let surface = Surface::new()
            .action(Action::post("sync", "/sync").policy(crate::route_policy::RoutePolicy::ApiKey))
            .action(join());
        let public = surface.public();
        assert!(public.actions.iter().all(|action| action.name != "sync"));
        assert!(public.actions.iter().any(|action| action.name == "join"));
    }

    #[test]
    fn only_a_signature_action_may_name_a_verifier() {
        // A per-route verifier says how a webhook proves a delivery. On
        // any other policy it is a claim the gate cannot honour, so the
        // validator refuses it (issue #595).
        let stray = Action::post("join", "/").captcha().verification(
            crate::route_policy::SignatureVerification::Hmac {
                secret: "WEBHOOK_SECRET",
            },
        );
        let errors = errors_of(&Surface::new().action(stray));
        assert!(
            errors
                .iter()
                .any(|error| error.contains("policy is not Signature")),
            "{errors:?}"
        );

        // A Signature route accepts it — both the default and a per-route
        // HMAC verifier.
        let accepted = Surface::new()
            .action(
                Action::post("stripe", "/webhooks/stripe")
                    .policy(crate::route_policy::RoutePolicy::Signature),
            )
            .action(
                Action::post("revenuecat", "/webhooks/revenuecat")
                    .policy(crate::route_policy::RoutePolicy::Signature)
                    .verification(crate::route_policy::SignatureVerification::Hmac {
                        secret: "REVENUECAT_WEBHOOK_SECRET",
                    }),
            );
        assert!(errors_of(&accepted).is_empty());
    }
}
