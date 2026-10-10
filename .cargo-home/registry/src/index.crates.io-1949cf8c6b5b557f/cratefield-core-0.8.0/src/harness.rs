//! The `Harness` builder and axum router assembly (issue #2, architecture
//! section 4).
//!
//! `Harness::build()` collects **all** configuration problems and reports
//! them together; `Harness::router(ports)` mounts every module under
//! `/v1/<name>` and adds `GET /__health` and `GET /__ready` plus the
//! middleware stack from architecture section 6.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use serde_json::json;
use tracing::error;

use crate::admin::require_admin;
use crate::config::Config;
use crate::config::ConfigError;
use crate::events::EventBus;
use crate::http::{
    Json, MAX_BODY_BYTES, ScopeState, cors_layer, rate_limited, scope_layer,
    security_headers_layer, token_response_layer,
};
use crate::module::{HARNESS_API, Module, ModuleContext, harness_api_mismatch};
use crate::ports::Dispatcher;
use crate::ports::{
    Clock, Database, Port, Ports, RateLimiter, Statement, SystemClock, warn_undeclared_ports,
};
use crate::problem::Problem;
use crate::problems::SLUGS;
use crate::rate_limit::{RateLimit, RateLimitFailure};
use crate::route_policy::deployed_env;
use crate::scheduled::ScheduledBudget;
use crate::scope::Scope;
use crate::sidecar::{
    GatewayGuard, SIDECAR_REQUIRE_GATEWAY, SidecarMount, X_HARNESS_GATEWAY, gateway_guard,
    gateway_signer, mint_gateway, truthy,
};
use crate::signer::HmacSigner;
use crate::stream::{RequestStream, StreamRoute};
use crate::surface::{
    MAX_SIDECAR_SURFACE_BYTES, RenderedSurface, SurfaceDocument, SurfaceSource, UiContext, UiMount,
    sanitize_sidecar_document, strip_unguarded_captcha_actions,
};
use crate::template::{Template, TemplateRegistry};
use crate::venture::{Venture, VentureEnv};

/// The two checks about a module's tables: that nobody else claimed one, and
/// that its personal-data declarations can mean something.
///
/// Extracted from `HarnessBuilder::build`, which sat one line under the
/// workspace's function-length lint before this. Collecting one more category
/// of problem should not be what makes that function too long to follow, and
/// the two checks read better together anyway: both are about the tables the
/// module just claimed, and the second is only meaningful against the first.
fn check_tables(
    module: &dyn Module,
    tables: &mut HashMap<&'static str, &'static str>,
    errors: &mut ConfigError,
) {
    let name = module.name();
    for table in module.tables() {
        match tables.get(table) {
            Some(owner) => errors.push(format!(
                "duplicate table `{table}` claimed by modules `{owner}` and `{name}`"
            )),
            None => {
                tables.insert(table, name);
            }
        }
    }

    // Against the tables the module just claimed, so a rename that misses a
    // declaration is a build error rather than a row that quietly stops being
    // exported.
    let owns = module.tables();
    let mut declared: Vec<&'static str> = Vec::new();
    for set in module.personal_data() {
        for problem in set.validate(name, owns) {
            errors.push(problem);
        }
        if declared.contains(&set.table) {
            errors.push(format!(
                "module `{name}` declares table `{}` twice in personal_data()",
                set.table
            ));
        }
        declared.push(set.table);
    }
}

/// A runtime resolves environment bindings into [`Ports`] and declares
/// statically which ports it can provide, so `Harness::build` can reject a
/// module that requires something the runtime will never hand it
/// (ADR 0002). Reference implementation: `cratefield-runtime-cloudflare`.
pub trait Runtime: Send + Sync + 'static {
    fn provides(&self) -> Vec<Port>;
    /// Whether the named port is not merely present but usable for its
    /// production duty (issue #133): a captcha adapter that reports
    /// itself unbound cannot protect a `HumanForm` route, so the runtime
    /// that wraps it says "no" here even though `provides()` lists the
    /// port. Default: presence in `provides()`.
    fn effectively_configured(&self, port: Port) -> bool {
        self.provides().contains(&port)
    }
}

/// A built harness: immutable after `build()`.
pub struct Harness {
    venture: Arc<Venture>,
    modules: Vec<Arc<dyn Module>>,
    templates: Arc<TemplateRegistry>,
    events: EventBus,
    runtime: Option<Arc<dyn Runtime>>,
    /// The single module-provided `/.well-known` router, if any
    /// (issue #46); nested at the root by `router()`.
    well_known: Option<Router>,
    /// The composed UI surface (ADR 0010), rendered once for
    /// `GET /__surface`: the admin variant and the public subset.
    surface: Arc<SurfaceVariants>,
    /// The renderer mounted at `/ui`, if the venture chose one.
    ui: Option<Arc<dyn UiMount>>,
    /// Every module's personal-data declarations, composed once at build so a
    /// request does not walk the module list to answer an export.
    personal_data: Arc<crate::PersonalDataCatalog>,
    /// Whether the boot has already recorded the operator's
    /// `HARNESS_ALLOW_UNPROTECTED_WRITES` acceptance (issue #143), and the
    /// `HARNESS_ALLOW_UNLIMITED_PUBLIC_ROUTES` one (issue #437). Workers
    /// rebuild the router per request, so the recording has to gate itself:
    /// one line per waiver, the first time the gate serves on it — not one
    /// per request. Per-`Harness` rather than a process static, which is the
    /// same span in every real deployment (the harness is built once per
    /// isolate) and keeps tests and multi-venture hosts from suppressing
    /// each other's records.
    unprotected_acceptance_recorded: AtomicBool,
    unlimited_acceptance_recorded: AtomicBool,
}

struct SurfaceVariants {
    document: Arc<SurfaceDocument>,
    full: RenderedSurface,
    public: RenderedSurface,
}

impl SurfaceVariants {
    fn compose(
        venture: &Venture,
        modules: &[Arc<dyn Module>],
        ui: Option<&Arc<dyn UiMount>>,
    ) -> Self {
        let mut document = SurfaceDocument::compose(venture, modules);
        document.ui = ui.and_then(|ui| ui.describe());
        Self {
            full: RenderedSurface::render(&document),
            public: RenderedSurface::render(&document.public()),
            document: Arc::new(document),
        }
    }
}

impl std::fmt::Debug for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let modules: Vec<&str> = self.modules.iter().map(|m| m.name()).collect();
        f.debug_struct("Harness")
            .field("venture", &self.venture.name)
            .field("modules", &modules)
            .finish_non_exhaustive()
    }
}

impl Harness {
    /// Cheap shared handle: composition is `Arc` fields, so the only
    /// sensible clone is the `Arc` itself. The reconciler hands one
    /// `Arc` to every tenant task it fans out.
    #[must_use]
    pub fn clone_arc(self: &std::sync::Arc<Self>) -> std::sync::Arc<Self> {
        std::sync::Arc::clone(self)
    }
    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::default()
    }

    pub fn venture(&self) -> &Arc<Venture> {
        &self.venture
    }

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    /// The largest body a runtime may buffer for the route at `path`,
    /// answerable before any byte of it has been read (issue #440).
    ///
    /// `DefaultBodyLimit` inside `router()` is the precise per-route
    /// enforcer, but it fires only once the body is already resident — too
    /// late for a runtime that must buffer into a fixed memory ceiling (a
    /// Workers isolate). This is the coarse pre-buffer ceiling that runtime
    /// consults instead: for a path of the form `/v1/<name>` or
    /// `/v1/<name>/...` it is the named module's [`Module::max_body_bytes`],
    /// and for everything else — an unknown module, `/ui/*`, `/__events`,
    /// `/.well-known/*`, or any path outside `/v1` — [`MAX_BODY_BYTES`].
    ///
    /// The result is floored at [`MAX_BODY_BYTES`] even for the module
    /// routes: a module may raise the ceiling for a route (LinkedIn's image
    /// upload), but the runtime guard sits in front of the router, and a
    /// module that tightened it below what the router itself accepts would
    /// 413 working requests.
    ///
    /// `path` is the URL path only — what `url.path()` returns. A query
    /// string is tolerated and ignored, and empty segments from a leading,
    /// trailing or doubled slash are collapsed; `/v1` with no module
    /// segment is simply the default ceiling.
    pub fn max_body_bytes(&self, path: &str, cfg: &dyn Config) -> usize {
        let Some((name, _)) = module_and_segments(path) else {
            return MAX_BODY_BYTES;
        };
        self.modules
            .iter()
            .find(|module| module.name() == name)
            .map_or(MAX_BODY_BYTES, |module| {
                MAX_BODY_BYTES.max(module.max_body_bytes(cfg))
            })
    }

    /// The streaming route that serves `method` at `path`, if the module
    /// mounted there declared one — answering its own
    /// [`StreamRoute::max_bytes`] ceiling (issue #585).
    ///
    /// The counterpart of [`Harness::max_body_bytes`] on the streaming side:
    /// a runtime consults this **before** reading a body, to know whether
    /// the route streams (and with what ceiling) or buffers, exactly as
    /// `max_body_bytes` tells it how much a buffered route may hold. The
    /// ceiling is returned verbatim — a streaming route's `max_bytes` is the
    /// precise per-route limit, not a coarse pre-buffer guard, so it is not
    /// floored at [`MAX_BODY_BYTES`].
    ///
    /// Path normalisation is exact, not [`Harness::max_body_bytes`]': a query
    /// or fragment is ignored, but empty segments are **not** collapsed, so a
    /// trailing or doubled slash matches no route — the request then keeps
    /// its buffered body and axum's own 404, exactly as without streaming.
    /// `path` is the URL path only; `method` is the request's.
    pub fn streaming_route(&self, path: &str, method: &axum::http::Method) -> Option<usize> {
        let (name, segments) = exact_module_and_segments(path)?;
        let module = self.modules.iter().find(|module| module.name() == name)?;
        match_streaming(module.streaming_routes(), method, &segments)
    }

    pub fn templates(&self) -> &Arc<TemplateRegistry> {
        &self.templates
    }

    pub fn events(&self) -> &EventBus {
        &self.events
    }

    /// Builds the context a module sees: its declared ports (view), the
    /// config, the shared bus, templates and venture. `router()` uses this
    /// per module; `cratefield-runtime-cloudflare` uses it for scheduled
    /// fan-out.
    pub fn module_context(&self, module: &dyn Module, ports: &Ports) -> ModuleContext {
        // `venture.env` here is the environment the **deployment**
        // declares, not the compiled default (issue #143).
        //
        // #143 corrected the boot gate and the surface merge and left
        // this path alone, which is the one that decides per request. A
        // module reading `ctx.venture.env` was getting `Development` on a
        // Worker serving production — and `module-waitlist` reads exactly
        // that to decide whether a missing `Captcha` port fails closed.
        // So the rule that says "no captcha port in production is a
        // refusal" never fired for the venture it was written for.
        //
        // Corrected here rather than at the call site so the field cannot
        // lie: leaving `ctx.venture.env` looking right and being wrong is
        // how this survived the fix that was meant to remove it.
        let venture = self.venture_as_deployed(ports.config.as_ref());
        ModuleContext {
            config: Arc::clone(&ports.config),
            ports: ports.view_for(module),
            events: self.events_for(ports),
            templates: Arc::clone(&self.templates),
            venture,
            unprotected_writes_accepted: crate::route_policy::unprotected_writes_override(
                ports.config.as_ref(),
            )
            .is_some(),
            personal_data: Arc::clone(&self.personal_data),
            ui_mounted: self.ui.is_some(),
            // Unbounded: the core has no invocation limits to spend. The
            // runtimes replace this per module during scheduled fan-out
            // (issue #537); request handlers keep this one.
            scheduled: Arc::new(ScheduledBudget::unbounded()),
        }
    }

    /// The sidecar mounts that apply: read from configuration, not from
    /// the composition (ADR 0009), so the same artifact serves ventures
    /// with and without them. A malformed table mounts nothing and is
    /// logged; a mount that collides with an in-process module is
    /// dropped and logged. Neither takes down the in-process modules.
    /// This deployment's sidecar-role enforcement state (issue #131):
    /// whether the gate is closed, the key that verifies a stamp, and the
    /// sidecar's own admin token — which never crosses the boundary and is
    /// only ever re-asserted for a request the host already authorized.
    fn gateway_guard_state(ports: &Ports, gateway: Option<&Arc<HmacSigner>>) -> GatewayGuard {
        GatewayGuard {
            require: truthy(ports.config.as_ref(), SIDECAR_REQUIRE_GATEWAY),
            signer: gateway.map(Arc::clone),
            admin_token: ports
                .config
                .get("ADMIN_TOKEN")
                .filter(|token| !token.is_empty()),
        }
    }

    /// The surface this deployment serves: the composed one, plus any
    /// mounted sidecar's public part merged in per request (issue #131).
    fn merged_surface(
        &self,
        mounts: Vec<SidecarMount>,
        ports: &Ports,
        gateway: Option<Arc<HmacSigner>>,
        env: VentureEnv,
    ) -> Arc<dyn SurfaceSource> {
        Arc::new(MergedSurface {
            base: Arc::clone(&self.surface),
            mounts,
            dispatcher: ports.dispatcher.clone(),
            gateway,
            env,
            captcha_configured: ports.captcha.is_some(),
        })
    }

    /// The venture descriptor with the environment the **deployment**
    /// declares (issue #143), which is what anything reporting or
    /// enforcing on it must read. Returns the original `Arc` untouched
    /// when the two already agree, which is every venture that sets its
    /// environment honestly in code.
    fn venture_as_deployed(&self, config: &dyn Config) -> Arc<Venture> {
        let env = deployed_env(self.venture.env, config);
        if env == self.venture.env {
            return Arc::clone(&self.venture);
        }
        let mut deployed = (*self.venture).clone();
        deployed.env = env;
        Arc::new(deployed)
    }

    /// Nests each in-process module under its `/v1/<name>` prefix.
    /// Split out of [`Harness::router`] so that method stays readable.
    /// Layered in [`Harness::router`], not here: a layer applied inside
    /// this function would wrap only the module routes, and the sidecar
    /// prefixes nested after it would sit outside the admin floor.
    fn nest_modules(&self, ports: &Ports) -> Router {
        let mut api = Router::new();
        for module in &self.modules {
            let ctx = self.module_context(module.as_ref(), ports);
            api = api.nest(&format!("/v1/{}", module.name()), module.router(ctx));
        }
        api
    }

    /// The production readiness verdict for the environment this
    /// deployment actually runs in (issue #143).
    ///
    /// `HarnessBuilder::build` already ran this against the **compiled**
    /// `Venture::env`. When the deployment declares a stricter one that
    /// check was made against the wrong environment, so it is re-made
    /// here against the same runtime report — the answer must not depend
    /// on whether anyone remembered to call `.env()`.
    ///
    /// The limiter leg is decided here against the **resolved** port, not
    /// the runtime's advertisement (issue #437): a Cloudflare binding that
    /// fails to resolve degrades to `ports.rate_limiter == None`, and this
    /// is the check that catches it. The signer leg likewise (issue #478):
    /// a harness configuration that fails to parse leaves `ports.signer ==
    /// None` behind an advertised `Port::Signer`.
    fn production_readiness_now(
        &self,
        env: VentureEnv,
        config: &dyn Config,
        rate_limiter_ready: bool,
        signer_ready: bool,
    ) -> Vec<String> {
        if let Some(note) = crate::route_policy::env_disagreement(self.venture.env, env) {
            tracing::warn!("{note}");
            crate::logging::forward_control_event(crate::logging::ControlLevel::Warn, &note);
        }
        // Each escape hatch is read here — in the serving path — and
        // passed to its own leg, so a waiver covers exactly the control it
        // names and refuses alongside whatever remains unwaived.
        let unprotected = crate::route_policy::unprotected_writes_override(config);
        let unlimited = crate::route_policy::unlimited_public_routes_override(config);
        let guards = crate::route_policy::WriteGuards::collect(&self.modules);
        let mut problems = crate::route_policy::production_readiness(
            env,
            &guards,
            self.runtime.as_ref(),
            rate_limiter_ready,
            signer_ready,
            unprotected.as_deref(),
            unlimited.as_deref(),
        );
        // The webhook-secret leg is boot-time-only (issue #533): it reads
        // the deployment config, which the build-time gate does not have.
        // It has no waiver, so it is held out of the loop below — that loop
        // names the escape hatch, which clears nothing here.
        let hmac_problems = crate::route_policy::webhook_secret_readiness(env, &guards, config);
        if problems.is_empty() && hmac_problems.is_empty() {
            // An operator may accept this deployment's gaps explicitly,
            // and the acceptance is recorded rather than discarded
            // (issue #143) — once, even though Workers rebuild this
            // router per request (issue #437).
            // What the gate WOULD have refused, asked for again with no
            // waivers: the waived text is never pushed, so this is the only
            // way to name the problems the operator accepted — and #441's
            // record is only accountable if it carries them.
            let accepted = crate::route_policy::production_readiness(
                env,
                &guards,
                self.runtime.as_ref(),
                rate_limiter_ready,
                signer_ready,
                None,
                None,
            );
            self.record_acceptances_once(
                &guards,
                rate_limiter_ready,
                unprotected.as_deref(),
                unlimited.as_deref(),
                &accepted,
            );
            return problems;
        }
        // No blanket escape hatch here any more. Each waiver is passed
        // into `production_readiness` above and applied to the leg it
        // names, so what comes back is already only the UNWAIVED problems
        // — clearing them all on `unprotected_writes_override` would let a
        // waiver for one control excuse another, which is exactly what
        // `a_refusing_deployment_records_no_acceptance_at_all` forbids: a
        // captcha waiver must not serve a venture with no rate limiter.
        for problem in &problems {
            let detail = format!(
                "refusing guarded routes: {problem} — set {} to a reason to accept this \
                 explicitly while the port is wired",
                crate::route_policy::ALLOW_UNPROTECTED_WRITES
            );
            error!("{detail}");
            crate::logging::forward_control_event(crate::logging::ControlLevel::Error, &detail);
        }
        problems.extend(hmac_problems);
        problems
    }

    /// Records an operator's escape-hatch acceptance exactly once, next to
    /// the boot decision that served on it (issue #143, #437). Each guard
    /// below is the readiness leg it mirrors minus the waiver clause, so a
    /// waiver is recorded only when it actually removed a refusal — not
    /// when the port was fine all along.
    fn record_acceptances_once(
        &self,
        guards: &crate::route_policy::WriteGuards,
        rate_limiter_ready: bool,
        unprotected: Option<&str>,
        unlimited: Option<&str>,
        accepted: &[String],
    ) {
        if guards.needs_captcha()
            && !crate::route_policy::captcha_effective(self.runtime.as_ref())
            && let Some(reason) = unprotected
            && !self
                .unprotected_acceptance_recorded
                .swap(true, Ordering::Relaxed)
        {
            let detail = format!(
                "serving guarded routes unprotected on an operator's recorded acceptance \
                 (reason: {reason}; problems: {})",
                accepted.join("; ")
            );
            tracing::warn!(
                control = "production-readiness",
                acceptance = crate::route_policy::ALLOW_UNPROTECTED_WRITES,
                reason,
                "serving captcha-guarded routes unprotected on an operator's recorded acceptance"
            );
            // Forwarded, not just traced (issue #441): on wasm the tracing
            // event goes nowhere, and an acceptance nobody can read is an
            // acceptance nobody answers for.
            crate::logging::forward_control_event(crate::logging::ControlLevel::Warn, &detail);
        }
        if guards.needs_rate_limiter()
            && !rate_limiter_ready
            && let Some(reason) = unlimited
            && !self
                .unlimited_acceptance_recorded
                .swap(true, Ordering::Relaxed)
        {
            let detail = format!(
                "serving public writes and admin routes without a rate limiter on an \
                 operator's recorded acceptance (reason: {reason}; problems: {})",
                accepted.join("; ")
            );
            tracing::warn!(
                control = "production-readiness",
                acceptance = crate::route_policy::ALLOW_UNLIMITED_PUBLIC_ROUTES,
                reason,
                "serving public writes and admin routes without a rate limiter on an \
                 operator's recorded acceptance"
            );
            // Forwarded for the same reason as the leg above (issue #441).
            crate::logging::forward_control_event(crate::logging::ControlLevel::Warn, &detail);
        }
    }

    /// Nests one forwarding router per mounted sidecar (issue #131).
    /// Split out of [`Harness::router`] so that method stays readable.
    fn nest_sidecars(
        mut api: Router,
        mounted: &[SidecarMount],
        ports: &Ports,
        gateway: Option<&Arc<HmacSigner>>,
    ) -> Router {
        for mount in mounted {
            api = api.nest(
                &format!("/v1/{}", mount.name),
                crate::sidecar::router(
                    mount.clone(),
                    ports.dispatcher.clone(),
                    Arc::clone(&ports.config),
                    ports.rate_limiter.clone(),
                    gateway.map(Arc::clone),
                ),
            );
        }
        api
    }

    fn sidecar_mounts(&self, ports: &Ports) -> Vec<SidecarMount> {
        let mounts = match crate::sidecar::SidecarMounts::from_config(ports.config.as_ref()) {
            Ok(mounts) => mounts,
            Err(errors) => {
                for error in errors {
                    let detail = format!("ignoring the sidecar mount table: {error}");
                    tracing::error!(error, "ignoring the sidecar mount table");
                    // A dropped mount quietly unmounts a service (issue
                    // #441): the operator must be able to read why.
                    crate::logging::forward_control_event(
                        crate::logging::ControlLevel::Error,
                        &detail,
                    );
                }
                crate::sidecar::SidecarMounts::default()
            }
        };
        let module_names: Vec<&str> = self.modules.iter().map(|m| m.name()).collect();
        for collision in mounts.collisions(&module_names) {
            let detail = format!("ignoring the colliding sidecar mount: {collision}");
            tracing::error!(error = collision, "ignoring the colliding sidecar mount");
            crate::logging::forward_control_event(crate::logging::ControlLevel::Error, &detail);
        }
        mounts
            .iter()
            .filter(|m| !module_names.contains(&m.name.as_str()))
            .cloned()
            .collect()
    }

    /// [`Harness::sidecar_mounts`] without the logging: `events_for` runs
    /// per module per router, and re-logging the same malformed table once
    /// per module would turn one operator error into a page of noise.
    fn resolved_mounts(&self, ports: &Ports) -> Vec<SidecarMount> {
        let mounts =
            crate::sidecar::SidecarMounts::from_config(ports.config.as_ref()).unwrap_or_default();
        let module_names: Vec<&str> = self.modules.iter().map(|m| m.name()).collect();
        mounts
            .iter()
            .filter(|m| !module_names.contains(&m.name.as_str()))
            .cloned()
            .collect()
    }

    /// The bus a module sees: the handlers collected at `build`, plus —
    /// when this deployment mounts sidecars — the forwarder that carries
    /// every emission across the boundary (issue #62, ADR 0017). Built
    /// here rather than in `build` because only `router(ports)` has the
    /// resolved `Dispatcher` and mount table; that is also the choice that
    /// keeps `Scope` and every handler signature untouched, so the
    /// contract version does not move.
    fn events_for(&self, ports: &Ports) -> EventBus {
        let mounts = self.resolved_mounts(ports);
        if mounts.is_empty() {
            return self.events.clone();
        }
        let Some(dispatcher) = ports.dispatcher.clone() else {
            return self.events.clone();
        };
        let gateway = gateway_signer(
            ports.config.as_ref(),
            ports.clock.clone().unwrap_or_else(|| Arc::new(SystemClock)),
        );
        self.events
            .clone()
            .forwarding_to(crate::sidecar::EventForwarder::new(
                mounts, dispatcher, gateway,
            ))
    }

    /// The venture's UI plane, if it declared one. Lifted out of
    /// [`Harness::router`] only because adding `/__events` to that function
    /// put it over the line limit, and a mechanical extraction is a better
    /// answer than an `allow` on the lint that noticed.
    fn ui_router(
        &self,
        api: &Router,
        ports: &Ports,
        surface: &Arc<dyn SurfaceSource>,
    ) -> Option<Router> {
        self.ui.as_ref().map(|ui| {
            ui.router(UiContext {
                surface: Arc::clone(surface),
                api: api.clone(),
                config: Arc::clone(&ports.config),
                venture: Arc::clone(&self.venture),
                captcha_configured: ports.captcha.is_some(),
                signer: ports.signer.clone(),
                rate_limiter: ports.rate_limiter.clone(),
            })
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        })
    }

    /// The root router: the probes and the surface, inbound events, then
    /// the API, `/.well-known` and the UI plane nested on top. A sibling
    /// of [`Harness::ui_router`] in the same spirit — the assembly is one
    /// concern, [`Harness::router`] another, and keeping them apart is
    /// what lets each stay readable.
    fn root_router(
        &self,
        api: Router,
        ui: Option<Router>,
        gateway: Option<Arc<HmacSigner>>,
        health_state: HealthState,
        ready_state: ReadyState,
        surface_state: SurfaceState,
    ) -> Router {
        let root = Router::new()
            .route("/__health", get(health_handler))
            .with_state(health_state)
            .route("/__ready", get(ready_handler))
            .with_state(ready_state)
            .route("/__surface", get(surface_handler))
            .with_state(surface_state)
            // Empty without a gateway secret, and merging an empty router
            // adds no route — see `inbound_events_route` for why absent.
            .merge(self.inbound_events_route(gateway).unwrap_or_default())
            .merge(api);
        let root = match &self.well_known {
            Some(well_known) => root.nest(
                "/.well-known",
                well_known
                    .clone()
                    .layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
            ),
            None => root,
        };
        match ui {
            Some(ui) => root.nest("/ui", ui),
            None => root,
        }
    }

    /// The sidecar half of event forwarding (issue #62, ADR 0017):
    /// `POST /__events`, delivering into this deployment's **own** bus.
    ///
    /// Deliberately not the forwarding bus from [`Harness::events_for`]. A
    /// deployment can be both a host and, to someone above it, a sidecar;
    /// delivering an inbound event through a bus that forwards would re-post
    /// it to this deployment's own mounts, and two deployments that mount
    /// each other would loop with nothing able to detect it.
    ///
    /// `None` without a gateway secret: absent is safer than open. Without
    /// the shared secret there is no way to tell the host's forward from
    /// anyone else's `POST`, and an unauthenticated event trigger would let
    /// a stranger forge the payloads in-process handlers act on.
    fn inbound_events_route(&self, gateway: Option<Arc<HmacSigner>>) -> Option<Router> {
        gateway.as_ref()?;
        Some(
            Router::new()
                .route(
                    "/__events",
                    post(crate::sidecar::events_inbound)
                        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES)),
                )
                .with_state(Arc::new(crate::sidecar::InboundEvents {
                    bus: self.events.clone(),
                    gateway,
                })),
        )
    }

    /// The runtime this harness was validated against, if one was supplied.
    pub fn runtime(&self) -> Option<&Arc<dyn Runtime>> {
        self.runtime.as_ref()
    }

    /// The composed UI surface, admin actions included, for tooling
    /// (`fz`, the control plane). `GET /__surface` serves the same
    /// document, public subset unless the admin bearer is presented.
    #[must_use]
    pub fn surface(&self) -> &SurfaceDocument {
        &self.surface.document
    }

    /// Assembles the full router: each module nested under `/v1/<name>`,
    /// the one `/.well-known` router (if any) nested at the root,
    /// `GET /__health`, `GET /__ready`, `GET /__surface`, the UI renderer
    /// at `/ui` when one is mounted, and the shared middleware
    /// (request-id/Scope, CORS allowlist, 64 KiB body limit, `/v1/*`
    /// security headers, no-store headers for any request carrying a
    /// `token` query parameter — issue #135). Nothing but `/.well-known`,
    /// `/ui` and the `/__*` probes is ever mounted at the root.
    /// What `/__health` answers from.
    ///
    /// Extracted from [`Harness::router`] only because that function is
    /// at the line limit; it is one expression and it belongs to the
    /// router's assembly.
    fn health_state(&self, ports: &Ports, sidecars: Vec<SidecarMount>) -> HealthState {
        HealthState {
            // The deployment's environment, not the compiled default:
            // `cratefield-waitlist` answered `"env":"development"` while
            // serving production, which is the same lie #143 removed from
            // the gates and left here.
            venture: self.venture_as_deployed(ports.config.as_ref()),
            modules: self.modules.clone(),
            harness_build: ports.config.get("HARNESS_BUILD").filter(|b| !b.is_empty()),
            mailer_configured: ports.mailer.is_some(),
            captcha_configured: ports.captcha.is_some(),
            sidecars,
            dispatcher: ports.dispatcher.clone(),
            clock: ports.clock.clone().unwrap_or_else(|| Arc::new(SystemClock)),
            probe_cache: new_probe_cache(),
        }
    }

    pub fn router(&self, ports: Ports) -> Router {
        // The environment the *deployment* declares, not only the one
        // compiled in (issue #143). The limiter and signer legs read the
        // resolved ports, not the runtime's advertisement (issues #437,
        // #478) — captured before `ports` is destructured below.
        let env = deployed_env(self.venture.env, ports.config.as_ref());
        let (limiter, signer) = (ports.rate_limiter.is_some(), ports.signer.is_some());
        let readiness = self.production_readiness_now(env, ports.config.as_ref(), limiter, signer);
        // The problem `type` base of *this* venture, resolved once per
        // router (issue #557): the venture's override, else
        // `<public_url>/problems/`, else `about:blank`.
        let problem_type_base: Arc<str> = self.venture.problem_type_base().into();
        let mut api = self.nest_modules(&ports);
        // The gateway signer is this deployment's half of the sidecar
        // trust boundary (issue #131): absent secret, absent capability.
        let gateway = gateway_signer(
            ports.config.as_ref(),
            ports.clock.clone().unwrap_or_else(|| Arc::new(SystemClock)),
        );
        let mounted = self.sidecar_mounts(&ports);
        api = Self::nest_sidecars(api, &mounted, &ports, gateway.as_ref());
        let gateway_state = Self::gateway_guard_state(&ports, gateway.as_ref());
        let mounts_for_health = mounted.clone();
        // Captured before `ports` is destructured below.
        let tenant_layer = Arc::new(TenantLayer {
            routing: ports.tenants.clone(),
            fallback: ports.db.clone(),
        });
        // The harness is the floor of the admin plane's abuse control
        // (issue #437): a module that forgets to limit its own `/admin`
        // routes still gets the budget, namespaced under `admin:` so a
        // guess at the admin bearer cannot share — or exhaust — a public
        // route's. Modules that limit as well are double-limited, which
        // is the floor's cost and not a bug. Applied here — after the
        // module *and* sidecar nests — because a layer only wraps the
        // routes present when it is applied: applied inside either nest,
        // the other's `/admin/*` paths would sit outside the floor.
        // Innermost of the four, so it spends budget only on requests
        // that survived tenant resolution.
        // Resolution last before the module routes, and on them only
        // (TENANT-ROUTING.md §3): `/__health`, `/__ready`, `/.well-known`
        // and `/ui` have no tenant, and resolving there would 404 every
        // liveness probe in production.
        //
        // The streaming request layer (issue #585) is applied first, so it
        // is the innermost of all: the `413` a declared over-ceiling body
        // earns still passes back out through security headers, tenant
        // resolution and the request-id/CORS layers, and a streaming route
        // gets the same abuse-floor budget every other route does.
        let streaming = StreamingState::build(&self.modules);
        let api = api.layer(from_fn_with_state(streaming, streaming_request_layer));
        let api = with_abuse_floor(api, ports.rate_limiter.clone(), tenant_layer);

        let surface_source = self.merged_surface(mounted, &ports, gateway.clone(), env);

        let ui = self.ui_router(&api, &ports, &surface_source);

        let health_state = self.health_state(&ports, mounts_for_health);
        // Readiness must know what the composition asked for but this
        // bundle cannot answer, and it asks before `ports` is destructured
        // below.
        let missing_ports = missing_module_ports(&self.modules, &ports);
        let Ports {
            config,
            db,
            auth: _,
            mailer: _,
            captcha: _,
            rate_limiter: _,
            signer: _,
            kv: _,
            blob: _,
            push: _,
            payments: _,
            tracker: _,
            realtime: _,
            text_model: _,
            classifier: _,
            vector_index: _,
            embedder: _,
            custom_hostnames: _,
            http: _,
            clock,
            id_gen,
            defer,
            dispatcher: _,
            tenants: _,
        } = ports;

        let scope_state = ScopeState {
            defer: defer.unwrap_or_else(|| Arc::new(crate::ports::NoopDefer)),
            id_gen: id_gen.unwrap_or_else(|| Arc::new(crate::ports::UlidIdGen)),
            // The identity stamp names a module only where there is exactly
            // one to name: the sidecar role (issue #61).
            module: (self.modules.len() == 1).then(|| self.modules[0].name()),
        };
        let ready_state = ReadyState {
            db,
            clock: clock.unwrap_or_else(|| Arc::new(SystemClock)),
            missing_ports,
        };

        let surface_state = SurfaceState {
            config,
            source: surface_source,
        };

        let root = self.root_router(api, ui, gateway, health_state, ready_state, surface_state);

        // Innermost layer: the gate runs after `Scope`, so refusals carry
        // the request id, and it wraps every route — nested `/v1/*`, `/ui`
        // and `/__surface` alike (issue #131). Tower order: the layer
        // applied first is the innermost, so this line must come before
        // `scope_layer` in the chain.
        // Innermost of all: a deployment that declares production and
        // cannot satisfy its own declared abuse controls refuses the
        // guarded routes rather than serving them unprotected (#143).
        root.layer(from_fn_with_state(
            Arc::new(readiness),
            production_readiness_guard,
        ))
        .layer(from_fn_with_state(gateway_state, gateway_guard))
        .layer(from_fn_with_state(scope_state, scope_layer))
        .layer(axum::middleware::from_fn(token_response_layer))
        .layer(cors_layer(&self.venture.cors_origins))
        // Outermost of all (issue #557): every problem body is named under
        // *this* venture's base, whichever layer produced it — a module
        // handler, the tenant or readiness gates, a 429, a rejection from
        // an extractor with no state at all. `Problem::into_response`
        // renders context-free (`about:blank`) and stores itself in the
        // response extensions; this layer re-renders the body and nothing
        // else. Applied last, so it wraps the module nests, the sidecars,
        // `/.well-known`, `/ui` and the fallback alike.
        .layer(from_fn_with_state(problem_type_base, problem_type_layer))
    }
}

/// The `/v1/<name>` module a path addresses, plus its remaining segments.
/// `None` when the path is not under a module mount. A query or fragment is
/// cut at the first `?`/`#` (a caller passing a whole URL must not have the
/// module misidentified from its tail) and empty segments from a leading,
/// trailing or doubled slash are collapsed — [`Harness::max_body_bytes`]'
/// lenient normalisation, which tolerates a path a caller typed by hand.
/// Streaming classification uses the stricter [`exact_module_and_segments`].
fn module_and_segments(path: &str) -> Option<(&str, Vec<&str>)> {
    let path = match path.split_once(['?', '#']) {
        Some((path, _)) => path,
        None => path,
    };
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    if segments.next() != Some("v1") {
        return None;
    }
    let name = segments.next()?;
    Some((name, segments.collect()))
}

/// The exact-segment counterpart of [`module_and_segments`], for classifying
/// **streaming** routes. It collapses nothing: a trailing or doubled slash
/// is a segment of its own, so `/upload/` and `//upload` match no route and
/// are left to axum's own routing (a 404) — streaming must never claim a
/// request axum would not serve. `path` must be a root-relative URL path (a
/// leading `/`), which is what every request's `uri().path()` is.
fn exact_module_and_segments(path: &str) -> Option<(&str, Vec<&str>)> {
    let path = match path.split_once(['?', '#']) {
        Some((path, _)) => path,
        None => path,
    };
    let mut segments = path.split('/');
    // The split before the leading slash is an empty segment.
    if segments.next() != Some("") || segments.next() != Some("v1") {
        return None;
    }
    let name = segments.next()?;
    if name.is_empty() {
        return None;
    }
    Some((name, segments.collect()))
}

/// Whether `method` + `segments` matches one of `routes`, returning the
/// route's ceiling.
fn match_streaming(routes: &[StreamRoute], method: &Method, segments: &[&str]) -> Option<usize> {
    routes.iter().find_map(|route| {
        (route.method == *method && pattern_matches(route.path, segments))
            .then_some(route.max_bytes)
    })
}

/// Matches one route pattern's segments against a request path's: a literal
/// segment compares equal, `{param}` matches exactly one segment, and
/// `{*rest}` matches the remaining one-or-more and must be last.
fn pattern_matches(pattern: &str, segments: &[&str]) -> bool {
    let mut pattern_segments = pattern.split('/').filter(|segment| !segment.is_empty());
    let mut rest = segments.iter();
    loop {
        match pattern_segments.next() {
            Some("{*rest}") => {
                return pattern_segments.next().is_none() && rest.next().is_some();
            }
            Some(param) if param.starts_with('{') && param.ends_with('}') => {
                if rest.next().is_none() {
                    return false;
                }
            }
            Some(literal) => {
                if rest.next() != Some(&literal) {
                    return false;
                }
            }
            None => return rest.next().is_none(),
        }
    }
}

/// Every module's streaming routes, snapshotted once per router so the
/// request layer can match without touching the module list.
#[derive(Clone)]
struct StreamingState {
    modules: Arc<Vec<(&'static str, &'static [StreamRoute])>>,
}

impl StreamingState {
    fn build(modules: &[Arc<dyn Module>]) -> Self {
        // Only modules that declared a route are kept, so a deployment with
        // no streaming routes short-circuits with an empty vec.
        let routes = modules
            .iter()
            .filter(|module| !module.streaming_routes().is_empty())
            .map(|module| (module.name(), module.streaming_routes()))
            .collect();
        Self {
            modules: Arc::new(routes),
        }
    }

    fn max_bytes(&self, path: &str, method: &Method) -> Option<usize> {
        let (name, segments) = exact_module_and_segments(path)?;
        let (_, routes) = self.modules.iter().find(|(module, _)| *module == name)?;
        match_streaming(routes, method, &segments)
    }
}

/// Turns the body of a declared streaming route into a [`RequestStream`]
/// (issue #585): the innermost layer of the API stack, so request id, CORS,
/// security headers, the abuse floor and the tenant gate all still apply,
/// and the `413` a declared over-ceiling `content-length` earns is decorated
/// by request id and CORS like any other problem.
///
/// A runtime that already broke the body into a stream — `runtime-cloudflare`
/// — pre-inserts its own [`RequestStream`] and hands an empty body; this sees
/// the extension and leaves the request untouched. Every route whose
/// `(method, path)` names no declared route passes straight through with its
/// buffered body and `DefaultBodyLimit` intact.
async fn streaming_request_layer(
    State(state): State<StreamingState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    if state.modules.is_empty() {
        return next.run(request).await;
    }
    let Some(max_bytes) = state.max_bytes(request.uri().path(), request.method()) else {
        return next.run(request).await;
    };
    if request.extensions().get::<RequestStream>().is_some() {
        return next.run(request).await;
    }
    // Refused before any byte is read: a declared length over the route's
    // ceiling is the same `413 request-too-large` a buffered route answers.
    if let Some(declared) = crate::ports::declared_content_length(request.headers())
        && declared > max_bytes
    {
        let problem = Problem::request_too_large();
        let problem = match request.extensions().get::<Scope>() {
            Some(scope) => problem.instance(&scope.request_id),
            None => problem,
        };
        return problem.into_response();
    }
    let body = std::mem::replace(request.body_mut(), axum::body::Body::empty());
    request
        .extensions_mut()
        .insert(RequestStream::new(body.into_data_stream(), max_bytes));
    next.run(request).await
}

/// The outer four layers every request passes, innermost last in source
/// order: the abuse floor (issue #437), tenant resolution, security
/// headers, body limit. Extracted so `Harness::router` stays under
/// clippy's line cap.
fn with_abuse_floor(
    api: Router,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    tenant_layer: Arc<TenantLayer>,
) -> Router {
    api.layer(from_fn_with_state(rate_limiter, admin_rate_limit_layer))
        .layer(axum::middleware::from_fn_with_state(
            tenant_layer,
            resolve_tenant_layer,
        ))
        .layer(axum::middleware::from_fn(security_headers_layer))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// The outermost response layer (issue #557): re-renders a problem body
/// under the serving venture's base. Status, headers and everything a
/// module added ride through untouched — only the body is replaced, and
/// the now-stale `content-length` with it.
async fn problem_type_layer(
    State(base): State<Arc<str>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let Some(problem) = response.extensions().get::<Problem>().cloned() else {
        return response;
    };
    let body = problem.body(&base).to_string();
    *response.body_mut() = axum::body::Body::from(body);
    response.headers_mut().remove(header::CONTENT_LENGTH);
    // Idempotence: drop the carriage once named. A harness router nested
    // in a larger service — whose own outermost layer may carry a *different*
    // venture's base — must not be re-rendered a second time.
    response.extensions_mut().remove::<Problem>();
    response
}

/// What one `/__health` sidecar fan-out produced: when it ran (epoch ms)
/// and one entry per mount.
type ProbeCache = Option<(i64, Vec<serde_json::Value>)>;

/// The fresh cache every router starts with. The shared mutex lives in one
/// place so the scoped allow for it has one justification to point at.
#[allow(clippy::disallowed_types)]
fn new_probe_cache() -> Arc<std::sync::Mutex<ProbeCache>> {
    Arc::new(std::sync::Mutex::new(None))
}

#[derive(Clone)]
struct HealthState {
    venture: Arc<Venture>,
    modules: Vec<Arc<dyn Module>>,
    /// Git sha injected as a var by the deploy workflow (issue #14).
    harness_build: Option<String>,
    mailer_configured: bool,
    captcha_configured: bool,
    sidecars: Vec<SidecarMount>,
    dispatcher: Option<Arc<dyn Dispatcher>>,
    clock: Arc<dyn Clock>,
    /// The last sidecar probe, kept for one [`SIDECAR_PROBE_TTL_SECS`]
    /// window. The stamp on each forwarded response is the real contract
    /// check (issue #61); this probe exists only so `/__health` can show
    /// each sidecar's state, and caching it keeps a polling dashboard from
    /// turning every health check into a fan-out of subrequests.
    /// Deployment-scoped, not request state: it outlives no request, so
    /// ADR 0007's ban on ambient request state does not apply.
    #[allow(clippy::disallowed_types)]
    probe_cache: Arc<std::sync::Mutex<ProbeCache>>,
}

/// How long a `/__health` sidecar listing stays fresh (issue #61). Short on
/// purpose: the point of the listing is to notice a redeploy.
const SIDECAR_PROBE_TTL_SECS: i64 = 30;

/// Per-sidecar probe budget, same generosity the readiness probe grants
/// the database.
const SIDECAR_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

async fn health_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let modules: Vec<serde_json::Value> = state
        .modules
        .iter()
        .map(|module| {
            json!({
                "name": module.name(),
                "version": module.version(),
                "requires": module.requires().iter().map(Port::name).collect::<Vec<_>>(),
                "optional": module.optional().iter().map(Port::name).collect::<Vec<_>>(),
                "tables": module.tables(),
                "emits": module.emits(),
            })
        })
        .collect();
    let sidecars = probe_sidecars(&state).await;
    Json(json!({
        "venture": state.venture.name,
        "env": state.venture.env.as_str(),
        "harness_api": HARNESS_API,
        "harness_build": state.harness_build,
        // Port presence: the Mailer/Captcha traits carry no probe, so a
        // NotConfigured adapter still reports its port as configured.
        "mailer": if state.mailer_configured { "configured" } else { "not_configured" },
        "captcha": if state.captcha_configured { "configured" } else { "absent" },
        "modules": modules,
        "sidecars": sidecars,
    }))
}

/// One mount, probed. `probe` is the verdict (`ok`, `mismatch`,
/// `unreachable`); `contract`, `module` and `version` are what the sidecar
/// said about itself, `null` when it said nothing. A sidecar that answers
/// a wrong contract still reports here — the operator reading `/__health`
/// needs both numbers, and the per-request refusal is a separate story.
async fn probe_sidecars(state: &HealthState) -> Vec<serde_json::Value> {
    if state.sidecars.is_empty() {
        return Vec::new();
    }
    let now_ms =
        i64::try_from(state.clock.now().unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
    if let Some((at_ms, entries)) = state.probe_cache.lock().unwrap().as_ref()
        && now_ms - at_ms < SIDECAR_PROBE_TTL_SECS * 1000
    {
        return entries.clone();
    }

    let mut entries = Vec::new();
    for mount in &state.sidecars {
        entries.push(probe_one_sidecar(state, mount).await);
    }
    *state.probe_cache.lock().unwrap() = Some((now_ms, entries.clone()));
    entries
}

async fn probe_one_sidecar(state: &HealthState, mount: &SidecarMount) -> serde_json::Value {
    let mut missing = json!({
        "name": mount.name,
        "binding": mount.binding,
        "probe": "unreachable",
        "contract": serde_json::Value::Null,
        "module": serde_json::Value::Null,
        "version": serde_json::Value::Null,
    });
    let Some(dispatcher) = state.dispatcher.as_ref() else {
        return missing;
    };
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/__health")
        .body(Bytes::new());
    let Ok(request) = request else {
        return missing;
    };
    // `/__health` stays open on the sidecar side of the gateway (probes
    // must probe), so no stamp is needed to reach it. The future is owned
    // because the clock's timeout demands `'static`; the binding outlives
    // the call only as a clone.
    let dispatcher = Arc::clone(dispatcher);
    let binding = mount.binding.clone();
    let probe = async move { dispatcher.dispatch(&binding, request).await };
    let Some(Ok(response)) =
        crate::ports::timeout(&*state.clock, probe, SIDECAR_PROBE_TIMEOUT).await
    else {
        return missing;
    };
    let contract = response
        .headers()
        .get(crate::sidecar::X_HARNESS_API)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok());
    let body = serde_json::from_slice::<serde_json::Value>(response.body()).ok();
    let module = response
        .headers()
        .get(crate::sidecar::X_HARNESS_MODULE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| first_module_string(body.as_ref(), "name"));
    let version = first_module_string(body.as_ref(), "version");
    let tables = declared_tables(body.as_ref());
    let contract = contract.or_else(|| {
        body.as_ref()
            .and_then(|b| b.get("harness_api"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|api| u32::try_from(api).ok())
    });
    missing["contract"] = contract.map_or(serde_json::Value::Null, |api| json!(api));
    missing["module"] = module.map_or(serde_json::Value::Null, |name| json!(name));
    missing["version"] = version.map_or(serde_json::Value::Null, |version| json!(version));
    missing["tables"] = json!(tables);
    match contract {
        Some(api) if api != HARNESS_API => missing["probe"] = json!("mismatch"),
        Some(_) => missing["probe"] = json!("ok"),
        None => missing["probe"] = json!("unreachable"),
    }
    // A sidecar owns tables in the *same* database as its host, and the
    // build-time duplicate check (`check_tables`) cannot see it: it walks
    // `harness.modules()`, which a mount is not in. So the clash is caught
    // here, the first time the host hears what the sidecar claims, and it
    // is reported rather than inferred - `CREATE TABLE IF NOT EXISTS`
    // would otherwise have the two modules quietly sharing one table
    // (issue #66).
    //
    // Only a *positive* observation sets this. An unreachable sidecar
    // declares nothing, and "declared nothing" must never read as "clean":
    // that is the difference between a check and a coin flip.
    let clashes = collisions_with(&tables, state, &mount.name);
    if !clashes.is_empty() {
        let detail = format!(
            "sidecar `{}` claims table(s) {} already claimed in this deployment",
            mount.name,
            clashes.join(", ")
        );
        tracing::error!(sidecar = %mount.name, tables = %clashes.join(","), "{detail}");
        crate::logging::forward_internal_error(&detail);
        missing["probe"] = json!("table-collision");
        missing["table_collisions"] = json!(clashes);
    }
    missing
}

/// Every table named by `modules[*].tables` in a sidecar's `/__health`
/// body. Absent or malformed reads as an empty set, never as "no clash" -
/// see the caller.
fn declared_tables(body: Option<&serde_json::Value>) -> Vec<String> {
    let Some(modules) = body
        .and_then(|b| b.get("modules"))
        .and_then(|m| m.as_array())
    else {
        return Vec::new();
    };
    let mut tables: Vec<String> = modules
        .iter()
        .filter_map(|module| module.get("tables")?.as_array())
        .flatten()
        .filter_map(|table| table.as_str().map(str::to_owned))
        .collect();
    tables.sort_unstable();
    tables.dedup();
    tables
}

/// The tables `claimed` shares with a compiled-in module, reported with the
/// owner so the operator knows which side to rename.
fn collisions_with(claimed: &[String], state: &HealthState, mount: &str) -> Vec<String> {
    let mut clashes: Vec<String> = Vec::new();
    for module in &state.modules {
        if module.name() == mount {
            continue;
        }
        for table in module.tables() {
            if claimed.iter().any(|claimed| claimed == table)
                && !clashes.iter().any(|seen| seen == table)
            {
                clashes.push(format!("`{table}` (also module `{}`)", module.name()));
            }
        }
    }
    clashes
}

/// A sidecar's `/__health` body names its module and version at
/// `modules[0]`; a stamp header takes precedence, so this is the fallback.
fn first_module_string(body: Option<&serde_json::Value>, key: &str) -> Option<String> {
    body?
        .get("modules")?
        .get(0)?
        .get(key)?
        .as_str()
        .map(str::to_owned)
}

/// What the resolution layer needs: the deployment's tenant plane, and
/// the handle to fall back to when it has none.
struct TenantLayer {
    routing: Option<Arc<dyn crate::tenant::TenantRouting>>,
    /// The single database of a deployment without a registry. `None`
    /// when no database port is configured at all, which is a legitimate
    /// harness (a venture of pure-HTTP modules) — the tenant still
    /// resolves, and a handler that asks for a `TenantConn` is the thing
    /// that fails.
    fallback: Option<Arc<dyn Database>>,
}

/// Resolves the request's tenant and puts it, with its database handle,
/// into the extensions for the `TenantConn` extractor (issue #32).
///
/// Refusals carry the request id because this runs inside `scope_layer` —
/// a refusal from outside the harness carries no `instance`, which is why
/// #143's readiness guard was pushed inside rather than left at the edge.
async fn resolve_tenant_layer(
    State(layer): State<Arc<TenantLayer>>,
    scope: Scope,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    // No tenant plane: the *no registry* deployment. Every host is the one
    // venture (TENANT-ROUTING.md §6), so a module is written once against
    // the stricter shape and the path most ventures run in production is
    // not the one without the isolation.
    let resolution = match layer.routing.as_ref() {
        Some(routing) => routing.resolve(&host),
        None => <crate::tenant::ImplicitTenant as crate::tenant::ResolveTenant>::resolve(
            &crate::tenant::ImplicitTenant,
            &host,
        ),
    };

    let tenant = match resolution.admit() {
        Ok(tenant) => tenant,
        Err(problem) => {
            return Problem::new(problem)
                .instance(&scope.request_id)
                .into_response();
        }
    };

    let db = match layer.routing.as_ref() {
        Some(routing) => match routing.database(&tenant).await {
            Ok(db) => Some(db),
            Err(err) => {
                // The registry is the only thing that knows a DSN, and
                // this error carries the tenant id and nothing else.
                tracing::error!(tenant = %tenant.id(), "{err}");
                crate::logging::forward_internal_error(&err.to_string());
                return Problem::new(&SLUGS.tenant_degraded)
                    .instance(&scope.request_id)
                    .into_response();
            }
        },
        None => layer.fallback.clone(),
    };

    if let Some(db) = db {
        // Which shape resolved this tenant, carried through to the
        // handler: a membership rule must be able to tell a registry
        // deployment from a no-registry one, because the two disagree
        // about who a verified caller is (#385).
        let tenancy = if layer.routing.is_some() {
            crate::tenant::Tenancy::FromRegistry
        } else {
            crate::tenant::Tenancy::Sole
        };
        request
            .extensions_mut()
            .insert(crate::tenant_conn::ResolvedTenant {
                tenant,
                tenancy,
                db,
            });
    }
    next.run(request).await
}

#[derive(Clone)]
struct ReadyState {
    db: Option<Arc<dyn Database>>,
    clock: Arc<dyn Clock>,
    /// Ports some composed module requires but this bundle did not resolve
    /// — see [`missing_module_ports`]. A deployment whose module cannot
    /// run is not ready, whatever the database says.
    missing_ports: Vec<Port>,
}

/// The probed ports ([`Port::VectorIndex`], [`Port::Embedder`]) some
/// composed module requires but this bundle does not provide (issue #561):
/// the DB has its own leg of the probe, and an unwired port here means a
/// module that would answer every request with `NotConfigured`.
fn missing_module_ports(modules: &[Arc<dyn Module>], ports: &Ports) -> Vec<Port> {
    const PROBED: &[Port] = &[Port::VectorIndex, Port::Embedder];
    PROBED
        .iter()
        .copied()
        .filter(|port| {
            modules
                .iter()
                .any(|module| module.requires().contains(port))
                && !ports.has(*port)
        })
        .collect()
}

/// `GET /__ready`: every port a module requires must be resolved, then
/// `SELECT 1` through the `Database` port; 503 problem on failure
/// (architecture section 6).
async fn ready_handler(State(state): State<ReadyState>) -> impl IntoResponse {
    if !state.missing_ports.is_empty() {
        let detail = state
            .missing_ports
            .iter()
            .map(|port| format!("{} port is not configured", port.name()))
            .collect::<Vec<_>>()
            .join("; ");
        return Problem::not_ready(detail).into_response();
    }
    let Some(db) = state.db else {
        return Problem::not_ready("database port is not configured").into_response();
    };
    let stmt = Statement::new("SELECT 1");
    let query = async move { db.query(&stmt).await };
    match crate::ports::timeout(&*state.clock, query, Duration::from_secs(2)).await {
        Some(Ok(_rows)) => Json(json!({ "ok": true })).into_response(),
        Some(Err(err)) => {
            error!(error = %err, "readiness probe query failed");
            crate::logging::forward_internal_error(&format!("readiness probe query failed: {err}"));
            Problem::not_ready("database query failed").into_response()
        }
        None => Problem::not_ready("database did not answer within 2 s").into_response(),
    }
}

#[derive(Clone)]
struct SurfaceState {
    config: Arc<dyn Config>,
    source: Arc<dyn SurfaceSource>,
}

/// The build-time surface plus whatever the mounted sidecars answer
/// (issue #76). Sidecar surfaces are fetched on every call: a sidecar's
/// own `/__surface` is prerendered, the service binding runs on the same
/// thread (ADR 0009), and a cache here would hide a redeploy. Only the
/// public part of a sidecar merges: its admin routes take its own token,
/// which this host does not hold.
struct MergedSurface {
    base: Arc<SurfaceVariants>,
    mounts: Vec<SidecarMount>,
    dispatcher: Option<Arc<dyn Dispatcher>>,
    /// Mints the gateway stamp for `/__surface` fetches: the host is not
    /// exempt from the boundary it enforces on others (issue #131).
    gateway: Option<Arc<HmacSigner>>,
    env: VentureEnv,
    captcha_configured: bool,
}

impl MergedSurface {
    /// What each mounted sidecar contributes, in mount order.
    async fn sidecar_modules(&self) -> Vec<crate::surface::ModuleSurface> {
        let mut extra = Vec::new();
        let Some(dispatcher) = &self.dispatcher else {
            return extra;
        };
        for mount in &self.mounts {
            if !dispatcher.has(&mount.binding) {
                continue;
            }
            let mut builder = axum::http::Request::builder()
                .method(axum::http::Method::GET)
                .uri("/__surface")
                .header(header::ACCEPT, "application/json");
            if let Some(signer) = &self.gateway {
                // A surface fetch is not an admin request: the plain purpose.
                builder =
                    builder.header(X_HARNESS_GATEWAY, mint_gateway(signer, &mount.name, false));
            }
            let request = builder
                .body(bytes::Bytes::new())
                .expect("static request builds");
            let answer = match dispatcher.dispatch(&mount.binding, request).await {
                Ok(response) if response.status().is_success() => response,
                Ok(response) => {
                    tracing::warn!(module = mount.name, status = %response.status(), "sidecar surface not available");
                    continue;
                }
                Err(err) => {
                    tracing::warn!(module = mount.name, error = %err, "sidecar surface fetch failed");
                    continue;
                }
            };
            // Cap before parsing: an unbounded document turns a merge into
            // a memory attack on this Worker (issue #131).
            if answer.body().len() > MAX_SIDECAR_SURFACE_BYTES {
                tracing::warn!(
                    module = mount.name,
                    "sidecar surface exceeds {MAX_SIDECAR_SURFACE_BYTES} bytes and was not merged"
                );
                continue;
            }
            match serde_json::from_slice::<SurfaceDocument>(answer.body()) {
                Ok(document) => match sanitize_sidecar_document(&document, &mount.name) {
                    Ok(entries) => extra.extend(entries.into_iter().filter_map(|mut entry| {
                        // A production host with no Captcha port cannot
                        // render the widget a merged action demands, so the
                        // honest surface drops it (issue #131).
                        if self.env == VentureEnv::Production
                            && !self.captcha_configured
                            && strip_unguarded_captcha_actions(&mut entry.surface) > 0
                        {
                            tracing::warn!(
                                module = entry.name,
                                "merged sidecar actions requiring a captcha were dropped: no Captcha port here"
                            );
                        }
                        (!entry.surface.is_empty()).then_some(entry)
                    })),
                    Err(problems) => {
                        for problem in problems {
                            tracing::warn!(module = mount.name, error = problem, "sidecar surface rejected at merge");
                        }
                    }
                },
                Err(err) => {
                    tracing::warn!(module = mount.name, error = %err, "sidecar surface is not a surface document");
                }
            }
        }
        extra
    }
}

#[async_trait::async_trait]
impl SurfaceSource for MergedSurface {
    async fn current(&self) -> Arc<SurfaceDocument> {
        if self.mounts.is_empty() {
            return Arc::clone(&self.base.document);
        }
        let mut document = (*self.base.document).clone();
        document.modules.extend(self.sidecar_modules().await);
        Arc::new(document)
    }

    fn built(&self) -> Arc<SurfaceDocument> {
        Arc::clone(&self.base.document)
    }

    fn rendered(&self, admin: bool) -> Option<&RenderedSurface> {
        Some(if admin {
            &self.base.full
        } else {
            &self.base.public
        })
    }
}

/// `GET /__surface` (ADR 0010): the composed surface, public subset by
/// default, admin actions included when `Authorization: Bearer
/// <ADMIN_TOKEN>` is valid. A wrong or stale bearer is not an error here,
/// it just gets the public document: this route exists to be read by
/// renderers and tooling, and a `403` would leak whether admin is on.
/// Strong `ETag` per variant; `If-None-Match` answers `304`.
///
/// Both variants share this URL, so caching is split per variant (issue
/// #130): the public document stays `no-cache` (shared caches may store
/// it but must revalidate — nothing in it is a secret), while the
/// authenticated document is `private, no-store` on the `200` *and* on
/// the `304`, because a `304` refreshes what a cache already holds.
/// `Vary: Authorization` alone is not enough: an intermediary that
/// ignores `Vary` could otherwise store the admin variant and expose it
/// to an unauthenticated caller.
async fn surface_handler(
    State(state): State<SurfaceState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let admin = require_admin(&*state.config, &headers).is_ok();
    // With no sidecar the source hands back the build-time Arc, and the
    // prerendered variants are reused; with sidecars the merged document
    // is rendered per request (a hash, microseconds).
    let current = state.source.current().await;
    let built = state.source.built();
    let prerendered = Arc::ptr_eq(&current, &built).then(|| state.source.rendered(admin));
    let fresh;
    let rendered: &RenderedSurface = if let Some(rendered) = prerendered.flatten() {
        rendered
    } else {
        fresh = if admin {
            RenderedSurface::render(&current)
        } else {
            RenderedSurface::render(&current.public())
        };
        &fresh
    };
    let matches = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|tag| tag == "*" || tag == rendered.etag)
        });
    let mut response = if matches {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(header::CONTENT_TYPE, "application/json")],
            rendered.json.clone(),
        )
            .into_response()
    };
    let response_headers = response.headers_mut();
    response_headers.insert(
        header::ETAG,
        header::HeaderValue::from_str(&rendered.etag).expect("hex etag is a valid header"),
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        if admin {
            header::HeaderValue::from_static("private, no-store")
        } else {
            header::HeaderValue::from_static("no-cache")
        },
    );
    response_headers.insert(
        header::VARY,
        header::HeaderValue::from_static("Authorization"),
    );
    response
}

/// Builder: `.venture(..)`, `.module(..)`, `.runtime(..)`, `.template(..)`,
/// then `.build()`.
#[derive(Default)]
pub struct HarnessBuilder {
    venture: Option<Venture>,
    modules: Vec<Arc<dyn Module>>,
    provides: Vec<Port>,
    runtime: Option<Arc<dyn Runtime>>,
    module_templates: Vec<(String, Box<dyn Template>)>,
    overrides: Vec<(String, Box<dyn Template>)>,
    ui: Option<Arc<dyn UiMount>>,
}

impl HarnessBuilder {
    #[must_use]
    pub fn venture(mut self, venture: Venture) -> Self {
        self.venture = Some(venture);
        self
    }

    /// Adds a module. Composition is compile-time: the wasm binary contains
    /// exactly the modules listed here (ADR 0003).
    #[must_use]
    pub fn module(mut self, module: impl Module) -> Self {
        self.modules.push(Arc::new(module));
        self
    }

    /// Adds an already-shared module (`cratefield-testing` keeps handles to
    /// apply migrations and run conformance).
    #[must_use]
    pub fn module_arc(mut self, module: Arc<dyn Module>) -> Self {
        self.modules.push(module);
        self
    }

    /// Declares the runtime: its `provides()` set drives build-time
    /// checking of every module's `requires()`. The runtime is kept on the
    /// built harness for tooling (`fz doctor`, scheduled fan-out).
    #[must_use]
    pub fn runtime(mut self, runtime: impl Runtime) -> Self {
        let runtime: Arc<dyn Runtime> = Arc::new(runtime);
        self.provides = runtime.provides();
        self.runtime = Some(runtime);
        self
    }

    /// Registers module default templates (`<module>/<template>` ids).
    /// Call before overrides; see `template.rs` for the convention.
    #[must_use]
    pub fn templates(
        mut self,
        templates: impl IntoIterator<Item = (String, Box<dyn Template>)>,
    ) -> Self {
        self.module_templates.extend(templates);
        self
    }

    /// Mounts a UI renderer at `/ui` (ADR 0010): `cratefield_ui::Ui`. Off
    /// unless called, so a venture without a UI serves nothing there.
    #[must_use]
    pub fn ui(mut self, ui: impl UiMount) -> Self {
        self.ui = Some(Arc::new(ui));
        self
    }

    /// Venture template override. Wins over any module default with the
    /// same id; the id's module part must name a registered module.
    #[must_use]
    pub fn template(mut self, id: impl Into<String>, template: Box<dyn Template>) -> Self {
        self.overrides.push((id.into(), template));
        self
    }

    /// Validates everything, collecting **all** problems before failing
    /// (issue #2).
    ///
    /// # Errors
    ///
    /// `Err` whose `Display` lists every problem: invalid venture, unknown
    /// or duplicated port declarations, duplicate module names, tables or
    /// `/.well-known` routers, `harness_api` mismatches, invalid UI
    /// surfaces, unprovided required ports, and template ids naming
    /// unregistered modules.
    pub fn build(self) -> Result<Harness, ConfigError> {
        let mut errors = ConfigError::default();

        let venture = if let Some(venture) = self.venture {
            venture.validate(&mut errors);
            venture
        } else {
            errors.push("missing venture: call .venture(Venture::new(..)) before .build()");
            Venture::new("invalid", "invalid.invalid")
        };

        let mut names: HashMap<&'static str, usize> = HashMap::new();
        let mut tables: HashMap<&'static str, &'static str> = HashMap::new();

        for module in &self.modules {
            if module.harness_api() != HARNESS_API {
                errors.push(harness_api_mismatch(module.as_ref()));
            }

            let name = module.name();
            if name.is_empty() || !is_module_name(name) {
                errors.push(format!(
                    "module name `{name}` must be kebab-case ([a-z0-9]+ separated by '-')"
                ));
            }
            if names.insert(name, 1).is_some() {
                errors.push(format!("duplicate module name `{name}`"));
            }

            for port in module.requires().iter().chain(module.optional()) {
                if !Port::ALL.contains(port) {
                    errors.push(format!(
                        "module `{name}` declares unknown port {}",
                        port.name()
                    ));
                }
            }
            for port in module.requires() {
                if module.optional().contains(port) {
                    errors.push(format!(
                        "module `{name}` lists port {} in both requires() and optional()",
                        port.name()
                    ));
                }
            }

            module.surface().validate(name, &mut errors);

            check_tables(module.as_ref(), &mut tables, &mut errors);
        }

        let well_known = collect_well_known(&self.modules, &mut errors);

        for module in &self.modules {
            for port in module.requires() {
                if !self.provides.contains(port) {
                    errors.push(format!(
                        "module `{}` requires port {} which the runtime does not provide",
                        module.name(),
                        port.name()
                    ));
                }
            }
            warn_undeclared_ports(module.as_ref(), &self.provides);
        }

        let ordered = resolve_dependency_order(&self.modules, &mut errors);

        append_production_readiness(&venture, &self.modules, self.runtime.as_ref(), &mut errors);

        check_template_ids(
            self.overrides.iter().chain(self.module_templates.iter()),
            &names,
            &mut errors,
        );

        let surface = Arc::new(SurfaceVariants::compose(
            &venture,
            &self.modules,
            self.ui.as_ref(),
        ));
        if let Some(ui) = &self.ui {
            ui.validate(&surface.document, &mut errors);
        }

        errors.into_result()?;

        let mut registry = TemplateRegistry::new();
        registry.register_all(self.module_templates);
        registry.register_all(self.overrides);

        let mut events = EventBus::new();
        for module in &self.modules {
            for (name, handler) in module.events() {
                events = events.on(name, handler);
            }
        }

        Ok(Harness {
            venture: Arc::new(venture),
            unprotected_acceptance_recorded: AtomicBool::new(false),
            unlimited_acceptance_recorded: AtomicBool::new(false),
            // Dependency order, which is composition order until a module
            // declares something (RECONCILIATION.md §2).
            // Composed from the resolved order, so the catalog reads the way
            // the schema applies: a reader tracing an export down the list
            // meets a table before the tables that point at it.
            personal_data: Arc::new(crate::PersonalDataCatalog::compose(
                ordered.iter().map(|m| (m.name(), m.personal_data())),
            )),
            modules: ordered,
            templates: Arc::new(registry),
            events,
            runtime: self.runtime,
            well_known,
            surface,
            ui: self.ui,
        })
    }
}

/// A template id's module part must name a registered module.
/// Orders modules so that every module follows the ones it declares in
/// [`Module::depends_on`] (RECONCILIATION.md §2), reporting an unknown
/// dependency or a cycle as a build error rather than a boot one.
///
/// The sort is **stable**: modules with no dependency between them keep
/// composition order. With nothing declared anywhere — which is every
/// venture today — the result is the input, so adopting this changes no
/// ordering that already exists.
///
/// Returns composition order when the graph is unusable, so `build`
/// collects the rest of its errors instead of stopping at the first.
fn resolve_dependency_order(
    modules: &[Arc<dyn Module>],
    errors: &mut ConfigError,
) -> Vec<Arc<dyn Module>> {
    let names: BTreeSet<&str> = modules.iter().map(|module| module.name()).collect();
    let mut unknown = false;
    for module in modules {
        for needed in module.depends_on() {
            if !names.contains(needed) {
                unknown = true;
                errors.push(format!(
                    "module `{}` depends on `{needed}`, which this venture does not compose: \
                     add the module or drop the dependency",
                    module.name()
                ));
            }
        }
    }
    if unknown {
        return modules.to_vec();
    }

    // Kahn's algorithm over composition order, which is what makes the
    // result stable: at each step the earliest-composed ready module is
    // taken, so an undeclared pair never reorders.
    let mut remaining: Vec<Option<Arc<dyn Module>>> = modules
        .iter()
        .map(|module| Some(Arc::clone(module)))
        .collect();
    let mut placed: BTreeSet<&str> = BTreeSet::new();
    let mut ordered: Vec<Arc<dyn Module>> = Vec::with_capacity(modules.len());

    while ordered.len() < modules.len() {
        let mut progressed = false;
        for slot in &mut remaining {
            let ready = slot.as_ref().is_some_and(|module| {
                module
                    .depends_on()
                    .iter()
                    .all(|needed| placed.contains(needed))
            });
            if ready {
                let module = slot.take().expect("checked above");
                placed.insert(module.name());
                ordered.push(module);
                progressed = true;
            }
        }
        if !progressed {
            // Everything left is waiting on something else left: a cycle.
            let stuck: Vec<&str> = remaining
                .iter()
                .filter_map(|slot| slot.as_ref().map(|module| module.name()))
                .collect();
            errors.push(format!(
                "modules [{}] depend on each other in a cycle: migrations cannot be ordered so \
                 that every module follows the ones it sits on top of",
                stuck.join(", ")
            ));
            return modules.to_vec();
        }
    }
    ordered
}

fn check_template_ids<'a>(
    ids: impl Iterator<Item = &'a (String, Box<dyn Template>)>,
    names: &HashMap<&'static str, usize>,
    errors: &mut ConfigError,
) {
    for (id, _) in ids {
        let Some(module_name) = id.split('/').next() else {
            continue;
        };
        if !names.contains_key(module_name) {
            errors.push(format!(
                "template `{id}` names module `{module_name}` which is not registered"
            ));
        }
    }
}

fn is_module_name(name: &str) -> bool {
    name.split('-').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    })
}

/// Refuses every guarded route when the deployment declares production
/// and cannot satisfy the abuse controls its own routes declare
/// (issue #143).
///
/// Fail *closed*, not fatal: a panicking Worker is an outage with no
/// diagnosis, so the probes and the UI stay up to say why while `/v1/*`
/// answers `503 not-production-ready`. `Harness::build` still refuses the
/// same composition outright when the venture declares its environment
/// honestly; this catches the deployment that did not.
async fn production_readiness_guard(
    State(problems): State<Arc<Vec<String>>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if problems.is_empty() || !request.uri().path().starts_with("/v1/") {
        return next.run(request).await;
    }
    let problem = Problem::new(&SLUGS.not_production_ready).with_detail(problems.join("; "));
    match request.extensions().get::<Scope>() {
        Some(scope) => problem.instance(&scope.request_id.clone()),
        None => problem,
    }
    .into_response()
}

/// Limits every `/admin/*` route by client IP at the harness layer
/// (issue #437), whether or not the module limits its own. The keys are
/// prefixed `admin:` so a guess at the admin bearer draws from its own
/// budget, the way the auth crates namespace theirs (`auth-password:<key>`),
/// and no email key joins them — the caller is anonymous until it
/// authenticates. A limiter transport error denies: the admin token has no
/// captcha or cooldown behind it, so there is nothing to fail open into
/// (the sidecar forward reaches the same verdict for the same reason).
async fn admin_rate_limit_layer(
    State(limiter): State<Option<Arc<dyn RateLimiter>>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !crate::sidecar::is_admin_path(request.uri().path()) {
        return next.run(request).await;
    }
    let keys: Vec<String> = crate::rate_limit::rate_limit_keys(
        crate::rate_limit::client_ip(request.headers()).as_deref(),
        None,
    )
    .into_iter()
    .map(|key| format!("admin:{key}"))
    .collect();
    if let RateLimit::Denied { decision } =
        crate::rate_limit::check_rate_limit(limiter.as_ref(), &keys, RateLimitFailure::FailClosed)
            .await
    {
        return rate_limited(&decision);
    }
    next.run(request).await
}

/// Collects the modules' `/.well-known` routers (issue #46): at most one
/// module may provide one — `/.well-known` is a singleton discovery
/// namespace — and more is a build error naming every provider.
/// Production abuse controls are an initialization rule, not a doctor
/// suggestion (issue #133): a venture that boots in production cannot
/// rely on captcha or payment verification it does not actually have.
/// The overrides are deliberately `None` here — the operator's recorded
/// acceptances belong to the boot gate, which reads them from the
/// deployment config against the resolved ports. The webhook-secret leg
/// (`webhook_secret_readiness`, issue #533) is skipped for the same
/// reason: it reads the deployment config, which a build has none of.
fn append_production_readiness(
    venture: &Venture,
    modules: &[Arc<dyn Module>],
    runtime: Option<&Arc<dyn Runtime>>,
    errors: &mut ConfigError,
) {
    for error in crate::route_policy::production_readiness(
        venture.env,
        &crate::route_policy::WriteGuards::collect(modules),
        runtime,
        // Build time has no resolved ports, so these are the runtime's own
        // answers — provisionally optimistic for a binding that is named
        // but fails to resolve, or a secret that fails to parse. The boot
        // gate re-checks against the ports the runtime actually handed
        // over, and refuses there.
        crate::route_policy::rate_limiter_effective(runtime),
        crate::route_policy::signer_effective(runtime),
        None,
        None,
    ) {
        errors.push(error);
    }
}

fn collect_well_known(modules: &[Arc<dyn Module>], errors: &mut ConfigError) -> Option<Router> {
    let mut providers: Vec<&'static str> = Vec::new();
    let mut well_known = None;
    for module in modules {
        if let Some(router) = module.well_known() {
            providers.push(module.name());
            well_known = Some(router);
        }
    }
    if providers.len() > 1 {
        let listed = providers
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ");
        errors.push(format!(
            "modules {listed} all provide a well-known router; at most one module may occupy /.well-known"
        ));
    }
    well_known
}

#[cfg(test)]
mod acceptance_recording {
    //! The once-per-deployment recording of an operator's escape-hatch
    //! acceptance (issue #143, #437). In-file because the guards are
    //! private `AtomicBool`s on `Harness`, and per-`Harness` rather than a
    //! process static so each test's harness carries its own record.

    use super::*;
    use crate::Migrations;
    use crate::config::MapConfig;

    /// A surface-less public writer — the conservative-fallback shape,
    /// which the captcha leg satisfies through the runtime below.
    struct PubWriter;

    impl Module for PubWriter {
        fn name(&self) -> &'static str {
            "writer"
        }
        fn version(&self) -> &'static str {
            "0.0.0-test"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn public_writes(&self) -> bool {
            true
        }
        fn migrations(&self) -> Migrations {
            Migrations::default()
        }
        fn validate_config(&self, _: &dyn Config) -> Result<(), ConfigError> {
            Ok(())
        }
        fn router(&self, _: ModuleContext) -> Router {
            Router::new()
        }
    }

    /// Advertises every port, so the captcha leg is satisfied and each
    /// test below is about the limiter leg alone.
    struct AllPorts;

    impl Runtime for AllPorts {
        fn provides(&self) -> Vec<Port> {
            Port::ALL.to_vec()
        }
    }

    fn harness() -> Harness {
        Harness::builder()
            .venture(
                Venture::new("test-venture", "test.example").cors_origins(["https://test.example"]),
            )
            .module(PubWriter)
            .runtime(AllPorts)
            .build()
            .expect("a development venture builds")
    }

    fn deployed(unlimited: Option<&str>) -> MapConfig {
        let pairs = [("ENV", "production")].into_iter().chain(
            unlimited.map(|reason| (crate::route_policy::ALLOW_UNLIMITED_PUBLIC_ROUTES, reason)),
        );
        MapConfig::from_pairs(pairs)
    }

    #[test]
    fn the_waiver_is_recorded_once_and_only_when_it_waived() {
        let harness = harness();
        let config = deployed(Some("issue #437: limiter binding pending"));
        assert!(
            harness
                .production_readiness_now(VentureEnv::Production, &config, false, true)
                .is_empty(),
            "the recorded acceptance serves"
        );
        assert!(
            harness
                .unlimited_acceptance_recorded
                .load(Ordering::Relaxed)
        );

        // A later router build — on Workers there is one per request —
        // neither refuses nor re-records.
        assert!(
            harness
                .production_readiness_now(VentureEnv::Production, &config, false, true)
                .is_empty()
        );
    }

    #[test]
    fn nothing_is_recorded_when_the_port_was_fine_all_along() {
        let harness = harness();
        let config = deployed(Some("unused: the limiter resolved"));
        assert!(
            harness
                .production_readiness_now(VentureEnv::Production, &config, true, true)
                .is_empty()
        );
        assert!(
            !harness
                .unlimited_acceptance_recorded
                .load(Ordering::Relaxed),
            "a waiver that removed no refusal is not a recorded acceptance"
        );
    }

    #[test]
    fn a_refusing_deployment_records_no_acceptance_at_all() {
        let harness = harness();
        // The captcha waiver does not reach the limiter leg, so the gate
        // refuses — and an acceptance that left the deployment refusing
        // recorded nothing, for either key.
        let config = MapConfig::from_pairs([
            ("ENV", "production"),
            (
                crate::route_policy::ALLOW_UNPROTECTED_WRITES,
                "captcha pending",
            ),
        ]);
        assert_eq!(
            harness
                .production_readiness_now(VentureEnv::Production, &config, false, true)
                .len(),
            1
        );
        assert!(
            !harness
                .unprotected_acceptance_recorded
                .load(Ordering::Relaxed)
        );
        assert!(
            !harness
                .unlimited_acceptance_recorded
                .load(Ordering::Relaxed)
        );
    }

    /// A webhook receiver that verifies its deliveries with the core HMAC
    /// scheme (issue #533): a signature writer that asks nothing of the
    /// Payments port — its secret key is the whole production gate.
    struct HmacWriter;

    impl Module for HmacWriter {
        fn name(&self) -> &'static str {
            "webhooks"
        }
        fn version(&self) -> &'static str {
            "0.0.0-test"
        }
        fn requires(&self) -> &'static [Port] {
            &[]
        }
        fn public_writes(&self) -> bool {
            true
        }
        fn public_write_policy(&self) -> crate::route_policy::RoutePolicy {
            crate::route_policy::RoutePolicy::Signature
        }
        fn signature_verification(&self) -> crate::route_policy::SignatureVerification {
            crate::route_policy::SignatureVerification::Hmac {
                secret: "WEBHOOK_SECRET",
            }
        }
        fn migrations(&self) -> Migrations {
            Migrations::default()
        }
        fn validate_config(&self, _: &dyn Config) -> Result<(), ConfigError> {
            Ok(())
        }
        fn router(&self, _: ModuleContext) -> Router {
            Router::new()
        }
    }

    #[test]
    fn a_non_payments_signature_venture_boots_on_its_webhook_secret_alone() {
        let harness = Harness::builder()
            .venture(
                Venture::new("test-venture", "test.example").cors_origins(["https://test.example"]),
            )
            .module(HmacWriter)
            .runtime(AllPorts)
            .build()
            .expect("a development venture builds");
        let deployed = MapConfig::from_pairs([("ENV", "production")]);
        let problems =
            harness.production_readiness_now(VentureEnv::Production, &deployed, true, true);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("WEBHOOKS_WEBHOOK_SECRET"),
            "{}",
            problems[0]
        );
        assert!(
            !problems[0].contains("Payments"),
            "a module verifying through the HMAC scheme is not the Payments leg's business: {}",
            problems[0]
        );

        // The secret configured: the same venture is ready to serve.
        let ready = MapConfig::from_pairs([
            ("ENV", "production"),
            ("WEBHOOKS_WEBHOOK_SECRET", "whsec-test-dummy"),
        ]);
        assert!(
            harness
                .production_readiness_now(VentureEnv::Production, &ready, true, true)
                .is_empty()
        );
    }
}
