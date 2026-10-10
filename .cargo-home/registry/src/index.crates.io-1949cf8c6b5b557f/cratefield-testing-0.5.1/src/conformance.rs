//! The shared conformance suite (issue #9): every module must pass it.

use cratefield_core::{
    AnyError, BoxFuture, Config, ConfigError, EventHandler, EventName, HmacSigner, Migrations,
    Module, ModuleContext, Port, Ports, UlidIdGen,
};
use std::sync::Arc;

use crate::{TestHarness, request};

/// Wraps a module so its `well_known` router (when present) carries a
/// probe route the kit can request, proving where `Harness::router`
/// mounted it (issue #46). Everything else delegates unchanged.
struct WellKnownProbe {
    inner: Arc<dyn Module>,
}

impl Module for WellKnownProbe {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn version(&self) -> &'static str {
        self.inner.version()
    }
    fn harness_api(&self) -> u32 {
        self.inner.harness_api()
    }
    fn requires(&self) -> &'static [Port] {
        self.inner.requires()
    }
    fn optional(&self) -> &'static [Port] {
        self.inner.optional()
    }
    fn tables(&self) -> &'static [&'static str] {
        self.inner.tables()
    }
    /// Delegated, like `tables`, and for the same reason: the kit builds a
    /// harness out of this wrapper, and `HarnessBuilder::build` validates a
    /// module's personal-data declarations against the tables it claims. A
    /// wrapper that answered core's empty default would hand every module a
    /// build that checked declarations it could not see.
    fn personal_data(&self) -> &'static [cratefield_core::PersonalDataSet] {
        self.inner.personal_data()
    }
    fn emits(&self) -> &'static [&'static str] {
        self.inner.emits()
    }
    fn public_writes(&self) -> bool {
        self.inner.public_writes()
    }
    fn migrations(&self) -> Migrations {
        self.inner.migrations()
    }
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        self.inner.validate_config(cfg)
    }
    fn self_check(&self) -> Vec<String> {
        self.inner.self_check()
    }
    fn router(&self, ctx: ModuleContext) -> axum::Router {
        self.inner.router(ctx)
    }
    fn well_known(&self) -> Option<axum::Router> {
        self.inner.well_known().map(|router| {
            router.route(
                WELL_KNOWN_PROBE_PATH,
                axum::routing::get(|| async { "well-known" }),
            )
        })
    }
    fn events(&self) -> Vec<(EventName, EventHandler)> {
        self.inner.events()
    }
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        self.inner.scheduled(ctx, cron)
    }
}

/// Route the probe wrapper registers inside the module's well-known
/// router; reachable at `/.well-known{WELL_KNOWN_PROBE_PATH}`.
const WELL_KNOWN_PROBE_PATH: &str = "/conformance-probe";

/// A [`Ports`] bundle with every [`Port`] wired to a fake, for checks that
/// need a full bundle: conformance's visibility check (declared ports must
/// survive [`Ports::view_for`], undeclared ones must be hidden), and a
/// runtime proving it carries every port through a copy of its bundle.
/// `dispatcher` and `tenants` are not ports and stay `None`.
///
/// # Panics
///
/// Only if the kit's own fixed signer secret or clock epoch is invalid.
#[must_use]
pub fn full_fake_ports() -> Ports {
    let mut ports = Ports::empty();
    ports.db = Some(Arc::new(crate::fakes::EmptyDatabase));
    ports.auth = Some(Arc::new(crate::fakes::FakeAuth::new(
        crate::fakes::AuthMode::Anonymous,
    )));
    ports.mailer = Some(Arc::new(crate::fakes::FakeMailer::new(
        crate::fakes::MailerMode::SendOk,
    )));
    ports.captcha = Some(Arc::new(crate::fakes::FakeCaptcha::allow_all()));
    ports.rate_limiter = Some(Arc::new(crate::fakes::FakeRateLimiter::always_allow()));
    ports.signer = Some(Arc::new(
        HmacSigner::new(crate::TEST_HARNESS_SECRET, None).expect("test secret is long enough"),
    ));
    ports.kv = Some(Arc::new(crate::fakes::MemoryKeyValue::new()));
    ports.blob = Some(Arc::new(crate::fakes::MemoryBlob::new()));
    ports.push = Some(Arc::new(crate::fakes::FakePush::new(
        crate::fakes::PushMode::DeliverOk,
    )));
    ports.payments = Some(Arc::new(crate::fakes::FakePayments::new(
        crate::fakes::PaymentsMode::Ok,
    )));
    ports.tracker = Some(Arc::new(crate::fakes::FakeTracker::new(
        crate::fakes::TrackerMode::FileOk,
    )));
    ports.realtime = Some(Arc::new(crate::fakes::FakeRealtime::new()));
    ports.text_model = Some(Arc::new(crate::fakes::FakeTextModel::default()));
    ports.classifier = Some(Arc::new(crate::fakes::FakeClassifier::default()));
    // The index's dimensions are the fake embedder's width: an index and
    // the embedder feeding it must agree (issue #561).
    ports.vector_index = Some(Arc::new(cratefield_core::ExactVectorIndex::new(
        crate::fakes::FAKE_EMBEDDER_DIMENSIONS,
    )));
    ports.embedder = Some(Arc::new(crate::fakes::FakeEmbedder));
    ports.custom_hostnames = Some(Arc::new(crate::fakes::FakeCustomHostnames::new(
        "cratefield.app",
    )));
    ports.http = Some(Arc::new(crate::fakes::FakeHttpClient::ok_json("{}")));
    ports.clock = Some(Arc::new(crate::fakes::FixedClock(
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed epoch"),
    )));
    ports.id_gen = Some(Arc::new(UlidIdGen));
    ports.defer = Some(Arc::new(crate::fakes::FakeDefer::new()));
    // The actor host gets its own clock: the ports' `FixedClock` is
    // immutable, while a test that fires an alarm advances this one. An
    // empty handler registry is enough — a module only ever reaches a
    // `ScopedActors` over it, and nothing here declares an actor kind.
    ports.actors = Some(Arc::new(crate::fakes::MemoryActors::new(
        cratefield_core::ActorHandlers::new(),
        crate::fakes::ManualClock::new(
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed epoch"),
        ),
    )));
    ports
}

/// Runs the shared conformance suite against one module, once per
/// dialect available in the environment (issue #20 — SQLite always,
/// Postgres when `FZ_TEST_POSTGRES_URL` names a server):
///
/// 1. mounts under `/v1/<name>` and `/__health` lists it with its version;
/// 2. a request under the module prefix is answered (no harness-level
///    crash — module-specific routes are covered by the module's own
///    tests via [`crate::request`]);
/// 3. migrations apply from scratch **twice** on fresh databases
///    (idempotence);
/// 4. no undeclared port access: `Ports::view_for` hides every port the
///    module did not declare;
/// 5. two concurrent requests keep their own request ids (ADR 0007);
/// 6. a well-known router, when provided, serves at the root under
///    `/.well-known` and never under `/v1` (issue #46);
/// 7. every table the module owns has a personal-data declaration, so a
///    table cannot be added to `tables()` and left outside export and
///    erasure (issue #244);
/// 8. every table the module's **migrations** create is in `tables()`, so a
///    table cannot come into being outside all three lists at once — and,
///    the other way round, every table `tables()` names is one the scan
///    actually found, so check 8 cannot pass by seeing nothing (issue #272).
///
/// # Panics
///
/// Panics with a message naming the failed check and the dialect.
pub fn conformance(module: Box<dyn Module>) {
    let inner: Arc<dyn Module> = Arc::from(module);
    conformance_inner(&inner, true);
}

/// [`conformance`] without the sidecar parity axis (issue #64). `reason`
/// is recorded in code and printed by the run, so a module that opts out
/// says why in the same place it opts out. Use it only for a module that
/// genuinely cannot be sidecar-mounted; "it fails" is not a reason.
///
/// # Panics
///
/// Panics when `reason` is empty, and on any conformance failure.
pub fn conformance_in_process_only(module: Box<dyn Module>, reason: &str) {
    assert!(
        !reason.trim().is_empty(),
        "conformance_in_process_only needs a reason: it is the only record of why \
         `{}` is not checked for sidecar parity",
        module.name()
    );
    eprintln!("[{}] sidecar parity axis skipped: {reason}", module.name());
    let inner: Arc<dyn Module> = Arc::from(module);
    conformance_inner(&inner, false);
}

/// The modules that own tables and have not said what is personal about
/// them, with the tables still missing.
///
/// **Empty, and that is the deliverable** (issue #265). `auth-core`, `cms`,
/// `email-signup`, `linkedin` and `waitlist` each sat here while they were
/// being worked through, and each left as it was declared. The mechanism
/// stays because the next module to grow a table before its declaration will
/// want it — but an entry is a debt with a number on it, not a place to park
/// one, and the list is checked empty by
/// `no_module_is_exempt_from_the_personal_data_rule`.
///
/// An exemption is a loud silence rather than a quiet one. `HarnessBuilder::build`
/// has always refused a declaration for a table a module does **not** own; the
/// converse — a table with no declaration at all — is what actually happens,
/// and what left `cratefield-module-notifications` holding addresses, device
/// tokens and inbox rows outside the erasure catalogue through six migrations
/// in two days (issue #244).
///
/// An entry names the tables, not just the module, so it cannot rot: a module
/// that declares one of them fails until its entry is corrected or removed,
/// and a module that grows a **new** undeclared table fails even while it is
/// listed. Every exemption prints on the run that uses it.
const UNDECLARED_TABLES: &[(&str, &[&str])] = &[];

/// What [`personal_data_verdict`] found.
enum Verdict {
    /// Every table the module owns has a declaration.
    Declared,
    /// Listed in `UNDECLARED_TABLES`, and the entry still describes the
    /// module exactly. Printed on the run rather than failing it.
    Exempt(String),
    /// The panic message.
    Failed(String),
}

/// The personal-data rule, as a value rather than a panic (issue #244).
///
/// Split out from [`check_personal_data`] so the exemption's anti-rot half
/// keeps a test after the list went empty: with nothing listed there is no
/// module left to reach that branch through `conformance` itself, and a
/// mechanism that only runs when somebody needs it is exactly the one that
/// must not be allowed to quietly stop working in between.
fn personal_data_verdict(
    name: &str,
    undeclared: &[&'static str],
    exemptions: &[(&str, &[&str])],
) -> Verdict {
    let exempt = exemptions
        .iter()
        .find(|(listed, _)| *listed == name)
        .map(|(_, tables)| *tables);

    if let Some(tables) = exempt {
        if undeclared != tables {
            return Verdict::Failed(format!(
                "[{name}] is exempt from the personal-data rule for {tables:?} (issue #265), but \
                 its undeclared tables are now {undeclared:?}. Correct the entry in \
                 UNDECLARED_TABLES in cratefield-testing, or remove it: an exemption that no \
                 longer describes the module is how the next omission hides."
            ));
        }
        return Verdict::Exempt(format!(
            "[{name}] personal-data declarations missing for {tables:?}; exempt under issue #265"
        ));
    }

    if undeclared.is_empty() {
        return Verdict::Declared;
    }
    Verdict::Failed(format!(
        "[{name}] owns {undeclared:?} and declares nothing personal about them. \
         `cratefield-module-privacy` plans an export and an erasure from \
         `Module::personal_data()`, so a table missing from it is never exported and never \
         erased. Declare each one with a `PersonalDataSet`, or with `PersonalDataSet::none(table, \
         reason)` if it holds nobody — \"no declaration\" and \"nothing here\" must not look the \
         same."
    ))
}

/// Fails a module that owns a table it declares nothing about (issue #244).
///
/// Export walks [`Module::tables`] and erasure plans from
/// [`Module::personal_data`], so a table added to the first and forgotten in
/// the second is invisible from both ends: the venture boots, the export runs,
/// the erasure reports success, and the rows are never in either. Nothing
/// catches it but this.
fn check_personal_data(module: &dyn Module) {
    match personal_data_verdict(
        module.name(),
        &cratefield_core::undeclared_tables(module),
        UNDECLARED_TABLES,
    ) {
        Verdict::Declared => {}
        Verdict::Exempt(note) => eprintln!("{note}"),
        Verdict::Failed(message) => panic!("{message}"),
    }
}

/// The migrations-versus-`tables()` rule, as a value rather than a panic
/// (issue #272). `Err` is the panic message.
///
/// **No exemption list.** The rule it completes has one, emptied in #271, and
/// an entry in it is a debt with a number on it. This one starts empty and
/// stays that way: a module that cannot pass it has a table outside export and
/// outside erasure right now, and the entry would be the record of deciding
/// not to mind. #265 is what a list that grows looks like.
///
/// `found` is every table the module's migrations leave behind and `listed` is
/// what `tables()` says, and **both directions are checked**, deliberately:
///
/// - a table in `found` and not in `listed` is the hole this exists for;
/// - a table in `listed` that the scan did not find is the failure mode that
///   makes the first check pass for the wrong reason. "No unlisted table" is
///   an absence assertion, and a scan that has quietly stopped matching —
///   a dialect that stops embedding its SQL, a `CREATE TABLE` written a way
///   the walk does not read — satisfies it perfectly while seeing nothing.
///   A module with migrations and a table list must be able to show the scan
///   found what it listed.
fn unlisted_verdict(
    name: &str,
    migration_count: usize,
    listed: &[&'static str],
    found: &[String],
) -> Result<(), String> {
    if migration_count > 0 {
        let missed: Vec<&str> = listed
            .iter()
            .copied()
            .filter(|table| !found.iter().any(|seen| seen.eq_ignore_ascii_case(table)))
            .collect();
        if !missed.is_empty() {
            return Err(format!(
                "[{name}] lists {missed:?} in `Module::tables()`, but the `CREATE TABLE` scan \
                 over its {migration_count} migrations did not find them — it found {found:?}. \
                 Either the module does not create those tables, or the scan has stopped \
                 matching; the second is why this is checked at all, because \"no unlisted \
                 table\" is an absence assertion and a scan that sees nothing satisfies it \
                 forever (issue #272)."
            ));
        }
    }

    let unlisted: Vec<&String> = found
        .iter()
        .filter(|table| !listed.iter().any(|name| name.eq_ignore_ascii_case(table)))
        .collect();
    if unlisted.is_empty() {
        return Ok(());
    }
    Err(format!(
        "[{name}] creates {unlisted:?} in its migrations and does not list them in \
         `Module::tables()`. A table in neither list is outside three things at once: \
         `fz data export` walks `tables()`, subject access and erasure walk \
         `personal_data()`, and the rule that compares them can only read the two lists it \
         is handed. `auth-core` held `deletion_jobs` — and a person's identifier at their \
         identity provider with it — in exactly that position (issue #272). Add each table \
         to `tables()` and give it a `PersonalDataSet`; note that `tables()` is also what a \
         whole-database `fz data export`/`import` carries, so adding one changes what a \
         move of this venture takes with it."
    ))
}

/// Fails a module that creates a table its `tables()` never mentions
/// (issue #272).
///
/// The converse of [`check_personal_data`], one step further back: that rule
/// reads `tables()`, so it cannot see a table that never reached the list.
/// The migrations can, because a `CREATE TABLE` is where a table comes into
/// being and is the one statement its author cannot forget to write.
///
/// It reaches a module through the module's own `tests/conformance.rs`, which
/// is the cost of being a kit check rather than a build error: a module
/// without that file is not checked by anything. The control plane's two
/// modules are in exactly that position and own six unlisted tables between
/// them (issue #280).
fn check_module_tables(module: &dyn Module) {
    if let Err(message) = unlisted_verdict(
        module.name(),
        module.migrations().sqlite.len() + module.migrations().postgres.len(),
        module.tables(),
        &cratefield_core::migration_tables(module),
    ) {
        panic!("{message}");
    }
}

fn conformance_inner(inner: &Arc<dyn Module>, parity: bool) {
    check_module_tables(inner.as_ref());
    check_personal_data(inner.as_ref());
    let name = inner.name().to_owned();
    let version = inner.version().to_owned();
    let has_well_known = inner.well_known().is_some();
    let module: Arc<dyn Module> = Arc::new(WellKnownProbe {
        inner: inner.clone(),
    });

    for dialect in crate::dialect::Dialect::available() {
        conformance_on_dialect(&dialect, module.clone(), &name, &version, has_well_known);
    }

    if parity {
        // One instance across both mounts, as the dialect axis above
        // already does: the probes never reach a module's parked context.
        parity_on(inner, &name);
    }
}

fn conformance_on_dialect(
    dialect: &crate::dialect::Dialect,
    module: Arc<dyn Module>,
    name: &str,
    version: &str,
    has_well_known: bool,
) {
    let kit = TestHarness::from_arcs(vec![module], dialect.clone(), |_| {});
    let module = kit
        .modules
        .iter()
        .find(|m| m.name() == name)
        .unwrap_or_else(|| panic!("module {name} missing from kit"))
        .clone();

    // 1. health lists it.
    let health = pollster::block_on(request(
        &kit.router,
        axum::http::Method::GET,
        "/__health",
        None,
    ));
    let body = health.json();
    let listed = body["modules"]
        .as_array()
        .unwrap_or_else(|| panic!("health modules array missing: {body}"));
    let entry = listed
        .iter()
        .find(|entry| entry["name"] == *name)
        .unwrap_or_else(|| panic!("health does not list {name}: {body}"));
    assert_eq!(
        entry["version"],
        version,
        "[{}] health lists the module version",
        dialect.name()
    );

    // 2. a request under the prefix is answered without panicking.
    let probe = pollster::block_on(request(
        &kit.router,
        axum::http::Method::GET,
        &format!("/v1/{name}/"),
        None,
    ));
    // Any status is the module's business; the point is no crash.
    let _ = probe.status;

    // 3. migrations apply twice on fresh databases.
    #[cfg(feature = "postgres")]
    if let crate::dialect::Dialect::Postgres { .. } = &dialect {
        crate::pg::migrations_apply_twice(&kit.modules)
            .unwrap_or_else(|message| panic!("[postgres] {message}"));
        check_visibility_and_scope(&kit, module.as_ref(), name, has_well_known);
        return;
    }
    for round in 1..=2 {
        let fresh = cratefield_adapter_sqlite::SqliteDatabase::in_memory()
            .unwrap_or_else(|err| panic!("[sqlite] fresh db {round}: {err}"));
        for module in &kit.modules {
            fresh
                .apply_migrations(module.name(), module.migrations().sqlite)
                .unwrap_or_else(|err| panic!("[sqlite] round {round}, {}: {err}", module.name()));
        }
    }
    check_visibility_and_scope(&kit, module.as_ref(), name, has_well_known);
}

/// Conformance checks 4-6: undeclared ports stay hidden, concurrent
/// requests keep their request ids, and a well-known router mounts at
/// the root only.
fn check_visibility_and_scope(
    kit: &TestHarness,
    module: &dyn Module,
    name: &str,
    has_well_known: bool,
) {
    // 4. undeclared ports are hidden (declared ones stay visible).
    // Walks `Port::ALL` rather than a list of its own: a hand-written one
    // had already lost `Port::Auth` (issue #450).
    let view = full_fake_ports().view_for(module);
    for port in Port::ALL {
        let declared = module.requires().contains(port) || module.optional().contains(port);
        assert_eq!(
            view.has(*port),
            declared,
            "{name}: port {} must be visible only when declared",
            port.name()
        );
    }

    // 5. two concurrent requests keep their own request ids (ADR 0007).
    let router_a = kit.router.clone();
    let router_b = kit.router.clone();
    let id_a = "conformance-AAAAAAAA";
    let id_b = "conformance-BBBBBBBB";
    let make = |router: axum::Router, id: &'static str| {
        std::thread::spawn(move || {
            use tower::ServiceExt;
            let request = axum::http::Request::builder()
                .uri("/__health")
                .header("x-request-id", id)
                .body(axum::body::Body::empty())
                .expect("request builds");
            let response = pollster::block_on(router.oneshot(request)).expect("router answers");
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .expect("request id echoed")
                .to_string()
        })
    };
    let handle_a = make(router_a, id_a);
    let handle_b = make(router_b, id_b);
    assert_eq!(handle_a.join().expect("a completes"), id_a);
    assert_eq!(handle_b.join().expect("b completes"), id_b);

    check_well_known_mount(kit, name, has_well_known);
}

/// Conformance check 6 (issue #46): the module's well-known router, when
/// present, serves at the root under `/.well-known` and never under
/// `/v1`; when absent, nothing mounts at `/.well-known`.
fn check_well_known_mount(kit: &TestHarness, name: &str, has_well_known: bool) {
    let probe = pollster::block_on(request(
        &kit.router,
        axum::http::Method::GET,
        &format!("/.well-known{WELL_KNOWN_PROBE_PATH}"),
        None,
    ));
    if has_well_known {
        assert_eq!(
            probe.status,
            axum::http::StatusCode::OK,
            "{name}: well-known router must serve at the root"
        );
        let under_v1 = pollster::block_on(request(
            &kit.router,
            axum::http::Method::GET,
            &format!("/v1/{name}/.well-known{WELL_KNOWN_PROBE_PATH}"),
            None,
        ));
        assert_eq!(
            under_v1.status,
            axum::http::StatusCode::NOT_FOUND,
            "{name}: well-known routes must not be nested under /v1"
        );
    } else {
        assert_eq!(
            probe.status,
            axum::http::StatusCode::NOT_FOUND,
            "{name}: nothing must mount at /.well-known without a well-known router"
        );
    }
}

/// One probe of the [`sidecar_parity`] battery: a request whose answer
/// must be identical whether the module is linked in or reached over a
/// service binding.
struct Probe {
    what: &'static str,
    method: axum::http::Method,
    /// Appended to `/v1/<module>`.
    path: &'static str,
    body: Option<&'static str>,
}

/// The request id both mounts are given, so `instance` in a problem body
/// and the `x-request-id` header can be compared byte for byte. The
/// harness accepts a client-supplied id that matches its pattern.
const PARITY_REQUEST_ID: &str = "parity-0123456789abcdef";

/// Sends one probe through `router`, with the fixed request id.
async fn probe_once(router: &axum::Router, name: &str, probe: &Probe) -> crate::TestResponse {
    use axum::http::{HeaderValue, Request, header};
    use tower::ServiceExt;

    let uri = format!("/v1/{name}{}", probe.path);
    let mut builder = Request::builder()
        .method(probe.method.clone())
        .uri(uri)
        .header(
            cratefield_core::X_REQUEST_ID,
            HeaderValue::from_static(PARITY_REQUEST_ID),
        )
        .header("cf-connecting-ip", HeaderValue::from_static("203.0.113.9"));
    let body = match probe.body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(json)
        }
        None => axum::body::Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(builder.body(body).expect("probe request builds"))
        .await
        .expect("router is infallible");
    crate::TestResponse::of(response).await
}

/// Asserts that a module answers identically in-process and behind a
/// sidecar mount (issue #64, ADR 0009: a caller cannot tell which).
///
/// Both mounts are given the same client-supplied request id, so the
/// `instance` of a problem body and the `x-request-id` header are
/// comparable byte for byte. Probes are deliberately module-agnostic —
/// unknown paths, a malformed body, a wrong method — because the kit
/// does not know the module's routes and because those are exactly the
/// paths where the hop could quietly rewrite something.
///
/// Also asserted: a body over the harness's 64 KiB cap is refused by the
/// **host** and never forwarded.
///
/// # Panics
///
/// Panics naming the probe and the field that diverged.
pub fn sidecar_parity(module: Box<dyn Module>) {
    let name = module.name().to_owned();
    parity_on(&Arc::from(module), &name);
}

fn parity_on(shared: &Arc<dyn Module>, name: &str) {
    // In-process: the module is linked into the harness under test.
    let in_process = TestHarness::from_arcs(
        vec![shared.clone()],
        crate::dialect::Dialect::Sqlite,
        |_| {},
    );

    // Sidecar: a second harness holds the module, and the host holds a
    // mount table pointing at it over a fake service binding.
    let remote = TestHarness::from_arcs(
        vec![shared.clone()],
        crate::dialect::Dialect::Sqlite,
        |_| {},
    );
    let (sidecar, dispatcher) = crate::sidecar::shared(crate::sidecar::FakeSidecar::new(
        "PARITY",
        remote.router.clone(),
    ));
    let table = format!("{{\"{name}\":\"PARITY\"}}");
    let host = TestHarness::with_builder(
        Vec::new(),
        |builder| builder,
        |ports| {
            ports.config = Arc::new(cratefield_core::MapConfig::from_pairs([
                ("HARNESS_SECRET", crate::TEST_HARNESS_SECRET),
                (cratefield_core::HARNESS_SIDECARS, table.as_str()),
            ]));
            ports.dispatcher = Some(dispatcher);
        },
    );

    let probes = [
        Probe {
            what: "an unknown path under the module prefix",
            method: axum::http::Method::GET,
            path: "/__parity_no_such_route",
            body: None,
        },
        Probe {
            what: "a POST to an unknown path",
            method: axum::http::Method::POST,
            path: "/__parity_no_such_route",
            body: Some(r#"{"parity":true}"#),
        },
        Probe {
            what: "the module root",
            method: axum::http::Method::GET,
            path: "",
            body: None,
        },
        Probe {
            what: "a malformed JSON body at the module root",
            method: axum::http::Method::POST,
            path: "",
            body: Some("{not json"),
        },
    ];

    for (sent, probe) in probes.iter().enumerate() {
        let direct = pollster::block_on(probe_once(&in_process.router, name, probe));
        let hopped = pollster::block_on(probe_once(&host.router, name, probe));
        // Without this the axis could pass vacuously: if the mount stopped
        // forwarding, the host would answer its own 404 and a module that
        // also answers 404 would compare equal. Every probe must have
        // crossed the hop.
        assert_eq!(
            sidecar.calls(),
            sent + 1,
            "[{name}] {} never reached the sidecar: the mount is not forwarding, \
             so this comparison proves nothing",
            probe.what
        );
        compare(name, probe.what, &direct, &hopped);
    }

    check_oversized_body_stops_at_the_host(&host, &sidecar, name);
}

/// A body over the harness cap is refused by the **host** and never
/// forwarded: the forwarder buffers, so a body it accepted would be held
/// in the isolate twice (issue #64, amended).
fn check_oversized_body_stops_at_the_host(
    host: &TestHarness,
    sidecar: &Arc<crate::sidecar::FakeSidecar>,
    name: &str,
) {
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    let before = sidecar.calls();
    let big = "x".repeat(cratefield_core::MAX_BODY_BYTES + 1);
    let response = pollster::block_on(async {
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri(format!("/v1/{name}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(big))
            .expect("oversized request builds");
        let response = host
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router is infallible");
        crate::TestResponse::of(response).await
    });
    assert_eq!(
        response.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "[{name}] a body over {} bytes must be refused by the host",
        cratefield_core::MAX_BODY_BYTES
    );
    assert_eq!(
        sidecar.calls(),
        before,
        "[{name}] an oversized body must never be forwarded to the sidecar"
    );
}

/// Compares one probe's two answers: status, the problem body byte for
/// byte, and the request id (present exactly once, and the one the
/// caller sent).
fn compare(name: &str, what: &str, direct: &crate::TestResponse, hopped: &crate::TestResponse) {
    assert_eq!(
        direct.status, hopped.status,
        "[{name}] status differs over the sidecar hop for {what}"
    );
    assert_eq!(
        direct.body(),
        hopped.body(),
        "[{name}] body differs over the sidecar hop for {what}"
    );
    for header in [
        axum::http::header::CONTENT_TYPE.as_str(),
        axum::http::header::LOCATION.as_str(),
    ] {
        assert_eq!(
            direct.headers.get(header),
            hopped.headers.get(header),
            "[{name}] `{header}` differs over the sidecar hop for {what}"
        );
    }
    for (label, response) in [("in-process", direct), ("sidecar", hopped)] {
        let ids: Vec<_> = response
            .headers
            .get_all(cratefield_core::X_REQUEST_ID)
            .iter()
            .collect();
        assert_eq!(
            ids.len(),
            1,
            "[{name}] {label} answered {} request ids for {what}; exactly one is the contract",
            ids.len()
        );
        assert_eq!(
            ids[0], PARITY_REQUEST_ID,
            "[{name}] {label} did not echo the caller's request id for {what}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{UNDECLARED_TABLES, Verdict, personal_data_verdict, unlisted_verdict};

    /// A fixture list, so these cover the mechanism rather than whatever
    /// happens to be exempt on the day.
    const FIXTURE: &[(&str, &[&str])] = &[("ledger", &["ledger_entries", "ledger_lines"])];

    fn message(verdict: Verdict) -> String {
        match verdict {
            Verdict::Failed(message) | Verdict::Exempt(message) => message,
            Verdict::Declared => String::new(),
        }
    }

    #[test]
    fn no_module_is_exempt_from_the_personal_data_rule() {
        // Issue #265: the five modules that could not pass the rule when it
        // landed are declared, and the list they sat in is empty. The
        // mechanism stays for the next module that needs it; an entry in it
        // is a debt, and this is the test that notices one being taken on.
        assert!(
            UNDECLARED_TABLES.is_empty(),
            "a module is exempt from the personal-data rule again: {UNDECLARED_TABLES:?}. \
             An exemption means a venture composing that module answers an erasure request \
             without the rows it lists — declare them instead, and open the issue the entry \
             would have tracked."
        );
    }

    #[test]
    fn a_declared_module_passes() {
        assert!(matches!(
            personal_data_verdict("notes", &[], FIXTURE),
            Verdict::Declared
        ));
    }

    #[test]
    fn an_exempt_module_that_declared_everything_is_told_to_remove_its_entry() {
        // The other end of the anti-rot rule, and the one this change ran
        // into: a module that has done the work still fails while its
        // exemption stands, because an entry left behind is how the next
        // omission hides behind the last one.
        let message = message(personal_data_verdict("ledger", &[], FIXTURE));
        assert!(message.contains("or remove it"), "{message}");
        assert!(message.contains("#265"), "{message}");
    }

    #[test]
    fn an_undeclared_table_fails_and_says_what_to_write() {
        let message = message(personal_data_verdict("notes", &["note_tags"], FIXTURE));
        assert!(message.contains("note_tags"), "{message}");
        assert!(message.contains("PersonalDataSet::none"), "{message}");
    }

    #[test]
    fn an_exemption_that_still_describes_its_module_is_printed_not_failed() {
        let verdict = personal_data_verdict("ledger", &["ledger_entries", "ledger_lines"], FIXTURE);
        assert!(matches!(verdict, Verdict::Exempt(_)));
        assert!(message(verdict).contains("exempt under issue #265"));
    }

    #[test]
    fn an_exemption_that_no_longer_describes_its_module_fails() {
        // The anti-rot half. A module that declared one of its listed tables
        // is a different module from the one that was exempted, and letting
        // the entry keep covering it is how the next omission hides behind
        // the last one.
        let message = message(personal_data_verdict("ledger", &["ledger_lines"], FIXTURE));
        assert!(message.contains("#265"), "{message}");
        assert!(message.contains("ledger_entries"), "{message}");
    }

    #[test]
    fn an_exempt_module_that_grows_a_new_undeclared_table_fails() {
        let message = message(personal_data_verdict(
            "ledger",
            &["ledger_entries", "ledger_lines", "ledger_fx"],
            FIXTURE,
        ));
        assert!(message.contains("ledger_fx"), "{message}");
    }

    fn problem(verdict: Result<(), String>) -> String {
        verdict.err().unwrap_or_default()
    }

    #[test]
    fn a_module_that_lists_every_table_it_creates_passes() {
        assert!(
            unlisted_verdict(
                "auth-core",
                6,
                &["users", "sessions"],
                &["users".to_owned(), "sessions".to_owned()],
            )
            .is_ok()
        );
    }

    #[test]
    fn a_table_the_migrations_create_and_tables_omits_fails() {
        // The live shape: `auth-core` creates `deletion_jobs` in migration
        // 0005 and lists seven tables that do not include it (issue #272).
        let message = problem(unlisted_verdict(
            "auth-core",
            6,
            &["users"],
            &["users".to_owned(), "deletion_jobs".to_owned()],
        ));
        assert!(message.contains("deletion_jobs"), "{message}");
        assert!(message.contains("#272"), "{message}");
        // It has to say what to write, and that the list is also the export's.
        assert!(message.contains("PersonalDataSet"), "{message}");
        assert!(message.contains("fz data export"), "{message}");
    }

    #[test]
    fn a_scan_that_found_nothing_fails_rather_than_passing_vacuously() {
        // The failure this epic has hit twice: "no unlisted table" is an
        // absence assertion, and a scan that has stopped matching satisfies
        // it forever. A module with migrations and a table list must be able
        // to show the scan found what it listed.
        let message = problem(unlisted_verdict("auth-core", 6, &["users"], &[]));
        assert!(message.contains("stopped matching"), "{message}");
        assert!(message.contains("users"), "{message}");
    }

    #[test]
    fn a_scan_that_found_only_some_of_the_listed_tables_fails() {
        // Not only the all-or-nothing case: a walk that stops reading after
        // the first statement of a set would find one table and miss the rest.
        let message = problem(unlisted_verdict(
            "auth-core",
            6,
            &["users", "sessions"],
            &["users".to_owned()],
        ));
        // The one it missed is named, and what it did find is shown beside
        // it: a message that only said "something is missing" would send the
        // reader back to the scan with nothing to go on.
        assert!(message.contains(r#"lists ["sessions"]"#), "{message}");
        assert!(message.contains(r#"it found ["users"]"#), "{message}");
    }

    #[test]
    fn a_module_with_no_migrations_is_not_asked_to_have_found_anything() {
        // `auth-passkeys` and its siblings write to `auth-core`'s schema and
        // ship no migrations of their own; there is nothing for the scan to
        // read and nothing it could have missed.
        assert!(unlisted_verdict("auth-passkeys", 0, &[], &[]).is_ok());
    }
}
