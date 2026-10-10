//! [`TestHarness`]: a built harness over fakes whose database runs
//! in-memory SQLite by default, or a throwaway Postgres database for the
//! parity suite (issues #9, #20) — migrations applied per module at
//! creation.

use cratefield_adapter_sqlite::SqliteDatabase;
use cratefield_core::{
    Database, Harness, HarnessBuilder, HmacSigner, MapConfig, Module, Port, Ports, Runtime,
    UlidIdGen, Venture,
};
use std::sync::Arc;

use crate::dialect::Dialect;
use crate::fakes::{
    FakeCaptcha, FakeClassifier, FakeDefer, FakeHttpClient, FakeMailer, FakeRateLimiter,
    FakeTextModel, FakeTracker, FixedClock, MemoryKeyValue,
};

struct TestRuntime;

impl Runtime for TestRuntime {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

/// A harness with every port faked and a migrated database, migrations
/// applied per module on creation. The same database handle is wired
/// into the router and exposed for assertions — SQLite in memory by
/// default ([`TestHarness::new`]), or a throwaway Postgres 16 database
/// for the parity suite ([`TestHarness::with_database`], issue #20).
pub struct TestHarness {
    /// The assembled router: hand it to [`crate::request`].
    pub router: axum::Router,
    pub harness: Harness,
    pub mailer: FakeMailer,
    pub captcha: FakeCaptcha,
    pub rate_limiter: FakeRateLimiter,
    pub text_model: FakeTextModel,
    pub classifier: FakeClassifier,
    pub clock: FixedClock,
    pub kv: MemoryKeyValue,
    pub http: FakeHttpClient,
    pub defer: FakeDefer,
    pub tracker: FakeTracker,
    pub signer: Arc<HmacSigner>,
    /// The migrated database backing the `Database` port (shared with
    /// the router — assertions see module writes). On Postgres every
    /// call is marshalled onto the kit's own runtime, so any executor
    /// can drive it.
    pub db: Arc<dyn Database>,
    /// The modules passed in (for conformance access).
    pub modules: Vec<Arc<dyn Module>>,
    /// The engine `db` runs against: `"sqlite"` or `"postgres"`.
    pub dialect: &'static str,
    #[cfg(feature = "postgres")]
    pg: Option<crate::pg::PgFixture>,
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Postgres kits close their pool and drop their throwaway
        // database on the kit's runtime; this kit's router and port
        // handles go first so the close waits only on handles a test
        // leaked (a test's own threads are joined).
        #[cfg(feature = "postgres")]
        if let Some(pg) = self.pg.take() {
            self.router = axum::Router::new();
            self.db = Arc::new(crate::fakes::EmptyDatabase);
            pg.shutdown();
        }
    }
}

impl TestHarness {
    /// Builds the harness (venture `test-venture.test`), applies every
    /// module's sqlite migrations to a fresh in-memory database, and
    /// assembles the router.
    ///
    /// # Panics
    ///
    /// Panics when the harness cannot build (invalid module set) or a
    /// migration fails — exactly what a module test should surface.
    #[must_use]
    pub fn new(modules: Vec<Box<dyn Module>>) -> Self {
        Self::with_ports(modules, |_| {})
    }

    /// [`TestHarness::new`] with a patch over the default ports: swap in a
    /// token-checking `FakeCaptcha`, a scripted `FakeRateLimiter`, or a
    /// `MapConfig` carrying `ADMIN_TOKEN`, after the standard fakes (and
    /// the migrated database) are in place.
    ///
    /// # Panics
    ///
    /// Panics when the harness cannot build or a migration fails.
    #[must_use]
    pub fn with_ports(modules: Vec<Box<dyn Module>>, patch: impl FnOnce(&mut Ports)) -> Self {
        Self::with_database_and_ports(modules, Dialect::Sqlite, patch)
    }

    /// [`TestHarness::new`] over the chosen [`Dialect`] (issue #20):
    /// `Dialect::Sqlite` is the in-memory default; `Dialect::Postgres
    /// { url }` creates a throwaway Postgres 16 database on that server,
    /// applies every module's migrations (the `postgres` set when
    /// shipped, else the portable-linted `sqlite` set) and drops the
    /// database when the harness drops. Requires building
    /// `cratefield-testing` with the `postgres` feature.
    ///
    /// # Panics
    ///
    /// Panics when the harness cannot build, a migration fails, the
    /// Postgres server is unreachable, or the `postgres` feature is off
    /// and the Postgres dialect was requested anyway.
    #[must_use]
    pub fn with_database(modules: Vec<Box<dyn Module>>, dialect: Dialect) -> Self {
        Self::with_database_and_ports(modules, dialect, |_| {})
    }

    /// [`TestHarness::with_database`] with a patch over the default
    /// ports (the parity counterpart of [`TestHarness::with_ports`]).
    ///
    /// # Panics
    ///
    /// Panics for the same reasons as [`TestHarness::with_database`].
    #[must_use]
    pub fn with_database_and_ports(
        modules: Vec<Box<dyn Module>>,
        dialect: Dialect,
        patch: impl FnOnce(&mut Ports),
    ) -> Self {
        let shared: Vec<Arc<dyn Module>> = modules.into_iter().map(Arc::from).collect();
        Self::from_arcs(shared, dialect, patch)
    }

    /// One harness per dialect available in the environment — the parity
    /// loop (issue #20): `for kit in TestHarness::all_dialects(make) {
    /// … }` runs one test definition against SQLite and Postgres. The
    /// factory runs once per dialect so every kit gets **fresh module
    /// instances**: a module may carry per-build state (email-signup
    /// parks its `ModuleContext` for the `waitlist.confirmed` handler),
    /// and a shared instance would keep the first dialect's context
    /// alive in the next dialect's router.
    ///
    /// # Panics
    ///
    /// Panics like [`TestHarness::with_database`] for any dialect built.
    #[must_use]
    pub fn all_dialects(make_modules: impl Fn() -> Vec<Box<dyn Module>>) -> Vec<Self> {
        Dialect::available()
            .into_iter()
            .map(|dialect| Self::with_database(make_modules(), dialect))
            .collect()
    }

    /// [`TestHarness::all_dialects`] with a port patch applied to every
    /// kit. The patch runs once per dialect, so it must be a `Fn` over
    /// cloneable captures (`Arc` handles), not a one-shot mover.
    ///
    /// # Panics
    ///
    /// Panics like [`TestHarness::with_database`] for any dialect built.
    #[must_use]
    pub fn all_dialects_with_ports(
        make_modules: impl Fn() -> Vec<Box<dyn Module>>,
        patch: impl Fn(&mut Ports) + Clone,
    ) -> Vec<Self> {
        Dialect::available()
            .into_iter()
            .map(|dialect| {
                let patch = patch.clone();
                Self::with_database_and_ports(make_modules(), dialect, move |ports| patch(ports))
            })
            .collect()
    }

    pub(crate) fn from_arcs(
        shared: Vec<Arc<dyn Module>>,
        dialect: Dialect,
        patch: impl FnOnce(&mut Ports),
    ) -> Self {
        Self::from_arcs_with_builder(shared, dialect, |builder| builder, patch)
    }

    /// [`TestHarness::with_ports`] with a hook over the `HarnessBuilder`
    /// before it builds: mount a UI renderer (`.ui(..)`), add a template
    /// override, anything the venture would do in `src/lib.rs`.
    ///
    /// # Panics
    ///
    /// Panics when the harness cannot build or a migration fails.
    #[must_use]
    pub fn with_builder(
        modules: Vec<Box<dyn Module>>,
        configure: impl FnOnce(HarnessBuilder) -> HarnessBuilder,
        patch: impl FnOnce(&mut Ports),
    ) -> Self {
        let shared: Vec<Arc<dyn Module>> = modules.into_iter().map(Arc::from).collect();
        Self::from_arcs_with_builder(shared, Dialect::Sqlite, configure, patch)
    }

    fn from_arcs_with_builder(
        shared: Vec<Arc<dyn Module>>,
        dialect: Dialect,
        configure: impl FnOnce(HarnessBuilder) -> HarnessBuilder,
        patch: impl FnOnce(&mut Ports),
    ) -> Self {
        let mut builder = Harness::builder().venture(
            Venture::new("test-venture", "test.example").cors_origins(["https://test.example"]),
        );
        for module in &shared {
            builder = builder.module_arc(Arc::clone(module));
        }
        let harness = configure(builder)
            .runtime(TestRuntime)
            .build()
            .expect("test harness builds");

        let dialect_name = dialect.name();
        #[cfg(feature = "postgres")]
        let (db, pg) = backing(dialect, &shared);
        #[cfg(not(feature = "postgres"))]
        let (db, _no_postgres_feature) = backing(dialect, &shared);

        let mailer = FakeMailer::new(crate::fakes::MailerMode::SendOk);
        let captcha = FakeCaptcha::allow_all();
        let rate_limiter = FakeRateLimiter::always_allow();
        let text_model = FakeTextModel::default();
        let classifier = FakeClassifier::default();
        let clock = FixedClock(
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("fixed epoch"),
        );
        let kv = MemoryKeyValue::new();
        let http = FakeHttpClient::ok_json("{}");
        let defer = FakeDefer::new();
        let tracker = FakeTracker::new(crate::fakes::TrackerMode::FileOk);
        let signer = Arc::new(
            HmacSigner::new(crate::TEST_HARNESS_SECRET, None).expect("test secret is long enough"),
        );

        let mut ports = Ports::with_config(Arc::new(MapConfig::default()));
        ports.db = Some(db.clone());
        ports.mailer = Some(Arc::new(mailer.clone()));
        ports.captcha = Some(Arc::new(captcha.clone()));
        ports.rate_limiter = Some(Arc::new(rate_limiter.clone()));
        ports.text_model = Some(Arc::new(text_model.clone()));
        ports.classifier = Some(Arc::new(classifier.clone()));
        ports.signer = Some(signer.clone());
        ports.kv = Some(Arc::new(kv.clone()));
        ports.http = Some(Arc::new(http.clone()));
        ports.clock = Some(Arc::new(clock.clone()));
        ports.id_gen = Some(Arc::new(UlidIdGen));
        ports.defer = Some(Arc::new(defer.clone()));
        ports.tracker = Some(Arc::new(tracker.clone()));
        patch(&mut ports);

        let router = harness.router(ports);
        Self {
            router,
            harness,
            mailer,
            captcha,
            rate_limiter,
            text_model,
            classifier,
            clock,
            kv,
            http,
            defer,
            tracker,
            signer,
            db,
            modules: shared,
            dialect: dialect_name,
            #[cfg(feature = "postgres")]
            pg,
        }
    }
}

/// A fresh in-memory SQLite database with every module's sqlite
/// migrations applied. Panics on the first failure, naming the module.
fn sqlite_backing(modules: &[Arc<dyn Module>]) -> Arc<dyn Database> {
    let db = Arc::new(SqliteDatabase::in_memory().expect("in-memory sqlite"));
    for module in modules {
        db.apply_migrations(module.name(), module.migrations().sqlite)
            .unwrap_or_else(|err| panic!("migration for {}: {err}", module.name()));
    }
    db
}

/// The migrated database (and, on Postgres, the fixture owning the
/// throwaway database and its runtime) for the dialect.
#[cfg(feature = "postgres")]
fn backing(
    dialect: Dialect,
    modules: &[Arc<dyn Module>],
) -> (Arc<dyn Database>, Option<crate::pg::PgFixture>) {
    match dialect {
        Dialect::Sqlite => (sqlite_backing(modules), None),
        Dialect::Postgres { url } => {
            let fixture = crate::pg::PgFixture::create(&url, modules)
                .unwrap_or_else(|message| panic!("postgres parity kit: {message}"));
            let db = fixture.database();
            (db, Some(fixture))
        }
    }
}

/// Without the `postgres` feature there is no Postgres fixture type; the
/// second element of the pair is always `None` and asking for the
/// Postgres dialect fails loudly instead of silently passing.
// By value, like its `postgres` twin above, which moves the URL out of the
// dialect. Taking a reference here to satisfy the lint would give the two
// halves of one `cfg` pair different signatures — and the caller would then
// compile only with the feature it is meant to be independent of.
#[cfg(not(feature = "postgres"))]
#[allow(clippy::needless_pass_by_value)]
fn backing(
    dialect: Dialect,
    modules: &[Arc<dyn Module>],
) -> (Arc<dyn Database>, Option<std::convert::Infallible>) {
    match dialect {
        Dialect::Sqlite => (sqlite_backing(modules), None),
        Dialect::Postgres { .. } => panic!(
            "cratefield-testing was built without the `postgres` feature — the Postgres \
             parity leg needs it (dev-depend on cratefield-testing with \
             features = [\"postgres\"])"
        ),
    }
}
