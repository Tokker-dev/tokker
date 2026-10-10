//! The module contract (architecture section 4). A module is a crate that
//! contributes one router under `/v1/<name>`, its migrations, its events and
//! its scheduled work — and sees nothing but ports.

use crate::config::{Config, ConfigError};
use crate::events::{AnyError, EventBus, EventHandler, EventName};
use crate::ports::{Port, Ports};
use crate::scheduled::ScheduledBudget;
use crate::surface::Surface;
use crate::template::TemplateRegistry;
use crate::venture::Venture;
use std::sync::Arc;

pub use futures_core::future::BoxFuture;

/// Contract version shared by core and every module. `Harness::build`
/// rejects modules whose `harness_api` differs. Bumped only on breaking
/// contract changes; `cratefield-core`'s major follows it.
pub const HARNESS_API: u32 = 1;

/// The message `Harness::build` and `fz doctor` report for a module whose
/// [`Module::harness_api`] differs from core's: it names the module, the
/// module crate's version, the API it targets, and the `cratefield-core`
/// crate with its version and API (issue #17).
#[must_use]
pub fn harness_api_mismatch(module: &dyn Module) -> String {
    format!(
        "module `{name}` v{version} targets harness API {api}, but {core} v{core_version} \
         provides harness API {harness_api}: rebuild `{name}` against this core — the supported \
         ranges are in docs/COMPATIBILITY.md",
        name = module.name(),
        version = module.version(),
        api = module.harness_api(),
        core = env!("CARGO_PKG_NAME"),
        core_version = env!("CARGO_PKG_VERSION"),
        harness_api = HARNESS_API,
    )
}

/// One migration step, embedded with `include_str!` from
/// `crates/<module>/migrations/<dialect>/NNNN_name.sql` (issue #8).
///
/// `#[non_exhaustive]` plus [`SqlMigration::new`] is the same fix `Message`
/// got (issue #189): a module crate cannot build this by literal, so adding
/// a field here stops being a breaking change across the 70+ migration sets
/// in the workspace (issue #255).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SqlMigration {
    /// Sortable id: `0001`, `0002`, ... — zero-padded so lexical order is
    /// apply order.
    pub id: &'static str,
    /// Short slug from the file name (`0001_init.sql` -> `init`), used in
    /// the wrangler-facing collected file names.
    pub name: &'static str,
    pub sql: &'static str,
    /// Whether the migration and its tracking row commit atomically
    /// (the default). `false` marks the statements Postgres refuses inside
    /// a transaction block (`CREATE INDEX CONCURRENTLY`): they run alone,
    /// the tracking row follows, and the SQL must be idempotent —
    /// RECONCILIATION.md §4.
    pub transactional: bool,
}

impl SqlMigration {
    /// The ordinary migration: the four-digit id, the slug from the file
    /// name, the embedded SQL, transactional. `const` because every
    /// migration set is a `const` array checked by
    /// [`assert_migration_set`], itself a `const fn`.
    #[must_use]
    pub const fn new(id: &'static str, name: &'static str, sql: &'static str) -> Self {
        Self {
            id,
            name,
            sql,
            transactional: true,
        }
    }

    /// Marks the migration as running outside a transaction: for statements
    /// Postgres refuses inside one (`CREATE INDEX CONCURRENTLY`).
    #[must_use]
    pub const fn non_transactional(mut self) -> Self {
        self.transactional = false;
        self
    }
}

/// Rejects a malformed migration set **at compile time**.
///
/// The array a module hands to [`Migrations`] is the apply order, and
/// nothing checked that it agreed with the ids in it. `auth-core` defines
/// its six migration constants in the file in the order 1, 2, 5, 6, 4, 3
/// and lists them in the arrays correctly; that is one careless edit away
/// from applying `0005` before `0003`, against a database that would
/// record both as applied and never notice (issue #27).
///
/// Call it in a `const` item beside the set, where a failure is a build
/// error rather than something a boot discovers:
///
/// ```
/// # use cratefield_core::{SqlMigration, assert_migration_set};
/// const MIGRATIONS: [SqlMigration; 2] = [
///     SqlMigration::new("0001", "init", ""),
///     SqlMigration::new("0002", "next", ""),
/// ];
/// const _: () = assert_migration_set(&MIGRATIONS);
/// ```
///
/// A gap does not compile:
///
/// ```compile_fail
/// # use cratefield_core::{SqlMigration, assert_migration_set};
/// const MIGRATIONS: [SqlMigration; 2] = [
///     SqlMigration::new("0001", "init", ""),
///     SqlMigration::new("0003", "skipped", ""),
/// ];
/// const _: () = assert_migration_set(&MIGRATIONS);
/// ```
///
/// Nor a duplicate, nor an id out of order, nor one that is not four
/// digits:
///
/// ```compile_fail
/// # use cratefield_core::{SqlMigration, assert_migration_set};
/// const MIGRATIONS: [SqlMigration; 2] = [
///     SqlMigration::new("0002", "second", ""),
///     SqlMigration::new("0001", "first", ""),
/// ];
/// const _: () = assert_migration_set(&MIGRATIONS);
/// ```
///
/// ```compile_fail
/// # use cratefield_core::{SqlMigration, assert_migration_set};
/// const MIGRATIONS: [SqlMigration; 1] =
///     [SqlMigration::new("1", "unpadded", "")];
/// const _: () = assert_migration_set(&MIGRATIONS);
/// ```
///
/// # Panics
///
/// At compile time when called in a `const` item, at run time otherwise.
/// The message is a fixed string: `panic!` in a `const fn` cannot format,
/// so the offending id is not in it. The compile error points at the
/// `const` item, which names the crate and the line — enough to find the
/// set, which is the whole array anyway.
pub const fn assert_migration_set(set: &[SqlMigration]) {
    let mut index = 0;
    while index < set.len() {
        let id = set[index].id.as_bytes();
        assert!(
            id.len() == 4,
            "a migration id is four digits, zero-padded: `0001`, not `1`"
        );
        let mut digit = 0;
        while digit < 4 {
            assert!(
                id[digit] >= b'0' && id[digit] <= b'9',
                "a migration id is four digits, zero-padded: `0001`, not `init`"
            );
            digit += 1;
        }
        let value = (id[0] - b'0') as usize * 1000
            + (id[1] - b'0') as usize * 100
            + (id[2] - b'0') as usize * 10
            + (id[3] - b'0') as usize;
        assert!(
            value == index + 1,
            "migration ids run contiguously from 0001 in apply order: a gap, a duplicate, or an entry listed out of order"
        );
        index += 1;
    }
}

/// The sha256 of a migration's SQL, lowercase hex. Recorded in
/// `harness_migrations` when the migration is applied, so a later run
/// can tell "already applied" from "applied, then edited" — the rule
/// forward-only migrations rest on, enforced by the database rather
/// than by a lockfile in one repository (issues #28, #34).
///
/// The lockfile's hash covers the collected *file*; this covers the
/// embedded SQL. They answer different questions and are not compared.
#[must_use]
pub fn migration_checksum(sql: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(sql.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// True when the SQL carries an idempotence guard, so re-running it
/// after a crash is safe. Required of every migration marked
/// `transactional: false` (RECONCILIATION.md §4).
#[must_use]
pub fn is_idempotent_sql(sql: &str) -> bool {
    // Comments are stripped first. A guard that reads the whole file
    // accepts `-- we could use IF NOT EXISTS here but did not` above SQL
    // that has no guard at all — which is precisely the migration this
    // check exists to refuse, waved through by a sentence about it.
    let sql = strip_sql_comments(sql).to_ascii_lowercase();
    sql.contains("if not exists") || sql.contains("if exists") || sql.contains("or replace")
}

/// SQL with `--` line comments and `/* */` blocks removed.
///
/// Not a parser: it does not know that a `--` inside a string literal is
/// not a comment. That direction is safe here — it can only remove text
/// the guard would have read, so the guard refuses rather than accepts.
fn strip_sql_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut rest = sql;
    while let Some(at) = rest.find("--").into_iter().chain(rest.find("/*")).min() {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        if tail.starts_with("--") {
            rest = tail.find('\n').map_or("", |end| &tail[end..]);
        } else {
            rest = tail.find("*/").map_or("", |end| &tail[end + 2..]);
        }
    }
    out.push_str(rest);
    out
}

/// The message a non-transactional migration without an idempotence
/// guard gets. Shared so both engines say the same thing.
#[must_use]
pub fn migration_missing_guard(key: &str) -> String {
    format!(
        "migration `{key}` is marked transactional: false, so it runs outside a transaction and \
         must be idempotent: give the SQL an `IF NOT EXISTS` or `OR REPLACE` guard \
         (RECONCILIATION.md, section 4)"
    )
}

/// The message a migration whose recorded checksum no longer matches
/// gets. Shared so both engines say the same thing.
#[must_use]
pub fn migration_edited(key: &str, recorded: &str, found: &str) -> String {
    format!(
        "migration `{key}` was already applied to this database with different SQL \
         (recorded sha256 {}…, embedded {}…). Applied migrations are never edited: \
         revert the change and write a new migration instead \
         (docs/MODULE-AUTHORING.md, step 3)",
        &recorded[..recorded.len().min(12)],
        &found[..found.len().min(12)]
    )
}

/// The module's migrations, per dialect. `postgres` differs from `sqlite`
/// only where the SQL truly differs (ADR 0004).
#[derive(Debug, Clone)]
pub struct Migrations {
    pub sqlite: &'static [SqlMigration],
    pub postgres: &'static [SqlMigration],
}

impl Migrations {
    pub const EMPTY: Migrations = Migrations {
        sqlite: &[],
        postgres: &[],
    };

    pub const fn sqlite(migrations: &'static [SqlMigration]) -> Self {
        Migrations {
            sqlite: migrations,
            postgres: &[],
        }
    }
}

impl Default for Migrations {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Everything a module's router needs: its declared ports, the typed
/// config, the bus, the templates and the venture identity.
pub struct ModuleContext {
    /// Only the ports the module declared in `requires()`/`optional()`.
    pub ports: Ports,
    /// Full config; module keys are prefixed (`EMAIL_SIGNUP_CONFIRM_TTL_DAYS`).
    pub config: Arc<dyn Config>,
    pub events: EventBus,
    pub templates: Arc<TemplateRegistry>,
    pub venture: Arc<Venture>,
    /// Whether an operator has recorded an explicit acceptance that this
    /// deployment serves guarded routes it cannot fully protect
    /// (`HARNESS_ALLOW_UNPROTECTED_WRITES`, issue #143).
    ///
    /// It exists because the acceptance has to mean the same thing at
    /// both layers. The boot gate honours it and serves; if the
    /// per-request gate did not, the deployment would refuse every write
    /// anyway — the same outage, with a different status code. A module
    /// enforcing an abuse control passes this to
    /// [`verify_human_form`](crate::route_policy::verify_human_form)
    /// rather than deciding from the environment alone.
    pub unprotected_writes_accepted: bool,
    /// Every personal-data declaration in this composition, composed once at
    /// build (issue: privacy module). A module reads it to export or erase a
    /// subject's data without knowing which other modules the venture chose;
    /// most modules ignore it, which costs them an `Arc` clone per request.
    pub personal_data: std::sync::Arc<crate::PersonalDataCatalog>,
    /// `true` when the venture mounted a UI renderer (ADR 0010). A module
    /// then defaults its landing redirects (confirmed, expired,
    /// unsubscribed, status) to `<api base>/ui/<module>/<action>/<page>`
    /// instead of pages the venture site has to provide.
    pub ui_mounted: bool,
    /// The budget for the current scheduled invocation (issue #537):
    /// cooperative, so a module checks it around each unit of work and
    /// stops — never cancelled — when it has run out. Split across the
    /// modules by the runtime with each module's unspent share rolling
    /// forward. **Unbounded outside `scheduled`**: request handlers can
    /// read it and never see a limit that does not apply to them.
    pub scheduled: Arc<ScheduledBudget>,
}

/// A Factory Zero module. Object-safe; composed as `Arc<dyn Module>`.
///
/// Handlers get the request scope as an axum extractor:
/// `async fn join(scope: Scope, State(ctx): State<Arc<ModuleContext>>, ...)`.
/// There is no ambient "current request" (ADR 0007).
pub trait Module: Send + Sync + 'static {
    /// Kebab-case name; mounted at `/v1/<name>`.
    fn name(&self) -> &'static str;
    /// `env!("CARGO_PKG_VERSION")`, surfaced by `/__health`.
    fn version(&self) -> &'static str;
    /// Contract version, checked by `Harness::build`.
    fn harness_api(&self) -> u32 {
        HARNESS_API
    }
    /// Ports the module cannot run without; missing = build error.
    fn requires(&self) -> &'static [Port];
    /// Ports the module uses when present.
    fn optional(&self) -> &'static [Port] {
        &[]
    }
    /// Modules this one's schema sits on top of, by name.
    ///
    /// A partial order, not a load order for routes: it exists so
    /// migrations apply in an order where a foreign key can point at a
    /// table another module owns (RECONCILIATION.md §2). Naming a module
    /// the venture did not compose is a build error, and so is a cycle —
    /// both at `HarnessBuilder::build`, never at boot, because a boot
    /// error is one a deployment discovers in production.
    ///
    /// Declaring nothing is the common case and costs nothing: with no
    /// dependencies anywhere the resolved order is composition order,
    /// unchanged.
    fn depends_on(&self) -> &'static [&'static str] {
        &[]
    }
    /// Table names this module owns; duplicates across modules are a build
    /// error.
    fn tables(&self) -> &'static [&'static str] {
        &[]
    }
    /// What this module holds about a person, per table.
    ///
    /// Read by `cratefield-module-privacy` to export a subject's data, to
    /// erase it, and to publish the "what is stored" table. Declaring it here
    /// rather than in the privacy module is what makes that module reusable:
    /// it never names a venture's tables, so a schema change cannot leave it
    /// describing something that no longer exists.
    ///
    /// Validated at [`HarnessBuilder::build`]: a table this module does not
    /// own is an error, and so is a declaration that cannot mean anything —
    /// an `Anonymise` naming no columns, a `Retain` with no reason, a
    /// published description left blank. See [`PersonalDataSet::none`] for a
    /// table that legitimately holds nothing personal, which says so rather
    /// than staying silent.
    ///
    /// Defaulting to empty keeps every existing module compiling unchanged,
    /// and a module with no tables has nothing to say. A module that **owns**
    /// tables and declares nothing is a different thing, and since issue #244
    /// it fails [`cratefield_testing::conformance`] rather than the build:
    /// see [`undeclared_tables`](crate::undeclared_tables) for why the kit is
    /// the place that refuses it and a running deployment is not.
    ///
    /// [`cratefield_testing::conformance`]: https://docs.rs/cratefield-testing
    ///
    /// [`HarnessBuilder::build`]: crate::HarnessBuilder::build
    /// [`PersonalDataSet::none`]: crate::PersonalDataSet::none
    fn personal_data(&self) -> &'static [crate::PersonalDataSet] {
        &[]
    }
    /// Event names this module emits (`"<module>.<event>"`), listed by
    /// `/__health`.
    fn emits(&self) -> &'static [&'static str] {
        &[]
    }
    /// Whether the module has public write endpoints.
    ///
    /// **Advisory since issue #133.** The enforcement point is each
    /// route's [`RoutePolicy`] on the declared surface, collected by
    /// [`WriteGuards::collect`] and gated at `HarnessBuilder::build`.
    /// A module that writes publicly but declares **no** policy on any
    /// action counts as a [`HumanForm`] writer (the conservative
    /// fallback for pre-surface modules); declaring an explicit
    /// `Open`/`Signature` policy on every action opts out of the
    /// fallback.
    ///
    /// [`RoutePolicy`]: crate::route_policy::RoutePolicy
    /// [`WriteGuards::collect`]: crate::route_policy::WriteGuards::collect
    /// [`HumanForm`]: crate::route_policy::RoutePolicy::HumanForm
    fn public_writes(&self) -> bool {
        false
    }
    /// What actually protects those public writes, for a module with no
    /// ADR 0010 surface to hang a per-action [`RoutePolicy`] on
    /// (issue #143).
    ///
    /// Consulted **only** when [`public_writes`] is true and the surface
    /// declares no guarded action, so a module with a surface is
    /// unaffected and the conservative default is unchanged: say nothing
    /// and you are still a [`HumanForm`] writer. The auth login methods
    /// are the reason it exists — they are public writers whose proof is
    /// a single-use challenge or a signed link, never a CAPTCHA widget,
    /// and before this they could only be filed under a gate they can
    /// never satisfy.
    ///
    /// [`public_writes`]: Module::public_writes
    /// [`RoutePolicy`]: crate::route_policy::RoutePolicy
    /// [`HumanForm`]: crate::route_policy::RoutePolicy::HumanForm
    fn public_write_policy(&self) -> crate::route_policy::RoutePolicy {
        crate::route_policy::RoutePolicy::HumanForm
    }
    /// Which verifier proves this module's [`RoutePolicy::Signature`]
    /// deliveries (issue #533): how a webhook handler checks a machine
    /// signature before acting.
    ///
    /// This is the **default** for the module's signature routes. A route
    /// that declares its own verifier — `.verification(..)` on the
    /// [`Action`](crate::surface::Action) (issue #595) — overrides it, so
    /// one module can verify a Stripe webhook through `Payments` and a
    /// `RevenueCat` webhook with its own HMAC secret.
    ///
    /// Consulted only when the module actually has signature-guarded
    /// routes — [`WriteGuards::collect`] resolves each route's verifier
    /// (its own, else this) and the production gate demands exactly what
    /// was declared:
    ///
    /// - [`SignatureVerification::Payments`](crate::route_policy::SignatureVerification::Payments)
    ///   (the default): the handler
    ///   proves deliveries with `Payments::verify_webhook` plus the Inbox
    ///   dedup ledger, and production requires an effective `Payments`
    ///   port. Every module built before this existed gets this, unchanged.
    /// - [`SignatureVerification::Hmac`](crate::route_policy::SignatureVerification::Hmac):
    ///   the handler proves deliveries
    ///   with the core `webhook_signature` scheme (Svix, Stripe-style, or
    ///   a provider-specific layout), keyed by the module-scoped config
    ///   secret named here — a [`ModuleConfig`] suffix, so `"WEBHOOK_SECRET"`
    ///   on module `pos` is read from `POS_WEBHOOK_SECRET`. Production
    ///   requires that key and no `Payments` port.
    ///
    /// [`RoutePolicy::Signature`]: crate::route_policy::RoutePolicy::Signature
    /// [`WriteGuards::collect`]: crate::route_policy::WriteGuards::collect
    /// [`ModuleConfig`]: crate::config::ModuleConfig
    fn signature_verification(&self) -> crate::route_policy::SignatureVerification {
        crate::route_policy::SignatureVerification::Payments
    }
    /// The module's migrations, embedded per dialect.
    fn migrations(&self) -> Migrations;
    /// Rejects invalid configuration: missing required keys or malformed
    /// values, reported together with the module name.
    ///
    /// **When it runs.** The conformance kit calls it, and a module's own
    /// tests should. It cannot run at `Harness::build` or in `fz doctor`,
    /// because neither has the deploy config — the values live on the runtime
    /// `Env` and only exist per request. The Cloudflare runtime therefore runs
    /// it **once at cold start** and logs any failure loudly (`console_error!`,
    /// so it reaches Workers Logs); it does not fail the boot, so a
    /// misconfigured module still degrades per request (issue #101) rather
    /// than taking the whole Worker down. Turning that into a hard boot
    /// failure is a deployment decision for an ADR.
    ///
    /// # Errors
    ///
    /// `Err` listing every invalid or missing key for this module.
    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError>;
    /// The largest request body any route of this module accepts, so a
    /// runtime can refuse an oversize body **before** buffering it
    /// (issue #440).
    ///
    /// This is a coarse per-module ceiling, not a per-route limit. A
    /// runtime with a fixed memory budget — a Workers isolate, say — reads
    /// it through [`Harness::max_body_bytes`] when a request arrives and
    /// refuses everything above it at the door, because the precise
    /// enforcement, axum's `DefaultBodyLimit` inside [`Module::router`],
    /// only fires once the body is already resident in memory. It must
    /// never return less than the harness-wide [`MAX_BODY_BYTES`]: the
    /// runtime guard sits **in front of** the router, and a module that
    /// tightened it would 413 requests the router itself would have
    /// accepted. Raising it is legitimate — LinkedIn's image upload does —
    /// but the route that justifies the raise keeps its own
    /// `DefaultBodyLimit`, which stays the precise per-route enforcer.
    ///
    /// `cfg` is the live deployment config, so a module that moves a cap
    /// from configuration must read it here too: if an operator raises
    /// `MAX_IMAGE_BYTES` above the compiled default, the runtime guard must
    /// not refuse a body the route would have accepted.
    ///
    /// Default: [`MAX_BODY_BYTES`], so a module that says nothing changes
    /// nothing.
    ///
    /// [`Harness::max_body_bytes`]: crate::Harness::max_body_bytes
    /// [`MAX_BODY_BYTES`]: crate::http::MAX_BODY_BYTES
    fn max_body_bytes(&self, _cfg: &dyn Config) -> usize {
        crate::http::MAX_BODY_BYTES
    }

    /// Routes this module serves in **streaming** mode (issue #585), each
    /// with its own [`StreamRoute::max_bytes`] ceiling. Opt-in: the default
    /// is empty, and every existing route keeps the buffered behaviour it
    /// always had.
    ///
    /// On a declared route the router reads the body as a stream instead of
    /// buffering it: the handler extracts a [`RequestStream`], the route's
    /// `max_bytes` replaces [`Module::max_body_bytes`] for the declared
    /// `content-length` pre-check, and the handler may answer with a
    /// [`ResponseStream`]. The paths are relative to the module's
    /// `/v1/<name>` mount and use axum's pattern syntax (`/upload`,
    /// `/files/{id}`, `/files/{*rest}`). A `(method, path)` that names no
    /// declared route is untouched.
    ///
    /// [`RequestStream`]: crate::RequestStream
    /// [`ResponseStream`]: crate::ResponseStream
    /// [`StreamRoute::max_bytes`]: crate::StreamRoute::max_bytes
    fn streaming_routes(&self) -> &'static [crate::StreamRoute] {
        &[]
    }

    /// Problems the module can find in **itself**, with no configuration
    /// and no environment: its own embedded data, checked against its own
    /// declarations.
    ///
    /// This is the half of [`Module::validate_config`] that `fz doctor`
    /// can actually run. The doctor has no deploy config — those values
    /// live on the runtime `Env` and exist only per request — so it cannot
    /// ask a module whether its *deployment* is valid. It can ask whether
    /// what the module compiled in is coherent, and that answer is the
    /// same on a laptop, in CI and in production.
    ///
    /// The notifications module answers with every translation its catalog
    /// is missing (issue #190), so a translation gap is a pull request
    /// rather than a person reading a message id on a lock screen.
    ///
    /// Each string is one problem, already naming the module. Return
    /// **identifiers**, never values: this is printed by a CLI and copied
    /// into issues, so nothing read from the environment, a recipient or a
    /// URL may appear in one. Default: nothing, so no existing module
    /// changes.
    fn self_check(&self) -> Vec<String> {
        Vec::new()
    }
    /// The module's router, nested under `/v1/<name>`.
    fn router(&self, ctx: ModuleContext) -> axum::Router;
    /// Routes this module serves at the root under `/.well-known`, for
    /// spec-mandated discovery documents (OIDC `openid-configuration`,
    /// `jwks.json`) that must live outside `/v1` (issue #46). Paths are
    /// relative to the prefix: register `/jwks.json`, not
    /// `/.well-known/jwks.json`.
    ///
    /// At most one module may provide one: discovery URLs are a singleton
    /// namespace, so `Harness::build` fails (naming every provider) when
    /// two modules return a router here. `None` by default.
    fn well_known(&self) -> Option<axum::Router> {
        None
    }
    /// The module's UI surface (ADR 0010): the actions a renderer may
    /// offer and the views that compose them. Input schemas come from
    /// the handler's own body types (`Action::input::<Body>()`), so the
    /// declaration cannot drift from the route. `Harness::build`
    /// validates it; `GET /__surface` serves the composition. Default:
    /// nothing, and a module that declares nothing renders nothing.
    fn surface(&self) -> Surface {
        Surface::none()
    }
    /// Handlers for events other modules emit; registered at
    /// `Harness::build`.
    fn events(&self) -> Vec<(EventName, EventHandler)> {
        Vec::new()
    }
    /// Scheduled work (`cron` is the trigger expression). Default: none.
    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        let _ = (ctx, cron);
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod reconciliation_guard_tests {
    use super::{SqlMigration, is_idempotent_sql, migration_missing_guard};

    #[test]
    fn a_migration_is_transactional_unless_marked_otherwise() {
        // The flag exists so RECONCILIATION.md §4 has something to read;
        // every module that does not say a word keeps the atomic
        // behaviour both runners have always had.
        let migration = SqlMigration::new("0001", "init", "CREATE TABLE t (id TEXT PRIMARY KEY);");
        assert!(migration.transactional);
        assert!(!migration.clone().non_transactional().transactional);
    }

    #[test]
    fn guarded_ddl_is_idempotent_plain_ddl_is_not() {
        assert!(is_idempotent_sql(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS i ON t (c)"
        ));
        assert!(is_idempotent_sql(
            "CREATE OR REPLACE FUNCTION f() RETURNS void AS $$ BEGIN END $$;"
        ));
        assert!(is_idempotent_sql("DROP INDEX CONCURRENTLY IF EXISTS i"));
        assert!(!is_idempotent_sql("CREATE INDEX CONCURRENTLY i ON t (c)"));
        // Case-insensitive: SQL is written in any case.
        assert!(is_idempotent_sql("create index if not exists i on t (c)"));

        // A sentence about the guard is not the guard. Reading the whole
        // file waves through exactly the migration this refuses: one that
        // runs outside a transaction, is re-run after a crash, and fails.
        assert!(!is_idempotent_sql(
            "-- we could use IF NOT EXISTS here but did not\nCREATE INDEX CONCURRENTLY i ON t (c)"
        ));
        assert!(!is_idempotent_sql(
            "/* IF NOT EXISTS is unavailable on this engine */ CREATE INDEX i ON t (c)"
        ));
        // And a real guard after a comment is still found.
        assert!(is_idempotent_sql(
            "-- concurrently, so it must be idempotent\nCREATE INDEX CONCURRENTLY IF NOT EXISTS i ON t (c)"
        ));
    }

    #[test]
    fn the_missing_guard_message_names_the_migration_and_the_rule() {
        let message = migration_missing_guard("waitlist/0005");
        assert!(message.contains("waitlist/0005"), "{message}");
        assert!(message.contains("IF NOT EXISTS"), "{message}");
    }
}
