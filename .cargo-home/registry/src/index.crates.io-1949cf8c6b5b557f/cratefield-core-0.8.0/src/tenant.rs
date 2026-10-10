//! The tenant a request belongs to, and the statuses the control
//! database's registry carries (RECONCILIATION.md §6, ADR 0008,
//! TENANT-ROUTING.md).
//!
//! [`TenantId`] and [`Tenant`] are nameable everywhere and constructible
//! only here. That is the whole isolation argument: a module cannot ask
//! the registry for a neighbour's pool by writing a different string,
//! because it cannot write a [`TenantId`] at all. Same shape as
//! `HarnessOnly` in the secrets crate (#39), and for the same reason —
//! the type is the boundary, not a convention about how to call a
//! function.

/// A tenant database's reconciliation status.
///
/// Serializes as the registry's own text (`"active"`), not the variant
/// name, so a structured log field and a registry row cannot drift apart.
/// `round_trips_through_the_registry_text` and
/// `serializes_as_the_registry_text` together pin that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
// The lifecycle will grow again — #154 has a promotion path in it — and
// adding a variant to an exhaustive public enum is a breaking change for
// every downstream `match`. This release breaks anyway, adding
// `Offboarding` and `Archived`; spending that break once buys every later
// status for free.
#[non_exhaustive]
pub enum TenantStatus {
    /// Reconciled and serving.
    Active,
    /// Registered, reconciliation not yet succeeded.
    Provisioning,
    /// The last reconciliation failed: requests answer
    /// `503 tenant-degraded` until a boot succeeds.
    Degraded,
    /// Being retired: the export and key shred of
    /// `docs/TENANT-ONBOARDING.md` §2 are under way. It has stopped
    /// serving and will not start again.
    Offboarding,
    /// Retired. The database is dropped and the keys are destroyed;
    /// nothing about this tenant can be served or recovered.
    Archived,
}

impl TenantStatus {
    /// The registry's text form, lowercase and stable.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Provisioning => "provisioning",
            Self::Degraded => "degraded",
            Self::Offboarding => "offboarding",
            Self::Archived => "archived",
        }
    }

    /// Whether boot-time reconciliation should fly this tenant.
    ///
    /// A `match` and not a negation, which is the whole point. The
    /// reconciler asked `status != Degraded` while there were three
    /// statuses, so it was accidentally right; adding `Offboarding` and
    /// `Archived` silently enrolled both in the fleet, which would have
    /// reconnected to a shredded tenant's database and flipped it back to
    /// `active`. Written this way, the next variant added to this
    /// `#[non_exhaustive]` enum cannot compile until someone says which
    /// side of the line it is on.
    #[must_use]
    pub fn is_reconciled(self) -> bool {
        match self {
            Self::Active | Self::Provisioning => true,
            Self::Degraded | Self::Offboarding | Self::Archived => false,
        }
    }

    /// Whether the lifecycle ends here. Only [`TenantStatus::Archived`]
    /// does: the database is dropped and the data keys are destroyed
    /// (`docs/TENANT-ONBOARDING.md` §2), so there is nothing left to
    /// serve and no honest way back. The registry enforces it — see
    /// `Postgres::register_tenant`.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        match self {
            Self::Archived => true,
            Self::Active | Self::Provisioning | Self::Degraded | Self::Offboarding => false,
        }
    }

    /// The statuses a tenant may be in and still become this one.
    ///
    /// The lifecycle rule, in one place, because more than one writer
    /// moves a tenant through it: the reconciler, the offboarding
    /// runbook's tooling and the lifecycle API of #154. A rule that lived
    /// in one adapter's `WHERE` clause would be a rule the next writer
    /// did not have.
    ///
    /// Written as "who may become me" rather than "who may I become" so
    /// the match is on the target, which is what a caller setting a
    /// status has in its hand — and so the list drops straight into the
    /// `UPDATE`'s `WHERE` as the set of previous values that may be
    /// overwritten, making the check part of the same statement rather
    /// than a read the write races.
    ///
    /// Each status admits itself, because writing the status a tenant is
    /// already in changes nothing and a reconciler that runs twice must
    /// not fail the second time. [`TenantStatus::Archived`] is the
    /// exception: it admits nothing, itself included. The row is the
    /// record that the database was dropped and the keys destroyed, and a
    /// record of an irreversible act is not rewritten.
    #[must_use]
    pub const fn admits(self) -> &'static [Self] {
        match self {
            // A tenant is registered as provisioning and nothing returns
            // to it. Re-provisioning an existing tenant is a new tenant,
            // because the old one's keys are either live or destroyed.
            Self::Provisioning => &[Self::Provisioning],
            // Reconciliation succeeded — from a first boot, from a repeat
            // boot, or from a failure that has cleared. Not from
            // `Offboarding`: that tenant's export and key shred are under
            // way (`docs/TENANT-ONBOARDING.md` §2), and a reconciler
            // reviving it would serve a database whose keys are being
            // destroyed underneath it.
            Self::Active => &[Self::Provisioning, Self::Degraded, Self::Active],
            // Reconciliation failed. Reachable from anything still
            // serving or trying to.
            Self::Degraded => &[Self::Provisioning, Self::Active, Self::Degraded],
            // Retirement starts from anywhere that is not already
            // retiring or retired, including `Provisioning`: a tenant
            // abandoned before it ever served still has keys, and they
            // still have to be shredded.
            Self::Offboarding => &[
                Self::Provisioning,
                Self::Active,
                Self::Degraded,
                Self::Offboarding,
            ],
            // Only the offboarding that performed the shred ends here.
            // Archiving straight from `Active` would record a shred that
            // never happened.
            Self::Archived => &[Self::Offboarding],
        }
    }

    /// Whether `self` may become `next`. The same rule as
    /// [`TenantStatus::admits`], asked from the other end.
    #[must_use]
    pub fn can_become(self, next: Self) -> bool {
        next.admits().contains(&self)
    }

    /// Parses the registry's text form; anything else (a future version
    /// wrote a status this binary does not know) reads as
    /// [`TenantStatus::Degraded`] — refuse, do not guess.
    #[must_use]
    pub fn parse(status: &str) -> Self {
        match status {
            "active" => Self::Active,
            "provisioning" => Self::Provisioning,
            "offboarding" => Self::Offboarding,
            "archived" => Self::Archived,
            _ => Self::Degraded,
        }
    }
}

impl std::fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A tenant's key in the control database's registry.
///
/// Not `String`, and not constructible outside core:
///
/// ```compile_fail
/// use cratefield_core::TenantId;
/// // The field is private: module code cannot name a tenant.
/// let _id = TenantId("someone-elses-tenant".to_owned());
/// ```
///
/// Naming the type is fine, which keeps signatures writable:
///
/// ```
/// use cratefield_core::TenantId;
/// fn takes_id(_id: &TenantId) {}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct TenantId(String);

impl TenantId {
    /// Minted from a registry row. `pub(crate)` on purpose — see the
    /// module docs.
    pub(crate) fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The tenant a request belongs to. Immutable, and built only by core's
/// resolution layer from a registry row — never from a header, a path
/// segment, or module code.
///
/// `Clone` because a request carries it into deferred work. Deliberately
/// **not** `Deserialize`: the threat is an identity read back in from an
/// attacker-supplied body, not one written out, so `Serialize` is fine
/// and wanted — a tenant id is a structured log field.
///
/// ```compile_fail
/// use cratefield_core::{Tenant, TenantStatus};
/// // No public constructor, so a handler cannot conjure a neighbour.
/// let _t = Tenant::new("other", TenantStatus::Active);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Tenant {
    id: TenantId,
    status: TenantStatus,
}

impl Tenant {
    pub(crate) fn new(id: impl Into<String>, status: TenantStatus) -> Self {
        Self {
            id: TenantId::new(id),
            status,
        }
    }

    #[must_use]
    pub fn id(&self) -> &TenantId {
        &self.id
    }

    #[must_use]
    pub fn status(&self) -> TenantStatus {
        self.status
    }
}

/// What a deployment's registry says about a host.
///
/// The design sketch had three arms — `Found(Tenant)`, `Unknown`,
/// `Degraded(TenantId)` — but a `Tenant` already carries its status, so
/// the third was the same fact twice and two places to keep in step. It
/// also could not work: a `ResolveTenant` impl lives in a runtime crate,
/// and if the arm carried a `Tenant` the constructor would have to be
/// `pub`, which is exactly what §3 wants to avoid. So the trait reports
/// what the registry said and **core mints the [`Tenant`]**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A registry row for this host.
    Found {
        /// The row's primary key.
        id: String,
        /// The row's status, parsed fail-closed by
        /// [`TenantStatus::parse`].
        status: TenantStatus,
    },
    /// No row for this host: `404 unknown-tenant`.
    Unknown,
}

impl Resolution {
    /// The tenant a request may proceed with, or the problem that refuses
    /// it.
    ///
    /// Only [`TenantStatus::Active`] serves. `Provisioning` is refused
    /// with the same `503 tenant-degraded` as `Degraded`: it means
    /// registered-but-not-yet-reconciled, so its schema is not known to
    /// match the code, which is the condition the refusal exists for. One
    /// slug rather than two because the caller's situation is identical —
    /// come back later — and the operator learns which from the registry,
    /// not from the response.
    pub(crate) fn admit(self) -> Result<Tenant, &'static crate::problems::ProblemDef> {
        match self {
            Self::Found { id, status } if status == TenantStatus::Active => {
                Ok(Tenant::new(id, status))
            }
            // Retired, in either sense: the caller is not waiting for a
            // boot, and there is nothing to come back to. Answered as an
            // unknown tenant so a retired tenant and a host that never
            // existed are indistinguishable from outside — "offboarding"
            // is a fact about a customer, not something to publish to
            // whoever guesses the host.
            Self::Found { status, .. }
                if status == TenantStatus::Offboarding || status == TenantStatus::Archived =>
            {
                Err(&crate::problems::SLUGS.unknown_tenant)
            }
            Self::Found { .. } => Err(&crate::problems::SLUGS.tenant_degraded),
            Self::Unknown => Err(&crate::problems::SLUGS.unknown_tenant),
        }
    }
}

/// How a deployment turns a request's host into a tenant.
///
/// A trait so a deployment that must resolve by something else can, and
/// so tests resolve without DNS. Host is the harness's answer — it is
/// established before any tenant state is consulted, is already validated
/// (#129), and is what the registry is keyed on anyway. A caller-supplied
/// header is refused as policy: a deployment that got
/// `TRUSTED_PROXY_HEADERS` wrong would let any caller name any tenant,
/// and the blast radius of that mistake is every tenant's data
/// (TENANT-ROUTING.md §3).
pub trait ResolveTenant: Send + Sync {
    /// The registry's answer for `host`. Implementations must not block
    /// on a per-request round trip to the control database; see §13's
    /// open question on cache lifetime.
    fn resolve(&self, host: &str) -> Resolution;
}

/// How a deployment turns a resolved tenant into a database handle.
///
/// Separate from [`ResolveTenant`] because the two answers come from
/// different places and fail differently: resolution reads a registry row
/// (cheap, cacheable, and a miss means `404`), while this opens or reuses
/// a connection pool (lazy, evictable, and a failure means the tenant is
/// unreachable rather than unknown).
///
/// Implemented by the runtime, never by a module. The registry that backs
/// it is the only thing in the process that knows a DSN
/// (TENANT-ROUTING.md §4): it maps a connect failure to
/// [`TenantDbError::Unreachable`] **before** the URL can reach a log line
/// or a response body. `Display for DbError` already scrubs, so that is
/// not the only defence — but `Debug` derives raw, and a DSN formatted
/// before it ever becomes a `DbError` is scrubbed by nothing. Not
/// producing the string is the first line; the sink is the second.
#[async_trait::async_trait]
pub trait TenantDatabases: Send + Sync {
    /// The handle for `tenant`, opening its pool on first use.
    ///
    /// # Errors
    ///
    /// [`TenantDbError::Unreachable`] when the tenant's database cannot be
    /// reached. The DSN is never part of the error.
    async fn database(
        &self,
        tenant: &Tenant,
    ) -> Result<std::sync::Arc<dyn crate::ports::Database>, TenantDbError>;
}

/// Why a tenant's database could not be handed over. Deliberately carries
/// the tenant id and nothing else — no DSN, no driver message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantDbError {
    /// The pool could not be opened or the server did not answer.
    Unreachable {
        /// Which tenant. Safe to log.
        tenant: String,
    },
}

impl std::fmt::Display for TenantDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { tenant } => {
                write!(f, "tenant `{tenant}`'s database is unreachable")
            }
        }
    }
}

impl std::error::Error for TenantDbError {}

/// A deployment's tenant plane: a host becomes a tenant, and a tenant
/// becomes a database handle.
///
/// One slot on [`Ports`](crate::Ports) rather than two, because the
/// resolution layer needs both halves of the same request and a
/// deployment that supplied only one would be misconfigured in a way no
/// type could catch. The blanket impl means a runtime writes the two
/// traits and gets this for free.
pub trait TenantRouting: ResolveTenant + TenantDatabases {}

impl<T: ResolveTenant + TenantDatabases> TenantRouting for T {}

/// The registry id a deployment without a registry resolves to.
///
/// Not a magic string scattered across three runtimes: one constant, so
/// a log line from a Cloudflare Worker and one from a `cargo test` run
/// say the same word.
pub const IMPLICIT_TENANT: &str = "default";

/// The resolver a deployment with **no control database** uses: every
/// host is the one venture, always `active`.
///
/// This is not the Cloudflare path, it is the *no registry* path — which
/// is also the browser runtime, and native in every development run and
/// every test (TENANT-ROUTING.md §6). Scoping it to Cloudflare would mean
/// `cargo test` cannot resolve a tenant and every module suite 500s.
///
/// A module is therefore written once, against the stricter shape, and
/// the path most ventures actually run in production is not the one
/// without the isolation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImplicitTenant;

impl ResolveTenant for ImplicitTenant {
    fn resolve(&self, _host: &str) -> Resolution {
        Resolution::Found {
            id: IMPLICIT_TENANT.to_owned(),
            status: TenantStatus::Active,
        }
    }
}

/// Which of the two tenancy shapes served a request.
///
/// A deployment either has a tenant plane — a registry that turns each
/// request's `Host` into a tenant — or it has none, and every host is
/// the one implicit tenant ([`ImplicitTenant`], TENANT-ROUTING.md §6).
/// The two shapes differ in more than wiring: they differ in what "a
/// verified caller" can mean (issue #385). With a registry,
/// `a.example` and `b.example` are different tenants behind one binary,
/// and a subject who signed in as a user of tenant A can present the
/// same bearer at tenant B's host — there, "any verified caller" and
/// "a member of this tenant" are different sets. Without one, the
/// request could only ever have reached the single database there is,
/// and the two sets are the same set.
///
/// The bit records which shape a request arrived under, so a rule that
/// needs membership can fail closed where the sets differ and serve
/// where they coincide. It is a routing fact and deliberately nothing
/// more: [`Tenancy::FromRegistry`] says a registry *named* this tenant,
/// not that the caller belongs to it. Membership is a registry fact
/// this bit does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tenancy {
    /// No tenant plane: every host is the one implicit tenant
    /// ([`IMPLICIT_TENANT`]), and there is no second tenant to leak
    /// into.
    Sole,
    /// A registry resolved this request's tenant from its `Host`
    /// header.
    FromRegistry,
}

#[cfg(test)]
mod tests {
    use super::{Resolution, TenantStatus};

    fn found(status: TenantStatus) -> Resolution {
        Resolution::Found {
            id: "acme".to_owned(),
            status,
        }
    }

    /// Declares [`EVERY`] and, from the same list, a match that has to
    /// be exhaustive.
    ///
    /// Every "for each status" test reads `EVERY` rather than writing its
    /// own list, because a hand-written list quietly covers one fewer
    /// case than its name claims the day a variant is added — which had
    /// already happened here: `Offboarding` and `Archived` arrived in
    /// #336 and the serialization test kept checking three of five.
    ///
    /// The macro is what makes that impossible rather than merely
    /// discouraged. A first attempt at this used a separate
    /// `position(status) -> usize` with an exhaustive match, which only
    /// forced the *function* to be updated: nothing ever called it for a
    /// variant the array did not already hold, so the array could stay
    /// short and every test still passed. Adding a variant to the enum
    /// now fails to compile in `exhaustive` below, and the only way to
    /// satisfy that is to add it to this one invocation — which is also
    /// the array.
    macro_rules! statuses {
        ($($variant:ident),+ $(,)?) => {
            /// Every status. Not public: a caller enumerating an
            /// `#[non_exhaustive]` enum is the thing that attribute
            /// exists to prevent, and inside the crate it is exhaustive
            /// anyway.
            const EVERY: &[TenantStatus] = &[$(TenantStatus::$variant),+];

            /// Never called. It exists so that a variant absent from the
            /// list above is a compile error here.
            #[expect(dead_code, reason = "its only job is to be exhaustive")]
            fn exhaustive(status: TenantStatus) {
                match status {
                    $(TenantStatus::$variant => {}),+
                }
            }
        };
    }

    statuses!(Provisioning, Active, Degraded, Offboarding, Archived);

    #[test]
    fn the_implicit_tenant_answers_for_every_host() {
        use super::{IMPLICIT_TENANT, ImplicitTenant, ResolveTenant};
        // A deployment with no registry has one tenant, and which host
        // asked is not a question it can answer differently - including
        // for a host it has never seen, which is what a test client and a
        // loopback probe both look like.
        for host in ["acme.example", "localhost:8787", ""] {
            let tenant = ImplicitTenant
                .resolve(host)
                .admit()
                .expect("the implicit tenant always serves");
            assert_eq!(tenant.id().as_str(), IMPLICIT_TENANT);
            assert_eq!(tenant.status(), TenantStatus::Active);
        }
    }

    #[test]
    fn only_an_active_tenant_is_admitted() {
        let tenant = found(TenantStatus::Active)
            .admit()
            .expect("an active tenant serves");
        assert_eq!(tenant.id().as_str(), "acme");
        assert_eq!(tenant.status(), TenantStatus::Active);
    }

    #[test]
    fn provisioning_is_refused_like_degraded_and_not_like_unknown() {
        // Registered but not yet reconciled: the schema is not known to
        // match the code, which is the condition the refusal exists for.
        // The caller's situation is identical to degraded - come back
        // later - so it is one slug, and the operator learns which from
        // the registry rather than from the response.
        for status in [TenantStatus::Provisioning, TenantStatus::Degraded] {
            let problem = found(status).admit().expect_err("must not serve");
            assert_eq!(problem.slug, "tenant-degraded", "for {status}");
            assert_eq!(problem.status.as_u16(), 503);
        }
    }

    #[test]
    fn a_retired_tenant_is_indistinguishable_from_one_that_never_existed() {
        // Not `tenant-degraded`: that says "come back later", and there is
        // nothing to come back to. Answering as unknown also keeps
        // "this customer left" from being readable by anyone who guesses
        // the host.
        for status in [TenantStatus::Offboarding, TenantStatus::Archived] {
            let retired = found(status).admit().expect_err("must not serve");
            let never_existed = Resolution::Unknown.admit().expect_err("must not serve");
            assert_eq!(
                retired.slug, never_existed.slug,
                "{status} must answer exactly as an unknown host does"
            );
        }
    }

    #[test]
    fn every_status_round_trips_through_the_registry_text() {
        for &status in EVERY {
            assert_eq!(
                TenantStatus::parse(status.as_str()),
                status,
                "{status} does not survive a trip through the registry"
            );
        }
    }

    #[test]
    fn only_active_serves() {
        // The whole lifecycle, stated once: exactly one status admits.
        for &status in EVERY
            .iter()
            .filter(|status| **status != TenantStatus::Active)
        {
            assert!(
                found(status).admit().is_err(),
                "{status} must not serve requests"
            );
        }
        assert!(found(TenantStatus::Active).admit().is_ok());
    }

    #[test]
    fn a_retired_tenant_is_never_flown_by_the_fleet() {
        // The bug this pins: the reconciler filtered `status != Degraded`,
        // which was right for three statuses and silently enrolled both
        // new ones. Flying an offboarding tenant reconnects to a database
        // mid-shred and flips it back to `active`; flying an archived one
        // reconnects to a database that no longer exists.
        assert!(TenantStatus::Active.is_reconciled());
        assert!(TenantStatus::Provisioning.is_reconciled());
        for retired in [
            TenantStatus::Degraded,
            TenantStatus::Offboarding,
            TenantStatus::Archived,
        ] {
            assert!(
                !retired.is_reconciled(),
                "{retired} must not be flown by boot reconciliation"
            );
        }
    }

    #[test]
    fn archived_is_the_only_terminal_status() {
        assert!(TenantStatus::Archived.is_terminal());
        for live in [
            TenantStatus::Active,
            TenantStatus::Provisioning,
            TenantStatus::Degraded,
            TenantStatus::Offboarding,
        ] {
            assert!(!live.is_terminal(), "{live} is a state, not an ending");
        }
    }

    #[test]
    fn a_terminal_status_never_serves_and_is_never_reconciled() {
        // The two properties together are what "retired" means: it cannot
        // answer a request and no boot brings it back. Asserting each
        // separately would let a future variant satisfy one and not the
        // other.
        for &status in EVERY {
            if status.is_terminal() {
                assert!(found(status).admit().is_err(), "{status} served");
                assert!(!status.is_reconciled(), "{status} was flown");
            }
        }
    }

    #[test]
    fn an_unknown_host_is_a_404_not_a_503() {
        // Distinguishable on purpose: 503 says "this tenant exists and is
        // unwell", 404 says "no such tenant". Collapsing them would tell
        // an operator the wrong thing during an incident.
        let problem = Resolution::Unknown.admit().expect_err("must not serve");
        assert_eq!(problem.slug, "unknown-tenant");
        assert_eq!(problem.status.as_u16(), 404);
    }

    #[test]
    fn a_status_this_binary_does_not_know_is_refused_not_guessed() {
        // `parse` is fail-closed, so a future version writing a status
        // this binary has never heard of reads as degraded and is
        // refused. The alternative - defaulting to active - would serve a
        // tenant on the strength of not understanding it.
        let unknown = TenantStatus::parse("quiesced");
        assert_eq!(unknown, TenantStatus::Degraded);
        assert!(found(unknown).admit().is_err());
    }

    #[test]
    fn serializes_as_the_registry_text_not_the_variant_name() {
        for &status in EVERY {
            let json = serde_json::to_string(&status).expect("a unit variant serializes");
            assert_eq!(
                json,
                format!("\"{}\"", status.as_str()),
                "the wire form is the registry's word, so a log field and a row agree"
            );
        }
    }

    #[test]
    fn an_unknown_status_reads_as_degraded() {
        assert_eq!(TenantStatus::parse("busy"), TenantStatus::Degraded);
        assert_eq!(TenantStatus::parse(""), TenantStatus::Degraded);
    }

    #[test]
    fn a_tenant_being_shredded_is_not_revived_by_a_reconciliation() {
        // The live one. `offboarding` means the export and key shred of
        // `docs/TENANT-ONBOARDING.md` §2 are under way; a reconciler
        // writing `active` would serve a database whose keys are being
        // destroyed underneath it. The fleet already skips it
        // (`is_reconciled`), and this is the second line, because the
        // reconciler is not the only writer.
        assert!(!TenantStatus::Offboarding.can_become(TenantStatus::Active));
        assert!(!TenantStatus::Offboarding.can_become(TenantStatus::Degraded));
        assert!(!TenantStatus::Offboarding.can_become(TenantStatus::Provisioning));
        // Forward is the only way out.
        assert!(TenantStatus::Offboarding.can_become(TenantStatus::Archived));
    }

    #[test]
    fn archiving_records_a_shred_that_happened() {
        // Only the offboarding that performed it ends there. Archiving
        // straight from `active` would record a destruction of keys that
        // nothing has destroyed.
        assert_eq!(
            TenantStatus::Archived.admits(),
            &[TenantStatus::Offboarding]
        );
        for &from in EVERY {
            assert_eq!(
                from.can_become(TenantStatus::Archived),
                from == TenantStatus::Offboarding,
                "{from} -> archived"
            );
        }
    }

    #[test]
    fn nothing_leaves_archived_including_a_write_of_archived() {
        // The row is the record that the database was dropped and the
        // keys destroyed. A record of an irreversible act is not
        // rewritten — not even with the same word, which would move its
        // timestamp and lose when the shred actually happened.
        for &to in EVERY {
            assert!(
                !TenantStatus::Archived.can_become(to),
                "archived -> {to} is not a move that exists"
            );
        }
    }

    #[test]
    fn a_status_written_twice_is_not_a_failure() {
        // A reconciler that runs twice writes `active` twice, and the
        // second must not be refused. Archived is the exception, and has
        // its own test saying why.
        for &status in EVERY {
            assert_eq!(
                status.can_become(status),
                status != TenantStatus::Archived,
                "{status} -> {status}"
            );
        }
    }

    #[test]
    fn a_tenant_abandoned_before_it_served_still_has_keys_to_shred() {
        // So retirement starts from `provisioning` too. Skipping straight
        // to `archived` would leave the keys alive and claim they were
        // destroyed.
        assert!(TenantStatus::Provisioning.can_become(TenantStatus::Offboarding));
        assert!(!TenantStatus::Provisioning.can_become(TenantStatus::Archived));
    }

    #[test]
    fn a_tenant_never_goes_back_to_provisioning() {
        // Re-provisioning an existing tenant is a new tenant: the old
        // one's keys are either live or destroyed, and neither is a
        // starting point.
        assert_eq!(
            TenantStatus::Provisioning.admits(),
            &[TenantStatus::Provisioning]
        );
    }

    #[test]
    fn the_rule_reads_the_same_from_both_ends() {
        // `admits` is the match and `can_become` asks it backwards. One
        // rule, so a change to either cannot disagree with the other.
        for &to in EVERY {
            for &from in EVERY {
                assert_eq!(
                    from.can_become(to),
                    to.admits().contains(&from),
                    "{from} -> {to}"
                );
            }
        }
    }

    #[test]
    fn a_status_the_fleet_flies_is_one_a_reconciliation_can_write() {
        // The two rules have to agree or a reconciled tenant is one whose
        // outcome the registry will not take: `is_reconciled` picks the
        // tenants the fleet boots, and reconciliation ends by writing
        // `active` or `degraded`.
        for &status in EVERY.iter().filter(|status| status.is_reconciled()) {
            assert!(
                status.can_become(TenantStatus::Active)
                    && status.can_become(TenantStatus::Degraded),
                "{status} is flown, and its own outcome would be refused"
            );
        }
    }
}
