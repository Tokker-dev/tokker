//! The write half of the tenant registry (issue #154): registering a
//! tenant, reading the registry back, and walking a tenant to its
//! erasure. The read half — turning a request's host into a tenant, and
//! a tenant into a database handle — is [`ResolveTenant`] and
//! [`TenantDatabases`]; those answer requests against the rows this
//! writes. One registry, two halves, because the two fail differently
//! and are trusted by different callers.
//!
//! Until now the only writers were `Postgres::register_tenant` and
//! `Postgres::set_tenant_status`, and their answers were a `bool` and a
//! string: a refused move and a failed write were the same `false`, and
//! re-registering an archived id was a `DbError` whose reason lived in
//! prose. That is the failure this shape prevents — a caller above the
//! adapter could not tell "the lifecycle says no" from "the database is
//! down" without parsing driver text, so it could not reliably refuse,
//! retry or page. `docs/TENANT-ONBOARDING.md` §4 names exactly this gap
//! and asks for the port; `docs/TENANT-PROMOTION.md` describes the
//! promotion side of the same state machine.
//!
//! The state machine itself is not reimplemented here.
//! [`TenantStatus::admits`] is the one place the rule lives, and a
//! second copy — in a `WHERE` clause, a fake, or a runbook script — is
//! how the copies drift. The runbook *order* is what this port owns:
//! [`TenantLifecycle::begin_erasure`] and
//! [`TenantLifecycle::complete_erasure`] encode the two registry writes
//! of `docs/TENANT-ONBOARDING.md` §2 so no caller has to know that
//! `offboarding` comes before the export or that `archived` is last.
//!
//! It is deliberately **not** a [`Port`](crate::ports::Port). Modules
//! must not write the registry: the registry is what decides which
//! tenant — and therefore which database — a module is allowed to touch,
//! and a module that could move its own row back out of `offboarding`
//! would resurrect a tenant whose keys are being destroyed. Offboarding
//! is an operator and CLI concern (`docs/TENANT-ONBOARDING.md` §2, §4);
//! the `fz tenant` command (#36) stands on this port when it arrives,
//! which is why the port is runtime-neutral and the Postgres impl is
//! not part of the module surface.

use crate::tenant::TenantStatus;

/// Why a registry write did not happen.
///
/// Carries the tenant id — the one thing every caller needs to know
/// which row failed — and never a DSN, mirroring [`crate::tenant::TenantDbError`]:
/// the DSN is a global secret (ADR 0008) that the registry exists to
/// *name*, not to hand out, and an error is exactly the thing most
/// likely to be logged verbatim. The one field that holds foreign text,
/// `Backend`'s `message`, goes through [`crate::logging::scrub_text`]
/// when rendered, because a driver message can quote a connect string —
/// the guarantee belongs to this type, not to whoever constructs it,
/// and construction is not something an enum's variants can control.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TenantLifecycleError {
    /// No registry row for this tenant.
    Unknown {
        /// Which tenant was asked about. Safe to log.
        tenant: String,
    },
    /// The move is not one [`TenantStatus::can_become`] allows.
    Refused {
        /// Which tenant was being moved. Safe to log.
        tenant: String,
        /// The status the row was in.
        from: TenantStatus,
        /// The status that was asked for.
        to: TenantStatus,
    },
    /// The registry write itself failed.
    Backend {
        /// Which tenant was being written. Safe to log.
        tenant: String,
        /// Why, scrubbed of secrets on the way out — a driver message
        /// can quote a DSN.
        message: String,
    },
}

impl std::fmt::Display for TenantLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { tenant } => {
                write!(f, "no registry row for tenant `{tenant}`")
            }
            Self::Refused { tenant, from, to } => {
                write!(f, "tenant `{tenant}` cannot move from {from} to {to}")
            }
            Self::Backend { tenant, message } => {
                // Scrub at the sink: the variant's fields are public, so
                // the type cannot control what it is constructed with,
                // and `scrub_text` is idempotent for the paths that
                // scrubbed at construction.
                let message = crate::logging::scrub_text(message);
                write!(f, "tenant `{tenant}`'s registry write failed: {message}")
            }
        }
    }
}

impl std::error::Error for TenantLifecycleError {}

/// One row of the registry, as this port reports it.
///
/// Deliberately omits the DSN, unlike the adapter's `TenantRecord`
/// (which carries it, because reconciliation connects with it): a
/// runtime-neutral listing is the thing most likely to be logged,
/// rendered into a dashboard, or printed by the `fz tenant` command
/// this port exists for. ADR 0008 makes a tenant DSN a global secret
/// the registry names but never hands out, so a type that does not
/// contain the string is a leak the compiler rules out — a comment on a
/// field that does is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSummary {
    /// The tenant id, e.g. `factory0`.
    pub tenant: String,
    /// The status the registry last recorded.
    pub status: TenantStatus,
}

/// One step of a tenant's erasure, in the order
/// `docs/TENANT-ONBOARDING.md` §2 gives it.
///
/// The order is the contract: the export happens while the data is
/// still readable, the crypto-shred happens *before* the drop so any
/// copy of the ciphertext — including provider backups that outlive the
/// drop — stays unreadable, and the drop happens after the retention
/// hold. Two of the steps are registry writes this port performs; the
/// rest are a person's, which [`ErasureStep::is_operator`] states so a
/// runbook can list only the steps it has to wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErasureStep {
    /// §2 row 1: set status `offboarding`; the tenant stops serving.
    StopServing,
    /// §2 row 2: final export with `fz data export`.
    ExportData,
    /// §2 row 3: crypto-shred — destroy the tenant's data keys
    /// (`docs/KEY-ROTATION.md`).
    ShredDataKeys,
    /// §2 row 4: retention hold for the agreed period.
    HoldRetention,
    /// §2 row 5: drop the database after the hold.
    DropDatabase,
    /// §2 row 6: set status `archived`; the id can never be registered
    /// again.
    Archive,
}

impl ErasureStep {
    /// The runbook's lowercase name for the step.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopServing => "stop-serving",
            Self::ExportData => "export-data",
            Self::ShredDataKeys => "shred-data-keys",
            Self::HoldRetention => "hold-retention",
            Self::DropDatabase => "drop-database",
            Self::Archive => "archive",
        }
    }

    /// Whether the step is a person's rather than this port's.
    ///
    /// `docs/TENANT-ONBOARDING.md` §2 marks every step `harness` or
    /// `operator`, where operator means a person's step — it touches a
    /// cloud console or holds a credential, and the harness cannot do it
    /// (§1's definition of the mark). The two `harness` rows are the
    /// registry writes this port performs; everything a console,
    /// clipboard or calendar is involved in belongs to an operator.
    #[must_use]
    pub const fn is_operator(self) -> bool {
        match self {
            // §2 row 1, "harness, no CLI (§4)": this port's
            // `begin_erasure` performs it — as row 6, also "harness, no
            // CLI (§4)", is performed by `complete_erasure`.
            Self::StopServing | Self::Archive => false,
            // §2 rows 2–5 are the "operator" steps, each a person's:
            // `fz data export` is run by one (row 2); destroying data
            // keys is a person's step (`docs/KEY-ROTATION.md`, row 3);
            // the hold is a person's calendar entry, and nothing is
            // dropped during it (row 4); the drop happens in the
            // provider console, and its evidence is the console itself
            // (row 5).
            Self::ExportData | Self::ShredDataKeys | Self::HoldRetention | Self::DropDatabase => {
                true
            }
        }
    }
}

impl std::fmt::Display for ErasureStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The erasure steps still outstanding for a tenant in `status`.
///
/// This is the runbook's position, in one place: a caller that stops a
/// tenant and needs to know what it is now waiting for asks here
/// instead of keeping its own copy of §2's table. A tenant still serving
/// has all six steps ahead of it; one in `offboarding` has had the stop
/// performed for it and starts at the export; an archived tenant has
/// nothing left, because `archived` records that the drop and the shred
/// both happened.
///
/// # The match is the exhaustiveness argument
///
/// [`TenantStatus`] is `#[non_exhaustive]` so downstream crates can keep
/// matching it as variants are added. This match lives in the same
/// crate as the enum, so that attribute does not weaken it here: a new
/// status cannot compile until someone places it in this match and says
/// which erasure steps it leaves outstanding — the same idiom
/// [`TenantStatus::is_reconciled`] established, applied to the runbook
/// instead of the fleet.
#[must_use]
pub fn remaining_erasure(status: TenantStatus) -> &'static [ErasureStep] {
    match status {
        // Serving, trying to serve, or unwell — §2 row 1 has not run,
        // so every step is outstanding.
        TenantStatus::Active | TenantStatus::Provisioning | TenantStatus::Degraded => &[
            ErasureStep::StopServing,
            ErasureStep::ExportData,
            ErasureStep::ShredDataKeys,
            ErasureStep::HoldRetention,
            ErasureStep::DropDatabase,
            ErasureStep::Archive,
        ],
        // The stop happened (`begin_erasure` performed §2 row 1); the
        // export is the first step still to do.
        TenantStatus::Offboarding => &[
            ErasureStep::ExportData,
            ErasureStep::ShredDataKeys,
            ErasureStep::HoldRetention,
            ErasureStep::DropDatabase,
            ErasureStep::Archive,
        ],
        // Terminal: the shred and the drop happened. §2 has no further
        // row for this tenant.
        TenantStatus::Archived => &[],
    }
}

/// The write half of the tenant registry: create a tenant, read the
/// registry, and walk a tenant through its erasure.
///
/// Implemented by the runtime's registry adapter — on Postgres, against
/// the `harness_tenants` table — and by test doubles; never by a
/// module, which has no business writing the row that decides what it
/// may touch. The legal moves are [`TenantStatus`]'s alone: an
/// implementation enforces [`TenantStatus::admits`] and reports a
/// refusal through [`TenantLifecycleError::Refused`], it does not have
/// an opinion about the lifecycle.
#[async_trait::async_trait]
pub trait TenantLifecycle: Send + Sync {
    /// Registers a tenant: the row is inserted, or an existing
    /// non-archived row is re-pointed at `dsn`, and the status lands on
    /// [`TenantStatus::Provisioning`] — the next reconciliation is what
    /// promotes it.
    ///
    /// # Errors
    ///
    /// [`TenantLifecycleError::Refused`] with `from` =
    /// [`TenantStatus::Archived`] when the id was archived: archiving
    /// destroyed its data keys, so a resurrected row would name a tenant
    /// nothing can reconstitute. [`TenantLifecycleError::Backend`] when
    /// the write itself fails. Never a DSN in either case.
    async fn create(&self, tenant: &str, dsn: &str) -> Result<(), TenantLifecycleError>;

    /// The status the registry records for `tenant`.
    ///
    /// # Errors
    ///
    /// [`TenantLifecycleError::Unknown`] when there is no row;
    /// [`TenantLifecycleError::Backend`] when the read fails.
    async fn status(&self, tenant: &str) -> Result<TenantStatus, TenantLifecycleError>;

    /// Every row of the registry, as [`TenantSummary`]s — no DSNs.
    ///
    /// # Errors
    ///
    /// [`TenantLifecycleError::Backend`] when the read fails.
    async fn tenants(&self) -> Result<Vec<TenantSummary>, TenantLifecycleError>;

    /// Moves the tenant's status, if [`TenantStatus::can_become`]
    /// allows the move.
    ///
    /// # Errors
    ///
    /// [`TenantLifecycleError::Unknown`] when there is no row;
    /// [`TenantLifecycleError::Refused`] naming the row's actual status
    /// when the move is not allowed;
    /// [`TenantLifecycleError::Backend`] when the write fails.
    async fn set_status(
        &self,
        tenant: &str,
        next: TenantStatus,
    ) -> Result<(), TenantLifecycleError>;

    /// Begins an erasure: moves the tenant to
    /// [`TenantStatus::Offboarding`] and returns the steps of
    /// `docs/TENANT-ONBOARDING.md` §2 still outstanding, in order, so
    /// the caller can work down the list without keeping its own copy
    /// of the table.
    ///
    /// This stops the tenant serving **immediately**, and that is the
    /// point rather than a side effect: `Resolution::admit` answers an
    /// `offboarding` row as a 404 unknown-tenant — indistinguishable
    /// from a host that never existed — so the moment the row moves, the
    /// fleet stops flying the tenant and its hosts go dark, before
    /// anyone starts destroying its keys.
    ///
    /// # Errors
    ///
    /// [`TenantLifecycleError::Unknown`] when there is no row;
    /// [`TenantLifecycleError::Refused`] when the tenant is archived
    /// (there is nothing left to erase) or otherwise unable to move;
    /// [`TenantLifecycleError::Backend`] when the write fails.
    async fn begin_erasure(&self, tenant: &str) -> Result<Vec<ErasureStep>, TenantLifecycleError> {
        self.set_status(tenant, TenantStatus::Offboarding).await?;
        Ok(remaining_erasure(TenantStatus::Offboarding).to_vec())
    }

    /// Completes an erasure: records [`TenantStatus::Archived`].
    ///
    /// Irreversible by design: `Archived` is terminal
    /// ([`TenantStatus::is_terminal`], and it admits nothing, itself
    /// included), because the row is the record that the database was
    /// dropped and the data keys destroyed — a record of an irreversible
    /// act is not rewritten, and the id can never be registered again.
    /// Call it only after the operator steps of §2 are done.
    ///
    /// # Errors
    ///
    /// [`TenantLifecycleError::Unknown`] when there is no row;
    /// [`TenantLifecycleError::Refused`] naming the row's actual status
    /// when the tenant is not in [`TenantStatus::Offboarding`] — only
    /// the offboarding that performed the shred ends here;
    /// [`TenantLifecycleError::Backend`] when the write fails.
    async fn complete_erasure(&self, tenant: &str) -> Result<(), TenantLifecycleError> {
        self.set_status(tenant, TenantStatus::Archived).await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ErasureStep, TenantLifecycle, TenantLifecycleError, TenantSummary, remaining_erasure,
    };
    use crate::tenant::TenantStatus;

    /// Declares [`EVERY`] and, from the same list, a match that has to
    /// be exhaustive. The local twin of `tenant.rs`'s `statuses!`, which
    /// is private to that module's test block and cannot be imported.
    macro_rules! statuses {
        ($($variant:ident),+ $(,)?) => {
            const EVERY: &[TenantStatus] = &[$(TenantStatus::$variant),+];

            #[expect(dead_code, reason = "its only job is to be exhaustive")]
            fn exhaustive(status: TenantStatus) {
                match status {
                    $(TenantStatus::$variant => {}),+
                }
            }
        };
    }

    statuses!(Provisioning, Active, Degraded, Offboarding, Archived);

    /// A row of the fake registry. The DSN is kept only so the tests can
    /// prove the listing drops it.
    struct FakeRow {
        tenant: String,
        status: TenantStatus,
        dsn: String,
    }

    /// An in-memory registry with the same shape the Postgres adapter
    /// implements: an upsert that refuses archived ids, and status
    /// writes gated on `TenantStatus::can_become`.
    struct FakeLifecycle {
        #[expect(
            clippy::disallowed_types,
            reason = "a test double needs interior mutability behind the trait's \
                      `Sync` bound, and lock poisoning is irrelevant here: a \
                      poisoned lock means a test has already failed"
        )]
        rows: std::sync::Mutex<Vec<FakeRow>>,
    }

    impl FakeLifecycle {
        #[expect(
            clippy::disallowed_types,
            reason = "the same double's constructor names the same lock the \
                      field above already carries the expect for: interior \
                      mutability behind the trait's `Sync` bound, with lock \
                      poisoning irrelevant to a test that has already failed"
        )]
        fn new() -> Self {
            Self {
                rows: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    const DSN: &str = "postgres://acme:s3cret@db.internal:5432/acme";

    #[async_trait::async_trait]
    impl TenantLifecycle for FakeLifecycle {
        async fn create(&self, tenant: &str, dsn: &str) -> Result<(), TenantLifecycleError> {
            let mut rows = self
                .rows
                .lock()
                .expect("a poisoned lock means a test has already failed");
            match rows.iter_mut().find(|row| row.tenant == tenant) {
                // The upsert the Postgres adapter performs: re-point the
                // DSN and reset to provisioning — unless archived,
                // which refuses.
                Some(row) if row.status != TenantStatus::Archived => {
                    row.status = TenantStatus::Provisioning;
                    row.dsn = dsn.to_owned();
                    Ok(())
                }
                Some(row) => {
                    let from = row.status;
                    Err(TenantLifecycleError::Refused {
                        tenant: row.tenant.clone(),
                        from,
                        to: TenantStatus::Provisioning,
                    })
                }
                None => {
                    rows.push(FakeRow {
                        tenant: tenant.to_owned(),
                        status: TenantStatus::Provisioning,
                        dsn: dsn.to_owned(),
                    });
                    Ok(())
                }
            }
        }

        async fn status(&self, tenant: &str) -> Result<TenantStatus, TenantLifecycleError> {
            let rows = self
                .rows
                .lock()
                .expect("a poisoned lock means a test has already failed");
            match rows.iter().find(|row| row.tenant == tenant) {
                Some(row) => Ok(row.status),
                None => Err(TenantLifecycleError::Unknown {
                    tenant: tenant.to_owned(),
                }),
            }
        }

        async fn tenants(&self) -> Result<Vec<TenantSummary>, TenantLifecycleError> {
            let rows = self
                .rows
                .lock()
                .expect("a poisoned lock means a test has already failed");
            let mut summaries: Vec<TenantSummary> = rows
                .iter()
                .map(|row| TenantSummary {
                    tenant: row.tenant.clone(),
                    status: row.status,
                })
                .collect();
            summaries.sort_by(|a, b| a.tenant.cmp(&b.tenant));
            Ok(summaries)
        }

        async fn set_status(
            &self,
            tenant: &str,
            next: TenantStatus,
        ) -> Result<(), TenantLifecycleError> {
            let mut rows = self
                .rows
                .lock()
                .expect("a poisoned lock means a test has already failed");
            match rows.iter_mut().find(|row| row.tenant == tenant) {
                Some(row) if row.status.can_become(next) => {
                    row.status = next;
                    Ok(())
                }
                Some(row) => {
                    let from = row.status;
                    Err(TenantLifecycleError::Refused {
                        tenant: row.tenant.clone(),
                        from,
                        to: next,
                    })
                }
                None => Err(TenantLifecycleError::Unknown {
                    tenant: tenant.to_owned(),
                }),
            }
        }
    }

    #[pollster::test]
    async fn a_tenant_walks_the_whole_lifecycle_through_the_port() {
        let lifecycle = FakeLifecycle::new();
        lifecycle
            .create("acme", DSN)
            .await
            .expect("a fresh id registers");
        assert_eq!(
            lifecycle.status("acme").await.expect("registered"),
            TenantStatus::Provisioning,
            "a tenant registers as provisioning"
        );
        lifecycle
            .set_status("acme", TenantStatus::Active)
            .await
            .expect("provisioning becomes active once reconciliation succeeds");

        let steps = lifecycle
            .begin_erasure("acme")
            .await
            .expect("a serving tenant can be retired");
        assert_eq!(
            lifecycle.status("acme").await.expect("registered"),
            TenantStatus::Offboarding,
            "begin_erasure moved the row to offboarding"
        );
        assert_eq!(
            steps,
            remaining_erasure(TenantStatus::Offboarding).to_vec(),
            "the returned steps are the ones §2 still has outstanding"
        );
        assert_eq!(
            steps.first(),
            Some(&ErasureStep::ExportData),
            "the stop already happened, so the export is the first step left"
        );

        lifecycle
            .complete_erasure("acme")
            .await
            .expect("archived is the only way out of offboarding");
        assert_eq!(
            lifecycle.status("acme").await.expect("registered"),
            TenantStatus::Archived,
        );
    }

    #[pollster::test]
    async fn every_revival_out_of_offboarding_is_a_typed_refusal() {
        // Offboarding admits only itself and archived. Every other
        // target is the refusal the port exists to type: `from` is the
        // row's real status, `to` is what was asked for.
        let lifecycle = FakeLifecycle::new();
        lifecycle.create("acme", DSN).await.expect("registers");
        lifecycle
            .begin_erasure("acme")
            .await
            .expect("retirement starts");

        for &revival in EVERY {
            let outcome = lifecycle.set_status("acme", revival).await;
            if matches!(revival, TenantStatus::Offboarding | TenantStatus::Archived) {
                assert!(
                    outcome.is_ok(),
                    "{revival} is a legal way out of offboarding"
                );
            } else {
                assert_eq!(
                    outcome,
                    Err(TenantLifecycleError::Refused {
                        tenant: "acme".to_owned(),
                        from: TenantStatus::Offboarding,
                        to: revival,
                    }),
                    "{revival} must be refused with the move that was asked for"
                );
            }
        }
    }

    #[pollster::test]
    async fn nothing_leaves_archived_through_the_port() {
        let lifecycle = FakeLifecycle::new();
        lifecycle.create("acme", DSN).await.expect("registers");
        lifecycle
            .begin_erasure("acme")
            .await
            .expect("retirement starts");
        lifecycle.complete_erasure("acme").await.expect("archives");

        for &to in EVERY {
            assert_eq!(
                lifecycle.set_status("acme", to).await,
                Err(TenantLifecycleError::Refused {
                    tenant: "acme".to_owned(),
                    from: TenantStatus::Archived,
                    to,
                }),
                "archived -> {to} is not a move that exists, not even a repeat"
            );
        }
        // Re-creating the id is refused the same way: the record of a
        // destroyed tenant is not overwritten.
        assert_eq!(
            lifecycle.create("acme", DSN).await,
            Err(TenantLifecycleError::Refused {
                tenant: "acme".to_owned(),
                from: TenantStatus::Archived,
                to: TenantStatus::Provisioning,
            }),
            "an archived id must not re-register"
        );
        assert_eq!(
            lifecycle.status("acme").await.expect("registered"),
            TenantStatus::Archived,
            "the row survived every attempt unmoved"
        );
    }

    #[pollster::test]
    async fn an_absent_tenant_is_unknown_not_backend() {
        let lifecycle = FakeLifecycle::new();
        assert_eq!(
            lifecycle.status("ghost").await,
            Err(TenantLifecycleError::Unknown {
                tenant: "ghost".to_owned(),
            }),
            "a tenant with no row is unknown"
        );
        assert_eq!(
            lifecycle.set_status("ghost", TenantStatus::Active).await,
            Err(TenantLifecycleError::Unknown {
                tenant: "ghost".to_owned(),
            }),
            "moving a tenant with no row is unknown, not a refusal"
        );
        // The provided methods stand on `set_status`, so they answer the
        // same way and not with something new.
        assert!(
            matches!(
                lifecycle.begin_erasure("ghost").await,
                Err(TenantLifecycleError::Unknown { .. })
            ),
            "begin_erasure on an absent tenant is unknown"
        );
        assert!(
            matches!(
                lifecycle.complete_erasure("ghost").await,
                Err(TenantLifecycleError::Unknown { .. })
            ),
            "complete_erasure on an absent tenant is unknown"
        );
    }

    #[pollster::test]
    async fn a_listing_through_the_port_never_carries_a_dsn() {
        let lifecycle = FakeLifecycle::new();
        lifecycle.create("acme", DSN).await.expect("registers");
        lifecycle.create("zephyr", DSN).await.expect("registers");

        let summaries: Vec<TenantSummary> = lifecycle.tenants().await.expect("readable");
        assert_eq!(summaries.len(), 2, "every row is listed");
        assert_eq!(
            summaries
                .iter()
                .map(|summary| (summary.tenant.as_str(), summary.status))
                .collect::<Vec<_>>(),
            vec![
                ("acme", TenantStatus::Provisioning),
                ("zephyr", TenantStatus::Provisioning),
            ],
            "the listing carries the tenant and its status"
        );

        // The type has no field a DSN could ride in; this asserts the
        // fake's stored DSN does not survive into the formatted listing
        // either — the rendering is what gets logged.
        let rendered = format!("{summaries:?}");
        assert!(
            !rendered.contains("postgres://"),
            "a listing leaked a connect string: {rendered}"
        );
        assert!(
            !rendered.contains("s3cret"),
            "a listing leaked the DSN's secret: {rendered}"
        );
    }

    #[test]
    fn the_remaining_erasure_of_a_status_is_its_runbook_position() {
        assert!(
            remaining_erasure(TenantStatus::Archived).is_empty(),
            "an archived tenant has no erasure left"
        );
        assert_eq!(
            remaining_erasure(TenantStatus::Active).first(),
            Some(&ErasureStep::StopServing),
            "a serving tenant has not even been stopped"
        );
        assert_eq!(
            remaining_erasure(TenantStatus::Active),
            remaining_erasure(TenantStatus::Provisioning),
            "every status that still serves has the whole runbook ahead of it"
        );
        assert_eq!(
            remaining_erasure(TenantStatus::Offboarding).first(),
            Some(&ErasureStep::ExportData),
            "offboarding means the stop was performed for it"
        );
        // §2's order, stated once: the export while the data is readable,
        // the shred before the drop, the drop after the hold.
        assert_eq!(
            remaining_erasure(TenantStatus::Offboarding),
            &[
                ErasureStep::ExportData,
                ErasureStep::ShredDataKeys,
                ErasureStep::HoldRetention,
                ErasureStep::DropDatabase,
                ErasureStep::Archive,
            ]
        );
    }

    #[test]
    fn a_backend_message_is_scrubbed_on_its_way_out() {
        // `scrub_text` rewrites URL userinfo to `scheme://[redacted]@host`
        // and cuts the query, so the rendered error carries neither the
        // password nor the parameters — but keeps the host, which is what
        // makes a connect failure diagnosable at all.
        let error = TenantLifecycleError::Backend {
            tenant: "acme".to_owned(),
            message: "error connecting to postgres://venture:sup3r-s3cret@db.internal:5432/app?\
                      sslmode=require"
                .to_owned(),
        };
        let rendered = error.to_string();
        assert!(
            !rendered.contains("sup3r-s3cret"),
            "the password reached the rendered error: {rendered}"
        );
        assert!(
            !rendered.contains("sslmode"),
            "the query reached the rendered error: {rendered}"
        );
        assert!(
            rendered.contains("postgres://[redacted]@db.internal:5432/app?[redacted]"),
            "what survives is the scrubbed host and path: {rendered}"
        );
        assert!(
            rendered.contains("acme"),
            "the error still names its tenant: {rendered}"
        );
    }
}
