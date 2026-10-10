//! [`TenantConn`]: the only handle a module has on a database, and one it
//! cannot have obtained for a tenant other than the request's
//! (TENANT-ROUTING.md §5, issue #32).
//!
//! It is fair to say this is `ports.db` with a private constructor and a
//! [`Tenant`] welded to it. That is the whole idea. `ModuleContext` holds
//! `Ports`, `Ports` holds one `Arc<dyn Database>`, and the context is
//! built once and captured in handler state — so the handle a module
//! reaches today is the same one for every request, whoever asked. The
//! isolation argument is not that modules are careful; it is that the
//! careless thing stops being expressible.
//!
//! Core cannot name a sqlx type — `adapter-postgres` never builds for
//! wasm — so this holds an `Arc<dyn Database>` that the resolution layer
//! already resolved, never a checkout.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::ports::Database;
use crate::problem::Problem;
use crate::tenant::{Tenancy, Tenant};

/// What the resolution layer puts in the request's extensions: the
/// tenant, and the handle on *its* database.
///
/// Not `pub`: a module cannot name it, so a module cannot insert one.
#[derive(Clone)]
pub(crate) struct ResolvedTenant {
    pub(crate) tenant: Tenant,
    pub(crate) tenancy: Tenancy,
    pub(crate) db: Arc<dyn Database>,
}

/// A database handle bound to the request's tenant.
///
/// Obtained only as an axum extractor, and only on a route the resolution
/// layer covers. There is no constructor:
///
/// ```compile_fail
/// use cratefield_core::TenantConn;
/// # use std::sync::Arc;
/// # fn db() -> Arc<dyn cratefield_core::Database> { unimplemented!() }
/// // No public constructor: a handler cannot build a handle for a
/// // tenant it was not given.
/// let _conn = TenantConn { tenant: todo!(), db: db() };
/// ```
///
/// Naming it is fine, which is what keeps a handler signature writable:
///
/// ```
/// use cratefield_core::TenantConn;
/// async fn handler(_db: TenantConn) {}
/// ```
#[derive(Clone)]
pub struct TenantConn {
    tenant: Tenant,
    tenancy: Tenancy,
    db: Arc<dyn Database>,
}

impl TenantConn {
    /// The tenant this handle belongs to.
    #[must_use]
    pub fn tenant(&self) -> &Tenant {
        &self.tenant
    }

    /// Which tenancy shape served this request: a registry resolved it,
    /// or the deployment has no registry and this host is the one
    /// implicit tenant.
    ///
    /// A routing fact, not a membership fact (#385):
    /// [`Tenancy::FromRegistry`] says the registry named this tenant for
    /// this host, and nothing about who the caller is to it. A rule that
    /// needs membership reads this to fail closed under
    /// [`Tenancy::FromRegistry`] — where "any verified caller" and "a
    /// member of this tenant" are different sets — and to serve under
    /// [`Tenancy::Sole`], where they are the same set.
    #[must_use]
    pub fn tenancy(&self) -> Tenancy {
        self.tenancy
    }
}

impl std::fmt::Debug for TenantConn {
    /// Names the tenant and never the handle. `Display for DbError`
    /// already scrubs a DSN out of a *message* (#135), but `Debug`
    /// derives raw, and a database handle has no business being printed
    /// at all — so this does not derive. The tenancy bit is shown: it is
    /// a routing fact with nothing secret in it, and it is the first
    /// question anyone debugging a refused request asks — did a registry
    /// even resolve this tenant (#385)?
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantConn")
            .field("tenant", &self.tenant.id())
            .field("tenancy", &self.tenancy)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl Database for TenantConn {
    async fn execute(&self, stmt: &crate::ports::Statement) -> Result<u64, crate::ports::DbError> {
        self.db.execute(stmt).await
    }

    async fn query(
        &self,
        stmt: &crate::ports::Statement,
    ) -> Result<crate::ports::Rows, crate::ports::DbError> {
        self.db.query(stmt).await
    }

    async fn batch_atomic(
        &self,
        stmts: &[crate::ports::Statement],
    ) -> Result<(), crate::ports::DbError> {
        self.db.batch_atomic(stmts).await
    }
}

impl<S> FromRequestParts<S> for TenantConn
where
    S: Send + Sync,
{
    type Rejection = Problem;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        // A 500 and not a 404: reaching a handler that asks for a
        // `TenantConn` on a route the resolution layer does not cover is
        // a wiring mistake in the harness, not something the caller did.
        // Answering 404 would make it look like the caller's problem and
        // hide it.
        std::future::ready(
            parts
                .extensions
                .get::<ResolvedTenant>()
                .map(|resolved| Self {
                    tenant: resolved.tenant.clone(),
                    tenancy: resolved.tenancy,
                    db: Arc::clone(&resolved.db),
                })
                .ok_or_else(Problem::internal),
        )
    }
}
