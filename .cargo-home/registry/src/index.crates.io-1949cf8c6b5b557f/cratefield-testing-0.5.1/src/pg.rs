//! The Postgres backing for the parity kit (issue #20): a throwaway
//! database per harness on the server named by `FZ_TEST_POSTGRES_URL`,
//! driven by a private tokio runtime, and a marshalling
//! [`Database`] wrapper so any executor can call it.
//!
//! sqlx (runtime-tokio) needs a tokio reactor, but module tests are
//! driven by pollster, plain test threads running cloned routers, and
//! deferred-event drains — none of which provide one. The wrapper
//! spawns every port call onto the kit's own runtime and blocks the
//! calling thread on a channel until it completes, which is correct
//! from any thread that is not a worker of that runtime.

use cratefield_adapter_postgres::testing::TempDb;
use cratefield_adapter_postgres::{Postgres, select_set};
use cratefield_core::{Database, DbError, Module, Statement};
use std::sync::Arc;

/// The throwaway database, its pool and the private runtime driving it.
/// The harness holds one; dropping the harness closes the pool, drops
/// the database and shuts the runtime down.
pub(crate) struct PgFixture {
    runtime: tokio::runtime::Runtime,
    pool: Arc<Postgres>,
    temp: TempDb,
}

impl PgFixture {
    /// Creates a throwaway database on the server at `base`, asserts it
    /// is Postgres 16, connects a pool and applies every module's
    /// migrations (the `postgres` set when shipped, else the `sqlite`
    /// set when it passes the portable lint — [`select_set`], the same
    /// selection `fz migrations apply` makes).
    ///
    /// # Errors
    ///
    /// A human-readable message when the runtime, the server or a
    /// migration fails. The throwaway database is dropped on failure.
    pub(crate) fn create(base: &str, modules: &[Arc<dyn Module>]) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|err| format!("cannot start the parity runtime: {err}"))?;
        let setup = runtime.block_on(async {
            let temp = TempDb::create(base, "parity")
                .await
                .ok_or_else(|| "cannot create a throwaway database".to_owned())?;
            temp.assert_postgres_16().await;
            let result = async {
                let db = Postgres::connect(&temp.url)
                    .await
                    .map_err(|err| err.to_string())?;
                for module in modules {
                    let set = select_set(&module.migrations())
                        .map_err(|reason| format!("module {}: {reason}", module.name()))?;
                    db.apply_migrations(module.name(), set)
                        .await
                        .map_err(|err| format!("migration for {}: {err}", module.name()))?;
                }
                Ok(db)
            }
            .await;
            match result {
                Ok(db) => Ok((temp, db)),
                Err(message) => {
                    temp.finish().await;
                    Err(message)
                }
            }
        });
        match setup {
            Ok((temp, pool)) => Ok(Self {
                runtime,
                pool: Arc::new(pool),
                temp,
            }),
            Err(message) => Err(message),
        }
    }

    /// The pool marshalled as the `Database` port the router and the
    /// tests share.
    pub(crate) fn database(&self) -> Arc<dyn Database> {
        Arc::new(MarshalledDatabase {
            handle: self.runtime.handle().clone(),
            inner: self.pool.clone(),
        })
    }

    /// Closes the pool, drops the throwaway database and lets the
    /// runtime shut down. Called from `TestHarness::drop` after the
    /// harness released its router and port handles.
    ///
    /// # Panics
    ///
    /// Panics when called from an async context on a tokio worker
    /// thread — parity kits are dropped on plain test threads.
    pub(crate) fn shutdown(self) {
        let Self {
            runtime,
            pool,
            temp,
        } = self;
        runtime.block_on(async move {
            let _ = pool.close().await;
            temp.finish().await;
        });
    }
}

/// A `Database` port that marshals every call onto the kit's runtime and
/// blocks the calling thread until it completes (see the module docs for
/// why). The connection string never travels through this type, and a
/// panicked sqlx call surfaces as [`DbError::Execute`] rather than
/// vanishing with the runtime task.
struct MarshalledDatabase {
    handle: tokio::runtime::Handle,
    inner: Arc<Postgres>,
}

impl MarshalledDatabase {
    fn marshal<T: Send + 'static>(
        &self,
        call: impl Future<Output = Result<T, DbError>> + Send + 'static,
    ) -> Result<T, DbError> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.handle.spawn(async move {
            let _ = tx.send(call.await);
        });
        match rx.recv() {
            Ok(result) => result,
            Err(_) => Err(DbError::Execute(
                "the parity runtime dropped a database call".to_owned(),
            )),
        }
    }
}

#[async_trait::async_trait]
impl Database for MarshalledDatabase {
    async fn execute(&self, stmt: &Statement) -> Result<u64, DbError> {
        let inner = self.inner.clone();
        let stmt = stmt.clone();
        self.marshal(async move { inner.execute(&stmt).await })
    }

    async fn query(&self, stmt: &Statement) -> Result<cratefield_core::Rows, DbError> {
        let inner = self.inner.clone();
        let stmt = stmt.clone();
        self.marshal(async move { inner.query(&stmt).await })
    }

    async fn batch_atomic(&self, stmts: &[Statement]) -> Result<(), DbError> {
        let inner = self.inner.clone();
        let stmts = stmts.to_vec();
        self.marshal(async move { inner.batch_atomic(&stmts).await })
    }
}

/// Applies every module's migrations twice, each round on a fresh
/// throwaway database — conformance check 3 for the Postgres leg.
///
/// # Errors
///
/// A human-readable message when a server or a migration fails.
pub(crate) fn migrations_apply_twice(modules: &[Arc<dyn Module>]) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|err| format!("cannot start the parity runtime: {err}"))?;
    runtime.block_on(async {
        for round in 1..=2 {
            let Some(temp) = TempDb::create(
                &cratefield_adapter_postgres::testing::base_url()
                    .expect("the caller checked FZ_TEST_POSTGRES_URL"),
                "conformance",
            )
            .await
            else {
                return Err("cannot create a throwaway database".to_owned());
            };
            let result: Result<(), String> = async {
                let db = Postgres::connect(&temp.url)
                    .await
                    .map_err(|err| err.to_string())?;
                for module in modules {
                    let set = select_set(&module.migrations())
                        .map_err(|reason| format!("module {}: {reason}", module.name()))?;
                    db.apply_migrations(module.name(), set)
                        .await
                        .map_err(|err| format!("round {round}, {}: {err}", module.name()))?;
                }
                Ok(())
            }
            .await;
            temp.finish().await;
            result?;
        }
        Ok(())
    })
}
