//! The database engines a [`TestHarness`](crate::TestHarness) can run a
//! module's tests against (issue #20): SQLite always, Postgres when the
//! environment names a server.

/// The database engine backing a test harness.
///
/// `Dialect::available()` is the parity entry point: a module suite
/// loops over it so one test definition runs against every dialect the
/// environment provides — SQLite in-memory always, Postgres 16 when
/// `FZ_TEST_POSTGRES_URL` names a server (CI's `postgres:16` service
/// container).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialect {
    /// A fresh in-memory SQLite database (the default; always
    /// available).
    Sqlite,
    /// A throwaway database on the Postgres server at `url`, created
    /// when the harness builds and dropped when it drops. Requires
    /// building `cratefield-testing` with the `postgres` feature.
    Postgres { url: String },
}

impl Dialect {
    /// The lowercase engine name, for test-output tagging (`sqlite`,
    /// `postgres`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Dialect::Sqlite => "sqlite",
            Dialect::Postgres { .. } => "postgres",
        }
    }

    /// The Postgres server URL from `FZ_TEST_POSTGRES_URL` (trimmed,
    /// non-empty), when the parity leg is available.
    #[must_use]
    pub fn postgres_url() -> Option<String> {
        std::env::var("FZ_TEST_POSTGRES_URL")
            .ok()
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty())
    }

    /// The dialects available in this environment: always SQLite;
    /// Postgres when `FZ_TEST_POSTGRES_URL` names a server. Prints one
    /// notice per process when the Postgres leg is unavailable, so a
    /// silently-skipped matrix leg is visible in the output.
    #[must_use]
    pub fn available() -> Vec<Self> {
        static NOTICED: std::sync::Once = std::sync::Once::new();
        let mut dialects = vec![Dialect::Sqlite];
        match Self::postgres_url() {
            Some(url) => dialects.push(Dialect::Postgres { url }),
            None => NOTICED.call_once(|| {
                eprintln!(
                    "NOTE: FZ_TEST_POSTGRES_URL is not set — the Postgres parity leg is \
                     skipped ({}); CI runs it against a postgres:16 service container",
                    crate::POSTGRES_SKIP_REASON
                );
            }),
        }
        dialects
    }
}
