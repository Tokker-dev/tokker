//! API-key auth for developer-facing APIs (issue #532): hashed bearer
//! keys with a public prefix, per-key scopes and a test/live mode.
//!
//! A key is `{namespace}_{mode}_{id}_{secret}`, e.g.
//! `pos_live_3f9a0c1d2e4b5a6c_<64 hex>`. The **prefix** is public —
//! stored in the clear and the lookup key; the **secret** (32 random
//! bytes) is shown once at issue time and never stored: the row holds
//! SHA-256 over the whole token, re-derived and compared in constant
//! time at verify. SHA-256 rather than ADR 0200's argon2id is
//! deliberate: 256 random bits leave nothing for a slow search to find,
//! and argon2 per request would burn the Workers CPU budget on every
//! call. This is **auth, not routing** (`docs/TENANT-ROUTING.md` §3
//! keeps rejecting API keys for the host→tenant decision — the
//! bootstrap is circular): a key identifies a subject *inside* the
//! already-selected tenant's database.
//!
//! ```ignore
//! let keys = ApiKeys::new(db, clock, Arc::new(OsRandom), "api_keys");
//! let issued = keys.issue("pos", "acct_123", &["read", "write"], ApiKeyMode::Live).await?;
//! // `issued.token` is returned exactly once; `issued.prefix` is public.
//! // Per request, on a route declared `RoutePolicy::ApiKey`:
//! let principal = require_api_key(&keys, &headers, "read").await?;
//! // Per-key rate limiting slots into the issue #538 limiter:
//! check_rate_limit(limiter.as_ref(), &[principal.rate_limit_key()],
//!     RateLimitFailure::FailClosed).await;
//! ```

use std::fmt::Write as _;
use std::sync::Arc;

use axum::http::HeaderMap;
use sea_query::{Alias, Expr, Query};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::admin::{bearer_token, constant_time_eq};
use crate::ports::{Clock, Database, DbError, Row, Statement};
use crate::problem::Problem;
use crate::problems::SLUGS;

/// Random bytes in the id part of a generated key.
const ID_BYTES: usize = 8;
/// Random bytes in the secret part: 256 bits, the reason a slow KDF
/// would buy nothing (see the module docs).
const SECRET_BYTES: usize = 32;
/// The longest namespace an app may choose.
const MAX_NAMESPACE_CHARS: usize = 32;
/// How stale `last_used_at` may get before a verify rewrites it.
const TOUCH_WINDOW_SECONDS: i64 = 60;

/// The columns every insert fills.
const KEY_COLUMNS: [&str; 7] = [
    "prefix",
    "secret_hash",
    "namespace",
    "subject",
    "scopes",
    "mode",
    "created_at",
];

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

/// Lowercase hex, the encoding of every key part this module emits.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// RFC 3339 for a clock reading; an unformattable instant fails the
/// operation rather than storing an empty stamp.
fn stamp(at: OffsetDateTime) -> Result<String, DbError> {
    at.format(&Rfc3339)
        .map_err(|err| DbError::Execute(format!("clock reading is not RFC 3339: {err}")))
}

/// A NOT NULL text column of `row`; absent or unreadable is a schema
/// mismatch — an error, never an empty hash that would silently 401.
fn required(row: &Row, name: &str) -> Result<String, DbError> {
    row.get::<Option<String>>(name)
        .flatten()
        .ok_or_else(|| DbError::Query(format!("api key row is missing its `{name}` column")))
}

/// Whether `s` is a valid namespace: `[a-z0-9]+`, at most
/// [`MAX_NAMESPACE_CHARS`] of it.
fn is_valid_namespace(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAMESPACE_CHARS
        && s.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The CSPRNG [`ApiKeys`] draws key material from. Injected like every
/// environment effect (ADR 0002) — core carries no entropy source, and
/// the deployment (or a test) supplies its own. An app crate declaring
/// `getrandom` (the workspace-wide leaf pattern) writes:
///
/// ```ignore
/// struct OsRandom;
/// impl cratefield_core::RandomBytes for OsRandom {
///     fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError> {
///         getrandom::fill(dest).map_err(|err| RandomError(err.to_string()))
///     }
/// }
/// ```
pub trait RandomBytes: Send + Sync {
    /// Fills `dest` with cryptographically random bytes.
    ///
    /// # Errors
    ///
    /// [`RandomError`] when the platform entropy source fails.
    fn fill(&self, dest: &mut [u8]) -> Result<(), RandomError>;
}

/// Why an entropy draw failed: no key material existed yet, so the
/// message carries only the platform's own words.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("entropy source failed: {0}")]
pub struct RandomError(String);

/// Why a key operation failed; in every variant, nothing was written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApiKeyError {
    /// The namespace failed the `[a-z0-9]+` check.
    #[error("invalid key namespace {0:?}: expected [a-z0-9]+")]
    Namespace(String),
    /// A scope was empty or contained whitespace, which the
    /// space-separated storage could not round-trip.
    #[error("invalid scope {0:?}: empty, or containing whitespace")]
    Scope(String),
    /// The prefix named no active key (unknown, or already revoked).
    #[error("no active key with prefix {0:?}")]
    UnknownKey(String),
    /// The entropy source failed.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// A database statement (or an unformattable clock reading) failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Which environment a key belongs to: sandbox or production money.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyMode {
    /// A sandbox key: same shape, separate records.
    Test,
    /// A production key.
    Live,
}

impl ApiKeyMode {
    /// The token spelling of the mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Live => "live",
        }
    }

    /// Parses the token spelling; anything else is a malformed token.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "test" => Some(Self::Test),
            "live" => Some(Self::Live),
            _ => None,
        }
    }
}

/// A newly minted key: `token` is the only time the plaintext exists —
/// show it once, store nothing; `prefix` is public and safe to display.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedKey {
    /// The full plaintext token: `{namespace}_{mode}_{id}_{secret}`.
    pub token: String,
    /// The public prefix `{namespace}_{mode}_{id}`, exactly as stored.
    pub prefix: String,
}

impl std::fmt::Debug for IssuedKey {
    /// The plaintext token never reaches a log line (house rule, as
    /// `KeyRing` and `HmacSigner` in `crate::signer`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedKey")
            .field("prefix", &self.prefix)
            .field("token", &"[redacted]")
            .finish()
    }
}

/// A verified key's answer to "who is calling, and what may they do?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyPrincipal {
    /// The public prefix the request presented.
    pub prefix: String,
    /// The app-chosen namespace the key was issued under.
    pub namespace: String,
    /// The opaque subject (tenant/account id) the key speaks for.
    pub subject: String,
    /// What the key may do; the gate checks one of these per request.
    pub scopes: Vec<String>,
    /// Which environment the key belongs to.
    pub mode: ApiKeyMode,
}

impl ApiKeyPrincipal {
    /// Whether the key carries `scope`; scopes are exact-match strings.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| granted == scope)
    }

    /// The per-key rate-limit key `apikey:<prefix>`: a
    /// [`RateLimitPolicy`](crate::RateLimiter) arm matching that prefix
    /// sets the key's budget, the way `rate_limit_keys`' `ip:`/`email:`
    /// keys slot into the shared limiter (issue #538).
    #[must_use]
    pub fn rate_limit_key(&self) -> String {
        format!("apikey:{}", self.prefix)
    }

    /// The [`Subject`](crate::ports::Subject) this key speaks for, for
    /// code shared with the session auth port; the session id is the
    /// prefix, so instant revocation already exists — revoke the key.
    #[must_use]
    pub fn to_subject(&self) -> crate::ports::Subject {
        crate::ports::Subject::new(self.subject.clone()).session(self.prefix.clone())
    }
}

/// A token that parsed. Nothing here is trustworthy until the hash
/// compares; the prefix is only a lookup key.
struct ParsedKey {
    prefix: String,
    namespace: String,
    mode: ApiKeyMode,
}

/// Parses a public prefix `{namespace}_{mode}_{id}` into namespace and
/// mode, checking every shape before the database is touched.
fn parse_prefix(prefix: &str) -> Option<(String, ApiKeyMode)> {
    let mut parts = prefix.split('_');
    let namespace = parts.next()?;
    let mode = parts.next()?;
    let id = parts.next()?;
    if parts.next().is_some()
        || !is_valid_namespace(namespace)
        || id.len() != ID_BYTES * 2
        || !is_lower_hex(id)
    {
        return None;
    }
    Some((namespace.to_owned(), ApiKeyMode::parse(mode)?))
}

impl ParsedKey {
    /// Parses `{namespace}_{mode}_{id}_{secret}` strictly: a malformed
    /// token never costs a query.
    fn parse(token: &str) -> Option<Self> {
        let (prefix, secret) = token.rsplit_once('_')?;
        if secret.len() != SECRET_BYTES * 2 || !is_lower_hex(secret) {
            return None;
        }
        let (namespace, mode) = parse_prefix(prefix)?;
        Some(Self {
            prefix: prefix.to_owned(),
            namespace,
            mode,
        })
    }
}

/// The stored half of an API key: everything but the secret.
struct KeyRow {
    secret_hash: String,
    subject: String,
    scopes: String,
    last_used_at: Option<String>,
}

/// A store of API keys over the [`Database`] port; the owning app ships
/// [`create_table_sql`](Self::create_table_sql) as a migration.
/// Timestamps are RFC 3339 `TEXT` from the [`Clock`] port, the house
/// shape (`cratefield_core::SendCooldown` documents why lexicographic
/// order on that format is chronological order).
#[derive(Clone)]
pub struct ApiKeys {
    db: Arc<dyn Database>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn RandomBytes>,
    table: String,
}

impl ApiKeys {
    /// A key store over `db`, timed by `clock`, keyed by `rng`.
    #[must_use]
    pub fn new(
        db: Arc<dyn Database>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn RandomBytes>,
        table: impl Into<String>,
    ) -> Self {
        Self {
            db,
            clock,
            rng,
            table: table.into(),
        }
    }

    /// The portable DDL for the key table (SQLite/D1/Postgres, ADR 0004),
    /// shipped as a forward-only migration. Only the hash and the public
    /// prefix are ever stored.
    #[must_use]
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n    \
             prefix TEXT PRIMARY KEY,\n    \
             secret_hash TEXT NOT NULL,\n    \
             namespace TEXT NOT NULL,\n    \
             subject TEXT NOT NULL,\n    \
             scopes TEXT NOT NULL,\n    \
             mode TEXT NOT NULL,\n    \
             created_at TEXT NOT NULL,\n    \
             last_used_at TEXT,\n    \
             revoked_at TEXT\n);",
            table = self.table
        )
    }

    /// Draws `ID_BYTES + SECRET_BYTES` fresh bytes and formats the id
    /// and secret parts.
    fn generate(&self) -> Result<(String, String), RandomError> {
        let mut bytes = [0u8; ID_BYTES + SECRET_BYTES];
        self.rng.fill(&mut bytes)?;
        let (id, secret) = bytes.split_at(ID_BYTES);
        Ok((hex(id), hex(secret)))
    }

    /// Mints a key for `subject` with `scopes`, and stores its hash; the
    /// returned [`IssuedKey::token`] is shown exactly once.
    ///
    /// # Errors
    ///
    /// [`ApiKeyError::Namespace`] or [`ApiKeyError::Scope`] on a caller
    /// mistake, [`ApiKeyError::Random`] or [`ApiKeyError::Db`] — in
    /// every failure case no key was issued.
    pub async fn issue(
        &self,
        namespace: &str,
        subject: &str,
        scopes: &[&str],
        mode: ApiKeyMode,
    ) -> Result<IssuedKey, ApiKeyError> {
        if !is_valid_namespace(namespace) {
            return Err(ApiKeyError::Namespace(namespace.to_owned()));
        }
        for scope in scopes {
            if scope.is_empty() || scope.contains(char::is_whitespace) {
                return Err(ApiKeyError::Scope((*scope).to_owned()));
            }
        }
        let (id, secret) = self.generate()?;
        let prefix = format!("{namespace}_{}_{id}", mode.as_str());
        let token = format!("{prefix}_{secret}");
        let now = stamp(self.clock.now())?;
        let mut insert = Query::insert();
        insert
            .into_table(iden(&self.table))
            .columns(KEY_COLUMNS)
            .values_panic([
                prefix.clone().into(),
                sha256_hex(token.as_bytes()).into(),
                namespace.to_owned().into(),
                subject.to_owned().into(),
                scopes.join(" ").into(),
                mode.as_str().into(),
                now.into(),
            ]);
        self.db.execute(&Statement::render(&insert)).await?;
        Ok(IssuedKey { token, prefix })
    }

    /// Reads one active (unrevoked) key row by prefix.
    async fn load(&self, prefix: &str) -> Result<Option<KeyRow>, DbError> {
        let mut select = Query::select();
        select
            .columns([
                "secret_hash",
                "subject",
                "scopes",
                "last_used_at",
                "revoked_at",
            ])
            .from(iden(&self.table))
            .and_where(Expr::col(iden("prefix")).eq(prefix));
        let rows = self.db.query(&Statement::render(&select)).await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        // `None` inside means SQL NULL; the `Option` outside means the
        // column was absent or unreadable, which revokes nothing.
        if let Some(Some(_)) = row.get::<Option<String>>("revoked_at") {
            return Ok(None);
        }
        Ok(Some(KeyRow {
            secret_hash: required(row, "secret_hash")?,
            subject: required(row, "subject")?,
            scopes: required(row, "scopes")?,
            last_used_at: row.get::<Option<String>>("last_used_at").flatten(),
        }))
    }

    /// Verifies one presented token: parse, look the prefix up, re-derive
    /// the hash, compare in constant time; on success touch `last_used_at`
    /// (once per window, best effort — logged, never a failed request).
    ///
    /// `Ok(None)` is every auth failure there is — malformed, unknown,
    /// revoked, wrong secret — deliberately indistinguishable, so probing
    /// a gate built on this learns nothing. A database failure is
    /// [`Err`], and nothing about it says "unauthorized".
    ///
    /// # Errors
    ///
    /// [`DbError`] when the lookup fails.
    pub async fn verify(&self, token: &str) -> Result<Option<ApiKeyPrincipal>, DbError> {
        let Some(parsed) = ParsedKey::parse(token) else {
            return Ok(None);
        };
        let Some(row) = self.load(&parsed.prefix).await? else {
            return Ok(None);
        };
        let presented = sha256_hex(token.as_bytes());
        if !constant_time_eq(presented.as_bytes(), row.secret_hash.as_bytes()) {
            return Ok(None);
        }
        if let Err(err) = self
            .touch(&parsed.prefix, row.last_used_at.as_deref())
            .await
        {
            // The key is verified; a cosmetic write must not fail the
            // request. The prefix is public, so naming it leaks nothing.
            tracing::warn!(error = %err, prefix = %parsed.prefix, "api key last-used touch failed");
        }
        Ok(Some(ApiKeyPrincipal {
            prefix: parsed.prefix,
            namespace: parsed.namespace,
            subject: row.subject,
            scopes: row
                .scopes
                .split(' ')
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .collect(),
            mode: parsed.mode,
        }))
    }

    /// Whether `last_used_at` is stale enough to rewrite: never set,
    /// older than the touch window, or unparseable (repaired).
    fn touch_due(last_used_at: Option<&str>, now: OffsetDateTime) -> bool {
        let Some(stored) = last_used_at else {
            return true;
        };
        match OffsetDateTime::parse(stored, &Rfc3339) {
            Ok(then) => (now - then).whole_seconds() >= TOUCH_WINDOW_SECONDS,
            Err(_) => true,
        }
    }

    /// The throttled `last_used_at` write behind [`Self::verify`].
    async fn touch(&self, prefix: &str, last_used_at: Option<&str>) -> Result<(), DbError> {
        let now = self.clock.now();
        if !Self::touch_due(last_used_at, now) {
            return Ok(());
        }
        let mut update = Query::update();
        update
            .table(iden(&self.table))
            .value(iden("last_used_at"), stamp(now)?)
            .and_where(Expr::col(iden("prefix")).eq(prefix));
        self.db.execute(&Statement::render(&update)).await?;
        Ok(())
    }

    /// Marks a key revoked: every later verify answers `Ok(None)`. The
    /// row stays, so a later rotate of the same prefix is refused and an
    /// audit can still see the key existed. Idempotent.
    ///
    /// # Errors
    ///
    /// [`ApiKeyError::UnknownKey`] when the prefix names no key,
    /// [`ApiKeyError::Db`] when the write fails.
    pub async fn revoke(&self, prefix: &str) -> Result<(), ApiKeyError> {
        let mut update = Query::update();
        update
            .table(iden(&self.table))
            .value(iden("revoked_at"), stamp(self.clock.now())?)
            .and_where(Expr::col(iden("prefix")).eq(prefix));
        if self.db.execute(&Statement::render(&update)).await? == 0 {
            return Err(ApiKeyError::UnknownKey(prefix.to_owned()));
        }
        Ok(())
    }

    /// Rotates a key: mints a fresh token for the same namespace, mode,
    /// subject and scopes and revokes the old one, both statements in
    /// one [`Database::batch_atomic`] batch (issue #126) — the old key
    /// never keeps working while the new one does not exist yet, nor the
    /// reverse. The copy is an `INSERT ... SELECT` keyed to the old row
    /// still being active, so a rotate racing a revoke — or a second
    /// rotate — mints nothing instead of a second live key.
    ///
    /// # Errors
    ///
    /// [`ApiKeyError::UnknownKey`] when the prefix names no active key
    /// (a revoked one included — rotate the replacement instead),
    /// [`ApiKeyError::Random`] or [`ApiKeyError::Db`] as [`Self::issue`].
    pub async fn rotate(&self, prefix: &str) -> Result<IssuedKey, ApiKeyError> {
        let Some((namespace, mode)) = parse_prefix(prefix) else {
            return Err(ApiKeyError::UnknownKey(prefix.to_owned()));
        };
        let (id, secret) = self.generate()?;
        let new_prefix = format!("{namespace}_{}_{id}", mode.as_str());
        let token = format!("{new_prefix}_{secret}");
        let now = stamp(self.clock.now())?;
        // Copy the still-active row into the new key.
        let mut insert = Query::insert();
        insert
            .into_table(iden(&self.table))
            .columns(KEY_COLUMNS)
            .select_from(
                Query::select()
                    .expr(Expr::val(new_prefix.clone()))
                    .expr(Expr::val(sha256_hex(token.as_bytes())))
                    .expr(Expr::col(iden("namespace")))
                    .expr(Expr::col(iden("subject")))
                    .expr(Expr::col(iden("scopes")))
                    .expr(Expr::col(iden("mode")))
                    .expr(Expr::val(now.clone()))
                    .from(iden(&self.table))
                    .and_where(Expr::col(iden("prefix")).eq(prefix))
                    .and_where(Expr::col(iden("revoked_at")).is_null())
                    .to_owned(),
            )
            .map_err(|err| DbError::Execute(format!("rotate copy is malformed: {err}")))?;
        let mut revoke_old = Query::update();
        revoke_old
            .table(iden(&self.table))
            .value(iden("revoked_at"), now)
            .and_where(Expr::col(iden("prefix")).eq(prefix))
            .and_where(Expr::col(iden("revoked_at")).is_null());
        self.db
            .batch_atomic(&[Statement::render(&insert), Statement::render(&revoke_old)])
            .await?;
        // batch_atomic reports no row counts, so confirm the copy landed:
        // an unknown or already-revoked prefix inserted nothing.
        if self.load(&new_prefix).await?.is_none() {
            return Err(ApiKeyError::UnknownKey(prefix.to_owned()));
        }
        Ok(IssuedKey {
            token,
            prefix: new_prefix,
        })
    }
}

/// The per-request gate, the API-key sibling of
/// `cratefield_core::require_admin`: reads `Authorization: Bearer
/// <token>`, verifies it against `keys`, and demands `scope`. A missing
/// header, malformed token, unknown prefix, revoked key or wrong secret
/// all answer `401 api-key-unauthorized`, one uniform problem so a probe
/// cannot tell which held; a valid key without `scope` answers
/// `403 api-key-forbidden`; a store failure answers `503 not-ready`
/// (generic detail — the error itself is only logged).
///
/// # Errors
///
/// The [`Problem`] described above; carry it straight into the handler's
/// `Err`.
pub async fn require_api_key(
    keys: &ApiKeys,
    headers: &HeaderMap,
    scope: &str,
) -> Result<ApiKeyPrincipal, Problem> {
    let unauthorized = || Problem::new(&SLUGS.api_key_unauthorized);
    let Some(token) = bearer_token(headers) else {
        return Err(unauthorized());
    };
    let Some(principal) = keys.verify(token).await.map_err(|err| {
        tracing::warn!(error = %err, "api key lookup failed");
        Problem::new(&SLUGS.not_ready).with_detail("api key store lookup failed")
    })?
    else {
        return Err(unauthorized());
    };
    if !principal.has_scope(scope) {
        return Err(Problem::new(&SLUGS.api_key_forbidden)
            .with_detail(format!("the key lacks the required scope {scope:?}")));
    }
    Ok(principal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_the_documented_shape() {
        let token = "pos_live_3f9a0c1d2e4b5a6c_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let parsed = ParsedKey::parse(token).expect("parses");
        assert_eq!(parsed.prefix, "pos_live_3f9a0c1d2e4b5a6c");
        assert_eq!(parsed.namespace, "pos");
        assert_eq!(parsed.mode, ApiKeyMode::Live);
    }

    #[test]
    fn parse_rejects_every_malformed_shape() {
        let good_secret = "ab".repeat(SECRET_BYTES);
        let good_id = "cd".repeat(ID_BYTES);
        let malformed: Vec<String> = vec![
            String::new(),
            format!("pos_live_{good_id}"),
            format!("pos_live_{good_id}_{good_secret}_extra"),
            format!("pos_test_{good_id}_short"),
            format!("pos_test_{good_id}_{}", "AB".repeat(SECRET_BYTES)),
            format!("pos_live_3f9a_{good_secret}"),
            format!("pos_sand_{good_id}_{good_secret}"),
            format!("Pos_live_{good_id}_{good_secret}"),
            format!("pos-api_live_{good_id}_{good_secret}"),
            format!(
                "{}s_live_{good_id}_{good_secret}",
                "a".repeat(MAX_NAMESPACE_CHARS)
            ),
            format!("pos_live_{good_id}_{good_secret} "),
        ];
        for token in &malformed {
            assert!(ParsedKey::parse(token).is_none(), "{token:?} parsed");
        }
    }
}
