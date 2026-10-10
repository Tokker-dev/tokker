//! The HMAC-SHA256 reference `Signer` over a bounded key ring (ADR 0006,
//! amended by ADR 0014; issue #3, issue #137).
//!
//! Token format: `base64url(json).base64url(mac)` where the MAC is
//! computed over the **encoded** payload string — the exact bytes between
//! the dots — so a token has exactly one valid encoding.
//!
//! ## The ring (issue #137)
//!
//! The flat current/previous pair is replaced by a [`KeyRing`] of at most
//! [`KeyRing::CAPACITY`] keys, each in one of three states:
//!
//! - [`KeyState::Signing`] — exactly one; every new token names it.
//! - [`KeyState::VerifyingOnly`] — still verifies its old tokens, can
//!   never sign again. Normal rotation demotes the outgoing key here.
//! - [`KeyState::Revoked`] — refused for verification *and* signing; its
//!   id cannot be re-added, and its secret can never re-enter the ring.
//!   This is what makes a compromised key retire immediately rather than
//!   merely demote (issue #137).
//!
//! Because the ring is bounded, adding a key past the bound retires the
//! oldest non-signing entry: **a link survives at most `CAPACITY − 1`
//! rotations after it was minted.** That is the honest half of the
//! longevity-vs-revocation tradeoff; the other half is that the
//! unsubscribe path does not depend on the signing key at all once a
//! subscriber has been re-mailed — see `module-email-signup`'s opaque
//! per-subscription tokens and `docs/KEY-ROTATION.md`.
//!
//! ## Time
//!
//! Expiry checks and lifetime clamping read the clock exclusively through
//! the [`Clock`] port (architecture section 5) — never a direct system
//! read — so a test can drive rotation and expiry without waiting, and the
//! wasm target never gains a hidden time dependency.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::Clock;
use crate::ports::signer::{Kid, MAX_KID_NAME, Payload, Signer};

type HmacSha256 = Hmac<Sha256>;

/// Minimum secret length. `HARNESS_SECRET` must be at least 32 bytes.
pub const MIN_SECRET_BYTES: usize = 32;

/// Errors from constructing an [`HmacSigner`] or a [`KeyRing`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    #[error("harness secret must be at least {MIN_SECRET_BYTES} bytes")]
    SecretTooShort,
    #[error("key id {0:?} is already present in the ring")]
    KeyIdTaken(String),
    #[error("key id {0:?} was revoked and can never re-enter the ring (issue #137)")]
    KeyRevoked(String),
    #[error("a revoked secret can never be re-added under another key id (issue #137)")]
    RevokedSecretReuse,
    #[error("key id {0:?} exceeds the {MAX_KID_NAME}-character limit")]
    KeyIdTooLong(String),
    #[error(
        "the ring is full and every live key is the signing key; nothing can be retired to make room"
    )]
    RingFull,
}

/// A key's role in the ring (ADR 0014, issue #137).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Signs every new token. At most one key holds this state.
    Signing,
    /// Verifies tokens it signed before demotion; can never sign.
    VerifyingOnly,
    /// Compromised or deliberately retired: its tokens are refused, its
    /// id is burned, and its secret can never re-enter the ring.
    Revoked,
}

/// One ring entry. Deliberately not `Debug`: the ring's debug view
/// ([`KeyRing::states`]) shows ids and states but never key material
/// (issue #135's scrubbing rule applies to key bytes too).
#[derive(Clone)]
pub struct RingKey {
    kid: Kid,
    secret: Vec<u8>,
    state: KeyState,
}

/// A bounded set of token-signing keys with explicit states (issue #137).
///
/// A ring is built once — from the environment in a Worker, or
/// programmatically by rotation tooling — and then frozen inside an
/// [`HmacSigner`]. It is not ambient request state (ADR 0007): each
/// signer owns its ring, and rotating keys in a running Worker means
/// updating the secrets so the next isolate builds a new ring.
#[derive(Clone)]
pub struct KeyRing {
    keys: Vec<RingKey>,
}

impl KeyRing {
    /// Maximum number of entries: one signing key plus `CAPACITY − 1`
    /// verification-only or revoked. A token survives at most
    /// `CAPACITY − 1` rotations after it was minted; past that, its key
    /// is retired and the link is dead by design — the documented cost of
    /// being able to revoke a compromised key without a token table
    /// (ADR 0014).
    pub const CAPACITY: usize = 4;

    #[must_use]
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Number of entries, including revoked ones still remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Safe view of the ring: each key's id and state, never its bytes.
    #[must_use]
    pub fn states(&self) -> Vec<(Kid, KeyState)> {
        self.keys
            .iter()
            .map(|key| (key.kid.clone(), key.state))
            .collect()
    }

    /// The key currently signing new tokens, if any.
    #[must_use]
    pub fn signing_key(&self) -> Option<&RingKey> {
        self.keys.iter().find(|key| key.state == KeyState::Signing)
    }

    #[must_use]
    pub fn state_of(&self, kid: &Kid) -> Option<KeyState> {
        self.keys
            .iter()
            .find(|key| &key.kid == kid)
            .map(|key| key.state)
    }

    /// Installs `secret` as the single signing key, demoting the previous
    /// signer to [`KeyState::VerifyingOnly`]. If the ring is at capacity,
    /// the oldest non-signing entry is retired to make room (its id is
    /// kept as a burned tombstone); the retired id is returned.
    ///
    /// # Errors
    ///
    /// [`SignerError::SecretTooShort`], [`SignerError::KeyIdTooLong`],
    /// [`SignerError::KeyIdTaken`], [`SignerError::KeyRevoked`] or
    /// [`SignerError::RevokedSecretReuse`] when the new key is invalid;
    /// [`SignerError::RingFull`] only in the degenerate ring whose entries
    /// are all signing or revoked-with-nothing-to-drop (impossible under
    /// [`Self::CAPACITY`] ≥ 1 except with hand-built state).
    pub fn rotate_signing(
        &mut self,
        kid: Kid,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Option<Kid>, SignerError> {
        self.install(kid, secret.into(), KeyState::Signing)
    }

    /// Adds a verification-only key — the shape of `HARNESS_SECRET_PREVIOUS`
    /// in the environment wiring. Same capacity and revocation rules as
    /// [`Self::rotate_signing`].
    ///
    /// # Errors
    ///
    /// Identical to [`Self::rotate_signing`]: [`SignerError::SecretTooShort`],
    /// [`SignerError::KeyIdTooLong`], [`SignerError::KeyIdTaken`],
    /// [`SignerError::KeyRevoked`] or [`SignerError::RevokedSecretReuse`]
    /// when the key is invalid, and [`SignerError::RingFull`] only in a
    /// degenerate ring where nothing can be retired to make room.
    pub fn add_verifying_only(
        &mut self,
        kid: Kid,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Option<Kid>, SignerError> {
        self.install(kid, secret.into(), KeyState::VerifyingOnly)
    }

    /// Marks `kid` [`KeyState::Revoked`]. Its tokens stop verifying
    /// immediately, even while its secret stays configured somewhere in
    /// the ring — revocation is a state, not a deletion race. Returns
    /// whether an entry existed to be revoked; a missing id is still
    /// burned as a tombstone, so `revoke(prev)` survives the moment the
    /// operator also drops `HARNESS_SECRET_PREVIOUS`.
    pub fn revoke(&mut self, kid: &Kid) -> bool {
        if let Some(key) = self.keys.iter_mut().find(|key| &key.kid == kid) {
            key.state = KeyState::Revoked;
            return true;
        }
        // Burn the id without ever having held the secret. Bytes stay
        // empty: a tombstone is metadata, never key material. The ring is
        // bounded, so an id is only burned while a slot is genuinely
        // free: the oldest empty tombstone is recycled first, and a ring
        // full of live keys keeps its memory (its bytes are refused by
        // removal anyway; the id simply is not remembered past that).
        if self.keys.len() >= Self::CAPACITY && !self.make_room_for_tombstone() {
            return false;
        }
        self.keys.push(RingKey {
            kid: kid.clone(),
            secret: Vec::new(),
            state: KeyState::Revoked,
        });
        false
    }

    /// Drops the oldest bytes-empty revoked entry to free a slot for a
    /// new tombstone. Returns whether a slot was freed.
    fn make_room_for_tombstone(&mut self) -> bool {
        match self
            .keys
            .iter()
            .position(|key| key.state == KeyState::Revoked && key.secret.is_empty())
        {
            Some(index) => {
                self.keys.remove(index);
                true
            }
            None => false,
        }
    }

    /// The shared insert path: validate, demote the old signer on a
    /// rotation, evict oldest-if-full, then append.
    fn install(
        &mut self,
        kid: Kid,
        secret: Vec<u8>,
        state: KeyState,
    ) -> Result<Option<Kid>, SignerError> {
        if secret.len() < MIN_SECRET_BYTES {
            return Err(SignerError::SecretTooShort);
        }
        if kid_name_len(&kid) > MAX_KID_NAME {
            return Err(SignerError::KeyIdTooLong(kid_display(&kid)));
        }
        if let Some(existing) = self.state_of(&kid) {
            return Err(match existing {
                KeyState::Revoked => SignerError::KeyRevoked(kid_display(&kid)),
                _ => SignerError::KeyIdTaken(kid_display(&kid)),
            });
        }
        if self.keys.iter().any(|key| {
            key.state == KeyState::Revoked && !key.secret.is_empty() && key.secret == secret
        }) {
            return Err(SignerError::RevokedSecretReuse);
        }
        if state == KeyState::Signing
            && let Some(previous) = self
                .keys
                .iter_mut()
                .find(|key| key.state == KeyState::Signing)
        {
            previous.state = KeyState::VerifyingOnly;
        }
        let mut retired = None;
        while self.keys.len() >= Self::CAPACITY {
            match self.evict_oldest_non_signing() {
                Some(evicted) => retired = Some(evicted),
                None => return Err(SignerError::RingFull),
            }
        }
        self.keys.push(RingKey { kid, secret, state });
        Ok(retired)
    }

    /// Drops the oldest entry that is not the signing key, preferring a
    /// revoked tombstone, then the oldest verification-only key. Returns
    /// the retired id.
    ///
    /// A retired verification-only key is remembered as a *bytes-empty*
    /// tombstone — its id stays burned so an operator can never re-mint
    /// it under a live secret and confuse links that still name it — but
    /// only while that costs nothing: burning an id may never consume the
    /// very room the eviction was for. Under capacity pressure the oldest
    /// id decays, the same bounded-memory-over-burned-name rule as
    /// [`Self::revoke`]. Each call therefore strictly shrinks the ring
    /// unless the tombstone leaves it below the bound already.
    fn evict_oldest_non_signing(&mut self) -> Option<Kid> {
        let index = self
            .keys
            .iter()
            .position(|key| key.state == KeyState::Revoked)
            .or_else(|| {
                self.keys
                    .iter()
                    .position(|key| key.state == KeyState::VerifyingOnly)
            })?;
        let evicted = self.keys.remove(index);
        if self.keys.len() < Self::CAPACITY - 1 {
            self.keys.insert(
                index,
                RingKey {
                    kid: evicted.kid.clone(),
                    secret: Vec::new(),
                    state: KeyState::Revoked,
                },
            );
        }
        Some(evicted.kid)
    }
}

impl Default for KeyRing {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for KeyRing {
    /// Never prints key material (issue #135).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("keys", &self.states())
            .finish_non_exhaustive()
    }
}

/// A per-purpose lifetime ceiling (ADR 0014, issue #137).
///
/// The signer applies the policy at *sign* time: a requested `exp` beyond
/// the ceiling is clamped down, and a missing `exp` gets the ceiling as a
/// definite expiry. Only a purpose whose ceiling is `None` may mint a
/// genuinely non-expiring token, and that must be a justified line in the
/// policy table, never an omission by the caller.
#[derive(Debug, Clone)]
pub struct TokenPolicy {
    rules: Vec<(String, i64)>,
    default_secs: Option<i64>,
}

/// Seven days: the ADR 0006 confirmation default, expressed as a policy
/// ceiling rather than a caller habit.
pub const CONFIRM_TOKEN_MAX_TTL_SECS: i64 = 7 * 86_400;

/// The status-token policy (issue #137): a waitlist position is not
/// secret, but a URL that never expires is a URL forever in logs,
/// forwards and bookmarks. Ninety days, renewed on every confirm hit.
pub const STATUS_TOKEN_MAX_TTL_SECS: i64 = 90 * 86_400;

/// The default ceiling for any purpose not listed explicitly. An unknown
/// purpose can never mint a non-expiring token by omission.
pub const DEFAULT_TOKEN_MAX_TTL_SECS: i64 = 30 * 86_400;

/// The one action with a deliberately non-expiring ceiling, justified in
/// ADR 0014: unsubscribe must always be reachable, and the longevity the
/// signed link used to buy from the global key ring is now *also* carried
/// by the per-subscription opaque token in `module-email-signup`, which
/// outlives any key rotation because it lives in the subscriber's row.
pub const UNSUBSCRIBE_ACTION: &str = "unsubscribe";

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            rules: vec![
                ("confirm".to_owned(), CONFIRM_TOKEN_MAX_TTL_SECS),
                ("status".to_owned(), STATUS_TOKEN_MAX_TTL_SECS),
            ],
            default_secs: Some(DEFAULT_TOKEN_MAX_TTL_SECS),
        }
    }
}

impl TokenPolicy {
    /// Overrides one action's ceiling. `Some(secs)` bounds the action;
    /// `None` makes it explicitly non-expiring — a decision a venture
    /// must name on purpose, which is exactly the point of issue #137.
    /// A zero ceiling means the same as `None` (`max_ttl_secs` maps it),
    /// so the table always carries the decision, never an omission.
    #[must_use]
    pub fn with_max(mut self, action: &str, secs: Option<i64>) -> Self {
        let ceiling = secs.unwrap_or(0);
        self.rules.retain(|(name, _)| name != action);
        self.rules.push((action.to_owned(), ceiling));
        self
    }

    /// The ceiling for a purpose's action part (the text after the first
    /// `.`, the whole string when there is none). `None` means an
    /// explicitly sanctioned non-expiring purpose.
    #[must_use]
    pub fn max_ttl_secs(&self, purpose: &str) -> Option<i64> {
        let action = purpose.split_once('.').map_or(purpose, |(_, rest)| rest);
        if action == UNSUBSCRIBE_ACTION {
            return None;
        }
        match self.rules.iter().find(|(name, _)| name == action) {
            Some((_, 0)) => None,
            Some((_, secs)) => Some(*secs),
            None => self.default_secs,
        }
    }

    /// The effective expiry: `min(requested, now + ceiling)`, and
    /// `now + ceiling` when the caller supplied no expiry at all.
    #[must_use]
    pub fn effective_exp(&self, purpose: &str, requested: Option<u64>, now: u64) -> Option<u64> {
        self.max_ttl_secs(purpose).map(|ceiling| {
            let limit = now.saturating_add(u64::try_from(ceiling.max(0)).unwrap_or(0));
            requested.map_or(limit, |exp| exp.min(limit))
        })
    }
}

#[derive(Serialize, Deserialize)]
struct PayloadJson {
    purpose: String,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    iss: Option<String>,
    kid: String,
}

/// HMAC-SHA256 signer over a [`KeyRing`] (ADR 0006, ADR 0014).
///
/// Cheap to clone: the ring, clock, binding and policy live behind one
/// `Arc`. `Debug` shows key ids and states only — never key material
/// (issue #135).
#[derive(Clone)]
pub struct HmacSigner {
    inner: Arc<SignerInner>,
}

#[derive(Clone)]
struct SignerInner {
    ring: KeyRing,
    clock: Arc<dyn Clock>,
    /// The venture/environment binding (issue #137): stamped into new
    /// tokens as `iss` and enforced against tokens that carry it. `None`
    /// only in tests and hand-built signers; every runtime sets it
    /// through [`crate::HarnessConfig::signer`].
    binding: Option<String>,
    policy: TokenPolicy,
}

impl std::fmt::Debug for HmacSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSigner")
            .field("ring", &self.inner.ring)
            .field("bound", &self.inner.binding.is_some())
            .finish()
    }
}

impl HmacSigner {
    /// The environment shape of ADR 0006: `HARNESS_SECRET` signs, the
    /// optional `HARNESS_SECRET_PREVIOUS` verifies only. No venture/env
    /// binding and the default [`TokenPolicy`]; runtimes build the bound
    /// signer through [`crate::HarnessConfig::signer`], where those
    /// fields come from config (issue #137).
    ///
    /// # Errors
    ///
    /// [`SignerError::SecretTooShort`] when the current secret is shorter
    /// than [`MIN_SECRET_BYTES`].
    pub fn new(
        current_secret: impl Into<String>,
        previous_secret: Option<String>,
    ) -> Result<Self, SignerError> {
        let mut ring = KeyRing::new();
        ring.rotate_signing(Kid::Cur, current_secret.into().into_bytes())?;
        if let Some(previous) = previous_secret {
            ring.add_verifying_only(Kid::Prev, previous.into_bytes())?;
        }
        Ok(Self::from_ring(ring))
    }

    /// A signer over an already-built ring: [`crate::SystemClock`], no
    /// binding, default [`TokenPolicy`]. Apply [`with_clock`],
    /// [`with_binding`] and [`with_policy`] before handing it out.
    ///
    /// [`with_clock`]: Self::with_clock
    /// [`with_binding`]: Self::with_binding
    /// [`with_policy`]: Self::with_policy
    #[must_use]
    pub fn from_ring(ring: KeyRing) -> Self {
        Self {
            inner: Arc::new(SignerInner {
                ring,
                clock: Arc::new(crate::SystemClock),
                binding: None,
                policy: TokenPolicy::default(),
            }),
        }
    }

    /// Overrides the clock used for expiry checks and lifetime clamping
    /// (the `Clock` port is the only time source in core, architecture
    /// section 5).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        Arc::make_mut(&mut self.inner).clock = clock;
        self
    }

    /// Stamps and enforces the venture/environment binding (issue #137).
    /// The labels come from config (`HARNESS_VENTURE`, `ENV`); a token
    /// minted under one binding never verifies under another. With both
    /// `None` the signer stays unbound — the pre-#137 shape, kept for
    /// tests and hand-built rings.
    #[must_use]
    pub fn with_binding(mut self, venture: Option<String>, env: Option<String>) -> Self {
        let binding = match (
            venture.filter(|value| !value.is_empty()),
            env.filter(|value| !value.is_empty()),
        ) {
            (None, None) => None,
            (venture, env) => Some(format!(
                "{}|{}",
                venture.as_deref().unwrap_or("-"),
                env.as_deref().unwrap_or("-")
            )),
        };
        Arc::make_mut(&mut self.inner).binding = binding;
        self
    }

    /// Replaces the per-purpose lifetime policy.
    #[must_use]
    pub fn with_policy(mut self, policy: TokenPolicy) -> Self {
        Arc::make_mut(&mut self.inner).policy = policy;
        self
    }

    /// The ring this signer verifies against (ids and states only).
    #[must_use]
    pub fn ring_states(&self) -> Vec<(Kid, KeyState)> {
        self.inner.ring.states()
    }

    fn now_secs(&self) -> u64 {
        u64::try_from(self.inner.clock.now().unix_timestamp().max(0)).unwrap_or(0)
    }

    fn mac(key: &[u8], encoded_payload: &str) -> [u8; 32] {
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(encoded_payload.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        out
    }

    /// Constant-time MAC against every live (non-revoked) key, with no
    /// early exit: the work is bounded by the ring size and independent of
    /// which key matches (issue #137). The old scheme tried the named key
    /// then one fallback; trying all live keys is its superset, which is
    /// what lets a token signed before the ring existed survive a
    /// rotation whichever positional name it carries.
    fn mac_matches_any_live_key(&self, mac: [u8; 32], encoded_payload: &str) -> bool {
        let mut matched = false;
        for key in &self.inner.ring.keys {
            if key.state == KeyState::Revoked || key.secret.is_empty() {
                continue;
            }
            matched |= bool::from(mac.ct_eq(&Self::mac(&key.secret, encoded_payload)));
        }
        matched
    }
}

impl Signer for HmacSigner {
    fn sign(&self, payload: &Payload) -> String {
        // Signing always uses the ring's signing key; a caller cannot
        // steer which key signs. The old `Kid::Prev` signing path is gone
        // — a verification-only key verifies only (ADR 0014). A ring with
        // no signing key yields an empty token rather than a panic:
        // `verify` treats it as malformed, and a correctly wired runtime
        // always has a signing key.
        let Some(signing) = self.inner.ring.signing_key() else {
            tracing::error!(purpose = %payload.purpose, "signer ring has no signing key; emitting an invalid token");
            return String::new();
        };
        let exp = self
            .inner
            .policy
            .effective_exp(&payload.purpose, payload.exp, self.now_secs());
        let json = PayloadJson {
            purpose: payload.purpose.clone(),
            subject: payload.subject.clone(),
            exp,
            iss: self.inner.binding.clone(),
            kid: kid_wire_name(&signing.kid),
        };
        let Ok(serialized) = serde_json::to_string(&json) else {
            tracing::error!(purpose = %payload.purpose, "signer payload failed to serialize; emitting an invalid token");
            return String::new();
        };
        let encoded = URL_SAFE_NO_PAD.encode(serialized);
        let mac = Self::mac(&signing.secret, &encoded);
        format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(mac))
    }

    fn verify(&self, token: &str, expected_purpose: &str) -> Option<Payload> {
        let (encoded_payload, encoded_mac) = token.split_once('.')?;
        if encoded_payload.is_empty() || encoded_mac.is_empty() {
            return None;
        }
        if token.matches('.').count() != 1 {
            return None;
        }

        let mac: [u8; 32] = URL_SAFE_NO_PAD.decode(encoded_mac).ok()?.try_into().ok()?;
        let json = URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())?;
        let payload: PayloadJson = serde_json::from_str(&json).ok()?;
        let kid = parse_kid(&payload.kid)?;

        // MAC over the encoded payload string (ADR 0006): the exact bytes
        // of `encoded_payload`, so a re-encoded (e.g. padded) payload
        // cannot reuse a MAC. Revoked keys are skipped by construction
        // (issue #137).
        if !self.mac_matches_any_live_key(mac, encoded_payload) {
            return None;
        }

        if payload.purpose != expected_purpose {
            return None;
        }
        // Binding (issue #137): a token that carries a venture/environment
        // scope must match this signer's scope, and a scope-carrying
        // token is refused by an unbound signer (fail closed on
        // misconfiguration). A legacy token with no `iss` verifies on —
        // already-sent links are not retroactively broken — but a bound
        // signer never mints one, so the unbound population only shrinks
        // (ADR 0014).
        if payload.iss.is_some() && payload.iss.as_deref() != self.inner.binding.as_deref() {
            return None;
        }
        if let Some(exp) = payload.exp
            && self.now_secs() >= exp
        {
            return None;
        }
        Some(Payload {
            purpose: payload.purpose,
            subject: payload.subject,
            exp: payload.exp,
            kid,
        })
    }
}

fn kid_wire_name(kid: &Kid) -> String {
    match kid {
        Kid::Cur => "cur".to_owned(),
        Kid::Prev => "prev".to_owned(),
        Kid::Named(name) => name.clone(),
    }
}

fn kid_display(kid: &Kid) -> String {
    kid_wire_name(kid)
}

fn kid_name_len(kid: &Kid) -> usize {
    match kid {
        Kid::Cur | Kid::Prev => 3,
        Kid::Named(name) => name.len(),
    }
}

fn parse_kid(name: &str) -> Option<Kid> {
    match name {
        "cur" => Some(Kid::Cur),
        "prev" => Some(Kid::Prev),
        other if !other.is_empty() && other.len() <= MAX_KID_NAME => {
            Some(Kid::Named(other.to_owned()))
        }
        _ => None,
    }
}
