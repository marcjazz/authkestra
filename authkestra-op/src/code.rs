use crate::error::OpError;
use async_trait::async_trait;
use authkestra_engine::auth::state::Identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// An authorization code issued at `/authorize`, pending exchange at
/// `/token`.
///
/// Codes are single-use (`used`) and short-lived (`expires_at`) — see
/// RFC-003 §7. `AuthorizationCodeStore::consume_code` is responsible for
/// enforcing single-use atomically; this struct is deliberately a plain
/// data holder with no enforcement logic of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// The opaque code value handed to the client.
    pub code: String,
    /// The client this code was issued to.
    pub client_id: String,
    /// The exact redirect_uri presented at `/authorize`; `/token` must
    /// receive the same value.
    pub redirect_uri: String,
    /// Space-delimited scopes granted.
    pub scope: String,
    /// PKCE code_challenge, if the client used PKCE.
    pub code_challenge: Option<String>,
    /// PKCE code_challenge_method (`plain` or `S256`).
    pub code_challenge_method: Option<String>,
    /// OIDC nonce, if provided in the authorization request.
    pub nonce: Option<String>,
    /// The authenticated identity this code represents.
    pub identity: Identity,
    /// When this code expires. Recommend issuing with a short lifetime
    /// (≤60s per RFC-003 §7).
    pub expires_at: DateTime<Utc>,
    /// Whether this code has already been exchanged. Storage
    /// implementations must treat consuming an already-used code as an
    /// error, not a silent no-op.
    pub used: bool,
}

impl AuthorizationCode {
    /// Returns true if this code is expired as of `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Storage interface for authorization codes.
///
/// `consume_code` **must** be atomic: check `used`, mark it used, and
/// return the code as a single indivisible operation. A
/// check-then-mark implemented as two separate storage calls is a
/// TOCTOU race that permits code replay — this is the single most
/// important correctness property in this crate. Implementations backed
/// by SQL should use a single `UPDATE ... WHERE used = false RETURNING *`
/// (or equivalent compare-and-swap) rather than a `SELECT` followed by an
/// `UPDATE`.
#[async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    /// Persists a newly issued code.
    async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError>;

    /// Atomically retrieves and invalidates a code by its value. Returns
    /// `Ok(None)` if the code does not exist, is already used, or is
    /// expired — callers map that to `OpError::InvalidCode` without
    /// distinguishing which case occurred, to avoid leaking timing/existence
    /// information to a potential attacker.
    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError>;
}

/// A minimal in-memory `AuthorizationCodeStore` for development and tests.
/// Not suitable for production (no persistence, no cross-instance sharing,
/// no expiry sweep — expired-but-unconsumed codes are only checked lazily
/// on lookup, not proactively evicted).
#[derive(Default)]
pub struct InMemoryAuthorizationCodeStore {
    codes: RwLock<HashMap<String, AuthorizationCode>>,
}

impl InMemoryAuthorizationCodeStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AuthorizationCodeStore for InMemoryAuthorizationCodeStore {
    async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError> {
        tracing::debug!(client_id = %code.client_id, "storing authorization code in memory");
        self.codes
            .write()
            .map_err(|_| {
                tracing::error!("authorization code store lock poisoned");
                OpError::Storage
            })?
            .insert(code.code.clone(), code);
        Ok(())
    }

    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        tracing::trace!("attempting to consume authorization code");
        let mut codes = self.codes.write().map_err(|_| {
            tracing::error!("authorization code store lock poisoned");
            OpError::Storage
        })?;
        // `get_mut` + check + mutate while holding the write lock is the
        // atomic step this trait's contract requires — do not replace this
        // with a separate read followed by a separate write.
        match codes.get_mut(code) {
            Some(entry) if !entry.used && !entry.is_expired(Utc::now()) => {
                tracing::debug!(client_id = %entry.client_id, "successfully consumed authorization code");
                entry.used = true;
                Ok(Some(entry.clone()))
            }
            Some(entry) if entry.used => {
                tracing::warn!(client_id = %entry.client_id, "attempted to consume an already-used authorization code");
                Ok(None)
            }
            Some(entry) => {
                tracing::debug!(client_id = %entry.client_id, "attempted to consume an expired authorization code");
                Ok(None)
            }
            None => {
                tracing::debug!("authorization code not found");
                Ok(None)
            }
        }
    }
}
