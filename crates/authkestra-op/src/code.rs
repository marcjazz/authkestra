use crate::error::OpError;
use async_trait::async_trait;
use authkestra_engine::auth::state::Identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An authorization code issued at `/authorize`, pending exchange at
/// `/token`.
///
/// Codes are single-use (`used`) and short-lived (`expires_at`) — see
/// RFC-003 §7. `AuthorizationCodeStore::consume_code` is responsible for
/// enforcing single-use atomically; this struct is deliberately a plain
/// data holder with no enforcement logic of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthorizationCode {
    /// The opaque code value handed to the client.
    pub code: String,
    /// The client this code was issued to.
    pub client_id: String,
    /// The exact redirect_uri presented at `/authorize`; `/token` must
    /// receive the same value. For a loopback IP redirect this is the URI
    /// *with* the ephemeral port the client actually bound, not the portless
    /// registered form it was matched against (RFC 8252 §7.3,
    /// authkestra#291), which is what keeps `/token`'s exact comparison
    /// (RFC 6749 §4.1.3) both correct and unchanged.
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
    /// Creates a new authorization code.
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction from outside
    /// this crate, but `AuthorizationCodeStore` implementations must be able
    /// to reconstruct a code from their own storage — this is the seam that
    /// makes that possible (authkestra#268). `used` is a required parameter
    /// rather than a default: this crate's own storage backends deliberately
    /// fail *closed* on it (treating a code as already-used if its stored
    /// value can't be read, e.g. `sqlx_store.rs`'s
    /// `row.try_get("used").unwrap_or(true)`), and a constructor that
    /// silently defaulted to `false` would make it easy for a downstream
    /// implementation to reconstruct an already-spent code as fresh by
    /// forgetting to set it. `code_challenge`, `code_challenge_method` and
    /// `nonce` start `None` and, since every field here is `pub`, can be set
    /// directly on the returned value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        code: String,
        client_id: String,
        redirect_uri: String,
        scope: String,
        identity: Identity,
        expires_at: DateTime<Utc>,
        used: bool,
    ) -> Self {
        Self {
            code,
            client_id,
            redirect_uri,
            scope,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            identity,
            expires_at,
            used,
        }
    }

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

use authkestra_engine::store::{AtomicConsume, KvStore};
use std::time::Duration;

#[async_trait]
impl<S> AuthorizationCodeStore for S
where
    S: KvStore<AuthorizationCode> + AtomicConsume<AuthorizationCode>,
{
    async fn store_code(&self, code: AuthorizationCode) -> Result<(), OpError> {
        tracing::debug!(client_id = %code.client_id, "storing authorization code");
        let ttl = code
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        self.set(&code.code, code.clone(), ttl).await.map_err(|e| {
            tracing::error!(error = %e, "failed to store authorization code");
            OpError::Storage
        })?;
        Ok(())
    }

    async fn consume_code(&self, code: &str) -> Result<Option<AuthorizationCode>, OpError> {
        tracing::trace!("attempting to consume authorization code");
        self.consume(code).await.map_err(|e| {
            tracing::error!(error = %e, "failed to consume authorization code");
            OpError::Storage
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_engine::store::memory::MemoryStore;

    #[tokio::test]
    async fn test_authorization_code_store() {
        let store = MemoryStore::default();
        let code = AuthorizationCode::new(
            "code1".into(),
            "client1".into(),
            "http://cb".into(),
            "openid".into(),
            Identity {
                provider_id: "local".into(),
                external_id: "user1".into(),
                email: Some("user1@example.com".to_string()),
                username: None,
                attributes: Default::default(),
            },
            Utc::now() + chrono::Duration::seconds(60),
            false,
        );

        // test store
        store.store_code(code.clone()).await.unwrap();

        // test consume
        let consumed = store.consume_code("code1").await.unwrap().unwrap();
        assert_eq!(consumed.client_id, "client1");

        // second consume should fail
        assert!(store.consume_code("code1").await.unwrap().is_none());

        // test is_expired
        assert!(!code.is_expired(Utc::now()));
        assert!(code.is_expired(Utc::now() + chrono::Duration::seconds(120)));
    }
}
