use async_trait::async_trait;
use authkestra_engine::auth::state::Identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a stored refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RefreshToken {
    /// The actual token string (usually a cryptographically secure random string).
    pub token: String,
    /// The client this token was issued to.
    pub client_id: String,
    /// The authenticated identity (user) this token acts on behalf of.
    pub identity: Identity,
    /// The scopes granted to this token.
    pub scope: String,
    /// When this token expires.
    pub expires_at: DateTime<Utc>,
    /// The RFC 7638 thumbprint of the DPoP key this token is bound to
    /// (RFC 9449 §5), if the request that minted it presented a DPoP proof.
    ///
    /// `None` means this refresh token is an ordinary bearer token — no
    /// continuity is required or enforced on rotation. Once `Some`, RFC
    /// 9449 §5 requires every future `refresh_token` grant redeeming this
    /// token (and each token it rotates into) to present a fresh DPoP
    /// proof for this *same* key; a request that omits DPoP, or presents a
    /// proof for a different key, must be refused. Without this check, an
    /// exfiltrated DPoP-bound refresh token could simply be redeemed with
    /// the attacker's own key (or with no proof at all), defeating exactly
    /// the sender-constraining guarantee DPoP exists to provide for public
    /// clients (authkestra#274).
    pub jkt: Option<String>,
}

impl RefreshToken {
    /// Creates a new refresh token.
    ///
    /// `#[non_exhaustive]` blocks struct-literal construction from outside
    /// this crate, but `RefreshTokenStore` implementations must be able to
    /// reconstruct a token from their own storage — this is the seam that
    /// makes that possible (authkestra#268).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: String,
        client_id: String,
        identity: Identity,
        scope: String,
        expires_at: DateTime<Utc>,
        jkt: Option<String>,
    ) -> Self {
        Self {
            token,
            client_id,
            identity,
            scope,
            expires_at,
            jkt,
        }
    }
}

/// Storage interface for refresh tokens.
#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    /// Stores a newly issued refresh token.
    async fn store_token(&self, token: RefreshToken) -> Result<(), crate::error::OpError>;

    /// Retrieves a refresh token without consuming it.
    async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, crate::error::OpError>;

    /// Revokes a refresh token (and potentially its lineage).
    async fn revoke_token(&self, token: &str) -> Result<(), crate::error::OpError>;

    /// Atomically retrieves and revokes a refresh token.
    /// This prevents replay attacks by ensuring a token can only be successfully rotated once.
    async fn consume_token(
        &self,
        token: &str,
    ) -> Result<Option<RefreshToken>, crate::error::OpError>;
}

use authkestra_engine::store::{AtomicConsume, KvStore};
use std::time::Duration;

#[async_trait]
impl<S> RefreshTokenStore for S
where
    S: KvStore<RefreshToken> + AtomicConsume<RefreshToken>,
{
    async fn store_token(&self, token: RefreshToken) -> Result<(), crate::error::OpError> {
        let ttl = token
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        self.set(&token.token, token.clone(), ttl)
            .await
            .map_err(|_| crate::error::OpError::Storage)
    }

    async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, crate::error::OpError> {
        self.get(token)
            .await
            .map_err(|_| crate::error::OpError::Storage)
    }

    async fn revoke_token(&self, token: &str) -> Result<(), crate::error::OpError> {
        self.delete(token)
            .await
            .map_err(|_| crate::error::OpError::Storage)
    }

    async fn consume_token(
        &self,
        token: &str,
    ) -> Result<Option<RefreshToken>, crate::error::OpError> {
        self.consume(token)
            .await
            .map_err(|_| crate::error::OpError::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_engine::store::memory::MemoryStore;

    #[tokio::test]
    async fn test_refresh_token_store() {
        let store = MemoryStore::default();
        let code = RefreshToken::new(
            "code1".into(),
            "client1".into(),
            Identity {
                provider_id: "local".into(),
                external_id: "user1".into(),
                email: Some("user1@example.com".to_string()),
                username: None,
                attributes: Default::default(),
            },
            "openid".into(),
            Utc::now() + chrono::Duration::seconds(60),
            None,
        );

        // test store
        store.store_token(code.clone()).await.unwrap();

        // test get
        let retrieved = store.get_token("code1").await.unwrap().unwrap();
        assert_eq!(retrieved.client_id, "client1");

        // test consume
        let consumed = store.consume_token("code1").await.unwrap().unwrap();
        assert_eq!(consumed.client_id, "client1");

        // second consume should fail
        assert!(store.consume_token("code1").await.unwrap().is_none());

        // test revoke
        store.store_token(code.clone()).await.unwrap();
        store.revoke_token("code1").await.unwrap();
        assert!(store.get_token("code1").await.unwrap().is_none());
    }
}
