use async_trait::async_trait;
use authkestra_engine::auth::state::Identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a stored refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
