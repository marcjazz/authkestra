use async_trait::async_trait;
use authkestra_engine::auth::state::Identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

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

/// A minimal in-memory `RefreshTokenStore` for development and tests.
#[derive(Default)]
pub struct InMemoryRefreshTokenStore {
    tokens: RwLock<HashMap<String, RefreshToken>>,
}

impl InMemoryRefreshTokenStore {
    /// Creates a new, empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RefreshTokenStore for InMemoryRefreshTokenStore {
    async fn store_token(&self, token: RefreshToken) -> Result<(), crate::error::OpError> {
        self.tokens
            .write()
            .expect("lock poisoned")
            .insert(token.token.clone(), token);
        Ok(())
    }

    async fn get_token(&self, token: &str) -> Result<Option<RefreshToken>, crate::error::OpError> {
        Ok(self
            .tokens
            .read()
            .expect("lock poisoned")
            .get(token)
            .cloned())
    }

    async fn revoke_token(&self, token: &str) -> Result<(), crate::error::OpError> {
        self.tokens.write().expect("lock poisoned").remove(token);
        Ok(())
    }

    async fn consume_token(
        &self,
        token: &str,
    ) -> Result<Option<RefreshToken>, crate::error::OpError> {
        let mut map = self.tokens.write().expect("lock poisoned");
        Ok(map.remove(token))
    }
}
