use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A unified identity structure returned by all providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub provider_id: String, // e.g., "github"
    pub external_id: String, // e.g., "12345"
    pub email: Option<String>,
    pub username: Option<String>,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Invalid code")]
    InvalidCode,
    #[error("Network error")]
    Network,
    #[error("Session error: {0}")]
    Session(String),
    #[error("Token error: {0}")]
    Token(String),
}

/// Trait for an OAuth2-compatible provider.
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Helper to get the authorization URL.
    fn get_authorization_url(&self, state: &str, scopes: &[&str]) -> String;
    
    /// Exchange an authorization code for an Identity.
    async fn exchange_code_for_identity(&self, code: &str) -> Result<Identity, AuthError>;
}

/// Trait for a Credentials-based provider (e.g., Email/Password).
#[async_trait]
pub trait CredentialsProvider: Send + Sync {
    type Credentials;
    
    /// Validate credentials and return an Identity.
    async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError>;
}
