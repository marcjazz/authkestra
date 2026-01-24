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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
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
    #[error("CSRF state mismatch")]
    CsrfMismatch,
}

/// Trait for an OAuth2-compatible provider.
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Helper to get the authorization URL.
    fn get_authorization_url(&self, state: &str, scopes: &[&str]) -> String;
    
    /// Exchange an authorization code for an Identity.
    async fn exchange_code_for_identity(&self, code: &str) -> Result<(Identity, OAuthToken), AuthError>;

    /// Refresh an access token using a refresh token.
    async fn refresh_token(&self, _refresh_token: &str) -> Result<OAuthToken, AuthError> {
        Err(AuthError::Provider("Token refresh not supported by this provider".into()))
    }

    /// Revoke an access token.
    async fn revoke_token(&self, _token: &str) -> Result<(), AuthError> {
        Err(AuthError::Provider("Token revocation not supported by this provider".into()))
    }
}

/// Trait for a Credentials-based provider (e.g., Email/Password).
#[async_trait]
pub trait CredentialsProvider: Send + Sync {
    type Credentials;
    
    /// Validate credentials and return an Identity.
    async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError>;
}
