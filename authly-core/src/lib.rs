use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod pkce;

/// A unified identity structure returned by all providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// The provider identifier (e.g., "github", "google")
    pub provider_id: String,
    /// The unique ID of the user within the provider's system
    pub external_id: String,
    /// The user's email address, if available and authorized
    pub email: Option<String>,
    /// The user's username or display name, if available
    pub username: Option<String>,
    /// Additional provider-specific attributes
    pub attributes: HashMap<String, String>,
}

/// Represents the tokens returned by an OAuth2 provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// The access token used for API requests
    pub access_token: String,
    /// The type of token (usually "Bearer")
    pub token_type: String,
    /// Seconds until the access token expires
    pub expires_in: Option<u64>,
    /// The refresh token used to obtain new access tokens
    pub refresh_token: Option<String>,
    /// The scopes granted by the user
    pub scope: Option<String>,
}

/// Errors that can occur during the authentication process.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// An error returned by the authentication provider
    #[error("Provider error: {0}")]
    Provider(String),
    /// The provided credentials (email/password) are invalid
    #[error("Invalid credentials")]
    InvalidCredentials,
    /// The authorization code is invalid or expired
    #[error("Invalid code")]
    InvalidCode,
    /// A network error occurred during communication with the provider
    #[error("Network error")]
    Network,
    /// An error occurred during session management
    #[error("Session error: {0}")]
    Session(String),
    /// An error occurred during token processing
    #[error("Token error: {0}")]
    Token(String),
    /// The CSRF state parameter does not match the expected value
    #[error("CSRF state mismatch")]
    CsrfMismatch,
}

/// Trait for an OAuth2-compatible provider.
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Helper to get the authorization URL.
    fn get_authorization_url(&self, state: &str, scopes: &[&str], code_challenge: Option<&str>) -> String;
    
    /// Exchange an authorization code for an Identity.
    async fn exchange_code_for_identity(&self, code: &str, code_verifier: Option<&str>) -> Result<(Identity, OAuthToken), AuthError>;

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

/// Trait for mapping a provider identity to a local user.
#[async_trait]
pub trait UserMapper: Send + Sync {
    type LocalUser: Send + Sync;

    /// Map an identity to a local user.
    /// This could involve creating a new user or finding an existing one.
    async fn map_user(&self, identity: &Identity) -> Result<Self::LocalUser, AuthError>;
}

#[async_trait]
impl UserMapper for () {
    type LocalUser = ();
    async fn map_user(&self, _identity: &Identity) -> Result<Self::LocalUser, AuthError> {
        Ok(())
    }
}

