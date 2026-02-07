//! # Authkestra Core
//!
//! `authkestra-core` provides the foundational traits and types for the Authkestra authentication framework.
//! It defines the core abstractions for identities, sessions, and providers that are used across the entire ecosystem.
//!
//! ## Key Components
//!
//! - **[`Identity`]**: A unified structure representing a user's identity across different providers.
//! - **[`SessionStore`]**: A trait for implementing session persistence (e.g., in-memory, Redis, SQL).
//! - **[`OAuthProvider`]**: A trait for implementing OAuth2 and OpenID Connect providers.
//! - **[`AuthError`]**: A comprehensive error type for authentication-related issues.

#![warn(missing_docs)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PKCE (Proof Key for Code Exchange) utilities.
pub mod pkce;

/// Discovery utilities for OAuth2 providers.
pub mod discovery;

/// Controls whether a cookie is sent with cross-site requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SameSite {
    /// The cookie is sent with "safe" cross-site requests (e.g., following a link).
    Lax,
    /// The cookie is only sent for same-site requests.
    Strict,
    /// The cookie is sent with all requests, including cross-site. Requires `Secure`.
    None,
}

/// Configuration for session cookies.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The name of the session cookie.
    pub cookie_name: String,
    /// Whether the cookie should only be sent over HTTPS.
    pub secure: bool,
    /// Whether the cookie should be inaccessible to client-side scripts.
    pub http_only: bool,
    /// The `SameSite` attribute for the cookie.
    pub same_site: SameSite,
    /// The path for which the cookie is valid.
    pub path: String,
    /// The maximum age of the session.
    pub max_age: Option<chrono::Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: "authkestra_session".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age: Some(chrono::Duration::hours(24)),
        }
    }
}

/// Represents an active user session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier.
    pub id: String,
    /// The identity associated with this session.
    pub identity: Identity,
    /// When the session expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Trait for implementing session persistence.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// Load a session by its ID.
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError>;
    /// Save or update a session.
    async fn save_session(&self, session: &Session) -> Result<(), AuthError>;
    /// Delete a session by its ID.
    async fn delete_session(&self, id: &str) -> Result<(), AuthError>;
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// The refresh token used to obtain new access tokens
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The scopes granted by the user
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The OIDC ID Token
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
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
    /// An error occurred during OIDC discovery
    #[error("Discovery error: {0}")]
    Discovery(String),
}

/// Trait for an OAuth2-compatible provider.
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Get the provider identifier.
    fn provider_id(&self) -> &str;

    /// Helper to get the authorization URL.
    fn get_authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_challenge: Option<&str>,
    ) -> String;

    /// Exchange an authorization code for an Identity.
    async fn exchange_code_for_identity(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError>;

    /// Refresh an access token using a refresh token.
    async fn refresh_token(&self, _refresh_token: &str) -> Result<OAuthToken, AuthError> {
        Err(AuthError::Provider(
            "Token refresh not supported by this provider".into(),
        ))
    }

    /// Revoke an access token.
    async fn revoke_token(&self, _token: &str) -> Result<(), AuthError> {
        Err(AuthError::Provider(
            "Token revocation not supported by this provider".into(),
        ))
    }
}

/// Trait for a Credentials-based provider (e.g., Email/Password).
#[async_trait]
pub trait CredentialsProvider: Send + Sync {
    /// The type of credentials accepted by this provider.
    type Credentials;

    /// Validate credentials and return an Identity.
    async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError>;
}

/// Trait for mapping a provider identity to a local user.
#[async_trait]
pub trait UserMapper: Send + Sync {
    /// The type of the local user object.
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

/// Orchestrates the Authorization Code flow.
#[async_trait]
pub trait ErasedOAuthFlow: Send + Sync {
    /// Get the provider identifier.
    fn provider_id(&self) -> String;
    /// Generates the redirect URL and CSRF state.
    fn initiate_login(&self, scopes: &[&str], pkce_challenge: Option<&str>) -> (String, String);
    /// Completes the flow by exchanging the code.
    async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError>;
}

#[async_trait]
impl<T: ErasedOAuthFlow + ?Sized> ErasedOAuthFlow for std::sync::Arc<T> {
    fn provider_id(&self) -> String {
        (**self).provider_id()
    }

    fn initiate_login(&self, scopes: &[&str], pkce_challenge: Option<&str>) -> (String, String) {
        (**self).initiate_login(scopes, pkce_challenge)
    }

    async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        (**self)
            .finalize_login(code, received_state, expected_state, pkce_verifier)
            .await
    }
}

#[async_trait]
impl<T: ErasedOAuthFlow + ?Sized> ErasedOAuthFlow for Box<T> {
    fn provider_id(&self) -> String {
        (**self).provider_id()
    }

    fn initiate_login(&self, scopes: &[&str], pkce_challenge: Option<&str>) -> (String, String) {
        (**self).initiate_login(scopes, pkce_challenge)
    }

    async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        (**self)
            .finalize_login(code, received_state, expected_state, pkce_verifier)
            .await
    }
}

/// Represents an error response from an OAuth2 provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthErrorResponse {
    /// The error code.
    pub error: String,
    /// A human-readable ASCII text description of the error.
    pub error_description: Option<String>,
}

/// An in-memory implementation of [`SessionStore`].
///
/// **Note**: This store is not persistent and will be cleared when the application restarts.
/// It is primarily intended for development and testing.
#[derive(Default)]
pub struct MemoryStore {
    sessions: std::sync::Mutex<HashMap<String, Session>>,
}

impl MemoryStore {
    /// Create a new, empty `MemoryStore`.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }
    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id.clone(), session.clone());
        Ok(())
    }
    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        self.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}
