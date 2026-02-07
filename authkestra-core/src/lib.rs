//! # Authkestra Core
//!
//! `authkestra-core` provides the foundational traits and types for the Authkestra authentication framework.
//! It defines the core abstractions for identities, authentication flows and providers that are used across the entire ecosystem.

#![warn(missing_docs)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// PKCE (Proof Key for Code Exchange) utilities.
pub mod pkce;

/// Errors that can occur during the authentication process.
pub mod error;
use crate::error::AuthError;

/// A unified identity structure returned by all providers.
pub mod state;
use crate::state::{Identity, OAuthToken};

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
impl UserMapper for () {
    type LocalUser = ();
    async fn map_user(&self, _identity: &Identity) -> Result<Self::LocalUser, AuthError> {
        Ok(())
    }
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
