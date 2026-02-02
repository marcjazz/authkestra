//! # Authkestra Flow
//!
//! `authkestra-flow` orchestrates authentication flows, such as OAuth2 Authorization Code,
//! PKCE, Client Credentials, and Device Flow. It acts as the bridge between the core traits
//! and the framework-specific adapters.
//!
//! ## Key Components
//!
//! - **[`OAuth2Flow`]**: Orchestrates the standard OAuth2 Authorization Code flow.
//! - **[`Authkestra`]**: The main service that holds providers, session stores, and token managers.
//! - **[`AuthkestraBuilder`]**: A builder for configuring and creating an [`Authkestra`] instance.
//! - **[`CredentialsFlow`]**: Orchestrates direct credentials-based authentication (e.g., email/password).

#![warn(missing_docs)]

use async_trait::async_trait;
use authkestra_core::{
    AuthError, CredentialsProvider, Identity, OAuthProvider, OAuthToken, SessionConfig,
    SessionStore, UserMapper,
};
use authkestra_token::TokenManager;
use std::collections::HashMap;
use std::sync::Arc;

/// Client Credentials flow implementation.
pub mod client_credentials_flow;
/// Device Authorization flow implementation.
pub mod device_flow;

pub use client_credentials_flow::ClientCredentialsFlow;
pub use device_flow::{DeviceAuthorizationResponse, DeviceFlow};

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
    ) -> Result<(authkestra_core::Identity, authkestra_core::OAuthToken), authkestra_core::AuthError>;
}

/// Orchestrates the standard OAuth2 Authorization Code flow.
pub struct OAuth2Flow<P: OAuthProvider, M: UserMapper = ()> {
    provider: P,
    mapper: Option<M>,
}

#[async_trait]
impl<P: OAuthProvider, M: UserMapper> ErasedOAuthFlow for OAuth2Flow<P, M> {
    fn provider_id(&self) -> String {
        self.provider.provider_id().to_string()
    }

    fn initiate_login(&self, scopes: &[&str], pkce_challenge: Option<&str>) -> (String, String) {
        self.initiate_login(scopes, pkce_challenge)
    }

    async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(authkestra_core::Identity, authkestra_core::OAuthToken), authkestra_core::AuthError>
    {
        let (identity, token, _) = self
            .finalize_login(code, received_state, expected_state, pkce_verifier)
            .await?;
        Ok((identity, token))
    }
}

impl<P: OAuthProvider> OAuth2Flow<P, ()> {
    /// Create a new `OAuth2Flow` with the given provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            mapper: None,
        }
    }
}

impl<P: OAuthProvider, M: UserMapper> OAuth2Flow<P, M> {
    /// Create a new `OAuth2Flow` with the given provider and user mapper.
    pub fn with_mapper(provider: P, mapper: M) -> Self {
        Self {
            provider,
            mapper: Some(mapper),
        }
    }

    /// Generates the redirect URL and CSRF state.
    pub fn initiate_login(
        &self,
        scopes: &[&str],
        pkce_challenge: Option<&str>,
    ) -> (String, String) {
        let state = uuid::Uuid::new_v4().to_string();
        let url = self
            .provider
            .get_authorization_url(&state, scopes, pkce_challenge);
        (url, state)
    }

    /// Completes the flow by exchanging the code.
    /// If a mapper is provided, it will also map the identity to a local user.
    pub async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken, Option<M::LocalUser>), AuthError> {
        if received_state != expected_state {
            return Err(AuthError::CsrfMismatch);
        }
        let (identity, token) = self
            .provider
            .exchange_code_for_identity(code, pkce_verifier)
            .await?;

        let local_user = if let Some(mapper) = &self.mapper {
            Some(mapper.map_user(&identity).await?)
        } else {
            None
        };

        Ok((identity, token, local_user))
    }

    /// Refresh an access token using a refresh token.
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthToken, AuthError> {
        self.provider.refresh_token(refresh_token).await
    }

    /// Revoke an access token.
    pub async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        self.provider.revoke_token(token).await
    }
}

/// The unified Authkestra service.
#[derive(Clone)]
pub struct Authkestra {
    /// Map of registered OAuth providers.
    pub providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    /// The session storage backend.
    pub session_store: Arc<dyn SessionStore>,
    /// Configuration for session cookies.
    pub session_config: SessionConfig,
    /// Manager for JWT signing and verification.
    pub token_manager: Arc<TokenManager>,
}

impl Authkestra {
    /// Create a new [`AuthkestraBuilder`] to configure the service.
    pub fn builder() -> AuthkestraBuilder {
        AuthkestraBuilder::default()
    }
}

/// A builder for configuring and creating an [`Authkestra`] instance.
#[derive(Default)]
pub struct AuthkestraBuilder {
    providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    session_store: Option<Arc<dyn SessionStore>>,
    session_config: SessionConfig,
    token_manager: Option<Arc<TokenManager>>,
}

impl AuthkestraBuilder {
    /// Register an OAuth provider flow.
    pub fn provider<P, M>(mut self, flow: OAuth2Flow<P, M>) -> Self
    where
        P: OAuthProvider + 'static,
        M: UserMapper + 'static,
    {
        let id = flow.provider_id();
        self.providers.insert(id, Arc::new(flow));
        self
    }

    /// Set the session store.
    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.session_store = Some(store);
        self
    }

    /// Set the session configuration.
    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }

    /// Set the token manager.
    pub fn token_manager(mut self, manager: Arc<TokenManager>) -> Self {
        self.token_manager = Some(manager);
        self
    }

    /// Build the [`Authkestra`] instance.
    pub fn build(self) -> Authkestra {
        Authkestra {
            providers: self.providers,
            session_store: self
                .session_store
                .unwrap_or_else(|| Arc::new(authkestra_core::MemoryStore::default())), // Wait, MemoryStore is in authkestra-session!
            session_config: self.session_config,
            token_manager: self
                .token_manager
                .unwrap_or_else(|| Arc::new(TokenManager::new(b"secret", None))),
        }
    }
}

/// Orchestrates a direct credentials flow.
pub struct CredentialsFlow<P: CredentialsProvider, M: UserMapper = ()> {
    provider: P,
    mapper: Option<M>,
}

impl<P: CredentialsProvider> CredentialsFlow<P, ()> {
    /// Create a new `CredentialsFlow` with the given provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            mapper: None,
        }
    }
}

impl<P: CredentialsProvider, M: UserMapper> CredentialsFlow<P, M> {
    /// Create a new `CredentialsFlow` with the given provider and user mapper.
    pub fn with_mapper(provider: P, mapper: M) -> Self {
        Self {
            provider,
            mapper: Some(mapper),
        }
    }

    /// Authenticate using the given credentials.
    pub async fn authenticate(
        &self,
        creds: P::Credentials,
    ) -> Result<(Identity, Option<M::LocalUser>), AuthError> {
        let identity = self.provider.authenticate(creds).await?;

        let local_user = if let Some(mapper) = &self.mapper {
            Some(mapper.map_user(&identity).await?)
        } else {
            None
        };

        Ok((identity, local_user))
    }
}
