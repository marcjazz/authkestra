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

pub use authkestra_core::ErasedOAuthFlow;
use authkestra_core::{
    error::AuthError, state::Identity, CredentialsProvider, OAuthProvider, UserMapper,
};
use authkestra_session::{MemoryStore, SessionConfig, SessionStore};
use authkestra_token::TokenManager;
use std::collections::HashMap;
use std::sync::Arc;

/// Client Credentials flow implementation.
pub mod client_credentials_flow;
/// Device Authorization flow implementation.
pub mod device_flow;
/// OAuth2 Authorization Code flow implementation.
pub mod oauth2;

pub use client_credentials_flow::ClientCredentialsFlow;
pub use device_flow::{DeviceAuthorizationResponse, DeviceFlow};
pub use oauth2::OAuth2Flow;

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
                .unwrap_or_else(|| Arc::new(MemoryStore::default())),
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
