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
use authkestra_session::{Session, SessionConfig, SessionStore};
pub use chrono;

/// Trait for components that can be used as a session store.
pub trait SessionStoreState: Send + Sync + 'static {
    /// Returns the session store if configured.
    fn get_store(&self) -> Arc<dyn SessionStore>;
}

impl SessionStoreState for Configured<Arc<dyn SessionStore>> {
    fn get_store(&self) -> Arc<dyn SessionStore> {
        self.0.clone()
    }
}

/// Trait for components that can be used as a token manager.
pub trait TokenManagerState: Send + Sync + 'static {
    /// Returns the token manager if configured.
    fn get_manager(&self) -> Arc<TokenManager>;
}

impl TokenManagerState for Configured<Arc<TokenManager>> {
    fn get_manager(&self) -> Arc<TokenManager> {
        self.0.clone()
    }
}
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

/// Marker for a missing component in the typestate pattern.
#[derive(Clone, Default)]
pub struct Missing;

/// Marker for a configured component in the typestate pattern.
#[derive(Clone)]
pub struct Configured<T>(pub T);

/// The unified Authkestra service.
#[derive(Clone)]
pub struct Authkestra<S = Missing, T = Missing> {
    /// Map of registered OAuth providers.
    pub providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    /// The session storage backend.
    pub session_store: S,
    /// Configuration for session cookies.
    pub session_config: SessionConfig,
    /// Manager for JWT signing and verification.
    pub token_manager: T,
    // Additional configuration options can be added here in the future.
    // For example. rate limiting, logging, etc.
    // pub config: AuthkestraConfig
}

impl Authkestra<Missing, Missing> {
    /// Create a new [`AuthkestraBuilder`] to configure the service.
    pub fn builder() -> AuthkestraBuilder<Missing, Missing> {
        AuthkestraBuilder::default()
    }
}

impl<T> Authkestra<Configured<Arc<dyn SessionStore>>, T> {
    /// Create a new session for the given identity.
    pub async fn create_session(&self, identity: Identity) -> Result<Session, AuthError> {
        let session_duration = self
            .session_config
            .max_age
            .unwrap_or(chrono::Duration::hours(24));
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            identity,
            expires_at: chrono::Utc::now() + session_duration,
        };

        self.session_store
            .0
            .save_session(&session)
            .await
            .map_err(|e| AuthError::Session(e.to_string()))?;

        Ok(session)
    }
}

impl<S> Authkestra<S, Configured<Arc<TokenManager>>> {
    /// Issue a JWT for the given identity.
    pub fn issue_token(
        &self,
        identity: Identity,
        expires_in_secs: u64,
    ) -> Result<String, AuthError> {
        self.token_manager
            .0
            .issue_user_token(identity, expires_in_secs, None)
            .map_err(|e| AuthError::Token(e.to_string()))
    }
}

/// A builder for configuring and creating an [`Authkestra`] instance.
pub struct AuthkestraBuilder<S, T> {
    providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    session_store: S,
    session_config: SessionConfig,
    token_manager: T,
}

impl Default for AuthkestraBuilder<Missing, Missing> {
    fn default() -> Self {
        Self {
            providers: HashMap::new(),
            session_store: Missing,
            session_config: SessionConfig::default(),
            token_manager: Missing,
        }
    }
}

impl<S, T> AuthkestraBuilder<S, T> {
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
    pub fn session_store(
        self,
        store: Arc<dyn SessionStore>,
    ) -> AuthkestraBuilder<Configured<Arc<dyn SessionStore>>, T> {
        AuthkestraBuilder {
            providers: self.providers,
            session_store: Configured(store),
            session_config: self.session_config,
            token_manager: self.token_manager,
        }
    }

    /// Set the token manager.
    pub fn token_manager(
        self,
        manager: Arc<TokenManager>,
    ) -> AuthkestraBuilder<S, Configured<Arc<TokenManager>>> {
        AuthkestraBuilder {
            providers: self.providers,
            session_store: self.session_store,
            session_config: self.session_config,
            token_manager: Configured(manager),
        }
    }

    /// Set the JWT secret for the default token manager.
    pub fn jwt_secret(self, secret: &[u8]) -> AuthkestraBuilder<S, Configured<Arc<TokenManager>>> {
        self.token_manager(Arc::new(TokenManager::new(secret, None)))
    }

    /// Build the [`Authkestra`] instance.
    pub fn build(self) -> Authkestra<S, T> {
        Authkestra {
            providers: self.providers,
            session_store: self.session_store,
            session_config: self.session_config,
            token_manager: self.token_manager,
        }
    }
}

impl<T> AuthkestraBuilder<Configured<Arc<dyn SessionStore>>, T> {
    /// Set the session configuration.
    ///
    /// This is only available if a session store is configured.
    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }
}

impl<S> AuthkestraBuilder<S, Configured<Arc<TokenManager>>> {
    /// Set the JWT issuer for the token manager.
    ///
    /// This is only available if a token manager is configured.
    pub fn jwt_issuer(self, issuer: impl Into<String>) -> Self {
        let manager = Arc::new((*self.token_manager.0).clone().with_issuer(issuer.into()));
        self.token_manager(manager)
    }
}

/// Trait for Authkestra instances that have a session store configured.
pub trait HasSessionStore {
    /// Returns the session store.
    fn session_store(&self) -> Arc<dyn SessionStore>;
}

impl<T> HasSessionStore for Authkestra<Configured<Arc<dyn SessionStore>>, T> {
    fn session_store(&self) -> Arc<dyn SessionStore> {
        self.session_store.0.clone()
    }
}

/// Trait for Authkestra instances that have a token manager configured.
pub trait HasTokenManager {
    /// Returns the token manager.
    fn token_manager(&self) -> Arc<TokenManager>;
}

impl<S> HasTokenManager for Authkestra<S, Configured<Arc<TokenManager>>> {
    fn token_manager(&self) -> Arc<TokenManager> {
        self.token_manager.0.clone()
    }
}

/// Marker for a configured session store.
pub type HasSessionStoreMarker = Configured<Arc<dyn SessionStore>>;
/// Marker for a missing session store.
pub type NoSessionStoreMarker = Missing;
/// Marker for a configured token manager.
pub type HasTokenManagerMarker = Configured<Arc<TokenManager>>;
/// Marker for a missing token manager.
pub type NoTokenManagerMarker = Missing;

/// Authkestra with session support only.
///
/// This type is typically used in traditional web applications where the server
/// manages user sessions.
pub type StatefullAuthkestra = Authkestra<HasSessionStoreMarker, NoTokenManagerMarker>;

/// Authkestra with token support only
///
/// A Resource Server (API) that validates tokens.
/// This type is used for APIs that need to verify JWTs issued by an authorization server.
pub type StatelessAuthkestra = Authkestra<NoSessionStoreMarker, HasTokenManagerMarker>;

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
