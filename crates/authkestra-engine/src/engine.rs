use crate::auth::session::{Session, SessionConfig, SessionStore};
use crate::auth::{AuthError, ErasedOAuthFlow, Identity};
#[cfg(feature = "token")]
use crate::token::TokenManager;
use std::collections::HashMap;
use std::sync::Arc;

/// Marker for a missing component in the typestate pattern.
#[derive(Clone, Default, Debug)]
pub struct Missing;

/// Marker for a configured component in the typestate pattern.
#[derive(Clone, Debug)]
pub struct Configured<T>(pub T);

/// Trait for the session store state in the `AuthEngine`.
pub trait SessionStoreState: Send + Sync + Clone {
    /// Returns the session store if configured.
    fn get_store(&self) -> Arc<dyn SessionStore>;
}

impl SessionStoreState for Configured<Arc<dyn SessionStore>> {
    fn get_store(&self) -> Arc<dyn SessionStore> {
        self.0.clone()
    }
}

/// Trait for the token manager state in the `AuthEngine`.
pub trait TokenManagerState: Send + Sync + Clone {
    /// Returns the token manager if configured.
    #[cfg(feature = "token")]
    fn get_manager(&self) -> Arc<TokenManager>;
}

#[cfg(feature = "token")]
impl TokenManagerState for Configured<Arc<TokenManager>> {
    fn get_manager(&self) -> Arc<TokenManager> {
        self.0.clone()
    }
}

/// The central orchestrator for Authkestra.
///
/// `AuthEngine` ties together authentication methods, session management, and flows.
/// It is constructed using the [`AuthEngineBuilder`] which uses the Typestate pattern
/// to ensure that certain methods are only available when the necessary components are configured.
pub struct AuthEngine<S = Missing, T = Missing> {
    /// Map of registered OAuth providers.
    pub providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    /// The session storage backend.
    pub session_store: S,
    /// Configuration for session cookies.
    pub session_config: SessionConfig,
    /// Manager for JWT signing and verification.
    #[cfg(feature = "token")]
    pub token_manager: T,
}

impl<S, T> Clone for AuthEngine<S, T>
where
    S: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            providers: self.providers.clone(),
            session_store: self.session_store.clone(),
            session_config: self.session_config.clone(),
            #[cfg(feature = "token")]
            token_manager: self.token_manager.clone(),
        }
    }
}

impl AuthEngine<Missing, Missing> {
    /// Start building a new `AuthEngine`.
    pub fn builder() -> AuthEngineBuilder<Missing, Missing> {
        AuthEngineBuilder {
            providers: HashMap::new(),
            session_store: Missing,
            session_config: SessionConfig::default(),
            #[cfg(feature = "token")]
            token_manager: Missing,
        }
    }
}

/// A builder for configuring and creating an [`AuthEngine`] instance.
pub struct AuthEngineBuilder<S = Missing, T = Missing> {
    providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    session_store: S,
    session_config: SessionConfig,
    #[cfg(feature = "token")]
    token_manager: T,
}

impl<S, T> AuthEngineBuilder<S, T> {
    /// Register an OAuth provider flow.
    pub fn provider<F>(mut self, flow: F) -> Self
    where
        F: ErasedOAuthFlow + 'static,
    {
        let id = flow.provider_id();
        self.providers.insert(id, Arc::new(flow));
        self
    }

    /// Set the session store.
    pub fn session_store(
        self,
        store: Arc<dyn SessionStore>,
    ) -> AuthEngineBuilder<Configured<Arc<dyn SessionStore>>, T> {
        AuthEngineBuilder {
            providers: self.providers,
            session_store: Configured(store),
            session_config: self.session_config,
            #[cfg(feature = "token")]
            token_manager: self.token_manager,
        }
    }

    /// Set the token manager.
    #[cfg(feature = "token")]
    pub fn token_manager(
        self,
        manager: Arc<TokenManager>,
    ) -> AuthEngineBuilder<S, Configured<Arc<TokenManager>>> {
        AuthEngineBuilder {
            providers: self.providers,
            session_store: self.session_store,
            session_config: self.session_config,
            token_manager: Configured(manager),
        }
    }

    /// Set the JWT secret for the default token manager.
    #[cfg(feature = "token")]
    pub fn jwt_secret(self, secret: &[u8]) -> AuthEngineBuilder<S, Configured<Arc<TokenManager>>> {
        self.token_manager(Arc::new(TokenManager::new(secret, None)))
    }

    /// Set the session configuration.
    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }

    /// Build the `AuthEngine`.
    pub fn build(self) -> AuthEngine<S, T> {
        AuthEngine {
            providers: self.providers,
            session_store: self.session_store,
            session_config: self.session_config,
            #[cfg(feature = "token")]
            token_manager: self.token_manager,
        }
    }
}

// Methods available only when a session store is present
impl<T> AuthEngine<Configured<Arc<dyn SessionStore>>, T> {
    /// Get the session store.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        self.session_store.0.clone()
    }

    /// Create a new session for the given identity.
    #[tracing::instrument(skip(self, identity), fields(user_id = %identity.external_id))]
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

        tracing::debug!(session_id = %session.id, "creating new session");

        self.session_store
            .0
            .save_session(&session)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to save session");
                AuthError::Session(e.to_string())
            })?;

        tracing::info!(session_id = %session.id, "session created successfully");
        Ok(session)
    }
}

#[cfg(feature = "token")]
impl<S> AuthEngine<S, Configured<Arc<TokenManager>>> {
    /// Get the token manager.
    pub fn token_manager(&self) -> Arc<TokenManager> {
        self.token_manager.0.clone()
    }

    /// Issue a JWT for the given identity.
    #[tracing::instrument(skip(self, identity), fields(user_id = %identity.external_id))]
    pub fn issue_token(
        &self,
        identity: Identity,
        expires_in_secs: u64,
    ) -> Result<String, AuthError> {
        tracing::debug!("issuing token for user");
        self.token_manager
            .0
            .issue_user_token(identity, expires_in_secs, None, None)
            .map_err(|e| {
                tracing::error!(error = %e, "failed to issue token");
                AuthError::Token(e.to_string())
            })
            .inspect(|_| {
                tracing::info!("token issued successfully");
            })
    }
}

/// Trait for Authkestra instances that have a session store configured.
pub trait HasSessionStore {
    /// Returns the session store.
    fn session_store(&self) -> Arc<dyn SessionStore>;
}

impl<T> HasSessionStore for AuthEngine<Configured<Arc<dyn SessionStore>>, T> {
    fn session_store(&self) -> Arc<dyn SessionStore> {
        self.session_store.0.clone()
    }
}

/// Trait for Authkestra instances that have a token manager configured.
#[cfg(feature = "token")]
pub trait HasTokenManager {
    /// Returns the token manager.
    fn token_manager(&self) -> Arc<TokenManager>;
}

#[cfg(feature = "token")]
impl<S> HasTokenManager for AuthEngine<S, Configured<Arc<TokenManager>>> {
    fn token_manager(&self) -> Arc<TokenManager> {
        self.token_manager.0.clone()
    }
}

/// Marker for a configured session store.
pub type HasSessionStoreMarker = Configured<Arc<dyn SessionStore>>;
/// Marker for a missing session store.
pub type NoSessionStoreMarker = Missing;

#[cfg(feature = "token")]
/// Marker for a configured token manager.
pub type HasTokenManagerMarker = Configured<Arc<TokenManager>>;
#[cfg(feature = "token")]
/// Marker for a missing token manager.
pub type NoTokenManagerMarker = Missing;

/// Authkestra with session support only.
pub type StatefulAuthEngine = AuthEngine<HasSessionStoreMarker, Missing>;
pub type StatefullAuthkestra = StatefulAuthEngine;

#[cfg(feature = "token")]
/// Authkestra with token support only.
pub type StatelessAuthEngine = AuthEngine<Missing, HasTokenManagerMarker>;
#[cfg(feature = "token")]
pub type StatelessAuthkestra = StatelessAuthEngine;

/// Deprecated alias for `AuthEngine`.
pub type Authkestra<S = Missing, T = Missing> = AuthEngine<S, T>;
