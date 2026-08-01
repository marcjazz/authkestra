use crate::auth::session::{Session, SessionConfig, SessionStore};
use crate::auth::{AuthError, AuthInput, AuthMethod, AuthResult, ErasedOAuthFlow, Identity};
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

/// Trait for the session store state in the `Engine`.
pub trait SessionStoreState: Send + Sync + Clone {
    /// Returns the session store if configured.
    fn get_store(&self) -> Arc<dyn SessionStore>;
}

impl SessionStoreState for Configured<Arc<dyn SessionStore>> {
    fn get_store(&self) -> Arc<dyn SessionStore> {
        self.0.clone()
    }
}

/// Trait for the token manager state in the `Engine`.
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

/// The central orchestrator for Engine.
///
/// `Engine` ties together authentication methods, session management, and flows.
/// It is constructed using the [`EngineBuilder`] which uses the Typestate pattern
/// to ensure that certain methods are only available when the necessary components are configured.
pub struct Engine<S = Missing, T = Missing> {
    /// Map of registered OAuth providers.
    pub providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    /// Map of registered local authentication methods.
    pub auth_methods: HashMap<String, Arc<dyn AuthMethod>>,
    /// Map of methods explicitly registered for step-up (MFA) use.
    pub mfa_methods: HashMap<String, Arc<dyn AuthMethod>>,
    /// Internal secret for signing temporary MFA JWT tokens.
    pub mfa_jwt_secret: [u8; 32],
    /// The session storage backend.
    pub session_store: S,
    /// Configuration for session cookies.
    pub session_config: SessionConfig,
    /// Manager for JWT signing and verification.
    #[cfg(feature = "token")]
    pub token_manager: T,
}

impl<S, T> Clone for Engine<S, T>
where
    S: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            providers: self.providers.clone(),
            auth_methods: self.auth_methods.clone(),
            mfa_methods: self.mfa_methods.clone(),
            mfa_jwt_secret: self.mfa_jwt_secret,
            session_store: self.session_store.clone(),
            session_config: self.session_config.clone(),
            #[cfg(feature = "token")]
            token_manager: self.token_manager.clone(),
        }
    }
}

impl Engine<Missing, Missing> {
    /// Start building a new `Engine`.
    pub fn builder() -> EngineBuilder<Missing, Missing> {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret);

        EngineBuilder {
            providers: HashMap::new(),
            auth_methods: HashMap::new(),
            mfa_methods: HashMap::new(),
            mfa_jwt_secret: secret,
            session_store: Missing,
            session_config: SessionConfig::default(),
            #[cfg(feature = "token")]
            token_manager: Missing,
        }
    }
}

/// A builder for configuring and creating an [`Engine`] instance.
pub struct EngineBuilder<S = Missing, T = Missing> {
    providers: HashMap<String, Arc<dyn ErasedOAuthFlow>>,
    auth_methods: HashMap<String, Arc<dyn AuthMethod>>,
    mfa_methods: HashMap<String, Arc<dyn AuthMethod>>,
    mfa_jwt_secret: [u8; 32],
    session_store: S,
    session_config: SessionConfig,
    #[cfg(feature = "token")]
    token_manager: T,
}

impl<S, T> EngineBuilder<S, T> {
    /// Register an OAuth provider flow.
    pub fn provider<F>(mut self, flow: F) -> Self
    where
        F: ErasedOAuthFlow + 'static,
    {
        let id = flow.provider_id();
        self.providers.insert(id, Arc::new(flow));
        self
    }

    /// Register a local authentication method.
    pub fn with_auth_method<M>(mut self, method: M) -> Self
    where
        M: AuthMethod + 'static,
    {
        self.auth_methods
            .insert(method.name().to_string(), Arc::new(method));
        self
    }

    /// Register a local authentication method to be used EXCLUSIVELY for step-up MFA challenges.
    pub fn with_mfa_method<M>(mut self, method: M) -> Self
    where
        M: AuthMethod + 'static,
    {
        self.mfa_methods
            .insert(method.name().to_string(), Arc::new(method));
        self
    }

    /// Register the TOTP authentication method.
    #[cfg(feature = "totp")]
    pub fn with_totp<C>(self, store: C) -> Self
    where
        C: crate::CredentialStore + 'static,
    {
        self.with_auth_method(crate::auth::totp::TotpAuthMethod::new(store))
    }

    /// Register the WebAuthn authentication method.
    #[cfg(feature = "webauthn")]
    pub fn with_webauthn<C>(self, webauthn: Arc<webauthn_rs::prelude::Webauthn>, store: C) -> Self
    where
        C: crate::CredentialStore + 'static,
    {
        self.with_auth_method(crate::auth::webauthn::WebAuthnAuthMethod::new(
            webauthn, store,
        ))
    }

    /// Set the session store.
    pub fn session_store(
        self,
        store: Arc<dyn SessionStore>,
    ) -> EngineBuilder<Configured<Arc<dyn SessionStore>>, T> {
        EngineBuilder {
            providers: self.providers,
            auth_methods: self.auth_methods,
            mfa_methods: self.mfa_methods,
            mfa_jwt_secret: self.mfa_jwt_secret,
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
    ) -> EngineBuilder<S, Configured<Arc<TokenManager>>> {
        EngineBuilder {
            providers: self.providers,
            auth_methods: self.auth_methods,
            mfa_methods: self.mfa_methods,
            mfa_jwt_secret: self.mfa_jwt_secret,
            session_store: self.session_store,
            session_config: self.session_config,
            token_manager: Configured(manager),
        }
    }

    /// Set the JWT secret for the default token manager.
    #[cfg(feature = "token")]
    pub fn jwt_secret(self, secret: &[u8]) -> EngineBuilder<S, Configured<Arc<TokenManager>>> {
        self.token_manager(Arc::new(TokenManager::new(secret, None)))
    }

    /// Set the session configuration.
    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }

    /// Build the `Engine`.
    pub fn build(self) -> Engine<S, T> {
        Engine {
            providers: self.providers,
            auth_methods: self.auth_methods,
            mfa_methods: self.mfa_methods,
            mfa_jwt_secret: self.mfa_jwt_secret,
            session_store: self.session_store,
            session_config: self.session_config,
            #[cfg(feature = "token")]
            token_manager: self.token_manager,
        }
    }
}

impl<S, T> Engine<S, T> {
    /// Attempt to authenticate a user.
    /// Returns `AuthResult::Success` if authentication is fully complete,
    /// or `AuthResult::MfaRequired` if a second factor is needed.
    pub async fn authenticate(&self, input: AuthInput) -> Result<AuthResult, AuthError> {
        // Handle MFA Challenge Continuation
        if let AuthInput::MfaChallenge {
            mfa_token,
            challenge_input,
        } = input
        {
            // Verify MFA Token
            let token_data = jsonwebtoken::decode::<crate::auth::state::MfaTokenClaims>(
                &mfa_token,
                &jsonwebtoken::DecodingKey::from_secret(&self.mfa_jwt_secret),
                &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
            )
            .map_err(|_| AuthError::InvalidInput)?;

            if !token_data.claims.mfa_pending {
                return Err(AuthError::InvalidInput);
            }

            let method_name = match &*challenge_input {
                #[cfg(feature = "totp")]
                AuthInput::Totp { .. } => "totp",
                #[cfg(feature = "webauthn")]
                AuthInput::WebAuthnAuthentication { .. } => "webauthn",
                _ => "",
            };

            if method_name.is_empty() {
                return Err(AuthError::InvalidInput);
            }

            let method = self
                .auth_methods
                .get(method_name)
                .or_else(|| self.mfa_methods.get(method_name))
                .ok_or_else(|| {
                    AuthError::Internal(format!("MFA method {} not registered", method_name))
                })?;

            let identity = method.authenticate(*challenge_input).await?;

            if identity.external_id != token_data.claims.sub {
                return Err(AuthError::Credentials("MFA token user mismatch".into()));
            }

            return Ok(AuthResult::Success(identity));
        }

        // Primary Authentication
        let method_name = match &input {
            AuthInput::Password { .. } => "password",
            #[cfg(feature = "totp")]
            AuthInput::Totp { .. } => "totp", // Could theoretically be used as primary
            #[cfg(feature = "webauthn")]
            AuthInput::WebAuthnAuthentication { .. } => "webauthn",
            _ => "",
        };

        if method_name.is_empty() {
            return Err(AuthError::InvalidInput);
        }

        let method = self.auth_methods.get(method_name).ok_or_else(|| {
            AuthError::Internal(format!(
                "Primary auth method {} not registered or is step-up only",
                method_name
            ))
        })?;

        let identity = method.authenticate(input).await?;

        // Check if user has MFA enrolled
        let mut enrolled_methods = Vec::new();
        for (name, m) in self.auth_methods.iter().chain(self.mfa_methods.iter()) {
            if name == "password" || name == method_name {
                continue;
            }
            if !enrolled_methods.contains(name)
                && m.has_enrolled(&identity.external_id).await.unwrap_or(false)
            {
                enrolled_methods.push(name.clone());
            }
        }

        // If this method was already an MFA method (e.g. WebAuthn primary), we don't prompt for MFA again.
        // Or if the user has no other MFA methods enrolled.
        if enrolled_methods.is_empty() || method.is_mfa_equivalent() {
            Ok(AuthResult::Success(identity))
        } else {
            // Issue MFA Token
            let exp = chrono::Utc::now() + chrono::Duration::minutes(15);
            let claims = crate::auth::state::MfaTokenClaims {
                sub: identity.external_id.clone(),
                mfa_pending: true,
                exp: exp.timestamp() as usize,
            };

            let mfa_token = jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(&self.mfa_jwt_secret),
            )
            .map_err(|e| AuthError::Internal(e.to_string()))?;

            Ok(AuthResult::MfaRequired {
                mfa_token,
                user_id: identity.external_id,
                allowed_methods: enrolled_methods,
            })
        }
    }

    /// Starts a WebAuthn authentication ceremony for a list of enrolled passkeys.
    #[cfg(feature = "webauthn")]
    pub fn start_webauthn(
        &self,
        passkeys: &[webauthn_rs::prelude::Passkey],
    ) -> Result<
        (
            webauthn_rs::prelude::RequestChallengeResponse,
            webauthn_rs::prelude::PasskeyAuthentication,
        ),
        AuthError,
    > {
        let method = self
            .auth_methods
            .get("webauthn")
            .ok_or_else(|| AuthError::Internal("WebAuthn method not registered".into()))?;

        let webauthn_starter = method.as_webauthn_starter().ok_or_else(|| {
            AuthError::Internal("WebAuthn method doesn't implement starter".into())
        })?;

        webauthn_starter.start_authentication(passkeys)
    }
}

// Methods available only when a session store is present
impl<T> Engine<Configured<Arc<dyn SessionStore>>, T> {
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
impl<S> Engine<S, Configured<Arc<TokenManager>>> {
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

/// Trait for Engine instances that have a session store configured.
pub trait HasSessionStore {
    /// Returns the session store.
    fn session_store(&self) -> Arc<dyn SessionStore>;
}

impl<T> HasSessionStore for Engine<Configured<Arc<dyn SessionStore>>, T> {
    fn session_store(&self) -> Arc<dyn SessionStore> {
        self.session_store.0.clone()
    }
}

/// Trait for Engine instances that have a token manager configured.
#[cfg(feature = "token")]
pub trait HasTokenManager {
    /// Returns the token manager.
    fn token_manager(&self) -> Arc<TokenManager>;
}

#[cfg(feature = "token")]
impl<S> HasTokenManager for Engine<S, Configured<Arc<TokenManager>>> {
    fn token_manager(&self) -> Arc<TokenManager> {
        self.token_manager.0.clone()
    }
}
