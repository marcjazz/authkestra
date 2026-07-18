use crate::auth::{
    error::AuthError, state::Identity, state::OAuth2State, state::OAuthToken, ErasedOAuthFlow,
    OAuthProvider, UserMapper,
};
use crate::flow::{Flow, FlowContext, FlowResult};
use async_trait::async_trait;

/// Orchestrates the standard OAuth2 Authorization Code flow.
pub struct OAuth2Flow<P: OAuthProvider, M: UserMapper = ()> {
    provider: P,
    mapper: Option<M>,
    scopes: Vec<String>,
    use_pkce: bool,
}

#[async_trait]
impl<P: OAuthProvider + 'static, M: UserMapper + 'static> Flow for OAuth2Flow<P, M> {
    fn id(&self) -> &str {
        self.provider.provider_id()
    }

    async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError> {
        if let Some(_code) = ctx.params.get("code") {
            let _received_state = ctx.params.get("state").ok_or(AuthError::CsrfMismatch)?;

            // In the new model, expected_state must be provided via some context.
            // For now, if it's missing from ctx, we might need to adjust FlowContext.
            // But ErasedOAuthFlow is what the adapters use.
            Err(AuthError::Token(
                "Direct Flow execution not updated for encrypted state".to_string(),
            ))
        } else {
            // Assume initiation if no code is present
            let scopes_str = ctx.params.get("scopes").map(|s| s.as_str()).unwrap_or("");
            let scopes_vec: Vec<&str> = if scopes_str.is_empty() {
                Vec::new()
            } else {
                scopes_str.split(',').collect()
            };

            let pkce_challenge = ctx.params.get("pkce_challenge").map(|s| s.as_str());
            let (url, _state) = self.initiate_login(&scopes_vec, pkce_challenge);
            Ok(FlowResult::Redirect(url))
        }
    }
}

#[async_trait]
impl<P: OAuthProvider + 'static, M: UserMapper + 'static> ErasedOAuthFlow for OAuth2Flow<P, M> {
    fn provider_id(&self) -> String {
        self.provider.provider_id().to_string()
    }

    fn initiate_login(
        &self,
        scopes: &[&str],
        pkce_challenge: Option<&str>,
    ) -> (String, OAuth2State) {
        let effective_scopes = if !scopes.is_empty() {
            scopes
        } else {
            &self
                .scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
        };

        self.initiate_login(effective_scopes, pkce_challenge)
    }

    async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &OAuth2State,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        let (identity, token, _) = self
            .finalize_login(code, received_state, expected_state)
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
            scopes: Vec::new(),
            use_pkce: true,
        }
    }
}

impl<P: OAuthProvider, M: UserMapper> OAuth2Flow<P, M> {
    /// Create a new `OAuth2Flow` with the given provider and user mapper.
    pub fn with_mapper(provider: P, mapper: M) -> Self {
        Self {
            provider,
            mapper: Some(mapper),
            scopes: Vec::new(),
            use_pkce: true,
        }
    }

    /// Set the scopes for the OAuth2 flow.
    pub fn with_scopes(mut self, scopes: Vec<impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Enable or disable PKCE for the OAuth2 flow.
    pub fn with_pkce(mut self, use_pkce: bool) -> Self {
        self.use_pkce = use_pkce;
        self
    }

    /// Generates the redirect URL and CSRF state.
    #[tracing::instrument(skip(self), fields(provider_id = %self.provider.provider_id()))]
    pub fn initiate_login(
        &self,
        scopes: &[&str],
        pkce_challenge: Option<&str>,
    ) -> (String, OAuth2State) {
        let state = uuid::Uuid::new_v4().to_string();
        let nonce = Some(uuid::Uuid::new_v4().to_string());

        let effective_scopes = if !scopes.is_empty() {
            scopes
        } else {
            &self
                .scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<&str>>()
        };

        tracing::debug!(scopes = ?effective_scopes, "generating authorization URL");

        let url = self.provider.get_authorization_url(
            &state,
            effective_scopes,
            pkce_challenge,
            nonce.as_deref(),
        );

        let auth_state = OAuth2State {
            state: state.clone(),
            nonce,
            code_verifier: None, // Will be set by the caller if needed before encryption
            success_url: None,
            provider_id: self.provider.provider_id().to_string(),
            expires_at: chrono::Utc::now().timestamp() + 600,
        };

        tracing::info!("authorization login initiated successfully");
        (url, auth_state)
    }

    /// Completes the flow by exchanging the code.
    /// If a mapper is provided, it will also map the identity to a local user.
    #[tracing::instrument(skip(self, code, expected_state), fields(provider_id = %self.provider.provider_id()))]
    pub async fn finalize_login(
        &self,
        code: &str,
        received_state: &str,
        expected_state: &OAuth2State,
    ) -> Result<(Identity, OAuthToken, Option<M::LocalUser>), AuthError> {
        if received_state != expected_state.state {
            tracing::error!("CSRF mismatch: received state does not match expected state");
            return Err(AuthError::CsrfMismatch);
        }

        tracing::debug!("exchanging code for identity");
        let (identity, token) = self
            .provider
            .exchange_code_for_identity(
                code,
                expected_state.code_verifier.as_deref(),
                expected_state.nonce.as_deref(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to exchange code for identity");
                e
            })?;

        tracing::info!(user_id = %identity.external_id, "successfully retrieved identity from provider");

        // TODO: Validate nonce if present in identity/ID token

        let local_user = if let Some(mapper) = &self.mapper {
            tracing::debug!("mapping user identity");
            Some(mapper.map_user(&identity).await.map_err(|e| {
                tracing::error!(error = %e, "failed to map user");
                e
            })?)
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
