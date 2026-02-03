use async_trait::async_trait;
use authkestra_core::{
    AuthError, ErasedOAuthFlow, Identity, OAuthProvider, OAuthToken, UserMapper,
};

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
    ) -> Result<(Identity, OAuthToken), AuthError> {
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
