use authly_core::{OAuthProvider, Identity, AuthError, CredentialsProvider, OAuthToken};

/// Orchestrates the Authorization Code flow.
pub struct OAuth2Flow<P: OAuthProvider> {
    provider: P,
}

impl<P: OAuthProvider> OAuth2Flow<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Generates the redirect URL and CSRF state.
    pub fn initiate_login(&self, scopes: &[&str]) -> (String, String) {
        let state = uuid::Uuid::new_v4().to_string();
        let url = self.provider.get_authorization_url(&state, scopes);
        (url, state)
    }

    /// Completes the flow by exchanging the code.
    pub async fn finalize_login(&self, code: &str, received_state: &str, expected_state: &str) -> Result<(Identity, OAuthToken), AuthError> {
        if received_state != expected_state {
            return Err(AuthError::CsrfMismatch);
        }
        self.provider.exchange_code_for_identity(code).await
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

/// Orchestrates a direct credentials flow.
pub struct CredentialsFlow<P: CredentialsProvider> {
    provider: P,
}

impl<P: CredentialsProvider> CredentialsFlow<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    pub async fn authenticate(&self, creds: P::Credentials) -> Result<Identity, AuthError> {
        self.provider.authenticate(creds).await
    }
}
