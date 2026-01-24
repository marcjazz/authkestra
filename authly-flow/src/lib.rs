use authly_core::{OAuthProvider, Identity, AuthError, CredentialsProvider};

/// Orchestrates the Authorization Code flow.
pub struct OAuth2Flow<P: OAuthProvider> {
    provider: P,
}

impl<P: OAuthProvider> OAuth2Flow<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Generates the redirect URL and CSRF state.
    pub fn initiate_login(&self) -> (String, String) {
        let state = uuid::Uuid::new_v4().to_string(); 
        let url = self.provider.get_authorization_url(&state, &[]);
        (url, state)
    }

    /// Completes the flow by exchanging the code.
    pub async fn finalize_login(&self, code: &str, _state: &str) -> Result<Identity, AuthError> {
        // In a real flow, you'd verify _state matches the one from initiate_login
        self.provider.exchange_code_for_identity(code).await
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
