use async_trait::async_trait;
use authly_core::{AuthError, Identity, OAuthProvider};
use std::collections::HashMap;

pub struct GithubProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

impl GithubProvider {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
        }
    }
}

#[async_trait]
impl OAuthProvider for GithubProvider {
    fn get_authorization_url(&self, state: &str, _scopes: &[&str]) -> String {
        format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
            self.client_id, self.redirect_uri, state
        )
    }

    async fn exchange_code_for_identity(&self, _code: &str) -> Result<Identity, AuthError> {
        // Implementation would:
        // 1. POST to https://github.com/login/oauth/access_token
        // 2. GET https://api.github.com/user
        // 3. Map to Identity
        
        // Mock identity for stub
        Ok(Identity {
            provider_id: "github".to_string(),
            external_id: "gh_12345".to_string(),
            email: Some("user@example.com".to_string()),
            username: Some("github_user".to_string()),
            attributes: HashMap::new(),
        })
    }
}
