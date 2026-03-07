use async_trait::async_trait;
use authkestra_core::{error::AuthError, state::Identity, state::OAuthToken, OAuthProvider};
use serde::Deserialize;
use std::collections::HashMap;

pub struct GithubProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: reqwest::Client,
    authorization_url: String,
    token_url: String,
    user_url: String,
}

impl GithubProvider {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
            http_client: reqwest::Client::new(),
            authorization_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_url: "https://api.github.com/user".to_string(),
        }
    }

    pub fn with_test_urls(
        mut self,
        authorization_url: String,
        token_url: String,
        user_url: String,
    ) -> Self {
        self.authorization_url = authorization_url;
        self.token_url = token_url;
        self.user_url = user_url;
        self
    }

    pub fn with_authorization_url(mut self, authorization_url: String) -> Self {
        self.authorization_url = authorization_url;
        self
    }
}

#[derive(Deserialize)]
struct GithubAccessTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct GithubUserResponse {
    id: u64,
    login: String,
    email: Option<String>,
}

#[async_trait]
impl OAuthProvider for GithubProvider {
    fn provider_id(&self) -> &str {
        "github"
    }

    fn get_authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        _code_challenge: Option<&str>,
    ) -> String {
        let scope_param = if scopes.is_empty() {
            "user:email".to_string()
        } else {
            scopes.join(" ")
        };

        format!(
            "{auth_url}?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&scope={scope_param}",
            auth_url = self.authorization_url,
            client_id = self.client_id,
            redirect_uri = self.redirect_uri
        )
    }

    async fn exchange_code_for_identity(
        &self,
        code: &str,
        _code_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        // 1. Exchange code for access token
        let token_response = self
            .http_client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("code", &code.to_string()),
                ("redirect_uri", &self.redirect_uri),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<GithubAccessTokenResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse token response: {e}")))?;

        // 2. Get user information
        let user_response = self
            .http_client
            .get(&self.user_url)
            .header(
                "Authorization",
                format!("Bearer {token}", token = token_response.access_token),
            )
            .header("User-Agent", "authkestra")
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<GithubUserResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse user response: {e}")))?;

        // 3. Map to Identity
        let identity = Identity {
            provider_id: "github".to_string(),
            external_id: user_response.id.to_string(),
            email: user_response.email,
            username: Some(user_response.login),
            attributes: HashMap::new(),
        };

        let token = OAuthToken {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response.refresh_token,
            scope: token_response.scope,
            id_token: token_response.id_token,
        };

        Ok((identity, token))
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<OAuthToken, AuthError> {
        let token_response = self
            .http_client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("grant_type", &"refresh_token".to_string()),
                ("refresh_token", &refresh_token.to_string()),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<GithubAccessTokenResponse>()
            .await
            .map_err(|e| {
                AuthError::Provider(format!("Failed to parse refresh token response: {e}"))
            })?;

        Ok(OAuthToken {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response
                .refresh_token
                .or_else(|| Some(refresh_token.to_string())),
            scope: token_response.scope,
            id_token: token_response.id_token,
        })
    }

    async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        let response = self
            .http_client
            .delete(format!(
                "https://api.github.com/applications/{}/token",
                self.client_id
            ))
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .header("User-Agent", "authkestra")
            .json(&serde_json::json!({
                "access_token": token
            }))
            .send()
            .await
            .map_err(|_| AuthError::Network)?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(AuthError::Provider(format!(
                "Failed to revoke token: {error_text}"
            )))
        }
    }
}
