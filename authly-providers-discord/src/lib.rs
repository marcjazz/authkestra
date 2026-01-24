use async_trait::async_trait;
use authly_core::{AuthError, Identity, OAuthProvider, OAuthToken};
use serde::Deserialize;
use std::collections::HashMap;

pub struct DiscordProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: reqwest::Client,
    token_url: String,
    user_url: String,
    revoke_url: String,
}

impl DiscordProvider {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
            http_client: reqwest::Client::new(),
            token_url: "https://discord.com/api/oauth2/token".to_string(),
            user_url: "https://discord.com/api/users/@me".to_string(),
            revoke_url: "https://discord.com/api/oauth2/token/revoke".to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_urls(mut self, token_url: String, user_url: String, revoke_url: String) -> Self {
        self.token_url = token_url;
        self.user_url = user_url;
        self.revoke_url = revoke_url;
        self
    }
}

#[derive(Deserialize)]
struct DiscordAccessTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct DiscordUserResponse {
    id: String,
    username: String,
    discriminator: String,
    email: Option<String>,
}

#[async_trait]
impl OAuthProvider for DiscordProvider {
    fn get_authorization_url(&self, state: &str, scopes: &[&str]) -> String {
        let scope_param = if scopes.is_empty() {
            "identify email".to_string()
        } else {
            scopes.join(" ")
        };

        format!(
            "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            self.client_id, urlencoding::encode(&self.redirect_uri), state, urlencoding::encode(&scope_param)
        )
    }

    async fn exchange_code_for_identity(&self, code: &str) -> Result<(Identity, OAuthToken), AuthError> {
        // 1. Exchange code for access token
        let token_response = self.http_client
            .post(&self.token_url)
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("grant_type", &"authorization_code".to_string()),
                ("code", &code.to_string()),
                ("redirect_uri", &self.redirect_uri),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<DiscordAccessTokenResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse token response: {}", e)))?;

        // 2. Get user information
        let user_response = self.http_client
            .get(&self.user_url)
            .header("Authorization", format!("Bearer {}", token_response.access_token))
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<DiscordUserResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse user response: {}", e)))?;

        // 3. Map to Identity
        let username = if user_response.discriminator == "0" {
            user_response.username
        } else {
            format!("{}#{}", user_response.username, user_response.discriminator)
        };

        let identity = Identity {
            provider_id: "discord".to_string(),
            external_id: user_response.id,
            email: user_response.email,
            username: Some(username),
            attributes: HashMap::new(),
        };

        let token = OAuthToken {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response.refresh_token,
            scope: token_response.scope,
        };

        Ok((identity, token))
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<OAuthToken, AuthError> {
        let token_response = self.http_client
            .post(&self.token_url)
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("grant_type", &"refresh_token".to_string()),
                ("refresh_token", &refresh_token.to_string()),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<DiscordAccessTokenResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse refresh token response: {}", e)))?;

        Ok(OAuthToken {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response.refresh_token.or_else(|| Some(refresh_token.to_string())),
            scope: token_response.scope,
        })
    }

    async fn revoke_token(&self, token: &str) -> Result<(), AuthError> {
        let response = self.http_client
            .post(&self.revoke_url)
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("token", &token.to_string()),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(AuthError::Provider(format!("Failed to revoke token: {}", error_text)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_exchange_code_for_identity() {
        let mut server = Server::new_async().await;
        let token_url = format!("{}/api/oauth2/token", server.url());
        let user_url = format!("{}/api/users/@me", server.url());

        let _token_mock = server.mock("POST", "/api/oauth2/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token": "test_token", "token_type": "Bearer"}"#)
            .create_async()
            .await;

        let _user_mock = server.mock("GET", "/api/users/@me")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id": "123456789", "username": "testuser", "discriminator": "0001", "email": "test@example.com"}"#)
            .create_async()
            .await;

        let provider = DiscordProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        ).with_test_urls(token_url, user_url, "http://localhost/api/oauth2/token/revoke".to_string());

        let (identity, token) = provider.exchange_code_for_identity("test_code").await.unwrap();

        assert_eq!(identity.provider_id, "discord");
        assert_eq!(identity.external_id, "123456789");
        assert_eq!(identity.username, Some("testuser#0001".to_string()));
        assert_eq!(identity.email, Some("test@example.com".to_string()));
        assert_eq!(token.access_token, "test_token");
    }
}
