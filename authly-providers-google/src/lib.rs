use async_trait::async_trait;
use authly_core::{AuthError, Identity, OAuthProvider, OAuthToken};
use serde::Deserialize;
use std::collections::HashMap;

pub struct GoogleProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: reqwest::Client,
    auth_url: String,
    token_url: String,
    userinfo_url: String,
    revoke_url: String,
}

impl GoogleProvider {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
            http_client: reqwest::Client::new(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: "https://www.googleapis.com/oauth2/v3/userinfo".to_string(),
            revoke_url: "https://oauth2.googleapis.com/revoke".to_string(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_urls(mut self, auth_url: String, token_url: String, userinfo_url: String, revoke_url: String) -> Self {
        self.auth_url = auth_url;
        self.token_url = token_url;
        self.userinfo_url = userinfo_url;
        self.revoke_url = revoke_url;
        self
    }
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct GoogleUserResponse {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    picture: Option<String>,
    email_verified: Option<bool>,
    locale: Option<String>,
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    fn get_authorization_url(&self, state: &str, scopes: &[&str]) -> String {
        let scope_param = if scopes.is_empty() {
            "openid email profile".to_string()
        } else {
            scopes.join(" ")
        };

        format!(
            "{}?client_id={}&redirect_uri={}&state={}&scope={}&response_type=code&access_type=offline&prompt=consent",
            self.auth_url, self.client_id, self.redirect_uri, state, scope_param
        )
    }

    async fn exchange_code_for_identity(&self, code: &str) -> Result<(Identity, OAuthToken), AuthError> {
        // 1. Exchange code for access token
        let token_response = self.http_client
            .post(&self.token_url)
            .form(&[
                ("code", code),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", &self.redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<GoogleTokenResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse token response: {}", e)))?;

        // 2. Get user information
        let user_response = self.http_client
            .get(&self.userinfo_url)
            .header("Authorization", format!("Bearer {}", token_response.access_token))
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<GoogleUserResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse user response: {}", e)))?;

        // 3. Map to Identity
        let mut attributes = HashMap::new();
        if let Some(picture) = user_response.picture {
            attributes.insert("picture".to_string(), picture);
        }
        if let Some(verified) = user_response.email_verified {
            attributes.insert("email_verified".to_string(), verified.to_string());
        }
        if let Some(locale) = user_response.locale {
            attributes.insert("locale".to_string(), locale);
        }

        let identity = Identity {
            provider_id: "google".to_string(),
            external_id: user_response.sub,
            email: user_response.email,
            username: user_response.name,
            attributes,
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
                ("refresh_token", refresh_token),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<GoogleTokenResponse>()
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
            .form(&[("token", token)])
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
        let auth_url = format!("{}/auth", server.url());
        let token_url = format!("{}/token", server.url());
        let userinfo_url = format!("{}/userinfo", server.url());

        let _token_mock = server.mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token": "test_token", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "test_refresh_token"}"#)
            .create_async()
            .await;

        let _user_mock = server.mock("GET", "/userinfo")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{
                "sub": "google-123",
                "email": "test@google.com",
                "name": "Google User",
                "picture": "http://picture",
                "email_verified": true,
                "locale": "en"
            }"#)
            .create_async()
            .await;

        let provider = GoogleProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        ).with_test_urls(auth_url, token_url, userinfo_url, "http://localhost/revoke".to_string());

        let (identity, token) = provider.exchange_code_for_identity("test_code").await.unwrap();

        assert_eq!(identity.provider_id, "google");
        assert_eq!(identity.external_id, "google-123");
        assert_eq!(identity.username, Some("Google User".to_string()));
        assert_eq!(identity.email, Some("test@google.com".to_string()));
        assert_eq!(identity.attributes.get("picture").unwrap(), "http://picture");
        assert_eq!(identity.attributes.get("email_verified").unwrap(), "true");
        assert_eq!(identity.attributes.get("locale").unwrap(), "en");
        assert_eq!(token.access_token, "test_token");
        assert_eq!(token.refresh_token, Some("test_refresh_token".to_string()));
    }
}
