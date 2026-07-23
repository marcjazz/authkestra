import os

macro_code = """
#[macro_export]
macro_rules! define_oauth_provider {
    (
        $provider_struct:ident,
        $provider_id:literal,
        $provider_name:literal,
        $default_auth_url:literal,
        $default_token_url:literal,
        $default_userinfo_url:literal,
        $default_scopes:expr,
        $user_response:ident { $($user_field:ident : $user_type:ty),* $(,)? },
        | $user_var:ident | $map_identity:block
    ) => {
        pub struct $provider_struct {
            client_id: String,
            client_secret: String,
            redirect_uri: String,
            http_client: reqwest::Client,
            authorization_url: String,
            token_url: String,
            user_url: String,
        }

        impl $provider_struct {
            pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
                Self {
                    client_id,
                    client_secret,
                    redirect_uri,
                    http_client: reqwest::Client::builder()
                        .user_agent("authkestra")
                        .build()
                        .unwrap_or_else(|_| reqwest::Client::new()),
                    authorization_url: $default_auth_url.to_string(),
                    token_url: $default_token_url.to_string(),
                    user_url: $default_userinfo_url.to_string(),
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

        #[async_trait::async_trait]
        impl authkestra_engine::auth::Provider for $provider_struct {
            async fn config(&self) -> authkestra_engine::auth::ProviderConfig {
                authkestra_engine::auth::ProviderConfig {
                    id: $provider_id.to_string(),
                    name: $provider_name.to_string(),
                    extra: std::collections::HashMap::new(),
                }
            }
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            token_type: String,
            expires_in: Option<u64>,
            refresh_token: Option<String>,
            scope: Option<String>,
            id_token: Option<String>,
        }

        #[derive(serde::Deserialize)]
        struct $user_response {
            $( $user_field: $user_type, )*
        }

        #[async_trait::async_trait]
        impl authkestra_engine::OAuthProvider for $provider_struct {
            fn provider_id(&self) -> &str {
                $provider_id
            }

            fn get_authorization_url(
                &self,
                state: &str,
                scopes: &[&str],
                code_challenge: Option<&str>,
                nonce: Option<&str>,
            ) -> String {
                let default_scopes: Vec<&str> = $default_scopes;
                let scope_param = if scopes.is_empty() {
                    default_scopes.join(" ")
                } else {
                    scopes.join(" ")
                };

                let mut url = format!(
                    "{auth_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&state={state}&scope={scope_param}",
                    auth_url = self.authorization_url,
                    client_id = self.client_id,
                    redirect_uri = urlencoding::encode(&self.redirect_uri),
                    state = state,
                    scope_param = urlencoding::encode(&scope_param)
                );

                if let Some(challenge) = code_challenge {
                    url.push_str(&format!("&code_challenge={challenge}&code_challenge_method=S256"));
                }

                if let Some(n) = nonce {
                    url.push_str(&format!("&nonce={n}"));
                }

                url
            }

            #[tracing::instrument(skip(self, code, code_verifier, _nonce))]
            async fn exchange_code_for_identity(
                &self,
                code: &str,
                code_verifier: Option<&str>,
                _nonce: Option<&str>,
            ) -> Result<(authkestra_engine::state::Identity, authkestra_engine::state::OAuthToken), authkestra_engine::error::AuthError> {
                tracing::debug!(concat!("exchanging ", $provider_name, " code for access token"));
                
                let mut params = vec![
                    ("client_id", self.client_id.clone()),
                    ("client_secret", self.client_secret.clone()),
                    ("grant_type", "authorization_code".to_string()),
                    ("code", code.to_string()),
                    ("redirect_uri", self.redirect_uri.clone()),
                ];

                if let Some(verifier) = code_verifier {
                    params.push(("code_verifier", verifier.to_string()));
                }

                let token_response = self
                    .http_client
                    .post(&self.token_url)
                    .header("Accept", "application/json")
                    .form(&params)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!("network error while exchanging ", $provider_name, " code"));
                        authkestra_engine::error::AuthError::Network
                    })?
                    .json::<TokenResponse>()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!("failed to parse ", $provider_name, " token response"));
                        authkestra_engine::error::AuthError::Provider(format!("Failed to parse token response: {e}"))
                    })?;

                tracing::debug!(concat!("fetching ", $provider_name, " user information"));
                let $user_var = self
                    .http_client
                    .get(&self.user_url)
                    .header(
                        "Authorization",
                        format!("Bearer {token}", token = token_response.access_token),
                    )
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!("network error while fetching ", $provider_name, " user"));
                        authkestra_engine::error::AuthError::Network
                    })?
                    .json::<$user_response>()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!("failed to parse ", $provider_name, " user response"));
                        authkestra_engine::error::AuthError::Provider(format!("Failed to parse user response: {e}"))
                    })?;

                let identity: authkestra_engine::state::Identity = $map_identity;

                let token = authkestra_engine::state::OAuthToken {
                    access_token: token_response.access_token,
                    token_type: token_response.token_type,
                    expires_in: token_response.expires_in,
                    refresh_token: token_response.refresh_token,
                    scope: token_response.scope,
                    id_token: token_response.id_token,
                };

                tracing::info!(external_id = %identity.external_id, concat!("successfully exchanged ", $provider_name, " code for identity"));
                Ok((identity, token))
            }

            #[tracing::instrument(skip(self, refresh_token))]
            async fn refresh_token(&self, refresh_token: &str) -> Result<authkestra_engine::state::OAuthToken, authkestra_engine::error::AuthError> {
                tracing::debug!(concat!("refreshing ", $provider_name, " access token"));
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
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!("network error while refreshing ", $provider_name, " token"));
                        authkestra_engine::error::AuthError::Network
                    })?
                    .json::<TokenResponse>()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!("failed to parse ", $provider_name, " refresh token response"));
                        authkestra_engine::error::AuthError::Provider(format!("Failed to parse refresh token response: {e}"))
                    })?;

                tracing::info!(concat!("successfully refreshed ", $provider_name, " access token"));
                Ok(authkestra_engine::state::OAuthToken {
                    access_token: token_response.access_token,
                    token_type: token_response.token_type,
                    expires_in: token_response.expires_in,
                    refresh_token: token_response.refresh_token,
                    scope: token_response.scope,
                    id_token: token_response.id_token,
                })
            }
        }
    };
}
"""

with open("crates/authkestra-providers/src/macros.rs", "w") as f:
    f.write(macro_code)

github_code = """
crate::define_oauth_provider! {
    GithubProvider,
    "github",
    "GitHub",
    "https://github.com/login/oauth/authorize",
    "https://github.com/login/oauth/access_token",
    "https://api.github.com/user",
    vec!["user:email"],
    GithubUserResponse {
        id: u64,
        login: String,
        email: Option<String>,
    },
    |user| {
        authkestra_engine::state::Identity {
            provider_id: "github".to_string(),
            external_id: user.id.to_string(),
            email: user.email,
            username: Some(user.login),
            attributes: std::collections::HashMap::new(),
        }
    }
}
"""
with open("crates/authkestra-providers/src/github.rs", "w") as f:
    f.write(github_code)

discord_code = """
crate::define_oauth_provider! {
    DiscordProvider,
    "discord",
    "Discord",
    "https://discord.com/api/oauth2/authorize",
    "https://discord.com/api/oauth2/token",
    "https://discord.com/api/users/@me",
    vec!["identify", "email"],
    DiscordUserResponse {
        id: String,
        username: String,
        discriminator: String,
        email: Option<String>,
    },
    |user| {
        authkestra_engine::state::Identity {
            provider_id: "discord".to_string(),
            external_id: user.id,
            email: user.email,
            username: Some(format!("{}#{}", user.username, user.discriminator)),
            attributes: std::collections::HashMap::new(),
        }
    }
}
"""
with open("crates/authkestra-providers/src/discord.rs", "w") as f:
    f.write(discord_code)

google_code = """
crate::define_oauth_provider! {
    GoogleProvider,
    "google",
    "Google",
    "https://accounts.google.com/o/oauth2/v2/auth",
    "https://oauth2.googleapis.com/token",
    "https://www.googleapis.com/oauth2/v3/userinfo",
    vec!["openid", "email", "profile"],
    GoogleUserResponse {
        sub: String,
        email: Option<String>,
        name: Option<String>,
        picture: Option<String>,
        email_verified: Option<bool>,
        locale: Option<String>,
    },
    |user| {
        let mut attributes = std::collections::HashMap::new();
        if let Some(picture) = user.picture {
            attributes.insert("picture".to_string(), picture);
        }
        if let Some(verified) = user.email_verified {
            attributes.insert("email_verified".to_string(), verified.to_string());
        }
        if let Some(locale) = user.locale {
            attributes.insert("locale".to_string(), locale);
        }

        authkestra_engine::state::Identity {
            provider_id: "google".to_string(),
            external_id: user.sub,
            email: user.email,
            username: user.name,
            attributes,
        }
    }
}
"""
with open("crates/authkestra-providers/src/google.rs", "w") as f:
    f.write(google_code)

lib_code = """
#[macro_use]
pub mod macros;

#[cfg(feature = "github")]
pub mod github;

#[cfg(feature = "google")]
pub mod google;

#[cfg(feature = "discord")]
pub mod discord;
"""
with open("crates/authkestra-providers/src/lib.rs", "w") as f:
    f.write(lib_code)

