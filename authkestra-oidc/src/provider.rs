use authkestra_core::ProviderMetadata;
use crate::error::OidcError;
use async_trait::async_trait;
use authkestra_core::{AuthError, Identity, OAuthProvider, OAuthToken};
use authkestra_token::offline_validation::OidcValidator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct OidcProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    metadata: ProviderMetadata,
    http_client: reqwest::Client,
    validator: OidcValidator,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

#[derive(Deserialize)]
struct OidcTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

impl OidcProvider {
    /// Creates a new provider by performing discovery
    pub async fn discover(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        issuer_url: &str,
    ) -> Result<Self, OidcError> {
        let client = reqwest::Client::new();
        let metadata = ProviderMetadata::discover(issuer_url, &client).await?;
        let validator = OidcValidator::discover(issuer_url).await?;
        Ok(Self {
            client_id,
            client_secret,
            redirect_uri,
            metadata,
            http_client: client,
            validator,
        })
    }

    pub fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }

    pub fn validator(&self) -> &OidcValidator {
        &self.validator
    }
}

#[async_trait]
impl OAuthProvider for OidcProvider {
    fn provider_id(&self) -> &str {
        "oidc"
    }

    fn get_authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_challenge: Option<&str>,
    ) -> String {
        let mut full_scopes = scopes.to_vec();
        if !full_scopes.contains(&"openid") {
            full_scopes.push("openid");
        }

        let scope_param = full_scopes.join(" ");

        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            self.metadata.authorization_endpoint,
            self.client_id,
            urlencoding::encode(&self.redirect_uri),
            state,
            urlencoding::encode(&scope_param)
        );

        if let Some(challenge) = code_challenge {
            url.push_str(&format!(
                "&code_challenge={}&code_challenge_method=S256",
                challenge
            ));
        }

        url
    }

    async fn exchange_code_for_identity(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        // 1. Exchange code for tokens
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code".to_string());
        params.insert("code", code.to_string());
        params.insert("redirect_uri", self.redirect_uri.clone());
        params.insert("client_id", self.client_id.clone());
        params.insert("client_secret", self.client_secret.clone());

        if let Some(verifier) = code_verifier {
            params.insert("code_verifier", verifier.to_string());
        }

        let token_response = self
            .http_client
            .post(&self.metadata.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<OidcTokenResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse token response: {}", e)))?;

        let id_token = token_response
            .id_token
            .ok_or_else(|| AuthError::Token("Missing id_token in response".to_string()))?;

        // 2. Validate ID Token using the validator
        let claims = self
            .validator
            .validate_id_token::<Claims>(&id_token, &self.client_id)
            .await
            .map_err(OidcError::from)
            .map_err(AuthError::from)?;

        // 4. Construct Identity
        let mut attributes = HashMap::new();
        if let Some(picture) = claims.picture {
            attributes.insert("picture".to_string(), picture);
        }

        let identity = Identity {
            provider_id: "oidc".to_string(), // Could be parameterized or inferred from issuer
            external_id: claims.sub,
            email: claims.email,
            username: claims.name,
            attributes,
        };

        let token = OAuthToken {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response.refresh_token,
            scope: token_response.scope,
            id_token: Some(id_token),
        };

        Ok((identity, token))
    }
}
