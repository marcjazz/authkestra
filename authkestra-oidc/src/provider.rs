use crate::error::OidcError;
use async_trait::async_trait;
use authkestra_engine::{
    auth::{Provider, ProviderConfig},
    discovery::ProviderMetadata,
    error::AuthError,
    state::{Identity, OAuthToken},
    OAuthProvider,
};
use authkestra_resource::jwt::{validate_jwt_generic, JwksCache};
use jsonwebtoken::Validation;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};

pub struct OidcProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    metadata: ProviderMetadata,
    http_client: reqwest::Client,
    cache: JwksCache,
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
    pub nonce: Option<String>,
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
    #[tracing::instrument(skip(client_id, client_secret))]
    pub async fn discover(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        issuer_url: &str,
    ) -> Result<Self, OidcError> {
        tracing::debug!("starting OIDC discovery process");
        let client = reqwest::Client::new();
        let metadata = ProviderMetadata::discover(issuer_url, client.clone())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "OIDC discovery failed");
                e
            })?;
        tracing::info!(issuer = %metadata.issuer, "successfully discovered OIDC provider metadata");
        let cache = JwksCache::new(metadata.jwks_uri.clone(), Duration::from_secs(3600));

        Ok(Self {
            client_id,
            client_secret,
            redirect_uri,
            metadata,
            http_client: client,
            cache,
        })
    }

    pub fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }
}

#[async_trait]
impl Provider for OidcProvider {
    async fn config(&self) -> ProviderConfig {
        ProviderConfig {
            id: "oidc".to_string(),
            name: "OIDC".to_string(),
            extra: HashMap::new(),
        }
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
        nonce: Option<&str>,
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
                "&code_challenge={challenge}&code_challenge_method=S256"
            ));
        }

        if let Some(n) = nonce {
            url.push_str(&format!("&nonce={n}"));
        }

        url
    }

    #[tracing::instrument(skip(self, code, code_verifier, nonce))]
    async fn exchange_code_for_identity(
        &self,
        code: &str,
        code_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        tracing::debug!("exchanging OIDC code for tokens");
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
            .map_err(|e| {
                tracing::error!(error = %e, "network error while exchanging OIDC code");
                AuthError::Network
            })?
            .json::<OidcTokenResponse>()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to parse OIDC token response");
                AuthError::Provider(format!("Failed to parse token response: {e}"))
            })?;

        let id_token = token_response.id_token.ok_or_else(|| {
            tracing::error!("missing id_token in OIDC response");
            AuthError::Token("Missing id_token in response".to_string())
        })?;

        tracing::debug!("validating OIDC ID Token");
        // 2. Validate ID Token using the validator
        let claims = validate_jwt_generic::<Claims>(&id_token, &self.cache, &Validation::default())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to validate OIDC ID Token");
                AuthError::from(OidcError::from(e))
            })?;

        // 3. Validate Nonce
        if let Some(expected_nonce) = nonce {
            if claims.nonce.as_deref() != Some(expected_nonce) {
                tracing::error!("nonce mismatch in OIDC ID Token");
                return Err(AuthError::Token("Nonce mismatch".to_string()));
            }
        }

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

        tracing::info!(external_id = %identity.external_id, "successfully exchanged OIDC code for identity");
        Ok((identity, token))
    }
}
