use async_trait::async_trait;
use authly_core::{AuthError, Identity, OAuthProvider, OAuthToken};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::discovery::ProviderMetadata;
use crate::error::OidcError;
use crate::jwks::Jwks;
use jsonwebtoken::{decode, decode_header, Validation, Algorithm};

pub struct OidcProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    metadata: ProviderMetadata,
    http_client: reqwest::Client,
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
        issuer_url: &str
    ) -> Result<Self, OidcError> {
        let client = reqwest::Client::new();
        let metadata = ProviderMetadata::discover(issuer_url, &client).await?;
        Ok(Self {
            client_id,
            client_secret,
            redirect_uri,
            metadata,
            http_client: client,
        })
    }

    pub fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }
}

#[async_trait]
impl OAuthProvider for OidcProvider {
    fn get_authorization_url(&self, state: &str, scopes: &[&str], code_challenge: Option<&str>) -> String {
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
            url.push_str(&format!("&code_challenge={}&code_challenge_method=S256", challenge));
        }

        url
    }

    async fn exchange_code_for_identity(&self, code: &str, code_verifier: Option<&str>) -> Result<(Identity, OAuthToken), AuthError> {
        // 1. Exchange code for tokens
        let mut params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("client_id", self.client_id.clone()),
            ("client_secret", self.client_secret.clone()),
        ];

        if let Some(verifier) = code_verifier {
            params.push(("code_verifier", verifier.to_string()));
        }

        let token_response = self.http_client
            .post(&self.metadata.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<OidcTokenResponse>()
            .await
            .map_err(|e| AuthError::Provider(format!("Failed to parse token response: {}", e)))?;

        let id_token = token_response.id_token.ok_or_else(|| AuthError::Token("Missing id_token in response".to_string()))?;

        // 2. Fetch JWKS
        let jwks = Jwks::fetch(&self.metadata.jwks_uri, &self.http_client).await
            .map_err(|e| AuthError::from(e))?;

        // 3. Decode and Validate ID Token
        let header = decode_header(&id_token)
            .map_err(|e| AuthError::Token(format!("Invalid ID Token header: {}", e)))?;
        
        let jwk = jwks.find_key(header.kid.as_deref())
            .ok_or_else(|| AuthError::Token("No matching key found in JWKS".to_string()))?;

        let decoding_key = jwk.to_decoding_key()
            .map_err(|e| AuthError::from(e))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.metadata.issuer.clone()]);
        validation.set_audience(&[self.client_id.clone()]);

        let token_data = decode::<Claims>(
            &id_token,
            &decoding_key,
            &validation
        ).map_err(|e| AuthError::Token(format!("ID Token validation failed: {}", e)))?;

        let claims = token_data.claims;

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
