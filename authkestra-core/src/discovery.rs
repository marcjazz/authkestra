use serde::{Deserialize, Serialize};

use crate::error::AuthError;

/// Metadata for an OpenID Connect provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    /// The issuer URL
    pub issuer: String,
    /// The authorization endpoint URL
    pub authorization_endpoint: String,
    /// The token endpoint URL
    pub token_endpoint: String,
    /// The JWKS URI
    pub jwks_uri: String,
    /// The userinfo endpoint URL, if available
    pub userinfo_endpoint: Option<String>,
    /// Scopes supported by the provider
    pub scopes_supported: Option<Vec<String>>,
    /// Response types supported by the provider
    pub response_types_supported: Option<Vec<String>>,
    /// ID token signing algorithms supported by the provider
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

impl ProviderMetadata {
    /// Fetches metadata from the issuer URL (appends /.well-known/openid-configuration)
    pub async fn discover(issuer_url: &str, client: reqwest::Client) -> Result<Self, AuthError> {
        let mut url = url::Url::parse(issuer_url)
            .map_err(|e| AuthError::Discovery(format!("Invalid issuer URL: {e}")))?;

        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| AuthError::Discovery("Cannot append to issuer URL".to_string()))?;
            path.push(".well-known");
            path.push("openid-configuration");
        }

        let metadata = client
            .get(url)
            .send()
            .await
            .map_err(|_| AuthError::Network)?
            .json::<ProviderMetadata>()
            .await
            .map_err(|e| AuthError::Discovery(format!("Failed to parse metadata: {e}")))?;

        Ok(metadata)
    }
}
