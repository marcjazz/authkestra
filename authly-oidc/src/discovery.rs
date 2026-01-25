use serde::Deserialize;
use crate::error::OidcError;

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

impl ProviderMetadata {
    /// Fetches metadata from the issuer URL (appends /.well-known/openid-configuration)
    pub async fn discover(issuer_url: &str, client: &reqwest::Client) -> Result<Self, OidcError> {
        let mut url = url::Url::parse(issuer_url)
            .map_err(|e| OidcError::Discovery(format!("Invalid issuer URL: {}", e)))?;
        
        {
            let mut path = url.path_segments_mut().map_err(|_| OidcError::Discovery("Cannot append to issuer URL".to_string()))?;
            path.push(".well-known");
            path.push("openid-configuration");
        }

        let metadata = client.get(url)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?
            .json::<ProviderMetadata>()
            .await
            .map_err(|e| OidcError::Discovery(format!("Failed to parse metadata: {}", e)))?;

        Ok(metadata)
    }
}
