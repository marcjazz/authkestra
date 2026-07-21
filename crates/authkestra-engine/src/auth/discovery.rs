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
    /// Fetches metadata from the issuer URL (appends /.well-known/openid-configuration).
    /// Also returns the parsed max-age from the Cache-Control header if present.
    pub async fn discover(
        issuer_url: &str,
        client: reqwest::Client,
    ) -> Result<(Self, Option<std::time::Duration>), AuthError> {
        let mut url = url::Url::parse(issuer_url)
            .map_err(|e| AuthError::Discovery(format!("Invalid issuer URL: {e}")))?;

        if !url.path().ends_with("/.well-known/openid-configuration") {
            let mut path = url.path_segments_mut().unwrap();
            path.push(".well-known");
            path.push("openid-configuration");
        }

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| AuthError::Network)?;

        let mut cache_max_age = None;
        if let Some(cache_control) = response.headers().get(reqwest::header::CACHE_CONTROL) {
            if let Ok(cc_str) = cache_control.to_str() {
                for directive in cc_str.split(',') {
                    let directive = directive.trim();
                    if let Some(rest) = directive.strip_prefix("max-age=") {
                        if let Ok(secs) = rest.parse::<u64>() {
                            cache_max_age = Some(std::time::Duration::from_secs(secs));
                        }
                    }
                }
            }
        }

        let metadata = response
            .json::<ProviderMetadata>()
            .await
            .map_err(|e| AuthError::Discovery(format!("Failed to parse metadata: {e}")))?;

        Ok((metadata, cache_max_age))
    }
}
