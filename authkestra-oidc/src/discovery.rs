use authkestra_core::{AuthError, ProviderMetadata};

/// Fetches metadata from the issuer URL (appends /.well-known/openid-configuration)
pub async fn discover(issuer_url: &str, client: &reqwest::Client) -> Result<ProviderMetadata, AuthError> {
    ProviderMetadata::discover(issuer_url, client).await
}
