use thiserror::Error;
use authly_core::AuthError;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Provider error: {0}")]
    Provider(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<OidcError> for AuthError {
    fn from(err: OidcError) -> Self {
        match err {
            OidcError::Discovery(e) => AuthError::Provider(format!("Discovery failed: {}", e)),
            OidcError::Network(_) => AuthError::Network,
            OidcError::ValidationError(e) => AuthError::Token(e),
            OidcError::Provider(e) => AuthError::Provider(e),
            OidcError::Internal(e) => AuthError::Provider(format!("Internal OIDC error: {}", e)),
        }
    }
}
