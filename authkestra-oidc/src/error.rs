use authkestra_core::error::AuthError;
use thiserror::Error;

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
            OidcError::Discovery(e) => AuthError::Provider(format!("Discovery failed: {e}")),
            OidcError::Network(_) => AuthError::Network,
            OidcError::ValidationError(e) => AuthError::Token(e),
            OidcError::Provider(e) => AuthError::Provider(e),
            OidcError::Internal(e) => AuthError::Provider(format!("Internal OIDC error: {e}")),
        }
    }
}

impl From<AuthError> for OidcError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::Discovery(e) => OidcError::Discovery(e),
            AuthError::Network => OidcError::Network("Network error".to_string()),
            AuthError::Token(e) => OidcError::ValidationError(e),
            AuthError::Provider(e) => OidcError::Provider(e),
            _ => OidcError::Internal(err.to_string()),
        }
    }
}

impl From<authkestra_guard::jwt::ValidationError> for OidcError {
    fn from(err: authkestra_guard::jwt::ValidationError) -> Self {
        match err {
            authkestra_guard::jwt::ValidationError::Discovery(e) => match e {
                AuthError::Discovery(msg) => OidcError::Discovery(msg),
                _ => OidcError::Discovery(e.to_string()),
            },
            authkestra_guard::jwt::ValidationError::Http(e) => OidcError::Network(e.to_string()),
            authkestra_guard::jwt::ValidationError::Jwt(e) => {
                OidcError::ValidationError(e.to_string())
            }
            authkestra_guard::jwt::ValidationError::Serialization(e) => {
                OidcError::Internal(e.to_string())
            }
            authkestra_guard::jwt::ValidationError::InvalidToken(e) => {
                OidcError::ValidationError(e)
            }
            authkestra_guard::jwt::ValidationError::KeyNotFound => {
                OidcError::ValidationError("Key not found".to_string())
            }
            authkestra_guard::jwt::ValidationError::Paseto(e) => OidcError::ValidationError(e),
            authkestra_guard::jwt::ValidationError::Validation(e) => OidcError::ValidationError(e),
        }
    }
}
