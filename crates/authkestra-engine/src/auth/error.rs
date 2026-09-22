use serde::{Deserialize, Serialize};

/// Errors that can occur during the authentication process.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// An error returned by the authentication provider
    #[error("Provider error: {0}")]
    Provider(String),
    /// The provided credentials (email/password) are invalid
    #[error("Invalid credentials")]
    InvalidCredentials,
    /// The authorization code is invalid or expired
    #[error("Invalid code")]
    InvalidCode,
    /// A network error occurred during communication with the provider
    #[error("Network error")]
    Network,
    /// An error occurred during session management
    #[error("Session error: {0}")]
    Session(String),
    /// An error occurred during token processing
    #[error("Token error: {0}")]
    Token(String),
    /// The CSRF state parameter does not match the expected value
    #[error("CSRF state mismatch")]
    CsrfMismatch,
    /// An error occurred during OIDC discovery
    #[error("Discovery error: {0}")]
    Discovery(String),
    /// A required component (e.g., SessionManager, TokenManager) is missing
    #[error("Missing component: {0}")]
    ComponentMissing(String),
    /// Invalid input provided
    #[error("Invalid input")]
    InvalidInput,
    /// Invalid or failed credentials verification
    #[error("Credentials error: {0}")]
    Credentials(String),
    /// An internal or unexpected storage error occurred
    #[error("Internal error: {0}")]
    Internal(String),
    /// The operation was refused because it was attempted too soon after a
    /// previous one.
    ///
    /// Distinct from [`AuthError::InvalidCredentials`] on purpose: nothing was
    /// wrong with what the caller presented, and retrying later will work.
    ///
    /// **Do not echo this to an unauthenticated caller verbatim.** It is
    /// scoped to a subject, so revealing it tells whoever asked that somebody
    /// recently requested something for that account — an enumeration signal
    /// the surrounding endpoint is responsible for not leaking, exactly as it
    /// is for the rest of these.
    #[error("Throttled")]
    Throttled,
    /// The credential store does not support this operation.
    /// When a store returns this, the operation has not been performed,
    /// and the data remains unchanged. This is different from a successful
    /// no-op — a store that silently ignores a revoke request is worse than
    /// one that admits it cannot perform the operation.
    #[error("Operation not supported by credential store")]
    Unsupported,
}

/// Represents an error response from an OAuth2 provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OAuthErrorResponse {
    /// The error code.
    pub error: String,
    /// A human-readable ASCII text description of the error.
    pub error_description: Option<String>,
}
