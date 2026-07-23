use thiserror::Error;

/// Errors that can occur during OpenID Provider operations.
#[derive(Debug, Error)]
pub enum OpError {
    /// The requested client_id is not registered.
    #[error("unknown client: {0}")]
    UnknownClient(String),

    /// The provided redirect_uri does not exactly match a registered URI
    /// for this client. Always treat this as a hard failure — never fall
    /// back to a "closest match" or prefix comparison.
    #[error("redirect_uri does not match a registered URI for this client")]
    RedirectUriMismatch,

    /// The authorization code was not found, already used, or expired.
    #[error("invalid or expired authorization code")]
    InvalidCode,

    /// PKCE verification failed.
    #[error("PKCE verification failed")]
    PkceMismatch,

    /// The client_secret did not match the stored hash.
    #[error("invalid client credentials")]
    InvalidClientCredentials,

    /// The requested grant_type is not enabled for this client.
    #[error("grant_type not permitted for this client")]
    GrantTypeNotPermitted,

    /// Underlying storage error, opaque to the caller by design — storage
    /// backends should not leak implementation details (e.g. SQL errors)
    /// into OAuth error responses.
    #[error("storage error")]
    Storage,

    /// Token issuance failed at the `authkestra_engine::TokenManager` layer.
    #[error("token issuance failed: {0}")]
    TokenIssuance(String),
}
