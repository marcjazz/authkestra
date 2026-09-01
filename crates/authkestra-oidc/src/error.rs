use authkestra_engine::error::AuthError;
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

impl From<authkestra_resource::jwt::ValidationError> for OidcError {
    fn from(err: authkestra_resource::jwt::ValidationError) -> Self {
        match err {
            authkestra_resource::jwt::ValidationError::Discovery(e) => match e {
                AuthError::Discovery(msg) => OidcError::Discovery(msg),
                _ => OidcError::Discovery(e.to_string()),
            },
            authkestra_resource::jwt::ValidationError::Http(e) => OidcError::Network(e.to_string()),
            authkestra_resource::jwt::ValidationError::Jwt(e) => {
                OidcError::ValidationError(e.to_string())
            }
            authkestra_resource::jwt::ValidationError::Serialization(e) => {
                OidcError::Internal(e.to_string())
            }
            authkestra_resource::jwt::ValidationError::InvalidToken(e) => {
                OidcError::ValidationError(e)
            }
            authkestra_resource::jwt::ValidationError::KeyNotFound => {
                OidcError::ValidationError("Key not found".to_string())
            }
            authkestra_resource::jwt::ValidationError::MissingKid => {
                OidcError::ValidationError("Token is missing a required 'kid' header".to_string())
            }
            // Multi-issuer resolution (#243). Both are validation failures from
            // an RP's point of view: the token names an issuer this verifier
            // holds no JWKS for, or names none at all so no JWKS can be picked.
            authkestra_resource::jwt::ValidationError::UntrustedIssuer(issuer) => {
                OidcError::ValidationError(format!(
                    "Token issuer {issuer:?} is not in the configured trust map"
                ))
            }
            authkestra_resource::jwt::ValidationError::MissingIssuer => OidcError::ValidationError(
                "Token is missing a required 'iss' claim; an issuer is needed to select a JWKS"
                    .to_string(),
            ),
            authkestra_resource::jwt::ValidationError::Paseto(e) => OidcError::ValidationError(e),
            authkestra_resource::jwt::ValidationError::Validation(e) => {
                OidcError::ValidationError(e)
            }
            // Not "the token is invalid" — "we could not determine whether
            // it is" (no DpopReplayStore configured, or it errored). See
            // that variant's doc comment for why `authkestra-resource`
            // itself treats this as distinct from `InvalidToken`.
            authkestra_resource::jwt::ValidationError::DpopReplayUnavailable(e) => {
                OidcError::Internal(e)
            }
            // `ValidationError` is `#[non_exhaustive]`: a variant added
            // there after this match was written lands here instead of
            // failing to compile — its `Display` text is preserved, just
            // without a specific `OidcError` mapping of its own yet.
            other => OidcError::ValidationError(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_resource::jwt::ValidationError;

    #[test]
    fn test_oidc_error_mappings() {
        let err = OidcError::Discovery("foo".into());
        let ae: AuthError = err.into();
        assert!(matches!(ae, AuthError::Provider(_)));

        let err = OidcError::Network("foo".into());
        assert!(matches!(AuthError::from(err), AuthError::Network));

        let err = OidcError::ValidationError("foo".into());
        assert!(matches!(AuthError::from(err), AuthError::Token(_)));

        let err = OidcError::Provider("foo".into());
        assert!(matches!(AuthError::from(err), AuthError::Provider(_)));

        let err = OidcError::Internal("foo".into());
        assert!(matches!(AuthError::from(err), AuthError::Provider(_)));

        let err = AuthError::Discovery("foo".into());
        let oe: OidcError = err.into();
        assert!(matches!(oe, OidcError::Discovery(_)));

        let err = AuthError::Network;
        assert!(matches!(OidcError::from(err), OidcError::Network(_)));

        let err = AuthError::Token("foo".into());
        assert!(matches!(
            OidcError::from(err),
            OidcError::ValidationError(_)
        ));

        let err = AuthError::Provider("foo".into());
        assert!(matches!(OidcError::from(err), OidcError::Provider(_)));

        let err = AuthError::InvalidInput;
        assert!(matches!(OidcError::from(err), OidcError::Internal(_)));

        let err = ValidationError::KeyNotFound;
        assert!(matches!(
            OidcError::from(err),
            OidcError::ValidationError(_)
        ));

        let err = ValidationError::MissingKid;
        assert!(matches!(
            OidcError::from(err),
            OidcError::ValidationError(_)
        ));

        let err = ValidationError::UntrustedIssuer("foo".into());
        assert!(matches!(
            OidcError::from(err),
            OidcError::ValidationError(_)
        ));

        let err = ValidationError::MissingIssuer;
        assert!(matches!(
            OidcError::from(err),
            OidcError::ValidationError(_)
        ));

        let err = ValidationError::Paseto("foo".into());
        assert!(matches!(
            OidcError::from(err),
            OidcError::ValidationError(_)
        ));

        let err = ValidationError::Validation("foo".into());
        assert!(matches!(
            OidcError::from(err),
            OidcError::ValidationError(_)
        ));

        let err = ValidationError::DpopReplayUnavailable("foo".into());
        assert!(matches!(OidcError::from(err), OidcError::Internal(_)));

        let err = ValidationError::InvalidToken("foo".into());
        assert!(matches!(
            OidcError::from(err),
            OidcError::ValidationError(_)
        ));
    }
}
