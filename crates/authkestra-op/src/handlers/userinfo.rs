use crate::config::OpConfig;
use authkestra_engine::token::TokenManager;
use serde::Serialize;

/// Request payload for the userinfo endpoint.
#[derive(Debug)]
pub struct UserInfoRequest {
    /// The access token provided in the Authorization header.
    pub access_token: String,
}

/// Success response for the userinfo endpoint.
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    /// Subject identifier.
    pub sub: String,
    /// End-User's preferred e-mail address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// End-User's name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Any other claims.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Error response for the userinfo endpoint.
#[derive(Debug, Serialize)]
pub struct UserInfoErrorResponse {
    /// The error code.
    pub error: String,
    /// A human-readable description of the error.
    pub error_description: String,
}

/// Handles userinfo requests.
pub async fn handle_userinfo(
    req: UserInfoRequest,
    _config: &OpConfig,
    tokens: &TokenManager,
) -> Result<UserInfoResponse, UserInfoErrorResponse> {
    tracing::debug!("Processing userinfo request");

    // 1. Verify token
    let claims = match tokens.validate_token(&req.access_token, None) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = ?e, "Invalid access token provided to userinfo endpoint");
            return Err(UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "The access token is invalid or expired".to_string(),
            });
        }
    };

    // 2. Check scopes
    let scope_str = claims.scope.unwrap_or_default();
    let scopes: Vec<&str> = scope_str.split_whitespace().collect();

    if !scopes.contains(&"openid") {
        tracing::warn!("Token lacks openid scope for userinfo endpoint");
        return Err(UserInfoErrorResponse {
            error: "insufficient_scope".to_string(),
            error_description: "The access token requires the openid scope".to_string(),
        });
    }

    // 3. Build response based on identity
    let identity = match claims.identity {
        Some(id) => id,
        None => {
            tracing::warn!("Token lacks identity information");
            return Err(UserInfoErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "The access token does not contain user identity".to_string(),
            });
        }
    };

    let mut response = UserInfoResponse {
        sub: identity.external_id,
        email: None,
        name: None,
        extra: std::collections::HashMap::new(),
    };

    if scopes.contains(&"email") {
        response.email = identity.email;
    }

    if scopes.contains(&"profile") {
        response.name = identity.username;
        // Optionally populate other profile claims from attributes
    }

    tracing::info!(sub = %response.sub, "Successfully returned userinfo");

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_engine::auth::state::Identity;

    fn test_config() -> OpConfig {
        OpConfig {
            issuer: "https://auth.example.com".to_string(),
            scopes_supported: vec![],
            response_types_supported: vec![],
            grant_types_supported: vec![],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
        }
    }

    fn test_tokens() -> TokenManager {
        TokenManager::new(b"secret", Some("issuer".to_string()))
    }

    fn test_identity() -> Identity {
        Identity {
            provider_id: "local".to_string(),
            external_id: "user-123".to_string(),
            email: Some("user@example.com".to_string()),
            username: Some("Test User".to_string()),
            attributes: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_missing_openid_scope() {
        let config = test_config();
        let tokens = test_tokens();

        // Issue token without openid scope
        let token = tokens
            .issue_user_token(test_identity(), 3600, Some("profile".to_string()))
            .unwrap();

        let req = UserInfoRequest {
            access_token: token,
        };

        let result = handle_userinfo(req, &config, &tokens).await;
        assert_eq!(result.unwrap_err().error, "insufficient_scope");
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let config = test_config();
        let tokens = test_tokens();

        let req = UserInfoRequest {
            access_token: "invalid.token.here".to_string(),
        };

        let result = handle_userinfo(req, &config, &tokens).await;
        assert_eq!(result.unwrap_err().error, "invalid_token");
    }

    #[tokio::test]
    async fn test_successful_userinfo() {
        let config = test_config();
        let tokens = test_tokens();

        // Issue token with openid, profile, email scopes
        let token = tokens
            .issue_user_token(
                test_identity(),
                3600,
                Some("openid profile email".to_string()),
            )
            .unwrap();

        let req = UserInfoRequest {
            access_token: token,
        };

        let result = handle_userinfo(req, &config, &tokens).await.unwrap();
        assert_eq!(result.sub, "user-123");
        assert_eq!(result.email.as_deref(), Some("user@example.com"));
        assert_eq!(result.name.as_deref(), Some("Test User"));
    }

    #[tokio::test]
    async fn test_successful_userinfo_no_email_scope() {
        let config = test_config();
        let tokens = test_tokens();

        // Issue token with openid, profile scopes (NO email)
        let token = tokens
            .issue_user_token(test_identity(), 3600, Some("openid profile".to_string()))
            .unwrap();

        let req = UserInfoRequest {
            access_token: token,
        };

        let result = handle_userinfo(req, &config, &tokens).await.unwrap();
        assert_eq!(result.sub, "user-123");
        assert_eq!(result.email, None); // Should be None because email scope wasn't requested
        assert_eq!(result.name.as_deref(), Some("Test User"));
    }
}
