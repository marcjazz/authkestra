use crate::client::ClientStore;
use crate::code::AuthorizationCodeStore;
use crate::config::OpConfig;
use authkestra_engine::token::TokenManager;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Request payload for the token endpoint.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// OAuth2 grant type.
    pub grant_type: String,
    /// The authorization code received from the authorization endpoint.
    pub code: String,
    /// The redirect URI used in the authorization request.
    pub redirect_uri: String,
    /// The client identifier.
    pub client_id: String,
    /// The PKCE code verifier used if a challenge was provided.
    pub code_verifier: Option<String>,
}

/// Success response for the token endpoint.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// The access token issued by the authorization server.
    pub access_token: String,
    /// The type of the token, typically "Bearer".
    pub token_type: String,
    /// The lifetime in seconds of the access token.
    pub expires_in: u64,
    /// The ID token, if `openid` scope was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The scope of the granted tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Error response for the token endpoint.
#[derive(Debug, Serialize)]
pub struct TokenErrorResponse {
    /// The OAuth2 error code.
    pub error: String,
    /// A human-readable description of the error.
    pub error_description: String,
}

/// Handles token exchange requests (e.g. `grant_type=authorization_code`).
pub async fn handle_token(
    req: TokenRequest,
    _config: &OpConfig,
    clients: &dyn ClientStore,
    codes: &dyn AuthorizationCodeStore,
    tokens: &TokenManager,
) -> Result<TokenResponse, TokenErrorResponse> {
    tracing::debug!(client_id = %req.client_id, "Processing token exchange request");

    // 1. Grant type validation
    if req.grant_type != "authorization_code" {
        tracing::warn!(grant_type = %req.grant_type, "Unsupported grant type");
        return Err(TokenErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: "Only authorization_code grant type is supported".to_string(),
        });
    }

    // 2. Client validation
    let client = match clients.find_client(&req.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::warn!(client_id = %req.client_id, "Unknown client ID during token exchange");
            return Err(TokenErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Client authentication failed".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Error finding client");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    // 3. Consume the code atomically
    let auth_code = match codes.consume_code(&req.code).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            tracing::warn!("Invalid or expired authorization code");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "Authorization code is invalid or already used".to_string(),
            });
        }
        Err(e) => {
            tracing::error!(error = ?e, "Error consuming authorization code");
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Internal server error".to_string(),
            });
        }
    };

    // Check expiration explicitly just in case the store didn't
    if Utc::now() > auth_code.expires_at {
        tracing::warn!("Authorization code expired");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Authorization code has expired".to_string(),
        });
    }

    // 4. Validate code was issued to this client
    if auth_code.client_id != req.client_id {
        tracing::warn!(
            expected_client = %auth_code.client_id,
            actual_client = %req.client_id,
            "Client ID mismatch during token exchange"
        );
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Authorization code was not issued to this client".to_string(),
        });
    }

    // 5. Validate redirect_uri matches
    if auth_code.redirect_uri != req.redirect_uri {
        tracing::warn!(
            expected_uri = %auth_code.redirect_uri,
            actual_uri = %req.redirect_uri,
            "Redirect URI mismatch during token exchange"
        );
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "Redirect URI does not match the one used during authorization"
                .to_string(),
        });
    }

    // 6. PKCE Enforcement
    if let Some(challenge) = &auth_code.code_challenge {
        let verifier = req.code_verifier.as_deref().unwrap_or("");
        if verifier.is_empty() {
            tracing::warn!("Missing code_verifier for PKCE-secured code");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "code_verifier is required".to_string(),
            });
        }

        let method = auth_code.code_challenge_method.as_deref().unwrap_or("");
        if method != "S256" {
            tracing::error!(
                method = %method,
                "Unsupported PKCE challenge method in stored authorization code. Only S256 is allowed."
            );
            return Err(TokenErrorResponse {
                error: "server_error".to_string(),
                error_description: "Unsupported PKCE challenge method".to_string(),
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        let computed_challenge = URL_SAFE_NO_PAD.encode(hash);

        if computed_challenge != *challenge {
            tracing::warn!("PKCE S256 code challenge mismatch");
            return Err(TokenErrorResponse {
                error: "invalid_grant".to_string(),
                error_description: "code_verifier is invalid".to_string(),
            });
        }
    } else if client.require_pkce {
        tracing::warn!("PKCE was required by client config but code lacks challenge");
        return Err(TokenErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "PKCE is required".to_string(),
        });
    }

    // 7. Issue tokens
    let expires_in = 3600; // Typically would come from config or client settings
    let scope_opt = if auth_code.scope.is_empty() {
        None
    } else {
        Some(auth_code.scope.clone())
    };

    let access_token =
        match tokens.issue_user_token(auth_code.identity.clone(), expires_in, scope_opt.clone()) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue access token");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate token".to_string(),
                });
            }
        };

    let id_token = if auth_code.scope.contains("openid") {
        // Here we just reissue a JWT for the ID token. In reality we might want a different audience, etc.
        match tokens.issue_user_token(auth_code.identity, expires_in, scope_opt.clone()) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::error!(error = ?e, "Failed to issue id token");
                return Err(TokenErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate ID token".to_string(),
                });
            }
        }
    } else {
        None
    };

    tracing::info!(
        client_id = %req.client_id,
        "Successfully exchanged authorization code for tokens"
    );

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        id_token,
        scope: scope_opt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientRegistration, GrantType, InMemoryClientStore};
    use crate::code::{AuthorizationCode, InMemoryAuthorizationCodeStore};
    use authkestra_engine::auth::state::Identity;
    use chrono::Duration;
    use std::collections::HashMap;

    fn test_config() -> OpConfig {
        OpConfig {
            issuer: "https://auth.example.com".to_string(),
            scopes_supported: vec![],
            response_types_supported: vec![],
            grant_types_supported: vec![],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
        }
    }

    fn test_identity() -> Identity {
        Identity {
            provider_id: "local".to_string(),
            external_id: "user-123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        }
    }

    fn test_tokens() -> TokenManager {
        TokenManager::new(b"secret", Some("issuer".to_string()))
    }

    #[tokio::test]
    async fn test_invalid_grant_type() {
        let clients = InMemoryClientStore::new();
        let codes = InMemoryAuthorizationCodeStore::new();
        let config = test_config();
        let tokens = test_tokens();

        let req = TokenRequest {
            grant_type: "client_credentials".to_string(), // Invalid
            code: "xyz".to_string(),
            redirect_uri: "http://cb".to_string(),
            client_id: "client-1".to_string(),
            code_verifier: None,
        };

        let result = handle_token(req, &config, &clients, &codes, &tokens).await;
        assert_eq!(result.unwrap_err().error, "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_successful_exchange_with_pkce() {
        let clients = InMemoryClientStore::new();
        clients.register(ClientRegistration {
            client_id: "client-1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![],
            require_pkce: true,
        });

        let codes = InMemoryAuthorizationCodeStore::new();
        let verifier = "my-secret-verifier";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        let code_val = "valid-code-123".to_string();
        codes
            .store_code(AuthorizationCode {
                code: code_val.clone(),
                client_id: "client-1".to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                code_challenge: Some(challenge),
                code_challenge_method: Some("S256".to_string()),
                identity: test_identity(),
                expires_at: Utc::now() + Duration::seconds(60),
                used: false,
            })
            .await
            .unwrap();

        let config = test_config();
        let tokens = test_tokens();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: code_val,
            redirect_uri: "https://app.example.com/cb".to_string(),
            client_id: "client-1".to_string(),
            code_verifier: Some(verifier.to_string()),
        };

        let res = handle_token(req, &config, &clients, &codes, &tokens)
            .await
            .unwrap();

        assert_eq!(res.token_type, "Bearer");
        assert!(res.id_token.is_some());
        assert_eq!(res.scope.as_deref(), Some("openid"));
    }

    #[tokio::test]
    async fn test_invalid_pkce_verifier() {
        let clients = InMemoryClientStore::new();
        clients.register(ClientRegistration {
            client_id: "client-1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![],
            require_pkce: true,
        });

        let codes = InMemoryAuthorizationCodeStore::new();
        let code_val = "valid-code-123".to_string();
        codes
            .store_code(AuthorizationCode {
                code: code_val.clone(),
                client_id: "client-1".to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                code_challenge: Some("some-challenge".to_string()),
                code_challenge_method: Some("S256".to_string()),
                identity: test_identity(),
                expires_at: Utc::now() + Duration::seconds(60),
                used: false,
            })
            .await
            .unwrap();

        let config = test_config();
        let tokens = test_tokens();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: code_val,
            redirect_uri: "https://app.example.com/cb".to_string(),
            client_id: "client-1".to_string(),
            code_verifier: Some("wrong-verifier".to_string()),
        };

        let result = handle_token(req, &config, &clients, &codes, &tokens).await;
        assert_eq!(result.unwrap_err().error, "invalid_grant");
    }

    #[tokio::test]
    async fn test_redirect_uri_mismatch() {
        let clients = InMemoryClientStore::new();
        clients.register(ClientRegistration {
            client_id: "client-1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![],
            require_pkce: false,
        });

        let codes = InMemoryAuthorizationCodeStore::new();
        let code_val = "valid-code-123".to_string();
        codes
            .store_code(AuthorizationCode {
                code: code_val.clone(),
                client_id: "client-1".to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(), // original
                scope: "".to_string(),
                code_challenge: None,
                code_challenge_method: None,
                identity: test_identity(),
                expires_at: Utc::now() + Duration::seconds(60),
                used: false,
            })
            .await
            .unwrap();

        let config = test_config();
        let tokens = test_tokens();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: code_val,
            redirect_uri: "https://wrong.example.com/cb".to_string(), // mismatch
            client_id: "client-1".to_string(),
            code_verifier: None,
        };

        let result = handle_token(req, &config, &clients, &codes, &tokens).await;
        assert_eq!(result.unwrap_err().error, "invalid_grant");
    }
    #[tokio::test]
    async fn test_reject_plain_pkce_method() {
        let clients = InMemoryClientStore::new();
        clients.register(ClientRegistration {
            client_id: "client-1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![],
            require_pkce: true,
        });

        let codes = InMemoryAuthorizationCodeStore::new();
        let code_val = "valid-code-123".to_string();
        codes
            .store_code(AuthorizationCode {
                code: code_val.clone(),
                client_id: "client-1".to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                code_challenge: Some("some-challenge".to_string()),
                // Deliberately malformed stored code using "plain" method
                code_challenge_method: Some("plain".to_string()),
                identity: test_identity(),
                expires_at: Utc::now() + Duration::seconds(60),
                used: false,
            })
            .await
            .unwrap();

        let config = test_config();
        let tokens = test_tokens();

        let req = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: code_val,
            redirect_uri: "https://app.example.com/cb".to_string(),
            client_id: "client-1".to_string(),
            code_verifier: Some("some-challenge".to_string()), // Even if it matches, it should be rejected
        };

        let result = handle_token(req, &config, &clients, &codes, &tokens).await;
        let err = result.unwrap_err();
        assert_eq!(err.error, "server_error");
        assert_eq!(err.error_description, "Unsupported PKCE challenge method");
    }
}
