use crate::client::{ClientStore, GrantType};
use crate::code::{AuthorizationCode, AuthorizationCodeStore};
use crate::config::OpConfig;
use crate::error::OpError;
use authkestra_engine::auth::state::Identity;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use rand::RngCore;

/// Represents an incoming OAuth2/OIDC authorization request.
pub struct AuthorizeRequest {
    /// Client ID requesting authorization.
    pub client_id: String,
    /// Exact match redirect URI.
    pub redirect_uri: String,
    /// Response type (must be "code").
    pub response_type: String,
    /// Space-delimited scopes requested.
    pub scope: String,
    /// Optional opaque state parameter.
    pub state: Option<String>,
    /// PKCE code challenge.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method ("S256").
    pub code_challenge_method: Option<String>,
}

/// The result of an authorization request handler.
#[derive(Debug)]
pub enum AuthorizeOutcome {
    /// redirect_uri was valid; caller should redirect the browser here.
    Redirect(String),
    /// client_id or redirect_uri could not be verified — do NOT redirect.
    DirectError(OpError),
}

/// Validates an incoming authorization request, enforces PKCE, and issues an authorization code.
pub async fn handle_authorize(
    req: AuthorizeRequest,
    identity: Identity,
    config: &OpConfig,
    clients: &dyn ClientStore,
    codes: &dyn AuthorizationCodeStore,
) -> AuthorizeOutcome {
    // 1. Look up client_id
    tracing::debug!(client_id = %req.client_id, "Looking up client for authorization request");
    let client = match clients.find_client(&req.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            tracing::warn!(client_id = %req.client_id, "Unknown client ID requested");
            return AuthorizeOutcome::DirectError(OpError::UnknownClient(req.client_id));
        }
        Err(e) => {
            tracing::error!(error = ?e, "Error finding client");
            return AuthorizeOutcome::DirectError(e);
        }
    };

    // 2. Validate exact redirect_uri
    if !client.allows_redirect_uri(&req.redirect_uri) {
        tracing::warn!(
            client_id = %req.client_id,
            requested_uri = %req.redirect_uri,
            "Redirect URI mismatch"
        );
        return AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch);
    }

    // FROM HERE ON, all further errors are Redirect outcomes
    let parsed_uri = match url::Url::parse(&req.redirect_uri) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse matched redirect URI");
            return AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch);
        }
    };

    let error_redirect = |error: &str, description: &str| -> AuthorizeOutcome {
        let mut url = parsed_uri.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("error", error);
            query.append_pair("error_description", description);
            if let Some(ref s) = req.state {
                query.append_pair("state", s);
            }
        }
        AuthorizeOutcome::Redirect(url.into())
    };

    // 4. Check response_type == "code"
    if req.response_type != "code" {
        tracing::warn!(
            client_id = %req.client_id,
            response_type = %req.response_type,
            "Unsupported response type requested"
        );
        return error_redirect(
            "unsupported_response_type",
            "Only response_type=code is supported",
        );
    }

    // 5. Check client allows AuthorizationCode grant type
    if !client.allows_grant_type(GrantType::AuthorizationCode) {
        tracing::warn!(
            client_id = %req.client_id,
            "Client is not permitted to use the authorization code grant"
        );
        return error_redirect(
            "unauthorized_client",
            "Client is not permitted to use the authorization code grant",
        );
    }

    // 6. PKCE requirements
    if client.require_pkce {
        if req.code_challenge.is_none() {
            tracing::warn!(client_id = %req.client_id, "Missing required code_challenge for PKCE");
            return error_redirect("invalid_request", "code_challenge is required");
        }
        if req.code_challenge_method.as_deref() != Some("S256") {
            tracing::warn!(client_id = %req.client_id, "Invalid code_challenge_method, S256 required");
            return error_redirect("invalid_request", "code_challenge_method must be S256");
        }
    } else if req.code_challenge.is_none() && req.code_challenge_method.is_some() {
        tracing::warn!(client_id = %req.client_id, "code_challenge_method specified without code_challenge");
        return error_redirect(
            "invalid_request",
            "code_challenge is required when method is specified",
        );
    } else if req.code_challenge.is_some() && req.code_challenge_method.as_deref() != Some("S256") {
        tracing::warn!(client_id = %req.client_id, "Invalid code_challenge_method provided (optional PKCE), S256 required");
        return error_redirect("invalid_request", "code_challenge_method must be S256");
    }

    // 7. Build an AuthorizationCode
    let mut rng = rand::rng();
    let mut code_bytes = [0u8; 32];
    rng.fill_bytes(&mut code_bytes);
    let code_val = URL_SAFE_NO_PAD.encode(code_bytes);

    let expires_at = Utc::now() + Duration::seconds(config.authorization_code_ttl_secs);

    let auth_code = AuthorizationCode {
        code: code_val.clone(),
        client_id: client.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        scope: req.scope.clone(),
        code_challenge: req.code_challenge.clone(),
        code_challenge_method: req.code_challenge_method.clone(),
        identity,
        expires_at,
        used: false,
    };

    // 8. Store the code
    if let Err(e) = codes.store_code(auth_code).await {
        tracing::error!(error = ?e, client_id = %req.client_id, "Failed to store authorization code");
        return error_redirect("server_error", "Failed to store authorization code");
    }

    // 9. Return Redirect with code and state
    let mut url = parsed_uri;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("code", &code_val);
        if let Some(ref s) = req.state {
            query.append_pair("state", s);
        }
    }

    tracing::info!(client_id = %req.client_id, "Successfully issued authorization code");
    AuthorizeOutcome::Redirect(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientRegistration, InMemoryClientStore};
    use crate::code::InMemoryAuthorizationCodeStore;

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
            attributes: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_unknown_client_direct_error() {
        let clients = InMemoryClientStore::new();
        let codes = InMemoryAuthorizationCodeStore::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "unknown".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &clients, &codes).await;
        assert!(matches!(
            outcome,
            AuthorizeOutcome::DirectError(OpError::UnknownClient(_))
        ));
    }

    #[tokio::test]
    async fn test_mismatched_redirect_uri_direct_error() {
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
        let config = test_config();

        // Exact match required, this has a trailing slash difference
        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb/".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &clients, &codes).await;
        assert!(matches!(
            outcome,
            AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch)
        ));
    }

    #[tokio::test]
    async fn test_unsupported_response_type_redirect_error() {
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
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "token".to_string(), // not code
            scope: "openid".to_string(),
            state: Some("xyz".to_string()),
            code_challenge: None,
            code_challenge_method: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &clients, &codes).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=unsupported_response_type"));
            assert!(url.contains("state=xyz"));
            assert!(url.starts_with("https://app.example.com/cb?"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_missing_pkce_redirect_error() {
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
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None, // Missing PKCE
            code_challenge_method: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &clients, &codes).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_plain_pkce_redirect_error() {
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
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("plain".to_string()), // plain is rejected
        };

        let outcome = handle_authorize(req, test_identity(), &config, &clients, &codes).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_successful_authorization() {
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
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid profile".to_string(),
            state: Some("abc".to_string()),
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
        };

        let outcome = handle_authorize(req, test_identity(), &config, &clients, &codes).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.starts_with("https://app.example.com/cb?code="));
            assert!(url.contains("&state=abc"));

            // Extract code and verify it was persisted
            let code_val = url
                .split("code=")
                .nth(1)
                .unwrap()
                .split('&')
                .next()
                .unwrap();

            let persisted = codes.consume_code(code_val).await.unwrap().unwrap();
            assert_eq!(persisted.client_id, "client-1");
            assert_eq!(persisted.redirect_uri, "https://app.example.com/cb");
            assert_eq!(persisted.scope, "openid profile");
            assert_eq!(persisted.code_challenge, Some("s256challenge".to_string()));
            assert_eq!(persisted.identity.external_id, "user-123");
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_state_encoding() {
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
        let config = test_config();

        // State containing characters that require URL encoding
        let dangerous_state = "foo&bar=baz#123";

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: Some(dangerous_state.to_string()),
            code_challenge: None,
            code_challenge_method: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &clients, &codes).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            let parsed = url::Url::parse(&url).expect("Should be a valid URL");

            // Check that `state` is perfectly preserved and there are no injected query params
            let mut state_found = false;
            let mut code_found = false;
            for (k, v) in parsed.query_pairs() {
                if k == "state" {
                    assert_eq!(v, dangerous_state);
                    state_found = true;
                }
                if k == "code" {
                    code_found = true;
                }
                if k == "error" || k == "bar" {
                    panic!("Injected parameter found!");
                }
            }
            assert!(state_found, "state parameter must be present");
            assert!(code_found, "code parameter must be present");
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_pkce_method_without_challenge_redirect_error() {
        let clients = InMemoryClientStore::new();
        clients.register(ClientRegistration {
            client_id: "client-1".to_string(),
            client_secret_hash: None,
            redirect_uris: vec!["https://app.example.com/cb".to_string()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![],
            require_pkce: false, // PKCE is optional
        });

        let codes = InMemoryAuthorizationCodeStore::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: Some("S256".to_string()), // Method provided without challenge
        };

        let outcome = handle_authorize(req, test_identity(), &config, &clients, &codes).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
            assert!(
                url.contains(
                    "error_description=code_challenge+is+required+when+method+is+specified"
                ) || url.contains("code_challenge%20is%20required")
            );
        } else {
            panic!("Expected Redirect");
        }
    }
}
