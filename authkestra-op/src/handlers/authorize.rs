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
    let client = match clients.find_client(&req.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return AuthorizeOutcome::DirectError(OpError::UnknownClient(req.client_id)),
        Err(e) => return AuthorizeOutcome::DirectError(e),
    };

    // 2. Validate exact redirect_uri
    if !client.allows_redirect_uri(&req.redirect_uri) {
        return AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch);
    }

    // FROM HERE ON, all further errors are Redirect outcomes
    let redirect_url = req.redirect_uri.clone();
    let state = req.state.clone();

    let error_redirect = |error: &str, description: &str| -> AuthorizeOutcome {
        let mut url = redirect_url.clone();
        let sep = if url.contains('?') { "&" } else { "?" };
        url.push_str(&format!(
            "{}error={}&error_description={}",
            sep, error, description
        ));
        if let Some(ref s) = state {
            url.push_str(&format!("&state={}", s));
        }
        AuthorizeOutcome::Redirect(url)
    };

    // 4. Check response_type == "code"
    if req.response_type != "code" {
        return error_redirect(
            "unsupported_response_type",
            "Only response_type=code is supported",
        );
    }

    // 5. Check client allows AuthorizationCode grant type
    if !client.allows_grant_type(GrantType::AuthorizationCode) {
        return error_redirect(
            "unauthorized_client",
            "Client is not permitted to use the authorization code grant",
        );
    }

    // 6. PKCE requirements
    if client.require_pkce {
        if req.code_challenge.is_none() {
            return error_redirect("invalid_request", "code_challenge is required");
        }
        if req.code_challenge_method.as_deref() != Some("S256") {
            return error_redirect("invalid_request", "code_challenge_method must be S256");
        }
    } else if req.code_challenge.is_some() && req.code_challenge_method.as_deref() != Some("S256") {
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
    if codes.store_code(auth_code).await.is_err() {
        return error_redirect("server_error", "Failed to store authorization code");
    }

    // 9. Return Redirect with code and state
    let mut url = redirect_url;
    let sep = if url.contains('?') { "&" } else { "?" };
    url.push_str(&format!("{}code={}", sep, code_val));
    if let Some(ref s) = state {
        url.push_str(&format!("&state={}", s));
    }

    AuthorizeOutcome::Redirect(url)
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
}
