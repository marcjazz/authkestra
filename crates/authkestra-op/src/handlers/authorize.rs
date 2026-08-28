use crate::client::GrantType;
use crate::code::AuthorizationCode;
use crate::config::OpConfig;
use crate::error::OpError;
use crate::store::OpStore;
use authkestra_engine::auth::state::Identity;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use rand::RngCore;

/// Represents an incoming OAuth2/OIDC authorization request.
#[derive(Debug, serde::Deserialize)]
#[non_exhaustive]
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
    /// PKCE code_challenge_method ("S256").
    pub code_challenge_method: Option<String>,
    /// OIDC nonce.
    pub nonce: Option<String>,
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
    op_store: &dyn OpStore,
) -> AuthorizeOutcome {
    // 1. Look up client_id
    tracing::debug!(client_id = %req.client_id, "Looking up client for authorization request");
    let client = match op_store.find_client(&req.client_id).await {
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

    // 3. Validate requested scope against the client's registration
    // (authkestra#278). `req.scope` was previously copied verbatim into the
    // stored code — and from there into the eventual token — with no check
    // at all, letting any registered client request (and receive) a scope
    // it was never granted. Rejects on the first offending scope, naming it
    // specifically, mirroring `default_handle_client_credentials`'s
    // existing (and correct) scope check at the token endpoint.
    for s in req.scope.split_whitespace() {
        if !client.allows_scope(s) {
            tracing::warn!(client_id = %req.client_id, scope = %s, "Client requested unauthorized scope");
            return error_redirect(
                "invalid_scope",
                &format!("Scope {s} is not allowed for this client"),
            );
        }
    }

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
    if !client.allows_grant_type(&GrantType::AuthorizationCode) {
        tracing::warn!(
            client_id = %req.client_id,
            "Client is not permitted to use the authorization code grant"
        );
        return error_redirect(
            "unauthorized_client",
            "Client is not permitted to use the authorization code grant",
        );
    }

    // 6. PKCE requirements — mandatory for every client, per OAuth 2.1 §4.1
    // (authkestra#273). `client.require_pkce` no longer gates this: OAuth 2.1
    // does not grandfather in confidential clients or any other exemption,
    // and per-client opt-out was the exact gap #273 closes.
    if req.code_challenge.is_none() {
        tracing::warn!(client_id = %req.client_id, "Missing required code_challenge for PKCE");
        return error_redirect("invalid_request", "code_challenge is required");
    }
    if req.code_challenge_method.as_deref() != Some("S256") {
        tracing::warn!(client_id = %req.client_id, "Invalid code_challenge_method, S256 required");
        return error_redirect("invalid_request", "code_challenge_method must be S256");
    }

    // 7. Build an AuthorizationCode
    let code_val = {
        let mut rng = rand::rng();
        let mut code_bytes = [0u8; 32];
        rng.fill_bytes(&mut code_bytes);
        URL_SAFE_NO_PAD.encode(code_bytes)
    };

    let expires_at = Utc::now() + Duration::seconds(config.authorization_code_ttl_secs);

    let auth_code = AuthorizationCode {
        code: code_val.clone(),
        client_id: client.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        scope: req.scope.clone(),
        code_challenge: req.code_challenge.clone(),
        code_challenge_method: req.code_challenge_method.clone(),
        nonce: req.nonce.clone(),
        identity,
        expires_at,
        used: false,
    };

    // 8. Store the code
    if let Err(e) = op_store.store_code(auth_code).await {
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
#[allow(deprecated)] // `require_pkce` (authkestra#273) — these fixtures don't exercise it
mod tests {
    use super::*;
    use crate::client::{ClientRegistration, GrantType};
    use crate::code::AuthorizationCodeStore;
    use authkestra_engine::store::KvStore;

    fn test_config() -> OpConfig {
        OpConfig {
            issuer: "https://op.example.com".to_string(),
            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
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
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "unknown".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        assert!(matches!(
            outcome,
            AuthorizeOutcome::DirectError(OpError::UnknownClient(_))
        ));
    }

    #[tokio::test]
    async fn test_mismatched_redirect_uri_direct_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec![],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
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
            nonce: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        assert!(matches!(
            outcome,
            AuthorizeOutcome::DirectError(OpError::RedirectUriMismatch)
        ));
    }

    #[tokio::test]
    async fn test_unsupported_response_type_redirect_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "token".to_string(), // not code
            scope: "openid".to_string(),
            state: Some("xyz".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
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
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None, // Missing PKCE
            code_challenge_method: None,
            nonce: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_plain_pkce_redirect_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("plain".to_string()), // plain is rejected
            nonce: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
        } else {
            panic!("Expected Redirect");
        }
    }

    #[tokio::test]
    async fn test_successful_authorization() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string(), "profile".to_string()],
                    require_pkce: true,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid profile".to_string(),
            state: Some("abc".to_string()),
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &crate::store::CompositeOpStore::new(clients, codes.clone(), authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
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
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        // State containing characters that require URL encoding
        let dangerous_state = "foo&bar=baz#123";

        // PKCE is mandatory (authkestra#273) regardless of `require_pkce`,
        // and unrelated to what this test actually covers (state encoding),
        // but required to reach the success path at all.
        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: Some(dangerous_state.to_string()),
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
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

    /// PKCE is mandatory regardless of `client.require_pkce` (authkestra#273):
    /// a client not opted into PKCE that still omits `code_challenge` (even
    /// while sending `code_challenge_method`) is rejected exactly like one
    /// that requires it.
    #[tokio::test]
    async fn test_pkce_method_without_challenge_redirect_error() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false, // no longer changes the outcome — PKCE is always required
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: Some("S256".to_string()), // Method provided without challenge
            nonce: None,
        };

        let outcome = handle_authorize(req, test_identity(), &config, &crate::store::CompositeOpStore::new(clients, codes, authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(), authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new())).await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
            assert!(url.contains("error_description=code_challenge+is+required"));
        } else {
            panic!("Expected Redirect");
        }
    }

    /// The core regression test for authkestra#273: a client explicitly
    /// registered with `require_pkce: false` and sending no PKCE parameters
    /// at all must still be rejected, since OAuth 2.1 §4.1 makes PKCE
    /// mandatory unconditionally rather than an opt-in per client.
    #[tokio::test]
    async fn test_pkce_is_mandatory_even_when_client_does_not_require_it() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
        };

        let outcome = handle_authorize(
            req,
            test_identity(),
            &config,
            &crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
        )
        .await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_request"));
            assert!(url.contains("error_description=code_challenge+is+required"));
        } else {
            panic!("Expected Redirect");
        }
    }

    /// The core regression test for authkestra#278: a client registered
    /// with a narrow scope must not be able to request — and receive an
    /// authorization code for — a scope it was never granted.
    #[tokio::test]
    async fn test_scope_not_granted_to_client_is_rejected() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "admin".to_string(),
            state: None,
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
        };

        let outcome = handle_authorize(
            req,
            test_identity(),
            &config,
            &crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
        )
        .await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_scope"));
            assert!(url.contains("error_description=Scope+admin+is+not+allowed"));
        } else {
            panic!("Expected Redirect");
        }
    }

    /// A request mixing a granted and an ungranted scope must still be
    /// rejected — partial credit is not an option.
    #[tokio::test]
    async fn test_one_ungranted_scope_among_several_is_rejected() {
        let clients = authkestra_engine::store::memory::MemoryStore::<
            crate::client::ClientRegistration,
        >::new();
        clients
            .set(
                "client-1",
                ClientRegistration {
                    client_id: "client-1".to_string(),
                    client_secret_hash: None,
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    grant_types: vec![GrantType::AuthorizationCode],
                    scopes: vec!["openid".to_string(), "profile".to_string()],
                    require_pkce: false,
                    allowed_audiences: vec![],
                    token_endpoint_auth_method: None,
                    jwks: None,
                },
                std::time::Duration::from_secs(31536000),
            )
            .await
            .unwrap();

        let codes =
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new();
        let config = test_config();

        let req = AuthorizeRequest {
            client_id: "client-1".to_string(),
            redirect_uri: "https://app.example.com/cb".to_string(),
            response_type: "code".to_string(),
            scope: "openid admin".to_string(),
            state: None,
            code_challenge: Some("s256challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: None,
        };

        let outcome = handle_authorize(
            req,
            test_identity(),
            &config,
            &crate::store::CompositeOpStore::new(
                clients,
                codes,
                authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(
                ),
                authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new(),
            ),
        )
        .await;
        if let AuthorizeOutcome::Redirect(url) = outcome {
            assert!(url.contains("error=invalid_scope"));
        } else {
            panic!("Expected Redirect");
        }
    }
}
