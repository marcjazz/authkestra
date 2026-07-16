use async_trait::async_trait;
use authkestra_engine::auth::{
    AuthError, Identity, OAuthProvider, OAuthToken, Provider, ProviderConfig,
};
use authkestra_engine::flow::OAuth2Flow;
use std::collections::HashMap;

struct MockOAuthProvider;

impl Provider for MockOAuthProvider {
    fn config(&self) -> ProviderConfig {
        ProviderConfig {
            id: "mock".to_string(),
            name: "Mock".to_string(),
            extra: HashMap::new(),
        }
    }
}

#[async_trait]
impl OAuthProvider for MockOAuthProvider {
    fn provider_id(&self) -> &str {
        "mock"
    }

    fn get_authorization_url(
        &self,
        state: &str,
        _scopes: &[&str],
        _code_challenge: Option<&str>,
        _nonce: Option<&str>,
    ) -> String {
        format!("https://example.com/auth?state={}", state)
    }

    async fn exchange_code_for_identity(
        &self,
        code: &str,
        _code_verifier: Option<&str>,
        _nonce: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        if code == "valid_code" {
            Ok((
                Identity {
                    provider_id: "mock".to_string(),
                    external_id: "user123".to_string(),
                    email: Some("user@example.com".to_string()),
                    username: Some("user".to_string()),
                    attributes: HashMap::new(),
                },
                OAuthToken {
                    access_token: "token".to_string(),
                    token_type: "Bearer".to_string(),
                    expires_in: None,
                    refresh_token: None,
                    scope: None,
                    id_token: None,
                },
            ))
        } else {
            Err(AuthError::Token("Invalid code".to_string()))
        }
    }
}

#[tokio::test]
async fn test_oauth2_flow_initiate() {
    let provider = MockOAuthProvider;
    let flow = OAuth2Flow::new(provider);

    let (url, state) = flow.initiate_login(&["openid"], None);

    assert!(url.contains("https://example.com/auth"));
    assert!(!state.state.is_empty());
}

#[tokio::test]
async fn test_oauth2_flow_finalize() {
    let provider = MockOAuthProvider;
    let flow = OAuth2Flow::new(provider);

    let (_, state) = flow.initiate_login(&["openid"], None);

    let (identity, _token, _) = flow
        .finalize_login("valid_code", &state.state, &state)
        .await
        .unwrap();

    assert_eq!(identity.external_id, "user123");
}

#[tokio::test]
async fn test_oauth2_flow_finalize_invalid_state() {
    let provider = MockOAuthProvider;
    let flow = OAuth2Flow::new(provider);

    let (_, state) = flow.initiate_login(&["openid"], None);

    let result = flow
        .finalize_login("valid_code", "wrong_state", &state)
        .await;
    assert!(matches!(result, Err(AuthError::CsrfMismatch)));
}
