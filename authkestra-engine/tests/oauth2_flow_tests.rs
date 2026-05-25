use authkestra_engine::auth::{
    AuthError, Identity, OAuthProvider, OAuthToken, Provider, ProviderConfig,
};
use authkestra_engine::flow::{Flow, FlowContext, FlowResult, OAuth2Flow};
use async_trait::async_trait;
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
    ) -> String {
        format!("https://example.com/auth?state={}", state)
    }

    async fn exchange_code_for_identity(
        &self,
        code: &str,
        _code_verifier: Option<&str>,
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
    
    let ctx = FlowContext {
        state: "new_state".to_string(),
        params: HashMap::new(),
    };
    
    let result = flow.execute(ctx).await.unwrap();
    
    match result {
        FlowResult::Redirect(url) => {
            assert!(url.contains("https://example.com/auth"));
            // The state in the URL might be different from ctx.state because OAuth2Flow::initiate_login generates its own UUID
            // but we just want to see it redirects.
        }
        _ => panic!("Expected Redirect"),
    }
}

#[tokio::test]
async fn test_oauth2_flow_finalize() {
    let provider = MockOAuthProvider;
    let flow = OAuth2Flow::new(provider);
    
    let mut params = HashMap::new();
    params.insert("code".to_string(), "valid_code".to_string());
    params.insert("state".to_string(), "correct_state".to_string());
    
    let ctx = FlowContext {
        state: "correct_state".to_string(),
        params,
    };
    
    let result = flow.execute(ctx).await.unwrap();
    
    match result {
        FlowResult::Complete(identity) => {
            assert_eq!(identity.external_id, "user123");
        }
        _ => panic!("Expected Complete"),
    }
}

#[tokio::test]
async fn test_oauth2_flow_finalize_invalid_state() {
    let provider = MockOAuthProvider;
    let flow = OAuth2Flow::new(provider);
    
    let mut params = HashMap::new();
    params.insert("code".to_string(), "valid_code".to_string());
    params.insert("state".to_string(), "wrong_state".to_string());
    
    let ctx = FlowContext {
        state: "correct_state".to_string(),
        params,
    };
    
    let result = flow.execute(ctx).await;
    assert!(matches!(result, Err(AuthError::CsrfMismatch)));
}
