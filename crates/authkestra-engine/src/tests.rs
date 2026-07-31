use crate::auth::session::{Session, SessionStore};
use crate::auth::{AuthError, AuthInput, AuthMethod, Identity, Provider, ProviderConfig};
use crate::flow::{Flow, FlowContext, FlowResult};
use async_trait::async_trait;
use std::collections::HashMap;

struct MockAuthMethod;
#[async_trait]
impl AuthMethod for MockAuthMethod {
    fn name(&self) -> &str {
        "mock"
    }
    async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
        Ok(Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: Some("mock@example.com".to_string()),
            username: Some("Mock User".to_string()),
            attributes: HashMap::new(),
        })
    }
    async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
        Ok(true) // pretend everyone is enrolled for testing
    }
}

struct MockProvider;
#[async_trait]
impl Provider for MockProvider {
    async fn config(&self) -> ProviderConfig {
        ProviderConfig {
            id: "mock-provider".to_string(),
            name: "Mock Provider".to_string(),
            extra: HashMap::new(),
        }
    }
}

struct MockFlow;
#[async_trait]
impl Flow for MockFlow {
    fn id(&self) -> &str {
        "mock-flow"
    }
    async fn execute(&self, _ctx: FlowContext) -> Result<FlowResult, AuthError> {
        Ok(FlowResult::Complete(Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: Some("mock@example.com".to_string()),
            username: Some("Mock User".to_string()),
            attributes: HashMap::new(),
        }))
    }
}

struct MockSessionStore;
#[async_trait]
impl SessionStore for MockSessionStore {
    async fn load_session(&self, _id: &str) -> Result<Option<Session>, AuthError> {
        Ok(None)
    }
    async fn save_session(&self, _session: &Session) -> Result<(), AuthError> {
        Ok(())
    }
    async fn delete_session(&self, _id: &str) -> Result<(), AuthError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_auth_method_mock() {
    let method = MockAuthMethod;
    let identity = method
        .authenticate(AuthInput::Token("test".to_string()))
        .await
        .unwrap();
    assert_eq!(identity.external_id, "user123");
}

#[tokio::test]
async fn test_provider_mock() {
    let provider = MockProvider;
    assert_eq!(provider.config().await.id, "mock-provider");
}

#[tokio::test]
async fn test_flow_mock() {
    let flow = MockFlow;
    let ctx = FlowContext {
        state: "test".to_string(),
        params: HashMap::new(),
    };
    let result = flow.execute(ctx).await.unwrap();
    if let FlowResult::Complete(identity) = result {
        assert_eq!(identity.external_id, "user123");
    } else {
        panic!("Expected FlowResult::Complete");
    }
}

#[tokio::test]
async fn test_session_store_mock() {
    let store = MockSessionStore;
    let session = store.load_session("test").await.unwrap();
    assert!(session.is_none());
}

#[test]
fn test_authkestra_builder_typestate() {
    use crate::engine::Engine;
    use std::sync::Arc;

    let builder = Engine::builder();
    let _engine = builder.build();

    let store = MockSessionStore;
    let engine_with_session = Engine::builder().session_store(Arc::new(store)).build();

    let _s = engine_with_session.session_store();
}

struct MockMfaMethod;
#[async_trait]
impl AuthMethod for MockMfaMethod {
    fn name(&self) -> &str {
        "mock_mfa"
    }
    async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
        Ok(Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: Some("mock@example.com".to_string()),
            username: Some("Mock User".to_string()),
            attributes: HashMap::new(),
        })
    }
    async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
        Ok(true) // enrolled
    }
}

#[tokio::test]
async fn test_primary_method_requires_mfa() {
    use crate::auth::AuthResult;
    use crate::Engine;

    struct TestPasswordMethod;
    #[async_trait]
    impl AuthMethod for TestPasswordMethod {
        fn name(&self) -> &str {
            "password"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "password".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    let engine = Engine::builder()
        .with_auth_method(TestPasswordMethod)
        .with_mfa_method(MockMfaMethod)
        .build();

    let res = engine
        .authenticate(AuthInput::Password {
            identifier: "".to_string(),
            password: "".to_string(),
        })
        .await
        .unwrap();

    match res {
        AuthResult::MfaRequired {
            allowed_methods, ..
        } => {
            assert_eq!(allowed_methods, vec!["mock_mfa"]);
        }
        _ => panic!("Expected MFA required"),
    }
}

#[tokio::test]
async fn test_mfa_equivalent_bypasses_mfa() {
    use crate::auth::AuthResult;
    use crate::Engine;

    struct TestWebAuthnMethod;
    #[async_trait]
    impl AuthMethod for TestWebAuthnMethod {
        fn name(&self) -> &str {
            "webauthn"
        }
        fn is_mfa_equivalent(&self) -> bool {
            true
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "webauthn".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    let engine = Engine::builder()
        .with_auth_method(TestWebAuthnMethod)
        .with_mfa_method(MockMfaMethod)
        .build();

    let res = engine
        .authenticate(AuthInput::WebAuthnAuthentication {
            user_id: "".to_string(),
            credential_id: "".to_string(),
            client_data_json: "".to_string(),
            authenticator_data: "".to_string(),
            signature: "".to_string(),
            user_handle: None,
            auth_state_json: None,
        })
        .await
        .unwrap();

    match res {
        AuthResult::Success(_) => {}
        _ => panic!("Expected Success"),
    }
}

#[tokio::test]
#[cfg(feature = "totp")]
async fn test_totp_primary_requires_mfa() {
    use crate::auth::AuthResult;
    use crate::Engine;

    struct TestTotpMethod;
    #[async_trait]
    impl AuthMethod for TestTotpMethod {
        fn name(&self) -> &str {
            "totp"
        }
        async fn authenticate(&self, _input: AuthInput) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "totp".to_string(),
                external_id: "user123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
    }

    let engine = Engine::builder()
        .with_auth_method(TestTotpMethod)
        .with_mfa_method(MockMfaMethod)
        .build();

    let res = engine
        .authenticate(AuthInput::Totp {
            user_id: "user123".to_string(),
            code: "123456".to_string(),
        })
        .await
        .unwrap();

    match res {
        AuthResult::MfaRequired {
            allowed_methods, ..
        } => {
            assert_eq!(allowed_methods, vec!["mock_mfa"]);
        }
        _ => panic!("Expected MFA required for TOTP primary"),
    }
}
