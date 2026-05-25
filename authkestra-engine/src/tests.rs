#[cfg(test)]
mod tests {
    use crate::auth::session::{Session, SessionStore};
    use crate::auth::{AuthError, AuthInput, AuthMethod, Identity, Provider, ProviderConfig};
    use crate::flow::{Flow, FlowContext, FlowResult};
    use crate::token::TokenService;
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
    }

    struct MockProvider;
    impl Provider for MockProvider {
        fn config(&self) -> ProviderConfig {
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

    struct MockTokenService;
    #[async_trait]
    impl TokenService for MockTokenService {
        async fn issue(
            &self,
            _identity: &Identity,
            _expires_in_secs: u64,
        ) -> Result<String, AuthError> {
            Ok("mock-token".to_string())
        }
        async fn verify(&self, _token: &str) -> Result<Identity, AuthError> {
            Ok(Identity {
                provider_id: "mock".to_string(),
                external_id: "user123".to_string(),
                email: Some("mock@example.com".to_string()),
                username: Some("Mock User".to_string()),
                attributes: HashMap::new(),
            })
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

    #[test]
    fn test_provider_mock() {
        let provider = MockProvider;
        assert_eq!(provider.config().id, "mock-provider");
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
    async fn test_token_service_mock() {
        let service = MockTokenService;
        let identity = Identity {
            provider_id: "mock".to_string(),
            external_id: "user123".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        };
        let token = service.issue(&identity, 3600).await.unwrap();
        assert_eq!(token, "mock-token");
        let verified = service.verify(&token).await.unwrap();
        assert_eq!(verified.external_id, "user123");
    }

    #[tokio::test]
    async fn test_session_store_mock() {
        let store = MockSessionStore;
        let session = store.load_session("test").await.unwrap();
        assert!(session.is_none());
    }

    #[test]
    fn test_auth_engine_builder_typestate() {
        use crate::engine::AuthEngine;
        use std::sync::Arc;

        // Base builder - session_store() not yet available (it is, but let's see how it behaves)
        let builder = AuthEngine::builder();
        let _engine = builder.build();
        // _engine.session_store(); // This would fail to compile

        // Transition to with session store
        let store = MockSessionStore;
        let engine_with_session = AuthEngine::builder().session_store(Arc::new(store)).build();

        // Now session_store() is available
        let _s = engine_with_session.session_store();
    }
}
