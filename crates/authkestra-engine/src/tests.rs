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
#[cfg(feature = "webauthn")]
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

// --- MFA continuation token: clock-skew window (#350 follow-up) ---
//
// `Engine::authenticate` validates the MFA token that resumes a
// half-completed login. That validation used to take `jsonwebtoken`'s
// 60-second `exp` tolerance silently; it is now stated explicitly. These
// characterize the window rather than a change, because the value did not
// move — the point is that the boundary is now visible in the suite, so
// tightening or widening it later has to be a deliberate edit with a failing
// test attached rather than an invisible consequence of a dependency bump.
//
// `Totp` is the `challenge_input`, not `Password`: `authenticate` maps only
// `Totp`/`WebAuthnAuthentication` to an MFA method and returns
// `InvalidInput` for anything else *before* it ever looks at `exp`. A first
// draft of these tests used `Password`, which made the "beyond the leeway"
// case pass for entirely the wrong reason — it would have passed with the
// expiry check deleted outright.
#[cfg(feature = "totp")]
mod mfa_token_leeway {
    use super::*;
    use crate::auth::AuthResult;
    use crate::Engine;

    /// An MFA method registered under the name the `Totp` challenge maps to,
    /// returning the same `external_id` the MFA token's `sub` carries so the
    /// post-validation user check passes.
    struct MockTotpMethod;
    #[async_trait]
    impl AuthMethod for MockTotpMethod {
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
        async fn has_enrolled(&self, _user_id: &str) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    fn engine() -> crate::Engine<crate::engine::Missing, crate::engine::Missing> {
        Engine::builder().with_mfa_method(MockTotpMethod).build()
    }

    /// Mints an MFA continuation token whose `exp` is `seconds_ago` in the
    /// past, signed with the engine's own secret so that expiry is the only
    /// thing wrong with it.
    fn expired_mfa_token<S, T>(engine: &crate::Engine<S, T>, seconds_ago: i64) -> String {
        let exp = chrono::Utc::now() - chrono::Duration::seconds(seconds_ago);
        let claims = crate::auth::state::MfaTokenClaims {
            sub: "user123".to_string(),
            mfa_pending: true,
            exp: exp.timestamp() as usize,
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&engine.mfa_jwt_secret),
        )
        .expect("signing the MFA token should succeed")
    }

    fn challenge(mfa_token: String) -> AuthInput {
        AuthInput::MfaChallenge {
            mfa_token,
            challenge_input: Box::new(AuthInput::Totp {
                user_id: "user123".to_string(),
                code: "000000".to_string(),
            }),
        }
    }

    /// A live token resumes the login. Establishes that everything *other*
    /// than expiry is wired correctly, so the rejection below is attributable
    /// to the window and not to the fixture.
    #[tokio::test]
    async fn a_live_mfa_token_resumes_the_login() {
        let engine = engine();
        // Negative "seconds ago" puts `exp` in the future.
        let token = expired_mfa_token(&engine, -600);

        let result = engine.authenticate(challenge(token)).await;
        assert!(
            matches!(result, Ok(AuthResult::Success(_))),
            "a live MFA token should resume the login, got {result:?}"
        );
    }

    #[tokio::test]
    async fn an_mfa_token_expired_within_the_leeway_still_resumes_the_login() {
        let engine = engine();
        let token = expired_mfa_token(&engine, 30);

        let result = engine.authenticate(challenge(token)).await;
        assert!(
            matches!(result, Ok(AuthResult::Success(_))),
            "within DEFAULT_LEEWAY_SECS the token is still honoured, got {result:?}"
        );
    }

    #[tokio::test]
    async fn an_mfa_token_expired_beyond_the_leeway_is_refused() {
        let engine = engine();
        // Comfortably past the tolerance, so this does not sit on the boundary.
        let token = expired_mfa_token(&engine, crate::token::DEFAULT_LEEWAY_SECS as i64 + 60);

        let result = engine.authenticate(challenge(token)).await;
        assert!(
            matches!(result, Err(AuthError::InvalidInput)),
            "past the tolerance a stale MFA token must not resume a login, got {result:?}"
        );
    }
}
