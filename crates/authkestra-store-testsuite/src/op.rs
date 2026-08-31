use authkestra_engine::auth::state::Identity;
use authkestra_engine::chrono::{Duration, Utc};
use authkestra_op::client_assertion::ClientAssertionStore;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_op::store::OpStore;
use std::collections::HashMap;

fn test_identity() -> Identity {
    Identity {
        provider_id: "test".to_string(),
        external_id: "user-1".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    }
}

/// Generic conformance suite for the `OpStore` family — proves an
/// implementation's `AuthorizationCodeStore`/`RefreshTokenStore`/
/// `DeviceCodeStore` methods honor the single-use, atomic-consume, and
/// full-lifecycle contracts every backend (first-party or third-party) must
/// uphold. This is the reusable check `authkestra-store-sqlx` and any ORM
/// example crate run against themselves, rather than each hand-rolling its
/// own version of these same tests.
///
/// `ClientStore` is deliberately **not** exercised here: it exposes only
/// `find_client` (registration is out-of-band, the deployment's business —
/// see `CompositeOpStore`'s docs), so there is no store-agnostic way to seed
/// a client through the trait itself for this suite to read back.
pub async fn run_op_store_tests<S: OpStore>(store: &mut S) {
    run_authorization_code_store_tests(store).await;
    run_refresh_token_store_tests(store).await;
    run_device_code_store_tests(store).await;
}

async fn run_authorization_code_store_tests<S: AuthorizationCodeStore>(store: &mut S) {
    let code = AuthorizationCode {
        code: "conformance-code-1".to_string(),
        client_id: "client-1".to_string(),
        redirect_uri: "https://cb.example.com".to_string(),
        scope: "openid".to_string(),
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
        identity: test_identity(),
        expires_at: Utc::now() + Duration::minutes(5),
        used: false,
    };

    store
        .store_code(code.clone())
        .await
        .expect("storing a fresh authorization code must succeed");

    let consumed = store
        .consume_code(&code.code)
        .await
        .expect("consuming a just-stored code must not error")
        .expect("consuming a just-stored code must return it");
    assert_eq!(consumed.code, code.code);
    assert_eq!(consumed.client_id, code.client_id);
    assert_eq!(consumed.identity.external_id, code.identity.external_id);

    let consumed_again = store
        .consume_code(&code.code)
        .await
        .expect("re-consuming an already-consumed code must not error");
    assert!(
        consumed_again.is_none(),
        "an authorization code must be single-use — consuming it twice must not \
         return it the second time"
    );

    let missing = store
        .consume_code("conformance-code-never-issued")
        .await
        .expect("consuming a code that was never issued must not error");
    assert!(
        missing.is_none(),
        "consuming a code that was never stored must return None, not an error"
    );
}

async fn run_refresh_token_store_tests<S: RefreshTokenStore>(store: &mut S) {
    let token = RefreshToken {
        token: "conformance-refresh-1".to_string(),
        client_id: "client-1".to_string(),
        identity: test_identity(),
        scope: "openid offline_access".to_string(),
        expires_at: Utc::now() + Duration::days(30),
        jkt: None,
    };

    store
        .store_token(token.clone())
        .await
        .expect("storing a fresh refresh token must succeed");

    let fetched = store
        .get_token(&token.token)
        .await
        .expect("getting a just-stored token must not error")
        .expect("getting a just-stored token must return it");
    assert_eq!(fetched.token, token.token);
    assert_eq!(fetched.scope, token.scope);

    // get_token must not consume — a second get must still see it.
    let fetched_again = store
        .get_token(&token.token)
        .await
        .expect("a second get must not error")
        .expect("get_token must not consume the token as a side effect");
    assert_eq!(fetched_again.token, token.token);

    let consumed = store
        .consume_token(&token.token)
        .await
        .expect("consuming a stored token must not error")
        .expect("consuming a stored token must return it");
    assert_eq!(consumed.token, token.token);

    let consumed_again = store
        .consume_token(&token.token)
        .await
        .expect("re-consuming an already-consumed token must not error");
    assert!(
        consumed_again.is_none(),
        "a refresh token must be single-use on rotation — consuming it twice \
         must not return it the second time"
    );

    let revocable = RefreshToken {
        token: "conformance-refresh-2".to_string(),
        ..token
    };
    store
        .store_token(revocable.clone())
        .await
        .expect("storing a second refresh token must succeed");
    store
        .revoke_token(&revocable.token)
        .await
        .expect("revoking a stored token must succeed");
    let after_revoke = store
        .get_token(&revocable.token)
        .await
        .expect("getting a revoked token must not error");
    assert!(
        after_revoke.is_none(),
        "a revoked refresh token must no longer be retrievable"
    );
}

async fn run_device_code_store_tests<S: DeviceCodeStore>(store: &mut S) {
    let session = DeviceCodeSession {
        device_code: "conformance-device-1".to_string(),
        user_code: "CONF-USER-1".to_string(),
        client_id: "client-1".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() + Duration::minutes(10),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
    };

    store
        .store_device_code(session.clone())
        .await
        .expect("storing a fresh device code session must succeed");

    let by_device = store
        .get_device_code(&session.device_code)
        .await
        .expect("getting by device_code must not error")
        .expect("getting a just-stored session by device_code must return it");
    assert!(matches!(by_device.status, DeviceCodeStatus::Pending));

    let by_user = store
        .get_by_user_code(&session.user_code)
        .await
        .expect("getting by user_code must not error")
        .expect("getting a just-stored session by user_code must return it");
    assert_eq!(by_user.device_code, session.device_code);

    let approved = DeviceCodeSession {
        status: DeviceCodeStatus::Approved(test_identity()),
        ..by_device
    };
    store
        .update_device_code(approved)
        .await
        .expect("updating a stored session must succeed");
    let after_update = store
        .get_device_code(&session.device_code)
        .await
        .expect("getting after an update must not error")
        .expect("the session must still be present after an update");
    assert!(
        matches!(after_update.status, DeviceCodeStatus::Approved(_)),
        "update_device_code must persist the new status"
    );

    let consumed = store
        .consume_device_code(&session.device_code)
        .await
        .expect("consuming an approved session must not error")
        .expect("consuming an approved session must return it");
    assert_eq!(consumed.device_code, session.device_code);

    let consumed_again = store
        .consume_device_code(&session.device_code)
        .await
        .expect("re-consuming an already-consumed session must not error");
    assert!(
        consumed_again.is_none(),
        "a device code session must be single-use on token issuance — \
         consuming it twice must not return it the second time"
    );

    let deletable = DeviceCodeSession {
        device_code: "conformance-device-2".to_string(),
        user_code: "CONF-USER-2".to_string(),
        ..session
    };
    store
        .store_device_code(deletable.clone())
        .await
        .expect("storing a second device code session must succeed");
    store
        .delete_device_code(&deletable.device_code)
        .await
        .expect("deleting a stored session must succeed");
    let after_delete = store
        .get_device_code(&deletable.device_code)
        .await
        .expect("getting a deleted session must not error");
    assert!(
        after_delete.is_none(),
        "a deleted device code session must no longer be retrievable"
    );
}

pub async fn run_client_assertion_store_tests<S: ClientAssertionStore>(store: &mut S) {
    let exp = Utc::now() + Duration::seconds(60);

    // 1. First record_jti succeeds
    let first = store.record_jti("unique-jti-1", exp).await.unwrap();
    assert!(first, "First presentation of JTI must succeed");

    // 2. Second record_jti before expiration fails
    let second = store.record_jti("unique-jti-1", exp).await.unwrap();
    assert!(!second, "Replay of same JTI must be rejected");

    // 3. Different JTI succeeds
    let another = store.record_jti("unique-jti-2", exp).await.unwrap();
    assert!(another, "Different JTI must succeed");

    // 4. Expired timestamp returns false immediately
    let past = Utc::now() - Duration::seconds(10);
    let expired = store.record_jti("unique-jti-3", past).await.unwrap();
    assert!(
        !expired,
        "An already expired assertion must be rejected without creating state"
    );
}
