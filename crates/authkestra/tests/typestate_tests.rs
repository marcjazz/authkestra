use authkestra::flow::Authkestra;
use authkestra_engine::state::Identity;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_typestate_session_flow() {
    // Start with Missing, Missing
    let builder = Authkestra::builder();

    // Configure session store -> transitions to Configured, Missing
    let auth = builder
        .session_store(Arc::new(authkestra_engine::store::memory::MemoryStore::default()))
        .build();

    // create_session should be available
    let identity = Identity {
        provider_id: "test".to_string(),
        external_id: "user1".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    };
    let session = auth.create_session(identity).await;
    assert!(session.is_ok());

    // issue_token should NOT be available on this type.
    // The following would fail to compile:
    // auth.issue_token(identity, 3600);
}

#[test]
fn test_typestate_token_flow() {
    // Start with Missing, Missing
    let builder = Authkestra::builder();

    // Configure token manager -> transitions to Missing, Configured
    let auth = builder.jwt_secret(b"secret").build();

    // issue_token should be available
    let identity = Identity {
        provider_id: "test".to_string(),
        external_id: "user1".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    };
    let token = auth.issue_token(identity, 3600);
    assert!(token.is_ok());

    // create_session should NOT be available on this type.
    // The following would fail to compile:
    // auth.create_session(identity).await;
}

#[tokio::test]
async fn test_typestate_full_flow() {
    let auth = Authkestra::builder()
        .session_store(Arc::new(authkestra_engine::store::memory::MemoryStore::default()))
        .jwt_secret(b"secret")
        .build();

    let identity = Identity {
        provider_id: "test".to_string(),
        external_id: "user1".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    };

    // Both should be available
    assert!(auth.create_session(identity.clone()).await.is_ok());
    assert!(auth.issue_token(identity, 3600).is_ok());
}
