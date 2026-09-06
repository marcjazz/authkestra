//! The typestate builder, driven entirely through the facade.
//!
//! `Authkestra::builder()` is the facade's own entry point, so this belongs
//! with the other facade tests. It moved here from `crates/authkestra/tests/`
//! for the reason given in this crate's `Cargo.toml`: there it reached
//! `authkestra_engine::` directly for `Identity` and `MemoryStore`, which
//! resolved through that crate's dev-dependencies rather than through
//! anything the facade forwards.
//!
//! It was declared `required-features = ["full"]`, yet `full` does not include
//! `memory` — the store it builds with. It compiled anyway, because the
//! dev-dependency enabled `memory` regardless. Reaching both types through
//! `authkestra::core` from here makes the test depend on the `memory`
//! forwarding it always implicitly relied on.

use authkestra::core::state::Identity;
use authkestra::core::store::memory::MemoryStore;
use authkestra::Authkestra;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn test_typestate_session_flow() {
    let builder = Authkestra::builder();
    let auth = builder
        .session_store(Arc::new(MemoryStore::default()))
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
    let builder = Authkestra::builder();
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
        .session_store(Arc::new(MemoryStore::default()))
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
