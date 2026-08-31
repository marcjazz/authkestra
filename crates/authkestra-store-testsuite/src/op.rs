use authkestra_op::store::OpStore;

// Here we can put generic OpStore tests (e.g. store_code, then get_code).
// For Phase 1, we just lay down the structure.
pub async fn run_op_store_tests<S: OpStore>(_store: S) {
    // Tests for find_client, etc.
}
use authkestra_engine::chrono::Utc;
use authkestra_op::client_assertion::ClientAssertionStore;

pub async fn run_client_assertion_store_tests<S: ClientAssertionStore>(store: &mut S) {
    let exp = Utc::now() + authkestra_engine::chrono::Duration::seconds(60);

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
    let past = Utc::now() - authkestra_engine::chrono::Duration::seconds(10);
    let expired = store.record_jti("unique-jti-3", past).await.unwrap();
    assert!(
        !expired,
        "An already expired assertion must be rejected without creating state"
    );
}
