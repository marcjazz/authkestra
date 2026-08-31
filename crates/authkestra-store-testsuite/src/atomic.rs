use authkestra_engine::store::{AtomicInsert, KvStore};
use std::time::Duration;

pub async fn run_atomic_insert_tests<S>(store_factory: &impl Fn() -> S)
where
    S: KvStore<String> + AtomicInsert<String> + Send + Sync + Clone + 'static,
{
    test_insert_if_absent_first_call_succeeds(store_factory()).await;
    test_insert_if_absent_second_call_fails(store_factory()).await;
    // Add other generic tests as needed
}

async fn test_insert_if_absent_first_call_succeeds<S: AtomicInsert<String> + KvStore<String>>(store: S) {
    let inserted = store
        .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(inserted);
    assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));
}

async fn test_insert_if_absent_second_call_fails<S: AtomicInsert<String> + KvStore<String>>(store: S) {
    assert!(store
        .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
        .await
        .unwrap());

    let inserted_again = store
        .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(!inserted_again);
    assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));
}

pub async fn run_atomic_insert_tests_extended<S>(store_factory: &impl Fn() -> S)
where
    S: KvStore<String> + AtomicInsert<String> + Send + Sync + Clone + 'static,
{
    test_insert_if_absent_first_call_succeeds(store_factory()).await;
    test_insert_if_absent_second_call_fails(store_factory()).await;
    test_insert_if_absent_with_sub_second_ttl_still_blocks_a_replay(store_factory()).await;
    test_insert_if_absent_with_zero_ttl_still_blocks_a_replay(store_factory()).await;
    test_insert_if_absent_allows_reuse_after_expiry(store_factory()).await;
    
    // Note: reclaims_expired_entries_under_other_keys uses store.len(), which isn't in the generic trait.
    // It's a backend-specific MemoryStore detail so we won't port it to the generic suite.

    test_insert_if_absent_sweep_ignores_a_stale_queue_entry_for_a_reused_key(store_factory()).await;
    test_insert_if_absent_is_atomic_under_concurrency(&store_factory).await;
}

async fn test_insert_if_absent_with_sub_second_ttl_still_blocks_a_replay<S: AtomicInsert<String> + KvStore<String>>(store: S) {
    let inserted = store
        .insert_if_absent("key1", "value1".to_string(), Duration::from_millis(10))
        .await
        .unwrap();
    assert!(inserted, "the first insert must succeed");

    let inserted_again = store
        .insert_if_absent("key1", "value2".to_string(), Duration::from_millis(10))
        .await
        .unwrap();
    assert!(
        !inserted_again,
        "a second insert under the same key, even with a sub-second TTL, is a replay and must be rejected"
    );
}

async fn test_insert_if_absent_with_zero_ttl_still_blocks_a_replay<S: AtomicInsert<String> + KvStore<String>>(store: S) {
    let inserted = store
        .insert_if_absent("key1", "value1".to_string(), Duration::ZERO)
        .await
        .unwrap();
    assert!(inserted, "the first insert must succeed");

    let inserted_again = store
        .insert_if_absent("key1", "value2".to_string(), Duration::ZERO)
        .await
        .unwrap();
    assert!(!inserted_again, "a zero-TTL replay must still be rejected");
}

async fn test_insert_if_absent_allows_reuse_after_expiry<S: AtomicInsert<String> + KvStore<String>>(store: S) {
    store
        .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(1))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(1100)).await;

    let inserted_again = store
        .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
        .await
        .unwrap();
    assert!(inserted_again);
    assert_eq!(store.get("key1").await.unwrap(), Some("value2".to_string()));
}

async fn test_insert_if_absent_sweep_ignores_a_stale_queue_entry_for_a_reused_key<S: AtomicInsert<String> + KvStore<String>>(store: S) {
    store
        .insert_if_absent("key1", "first".to_string(), Duration::from_secs(1))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;

    assert!(store
        .insert_if_absent("key1", "second".to_string(), Duration::from_secs(10))
        .await
        .unwrap());

    store
        .insert_if_absent("key2", "unrelated".to_string(), Duration::from_secs(10))
        .await
        .unwrap();

    assert_eq!(
        store.get("key1").await.unwrap(),
        Some("second".to_string()),
        "a stale queue entry for a reused key must not evict its current value"
    );
}

async fn test_insert_if_absent_is_atomic_under_concurrency<S: AtomicInsert<String> + KvStore<String> + Clone + 'static>(store_factory: &impl Fn() -> S) {
    let store = store_factory();
    let mut handles = Vec::new();
    for i in 0..50 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store
                .insert_if_absent("shared-key", i.to_string(), Duration::from_secs(10))
                .await
                .unwrap()
        }));
    }

    let mut successes = 0;
    for handle in handles {
        if handle.await.unwrap() {
            successes += 1;
        }
    }
    assert_eq!(successes, 1, "exactly one racing insert must win");
}
