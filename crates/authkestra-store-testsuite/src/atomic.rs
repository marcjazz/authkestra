use authkestra_engine::store::{AtomicInsert, KvStore};
use std::time::Duration;

pub async fn run_atomic_insert_tests<S>(store_factory: impl Fn() -> S)
where
    S: KvStore<String> + AtomicInsert<String> + Send + Sync,
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
