use authkestra_engine::store::KvStore;
use std::fmt::Debug;
use std::time::Duration;

pub async fn run_kv_tests<S>(store_factory: impl Fn() -> S)
where
    S: KvStore<String> + authkestra_engine::store::AtomicConsume<String> + Send + Sync,
{
    test_get_set_delete(store_factory()).await;
    test_ttl_expiry(store_factory()).await;
    test_atomic_consume(store_factory()).await;
}

async fn test_get_set_delete<S: KvStore<String> + authkestra_engine::store::AtomicConsume<String>>(store: S) {
    assert_eq!(store.get("key1").await.unwrap(), None);

    store
        .set("key1", "value1".to_string(), Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

    store.delete("key1").await.unwrap();
    assert_eq!(store.get("key1").await.unwrap(), None);
}

async fn test_ttl_expiry<S: KvStore<String> + authkestra_engine::store::AtomicConsume<String>>(store: S) {
    // We use a small whole second here if fractional ones are floored, 
    // but the original test used 10ms. Let's use 1s and sleep for 1.1s.
    // wait, we should check what the original test does.
    store
        .set("key1", "value1".to_string(), Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

    tokio::time::sleep(Duration::from_millis(1100)).await;

    assert_eq!(store.get("key1").await.unwrap(), None);
}

async fn test_atomic_consume<S: KvStore<String> + authkestra_engine::store::AtomicConsume<String>>(store: S) {
    store
        .set("key1", "value1".to_string(), Duration::from_secs(10))
        .await
        .unwrap();

    let value = store.consume("key1").await.unwrap();
    assert_eq!(value, Some("value1".to_string()));

    let value2 = store.consume("key1").await.unwrap();
    assert_eq!(value2, None);
}
