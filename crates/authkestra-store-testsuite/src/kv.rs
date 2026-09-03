use authkestra_engine::store::KvStore;

use std::time::Duration;

pub async fn run_kv_tests<S>(store_factory: impl Fn() -> S)
where
    S: KvStore<String> + authkestra_engine::store::AtomicConsume<String> + Send + Sync,
{
    test_get_set_delete(store_factory()).await;
    test_ttl_expiry(store_factory()).await;
    test_atomic_consume(store_factory()).await;
}

async fn test_get_set_delete<
    S: KvStore<String> + authkestra_engine::store::AtomicConsume<String>,
>(
    store: S,
) {
    assert_eq!(store.get("key1").await.unwrap(), None);

    store
        .set("key1", "value1".to_string(), Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

    store.delete("key1").await.unwrap();
    assert_eq!(store.get("key1").await.unwrap(), None);
}

async fn test_ttl_expiry<S: KvStore<String> + authkestra_engine::store::AtomicConsume<String>>(
    store: S,
) {
    // A whole second, not the original per-backend tests' 10ms: `KvStore::set`
    // on Redis stores TTL via `EX`, which only accepts whole seconds, so a
    // sub-second value here would be backend-dependent rather than a fair
    // generic test.
    store
        .set("key1", "value1".to_string(), Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

    tokio::time::sleep(Duration::from_millis(1100)).await;

    assert_eq!(store.get("key1").await.unwrap(), None);
}

async fn test_atomic_consume<
    S: KvStore<String> + authkestra_engine::store::AtomicConsume<String>,
>(
    store: S,
) {
    store
        .set("key1", "value1".to_string(), Duration::from_secs(10))
        .await
        .unwrap();

    let value = store.consume("key1").await.unwrap();
    assert_eq!(value, Some("value1".to_string()));

    let value2 = store.consume("key1").await.unwrap();
    assert_eq!(value2, None);
}

pub async fn run_indexed_store_tests<
    S: KvStore<String>
        + authkestra_engine::store::AtomicConsume<String>
        + authkestra_engine::store::IndexedKvStore<String>,
>(
    store_factory: impl Fn() -> S,
) {
    let store = store_factory();

    store
        .set_indexed("pk1", "sk1", "value1".to_string(), Duration::from_secs(10))
        .await
        .unwrap();

    assert_eq!(store.get("pk1").await.unwrap(), Some("value1".to_string()));
    assert_eq!(
        store.get_by_index("sk1").await.unwrap(),
        Some("value1".to_string())
    );

    store.consume("pk1").await.unwrap();

    assert_eq!(store.get_by_index("sk1").await.unwrap(), None);
}
