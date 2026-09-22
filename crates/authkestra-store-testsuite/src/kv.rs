use authkestra_engine::store::KvStore;

use std::time::Duration;

pub async fn run_kv_tests<S>(store_factory: impl Fn() -> S)
where
    S: KvStore<String>
        + authkestra_engine::store::AtomicConsume<String>
        + authkestra_engine::store::AtomicDecrement<String>
        + Send
        + Sync,
{
    test_get_set_delete(store_factory()).await;
    test_ttl_expiry(store_factory()).await;
    test_atomic_consume(store_factory()).await;
    test_atomic_decrement(store_factory()).await;
}

/// The contract every backend owes [`AtomicDecrement`].
///
/// The three cases that are easy to get wrong, and each of which turns a
/// retry budget into something that is not one:
///
///   * a counter that never existed must read as absent, not as zero and not
///     as unlimited — a `DECR` on a missing Redis key would happily create it
///     at -1;
///   * a spent counter must stay spent, rather than wrapping or running
///     negative on further calls;
///   * concurrent decrements must each take exactly one, which is the whole
///     reason this is not `get` plus `set`.
async fn test_atomic_decrement<
    S: KvStore<String> + authkestra_engine::store::AtomicDecrement<String>,
>(
    store: S,
) {
    use authkestra_engine::store::AtomicDecrement;

    // Absent is absent, not zero.
    assert_eq!(store.decrement("budget").await.unwrap(), None);

    store
        .init_counter("budget", 3, Duration::from_secs(10))
        .await
        .unwrap();

    assert_eq!(store.decrement("budget").await.unwrap(), Some(2));
    assert_eq!(store.decrement("budget").await.unwrap(), Some(1));
    assert_eq!(store.decrement("budget").await.unwrap(), Some(0));

    // Spent stays spent. A backend that wrapped here would hand out
    // four billion more attempts.
    assert_eq!(store.decrement("budget").await.unwrap(), Some(0));
    assert_eq!(store.decrement("budget").await.unwrap(), Some(0));

    // Re-initialising replaces rather than accumulating.
    store
        .init_counter("budget", 1, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(store.decrement("budget").await.unwrap(), Some(0));

    // A counter is independent of a value stored under the same key, so the
    // two namespaces cannot collide.
    store
        .set("shared", "value".to_string(), Duration::from_secs(10))
        .await
        .unwrap();
    store
        .init_counter("shared", 2, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(store.decrement("shared").await.unwrap(), Some(1));
    assert_eq!(
        store.get("shared").await.unwrap(),
        Some("value".to_string()),
        "decrementing a counter must not disturb the value under the same key"
    );
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
