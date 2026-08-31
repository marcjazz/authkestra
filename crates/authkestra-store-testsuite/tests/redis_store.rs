use authkestra_engine::store::redis::RedisStore;
use authkestra_store_testsuite::kv::{run_kv_tests, run_indexed_store_tests};
use authkestra_store_testsuite::atomic::run_atomic_insert_tests_extended;
use authkestra_store_testsuite::op::run_client_assertion_store_tests;
use authkestra_op::redis_store::RedisClientAssertionStore;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::redis::Redis;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

async fn setup_redis() -> (String, testcontainers::ContainerAsync<Redis>) {
    let container = Redis::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(6379).await.unwrap();
    let url = format!("redis://127.0.0.1:{}", port);
    (url, container)
}

#[tokio::test]
async fn test_redis_store_kv() {
    let (url, _c) = setup_redis().await;
    let counter = Arc::new(AtomicUsize::new(0));
    run_kv_tests(|| {
        let count = counter.fetch_add(1, Ordering::SeqCst);
        RedisStore::new(&url, format!("test_prefix_{}", count)).unwrap()
    }).await;
}

#[tokio::test]
async fn test_redis_store_atomic_insert() {
    let (url, _c) = setup_redis().await;
    let counter = Arc::new(AtomicUsize::new(0));
    run_atomic_insert_tests_extended(&|| {
        let count = counter.fetch_add(1, Ordering::SeqCst);
        RedisStore::new(&url, format!("test_prefix_{}", count)).unwrap()
    }).await;
}

#[tokio::test]
async fn test_redis_client_assertion_store() {
    let (url, _c) = setup_redis().await;
    let store = RedisClientAssertionStore::new(&url, "test_jti".to_string()).await.unwrap();
    run_client_assertion_store_tests(&store).await;
}
