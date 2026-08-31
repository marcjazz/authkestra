use authkestra_engine::store::memory::MemoryStore;
use authkestra_store_testsuite::atomic::run_atomic_insert_tests_extended;
use authkestra_store_testsuite::kv::{run_indexed_store_tests, run_kv_tests};

#[tokio::test]
async fn test_memory_store_kv() {
    run_kv_tests(MemoryStore::<String>::new).await;
    run_indexed_store_tests(MemoryStore::<String>::new).await;
}

#[tokio::test]
async fn test_memory_store_atomic_insert() {
    run_atomic_insert_tests_extended(&MemoryStore::<String>::new).await;
}
use authkestra_op::client_assertion::MemoryClientAssertionStore;
use authkestra_store_testsuite::op::run_client_assertion_store_tests;

#[tokio::test]
async fn test_memory_client_assertion_store() {
    let mut store = MemoryClientAssertionStore::default();
    run_client_assertion_store_tests(&mut store).await;
}
