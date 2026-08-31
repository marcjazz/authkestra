use authkestra_engine::store::memory::MemoryStore;
use authkestra_store_testsuite::kv::run_kv_tests;
use authkestra_store_testsuite::atomic::run_atomic_insert_tests;

#[tokio::test]
async fn test_memory_store_kv() {
    run_kv_tests(|| MemoryStore::<String>::new()).await;
}

#[tokio::test]
async fn test_memory_store_atomic_insert() {
    run_atomic_insert_tests(|| MemoryStore::<String>::new()).await;
}
