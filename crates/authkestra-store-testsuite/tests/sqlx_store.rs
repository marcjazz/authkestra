use authkestra_store_sqlx::SqlxOpStore;
use authkestra_store_testsuite::op::run_op_store_tests;
use sqlx::sqlite::SqlitePoolOptions;

/// Runs the shared `OpStore` conformance suite against `SqlxOpStore` — the
/// Phase C extraction into `authkestra-store-sqlx` moved this store's own
/// hand-written tests over unchanged, but never actually exercised it
/// against the generic suite Phase A built for exactly this purpose. This
/// closes that loop, in-memory SQLite so it stays fast and docker-free.
#[tokio::test]
async fn test_sqlx_op_store_sqlite() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite pool must connect");

    let mut store = SqlxOpStore::<sqlx::Sqlite>::new(pool.clone());
    store
        .migrate()
        .await
        .expect("migrating a fresh in-memory database must succeed");

    // `run_op_store_tests`'s AuthorizationCode/RefreshToken fixtures reference
    // `client_id: "client-1"` — `ClientStore` has no generic write method (by
    // design), so a store with a foreign key from codes/tokens to clients
    // (like this one) needs it seeded directly before the suite can run.
    sqlx::query(
        "INSERT INTO authkestra_oauth_clients \
         (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("client-1")
    .bind(None::<String>)
    .bind(true)
    .bind(sqlx::types::Json(vec!["https://cb.example.com"]))
    .bind(sqlx::types::Json(vec!["authorization_code"]))
    .bind(sqlx::types::Json(vec!["openid", "offline_access"]))
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .execute(&pool)
    .await
    .expect("seeding the fixture client must succeed");

    run_op_store_tests(&mut store).await;
}
