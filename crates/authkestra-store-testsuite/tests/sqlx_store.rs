use authkestra_engine::auth::state::Identity;
use authkestra_engine::chrono::{Duration, Utc};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_store_sqlx::SqlxOpStore;
use authkestra_store_testsuite::op::run_op_store_tests;
use authkestra_store_testsuite::tx::run_transactional_op_store_tests;
use sqlx::sqlite::SqlitePoolOptions;

/// Runs the shared `OpStore` conformance suite against `SqlxOpStore` — the
/// Phase C extraction into `authkestra-store-sqlx` moved this store's own
/// hand-written tests over unchanged, but never actually exercised it
/// against the generic suite Phase A built for exactly this purpose. This
/// closes that loop, in-memory SQLite so it stays fast and docker-free.
#[tokio::test]
async fn test_sqlx_op_store_sqlite() {
    // `sqlite::memory:` gives every connection its own private, independent
    // database — with the default pool size (10), a second physical
    // connection opened under the hood would silently see an empty
    // database. Pinning the pool to one connection is what actually makes
    // this a *shared* in-memory database rather than up to ten unrelated
    // ones; the test passing today with the default size is an accident of
    // sequential access, not something this test should rely on.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
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
    seed_fixture_client(&pool).await;

    run_op_store_tests(&mut store).await;
    run_transactional_op_store_tests(&mut store).await;
}

/// The composition this whole capability exists for (authkestra#336): a host
/// application's own write and an `OpStore` write, in one transaction, that
/// commit or roll back together.
///
/// Backend-specific by nature — the application's statement is written
/// against `sqlx`, not against any trait — which is exactly why reaching the
/// native connection is an inherent method on `SqlxOpStoreTx` rather than
/// something the dyn-compatible `OpStoreTransaction` trait tries to express.
#[tokio::test]
async fn test_host_write_and_store_write_commit_as_one_unit() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite pool must connect");

    let mut store = SqlxOpStore::<sqlx::Sqlite>::new(pool.clone());
    store.migrate().await.expect("migrating must succeed");
    seed_fixture_client(&pool).await;

    // A table the *host application* owns — authkestra knows nothing about it.
    sqlx::query("CREATE TABLE app_users (id TEXT PRIMARY KEY, email TEXT NOT NULL)")
        .execute(&pool)
        .await
        .expect("creating the host application's own table must succeed");

    // 1. The failing case: host row + store row, rolled back together.
    let mut tx = store
        .begin_tx()
        .await
        .expect("beginning a transaction must succeed");
    sqlx::query("INSERT INTO app_users (id, email) VALUES (?1, ?2)")
        .bind("user-rolled-back")
        .bind("rolled-back@example.com")
        .execute(tx.as_mut())
        .await
        .expect("the host's own insert must succeed inside the transaction");
    tx.store_token(refresh_token("host-tx-rolled-back"))
        .await
        .expect("the store's write must succeed in the same transaction");
    tx.rollback().await.expect("rolling back must succeed");

    let host_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM app_users WHERE id = 'user-rolled-back'")
            .fetch_one(&pool)
            .await
            .expect("counting host rows must succeed");
    assert_eq!(
        host_rows, 0,
        "the host application's row must roll back with the store's"
    );
    assert!(
        store
            .get_token("host-tx-rolled-back")
            .await
            .expect("reading must not error")
            .is_none(),
        "the store's row must roll back with the host application's"
    );

    // 2. The succeeding case: both durable after one commit.
    let mut tx = store
        .begin_tx()
        .await
        .expect("beginning a transaction must succeed");
    sqlx::query("INSERT INTO app_users (id, email) VALUES (?1, ?2)")
        .bind("user-committed")
        .bind("committed@example.com")
        .execute(tx.as_mut())
        .await
        .expect("the host's own insert must succeed inside the transaction");
    tx.store_token(refresh_token("host-tx-committed"))
        .await
        .expect("the store's write must succeed in the same transaction");
    tx.commit().await.expect("committing must succeed");

    let email: String =
        sqlx::query_scalar("SELECT email FROM app_users WHERE id = 'user-committed'")
            .fetch_one(&pool)
            .await
            .expect("the host application's row must be durable after the commit");
    assert_eq!(email, "committed@example.com");
    assert!(
        store
            .get_token("host-tx-committed")
            .await
            .expect("reading must not error")
            .is_some(),
        "the store's row must be durable after the same commit"
    );
}

fn refresh_token(token: &str) -> RefreshToken {
    RefreshToken::new(
        token.to_string(),
        "client-1".to_string(),
        Identity {
            provider_id: "test".to_string(),
            external_id: "user-1".to_string(),
            email: None,
            username: None,
            attributes: std::collections::HashMap::new(),
        },
        "openid".to_string(),
        Utc::now() + Duration::days(1),
        None,
    )
}

async fn seed_fixture_client(pool: &sqlx::SqlitePool) {
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
    .execute(pool)
    .await
    .expect("seeding the fixture client must succeed");
}
