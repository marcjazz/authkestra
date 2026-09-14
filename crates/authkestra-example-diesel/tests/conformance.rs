use authkestra_engine::auth::state::Identity;
use authkestra_engine::chrono::{Duration, Utc};
use authkestra_engine::store::StoreError;
use authkestra_example_diesel::DieselOpStore;
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_store_testsuite::op::run_op_store_tests;
use authkestra_store_testsuite::tx::run_transactional_op_store_tests;
use diesel::prelude::*;

/// Runs the shared `OpStore` conformance suite (authkestra-store-testsuite)
/// against the Diesel example store — the proof this example exists to
/// provide (authkestra#289, Phase D): that a third-party, *synchronous*
/// ORM can implement these async traits (via `spawn_blocking`) and pass
/// the same behavioral contract `authkestra-store-sqlx` and
/// `authkestra-example-seaorm` do.
#[tokio::test]
async fn test_diesel_op_store_sqlite() {
    let store = DieselOpStore::connect(":memory:").expect("in-memory sqlite pool must build");
    store
        .migrate()
        .await
        .expect("migrating a fresh in-memory database must succeed");

    // `run_op_store_tests`'s AuthorizationCode/RefreshToken/DeviceCodeSession
    // fixtures all reference `client_id: "client-1"` — `ClientStore` has no
    // generic write method (by design), so it's seeded directly here via a
    // raw Diesel insert, bypassing the trait the same way
    // authkestra-store-sqlx's and authkestra-example-seaorm's own
    // conformance tests do.
    seed_fixture_client(&store);

    let mut store = store;
    run_op_store_tests(&mut store).await;
    run_transactional_op_store_tests(&mut store).await;
}

fn seed_fixture_client(store: &DieselOpStore) {
    let mut conn = store.pool().get().expect("pool must hand out a connection");
    diesel::sql_query(
        "INSERT INTO oauth_clients \
         (client_id, client_secret_hash, require_pkce, redirect_uris, grant_types, scopes, allowed_audiences, token_endpoint_auth_method, jwks) \
         VALUES ('client-1', NULL, 1, '[\"https://cb.example.com\"]', '[\"authorization_code\"]', '[\"openid\",\"offline_access\"]', '[]', NULL, NULL)",
    )
    .execute(&mut conn)
    .expect("seeding the fixture client must succeed");
}

/// The composed unit of work (authkestra#336) against Diesel — the awkward
/// case, and the one worth having a test for: a synchronous ORM with no owned
/// transaction handle, driven through `spawn_blocking`, where the host's own
/// query arrives as a closure rather than a borrow.
#[tokio::test]
async fn test_host_write_and_store_write_commit_as_one_unit() {
    let store = DieselOpStore::connect(":memory:").expect("in-memory sqlite pool must build");
    store.migrate().await.expect("migrating must succeed");
    seed_fixture_client(&store);

    {
        let mut conn = store
            .pool()
            .get()
            .expect("checking out a connection must succeed");
        diesel::sql_query("CREATE TABLE app_users (id TEXT PRIMARY KEY, email TEXT NOT NULL)")
            .execute(&mut conn)
            .expect("creating the host application's own table must succeed");
    }

    let mut store = store;

    // Rolled back as one unit.
    let mut tx = store
        .begin_tx()
        .await
        .expect("beginning a transaction must succeed");
    tx.run(|conn| {
        diesel::sql_query("INSERT INTO app_users (id, email) VALUES ('u-rb', 'rb@example.com')")
            .execute(conn)
            .map(|_| ())
            .map_err(|e| StoreError::Internal(format!("diesel error: {e}")))
    })
    .await
    .expect("the host's own insert must succeed inside the transaction");
    tx.store_token(refresh_token("diesel-tx-rolled-back"))
        .await
        .expect("the store's write must succeed in the same transaction");
    tx.rollback().await.expect("rolling back must succeed");

    assert_eq!(
        count_app_users(&store, "u-rb"),
        0,
        "the host's row must roll back with the store's"
    );
    assert!(
        store
            .get_token("diesel-tx-rolled-back")
            .await
            .expect("reading must not error")
            .is_none(),
        "the store's row must roll back with the host application's"
    );

    // Committed as one unit.
    let mut tx = store
        .begin_tx()
        .await
        .expect("beginning a transaction must succeed");
    tx.run(|conn| {
        diesel::sql_query("INSERT INTO app_users (id, email) VALUES ('u-ok', 'ok@example.com')")
            .execute(conn)
            .map(|_| ())
            .map_err(|e| StoreError::Internal(format!("diesel error: {e}")))
    })
    .await
    .expect("the host's own insert must succeed inside the transaction");
    tx.store_token(refresh_token("diesel-tx-committed"))
        .await
        .expect("the store's write must succeed in the same transaction");
    tx.commit().await.expect("committing must succeed");

    assert_eq!(
        count_app_users(&store, "u-ok"),
        1,
        "the host's row must be durable after the commit"
    );
    assert!(
        store
            .get_token("diesel-tx-committed")
            .await
            .expect("reading must not error")
            .is_some(),
        "the store's row must be durable after the same commit"
    );
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

fn count_app_users(store: &DieselOpStore, id: &str) -> i64 {
    let mut conn = store
        .pool()
        .get()
        .expect("checking out a connection must succeed");
    diesel::sql_query(format!(
        "SELECT COUNT(*) AS n FROM app_users WHERE id = '{id}'"
    ))
    .get_result::<Count>(&mut conn)
    .expect("counting host rows must succeed")
    .n
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
