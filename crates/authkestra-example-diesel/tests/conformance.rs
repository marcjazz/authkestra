use authkestra_example_diesel::DieselOpStore;
use authkestra_store_testsuite::op::run_op_store_tests;
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
