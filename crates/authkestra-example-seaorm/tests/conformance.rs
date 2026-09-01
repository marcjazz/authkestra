use authkestra_example_seaorm::{client, SeaOrmOpStore};
use authkestra_store_testsuite::op::run_op_store_tests;
use sea_orm::{ActiveValue, EntityTrait};

/// Runs the shared `OpStore` conformance suite (authkestra-store-testsuite)
/// against the SeaORM example store — the actual proof this example is
/// meant to provide (authkestra#289, Phase D): that a third-party ORM can
/// implement these traits and pass the same behavioral contract
/// `authkestra-store-sqlx` does.
#[tokio::test]
async fn test_seaorm_op_store_sqlite() {
    let store = SeaOrmOpStore::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite connection must succeed");
    store
        .migrate()
        .await
        .expect("migrating a fresh in-memory database must succeed");

    // `run_op_store_tests`'s AuthorizationCode/RefreshToken/DeviceCodeSession
    // fixtures all reference `client_id: "client-1"` — `ClientStore` has no
    // generic write method (by design), so it's seeded directly here,
    // bypassing the trait the same way authkestra-store-sqlx's own
    // conformance test does.
    seed_fixture_client(&store).await;

    let mut store = store;
    run_op_store_tests(&mut store).await;
}

async fn seed_fixture_client(store: &SeaOrmOpStore) {
    let active = client::ActiveModel {
        client_id: ActiveValue::Set("client-1".to_string()),
        client_secret_hash: ActiveValue::Set(None),
        require_pkce: ActiveValue::Set(true),
        redirect_uris: ActiveValue::Set(serde_json::json!(["https://cb.example.com"])),
        grant_types: ActiveValue::Set(serde_json::json!(["authorization_code"])),
        scopes: ActiveValue::Set(serde_json::json!(["openid", "offline_access"])),
        allowed_audiences: ActiveValue::Set(serde_json::json!([])),
        token_endpoint_auth_method: ActiveValue::Set(None),
        jwks: ActiveValue::Set(None),
    };
    client::Entity::insert(active)
        .exec(store.connection())
        .await
        .expect("seeding the fixture client must succeed");
}
