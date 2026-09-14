use authkestra_engine::auth::state::Identity;
use authkestra_engine::chrono::{Duration, Utc};
use authkestra_example_seaorm::{client, SeaOrmOpStore};
use authkestra_op::refresh::{RefreshToken, RefreshTokenStore};
use authkestra_store_testsuite::op::run_op_store_tests;
use authkestra_store_testsuite::tx::run_transactional_op_store_tests;
use sea_orm::{ActiveValue, EntityTrait};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

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
    run_transactional_op_store_tests(&mut store).await;
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

/// The composed unit of work (authkestra#336) against SeaORM: a host
/// application's own entity write and an `OpStore` write in one transaction.
///
/// The point of running this on a second backend is that nothing in the
/// shared trait had to bend to accommodate it — only the accessor that hands
/// back the native handle differs (`&DatabaseTransaction` here,
/// `&mut Connection` in `authkestra-store-sqlx`).
#[tokio::test]
async fn test_host_write_and_store_write_commit_as_one_unit() {
    let store = SeaOrmOpStore::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite connection must succeed");
    store.migrate().await.expect("migrating must succeed");
    seed_fixture_client(&store).await;

    // A table the host application owns; authkestra knows nothing about it.
    store
        .connection()
        .execute_unprepared("CREATE TABLE app_users (id TEXT PRIMARY KEY, email TEXT NOT NULL)")
        .await
        .expect("creating the host application's own table must succeed");

    let mut store = store;

    // Rolled back as one unit.
    let mut tx = store
        .begin_tx()
        .await
        .expect("beginning a transaction must succeed");
    tx.transaction()
        .execute_unprepared("INSERT INTO app_users (id, email) VALUES ('u-rb', 'rb@example.com')")
        .await
        .expect("the host's own insert must succeed inside the transaction");
    tx.store_token(refresh_token("seaorm-tx-rolled-back"))
        .await
        .expect("the store's write must succeed in the same transaction");
    tx.rollback().await.expect("rolling back must succeed");

    let rows = store
        .connection()
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT id FROM app_users WHERE id = 'u-rb'",
        ))
        .await
        .expect("querying host rows must succeed");
    assert!(
        rows.is_empty(),
        "the host application's row must roll back with the store's"
    );
    assert!(
        store
            .get_token("seaorm-tx-rolled-back")
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
    tx.transaction()
        .execute_unprepared("INSERT INTO app_users (id, email) VALUES ('u-ok', 'ok@example.com')")
        .await
        .expect("the host's own insert must succeed inside the transaction");
    tx.store_token(refresh_token("seaorm-tx-committed"))
        .await
        .expect("the store's write must succeed in the same transaction");
    tx.commit().await.expect("committing must succeed");

    let rows = store
        .connection()
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT id FROM app_users WHERE id = 'u-ok'",
        ))
        .await
        .expect("querying host rows must succeed");
    assert_eq!(
        rows.len(),
        1,
        "the host application's row must be durable after the commit"
    );
    assert!(
        store
            .get_token("seaorm-tx-committed")
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
