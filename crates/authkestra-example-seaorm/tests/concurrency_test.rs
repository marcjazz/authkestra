//! Regression test for the compare-and-swap fix in `consume_code`: it used
//! to read `used`, decide in Rust whether to proceed, and only then run the
//! `UPDATE` — a TOCTOU race letting two concurrent redemptions of the same
//! authorization code both succeed on any backend without a hard
//! single-writer lock. This exercises real concurrent access against a
//! file-backed database (not `:memory:`, which this crate deliberately
//! pools down to a single connection — see `SeaOrmOpStore::connect`'s doc
//! comment — so it can't demonstrate a *cross-connection* race at all) to
//! mirror `authkestra-store-sqlx`'s own `test_sqlite_concurrency`.

use authkestra_engine::auth::state::Identity;
use authkestra_example_seaorm::{client, SeaOrmOpStore};
use authkestra_op::client::ClientStore;
use authkestra_op::code::{AuthorizationCode, AuthorizationCodeStore};
use chrono::{Duration, Utc};
use sea_orm::{ActiveValue, EntityTrait};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_db_path() -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "authkestra_seaorm_concurrency_test_{}_{n}.sqlite",
        std::process::id()
    ))
}

#[tokio::test]
async fn consume_code_is_atomic_under_concurrent_redemption() {
    let path = temp_db_path();
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let store = SeaOrmOpStore::connect(&url)
        .await
        .expect("file-backed sqlite connection must succeed");
    store
        .migrate()
        .await
        .expect("migrating a fresh database must succeed");

    let active = client::ActiveModel {
        client_id: ActiveValue::Set("concurrency-client".to_string()),
        client_secret_hash: ActiveValue::Set(None),
        require_pkce: ActiveValue::Set(true),
        redirect_uris: ActiveValue::Set(serde_json::json!(["https://cb.example.com"])),
        grant_types: ActiveValue::Set(serde_json::json!(["authorization_code"])),
        scopes: ActiveValue::Set(serde_json::json!(["openid"])),
        allowed_audiences: ActiveValue::Set(serde_json::json!([])),
        token_endpoint_auth_method: ActiveValue::Set(None),
        jwks: ActiveValue::Set(None),
    };
    client::Entity::insert(active)
        .exec(store.connection())
        .await
        .expect("seeding the fixture client must succeed");

    let mut seed_store = store.clone();
    assert!(
        seed_store
            .find_client("concurrency-client")
            .await
            .unwrap()
            .is_some(),
        "fixture client must be visible before racing consume_code"
    );

    let code = AuthorizationCode::new(
        "concurrent-code".to_string(),
        "concurrency-client".to_string(),
        "https://cb.example.com".to_string(),
        "openid".to_string(),
        Identity {
            provider_id: "local".to_string(),
            external_id: "user-1".to_string(),
            email: None,
            username: None,
            attributes: HashMap::new(),
        },
        Utc::now() + Duration::minutes(10),
        false,
    );
    seed_store.store_code(code).await.unwrap();

    // 20 concurrent redemption attempts of the exact same code, against a
    // pool with more than one real connection (SeaORM/sqlx's default,
    // since this is a file-backed database) — a genuine cross-connection
    // race, not just concurrent tasks serialized behind a single-connection
    // pool.
    let mut handles = Vec::new();
    for _ in 0..20 {
        let mut s = store.clone();
        handles.push(tokio::spawn(async move {
            s.consume_code("concurrent-code").await.unwrap()
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    for h in handles {
        if h.await.unwrap().is_some() {
            successes += 1;
        } else {
            failures += 1;
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one concurrent redemption may succeed"
    );
    assert_eq!(failures, 19);

    drop(store);
    let _ = std::fs::remove_file(&path);
}
