//! Conformance suite for [`TransactionalOpStore`] — proves a backend's
//! transaction-scoped store is a real unit of work, not a store that
//! commits as it goes and calls `rollback` a no-op.
//!
//! Only backends that opt into [`TransactionalOpStore`] run this. A store
//! with no transactions (the in-memory store, Redis) must not implement the
//! trait at all rather than implement it weakly, which is exactly what these
//! assertions are here to catch.

use authkestra_engine::auth::state::Identity;
use authkestra_engine::chrono::{Duration, Utc};
use authkestra_op::code::AuthorizationCode;
use authkestra_op::refresh::RefreshToken;
// `store_token`/`consume_code`/... arrive through the `OpStore` supertrait that
// `TransactionalOpStore` and `OpStoreTransaction` both require, so the individual
// store traits need no separate import here.
use authkestra_op::store::TransactionalOpStore;
use std::collections::HashMap;

fn test_identity() -> Identity {
    Identity {
        provider_id: "test".to_string(),
        external_id: "user-1".to_string(),
        email: None,
        username: None,
        attributes: HashMap::new(),
    }
}

fn token(name: &str) -> RefreshToken {
    RefreshToken::new(
        name.to_string(),
        "client-1".to_string(),
        test_identity(),
        "openid".to_string(),
        Utc::now() + Duration::days(1),
        None,
    )
}

/// Generic conformance suite for [`TransactionalOpStore`].
///
/// Like [`crate::op::run_op_store_tests`], this expects a client with
/// `client_id: "client-1"` to already exist — `ClientStore` has no generic
/// write method, so a backend with a foreign key from tokens to clients
/// needs it seeded out of band first.
///
/// What this deliberately does **not** assert: that an uncommitted write is
/// invisible to a *different* connection. That is the other half of what a
/// transaction means, but checking it requires holding the transaction open
/// while reading through the pool — and a backend under test may legitimately
/// be running on a single-connection pool (in-memory SQLite is, necessarily),
/// where that deadlocks rather than fails. Every assertion below therefore
/// finishes with the transaction before touching the store again.
pub async fn run_transactional_op_store_tests<S: TransactionalOpStore>(store: &mut S) {
    rollback_discards_writes(store).await;
    commit_persists_writes(store).await;
    drop_without_commit_rolls_back(store).await;
    reads_its_own_uncommitted_writes(store).await;
    rollback_undoes_a_consume(store).await;
}

async fn rollback_discards_writes<S: TransactionalOpStore>(store: &mut S) {
    let t = token("tx-rolled-back");

    let mut tx = store
        .begin()
        .await
        .expect("beginning a transaction must succeed");
    tx.store_token(t.clone())
        .await
        .expect("storing inside a transaction must succeed");
    tx.rollback().await.expect("rolling back must succeed");

    assert!(
        store
            .get_token(&t.token)
            .await
            .expect("reading after a rollback must not error")
            .is_none(),
        "a write made inside a rolled-back transaction must not be durable — if this fails, \
         the store is committing as it goes and `rollback` is not undoing anything"
    );
}

async fn commit_persists_writes<S: TransactionalOpStore>(store: &mut S) {
    let t = token("tx-committed");

    let mut tx = store
        .begin()
        .await
        .expect("beginning a transaction must succeed");
    tx.store_token(t.clone())
        .await
        .expect("storing inside a transaction must succeed");
    tx.commit().await.expect("committing must succeed");

    let found = store
        .get_token(&t.token)
        .await
        .expect("reading after a commit must not error")
        .expect("a committed write must be durable");
    assert_eq!(found.token, t.token);
    assert_eq!(found.client_id, t.client_id);
}

async fn drop_without_commit_rolls_back<S: TransactionalOpStore>(store: &mut S) {
    let t = token("tx-dropped");

    {
        let mut tx = store
            .begin()
            .await
            .expect("beginning a transaction must succeed");
        tx.store_token(t.clone())
            .await
            .expect("storing inside a transaction must succeed");
        // Dropped without committing — the case an early `?` in a host
        // application's composed unit of work hits.
    }

    assert!(
        store
            .get_token(&t.token)
            .await
            .expect("reading after a dropped transaction must not error")
            .is_none(),
        "dropping a transaction without committing must roll it back, or every `?` in a \
         caller's unit of work leaves a partial write behind"
    );
}

async fn reads_its_own_uncommitted_writes<S: TransactionalOpStore>(store: &mut S) {
    let t = token("tx-read-your-writes");

    let mut tx = store
        .begin()
        .await
        .expect("beginning a transaction must succeed");
    tx.store_token(t.clone())
        .await
        .expect("storing inside a transaction must succeed");

    let found = tx
        .get_token(&t.token)
        .await
        .expect("reading inside the same transaction must not error")
        .expect("a transaction must see its own uncommitted writes");
    assert_eq!(found.token, t.token);

    tx.rollback().await.expect("rolling back must succeed");
}

/// The single-use consume paths are the ones most likely to break when
/// composed: a backend without `DELETE ... RETURNING` (MySQL) implements
/// them by opening its *own* transaction. Called inside a caller's
/// transaction that has to become a nested savepoint, governed by the outer
/// rollback — not an independent transaction that commits on its own.
async fn rollback_undoes_a_consume<S: TransactionalOpStore>(store: &mut S) {
    let code = AuthorizationCode::new(
        "tx-consume-rolled-back".to_string(),
        "client-1".to_string(),
        "https://cb.example.com".to_string(),
        "openid".to_string(),
        test_identity(),
        Utc::now() + Duration::minutes(5),
        false,
    );

    let mut tx = store
        .begin()
        .await
        .expect("beginning a transaction must succeed");
    tx.store_code(code.clone())
        .await
        .expect("storing a code inside a transaction must succeed");
    let consumed = tx
        .consume_code(&code.code)
        .await
        .expect("consuming inside a transaction must not error")
        .expect("consuming a code stored in the same transaction must return it");
    assert_eq!(consumed.code, code.code);
    tx.rollback().await.expect("rolling back must succeed");

    assert!(
        store
            .consume_code(&code.code)
            .await
            .expect("reading after a rollback must not error")
            .is_none(),
        "a store-and-consume rolled back as a unit must leave nothing behind — if this fails, \
         the consume path opened its own transaction and committed independently of the caller's"
    );
}
