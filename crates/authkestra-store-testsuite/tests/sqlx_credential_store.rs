//! `CredentialStore` conformance against `SqlxCredentialStore`.
//!
//! Its own target rather than a case in `sqlx_store.rs`, because it needs
//! this crate's `credential-store` feature and a `[[test]]` target is the
//! only place Cargo lets that be stated — a dev-dependency cannot turn on a
//! feature of the package it belongs to. Sharing a file with the `OpStore`
//! test would have meant gating that behind the feature too.

use sqlx::sqlite::SqlitePoolOptions;

/// Runs the shared `CredentialStore` conformance suite against
/// `SqlxCredentialStore` — the only in-tree implementation, and the one whose
/// `delete_credential` atomicity `RecoveryCodeAuthMethod` depends on to make a
/// code single-use. In-memory SQLite, so it stays fast and docker-free.
#[tokio::test]
async fn test_sqlx_credential_store_sqlite() {
    use authkestra_engine::store::sql::SqlxCredentialStore;
    use authkestra_store_testsuite::credential::run_credential_store_tests;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // One connection, for the reason the OpStore test above documents:
    // `sqlite::memory:` gives every connection its own database, so a larger
    // pool would hand the concurrent-delete test several unrelated ones and
    // let every task "win" against its own private copy.
    //
    // Worth being straight about what that costs. A single-connection pool
    // serialises every statement, so the suite's concurrent-delete case
    // cannot fail here through a genuine race — a store doing SELECT-then-
    // DELETE would still see the row gone on its second pass. Against this
    // backend that case is a smoke check (it does catch a `delete` that
    // reports `true` unconditionally, though the serial case catches that
    // first); its real value is for a store whose deletes can actually run
    // in parallel, which is every other implementation the trait will get.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite pool must connect");

    // The suite wants a fresh, empty store per case and its factory is
    // synchronous, so the tables are migrated up front and handed out in
    // turn. They share one database rather than one table, which is what
    // keeps the cases from seeing each other's credentials.
    const CASES: usize = 8;
    for n in 0..CASES {
        SqlxCredentialStore::<sqlx::Sqlite>::with_table_name(
            pool.clone(),
            format!("ak_credentials_{n}"),
        )
        .migrate()
        .await
        .expect("migration must succeed");
    }

    let next = AtomicUsize::new(0);
    run_credential_store_tests(&|| {
        let n = next.fetch_add(1, Ordering::SeqCst);
        assert!(n < CASES, "the suite wanted more stores than were migrated");
        SqlxCredentialStore::<sqlx::Sqlite>::with_table_name(
            pool.clone(),
            format!("ak_credentials_{n}"),
        )
    })
    .await;
}
