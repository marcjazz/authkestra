//! Regression test for `SeaOrmOpStore::migrate()` actually creating the
//! `#[sea_orm(indexed)]` index declared on `device_code::Model::user_code` —
//! `create_table_from_entity` alone does not emit it (see `store.rs`'s
//! `migrate()` doc comment), and a passing `migrate().await` on its own
//! proves nothing about whether the index exists.

use authkestra_example_seaorm::SeaOrmOpStore;
use sea_orm::{ConnectionTrait, DbBackend, Statement};

#[tokio::test]
async fn migrate_creates_an_index_on_device_code_user_code() {
    let store = SeaOrmOpStore::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite connection must succeed");
    store
        .migrate()
        .await
        .expect("migrating a fresh in-memory database must succeed");

    // SQLite's own schema catalog, not a query-plan-text heuristic: every
    // real index on a table has a row here with its defining SQL, and
    // implicit indexes (e.g. the primary key's) have `sql IS NULL`, so this
    // can't accidentally match anything but a genuine `CREATE INDEX` naming
    // `user_code`.
    let rows = store
        .connection()
        .query_all(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT sql FROM sqlite_master \
             WHERE type = 'index' AND tbl_name = 'oauth_device_codes' AND sql IS NOT NULL",
        ))
        .await
        .expect("querying sqlite_master must succeed");

    let index_definitions: Vec<String> = rows
        .iter()
        .map(|row| {
            row.try_get_by::<String, _>(0usize)
                .expect("sql column must be a string")
        })
        .collect();

    assert!(
        index_definitions
            .iter()
            .any(|sql| sql.to_ascii_lowercase().contains("user_code")),
        "expected an index on oauth_device_codes.user_code after migrate(), found: {index_definitions:?}"
    );
}
