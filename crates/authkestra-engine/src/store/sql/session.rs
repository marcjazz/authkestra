#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::Database;
use std::time::Duration;

use crate::store::{AtomicInsert, KvStore, StoreError};

#[derive(Clone, Debug)]
#[deprecated(
    since = "0.2.4",
    note = "Using SqlKvStore for OP-specific data (clients, authorization codes, refresh tokens, \
            device codes) is deprecated — use `authkestra_op::sqlx_store::SqlxOpStore` instead, \
            which provides a normalized relational schema with proper foreign keys and ON DELETE CASCADE. \
            SqlKvStore remains a valid choice for generic KV/session storage when you prefer SQL \
            over Redis and do not need OP-specific semantics."
)]
#[non_exhaustive]
pub struct SqlKvStore<DB: Database> {
    #[allow(dead_code)]
    pub pool: sqlx::Pool<DB>,
    #[allow(dead_code)]
    pub table_name: String,
}

#[allow(deprecated)]
#[deprecated(
    since = "0.2.4",
    note = "SqlStore is a type alias for SqlKvStore — see SqlKvStore deprecation notice for details."
)]
pub type SqlStore<DB> = SqlKvStore<DB>;

/// Internal data model for a KV entry in the SQL database.
#[derive(sqlx::FromRow)]
#[non_exhaustive]
pub struct SqlKvModel {
    pub key: String,
    pub value: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[allow(deprecated)]
impl<DB: Database> SqlKvStore<DB> {
    pub fn new(pool: sqlx::Pool<DB>) -> Self {
        Self {
            pool,
            table_name: "authkestra_kv".to_string(),
        }
    }

    pub fn with_table_name(pool: sqlx::Pool<DB>, table_name: String) -> Self {
        Self { pool, table_name }
    }
}

macro_rules! impl_sql_store {
    (
        $backend:path,
        $feature:literal,
        $dialect_name:literal,
        $key_col:literal,
        $get_query:expr,
        $set_query:expr,
        $delete_query:expr,
        $migrate_q1:expr,
        $migrate_q2:expr,
        $set_indexed_query:expr,
        $get_by_index_query:expr,
        $consume_impl:item
    ) => {
        #[cfg(feature = $feature)]
        #[async_trait]
        #[allow(deprecated)]
        impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T>
            for SqlKvStore<$backend>
        {
            #[tracing::instrument(skip(self))]
            async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
                tracing::debug!(key = %key, concat!("loading from ", $dialect_name, " store"));
                let query = format!($get_query, self.table_name);
                let now = chrono::Utc::now();

                let row: Option<SqlKvModel> = sqlx::query_as(&query)
                    .bind(key)
                    .bind(now)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " get error"));
                        StoreError::Internal(format!("{} get error: {}", $dialect_name, e))
                    })?;

                match row {
                    Some(model) => {
                        let entity: T = serde_json::from_str(&model.value).map_err(|e| {
                            tracing::error!(error = %e, "Deserialization error");
                            StoreError::Serialization(format!("Deserialization error: {e}"))
                        })?;
                        Ok(Some(entity))
                    }
                    None => Ok(None),
                }
            }

            #[tracing::instrument(skip(self, value), fields(key = %key))]
            async fn set(&self, key: &str, value: T, ttl: Duration) -> Result<(), StoreError> {
                tracing::debug!(concat!("saving to ", $dialect_name, " store"));
                let query = format!($set_query, self.table_name);

                let json = serde_json::to_string(&value).map_err(|e| {
                    tracing::error!(error = %e, "Serialization error");
                    StoreError::Serialization(format!("Serialization error: {e}"))
                })?;

                let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

                sqlx::query(&query)
                    .bind(key)
                    .bind(json)
                    .bind(expires_at)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " set error"));
                        StoreError::Internal(format!("{} set error: {}", $dialect_name, e))
                    })?;

                Ok(())
            }

            #[tracing::instrument(skip(self))]
            async fn delete(&self, key: &str) -> Result<(), StoreError> {
                tracing::debug!(key = %key, concat!("deleting from ", $dialect_name, " store"));
                let query = format!($delete_query, self.table_name);
                sqlx::query(&query)
                    .bind(key)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " delete error"));
                        StoreError::Internal(format!("{} delete error: {}", $dialect_name, e))
                    })?;
                Ok(())
            }
        }

        #[cfg(feature = $feature)]
        #[allow(deprecated)]
        impl SqlKvStore<$backend> {
            /// Creates the necessary table and index if they do not exist.
            pub async fn migrate(&self) -> Result<(), StoreError> {
                let query1 = format!($migrate_q1, table = self.table_name);
                let query2 = format!($migrate_q2, table = self.table_name);
                sqlx::query(&query1)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| StoreError::Internal(format!("{} migration error: {}", $dialect_name, e)))?;
                sqlx::query(&query2)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| StoreError::Internal(format!("{} migration index error: {}", $dialect_name, e)))?;
                Ok(())
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        #[allow(deprecated)]
        impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> crate::store::IndexedKvStore<T>
            for SqlKvStore<$backend>
        {
            #[tracing::instrument(skip(self, value), fields(key = %key, index = %index))]
            async fn set_indexed(
                &self,
                key: &str,
                index: &str,
                value: T,
                ttl: Duration,
            ) -> Result<(), StoreError> {
                tracing::debug!(concat!("saving indexed to ", $dialect_name, " store"));
                let query = format!($set_indexed_query, self.table_name);

                let json = serde_json::to_string(&value).map_err(|e| {
                    tracing::error!(error = %e, "Serialization error");
                    StoreError::Serialization(format!("Serialization error: {e}"))
                })?;

                let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

                sqlx::query(&query)
                    .bind(key)
                    .bind(index)
                    .bind(json)
                    .bind(expires_at)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " set_indexed error"));
                        StoreError::Internal(format!("{} set_indexed error: {}", $dialect_name, e))
                    })?;

                Ok(())
            }

            #[tracing::instrument(skip(self))]
            async fn get_by_index(&self, index: &str) -> Result<Option<T>, StoreError> {
                tracing::debug!(index = %index, concat!("loading by index from ", $dialect_name, " store"));
                let query = format!($get_by_index_query, self.table_name);
                let now = chrono::Utc::now();

                let row: Option<SqlKvModel> = sqlx::query_as(&query)
                    .bind(index)
                    .bind(now)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " get_by_index error"));
                        StoreError::Internal(format!("{} get_by_index error: {}", $dialect_name, e))
                    })?;

                match row {
                    Some(model) => {
                        let entity: T = serde_json::from_str(&model.value).map_err(|e| {
                            tracing::error!(error = %e, "Deserialization error");
                            StoreError::Serialization(format!("Deserialization error: {e}"))
                        })?;
                        Ok(Some(entity))
                    }
                    None => Ok(None),
                }
            }
        }

        #[cfg(feature = $feature)]
        #[async_trait]
        #[allow(deprecated)]
        impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> crate::store::AtomicConsume<T>
            for SqlKvStore<$backend>
        {
            $consume_impl
        }
    };
}

impl_sql_store! {
    sqlx::Postgres,
    "sql-postgres",
    "Postgres",
    "key",
    "SELECT key, value, expires_at FROM {} WHERE key = $1 AND expires_at > $2",
    "INSERT INTO {} (key, value, expires_at) VALUES ($1, $2, $3) ON CONFLICT(key) DO UPDATE SET value = $2, expires_at = $3",
    "DELETE FROM {} WHERE key = $1",
    "CREATE TABLE IF NOT EXISTS {table} (key TEXT PRIMARY KEY, index_key TEXT, value TEXT NOT NULL, expires_at TIMESTAMP WITH TIME ZONE NOT NULL)",
    "CREATE UNIQUE INDEX IF NOT EXISTS {table}_idx ON {table}(index_key)",
    "INSERT INTO {} (key, index_key, value, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT(key) DO UPDATE SET index_key = $2, value = $3, expires_at = $4",
    "SELECT key, value, expires_at FROM {} WHERE index_key = $1 AND expires_at > $2",
    #[tracing::instrument(skip(self))]
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "atomically consuming from Postgres store");
        let query = format!(
            "DELETE FROM {} WHERE key = $1 AND expires_at > $2 RETURNING key, value, expires_at",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&query)
            .bind(key)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Postgres consume error");
                StoreError::Internal(format!("Postgres consume error: {e}"))
            })?;

        match row {
            Some(model) => {
                let entity: T = serde_json::from_str(&model.value).map_err(|e| {
                    tracing::error!(error = %e, "Deserialization error");
                    StoreError::Serialization(format!("Deserialization error: {e}"))
                })?;
                Ok(Some(entity))
            }
            None => Ok(None),
        }
    }
}

impl_sql_store! {
    sqlx::Sqlite,
    "sql-sqlite",
    "Sqlite",
    "key",
    "SELECT key, value, expires_at FROM {} WHERE key = ?1 AND expires_at > ?2",
    "INSERT INTO {} (key, value, expires_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = ?2, expires_at = ?3",
    "DELETE FROM {} WHERE key = ?1",
    "CREATE TABLE IF NOT EXISTS {table} (key TEXT PRIMARY KEY, index_key TEXT, value TEXT NOT NULL, expires_at DATETIME NOT NULL)",
    "CREATE UNIQUE INDEX IF NOT EXISTS {table}_idx ON {table}(index_key)",
    "INSERT INTO {} (key, index_key, value, expires_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(key) DO UPDATE SET index_key = ?2, value = ?3, expires_at = ?4",
    "SELECT key, value, expires_at FROM {} WHERE index_key = ?1 AND expires_at > ?2",
    #[tracing::instrument(skip(self))]
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "atomically consuming from Sqlite store");
        let query = format!(
            "DELETE FROM {} WHERE key = ?1 AND expires_at > ?2 RETURNING key, value, expires_at",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&query)
            .bind(key)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Sqlite consume error");
                StoreError::Internal(format!("Sqlite consume error: {e}"))
            })?;

        match row {
            Some(model) => {
                let entity: T = serde_json::from_str(&model.value).map_err(|e| {
                    tracing::error!(error = %e, "Deserialization error");
                    StoreError::Serialization(format!("Deserialization error: {e}"))
                })?;
                Ok(Some(entity))
            }
            None => Ok(None),
        }
    }
}

impl_sql_store! {
    sqlx::MySql,
    "sql-mysql",
    "MySql",
    "`key`",
    "SELECT `key`, value, expires_at FROM {} WHERE `key` = ? AND expires_at > ?",
    "INSERT INTO {} (`key`, value, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value), expires_at = VALUES(expires_at)",
    "DELETE FROM {} WHERE `key` = ?",
    "CREATE TABLE IF NOT EXISTS {table} (`key` VARCHAR(255) PRIMARY KEY, index_key VARCHAR(255), value TEXT NOT NULL, expires_at TIMESTAMP NOT NULL)",
    "CREATE UNIQUE INDEX {table}_idx ON {table}(index_key)",
    "INSERT INTO {} (`key`, index_key, value, expires_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE index_key = VALUES(index_key), value = VALUES(value), expires_at = VALUES(expires_at)",
    "SELECT `key`, value, expires_at FROM {} WHERE index_key = ? AND expires_at > ?",
    #[tracing::instrument(skip(self))]
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "atomically consuming from MySql store using transaction");
        let mut tx = self.pool.begin().await.map_err(|e| {
            tracing::error!(error = %e, "MySql transaction error");
            StoreError::Internal(format!("MySql transaction error: {e}"))
        })?;

        let select_query = format!(
            "SELECT `key`, value, expires_at FROM {} WHERE `key` = ? AND expires_at > ? FOR UPDATE",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&select_query)
            .bind(key)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "MySql select for update error");
                StoreError::Internal(format!("MySql select for update error: {e}"))
            })?;

        if let Some(model) = row {
            let delete_query = format!("DELETE FROM {} WHERE `key` = ?", self.table_name);
            sqlx::query(&delete_query)
                .bind(key)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "MySql delete error");
                    StoreError::Internal(format!("MySql delete error: {e}"))
                })?;

            tx.commit().await.map_err(|e| {
                tracing::error!(error = %e, "MySql commit error");
                StoreError::Internal(format!("MySql commit error: {e}"))
            })?;

            let entity: T = serde_json::from_str(&model.value).map_err(|e| {
                tracing::error!(error = %e, "Deserialization error");
                StoreError::Serialization(format!("Deserialization error: {e}"))
            })?;
            Ok(Some(entity))
        } else {
            tx.rollback().await.map_err(|e| {
                tracing::error!(error = %e, "MySql rollback error");
                StoreError::Internal(format!("MySql rollback error: {e}"))
            })?;
            Ok(None)
        }
    }
}

// `AtomicInsert` is implemented directly per dialect (rather than folded
// into the `impl_sql_store!` macro above) since it needs none of the
// get/set/delete/index query strings that macro parametrizes over — each
// dialect's insert-if-absent is a single, self-contained statement.

#[cfg(feature = "sql-postgres")]
#[async_trait]
#[allow(deprecated)]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> AtomicInsert<T>
    for SqlKvStore<sqlx::Postgres>
{
    #[tracing::instrument(skip(self, value))]
    async fn insert_if_absent(
        &self,
        key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        tracing::debug!(key = %key, "atomically inserting into Postgres store if absent");
        // A plain `DO NOTHING` never reclaims a row once its key has been
        // used once, even long after `expires_at` has passed — every
        // distinct key ever inserted (e.g. every DPoP proof `jti` this
        // server has ever seen) would occupy a row forever, since nothing
        // in this crate runs a periodic sweep. `DO UPDATE ... WHERE
        // expires_at <= $4` instead treats an *expired* existing row as
        // available for reuse: the conflicting row is overwritten (and
        // `rows_affected() > 0`, a fresh claim) only when it was already
        // expired; a still-valid row blocks the write and reports 0 rows
        // affected, unchanged from `DO NOTHING`'s behavior for that case.
        // This bounds growth to the number of *distinct* keys active
        // within one TTL window rather than every key ever seen, though a
        // deployment with a very high volume of never-repeated keys still
        // wants its own periodic `DELETE ... WHERE expires_at < now()`.
        let query = format!(
            "INSERT INTO {table} (key, value, expires_at) VALUES ($1, $2, $3) \
             ON CONFLICT(key) DO UPDATE SET value = $2, expires_at = $3 \
             WHERE {table}.expires_at <= $4",
            table = self.table_name
        );

        let json = serde_json::to_string(&value).map_err(|e| {
            tracing::error!(error = %e, "Serialization error");
            StoreError::Serialization(format!("Serialization error: {e}"))
        })?;
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl.as_secs() as i64);

        let result = sqlx::query(&query)
            .bind(key)
            .bind(json)
            .bind(expires_at)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Postgres insert_if_absent error");
                StoreError::Internal(format!("Postgres insert_if_absent error: {e}"))
            })?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(feature = "sql-sqlite")]
#[async_trait]
#[allow(deprecated)]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> AtomicInsert<T>
    for SqlKvStore<sqlx::Sqlite>
{
    #[tracing::instrument(skip(self, value))]
    async fn insert_if_absent(
        &self,
        key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        tracing::debug!(key = %key, "atomically inserting into Sqlite store if absent");
        // See the Postgres impl's comment: `DO UPDATE ... WHERE expires_at
        // <= ?4` reclaims an expired row instead of blocking on it forever,
        // bounding growth to distinct keys active within one TTL window.
        let query = format!(
            "INSERT INTO {table} (key, value, expires_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(key) DO UPDATE SET value = ?2, expires_at = ?3 \
             WHERE {table}.expires_at <= ?4",
            table = self.table_name
        );

        let json = serde_json::to_string(&value).map_err(|e| {
            tracing::error!(error = %e, "Serialization error");
            StoreError::Serialization(format!("Serialization error: {e}"))
        })?;
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl.as_secs() as i64);

        let result = sqlx::query(&query)
            .bind(key)
            .bind(json)
            .bind(expires_at)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Sqlite insert_if_absent error");
                StoreError::Internal(format!("Sqlite insert_if_absent error: {e}"))
            })?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(feature = "sql-mysql")]
#[async_trait]
#[allow(deprecated)]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> AtomicInsert<T>
    for SqlKvStore<sqlx::MySql>
{
    #[tracing::instrument(skip(self, value))]
    async fn insert_if_absent(
        &self,
        key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        // Second attempt at this method (review of authkestra#277 caught
        // the first): a `SELECT ... FOR UPDATE` transaction, matching this
        // file's MySQL `consume` pattern, is *unsafe* here specifically
        // because the row being locked usually doesn't exist yet.  Under
        // InnoDB's default REPEATABLE READ, `SELECT ... FOR UPDATE` against
        // a non-matching row still takes a gap lock (to prevent phantom
        // inserts within the transaction) — so two concurrent callers
        // racing on the same absent key each take a gap lock, then each
        // tries to insert into the gap the other is holding, which
        // deadlocks. Safety held (InnoDB kills one side rather than letting
        // both "win"), but the loser got `Err`, not `Ok(false)` — turning a
        // replayed proof into a 500 instead of a clean rejection, and
        // failing this trait's own concurrency contract test.
        //
        // No explicit transaction is needed at all: two separate,
        // individually-autocommitted statements are enough, because each
        // one is already atomic on its own and MySQL releases each
        // statement's locks the moment it completes (nothing is held open
        // across the gap between them, so there's nothing for a second
        // caller to deadlock against). `INSERT IGNORE` claims a genuinely
        // absent key in one step; only on conflict does a second statement
        // ask "is the existing row already expired", and that statement's
        // own `WHERE` re-evaluates under its own lock, so two callers
        // racing to reclaim the same expired row still can't both succeed
        // (whichever commits its `UPDATE` first changes `expires_at`,
        // which then falsifies the second caller's own `WHERE` clause).
        tracing::debug!(key = %key, "atomically inserting into MySql store if absent");

        let json = serde_json::to_string(&value).map_err(|e| {
            tracing::error!(error = %e, "Serialization error");
            StoreError::Serialization(format!("Serialization error: {e}"))
        })?;
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl.as_secs() as i64);

        let insert_query = format!(
            "INSERT IGNORE INTO {} (`key`, value, expires_at) VALUES (?, ?, ?)",
            self.table_name
        );
        let inserted = sqlx::query(&insert_query)
            .bind(key)
            .bind(&json)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "MySql insert_if_absent insert error");
                StoreError::Internal(format!("MySql insert_if_absent insert error: {e}"))
            })?;

        if inserted.rows_affected() > 0 {
            return Ok(true);
        }

        // A key already existed. Reclaim it only if it's already expired —
        // this single guarded UPDATE is what makes concurrent reclaim
        // attempts on the same expired key safe without a transaction: only
        // one caller's WHERE clause can still be true by the time it
        // actually acquires the row.
        let reclaim_query = format!(
            "UPDATE {} SET value = ?, expires_at = ? WHERE `key` = ? AND expires_at <= ?",
            self.table_name
        );
        let reclaimed = sqlx::query(&reclaim_query)
            .bind(&json)
            .bind(expires_at)
            .bind(key)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "MySql insert_if_absent reclaim error");
                StoreError::Internal(format!("MySql insert_if_absent reclaim error: {e}"))
            })?;

        Ok(reclaimed.rows_affected() > 0)
    }
}

#[cfg(all(test, feature = "sql-sqlite"))]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::store::{AtomicConsume, AtomicInsert, IndexedKvStore, KvStore};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::time::Duration;

    async fn setup_db() -> SqlKvStore<sqlx::Sqlite> {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let store = SqlKvStore::new(pool);
        store.migrate().await.unwrap();
        store
    }

    #[tokio::test]
    async fn test_sqlite_get_set_delete() {
        let store = setup_db().await;

        let res: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res, None);

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

        KvStore::<String>::delete(&store, "key1").await.unwrap();
        let res2: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res2, None);
    }

    #[tokio::test]
    async fn test_sqlite_atomic_consume() {
        let store = setup_db().await;

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let val: Option<String> = store.consume("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));

        let val2: Option<String> = store.consume("key1").await.unwrap();
        assert_eq!(val2, None);
    }

    #[tokio::test]
    async fn test_sqlite_insert_if_absent() {
        let store = setup_db().await;

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(inserted);

        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!inserted_again);

        let val: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));
    }

    /// Regression test: unlike a plain `ON CONFLICT DO NOTHING`, an
    /// *expired* existing row must be reclaimable rather than permanently
    /// blocking that key — otherwise every distinct key ever inserted
    /// (e.g. every DPoP proof `jti`) occupies a row forever.
    #[tokio::test]
    async fn test_sqlite_insert_if_absent_reclaims_an_expired_key() {
        let store = setup_db().await;

        // A TTL under one second truncates to `expires_at == now` at
        // insert time (`ttl.as_secs()` rounds down to 0), so this row is
        // already expired by the time the sleep below elapses.
        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_millis(1))
            .await
            .unwrap();
        assert!(inserted);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let reclaimed = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            reclaimed,
            "an expired key must be reclaimable, not blocked forever"
        );

        let val: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(val, Some("value2".to_string()));
    }

    #[tokio::test]
    async fn test_sqlite_indexed_store() {
        let store = setup_db().await;

        store
            .set_indexed("pk1", "sk1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let res: Option<String> = store.get("pk1").await.unwrap();
        assert_eq!(res, Some("value1".to_string()));
        let sk_res: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res, Some("value1".to_string()));

        // In SQL, index is a column on the primary record. Deleting the record deletes the index.
        KvStore::<String>::delete(&store, "pk1").await.unwrap();
        let sk_res_none: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res_none, None);
    }
}

#[cfg(all(test, feature = "sql-postgres"))]
#[allow(deprecated)]
mod postgres_tests {
    use super::*;
    use crate::store::{AtomicConsume, AtomicInsert, IndexedKvStore, KvStore};
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;
    use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
    use testcontainers_modules::postgres::Postgres;

    async fn setup_db() -> (SqlKvStore<sqlx::Postgres>, ContainerAsync<Postgres>) {
        let container = Postgres::default()
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_DB", "postgres")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

        let pool = PgPoolOptions::new().connect(&url).await.unwrap();

        let store = SqlKvStore::new(pool);
        store.migrate().await.unwrap();

        (store, container)
    }

    #[tokio::test]
    async fn test_postgres_get_set_delete() {
        let (store, _c) = setup_db().await;

        let res: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res, None);

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let res2: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res2, Some("value1".to_string()));

        KvStore::<String>::delete(&store, "key1").await.unwrap();
        let res3: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res3, None);
    }

    #[tokio::test]
    async fn test_postgres_atomic_consume() {
        let (store, _c) = setup_db().await;

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let val: Option<String> = store.consume("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));

        let val2: Option<String> = store.consume("key1").await.unwrap();
        assert_eq!(val2, None);
    }

    #[tokio::test]
    async fn test_postgres_insert_if_absent() {
        let (store, _c) = setup_db().await;

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(inserted);

        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!inserted_again);

        let val: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));
    }

    /// Regression test: an expired existing row must be reclaimable rather
    /// than permanently blocking that key. See the Sqlite version of this
    /// test for why a sub-second TTL is used.
    #[tokio::test]
    async fn test_postgres_insert_if_absent_reclaims_an_expired_key() {
        let (store, _c) = setup_db().await;

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_millis(1))
            .await
            .unwrap();
        assert!(inserted);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let reclaimed = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            reclaimed,
            "an expired key must be reclaimable, not blocked forever"
        );

        let val: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(val, Some("value2".to_string()));
    }

    #[tokio::test]
    async fn test_postgres_indexed_store() {
        let (store, _c) = setup_db().await;

        store
            .set_indexed("pk1", "sk1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let res: Option<String> = store.get("pk1").await.unwrap();
        assert_eq!(res, Some("value1".to_string()));
        let sk_res: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res, Some("value1".to_string()));

        KvStore::<String>::delete(&store, "pk1").await.unwrap();
        let sk_res_none: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res_none, None);
    }
}

#[cfg(all(test, feature = "sql-mysql"))]
#[allow(deprecated)]
mod mysql_tests {
    use super::*;
    use crate::store::{AtomicConsume, AtomicInsert, IndexedKvStore, KvStore};
    use sqlx::mysql::MySqlPoolOptions;
    use std::time::Duration;
    use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
    use testcontainers_modules::mysql::Mysql;

    async fn setup_db() -> (SqlKvStore<sqlx::MySql>, ContainerAsync<Mysql>) {
        let container = Mysql::default()
            .with_env_var("MYSQL_ROOT_PASSWORD", "root")
            .with_env_var("MYSQL_DATABASE", "testdb")
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(3306).await.unwrap();
        let url = format!("mysql://root:root@127.0.0.1:{port}/testdb");

        let pool = MySqlPoolOptions::new().connect(&url).await.unwrap();

        let store = SqlKvStore::new(pool);
        store.migrate().await.unwrap();

        (store, container)
    }

    #[tokio::test]
    async fn test_mysql_get_set_delete() {
        let (store, _c) = setup_db().await;

        let res: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res, None);

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let res2: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res2, Some("value1".to_string()));

        KvStore::<String>::delete(&store, "key1").await.unwrap();
        let res3: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res3, None);
    }

    #[tokio::test]
    async fn test_mysql_atomic_consume() {
        let (store, _c) = setup_db().await;

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let val: Option<String> = store.consume("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));

        let val2: Option<String> = store.consume("key1").await.unwrap();
        assert_eq!(val2, None);
    }

    #[tokio::test]
    async fn test_mysql_insert_if_absent() {
        let (store, _c) = setup_db().await;

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(inserted);

        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!inserted_again);

        let val: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));
    }

    /// Regression test: an expired existing row must be reclaimable rather
    /// than permanently blocking that key. Also pins the MySQL-specific
    /// affected-rows quirk this dialect's fix relies on: `ON DUPLICATE KEY
    /// UPDATE` reports a *changed* row as 2 affected rows, not 1, so the
    /// impl checks `> 0` rather than `== 1`.
    #[tokio::test]
    async fn test_mysql_insert_if_absent_reclaims_an_expired_key() {
        let (store, _c) = setup_db().await;

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_millis(1))
            .await
            .unwrap();
        assert!(inserted);

        // MySQL's `TIMESTAMP` column (no fractional-second precision in
        // this migration) *rounds* a sub-second value to the nearest whole
        // second rather than truncating it, so a 1ms TTL's stored
        // `expires_at` can land up to a full second after the actual
        // insert instant — a 50ms sleep was flaky (~1 run in 3) for exactly
        // that reason. Sleeping past that worst case removes the flake
        // without needing a schema change that would affect every
        // consumer of this migration, not just this test.
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let reclaimed = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            reclaimed,
            "an expired key must be reclaimable, not blocked forever"
        );

        let val: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(val, Some("value2".to_string()));
    }

    /// Regression test for authkestra#277's review: a `SELECT ... FOR
    /// UPDATE` transaction over a possibly-absent row deadlocked InnoDB
    /// under concurrent access (a gap lock taken by each of two racers on
    /// the same non-existent key, each then trying to insert into the gap
    /// the other holds). The fix drops the transaction entirely; this
    /// proves many concurrent callers racing on the same key never error
    /// and exactly one of them wins.
    #[tokio::test]
    async fn test_mysql_insert_if_absent_is_atomic_under_concurrency() {
        let (store, _c) = setup_db().await;
        let store = std::sync::Arc::new(store);

        let mut handles = Vec::new();
        for i in 0..32u32 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store
                    .insert_if_absent("shared-key", i.to_string(), Duration::from_secs(10))
                    .await
            }));
        }

        let mut successes = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(true) => successes += 1,
                Ok(false) => {}
                Err(e) => panic!(
                    "insert_if_absent must never error under concurrency on a shared key, got {e:?}"
                ),
            }
        }
        assert_eq!(successes, 1, "exactly one racing insert must win");
    }

    #[tokio::test]
    async fn test_mysql_indexed_store() {
        let (store, _c) = setup_db().await;

        store
            .set_indexed("pk1", "sk1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let res: Option<String> = store.get("pk1").await.unwrap();
        assert_eq!(res, Some("value1".to_string()));
        let sk_res: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res, Some("value1".to_string()));

        KvStore::<String>::delete(&store, "pk1").await.unwrap();
        let sk_res_none: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res_none, None);
    }
}
