import re

with open("crates/authkestra-engine/src/store/sql.rs", "r") as f:
    content = f.read()

# Extract test module
tests = re.search(r'#\[cfg\(all\(test, feature = "sql-sqlite"\)\)\].*', content, re.DOTALL).group(0)

new_content = """#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::Database;
use std::time::Duration;

use crate::store::{KvStore, StoreError};

#[derive(Clone, Debug)]
pub struct SqlKvStore<DB: Database> {
    #[allow(dead_code)]
    pool: sqlx::Pool<DB>,
    #[allow(dead_code)]
    table_name: String,
}

pub type SqlStore<DB> = SqlKvStore<DB>;

/// Internal data model for a KV entry in the SQL database.
#[derive(sqlx::FromRow)]
pub struct SqlKvModel {
    pub key: String,
    pub value: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

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
"""

with open("crates/authkestra-engine/src/store/sql.rs", "w") as f:
    f.write(new_content)
    f.write("\n")
    f.write(tests)
