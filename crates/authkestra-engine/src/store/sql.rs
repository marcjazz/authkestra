#[cfg(any(
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

#[cfg(feature = "sql-postgres")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T>
    for SqlKvStore<sqlx::Postgres>
{
    #[tracing::instrument(skip(self))]
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "loading from Postgres store");
        let query = format!(
            "SELECT key, value, expires_at FROM {} WHERE key = $1 AND expires_at > $2",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&query)
            .bind(key)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Postgres get error");
                StoreError::Internal(format!("Postgres get error: {e}"))
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
        tracing::debug!("saving to Postgres store");
        let query = format!(
            "INSERT INTO {} (key, value, expires_at)
             VALUES ($1, $2, $3)
             ON CONFLICT(key) DO UPDATE SET
             value = $2, expires_at = $3",
            self.table_name
        );

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
                tracing::error!(error = %e, "Postgres set error");
                StoreError::Internal(format!("Postgres set error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        tracing::debug!(key = %key, "deleting from Postgres store");
        let query = format!("DELETE FROM {} WHERE key = $1", self.table_name);
        sqlx::query(&query)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Postgres delete error");
                StoreError::Internal(format!("Postgres delete error: {e}"))
            })?;
        Ok(())
    }
}

#[cfg(feature = "sql-postgres")]
impl SqlKvStore<sqlx::Postgres> {
    /// Creates the necessary table and index if they do not exist.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let query1 = format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                key TEXT PRIMARY KEY,
                index_key TEXT,
                value TEXT NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL
            )",
            table = self.table_name
        );
        let query2 = format!(
            "CREATE INDEX IF NOT EXISTS {table}_idx ON {table}(index_key)",
            table = self.table_name
        );
        sqlx::query(&query1)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Internal(format!("Postgres migration error: {e}")))?;
        sqlx::query(&query2)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Internal(format!("Postgres migration index error: {e}")))?;
        Ok(())
    }
}

#[cfg(feature = "sql-postgres")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> crate::store::AtomicConsume<T>
    for SqlKvStore<sqlx::Postgres>
{
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

#[cfg(feature = "sql-postgres")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> crate::store::IndexedKvStore<T>
    for SqlKvStore<sqlx::Postgres>
{
    #[tracing::instrument(skip(self, value), fields(key = %key, index = %index))]
    async fn set_indexed(
        &self,
        key: &str,
        index: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        tracing::debug!("saving indexed to Postgres store");
        let query = format!(
            "INSERT INTO {} (key, index_key, value, expires_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(key) DO UPDATE SET
             index_key = $2, value = $3, expires_at = $4",
            self.table_name
        );

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
                tracing::error!(error = %e, "Postgres set_indexed error");
                StoreError::Internal(format!("Postgres set_indexed error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_index(&self, index: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(index = %index, "loading by index from Postgres store");
        let query = format!(
            "SELECT key, value, expires_at FROM {} WHERE index_key = $1 AND expires_at > $2",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&query)
            .bind(index)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Postgres get_by_index error");
                StoreError::Internal(format!("Postgres get_by_index error: {e}"))
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

#[cfg(feature = "sql-sqlite")]
impl SqlKvStore<sqlx::Sqlite> {
    /// Creates the necessary table and index if they do not exist.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let query = format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                key TEXT PRIMARY KEY,
                index_key TEXT,
                value TEXT NOT NULL,
                expires_at DATETIME NOT NULL
            );
            CREATE INDEX IF NOT EXISTS {table}_idx ON {table}(index_key);",
            table = self.table_name
        );
        sqlx::query(&query)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Internal(format!("Sqlite migration error: {e}")))?;
        Ok(())
    }
}

#[cfg(feature = "sql-sqlite")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T>
    for SqlKvStore<sqlx::Sqlite>
{
    #[tracing::instrument(skip(self))]
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "loading from Sqlite store");
        let query = format!(
            "SELECT key, value, expires_at FROM {} WHERE key = ?1 AND expires_at > ?2",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&query)
            .bind(key)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Sqlite get error");
                StoreError::Internal(format!("Sqlite get error: {e}"))
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
        tracing::debug!("saving to Sqlite store");
        let query = format!(
            "INSERT INTO {} (key, value, expires_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET
             value = ?2, expires_at = ?3",
            self.table_name
        );

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
                tracing::error!(error = %e, "Sqlite set error");
                StoreError::Internal(format!("Sqlite set error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        tracing::debug!(key = %key, "deleting from Sqlite store");
        let query = format!("DELETE FROM {} WHERE key = ?1", self.table_name);
        sqlx::query(&query)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Sqlite delete error");
                StoreError::Internal(format!("Sqlite delete error: {e}"))
            })?;
        Ok(())
    }
}

#[cfg(feature = "sql-sqlite")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> crate::store::AtomicConsume<T>
    for SqlKvStore<sqlx::Sqlite>
{
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

#[cfg(feature = "sql-sqlite")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> crate::store::IndexedKvStore<T>
    for SqlKvStore<sqlx::Sqlite>
{
    #[tracing::instrument(skip(self, value), fields(key = %key, index = %index))]
    async fn set_indexed(
        &self,
        key: &str,
        index: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        tracing::debug!("saving indexed to Sqlite store");
        let query = format!(
            "INSERT INTO {} (key, index_key, value, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET
             index_key = ?2, value = ?3, expires_at = ?4",
            self.table_name
        );

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
                tracing::error!(error = %e, "Sqlite set_indexed error");
                StoreError::Internal(format!("Sqlite set_indexed error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_index(&self, index: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(index = %index, "loading by index from Sqlite store");
        let query = format!(
            "SELECT key, value, expires_at FROM {} WHERE index_key = ?1 AND expires_at > ?2",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&query)
            .bind(index)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Sqlite get_by_index error");
                StoreError::Internal(format!("Sqlite get_by_index error: {e}"))
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

#[cfg(feature = "sql-mysql")]
impl SqlKvStore<sqlx::MySql> {
    /// Creates the necessary table and index if they do not exist.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let query = format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                `key` VARCHAR(255) PRIMARY KEY,
                index_key VARCHAR(255),
                value TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                INDEX {table}_idx (index_key)
            )",
            table = self.table_name
        );
        sqlx::query(&query)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Internal(format!("MySql migration error: {e}")))?;
        Ok(())
    }
}

#[cfg(feature = "sql-mysql")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T>
    for SqlKvStore<sqlx::MySql>
{
    #[tracing::instrument(skip(self))]
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "loading from MySql store");
        let query = format!(
            "SELECT `key`, value, expires_at FROM {} WHERE `key` = ? AND expires_at > ?",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&query)
            .bind(key)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "MySql get error");
                StoreError::Internal(format!("MySql get error: {e}"))
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
        tracing::debug!("saving to MySql store");
        let query = format!(
            "INSERT INTO {} (`key`, value, expires_at)
             VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE
             value = VALUES(value),
             expires_at = VALUES(expires_at)",
            self.table_name
        );

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
                tracing::error!(error = %e, "MySql set error");
                StoreError::Internal(format!("MySql set error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        tracing::debug!(key = %key, "deleting from MySql store");
        let query = format!("DELETE FROM {} WHERE `key` = ?", self.table_name);
        sqlx::query(&query)
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "MySql delete error");
                StoreError::Internal(format!("MySql delete error: {e}"))
            })?;
        Ok(())
    }
}

#[cfg(feature = "sql-mysql")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> crate::store::AtomicConsume<T>
    for SqlKvStore<sqlx::MySql>
{
    #[tracing::instrument(skip(self))]
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "atomically consuming from MySql store");
        let mut tx = self.pool.begin().await.map_err(|e| {
            tracing::error!(error = %e, "MySql begin tx error");
            StoreError::Internal(format!("MySql begin tx error: {e}"))
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
                tracing::error!(error = %e, "MySql consume select error");
                StoreError::Internal(format!("MySql consume select error: {e}"))
            })?;

        if let Some(model) = row {
            let delete_query = format!("DELETE FROM {} WHERE `key` = ?", self.table_name);
            sqlx::query(&delete_query)
                .bind(key)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "MySql consume delete error");
                    StoreError::Internal(format!("MySql consume delete error: {e}"))
                })?;

            tx.commit().await.map_err(|e| {
                tracing::error!(error = %e, "MySql commit tx error");
                StoreError::Internal(format!("MySql commit tx error: {e}"))
            })?;

            let entity: T = serde_json::from_str(&model.value).map_err(|e| {
                tracing::error!(error = %e, "Deserialization error");
                StoreError::Serialization(format!("Deserialization error: {e}"))
            })?;
            Ok(Some(entity))
        } else {
            tx.rollback().await.map_err(|e| {
                tracing::error!(error = %e, "MySql rollback tx error");
                StoreError::Internal(format!("MySql rollback tx error: {e}"))
            })?;
            Ok(None)
        }
    }
}

#[cfg(feature = "sql-mysql")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> crate::store::IndexedKvStore<T>
    for SqlKvStore<sqlx::MySql>
{
    #[tracing::instrument(skip(self, value), fields(key = %key, index = %index))]
    async fn set_indexed(
        &self,
        key: &str,
        index: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        tracing::debug!("saving indexed to MySql store");
        let query = format!(
            "INSERT INTO {} (`key`, index_key, value, expires_at)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             index_key = VALUES(index_key),
             value = VALUES(value),
             expires_at = VALUES(expires_at)",
            self.table_name
        );

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
                tracing::error!(error = %e, "MySql set_indexed error");
                StoreError::Internal(format!("MySql set_indexed error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_index(&self, index: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(index = %index, "loading by index from MySql store");
        let query = format!(
            "SELECT `key`, value, expires_at FROM {} WHERE index_key = ? AND expires_at > ?",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlKvModel> = sqlx::query_as(&query)
            .bind(index)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "MySql get_by_index error");
                StoreError::Internal(format!("MySql get_by_index error: {e}"))
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

#[cfg(all(test, feature = "sql-sqlite"))]
mod tests {
    use super::*;
    use crate::store::{AtomicConsume, IndexedKvStore, KvStore};
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
mod postgres_tests {
    use super::*;
    use crate::store::{AtomicConsume, IndexedKvStore, KvStore};
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
mod mysql_tests {
    use super::*;
    use crate::store::{AtomicConsume, IndexedKvStore, KvStore};
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
