#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
use async_trait::async_trait;
use sqlx::Database;
use std::time::Duration;
use serde::{de::DeserializeOwned, Serialize};

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
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T> for SqlKvStore<sqlx::Postgres> {
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

#[cfg(feature = "sql-sqlite")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T> for SqlKvStore<sqlx::Sqlite> {
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

#[cfg(feature = "sql-mysql")]
#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T> for SqlKvStore<sqlx::MySql> {
    #[tracing::instrument(skip(self))]
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "loading from MySql store");
        let query = format!(
            "SELECT key, value, expires_at FROM {} WHERE key = ? AND expires_at > ?",
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
            "INSERT INTO {} (key, value, expires_at)
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
        let query = format!("DELETE FROM {} WHERE key = ?", self.table_name);
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
