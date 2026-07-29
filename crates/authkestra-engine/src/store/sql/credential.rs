#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
use async_trait::async_trait;
use serde_json::Value;
use sqlx::Database;

use crate::auth::error::AuthError;
use crate::auth::store::CredentialStore;

/// SQLx implementation of the `CredentialStore` trait.
#[derive(Clone, Debug)]
pub struct SqlxCredentialStore<DB: Database> {
    pub pool: sqlx::Pool<DB>,
    pub table_name: String,
}

impl<DB: Database> SqlxCredentialStore<DB> {
    /// Create a new `SqlxCredentialStore` with the default table name `authkestra_credentials`.
    pub fn new(pool: sqlx::Pool<DB>) -> Self {
        Self {
            pool,
            table_name: "authkestra_credentials".to_string(),
        }
    }

    /// Create a new `SqlxCredentialStore` with a custom table name.
    pub fn with_table_name(pool: sqlx::Pool<DB>, table_name: String) -> Self {
        Self { pool, table_name }
    }
}

/// Helper model for deserializing database rows.
#[derive(sqlx::FromRow)]
struct SqlCredentialModel {
    #[allow(dead_code)]
    pub credential_id: String,
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub cred_type: String,
    pub data: String,
}

macro_rules! impl_credential_store {
    (
        $backend:path,
        $feature:literal,
        $dialect_name:literal,
        $save_query:expr,
        $get_query:expr,
        $update_query:expr,
        $migrate_q1:expr,
        $migrate_q2:expr
    ) => {
        #[cfg(feature = $feature)]
        #[async_trait]
        impl CredentialStore for SqlxCredentialStore<$backend> {
            #[tracing::instrument(skip(self, data))]
            async fn save_credential(
                &self,
                user_id: &str,
                cred_type: &str,
                data: Value,
            ) -> Result<(), AuthError> {
                tracing::debug!(concat!("saving credential to ", $dialect_name, " store"));
                let query = format!($save_query, self.table_name);

                let credential_id = data
                    .get("credential_id")
                    .or_else(|| data.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

                let json = serde_json::to_string(&data)
                    .map_err(|e| AuthError::Internal(format!("Serialization error: {e}")))?;

                sqlx::query(&query)
                    .bind(&credential_id)
                    .bind(user_id)
                    .bind(cred_type)
                    .bind(json)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " save_credential error"));
                        AuthError::Internal(format!("{} save_credential error: {}", $dialect_name, e))
                    })?;

                Ok(())
            }

            #[tracing::instrument(skip(self))]
            async fn get_credentials(
                &self,
                user_id: &str,
                cred_type: &str,
            ) -> Result<Vec<Value>, AuthError> {
                tracing::debug!(user_id = %user_id, cred_type = %cred_type, concat!("loading credentials from ", $dialect_name, " store"));
                let query = format!($get_query, self.table_name);

                let rows: Vec<SqlCredentialModel> = sqlx::query_as(&query)
                    .bind(user_id)
                    .bind(cred_type)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " get_credentials error"));
                        AuthError::Internal(format!("{} get_credentials error: {}", $dialect_name, e))
                    })?;

                let mut list = Vec::new();
                for row in rows {
                    let val: Value = serde_json::from_str(&row.data).map_err(|e| {
                        tracing::error!(error = %e, "Deserialization error");
                        AuthError::Internal(format!("Deserialization error: {e}"))
                    })?;
                    list.push(val);
                }

                Ok(list)
            }

            #[tracing::instrument(skip(self, data))]
            async fn update_credential(
                &self,
                credential_id: &str,
                data: Value,
            ) -> Result<(), AuthError> {
                tracing::debug!(credential_id = %credential_id, concat!("updating credential in ", $dialect_name, " store"));
                let query = format!($update_query, self.table_name);

                let json = serde_json::to_string(&data)
                    .map_err(|e| AuthError::Internal(format!("Serialization error: {e}")))?;

                sqlx::query(&query)
                    .bind(json)
                    .bind(credential_id)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, concat!($dialect_name, " update_credential error"));
                        AuthError::Internal(format!("{} update_credential error: {}", $dialect_name, e))
                    })?;

                Ok(())
            }
        }

        #[cfg(feature = $feature)]
        impl SqlxCredentialStore<$backend> {
            /// Creates the necessary credentials table and index if they do not exist.
            pub async fn migrate(&self) -> Result<(), AuthError> {
                let query1 = format!($migrate_q1, table = self.table_name);
                let query2 = format!($migrate_q2, table = self.table_name);
                sqlx::query(&query1)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| AuthError::Internal(format!("{} credential migration error: {}", $dialect_name, e)))?;
                sqlx::query(&query2)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| AuthError::Internal(format!("{} credential migration index error: {}", $dialect_name, e)))?;
                Ok(())
            }
        }
    };
}

impl_credential_store! {
    sqlx::Postgres,
    "sql-postgres",
    "Postgres",
    "INSERT INTO {} (credential_id, user_id, cred_type, data) VALUES ($1, $2, $3, $4) ON CONFLICT(credential_id) DO UPDATE SET data = $4",
    "SELECT credential_id, user_id, cred_type, data FROM {} WHERE user_id = $1 AND cred_type = $2",
    "UPDATE {} SET data = $1 WHERE credential_id = $2",
    "CREATE TABLE IF NOT EXISTS {table} (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, cred_type TEXT NOT NULL, data TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX IF NOT EXISTS {table}_user_idx ON {table}(user_id, cred_type)"
}

impl_credential_store! {
    sqlx::Sqlite,
    "sql-sqlite",
    "Sqlite",
    "INSERT INTO {} (credential_id, user_id, cred_type, data) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(credential_id) DO UPDATE SET data = ?4",
    "SELECT credential_id, user_id, cred_type, data FROM {} WHERE user_id = ?1 AND cred_type = ?2",
    "UPDATE {} SET data = ?1 WHERE credential_id = ?2",
    "CREATE TABLE IF NOT EXISTS {table} (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, cred_type TEXT NOT NULL, data TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX IF NOT EXISTS {table}_user_idx ON {table}(user_id, cred_type)"
}

impl_credential_store! {
    sqlx::MySql,
    "sql-mysql",
    "MySql",
    "INSERT INTO {} (credential_id, user_id, cred_type, data) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE data = VALUES(data)",
    "SELECT credential_id, user_id, cred_type, data FROM {} WHERE user_id = ? AND cred_type = ?",
    "UPDATE {} SET data = ? WHERE credential_id = ?",
    "CREATE TABLE IF NOT EXISTS {table} (credential_id VARCHAR(255) PRIMARY KEY, user_id VARCHAR(255) NOT NULL, cred_type VARCHAR(255) NOT NULL, data TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    "CREATE INDEX {table}_user_idx ON {table}(user_id, cred_type)"
}
