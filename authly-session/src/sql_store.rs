use authly_core::{AuthError, Identity};
use crate::{Session, SessionStore};
use async_trait::async_trait;
use sqlx::Database;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct SqlStore<DB: Database> {
    pool: sqlx::Pool<DB>,
    table_name: String,
}

impl<DB: Database> SqlStore<DB> {
    pub fn new(pool: sqlx::Pool<DB>) -> Self {
        Self {
            pool,
            table_name: "authly_sessions".to_string(),
        }
    }

    pub fn with_table_name(pool: sqlx::Pool<DB>, table_name: String) -> Self {
        Self { pool, table_name }
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl SessionStore for SqlStore<sqlx::Postgres> {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        let query = format!(
            "SELECT id, provider_id, external_id, email, username, claims, expires_at FROM {} WHERE id = $1 AND expires_at > $2",
            self.table_name
        );
        let now = chrono::Utc::now();
        
        let row: Option<(String, String, String, Option<String>, Option<String>, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(&query)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("Postgres load_session error: {}", e)))?;

        match row {
            Some((id, provider_id, external_id, email, username, claims_json, expires_at)) => {
                let claims: HashMap<String, String> = serde_json::from_str(&claims_json)
                    .map_err(|e| AuthError::Session(format!("Claims deserialization error: {}", e)))?;
                
                let session = Session {
                    id,
                    identity: Identity {
                        provider_id,
                        external_id,
                        email,
                        username,
                        attributes: claims,
                    },
                    expires_at,
                };
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        let query = format!(
            "INSERT INTO {} (id, provider_id, external_id, email, username, claims, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(id) DO UPDATE SET
             provider_id = $2, external_id = $3, email = $4, username = $5, claims = $6, expires_at = $7",
            self.table_name
        );
        let claims_json = serde_json::to_string(&session.identity.attributes)
            .map_err(|e| AuthError::Session(format!("Claims serialization error: {}", e)))?;

        sqlx::query(&query)
            .bind(&session.id)
            .bind(&session.identity.provider_id)
            .bind(&session.identity.external_id)
            .bind(&session.identity.email)
            .bind(&session.identity.username)
            .bind(claims_json)
            .bind(session.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("Postgres save_session error: {}", e)))?;

        Ok(())
    }

    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        let query = format!("DELETE FROM {} WHERE id = $1", self.table_name);
        sqlx::query(&query)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("Postgres delete_session error: {}", e)))?;
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
#[async_trait]
impl SessionStore for SqlStore<sqlx::Sqlite> {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        let query = format!(
            "SELECT id, provider_id, external_id, email, username, claims, expires_at FROM {} WHERE id = ?1 AND expires_at > ?2",
            self.table_name
        );
        let now = chrono::Utc::now();
        
        let row: Option<(String, String, String, Option<String>, Option<String>, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(&query)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("Sqlite load_session error: {}", e)))?;

        match row {
            Some((id, provider_id, external_id, email, username, claims_json, expires_at)) => {
                let claims: HashMap<String, String> = serde_json::from_str(&claims_json)
                    .map_err(|e| AuthError::Session(format!("Claims deserialization error: {}", e)))?;
                
                let session = Session {
                    id,
                    identity: Identity {
                        provider_id,
                        external_id,
                        email,
                        username,
                        attributes: claims,
                    },
                    expires_at,
                };
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        let query = format!(
            "INSERT INTO {} (id, provider_id, external_id, email, username, claims, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
             provider_id = ?2, external_id = ?3, email = ?4, username = ?5, claims = ?6, expires_at = ?7",
            self.table_name
        );
        let claims_json = serde_json::to_string(&session.identity.attributes)
            .map_err(|e| AuthError::Session(format!("Claims serialization error: {}", e)))?;

        sqlx::query(&query)
            .bind(&session.id)
            .bind(&session.identity.provider_id)
            .bind(&session.identity.external_id)
            .bind(&session.identity.email)
            .bind(&session.identity.username)
            .bind(claims_json)
            .bind(session.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("Sqlite save_session error: {}", e)))?;

        Ok(())
    }

    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        let query = format!("DELETE FROM {} WHERE id = ?1", self.table_name);
        sqlx::query(&query)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("Sqlite delete_session error: {}", e)))?;
        Ok(())
    }
}

#[cfg(feature = "mysql")]
#[async_trait]
impl SessionStore for SqlStore<sqlx::MySql> {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        let query = format!(
            "SELECT id, provider_id, external_id, email, username, claims, expires_at FROM {} WHERE id = ? AND expires_at > ?",
            self.table_name
        );
        let now = chrono::Utc::now();
        
        let row: Option<(String, String, String, Option<String>, Option<String>, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(&query)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("MySql load_session error: {}", e)))?;

        match row {
            Some((id, provider_id, external_id, email, username, claims_json, expires_at)) => {
                let claims: HashMap<String, String> = serde_json::from_str(&claims_json)
                    .map_err(|e| AuthError::Session(format!("Claims deserialization error: {}", e)))?;
                
                let session = Session {
                    id,
                    identity: Identity {
                        provider_id,
                        external_id,
                        email,
                        username,
                        attributes: claims,
                    },
                    expires_at,
                };
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        let query = format!(
            "INSERT INTO {} (id, provider_id, external_id, email, username, claims, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             provider_id = VALUES(provider_id),
             external_id = VALUES(external_id),
             email = VALUES(email),
             username = VALUES(username),
             claims = VALUES(claims),
             expires_at = VALUES(expires_at)",
            self.table_name
        );
        let claims_json = serde_json::to_string(&session.identity.attributes)
            .map_err(|e| AuthError::Session(format!("Claims serialization error: {}", e)))?;

        sqlx::query(&query)
            .bind(&session.id)
            .bind(&session.identity.provider_id)
            .bind(&session.identity.external_id)
            .bind(&session.identity.email)
            .bind(&session.identity.username)
            .bind(claims_json)
            .bind(session.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("MySql save_session error: {}", e)))?;

        Ok(())
    }

    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        let query = format!("DELETE FROM {} WHERE id = ?", self.table_name);
        sqlx::query(&query)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::Session(format!("MySql delete_session error: {}", e)))?;
        Ok(())
    }
}
