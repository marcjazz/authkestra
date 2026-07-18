#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
use async_trait::async_trait;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
use authkestra_engine::auth::{AuthError, Identity, Session, SessionStore};
use sqlx::Database;
#[cfg(any(feature = "postgres", feature = "sqlite", feature = "mysql"))]
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct SqlSessionStore<DB: Database> {
    #[allow(dead_code)]
    pool: sqlx::Pool<DB>,
    #[allow(dead_code)]
    table_name: String,
}

pub type SqlStore<DB> = SqlSessionStore<DB>;

/// Internal data model for a session in the SQL database.
#[derive(sqlx::FromRow)]
pub struct SqlSessionModel {
    pub id: String,
    pub provider_id: String,
    pub external_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub claims: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl<DB: Database> SqlSessionStore<DB> {
    pub fn new(pool: sqlx::Pool<DB>) -> Self {
        Self {
            pool,
            table_name: "authkestra_sessions".to_string(),
        }
    }

    pub fn with_table_name(pool: sqlx::Pool<DB>, table_name: String) -> Self {
        Self { pool, table_name }
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl SessionStore for SqlSessionStore<sqlx::Postgres> {
    #[tracing::instrument(skip(self))]
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        tracing::debug!(session_id = %id, "loading session from Postgres store");
        let query = format!(
            "SELECT id, provider_id, external_id, email, name, claims, expires_at FROM {} WHERE id = $1 AND expires_at > $2",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlSessionModel> = sqlx::query_as(&query)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Postgres load_session error");
                AuthError::Session(format!("Postgres load_session error: {e}"))
            })?;

        match row {
            Some(model) => {
                let claims: HashMap<String, String> =
                    serde_json::from_str(&model.claims).map_err(|e| {
                        tracing::error!(error = %e, "Claims deserialization error");
                        AuthError::Session(format!("Claims deserialization error: {e}"))
                    })?;

                let session = Session {
                    id: model.id,
                    identity: Identity {
                        provider_id: model.provider_id,
                        external_id: model.external_id,
                        email: model.email,
                        username: model.name,
                        attributes: claims,
                    },
                    expires_at: model.expires_at,
                };
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self, session), fields(session_id = %session.id))]
    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        tracing::debug!("saving session to Postgres store");
        let query = format!(
            "INSERT INTO {} (id, provider_id, external_id, email, name, claims, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(id) DO UPDATE SET
             provider_id = $2, external_id = $3, email = $4, name = $5, claims = $6, expires_at = $7",
            self.table_name
        );
        let claims_json = serde_json::to_string(&session.identity.attributes).map_err(|e| {
            tracing::error!(error = %e, "Claims serialization error");
            AuthError::Session(format!("Claims serialization error: {e}"))
        })?;

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
            .map_err(|e| {
                tracing::error!(error = %e, "Postgres save_session error");
                AuthError::Session(format!("Postgres save_session error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        tracing::debug!(session_id = %id, "deleting session from Postgres store");
        let query = format!("DELETE FROM {} WHERE id = $1", self.table_name);
        sqlx::query(&query)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Postgres delete_session error");
                AuthError::Session(format!("Postgres delete_session error: {e}"))
            })?;
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
#[async_trait]
impl SessionStore for SqlSessionStore<sqlx::Sqlite> {
    #[tracing::instrument(skip(self))]
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        tracing::debug!(session_id = %id, "loading session from Sqlite store");
        let query = format!(
            "SELECT id, provider_id, external_id, email, name, claims, expires_at FROM {} WHERE id = ?1 AND expires_at > ?2",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlSessionModel> = sqlx::query_as(&query)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Sqlite load_session error");
                AuthError::Session(format!("Sqlite load_session error: {e}"))
            })?;

        match row {
            Some(model) => {
                let claims: HashMap<String, String> =
                    serde_json::from_str(&model.claims).map_err(|e| {
                        tracing::error!(error = %e, "Claims deserialization error");
                        AuthError::Session(format!("Claims deserialization error: {e}"))
                    })?;

                let session = Session {
                    id: model.id,
                    identity: Identity {
                        provider_id: model.provider_id,
                        external_id: model.external_id,
                        email: model.email,
                        username: model.name,
                        attributes: claims,
                    },
                    expires_at: model.expires_at,
                };
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self, session), fields(session_id = %session.id))]
    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        tracing::debug!("saving session to Sqlite store");
        let query = format!(
            "INSERT INTO {} (id, provider_id, external_id, email, name, claims, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
             provider_id = ?2, external_id = ?3, email = ?4, name = ?5, claims = ?6, expires_at = ?7",
            self.table_name
        );
        let claims_json = serde_json::to_string(&session.identity.attributes).map_err(|e| {
            tracing::error!(error = %e, "Claims serialization error");
            AuthError::Session(format!("Claims serialization error: {e}"))
        })?;

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
            .map_err(|e| {
                tracing::error!(error = %e, "Sqlite save_session error");
                AuthError::Session(format!("Sqlite save_session error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        tracing::debug!(session_id = %id, "deleting session from Sqlite store");
        let query = format!("DELETE FROM {} WHERE id = ?1", self.table_name);
        sqlx::query(&query)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Sqlite delete_session error");
                AuthError::Session(format!("Sqlite delete_session error: {e}"))
            })?;
        Ok(())
    }
}

#[cfg(feature = "mysql")]
#[async_trait]
impl SessionStore for SqlSessionStore<sqlx::MySql> {
    #[tracing::instrument(skip(self))]
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        tracing::debug!(session_id = %id, "loading session from MySql store");
        let query = format!(
            "SELECT id, provider_id, external_id, email, name, claims, expires_at FROM {} WHERE id = ? AND expires_at > ?",
            self.table_name
        );
        let now = chrono::Utc::now();

        let row: Option<SqlSessionModel> = sqlx::query_as(&query)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "MySql load_session error");
                AuthError::Session(format!("MySql load_session error: {e}"))
            })?;

        match row {
            Some(model) => {
                let claims: HashMap<String, String> =
                    serde_json::from_str(&model.claims).map_err(|e| {
                        tracing::error!(error = %e, "Claims deserialization error");
                        AuthError::Session(format!("Claims deserialization error: {e}"))
                    })?;

                let session = Session {
                    id: model.id,
                    identity: Identity {
                        provider_id: model.provider_id,
                        external_id: model.external_id,
                        email: model.email,
                        username: model.name,
                        attributes: claims,
                    },
                    expires_at: model.expires_at,
                };
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self, session), fields(session_id = %session.id))]
    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        tracing::debug!("saving session to MySql store");
        let query = format!(
            "INSERT INTO {} (id, provider_id, external_id, email, name, claims, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             provider_id = VALUES(provider_id),
             external_id = VALUES(external_id),
             email = VALUES(email),
             name = VALUES(name),
             claims = VALUES(claims),
             expires_at = VALUES(expires_at)",
            self.table_name
        );
        let claims_json = serde_json::to_string(&session.identity.attributes).map_err(|e| {
            tracing::error!(error = %e, "Claims serialization error");
            AuthError::Session(format!("Claims serialization error: {e}"))
        })?;

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
            .map_err(|e| {
                tracing::error!(error = %e, "MySql save_session error");
                AuthError::Session(format!("MySql save_session error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        tracing::debug!(session_id = %id, "deleting session from MySql store");
        let query = format!("DELETE FROM {} WHERE id = ?", self.table_name);
        sqlx::query(&query)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "MySql delete_session error");
                AuthError::Session(format!("MySql delete_session error: {e}"))
            })?;
        Ok(())
    }
}
