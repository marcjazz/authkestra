use crate::client_assertion::ClientAssertionStore;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;

/// A Redis-backed store for client assertions to prevent replay attacks.
#[derive(Clone)]
#[non_exhaustive]
pub struct RedisClientAssertionStore {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisClientAssertionStore {
    /// Creates a new RedisClientAssertionStore from a redis URL and a key prefix.
    pub async fn new(
        redis_url: &str,
        prefix: String,
    ) -> Result<Self, authkestra_engine::store::StoreError> {
        let client = redis::Client::open(redis_url).map_err(|e| {
            tracing::error!(error = %e, "Failed to open redis client");
            authkestra_engine::store::StoreError::Internal("redis".into())
        })?;
        Self::with_client(client, prefix).await
    }

    /// Creates a new RedisClientAssertionStore from an existing redis client and a key prefix.
    pub async fn with_client(
        client: redis::Client,
        prefix: String,
    ) -> Result<Self, authkestra_engine::store::StoreError> {
        let conn = client.get_connection_manager().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to create Redis connection manager");
            authkestra_engine::store::StoreError::Internal("redis".into())
        })?;
        Ok(Self::with_connection_manager(conn, prefix))
    }

    /// Creates a new RedisClientAssertionStore from a pre-configured `ConnectionManager`.
    pub fn with_connection_manager(conn: ConnectionManager, prefix: String) -> Self {
        Self { conn, prefix }
    }

    fn key(&mut self, jti: &str) -> String {
        format!("{prefix}:{jti}", prefix = self.prefix)
    }
}

#[async_trait]
impl ClientAssertionStore for RedisClientAssertionStore {
    async fn record_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        let now = Utc::now();
        if expires_at <= now {
            tracing::debug!(jti = %jti, "Assertion is already expired; refusing without querying Redis");
            return Ok(false);
        }
        let ttl_secs = (expires_at - now).num_seconds().max(1) as u64;

        let mut conn = self.conn.clone();
        let res: Option<String> = redis::cmd("SET")
            .arg(self.key(jti))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis SET NX error");
                authkestra_engine::store::StoreError::Internal("redis".into())
            })?;

        // If res is Some("OK"), it means SET NX succeeded (the JTI is new).
        Ok(res.is_some())
    }
}
