use crate::client_assertion::ClientAssertionStore;
use crate::error::OpError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// A Redis-backed store for client assertions to prevent replay attacks.
#[derive(Clone)]
pub struct RedisClientAssertionStore {
    client: redis::Client,
    prefix: String,
}

impl RedisClientAssertionStore {
    /// Creates a new RedisClientAssertionStore from a redis URL and a key prefix.
    pub fn new(redis_url: &str, prefix: String) -> Result<Self, OpError> {
        let client = redis::Client::open(redis_url).map_err(|e| {
            tracing::error!("Failed to open redis client: {e}");
            OpError::Storage
        })?;
        Ok(Self { client, prefix })
    }

    /// Creates a new RedisClientAssertionStore from an existing redis client and a key prefix.
    pub fn with_client(client: redis::Client, prefix: String) -> Self {
        Self { client, prefix }
    }

    fn key(&self, jti: &str) -> String {
        format!("{prefix}:{jti}", prefix = self.prefix)
    }
}

#[async_trait]
impl ClientAssertionStore for RedisClientAssertionStore {
    async fn record_jti(&self, jti: &str, expires_at: DateTime<Utc>) -> Result<bool, OpError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                OpError::Storage
            })?;

        let now = Utc::now();
        if expires_at <= now {
            return Ok(false);
        }
        let ttl_secs = (expires_at - now).num_seconds().max(1) as u64;

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
                OpError::Storage
            })?;

        // If res is Some("OK"), it means SET NX succeeded (the JTI is new).
        Ok(res.is_some())
    }
}
