use async_trait::async_trait;
use crate::store::{KvStore, StoreError};
use redis::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

pub struct RedisStore {
    client: redis::Client,
    prefix: String,
}

impl RedisStore {
    pub fn new(redis_url: &str, prefix: String) -> Result<Self, StoreError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| StoreError::Internal(format!("Failed to open redis client: {e}")))?;
        Ok(Self { client, prefix })
    }

    fn key(&self, id: &str) -> String {
        format!("{prefix}:{id}", prefix = self.prefix)
    }
}

#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T> for RedisStore {
    #[tracing::instrument(skip(self))]
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "loading from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let data: Option<String> = conn.get(self.key(key)).await.map_err(|e| {
            tracing::error!(error = %e, "Redis get error");
            StoreError::Internal(format!("Redis get error: {e}"))
        })?;

        match data {
            Some(json) => {
                let entity: T = serde_json::from_str(&json).map_err(|e| {
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
        tracing::debug!("saving to redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let json = serde_json::to_string(&value).map_err(|e| {
            tracing::error!(error = %e, "Serialization error");
            StoreError::Serialization(format!("Serialization error: {e}"))
        })?;

        let ttl_secs = ttl.as_secs();
        if ttl_secs == 0 {
            tracing::warn!("ttl is 0, not saving to redis");
            return Ok(());
        }

        let _: () = conn
            .set_ex(self.key(key), json, ttl_secs)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis set error");
                StoreError::Internal(format!("Redis set error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        tracing::debug!(key = %key, "deleting from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let _: () = conn.del(self.key(key)).await.map_err(|e| {
            tracing::error!(error = %e, "Redis del error");
            StoreError::Internal(format!("Redis del error: {e}"))
        })?;

        Ok(())
    }
}
