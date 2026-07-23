use crate::store::{KvStore, StoreError};
use async_trait::async_trait;
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

use crate::store::{AtomicConsume, IndexedKvStore};

#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> AtomicConsume<T> for RedisStore {
    #[tracing::instrument(skip(self))]
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "atomically consuming from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let script = redis::Script::new(
            r#"
            local val = redis.call('GET', KEYS[1])
            if val then
                redis.call('DEL', KEYS[1])
            end
            return val
            "#,
        );

        let data: Option<String> = script
            .key(self.key(key))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis get/del script error");
                StoreError::Internal(format!("Redis get/del script error: {e}"))
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
}

impl RedisStore {
    fn index_key(&self, index: &str) -> String {
        format!("{prefix}:idx:{index}", prefix = self.prefix)
    }
}

#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> IndexedKvStore<T> for RedisStore {
    #[tracing::instrument(skip(self, value), fields(key = %key, index = %index))]
    async fn set_indexed(
        &self,
        key: &str,
        index: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        tracing::debug!("saving indexed to redis store");
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

        let mut pipe = redis::pipe();
        pipe.atomic().set_ex(self.key(key), json, ttl_secs).set_ex(
            self.index_key(index),
            key.to_string(),
            ttl_secs,
        );

        let _: () = pipe.query_async(&mut conn).await.map_err(|e| {
            tracing::error!(error = %e, "Redis set_indexed error");
            StoreError::Internal(format!("Redis set_indexed error: {e}"))
        })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_index(&self, index: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(index = %index, "loading by index from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let rel_key: Option<String> = conn.get(self.index_key(index)).await.map_err(|e| {
            tracing::error!(error = %e, "Redis index get error");
            StoreError::Internal(format!("Redis index get error: {e}"))
        })?;

        if let Some(key) = rel_key {
            let res = self.get(&key).await;
            if let Ok(None) = res {
                // Orphaned index, clean it up optionally
                let _: () = conn.del(self.index_key(index)).await.unwrap_or(());
            }
            res
        } else {
            Ok(None)
        }
    }
}

#[cfg(all(test, feature = "redis"))]
mod tests {
    use super::*;
    use crate::store::{KvStore, AtomicConsume, IndexedKvStore};
    use std::time::Duration;
    use testcontainers::{runners::AsyncRunner, ContainerAsync};
    use testcontainers_modules::redis::Redis;

    async fn setup_redis() -> (RedisStore, ContainerAsync<Redis>) {
        let container = Redis::default().start().await.unwrap();
        let port = container.get_host_port_ipv4(6379).await.unwrap();
        let url = format!("redis://127.0.0.1:{}", port);
        
        let store = RedisStore::new(&url, "test_prefix".to_string()).unwrap();
        (store, container)
    }

    #[tokio::test]
    async fn test_redis_get_set_delete() {
        let (store, _c) = setup_redis().await;

        let res: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res, None);

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        
        let res_some: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res_some, Some("value1".to_string()));

        KvStore::<String>::delete(&store, "key1").await.unwrap();
        let res_del: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res_del, None);
    }

    #[tokio::test]
    async fn test_redis_atomic_consume() {
        let (store, _c) = setup_redis().await;

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
    async fn test_redis_indexed_store() {
        let (store, _c) = setup_redis().await;

        store
            .set_indexed("pk1", "sk1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let pk_res: Option<String> = store.get("pk1").await.unwrap();
        assert_eq!(pk_res, Some("value1".to_string()));
        
        let sk_res: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res, Some("value1".to_string()));

        // Delete primary key manually
        KvStore::<String>::delete(&store, "pk1").await.unwrap();
        
        // This should return None and clean up the orphaned index
        let sk_res2: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res2, None);
    }
}
