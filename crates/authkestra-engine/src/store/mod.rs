use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Internal store error: {0}")]
    Internal(String),
    #[error("Not found")]
    NotFound,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[async_trait]
pub trait KvStore<T>: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError>;
    async fn set(&self, key: &str, value: T, ttl: Duration) -> Result<(), StoreError>;
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
}

#[async_trait]
pub trait Repository<T, ID>: Send + Sync + 'static {
    async fn find_by_id(&self, id: &ID) -> Result<Option<T>, StoreError>;
    async fn save(&self, entity: &T) -> Result<(), StoreError>;
    async fn delete(&self, id: &ID) -> Result<(), StoreError>;
}

#[cfg(feature = "memory")]
pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
pub mod sql;
