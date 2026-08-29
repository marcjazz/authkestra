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

/// Backends that can atomically fetch-and-remove a value implement this.
#[async_trait]
pub trait AtomicConsume<T>: KvStore<T> {
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError>;
}

/// Backends that can atomically insert a value only if no value is
/// currently stored under `key` implement this.
///
/// This is the complement of [`AtomicConsume`], not a duplicate of it:
/// `AtomicConsume` is for values the *server* creates and later atomically
/// fetches-and-removes (an authorization code, say — the key is only ever
/// seen after this server put it there). `AtomicInsert` is for values whose
/// key is supplied by the *caller* and was never stored by this server
/// first — the shape a replay guard needs, e.g. a DPoP proof's `jti`, which
/// a client generates and this server has never seen before the first time
/// it's presented.
#[async_trait]
pub trait AtomicInsert<T>: KvStore<T> {
    /// Inserts `value` under `key` only if `key` does not already hold a
    /// value. Returns `Ok(true)` if the insert happened (the key was
    /// fresh) and `Ok(false)` if a value was already present (the key was
    /// already claimed — e.g. a replay). Must be a single atomic
    /// operation: a check-then-set built from `get` followed by `set` is a
    /// TOCTOU race that defeats the entire purpose of a replay guard.
    async fn insert_if_absent(
        &self,
        key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<bool, StoreError>;
}

/// Backends that can atomically write a value under a primary key while
/// also maintaining a secondary lookup key implement this.
#[async_trait]
pub trait IndexedKvStore<T>: KvStore<T> {
    async fn set_indexed(
        &self,
        primary_key: &str,
        secondary_key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError>;
    async fn get_by_index(&self, secondary_key: &str) -> Result<Option<T>, StoreError>;
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
