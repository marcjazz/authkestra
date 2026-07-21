use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use crate::store::{KvStore, StoreError};

/// An in-memory implementation of [`KvStore`].
///
/// **Note**: This store is not persistent and will be cleared when the application restarts.
/// It is primarily intended for development and testing.
#[derive(Clone)]
pub struct MemoryStore<T> {
    data: Arc<Mutex<HashMap<String, T>>>,
}

impl<T> Default for MemoryStore<T> {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<T> MemoryStore<T> {
    /// Create a new, empty `MemoryStore`.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl<T: Clone + Send + Sync + 'static> KvStore<T> for MemoryStore<T> {
    #[tracing::instrument(skip(self))]
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "loading from memory store");
        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    #[tracing::instrument(skip(self, value), fields(key = %key))]
    async fn set(&self, key: &str, value: T, _ttl: Duration) -> Result<(), StoreError> {
        tracing::debug!("saving to memory store");
        self.data.lock().unwrap().insert(key.to_string(), value);
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        tracing::debug!(key = %key, "deleting from memory store");
        self.data.lock().unwrap().remove(key);
        Ok(())
    }
}
