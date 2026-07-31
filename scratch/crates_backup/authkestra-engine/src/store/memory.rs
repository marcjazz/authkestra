use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::store::{AtomicConsume, IndexedKvStore, KvStore, StoreError};
use async_trait::async_trait;

struct StoreEntry<T> {
    value: T,
    expires_at: Option<Instant>,
}

impl<T> StoreEntry<T> {
    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() >= expires_at
        } else {
            false
        }
    }
}

/// An in-memory implementation of [`KvStore`].
///
/// **Note**: This store is not persistent and will be cleared when the application restarts.
/// It is primarily intended for development and testing.
#[derive(Clone)]
pub struct MemoryStore<T> {
    data: Arc<Mutex<HashMap<String, StoreEntry<T>>>>,
    indices: Arc<Mutex<HashMap<String, String>>>,
}

impl<T> Default for MemoryStore<T> {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            indices: Arc::new(Mutex::new(HashMap::new())),
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
        let mut data = self.data.lock().unwrap();

        if let Some(entry) = data.get(key) {
            if entry.is_expired() {
                data.remove(key);
                return Ok(None);
            }
            return Ok(Some(entry.value.clone()));
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self, value), fields(key = %key))]
    async fn set(&self, key: &str, value: T, ttl: Duration) -> Result<(), StoreError> {
        tracing::debug!("saving to memory store");
        let entry = StoreEntry {
            value,
            expires_at: Some(Instant::now() + ttl),
        };
        self.data.lock().unwrap().insert(key.to_string(), entry);
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        tracing::debug!(key = %key, "deleting from memory store");
        self.data.lock().unwrap().remove(key);
        Ok(())
    }
}

#[async_trait]
impl<T: Clone + Send + Sync + 'static> AtomicConsume<T> for MemoryStore<T> {
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "atomically consuming from memory store");
        let mut data = self.data.lock().unwrap();
        if let Some(entry) = data.remove(key) {
            if entry.is_expired() {
                return Ok(None);
            }
            return Ok(Some(entry.value));
        }
        Ok(None)
    }
}

#[async_trait]
impl<T: Clone + Send + Sync + 'static> IndexedKvStore<T> for MemoryStore<T> {
    async fn set_indexed(
        &self,
        primary_key: &str,
        secondary_key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        tracing::debug!("saving indexed record to memory store");
        let entry = StoreEntry {
            value,
            expires_at: Some(Instant::now() + ttl),
        };
        let mut data = self.data.lock().unwrap();
        let mut indices = self.indices.lock().unwrap();

        data.insert(primary_key.to_string(), entry);
        indices.insert(secondary_key.to_string(), primary_key.to_string());

        Ok(())
    }

    async fn get_by_index(&self, secondary_key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(secondary_key = %secondary_key, "loading by index from memory store");
        let primary_key_opt = {
            let indices = self.indices.lock().unwrap();
            indices.get(secondary_key).cloned()
        };

        if let Some(primary_key) = primary_key_opt {
            let mut data = self.data.lock().unwrap();
            if let Some(entry) = data.get(&primary_key) {
                if entry.is_expired() {
                    data.remove(&primary_key);
                    // Also cleanup index opportunistically
                    self.indices.lock().unwrap().remove(secondary_key);
                    return Ok(None);
                }
                return Ok(Some(entry.value.clone()));
            } else {
                // Orphaned index pointer cleanup
                self.indices.lock().unwrap().remove(secondary_key);
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_get_set_delete() {
        let store = MemoryStore::<String>::new();

        assert_eq!(store.get("key1").await.unwrap(), None);

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

        store.delete("key1").await.unwrap();
        assert_eq!(store.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let store = MemoryStore::<String>::new();

        store
            .set("key1", "value1".to_string(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(store.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_atomic_consume() {
        let store = MemoryStore::<String>::new();

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        // Consume returns the value and deletes it
        let value = store.consume("key1").await.unwrap();
        assert_eq!(value, Some("value1".to_string()));

        // Second consume returns None
        let value2 = store.consume("key1").await.unwrap();
        assert_eq!(value2, None);
    }

    #[tokio::test]
    async fn test_indexed_store() {
        let store = MemoryStore::<String>::new();

        store
            .set_indexed("pk1", "sk1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        // Get by primary key
        assert_eq!(store.get("pk1").await.unwrap(), Some("value1".to_string()));

        // Get by index
        assert_eq!(
            store.get_by_index("sk1").await.unwrap(),
            Some("value1".to_string())
        );

        // Consume primary key cleans up entry
        let _ = store.consume("pk1").await.unwrap();

        // Next get by index should return None (and internally clean up the orphaned index)
        assert_eq!(store.get_by_index("sk1").await.unwrap(), None);
    }
}
