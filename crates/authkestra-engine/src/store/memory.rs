use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::store::{AtomicConsume, AtomicInsert, IndexedKvStore, KvStore, StoreError};
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
#[non_exhaustive]
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

#[cfg(test)]
impl<T> MemoryStore<T> {
    /// Test-only introspection: the number of entries currently held,
    /// expired or not. Used to prove `insert_if_absent`'s opportunistic
    /// sweep actually shrinks the map, not just that expired entries are
    /// unreachable through the public API.
    fn len(&self) -> usize {
        self.data.lock().unwrap().len()
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
impl<T: Clone + Send + Sync + 'static> AtomicInsert<T> for MemoryStore<T> {
    #[tracing::instrument(skip(self, value))]
    async fn insert_if_absent(
        &self,
        key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        tracing::debug!(key = %key, "atomically inserting into memory store if absent");
        // Held for the whole check-then-insert: this single lock is what
        // makes the operation atomic, exactly like `consume`'s single
        // `remove` call above.
        let mut data = self.data.lock().unwrap();
        // `get`/`consume` each self-heal by removing an expired entry the
        // next time *that same key* is looked up — but `insert_if_absent`
        // is also used for insert-only key spaces (a DPoP proof's `jti`,
        // unique per proof) where no later call ever revisits the same
        // key. Without this sweep, such an entry would sit expired-but-
        // present forever: nothing else would ever touch its key to
        // trigger the removal, leaking one entry per call for the life of
        // the process. Piggybacking the sweep on every insert instead
        // bounds this store's size by roughly the insert rate over one
        // TTL window, not by total inserts ever made.
        data.retain(|_, entry| !entry.is_expired());
        if data.contains_key(key) {
            return Ok(false);
        }
        data.insert(
            key.to_string(),
            StoreEntry {
                value,
                expires_at: Some(Instant::now() + ttl),
            },
        );
        Ok(true)
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
    async fn test_insert_if_absent_first_call_succeeds() {
        let store = MemoryStore::<String>::new();

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(inserted);
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_insert_if_absent_second_call_fails_and_keeps_the_first_value() {
        let store = MemoryStore::<String>::new();

        assert!(store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap());

        // A second insert under the same key — the replay case — must be
        // rejected, and must not clobber the value the first insert wrote.
        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!inserted_again);
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_insert_if_absent_allows_reuse_after_expiry() {
        let store = MemoryStore::<String>::new();

        store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_millis(10))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;

        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(inserted_again);
        assert_eq!(store.get("key1").await.unwrap(), Some("value2".to_string()));
    }

    /// `insert_if_absent` is the only primitive an insert-only key space
    /// (e.g. a DPoP proof's `jti`, unique per proof) ever calls — nothing
    /// ever revisits the same key the way `get`/`consume` are revisited for
    /// server-issued values. Without an opportunistic sweep, an expired
    /// entry under a never-repeated key would sit in the map forever,
    /// leaking one entry per call for the life of the process. This proves
    /// the map's size actually shrinks, not just that expired entries are
    /// unreachable through `get`.
    #[tokio::test]
    async fn test_insert_if_absent_reclaims_expired_entries_under_other_keys() {
        let store = MemoryStore::<String>::new();

        for i in 0..50 {
            store
                .insert_if_absent(
                    &format!("jti-{i}"),
                    "spent".to_string(),
                    Duration::from_millis(10),
                )
                .await
                .unwrap();
        }
        assert_eq!(store.len(), 50);

        tokio::time::sleep(Duration::from_millis(20)).await;

        // A single insert under a brand-new key must sweep every expired
        // entry from the previous batch, even though none of their keys
        // are ever looked up again.
        store
            .insert_if_absent("jti-new", "spent".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            store.len(),
            1,
            "expired insert-only entries under other keys must be swept, not retained forever"
        );
    }

    /// The property the whole replay-guard feature depends on: under real
    /// concurrency, two racing inserts of the same key must never both
    /// report success.
    #[tokio::test]
    async fn test_insert_if_absent_is_atomic_under_concurrency() {
        let store = Arc::new(MemoryStore::<u32>::new());
        let mut handles = Vec::new();
        for i in 0..50u32 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store
                    .insert_if_absent("shared-key", i, Duration::from_secs(10))
                    .await
                    .unwrap()
            }));
        }

        let mut successes = 0;
        for handle in handles {
            if handle.await.unwrap() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1, "exactly one racing insert must win");
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
