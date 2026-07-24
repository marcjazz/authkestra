---
title: Implementing Stores
description: How to write a custom store for Authkestra.
---

Implementing a custom store is as simple as implementing the `SessionStore` (or `KvStore`) traits.

## Custom Store Example

Authkestra relies heavily on the generic `KvStore` interface for mapping keys to values (such as sessions).

```rust
use async_trait::async_trait;
use authkestra_engine::store::KvStore;
use authkestra_engine::AuthError;
use std::time::Duration;

pub struct MyRedisStore {
    client: redis::Client,
}

#[async_trait]
impl<V: Send + Sync + serde::Serialize + serde::de::DeserializeOwned> KvStore<V> for MyRedisStore {
    async fn get(&self, key: &str) -> Option<V> {
        // Fetch from redis, deserialize, and return
        None
    }

    async fn set(&self, key: &str, value: V, ttl: Duration) -> Result<(), AuthError> {
        // Serialize and save to redis with TTL
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), AuthError> {
        // Delete from redis
        Ok(())
    }
}
```

## Performance: Trait Objects

For I/O bound paths (like talking to a database), Authkestra uses dynamic dispatch (e.g. `Arc<dyn SessionStore>`) rather than generics. This prevents code bloat, dramatically speeds up compile times, and ensures your engine type remains clean and simple.
