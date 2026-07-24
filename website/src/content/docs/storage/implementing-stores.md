---
title: Implementing Stores
description: How to write a custom store for Authkestra and prevent TOCTOU races.
---

Implementing a custom store means implementing the `KvStore` trait and its critical atomicity variants.

## The KvStore Interface

Authkestra relies heavily on the generic `KvStore` interface for mapping keys to values.

```rust
use async_trait::async_trait;
use authkestra_engine::store::{KvStore, StoreError};
use std::time::Duration;

pub struct MyRedisStore {
    client: redis::Client,
}

#[async_trait]
impl<V: Send + Sync + 'static> KvStore<V> for MyRedisStore {
    async fn get(&self, key: &str) -> Result<Option<V>, StoreError> {
        // Fetch from redis, deserialize, and return
        Ok(None)
    }

    async fn set(&self, key: &str, value: V, ttl: Duration) -> Result<(), StoreError> {
        // Serialize and save to redis with TTL
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        // Delete from redis
        Ok(())
    }
}
```

> [!CAUTION]
> **Atomicity Requirements**
> While `KvStore` handles basic storage, many operations in OAuth2 require strict atomicity to prevent Time-of-Check to Time-of-Use (TOCTOU) race conditions. For example, Authorization Codes and Device Codes MUST be single-use. If two parallel requests try to exchange the same code, only one must succeed.

To enforce this, you MUST also implement `AtomicConsume<T>` and `IndexedKvStore<T>` to provide atomic operations at the database layer.

## AtomicConsume

Any store used for one-time-use items (like Authorization Codes or PKCE states) must implement `AtomicConsume`. The `consume()` method must atomically fetch the value and delete it in a single transaction or atomic command.

```rust
use authkestra_engine::store::AtomicConsume;

#[async_trait]
impl<V: Send + Sync + 'static> AtomicConsume<V> for MyRedisStore {
    async fn consume(&self, key: &str) -> Result<Option<V>, StoreError> {
        // MUST BE ATOMIC. E.g., in Redis, use a Lua script or GETDEL.
        // In SQL, use `DELETE FROM ... RETURNING *`.
        // DO NOT implement this as a manual get() followed by a delete()!
        Ok(None)
    }
}
```

## IndexedKvStore

For items that need to be looked up by a secondary index (like Refresh Tokens which are looked up by token string but stored under a primary session ID), you must implement `IndexedKvStore`.

```rust
use authkestra_engine::store::IndexedKvStore;

#[async_trait]
impl<V: Send + Sync + 'static> IndexedKvStore<V> for MyRedisStore {
    async fn set_indexed(
        &self,
        primary_key: &str,
        secondary_key: &str,
        value: V,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        // Atomically set the primary key AND the secondary index
        Ok(())
    }

    async fn get_by_index(&self, secondary_key: &str) -> Result<Option<V>, StoreError> {
        // Lookup via secondary index
        Ok(None)
    }
}
```

## Performance: Trait Objects

For I/O bound paths (like talking to a database), Authkestra uses dynamic dispatch (e.g. `Arc<dyn SessionStore>`) rather than generics. This prevents code bloat, dramatically speeds up compile times, and ensures your engine type remains clean and simple.
