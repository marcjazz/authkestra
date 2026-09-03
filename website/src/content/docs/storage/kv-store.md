---
title: KV Stores
description: General-purpose Key-Value persistence for Authkestra.
---

KV Stores (Key-Value) are the primary way `authkestra-engine` persists session data and state. Because Authkestra treats most runtime structures as opaque blobs for storage, a Key-Value approach is perfectly sufficient for 99% of web applications.

## Available Implementations

Authkestra includes a few generic KV stores. The store implementations and their feature flags
live on `authkestra-engine` — the `authkestra` facade does not re-export `memory`/`redis`
as features of its own, so depend on the engine directly for these:

```toml
[dependencies]
authkestra = { version = "0.7", features = ["axum", "session"] }
# Example: Using the Redis KV store
authkestra-engine = { version = "0.7", features = ["session", "redis"] }
```

### 1. Memory Store (`memory`)

Great for testing and local development. Data is stored entirely in memory and is lost on restart.

```rust
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::SessionStore;
use std::sync::Arc;

// `MemoryStore<T>` is generic; the `Arc<dyn SessionStore>` annotation picks
// `T = Session` via the blanket `KvStore<Session>` impl.
let store: Arc<dyn SessionStore> = Arc::new(MemoryStore::default());
```

### 2. Redis Store (`redis`)

A production-ready distributed cache backed by `redis`.

`RedisStore::new` is synchronous and takes a key prefix alongside the URL; the prefix namespaces
every key this store writes, so several stores can share one Redis instance without colliding.

```rust
use authkestra_engine::store::redis::RedisStore;

let store = RedisStore::new("redis://127.0.0.1:6379/", "session".to_string())?;
```

If you already hold an open `redis::Client`, prefer `RedisStore::with_client(client, prefix)` —
it lets several prefixed stores share one connection pool instead of opening a new one each.

If you'd rather use a relational database for generic KV/session storage, implement
`authkestra_engine::store::KvStore` directly against it — see the
**[SQL Store](/storage/sql-store)** page for the OP-specific relational store `authkestra-op`
ships, and `authkestra-example-seaorm`/`authkestra-example-diesel` in the repository for real,
compiled examples of a third-party ORM implementing storage traits from scratch.
