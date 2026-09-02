---
title: KV Stores
description: General-purpose Key-Value persistence for Authkestra.
---

KV Stores (Key-Value) are the primary way `authkestra-engine` persists session data and state. Because Authkestra treats most runtime structures as opaque blobs for storage, a Key-Value approach is perfectly sufficient for 99% of web applications.

## Available Implementations

Authkestra includes a few generic KV stores. The store implementations and their feature flags
live on `authkestra-engine` — the `authkestra` facade does not re-export `memory`/`redis`/`sql-*`
as features of its own, so depend on the engine directly for these:

```toml
[dependencies]
authkestra = { version = "0.7", features = ["axum", "session"] }
# Example: Using Redis and SQLite KV stores
authkestra-engine = { version = "0.7", features = ["session", "redis", "sql-sqlite"] }
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

### 3. Generic SQL KV Store (`sql-postgres`, `sql-mysql`, `sql-sqlite`)

If you want to use a relational database but still leverage the simplicity of a KV interface, the `SqlKvStore` serializes data as JSON blobs into a simple SQL table.

This is useful if you already have a Postgres, MySQL, or SQLite database running and want to avoid introducing Redis to your infrastructure for **generic session storage**.

:::warning
`SqlKvStore` is **deprecated for OP-specific data** (OAuth clients, authorization codes, refresh tokens, device codes). If you are building an OpenID Provider, use [`SqlxOpStore`](/storage/sql-store) instead — it provides a normalized relational schema with proper foreign keys and `ON DELETE CASCADE`. `SqlKvStore` remains a valid option for session storage when Redis is not available.
:::

```rust
use authkestra_engine::store::sql::SqlKvStore;
use sqlx::sqlite::SqlitePoolOptions;

let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await?;

let store = SqlKvStore::new(pool);
// `migrate()` issues `CREATE TABLE IF NOT EXISTS` for the KV table and its
// expiry index. It is not run for you — call it once at startup.
store.migrate().await?;
```

The table defaults to `authkestra_kv`; use `SqlKvStore::with_table_name(pool, name)` to point it
somewhere else.

## Setup Differences (KV vs SQL Store)

`SqlKvStore` uses a single generic schema (a key column, a JSON blob value column, and an
expiry), and its `migrate()` call is idempotent — so "run migrations" here means one
`store.migrate().await?` at startup rather than a managed migration history.

This differs significantly from the specialized **[SQL Store](/storage/sql-store)** used in `authkestra-op`, which provides a proper normalized relational schema.
