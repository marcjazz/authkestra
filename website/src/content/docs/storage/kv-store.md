---
title: KV Stores
description: General-purpose Key-Value persistence for Authkestra.
---

KV Stores (Key-Value) are the primary way `authkestra-engine` persists session data and state. Because Authkestra treats most runtime structures as opaque blobs for storage, a Key-Value approach is perfectly sufficient for 99% of web applications.

## Available Implementations

Authkestra includes a few generic KV stores. Enable the required feature flags to use them:

```toml
[dependencies]
# Example: Using Redis and SQLite KV stores
authkestra = { version = "0.2.5", features = ["redis", "sql-sqlite"] }
```

### 1. Memory Store (`memory`)

Great for testing and local development. Data is stored entirely in memory and is lost on restart.

```rust
use authkestra_engine::store::memory::MemoryStore;

let store = MemoryStore::new();
```

### 2. Redis Store (`redis`)

A production-ready distributed cache utilizing `redis` and `mobc` for connection pooling.

```rust
use authkestra_engine::store::redis::RedisStore;

let store = RedisStore::new("redis://127.0.0.1:6379/").await?;
```

### 3. Generic SQL KV Store (`sql-postgres`, `sql-mysql`, `sql-sqlite`)

If you want to use a relational database but still leverage the simplicity of a KV interface, the `SqlKvStore` serializes data as JSON blobs into a simple SQL table.

This is useful if you already have a Postgres, MySQL, or SQLite database running and want to avoid introducing Redis to your infrastructure for **generic session storage**.

> [!WARNING]
> `SqlKvStore` is **deprecated for OP-specific data** (OAuth clients, authorization codes, refresh tokens, device codes). If you are building an OpenID Provider, use [`SqlxOpStore`](/storage/sql-store) instead — it provides a normalized relational schema with proper foreign keys and `ON DELETE CASCADE`. `SqlKvStore` remains a valid option for session storage when Redis is not available.

```rust
use authkestra_engine::store::sql::SqlKvStore;
use sqlx::sqlite::SqlitePoolOptions;

let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await?;

// The SqlKvStore will automatically create the necessary `authkestra_kv`
// table if it does not already exist.
let store = SqlKvStore::new(pool);
store.migrate().await?;
```

## Setup Differences (KV vs SQL Store)

When initializing a `SqlKvStore`, the table is automatically managed for you using a simple generic schema (typically a `key` column and a `value` JSON blob column). You do not need to manually run migrations.

This differs significantly from the specialized **[SQL Store](/storage/sql-store)** used in `authkestra-op`, which provides a proper normalized relational schema.
