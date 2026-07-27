---
title: Storage Overview
description: Understanding Authkestra's database-agnostic design.
---

Authkestra is entirely **Database Agnostic**. We never enforce database schemas, migrations, or ORM choices.

## The Trait-Based Approach

All data persistence is defined through simple Rust traits. For example, to manage sessions, the engine relies on the `SessionStore` trait:

```rust
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, id: &str) -> Option<Session>;
    async fn set(&self, session: Session) -> Result<(), AuthError>;
    async fn delete(&self, id: &str) -> Result<(), AuthError>;
}
```

Because this is a trait, you can implement it using `sqlx`, `diesel`, `redis`, or a simple in-memory `HashMap`.

## Included Stores

Authkestra comes with a few generic implementations out of the box for convenience. To use them, you must enable the corresponding feature flags in your `Cargo.toml`:

```toml
[dependencies]
# Example: Using Redis and SQLite stores
authkestra = { version = "0.2.3", features = ["redis", "sql-sqlite"] }
```

The available built-in stores and their feature flags are:
- **Memory Store**: `authkestra_engine::store::memory::MemoryStore` (Great for testing and local dev; enabled by the `memory` feature).
- **Redis Store**: `authkestra_engine::store::redis::RedisStore` (Production-ready distributed cache; enabled by the `redis` feature).
- **Generic SQL KV Store**: `authkestra_engine::store::sql::SqlKvStore` (Relational JSON blob persistence; enabled by `sql-postgres`, `sql-mysql`, or `sql-sqlite` features).

## OpenID Provider (OP) Storage

If you are building an OpenID Provider using `authkestra-op`, you can use the traits: `ClientStore`, `AuthorizationCodeStore`, `RefreshTokenStore`, and `DeviceCodeStore`.

To simplify building OPs, Authkestra provides a batteries-included **native SQL** implementation: `authkestra_op::sqlx_store::SqlxOpStore`. 

Unlike the generic `SqlKvStore` which stores JSON blobs, `SqlxOpStore` provides highly opinionated, normalized SQL tables with proper relational foreign keys, `ON DELETE CASCADE` constraints, and strictly defined columns (like `client_id`, `scopes`, `expires_at`).

To use it, enable the respective feature flag:
```toml
[dependencies]
authkestra-op = { version = "0.2.3", features = ["sqlx-postgres"] }
# or sqlx-mysql, sqlx-sqlite
```
