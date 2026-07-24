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

Authkestra comes with a few implementations out of the box for convenience:
- `authkestra_engine::store::memory::MemoryStore` (Great for testing and local dev)
