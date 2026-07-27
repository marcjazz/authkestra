---
title: Storage Overview
description: Understanding Authkestra's database-agnostic design and storage options.
---

Authkestra is entirely **Database Agnostic**. We never enforce database schemas, migrations, or ORM choices for the core library.

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

Authkestra comes with a few generic implementations out of the box for convenience. To use them, you must enable the corresponding feature flags in your `Cargo.toml`.

There are two primary paradigms for built-in storage in Authkestra:

1. **[KV Stores](/storage/kv-store)**: General-purpose Key-Value persistence used by the main `authkestra-engine`. This includes the Memory Store, Redis Store, and a generic SQL KV Store that serializes data as JSON blobs.
2. **[SQL Stores](/storage/sql-store)**: Highly opinionated, normalized relational SQL tables designed specifically for building an OpenID Provider (OP) via `authkestra-op`.

Continue reading to explore how to set up the [KV Store](/storage/kv-store) for typical setups, or the specialized [SQL Store](/storage/sql-store) for building your own OP. Or, if you have unique infrastructure needs, learn how to [Implement Custom Stores](/storage/implementing-stores).
