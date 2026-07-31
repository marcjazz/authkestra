---
title: OP SQL Store
description: Opinionated SQL relational persistence for building an OpenID Provider (OP).
---

If you are building an OpenID Provider (OP) using `authkestra-op`, you can implement the storage traits (`ClientStore`, `AuthorizationCodeStore`, `RefreshTokenStore`, and `DeviceCodeStore`) however you prefer.

However, to simplify building OPs, Authkestra provides a batteries-included **native SQL** implementation: `authkestra_op::sqlx_store::SqlxOpStore`.

## Opinionated Relational Schema

Unlike the generic [SqlKvStore](/storage/kv-store) which stores opaque JSON blobs, `SqlxOpStore` provides highly opinionated, normalized SQL tables with proper relational foreign keys, `ON DELETE CASCADE` constraints, and strictly defined columns (like `client_id`, `scopes`, `expires_at`).

This allows you to easily query your OAuth clients, see exactly which users have active refresh tokens, and manage authorization codes directly via standard SQL queries in your dashboard or admin tools.

## Enabling the Feature

To use it, enable the respective feature flag on the `authkestra-op` crate (or via the facade `authkestra` crate if you're using it):

```toml
[dependencies]
authkestra-op = { version = "0.2", features = ["sqlx-postgres"] }
# or sqlx-mysql, sqlx-sqlite
```

## Setup Differences (SQL Store vs KV Store)

Unlike the generic KV store that automatically initializes its single `authkestra_kv` table upon connection, the `SqlxOpStore` assumes you want strict control over your database schema and migrations.

Authkestra provides the required schema queries, but **it will not automatically run them for you** on connection. You can either run the migrations directly via code using `.migrate()`, or integrate the provided schema into your application's migration runner (e.g., `sqlx-cli`, `barrel`, or manually in a database console).

### 1. Extracting the Schema

You can obtain the necessary SQL schema string directly from the store at runtime, which is useful for logging or running in a setup script:

```rust
use authkestra_op::sqlx_store::SqlxOpStore;

// Prints the raw SQL needed to create all OP tables for Postgres
println!("{}", SqlxOpStore::<sqlx::Postgres>::schema());
```

### 2. Initialization & Migration

Once connected to your pool, you can initialize the store. Since migrations are not run automatically, you have the option of running them directly via code using `.migrate().await`:

```rust
use authkestra_op::sqlx_store::SqlxOpStore;
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new().connect("postgres://user:pass@localhost/db").await?;

// Initialize the store
let op_store = SqlxOpStore::new(pool);

// Optionally run the built-in migrations to ensure all tables exist
op_store.migrate().await?;
```

You can then pass this `op_store` into your `authkestra_op::OpBuilder` for client, code, and token storage.
