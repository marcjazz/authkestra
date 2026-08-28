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
authkestra-op = { version = "0.6", features = ["sqlx-postgres"] }
# or sqlx-mysql, sqlx-sqlite
```

## Setup Differences (SQL Store vs KV Store)

The generic KV store creates a single `authkestra_kv` table; `SqlxOpStore` instead owns a set of
normalized tables with foreign keys between them. Neither runs its migration for you on
connection — both expose an idempotent `migrate()` you call once at startup.

If you would rather manage the OP schema with your own migration runner (`sqlx-cli`, `refinery`,
or hand-written SQL), skip `migrate()` and create the tables yourself; the store issues plain
queries against them and does not track a migration version of its own.

### Initialization & Migration

Once connected to your pool, initialize the store and run the built-in migration:

```rust
use authkestra_op::sqlx_store::SqlxOpStore;
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new().connect("postgres://user:pass@localhost/db").await?;

// Initialize the store
let op_store = SqlxOpStore::new(pool);

// Create the OP tables if they do not already exist. Idempotent.
op_store.migrate().await?;
```

You then pass this `op_store` to `Op::builder().store(...)` (see
[`authkestra_op::OpBuilder`](/advanced/op-server)) for client, code, and token storage. A
runnable version lives in the repository:

```bash
cargo run -p authkestra --example axum_op_server_sqlx --all-features
```
