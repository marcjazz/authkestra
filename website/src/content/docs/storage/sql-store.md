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

### Upgrading a hand-managed schema to `authkestra-op` 0.7

0.7 added RFC 9449 DPoP refresh-token continuity and RFC 7523 `private_key_jwt` client
authentication, which need three new, nullable columns. `SqlxOpStore`'s `find_client` and
`store_token` reference these columns unconditionally — **not** only when you call `migrate()` —
so if you provision the schema yourself, upgrading to 0.7 without adding them breaks every
token request against your existing tables. If you call `migrate()`, it adds them for you
(idempotently, safe to run against a pre-0.7 database); this section is only for a schema you
create and evolve outside of it.

```sql
-- Postgres
ALTER TABLE authkestra.oauth_refresh_tokens ADD COLUMN IF NOT EXISTS jkt VARCHAR(255);
ALTER TABLE authkestra.oauth_clients ADD COLUMN IF NOT EXISTS token_endpoint_auth_method JSONB;
ALTER TABLE authkestra.oauth_clients ADD COLUMN IF NOT EXISTS jwks JSONB;
```

```sql
-- SQLite (no ADD COLUMN IF NOT EXISTS — skip a statement if the column is already there)
ALTER TABLE authkestra_oauth_refresh_tokens ADD COLUMN jkt TEXT;
ALTER TABLE authkestra_oauth_clients ADD COLUMN token_endpoint_auth_method TEXT;
ALTER TABLE authkestra_oauth_clients ADD COLUMN jwks TEXT;
```

```sql
-- MySQL (no ADD COLUMN IF NOT EXISTS across commonly-deployed versions — same caveat as SQLite)
ALTER TABLE authkestra_oauth_refresh_tokens ADD COLUMN jkt VARCHAR(255);
ALTER TABLE authkestra_oauth_clients ADD COLUMN token_endpoint_auth_method JSON;
ALTER TABLE authkestra_oauth_clients ADD COLUMN jwks JSON;
```

All three are nullable and additive: existing rows simply have `NULL` in them, read back as
`jkt: None` / `token_endpoint_auth_method: None` / `jwks: None`, exactly as if the client or
refresh token predates this release.

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
