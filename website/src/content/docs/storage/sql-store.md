---
title: OP SQL Store
description: Opinionated SQL relational persistence for building an OpenID Provider (OP).
---

If you are building an OpenID Provider (OP) using `authkestra-op`, you can implement the storage traits (`ClientStore`, `AuthorizationCodeStore`, `RefreshTokenStore`, and `DeviceCodeStore`) however you prefer.

However, to simplify building OPs, Authkestra provides a batteries-included **native SQL** implementation in a separate crate: `authkestra_store_sqlx::SqlxOpStore`. It lives outside `authkestra-op` so that core has zero `sqlx` dependency — you only pull in `sqlx` (and its Postgres/MySQL/SQLite driver) if you actually want SQL-backed storage.

## Opinionated Relational Schema

Unlike the generic [SqlKvStore](/storage/kv-store) which stores opaque JSON blobs, `SqlxOpStore` provides highly opinionated, normalized SQL tables with proper relational foreign keys, `ON DELETE CASCADE` constraints, and strictly defined columns (like `client_id`, `scopes`, `expires_at`).

This allows you to easily query your OAuth clients, see exactly which users have active refresh tokens, and manage authorization codes directly via standard SQL queries in your dashboard or admin tools.

## Enabling the Feature

To use it, add the `authkestra-store-sqlx` crate and enable the feature for the backend you want:

```toml
[dependencies]
authkestra-store-sqlx = { version = "0.6", features = ["postgres"] }
# or mysql, sqlite
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
authentication, which need three new, nullable columns **and one new table** (`oauth_dpop_jti`,
which backs DPoP proof replay tracking per RFC 9449 §11.1 — without it every DPoP request is
refused). `SqlxOpStore`'s `find_client` and
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

The replay table has no foreign key to `oauth_clients`: a DPoP `jti` is client-generated and
checked before the grant is dispatched, so it is not owned by a client row and must not be
cascade-deleted with one.

```sql
-- Postgres
CREATE TABLE IF NOT EXISTS authkestra.oauth_dpop_jti (
    jti VARCHAR(255) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

-- SQLite
CREATE TABLE IF NOT EXISTS authkestra_oauth_dpop_jti (
    jti TEXT PRIMARY KEY,
    expires_at DATETIME NOT NULL
);

-- MySQL: DATETIME(3), not DATETIME. MySQL rounds a plain DATETIME to whole
-- seconds, which would both hold a jti past its window and make the
-- expired-row reclaim compare against a rounded value.
CREATE TABLE IF NOT EXISTS authkestra_oauth_dpop_jti (
    jti VARCHAR(255) PRIMARY KEY,
    expires_at DATETIME(3) NOT NULL
);
```

Rows are self-expiring in the logical sense — a `jti` whose `expires_at` has passed is reclaimed
in place by the next proof that happens to reuse it — but nothing sweeps the table, so a busy OP
accumulates one row per distinct proof. Prune it on whatever schedule suits you:
`DELETE FROM ... WHERE expires_at <= now()`. Deleting a not-yet-expired row re-opens the replay
window for that proof's remaining lifetime.

```sql
-- MySQL (no ADD COLUMN IF NOT EXISTS across commonly-deployed versions — same caveat as SQLite)
ALTER TABLE authkestra_oauth_refresh_tokens ADD COLUMN jkt VARCHAR(255);
ALTER TABLE authkestra_oauth_clients ADD COLUMN token_endpoint_auth_method JSON;
ALTER TABLE authkestra_oauth_clients ADD COLUMN jwks JSON;
```

All three columns are nullable and additive: existing rows simply have `NULL` in them, read back
as `jkt: None` / `token_endpoint_auth_method: None` / `jwks: None`, exactly as if the client or
refresh token predates this release.

**`token_endpoint_auth_method` and `jwks` hold JSON, not bare text.** `find_client` decodes both
through `sqlx`'s `Json` type and — deliberately — returns a storage error rather than silently
falling back to `None` when a non-`NULL` value fails to decode, because `None` means "no client
authentication configured". On Postgres and MySQL the `JSONB`/`JSON` column type rejects a
malformed value at `INSERT` time; on SQLite the column is plain `TEXT` and will accept anything,
so the mistake only surfaces later, as a `500` on every authorize and token request for that
client.

`token_endpoint_auth_method` is a JSON **string**, so it must carry its quotes, and its value is
one of `"client_secret_basic"`, `"client_secret_post"`, `"private_key_jwt"`, or `"none"`:

```sql
-- correct
UPDATE authkestra_oauth_clients SET token_endpoint_auth_method = '"private_key_jwt"' WHERE client_id = 'my-client';
-- WRONG: not valid JSON — every lookup of this client now fails with a storage error
UPDATE authkestra_oauth_clients SET token_endpoint_auth_method = 'private_key_jwt' WHERE client_id = 'my-client';
-- WRONG: valid JSON, but not a method this release models — also a storage error, by design
UPDATE authkestra_oauth_clients SET token_endpoint_auth_method = '"client_secret_jwt"' WHERE client_id = 'my-client';
```

`jwks` is the client's JWK Set **object**, exactly as RFC 7517 §5 defines it — `{"keys": [ ... ]}`,
not a bare array and not a URL:

```sql
-- correct
UPDATE authkestra_oauth_clients SET jwks = '{"keys":[{"kty":"EC","crv":"P-256","x":"...","y":"...","kid":"k1"}]}' WHERE client_id = 'my-client';
-- WRONG: bare array, missing the "keys" wrapper
UPDATE authkestra_oauth_clients SET jwks = '[{"kty":"EC","crv":"P-256","x":"...","y":"..."}]' WHERE client_id = 'my-client';
```

### Initialization & Migration

Once connected to your pool, initialize the store and run the built-in migration:

```rust
use authkestra_store_sqlx::SqlxOpStore;
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
