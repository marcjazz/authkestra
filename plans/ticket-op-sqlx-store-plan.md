# Ticket Plan: Native SqlxOpStore Implementation

## Goal
Implement a native, batteries-included SQL implementation of the OpenID Provider (`OpStore`) using `sqlx`. While `SqlKvStore` exists for generic JSON blob persistence across the framework, the OpenID Provider requires highly opinionated, normalized SQL tables with proper relational foreign keys, `ON DELETE CASCADE` constraints, and strictly defined columns (like `client_id`, `scopes`, `expires_at`).

## Status: Done

## Context & Motivation
- Authkestra philosophy: "Authkestra is Database Agnostic... use our batteries-included SQL presets to get started in 5 minutes."
- Using standard relational schemas instead of JSON KV blobs enables powerful analytical queries, manual debugging, and stronger data integrity.
- Postgres requires multiple commands within a single migration to use `sqlx::Executor::execute` rather than `sqlx::query` to bypass prepared statement limitations.

## Implementation Steps
1. **Define Schema**: Create relational tables for OP entities (`oauth_clients`, `oauth_codes`, `oauth_refresh_tokens`, `oauth_device_codes`) with cascading deletes.
2. **`SqlxOpStore` Generic Struct**: Define `SqlxOpStore<DB: sqlx::Database>` which natively implements the four core OP traits (`ClientStore`, `AuthorizationCodeStore`, `RefreshTokenStore`, `DeviceCodeStore`).
3. **Macro Deduplication**: Use `impl_opstore_sql!` macro to generate backend-specific `migrate()` functions and dialact-specific parameter binding (e.g. `$1` vs `?`) for Postgres, MySQL, and SQLite.
4. **Integration Tests**: Set up `testcontainers` and `testcontainers-modules` to boot up a real Postgres instance to verify migrations and `ON DELETE CASCADE` integrity.
5. **Examples & Documentation**: 
   - Add `axum_op_server_sqlx` and `actix_op_server_sqlx` examples.
   - Update `docs/storage/overview.md` to introduce the new native OP store.

## DoD (Definition of Done)
- `SqlxOpStore` cleanly implements `OpStore`.
- `cargo test --features sqlx-postgres` passes with actual containers.
- Framework adapters (Axum/Actix) examples are updated to feature the new implementation.
- Documentation accurately reflects the existence and use-cases of the opinionated tables.
