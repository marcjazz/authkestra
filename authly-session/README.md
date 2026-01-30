# authly-session

Session management and persistence for [authly-rs](https://github.com/marcorichetta/authly-rs).

This crate provides a flexible session persistence layer with support for multiple backends including SQL (Postgres, MySQL, SQLite) and Redis.

## Features

- `Session` and `SessionStore` traits.
- **SQL Store**: Support for Postgres, MySQL, and SQLite via `sqlx`.
- **Redis Store**: Session persistence using Redis.
- **In-memory Store**: Lightweight store for testing and development.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-session = { version = "0.1.0", features = ["sqlite"] }
```

### Example: SQLite Session Store

```rust
use authly_session::SqlSessionStore;
use sqlx::SqlitePool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePool::connect("sqlite::memory:").await?;
    let store = SqlSessionStore::new(pool);
    
    // Use the store...
    Ok(())
}
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcorichetta/authly-rs) workspace.
