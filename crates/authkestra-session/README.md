# authkestra-session

Session management and persistence for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides a flexible session persistence layer with support for multiple backends including SQL (Postgres, MySQL, SQLite) and Redis.

## Features

- `Session` and `SessionStore` traits for abstract session management.
- **SQL Store**: Support for Postgres, MySQL, and SQLite via `sqlx`.
- **Redis Store**: Session persistence using Redis with automatic TTL.
- **In-memory Store**: Lightweight store for testing and development.
- **Async Support**: Built on `async-trait` for seamless integration with async runtimes.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-session = { version = "0.1.1", features = ["sqlite"] }
```

### Feature Flags

- `store-redis`: Enables Redis support.
- `store-sqlx`: Enables SQL support (base for postgres/mysql/sqlite).
- `postgres`: Enables PostgreSQL support via `sqlx`.
- `mysql`: Enables MySQL support via `sqlx`.
- `sqlite`: Enables SQLite support via `sqlx`.

## Usage

### In-Memory Store

Ideal for testing or development.

```rust
use authkestra_session::{MemoryStore, SessionStore};

let store = MemoryStore::new();
```

### Redis Store

Requires the `store-redis` feature.

```rust
use authkestra_session::RedisStore;

// redis_url, prefix
let store = RedisStore::new("redis://127.0.0.1/", "authkestra_session".to_string())?;
```

### SQL Session Store

Requires one of `postgres`, `mysql`, or `sqlite` features.

```rust
use authkestra_session::SqlSessionStore;
use sqlx::SqlitePool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePool::connect("sqlite::memory:").await?;
    
    // Uses default table name "authkestra_sessions"
    let store = SqlSessionStore::new(pool);
    
    // Or with a custom table name
    // let store = SqlSessionStore::with_table_name(pool, "my_sessions".to_string());
    
    Ok(())
}
```

## Working with Sessions

The `SessionStore` trait provides methods to manage sessions.

```rust
use authkestra_session::{Session, SessionStore};
use authkestra_core::Identity;
use chrono::{Utc, Duration};
use std::collections::HashMap;

async fn manage_session<S: SessionStore>(store: S) -> Result<(), Box<dyn std::error::Error>> {
    let session = Session {
        id: "session_123".to_string(),
        identity: Identity {
            provider_id: "github".to_string(),
            external_id: "user_888".to_string(),
            email: Some("user@example.com".to_string()),
            username: Some("rust_dev".to_string()),
            attributes: HashMap::new(),
        },
        expires_at: Utc::now() + Duration::hours(24),
    };

    // Save a session
    store.save_session(&session).await?;

    // Load a session
    if let Some(loaded) = store.load_session("session_123").await? {
        println!("Loaded session for: {:?}", loaded.identity.username);
    }

    // Delete a session
    store.delete_session("session_123").await?;

    Ok(())
}
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
