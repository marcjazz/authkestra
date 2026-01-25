# authly-session

Session management and persistence for `authly-rs`.

## Features

- `Session` and `SessionStore` traits.
- **SQL Store**: Support for Postgres, MySQL, and SQLite via `sqlx`.
- **Redis Store**: Session persistence using Redis.
- **In-memory Store**: Lightweight store for testing and development.

## Usage

### SQL Store

Enable the desired backend feature in your `Cargo.toml`:

```toml
[dependencies]
authly-session = { version = "0.1", features = ["postgres"] }
```

Then initialize the store:

```rust
use authly_session::SqlSessionStore;
use sqlx::PgPool;

let pool = PgPool::connect("postgres://...").await?;
let store = SqlSessionStore::new(pool);
```
