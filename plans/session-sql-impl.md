# Implementation Plan: SQL Session Store for `authly-session`

This plan outlines the steps to add SQL support to `authly-session` using `sqlx`.

## 1. Dependency Management (`authly-session/Cargo.toml`)

We need to make `redis` optional and add `sqlx` as an optional dependency with feature flags.

**Action**: Update `authly-session/Cargo.toml`:

```toml
[features]
default = []
store-redis = ["dep:redis"]
store-sqlx = ["dep:sqlx"]
postgres = ["store-sqlx", "sqlx/postgres"]
mysql = ["store-sqlx", "sqlx/mysql"]
sqlite = ["store-sqlx", "sqlx/sqlite"]

[dependencies]
# ... existing ...
redis = { version = "0.25", features = ["tokio-comp"], optional = true }
sqlx = { version = "0.8", features = ["runtime-tokio", "chrono", "tls-native-tls"], default-features = false, optional = true }
```

## 2. Refactor `lib.rs` (`authly-session/src/lib.rs`)

We need to conditionally include the stores based on features.

**Action**:
- Add `#[cfg(feature = "store-redis")]` to `RedisStore`.
- Add module declaration for `sql_store`:
  ```rust
  #[cfg(feature = "store-sqlx")]
  pub mod sql_store;
  
  #[cfg(feature = "store-sqlx")]
  pub use sql_store::SqlStore;
  ```

## 3. Implement SQL Store (`authly-session/src/sql_store.rs`)

Create a new file `authly-session/src/sql_store.rs`.

**Struct Definition**:
```rust
use authly_core::{AuthError, Identity};
use crate::{Session, SessionStore};
use async_trait::async_trait;
use sqlx::Database;

#[derive(Clone, Debug)]
pub struct SqlStore<DB: Database> {
    pool: sqlx::Pool<DB>,
    table_name: String,
}

impl<DB: Database> SqlStore<DB> {
    pub fn new(pool: sqlx::Pool<DB>) -> Self {
        Self {
            pool,
            table_name: "authly_sessions".to_string(),
        }
    }
}
```

**Schema**:
The implementation assumes the following table structure (create this in migration/docs):
```sql
CREATE TABLE authly_sessions (
    id VARCHAR(128) PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL -- or TIMESTAMPTZ / INTEGER based on DB
);
```

**Implementations**:

We need separate implementations for `Postgres`, `MySql`, and `Sqlite` to handle specific SQL syntax (mainly UPSERT).

**Example for Postgres**:
```rust
#[cfg(feature = "postgres")]
#[async_trait]
impl SessionStore for SqlStore<sqlx::Postgres> {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        let query = format!("SELECT data FROM {} WHERE id = $1 AND expires_at > $2", self.table_name);
        
        // Execute query, map error, deserialize data
        // ...
    }
    
    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        let query = format!(
            "INSERT INTO {} (id, data, expires_at) VALUES ($1, $2, $3) 
             ON CONFLICT(id) DO UPDATE SET data = $2, expires_at = $3",
            self.table_name
        );
        // ...
    }
    
    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
         let query = format!("DELETE FROM {} WHERE id = $1", self.table_name);
         // ...
    }
}
```

Repeat for `Sqlite` (similar `ON CONFLICT`) and `MySql` (`ON DUPLICATE KEY UPDATE`).

## 4. Update Documentation (`TECHNICAL_DESIGN.md`)

Update the "Session" section to include the SQL schema and usage examples.

## 5. Verification
- Run `cargo check --features postgres`
- Run `cargo check --features sqlite`
- Run `cargo check --features mysql`
