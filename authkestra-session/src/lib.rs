pub use authkestra_engine::auth::{
    AuthError, Identity, SameSite, Session, SessionConfig, SessionStore,
};

#[cfg(feature = "sqlx-store")]
pub mod sql;

#[cfg(feature = "sqlx-store")]
pub use sql::{SqlSessionStore, SqlStore};

#[cfg(feature = "redis-store")]
pub mod redis;

#[cfg(feature = "redis-store")]
pub use redis::RedisStore;

pub mod memory;
pub use memory::MemoryStore;
