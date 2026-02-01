use async_trait::async_trait;
pub use authly_core::{AuthError, Identity, Session, SessionStore};

use std::collections::HashMap;
use std::sync::Mutex;

#[cfg(feature = "store-sqlx")]
pub mod sql_store;

#[cfg(feature = "store-sqlx")]
pub use sql_store::{SqlSessionStore, SqlStore};

#[cfg(feature = "store-redis")]
pub mod redis_store;

#[cfg(feature = "store-redis")]
pub use redis_store::RedisStore;

pub use authly_core::MemoryStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store() {
        let store = MemoryStore::default();
        let session = Session {
            id: "test_id".to_string(),
            identity: Identity {
                provider_id: "test".to_string(),
                external_id: "123".to_string(),
                email: None,
                username: None,
                attributes: HashMap::new(),
            },
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        store.save_session(&session).await.unwrap();
        let loaded = store.load_session("test_id").await.unwrap().unwrap();
        assert_eq!(loaded.id, "test_id");

        store.delete_session("test_id").await.unwrap();
        let loaded = store.load_session("test_id").await.unwrap();
        assert!(loaded.is_none());
    }
}
