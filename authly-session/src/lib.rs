use async_trait::async_trait;
use authly_core::{Identity, AuthError};
use serde::{Deserialize, Serialize};
use redis::AsyncCommands;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub identity: Identity,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError>;
    async fn save_session(&self, session: &Session) -> Result<(), AuthError>;
    async fn delete_session(&self, id: &str) -> Result<(), AuthError>;
}

pub struct RedisStore {
    client: redis::Client,
    prefix: String,
}

impl RedisStore {
    pub fn new(redis_url: &str, prefix: String) -> Result<Self, AuthError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| AuthError::Session(format!("Failed to open redis client: {}", e)))?;
        Ok(Self { client, prefix })
    }

    fn key(&self, id: &str) -> String {
        format!("{}:{}", self.prefix, id)
    }
}

#[async_trait]
impl SessionStore for RedisStore {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Session(format!("Redis connection error: {}", e)))?;
        
        let data: Option<String> = conn.get(self.key(id))
            .await
            .map_err(|e| AuthError::Session(format!("Redis get error: {}", e)))?;

        match data {
            Some(json) => {
                let session: Session = serde_json::from_str(&json)
                    .map_err(|e| AuthError::Session(format!("Session deserialization error: {}", e)))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Session(format!("Redis connection error: {}", e)))?;

        let json = serde_json::to_string(session)
            .map_err(|e| AuthError::Session(format!("Session serialization error: {}", e)))?;

        let ttl = (session.expires_at - chrono::Utc::now()).num_seconds();
        if ttl <= 0 {
            return Ok(());
        }

        let _: () = conn.set_ex(self.key(&session.id), json, ttl as u64)
            .await
            .map_err(|e| AuthError::Session(format!("Redis set error: {}", e)))?;

        Ok(())
    }

    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        let mut conn = self.client.get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Session(format!("Redis connection error: {}", e)))?;

        let _: () = conn.del(self.key(id))
            .await
            .map_err(|e| AuthError::Session(format!("Redis del error: {}", e)))?;

        Ok(())
    }
}

use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct MemoryStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }
    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        self.sessions.lock().unwrap().insert(session.id.clone(), session.clone());
        Ok(())
    }
    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        self.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}

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
