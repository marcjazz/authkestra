use async_trait::async_trait;
use authkestra_core::error::AuthError;
use redis::AsyncCommands;

use crate::{Session, SessionStore};

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
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Session(format!("Redis connection error: {}", e)))?;

        let data: Option<String> = conn
            .get(self.key(id))
            .await
            .map_err(|e| AuthError::Session(format!("Redis get error: {}", e)))?;

        match data {
            Some(json) => {
                let session: Session = serde_json::from_str(&json).map_err(|e| {
                    AuthError::Session(format!("Session deserialization error: {}", e))
                })?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Session(format!("Redis connection error: {}", e)))?;

        let json = serde_json::to_string(session)
            .map_err(|e| AuthError::Session(format!("Session serialization error: {}", e)))?;

        let ttl = (session.expires_at - chrono::Utc::now()).num_seconds();
        if ttl <= 0 {
            return Ok(());
        }

        let _: () = conn
            .set_ex(self.key(&session.id), json, ttl as u64)
            .await
            .map_err(|e| AuthError::Session(format!("Redis set error: {}", e)))?;

        Ok(())
    }

    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AuthError::Session(format!("Redis connection error: {}", e)))?;

        let _: () = conn
            .del(self.key(id))
            .await
            .map_err(|e| AuthError::Session(format!("Redis del error: {}", e)))?;

        Ok(())
    }
}
