use async_trait::async_trait;
use authkestra_engine::auth::{AuthError, Session, SessionStore};
use redis::AsyncCommands;

pub struct RedisStore {
    client: redis::Client,
    prefix: String,
}

impl RedisStore {
    pub fn new(redis_url: &str, prefix: String) -> Result<Self, AuthError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| AuthError::Session(format!("Failed to open redis client: {e}")))?;
        Ok(Self { client, prefix })
    }

    fn key(&self, id: &str) -> String {
        format!("{prefix}:{id}", prefix = self.prefix)
    }
}

#[async_trait]
impl SessionStore for RedisStore {
    #[tracing::instrument(skip(self))]
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        tracing::debug!(session_id = %id, "loading session from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                AuthError::Session(format!("Redis connection error: {e}"))
            })?;

        let data: Option<String> = conn.get(self.key(id)).await.map_err(|e| {
            tracing::error!(error = %e, "Redis get error");
            AuthError::Session(format!("Redis get error: {e}"))
        })?;

        match data {
            Some(json) => {
                let session: Session = serde_json::from_str(&json).map_err(|e| {
                    tracing::error!(error = %e, "Session deserialization error");
                    AuthError::Session(format!("Session deserialization error: {e}"))
                })?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self, session), fields(session_id = %session.id))]
    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        tracing::debug!("saving session to redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                AuthError::Session(format!("Redis connection error: {e}"))
            })?;

        let json = serde_json::to_string(session).map_err(|e| {
            tracing::error!(error = %e, "Session serialization error");
            AuthError::Session(format!("Session serialization error: {e}"))
        })?;

        let ttl = (session.expires_at - chrono::Utc::now()).num_seconds();
        if ttl <= 0 {
            tracing::warn!("session already expired, not saving to redis");
            return Ok(());
        }

        let _: () = conn
            .set_ex(self.key(&session.id), json, ttl as u64)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis set error");
                AuthError::Session(format!("Redis set error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        tracing::debug!(session_id = %id, "deleting session from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                AuthError::Session(format!("Redis connection error: {e}"))
            })?;

        let _: () = conn.del(self.key(id)).await.map_err(|e| {
            tracing::error!(error = %e, "Redis del error");
            AuthError::Session(format!("Redis del error: {e}"))
        })?;

        Ok(())
    }
}
