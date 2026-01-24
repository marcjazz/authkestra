use async_trait::async_trait;
use authly_core::{Identity, AuthError};
use serde::{Deserialize, Serialize};

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
