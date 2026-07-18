use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use authkestra_engine::auth::{AuthError, Session, SessionStore};

/// An in-memory implementation of [`SessionStore`].
///
/// **Note**: This store is not persistent and will be cleared when the application restarts.
/// It is primarily intended for development and testing.
#[derive(Default, Clone)]
pub struct MemoryStore {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl MemoryStore {
    /// Create a new, empty `MemoryStore`.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    #[tracing::instrument(skip(self))]
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError> {
        tracing::debug!(session_id = %id, "loading session from memory store");
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }
    #[tracing::instrument(skip(self, session), fields(session_id = %session.id))]
    async fn save_session(&self, session: &Session) -> Result<(), AuthError> {
        tracing::debug!("saving session to memory store");
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id.clone(), session.clone());
        Ok(())
    }
    #[tracing::instrument(skip(self))]
    async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        tracing::debug!(session_id = %id, "deleting session from memory store");
        self.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_engine::auth::Identity;
    use std::collections::HashMap;

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
