use crate::auth::error::AuthError;
use crate::auth::state::Identity;
use crate::auth::SameSite;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Configuration for session cookies.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The name of the session cookie.
    pub cookie_name: String,
    /// Whether the cookie should only be sent over HTTPS.
    pub secure: bool,
    /// Whether the cookie should be inaccessible to client-side scripts.
    pub http_only: bool,
    /// The `SameSite` attribute for the cookie.
    pub same_site: SameSite,
    /// The path for which the cookie is valid.
    pub path: String,
    /// The maximum age of the session.
    pub max_age: Option<chrono::Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: "authkestra_session".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age: Some(chrono::Duration::hours(24)),
        }
    }
}

/// Represents an active user session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier.
    pub id: String,
    /// The identity associated with this session.
    pub identity: Identity,
    /// When the session expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Trait for implementing session persistence.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// Load a session by its ID.
    async fn load_session(&self, id: &str) -> Result<Option<Session>, AuthError>;
    /// Save or update a session.
    async fn save_session(&self, session: &Session) -> Result<(), AuthError>;
    /// Delete a session by its ID.
    async fn delete_session(&self, id: &str) -> Result<(), AuthError>;
}
