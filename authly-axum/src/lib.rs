use async_trait::async_trait;
use authly_session::{Session, SessionStore};
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
};
use std::sync::Arc;
use tower_cookies::Cookies;

/// The extractor for a validated session.
pub struct AuthSession(pub Session);

#[async_trait]
impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Arc<dyn SessionStore>: FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = Arc::from_ref(state);
        let cookies = <Cookies as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Cookies error".to_string()))?;

        let session_id = cookies
            .get("authly_session")
            .map(|c: tower_cookies::Cookie| c.value().to_string())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing session cookie".to_string()))?;

        let session = store
            .load_session(&session_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

        Ok(AuthSession(session))
    }
}
