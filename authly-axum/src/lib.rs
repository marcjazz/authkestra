use async_trait::async_trait;
use authly_session::{Session, SessionStore};
use authly_token::TokenManager;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, StatusCode},
};
use std::sync::Arc;
pub use tower_cookies::cookie::SameSite;
pub use tower_cookies::Cookie;
use tower_cookies::Cookies;

pub mod helpers;

pub use helpers::*;

#[derive(Clone)]
pub struct AuthlyState {
    pub store: Arc<dyn SessionStore>,
    pub config: SessionConfig,
}

impl FromRef<AuthlyState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AuthlyState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AuthlyState> for SessionConfig {
    fn from_ref(state: &AuthlyState) -> Self {
        state.config.clone()
    }
}

/// The extractor for a validated session.
pub struct AuthSession(pub Session);

#[async_trait]
impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Arc<dyn SessionStore>: FromRef<S>,
    SessionConfig: FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = Arc::from_ref(state);
        let config = SessionConfig::from_ref(state);

        let cookies = <Cookies as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Cookies error".to_string()))?;

        let session_id = cookies
            .get(&config.cookie_name)
            .map(|c: Cookie| c.value().to_string())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing session cookie".to_string()))?;

        let session = store
            .load_session(&session_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

        Ok(AuthSession(session))
    }
}

/// The extractor for a validated JWT.
///
/// Expects an `Authorization: Bearer <token>` header.
pub struct AuthToken(pub authly_core::Identity);

#[async_trait]
impl<S> FromRequestParts<S> for AuthToken
where
    S: Send + Sync,
    Arc<TokenManager>: FromRef<S>,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token_manager = Arc::from_ref(state);

        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED, "Invalid Authorization header".to_string()));
        }

        let token = &auth_header[7..];
        let identity = token_manager
            .validate_token(token)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e)))?;

        Ok(AuthToken(identity))
    }
}
