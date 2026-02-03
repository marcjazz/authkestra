pub use authkestra_core::{Session, SessionConfig, SessionStore};
pub use authkestra_flow::Authkestra;
use authkestra_token::TokenManager;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use std::sync::Arc;
pub use tower_cookies::cookie::SameSite;
pub use tower_cookies::Cookie;
use tower_cookies::Cookies;

pub mod helpers;

pub use helpers::*;

#[derive(Clone)]
pub struct AuthkestraState {
    pub authkestra: Authkestra,
}

impl From<Authkestra> for AuthkestraState {
    fn from(authkestra: Authkestra) -> Self {
        Self { authkestra }
    }
}

impl FromRef<AuthkestraState> for Authkestra {
    fn from_ref(state: &AuthkestraState) -> Self {
        state.authkestra.clone()
    }
}

impl FromRef<AuthkestraState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AuthkestraState) -> Self {
        state.authkestra.session_store.clone()
    }
}

impl FromRef<AuthkestraState> for SessionConfig {
    fn from_ref(state: &AuthkestraState) -> Self {
        state.authkestra.session_config.clone()
    }
}

impl FromRef<AuthkestraState> for Arc<TokenManager> {
    fn from_ref(state: &AuthkestraState) -> Self {
        state.authkestra.token_manager.clone()
    }
}

/// The extractor for a validated session.
pub struct AuthSession(pub Session);

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Arc<dyn SessionStore>: FromRef<S>,
    SessionConfig: FromRef<S>,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session_store = Arc::<dyn SessionStore>::from_ref(state);
        let session_config = SessionConfig::from_ref(state);
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|e| AuthkestraAxumError::Internal(e.1.to_string()))?;

        let session = helpers::get_session(&session_store, &session_config, &cookies).await?;

        Ok(AuthSession(session))
    }
}

/// The extractor for a validated JWT.
///
/// Expects an `Authorization: Bearer <token>` header.
pub struct AuthToken(pub authkestra_token::Claims);

impl<S> FromRequestParts<S> for AuthToken
where
    S: Send + Sync,
    Arc<TokenManager>: FromRef<S>,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token_manager = Arc::<TokenManager>::from_ref(state);
        let token = helpers::get_token(parts, &token_manager).await?;
        Ok(AuthToken(token))
    }
}

/// A generic JWT extractor for resource server validation.
///
/// Validates a Bearer token against a configured `JwksCache` and `jsonwebtoken::Validation`.
pub struct Jwt<T>(pub T);

impl<S, T> FromRequestParts<S> for Jwt<T>
where
    S: Send + Sync,
    Arc<authkestra_token::offline_validation::JwksCache>: FromRef<S>,
    jsonwebtoken::Validation: FromRef<S>,
    T: for<'de> serde::Deserialize<'de> + 'static,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let cache = Arc::<authkestra_token::offline_validation::JwksCache>::from_ref(state);
        let validation = jsonwebtoken::Validation::from_ref(state);

        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                AuthkestraAxumError::Unauthorized("Missing Authorization header".to_string())
            })?;

        if !auth_header.starts_with("Bearer ") {
            return Err(AuthkestraAxumError::Unauthorized(
                "Invalid Authorization header".to_string(),
            ));
        }

        let token = &auth_header[7..];
        let claims = authkestra_token::offline_validation::validate_jwt_generic::<T>(
            token,
            &cache,
            &validation,
        )
        .await
        .map_err(|e| AuthkestraAxumError::Unauthorized(format!("Invalid token: {}", e)))?;

        Ok(Jwt(claims))
    }
}

pub trait AuthkestraAxumExt {
    fn axum_router<S>(&self) -> axum::Router<S>
    where
        S: Clone + Send + Sync + 'static,
        Authkestra: FromRef<S>,
        SessionConfig: FromRef<S>,
        Arc<dyn SessionStore>: FromRef<S>;
}

impl AuthkestraAxumExt for Authkestra {
    fn axum_router<S>(&self) -> axum::Router<S>
    where
        S: Clone + Send + Sync + 'static,
        Authkestra: FromRef<S>,
        SessionConfig: FromRef<S>,
        Arc<dyn SessionStore>: FromRef<S>,
    {
        use axum::routing::get;
        axum::Router::new()
            .route("/auth/{provider}", get(helpers::axum_login_handler::<S>))
            .route(
                "/auth/{provider}/callback",
                get(helpers::axum_callback_handler::<S>),
            )
            .route("/auth/logout", get(helpers::axum_logout_handler::<S>))
    }
}
