use authkestra_core::strategy::Authenticator;
use authkestra_flow::{Authkestra, Missing};
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
pub struct AuthkestraState<S = Missing, T = Missing> {
    pub authkestra: Authkestra<S, T>,
}

impl<S, T> From<Authkestra<S, T>> for AuthkestraState<S, T> {
    fn from(authkestra: Authkestra<S, T>) -> Self {
        Self { authkestra }
    }
}

impl<S: Clone, T: Clone> FromRef<AuthkestraState<S, T>> for Authkestra<S, T> {
    fn from_ref(state: &AuthkestraState<S, T>) -> Self {
        state.authkestra.clone()
    }
}

impl<S, T> FromRef<AuthkestraState<S, T>> for Result<Arc<dyn SessionStore>, AuthkestraAxumError>
where
    S: authkestra_flow::SessionStoreState,
{
    fn from_ref(state: &AuthkestraState<S, T>) -> Self {
        Ok(state.authkestra.session_store.get_store())
    }
}

impl<S, T> FromRef<AuthkestraState<S, T>> for SessionConfig {
    fn from_ref(state: &AuthkestraState<S, T>) -> Self {
        state.authkestra.session_config.clone()
    }
}

impl<S, T> FromRef<AuthkestraState<S, T>> for Result<Arc<TokenManager>, AuthkestraAxumError>
where
    T: authkestra_flow::TokenManagerState,
{
    fn from_ref(state: &AuthkestraState<S, T>) -> Self {
        Ok(state.authkestra.token_manager.get_manager())
    }
}

/// The extractor for a validated session.
pub struct AuthSession(pub Session);

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Result<Arc<dyn SessionStore>, AuthkestraAxumError>: FromRef<S>,
    SessionConfig: FromRef<S>,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session_store = <Result<Arc<dyn SessionStore>, AuthkestraAxumError>>::from_ref(state)?;
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
    Result<Arc<TokenManager>, AuthkestraAxumError>: FromRef<S>,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token_manager = <Result<Arc<TokenManager>, AuthkestraAxumError>>::from_ref(state)?;
        let token = helpers::get_token(parts, &token_manager).await?;
        Ok(AuthToken(token))
    }
}

/// A generic JWT extractor for resource server validation.
///
/// Validates a Bearer token against a configured `JwksCache` and `JwtValidation`.
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

/// A unified extractor for authentication.
///
/// It uses the `Authenticator` from the application state to validate the request.
pub struct Auth<I>(pub I);

impl<S, I> FromRequestParts<S> for Auth<I>
where
    S: Send + Sync,
    Arc<Authenticator<I>>: FromRef<S>,
    I: Send + Sync + 'static,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let authenticator = Arc::<Authenticator<I>>::from_ref(state);
        match authenticator.authenticate(parts).await {
            Ok(Some(identity)) => Ok(Auth(identity)),
            Ok(None) => Err(AuthkestraAxumError::Unauthorized("Authentication failed".to_string())),
            Err(e) => Err(AuthkestraAxumError::Internal(e.to_string())),
        }
    }
}

pub trait AuthkestraAxumExt<S, T> {
    fn axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Authkestra<S, T>: FromRef<AppState>,
        SessionConfig: FromRef<AppState>,
        Result<Arc<dyn SessionStore>, AuthkestraAxumError>: FromRef<AppState>;
}

impl<S: Clone + Send + Sync + 'static, T: Clone + Send + Sync + 'static> AuthkestraAxumExt<S, T>
    for Authkestra<S, T>
{
    fn axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Authkestra<S, T>: FromRef<AppState>,
        SessionConfig: FromRef<AppState>,
        Result<Arc<dyn SessionStore>, AuthkestraAxumError>: FromRef<AppState>,
    {
        use axum::routing::get;
        axum::Router::new()
            .route(
                "/auth/{provider}",
                get(helpers::axum_login_handler::<AppState, S, T>),
            )
            .route(
                "/auth/{provider}/callback",
                get(helpers::axum_callback_handler::<AppState, S, T>),
            )
            .route(
                "/auth/logout",
                get(helpers::axum_logout_handler::<AppState, S, T>),
            )
    }
}
