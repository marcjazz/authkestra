#[cfg(feature = "flow")]
pub use authkestra_flow::{Authkestra, Missing, SessionConfig};
#[cfg(feature = "guard")]
pub use authkestra_guard::AuthkestraGuard;
#[cfg(feature = "token")]
pub use authkestra_token::TokenManager;
use axum::extract::FromRef;
#[cfg(feature = "session")]
use axum::extract::FromRequestParts;
#[cfg(any(feature = "session", feature = "token", feature = "guard"))]
use std::sync::Arc;

pub mod helpers;

pub use helpers::*;

#[cfg(feature = "macros")]
extern crate self as authkestra_axum;

#[cfg(feature = "macros")]
pub use authkestra_macros::AuthkestraFromRef;

#[derive(Clone, AuthkestraFromRef)]
pub struct AuthkestraState<S = Missing, T = Missing> {
    #[authkestra]
    pub authkestra: Authkestra<S, T>,
}

impl<S, T> From<Authkestra<S, T>> for AuthkestraState<S, T> {
    fn from(authkestra: Authkestra<S, T>) -> Self {
        Self { authkestra }
    }
}

/// The extractor for a validated session.
pub struct AuthSession(pub Session);

#[cfg(feature = "session")]
impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Result<Arc<dyn SessionStore>, AuthkestraAxumError>: FromRef<S>,
    SessionConfig: FromRef<S>,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        use tower_cookies::Cookies;
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
#[cfg(feature = "token")]
pub struct AuthToken(pub authkestra_token::Claims);

#[cfg(feature = "token")]
impl<S> FromRequestParts<S> for AuthToken
where
    S: Send + Sync,
    Result<Arc<TokenManager>, AuthkestraAxumError>: FromRef<S>,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let token_manager = <Result<Arc<TokenManager>, AuthkestraAxumError>>::from_ref(state)?;
        let token = helpers::get_token(parts, &token_manager).await?;
        Ok(AuthToken(token))
    }
}

/// A generic JWT extractor for resource server validation.
///
/// Validates a Bearer token against a configured `JwksCache` and `JwtValidation`.
#[cfg(feature = "guard")]
pub struct Jwt<T>(pub T);

#[cfg(feature = "guard")]
impl<S, T> FromRequestParts<S> for Jwt<T>
where
    S: Send + Sync,
    Arc<authkestra_guard::jwt::JwksCache>: FromRef<S>,
    jsonwebtoken::Validation: FromRef<S>,
    T: for<'de> serde::Deserialize<'de> + 'static,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let cache = Arc::<authkestra_guard::jwt::JwksCache>::from_ref(state);
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
        let claims = authkestra_guard::jwt::validate_jwt_generic::<T>(token, &cache, &validation)
            .await
            .map_err(|e| AuthkestraAxumError::Unauthorized(format!("Invalid token: {e}")))?;

        Ok(Jwt(claims))
    }
}

/// A unified extractor for authentication.
///
/// It uses the `AuthkestraGuard` from the application state to validate the request.
#[cfg(feature = "guard")]
pub struct Auth<I>(pub I);

#[cfg(feature = "guard")]
impl<S, I> FromRequestParts<S> for Auth<I>
where
    S: Send + Sync,
    Arc<AuthkestraGuard<I>>: FromRef<S>,
    I: Send + Sync + 'static,
{
    type Rejection = AuthkestraAxumError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let guard = Arc::<AuthkestraGuard<I>>::from_ref(state);
        match guard.authenticate(parts).await {
            Ok(Some(identity)) => Ok(Auth(identity)),
            Ok(None) => Err(AuthkestraAxumError::Unauthorized(
                "Authentication failed".to_string(),
            )),
            Err(e) => Err(AuthkestraAxumError::Internal(e.to_string())),
        }
    }
}

#[cfg(all(feature = "flow", feature = "session"))]
pub trait AuthkestraAxumExt<S, T> {
    fn axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Authkestra<S, T>: FromRef<AppState>,
        SessionConfig: FromRef<AppState>,
        Result<Arc<dyn SessionStore>, AuthkestraAxumError>: FromRef<AppState>;
}

#[cfg(all(feature = "flow", feature = "session"))]
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
