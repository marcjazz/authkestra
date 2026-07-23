#[cfg(feature = "token")]
pub use authkestra_engine::TokenManager;
#[cfg(feature = "flow")]
pub use authkestra_engine::{AkBase, Missing, SessionConfig};
#[cfg(feature = "resource")]
pub use authkestra_resource::AkResourceGuard;
#[allow(unused_imports)]
use axum::extract::FromRef;
#[cfg(feature = "session")]
use axum::extract::FromRequestParts;
#[cfg(any(feature = "session", feature = "token", feature = "resource"))]
use std::sync::Arc;

pub mod helpers;

#[cfg(feature = "op")]
pub mod op;

pub use helpers::AkAxumError;
#[cfg(feature = "session")]
pub use helpers::{Session, SessionStore};

#[cfg(feature = "op")]
pub use op::AkAxumOpExt;

#[cfg(feature = "macros")]
extern crate self as authkestra_axum;

#[cfg(feature = "macros")]
pub use authkestra_macros::AuthkestraState;

#[cfg(feature = "flow")]
#[derive(Clone, AuthkestraState)]
pub struct AkState<S = Missing, T = Missing> {
    #[authkestra(engine)]
    pub authkestra: AkBase<S, T>,
}

#[cfg(feature = "flow")]
impl<S, T> From<AkBase<S, T>> for AkState<S, T> {
    fn from(authkestra: AkBase<S, T>) -> Self {
        Self { authkestra }
    }
}

/// The extractor for a validated session.
#[cfg(feature = "session")]
pub struct AuthSession(pub Session);

#[cfg(feature = "session")]
impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Result<Arc<dyn SessionStore>, AkAxumError>: FromRef<S>,
    SessionConfig: FromRef<S>,
{
    type Rejection = AkAxumError;

    #[tracing::instrument(skip_all)]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        use tower_cookies::Cookies;
        tracing::debug!("extracting AuthSession from request");
        let session_store = <Result<Arc<dyn SessionStore>, AkAxumError>>::from_ref(state)?;
        let session_config = SessionConfig::from_ref(state);
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|e| {
                tracing::error!(error = %e.1, "failed to extract cookies");
                AkAxumError::Internal(e.1.to_string())
            })?;

        let session = helpers::get_session(&session_store, &session_config, &cookies)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to get session from store");
                e
            })?;

        tracing::info!(session_id = %session.id, user_id = %session.identity.external_id, "successfully extracted AuthSession");
        Ok(AuthSession(session))
    }
}

/// The extractor for a validated JWT.
///
/// Expects an `Authorization: Bearer <token>` header.
#[cfg(feature = "token")]
pub struct AuthToken(pub authkestra_engine::Claims);

#[cfg(feature = "token")]
impl<S> FromRequestParts<S> for AuthToken
where
    S: Send + Sync,
    Result<Arc<TokenManager>, AkAxumError>: FromRef<S>,
{
    type Rejection = AkAxumError;

    #[tracing::instrument(skip_all)]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        tracing::debug!("extracting AuthToken from request");
        let token_manager = <Result<Arc<TokenManager>, AkAxumError>>::from_ref(state)?;
        let token = helpers::get_token(parts, &token_manager)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to get and validate token");
                e
            })?;
        tracing::info!("successfully extracted and validated AuthToken");
        Ok(AuthToken(token))
    }
}

/// A generic JWT extractor for resource server validation.
///
/// Validates a Bearer token against a configured `JwksCache` and `JwtValidation`.
#[cfg(feature = "resource")]
pub struct Jwt<T>(pub T);

#[cfg(feature = "resource")]
impl<S, T> FromRequestParts<S> for Jwt<T>
where
    S: Send + Sync,
    Arc<authkestra_resource::jwt::JwksCache>: FromRef<S>,
    jsonwebtoken::Validation: FromRef<S>,
    T: for<'de> serde::Deserialize<'de> + 'static,
{
    type Rejection = AkAxumError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let cache = Arc::<authkestra_resource::jwt::JwksCache>::from_ref(state);
        let validation = jsonwebtoken::Validation::from_ref(state);

        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| AkAxumError::Unauthorized("Missing Authorization header".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(AkAxumError::Unauthorized(
                "Invalid Authorization header".to_string(),
            ));
        }

        let token = &auth_header[7..];
        let claims =
            authkestra_resource::jwt::validate_jwt_generic::<T>(token, &cache, &validation)
                .await
                .map_err(|e| AkAxumError::Unauthorized(format!("Invalid token: {e}")))?;

        Ok(Jwt(claims))
    }
}

/// A unified extractor for authentication.
///
/// It uses the `AkResourceGuard` from the application state to validate the request.
#[cfg(feature = "resource")]
pub struct Auth<I>(pub I);

#[cfg(feature = "resource")]
impl<S, I> FromRequestParts<S> for Auth<I>
where
    S: Send + Sync,
    Arc<authkestra_resource::AkResourceGuard<I>>: FromRef<S>,
    I: Send + Sync + 'static,
{
    type Rejection = AkAxumError;

    #[tracing::instrument(skip_all)]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        tracing::debug!("extracting generic Auth from request via AkResourceGuard");
        let guard = Arc::<authkestra_resource::AkResourceGuard<I>>::from_ref(state);
        match guard.authenticate(parts).await {
            Ok(Some(identity)) => {
                tracing::info!("successfully authenticated request via AkResourceGuard");
                Ok(Auth(identity))
            }
            Ok(None) => {
                tracing::warn!("authentication failed: no identity returned");
                Err(AkAxumError::Unauthorized(
                    "Authentication failed".to_string(),
                ))
            }
            Err(e) => {
                tracing::error!(error = %e, "internal error during authentication");
                Err(AkAxumError::Internal(e.to_string()))
            }
        }
    }
}

#[cfg(all(feature = "flow", feature = "session"))]
pub trait AkAxumExt<S, T> {
    fn axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        AkBase<S, T>: FromRef<AppState>,
        SessionConfig: FromRef<AppState>,
        Result<Arc<dyn SessionStore>, AkAxumError>: FromRef<AppState>;
}

#[cfg(all(feature = "flow", feature = "session"))]
impl<S: Clone + Send + Sync + 'static, T: Clone + Send + Sync + 'static> AkAxumExt<S, T>
    for AkBase<S, T>
{
    fn axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        AkBase<S, T>: FromRef<AppState>,
        SessionConfig: FromRef<AppState>,
        Result<Arc<dyn SessionStore>, AkAxumError>: FromRef<AppState>,
    {
        use axum::routing::get;
        axum::Router::new()
            .route(
                "/auth/login/{provider}",
                get(helpers::axum_login_handler::<AppState, S, T>),
            )
            .route(
                "/auth/callback/{provider}",
                get(helpers::axum_callback_handler::<AppState, S, T>),
            )
            .route(
                "/auth/logout",
                get(helpers::axum_logout_handler::<AppState, S, T>),
            )
    }
}
