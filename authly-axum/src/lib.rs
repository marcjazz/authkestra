pub use authly_core::{Session, SessionConfig, SessionStore};
pub use authly_flow::Authly;
use authly_token::TokenManager;
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
pub struct AuthlyState {
    pub authly: Authly,
}

impl From<Authly> for AuthlyState {
    fn from(authly: Authly) -> Self {
        Self { authly }
    }
}

impl FromRef<AuthlyState> for Authly {
    fn from_ref(state: &AuthlyState) -> Self {
        state.authly.clone()
    }
}

impl FromRef<AuthlyState> for Arc<dyn SessionStore> {
    fn from_ref(state: &AuthlyState) -> Self {
        state.authly.session_store.clone()
    }
}

impl FromRef<AuthlyState> for SessionConfig {
    fn from_ref(state: &AuthlyState) -> Self {
        state.authly.session_config.clone()
    }
}

impl FromRef<AuthlyState> for Arc<TokenManager> {
    fn from_ref(state: &AuthlyState) -> Self {
        state.authly.token_manager.clone()
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
    type Rejection = AuthlyAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session_store = Arc::<dyn SessionStore>::from_ref(state);
        let session_config = SessionConfig::from_ref(state);
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|e| AuthlyAxumError::Internal(e.1.to_string()))?;

        let session = helpers::get_session(&session_store, &session_config, &cookies).await?;

        Ok(AuthSession(session))
    }
}

/// The extractor for a validated JWT.
///
/// Expects an `Authorization: Bearer <token>` header.
pub struct AuthToken(pub authly_token::Claims);

impl<S> FromRequestParts<S> for AuthToken
where
    S: Send + Sync,
    Arc<TokenManager>: FromRef<S>,
{
    type Rejection = AuthlyAxumError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token_manager = Arc::<TokenManager>::from_ref(state);
        let token = helpers::get_token(parts, &token_manager).await?;
        Ok(AuthToken(token))
    }
}

pub trait AuthlyAxumExt {
    fn axum_router<S>(&self) -> axum::Router<S>
    where
        S: Clone + Send + Sync + 'static,
        Authly: FromRef<S>,
        SessionConfig: FromRef<S>,
        Arc<dyn SessionStore>: FromRef<S>;
}

impl AuthlyAxumExt for Authly {
    fn axum_router<S>(&self) -> axum::Router<S>
    where
        S: Clone + Send + Sync + 'static,
        Authly: FromRef<S>,
        SessionConfig: FromRef<S>,
        Arc<dyn SessionStore>: FromRef<S>,
    {
        use axum::routing::get;
        axum::Router::new()
            .route("/auth/:provider", get(helpers::axum_login_handler::<S>))
            .route(
                "/auth/:provider/callback",
                get(helpers::axum_callback_handler::<S>),
            )
            .route("/auth/logout", get(helpers::axum_logout_handler::<S>))
    }
}
