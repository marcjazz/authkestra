use axum::{extract::{State, Query, FromRef}, response::{IntoResponse, Response, Redirect}};
use authkestra_op::config::OpConfig;
use authkestra_op::client::ClientStore;
use authkestra_op::code::AuthorizationCodeStore;
use authkestra_engine::TokenManager;
use authkestra_axum::AuthEngineAxumError;
use std::sync::Arc;

pub async fn handler<AppState>(
    State(_state): State<AppState>,
    _cookies: tower_cookies::Cookies,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn ClientStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<TokenManager>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn authkestra_axum::SessionStore>, AuthEngineAxumError>: FromRef<AppState>,
    authkestra_engine::SessionConfig: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    (axum::http::StatusCode::OK, "test").into_response()
}

pub fn router<AppState>() -> axum::Router<AppState>
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn ClientStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<TokenManager>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn authkestra_axum::SessionStore>, AuthEngineAxumError>: FromRef<AppState>,
    authkestra_engine::SessionConfig: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    axum::Router::new().route("/authorize", axum::routing::get(handler::<AppState>))
}
