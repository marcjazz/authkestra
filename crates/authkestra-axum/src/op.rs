use crate::AuthEngineAxumError;
use authkestra_engine::TokenManager;
use authkestra_op::{
    client::ClientStore,
    code::AuthorizationCodeStore,
    config::OpConfig,
    device::DeviceCodeStore,
    handlers::{
        authorize::handle_authorize,
        device_authorization::{handle_device_authorization, DeviceAuthorizationRequest},
        discovery::OidcDiscovery,
        jwks::JwksResponse,
        token::{handle_token, TokenRequest},
        userinfo::{handle_userinfo, UserInfoErrorResponse, UserInfoRequest},
    },
    refresh::RefreshTokenStore,
};
use axum::{
    extract::{Form, FromRef, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use std::sync::Arc;

/// Handler for the JWKS endpoint.
pub async fn axum_jwks_handler<AppState>(State(state): State<AppState>) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<TokenManager>, AuthEngineAxumError>: FromRef<AppState>,
{
    let token_manager = match <Result<Arc<TokenManager>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    tracing::debug!("Handling JWKS request");
    (
        StatusCode::OK,
        Json(JwksResponse::new(token_manager.public_jwk())),
    )
        .into_response()
}

/// Handler for the OIDC discovery endpoint.
pub async fn axum_discovery_handler<AppState>(State(state): State<AppState>) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OIDC discovery request");
    let config = OpConfig::from_ref(&state);
    (StatusCode::OK, Json(OidcDiscovery::from_config(&config))).into_response()
}

/// Handler for the authorization endpoint.
/// Note: This is an initial implementation that directly calls `handle_authorize`.
/// In a real scenario, we might also need to extract the logged-in user from the session
/// and handle the consent screen redirect if identity is None.
pub async fn axum_authorize_handler<AppState>(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
    Query(req): Query<authkestra_op::handlers::authorize::AuthorizeRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn ClientStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn crate::SessionStore>, AuthEngineAxumError>: FromRef<AppState>,
    authkestra_engine::SessionConfig: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!(client_id = %req.client_id, "Handling OP authorize request (axum)");
    let clients = match <Result<Arc<dyn ClientStore>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let codes =
        match <Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError>>::from_ref(&state) {
            Ok(c) => c,
            Err(e) => return e.into_response(),
        };
    let config = OpConfig::from_ref(&state);

    let session_store =
        match <Result<Arc<dyn crate::SessionStore>, AuthEngineAxumError>>::from_ref(&state) {
            Ok(c) => c,
            Err(e) => return e.into_response(),
        };
    let session_config = authkestra_engine::SessionConfig::from_ref(&state);

    let session_res = crate::helpers::get_session(&session_store, &session_config, &cookies).await;

    let identity = match session_res {
        Ok(s) => s.identity,
        Err(e) => {
            tracing::info!(error = ?e, "Unauthenticated user on /authorize, redirecting to /login");
            return Redirect::to("/login").into_response();
        }
    };

    match handle_authorize(req, identity, &config, clients.as_ref(), codes.as_ref()).await {
        authkestra_op::handlers::authorize::AuthorizeOutcome::Redirect(url) => {
            Redirect::to(&url).into_response()
        }
        authkestra_op::handlers::authorize::AuthorizeOutcome::DirectError(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": err.to_string()
            })),
        )
            .into_response(),
    }
}

/// Handler for the device authorization endpoint.
pub async fn axum_device_authorization_handler<AppState>(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<DeviceAuthorizationRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn ClientStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn DeviceCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OP device authorization request (axum)");
    let clients = match <Result<Arc<dyn ClientStore>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let devices = match <Result<Arc<dyn DeviceCodeStore>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let config = OpConfig::from_ref(&state);

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match handle_device_authorization(
        req,
        auth_header,
        &config,
        clients.as_ref(),
        devices.as_ref(),
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_client" | "unauthorized_client" => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(err)).into_response()
        }
    }
}

/// Handler for the token endpoint.
pub async fn axum_token_handler<AppState>(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn ClientStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn RefreshTokenStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn DeviceCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<TokenManager>, AuthEngineAxumError>: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!(grant_type = %req.grant_type, "Handling OP token request (axum)");
    let clients = match <Result<Arc<dyn ClientStore>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let codes =
        match <Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError>>::from_ref(&state) {
            Ok(c) => c,
            Err(e) => return e.into_response(),
        };
    let refresh_tokens =
        match <Result<Arc<dyn RefreshTokenStore>, AuthEngineAxumError>>::from_ref(&state) {
            Ok(c) => c,
            Err(e) => return e.into_response(),
        };
    let devices = match <Result<Arc<dyn DeviceCodeStore>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let tokens = match <Result<Arc<TokenManager>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let config = OpConfig::from_ref(&state);

    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match handle_token(
        req,
        auth_header,
        &config,
        clients.as_ref(),
        codes.as_ref(),
        refresh_tokens.as_ref(),
        devices.as_ref(),
        tokens.as_ref(),
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_client" => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(err)).into_response()
        }
    }
}

/// Handler for the userinfo endpoint.
pub async fn axum_userinfo_handler<AppState>(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<TokenManager>, AuthEngineAxumError>: FromRef<AppState>,
    OpConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OP userinfo request (axum)");
    let tokens = match <Result<Arc<TokenManager>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let auth_header = match headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        Some(h) if h.starts_with("Bearer ") => h,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer")],
                Json(UserInfoErrorResponse {
                    error: "invalid_request".to_string(),
                    error_description: "Missing or invalid Authorization header".to_string(),
                }),
            )
                .into_response();
        }
    };

    let req = UserInfoRequest {
        access_token: auth_header[7..].to_string(),
    };

    let config = OpConfig::from_ref(&state);

    match handle_userinfo(req, &config, tokens.as_ref()).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            let status = match err.error.as_str() {
                "invalid_token" => StatusCode::UNAUTHORIZED,
                "insufficient_scope" => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(err)).into_response()
        }
    }
}

/// Handler for the device verify endpoint.
pub async fn axum_device_verify_handler<AppState>(
    State(state): State<AppState>,
    cookies: tower_cookies::Cookies,
    Form(req): Form<authkestra_op::handlers::device_verify::DeviceVerifyRequest>,
) -> Response
where
    AppState: Clone + Send + Sync + 'static,
    Result<Arc<dyn DeviceCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
    Result<Arc<dyn crate::SessionStore>, AuthEngineAxumError>: FromRef<AppState>,
    authkestra_engine::SessionConfig: FromRef<AppState>,
{
    tracing::debug!("Handling OP device verify request (axum)");
    let devices = match <Result<Arc<dyn DeviceCodeStore>, AuthEngineAxumError>>::from_ref(&state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let session_store =
        match <Result<Arc<dyn crate::SessionStore>, AuthEngineAxumError>>::from_ref(&state) {
            Ok(c) => c,
            Err(e) => return e.into_response(),
        };
    let session_config = authkestra_engine::SessionConfig::from_ref(&state);

    let session_res = crate::helpers::get_session(&session_store, &session_config, &cookies).await;

    let identity = match session_res {
        Ok(s) => s.identity,
        Err(e) => {
            tracing::info!(error = ?e, "Unauthenticated user on /device/verify, redirecting to /login");
            return Redirect::to("/login").into_response();
        }
    };

    match authkestra_op::handlers::device_verify::handle_device_verify(req, identity, devices.as_ref()).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": err.to_string()
            })),
        )
            .into_response(),
    }
}

pub trait AuthEngineAxumOpExt {
    fn op_axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Result<Arc<dyn ClientStore>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<dyn RefreshTokenStore>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<dyn DeviceCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<TokenManager>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<dyn crate::SessionStore>, AuthEngineAxumError>: FromRef<AppState>,
        authkestra_engine::SessionConfig: FromRef<AppState>,
        OpConfig: FromRef<AppState>;
}

// Implement for any type to allow standalone usage or usage with AuthEngine.
impl<T> AuthEngineAxumOpExt for T {
    fn op_axum_router<AppState>(&self) -> axum::Router<AppState>
    where
        AppState: Clone + Send + Sync + 'static,
        Result<Arc<dyn ClientStore>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<dyn AuthorizationCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<dyn RefreshTokenStore>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<dyn DeviceCodeStore>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<TokenManager>, AuthEngineAxumError>: FromRef<AppState>,
        Result<Arc<dyn crate::SessionStore>, AuthEngineAxumError>: FromRef<AppState>,
        authkestra_engine::SessionConfig: FromRef<AppState>,
        OpConfig: FromRef<AppState>,
    {
        use axum::routing::{get, post};
        axum::Router::new()
            .route("/jwks.json", get(axum_jwks_handler::<AppState>))
            .route(
                "/.well-known/openid-configuration",
                get(axum_discovery_handler::<AppState>),
            )
            .route("/authorize", get(axum_authorize_handler::<AppState>))
            .route(
                "/device_authorization",
                post(axum_device_authorization_handler::<AppState>),
            )
            .route("/token", post(axum_token_handler::<AppState>))
            .route(
                "/userinfo",
                get(axum_userinfo_handler::<AppState>).post(axum_userinfo_handler::<AppState>),
            )
            .route("/device/verify", post(axum_device_verify_handler::<AppState>))
    }
}
