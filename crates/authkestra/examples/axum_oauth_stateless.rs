//! # Axum Stateless OAuth Example
//!
//! This example demonstrates how to set up AkBase for OAuth2 in stateless mode,
//! where the callback returns a JWT instead of creating a server-side session.
//!
//! To run this example, you'll need:
//! - `AUTHKESTRA_GITHUB_CLIENT_ID`
//! - `AUTHKESTRA_GITHUB_CLIENT_SECRET`

use authkestra::flow::{AkBase, OAuth2Flow};
use authkestra_axum::{helpers, AuthToken, AkAxumError};
use authkestra_engine::{token::TokenManager, Configured, Missing};
use authkestra_providers::github::GithubProvider;
use axum::{
    extract::{FromRef, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_cookies::Cookies;

/// AkBase state with support for tokens (stateless mode).
#[derive(Clone)]
struct AppState {
    authkestra: AkBase<Missing, Configured<Arc<TokenManager>>>,
}

/// Required for the `AuthToken` extractor and internal helpers.
impl FromRef<AppState> for Result<Arc<TokenManager>, AkAxumError> {
    fn from_ref(state: &AppState) -> Self {
        Ok(state.authkestra.token_manager.0.clone())
    }
}

/// Required for the `AkBase` to be used in generic handlers.
impl FromRef<AppState> for AkBase<Missing, Configured<Arc<TokenManager>>> {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra.clone()
    }
}

/// Required for encrypted state handling.
impl FromRef<AppState> for authkestra_axum::SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.authkestra.session_config.clone()
    }
}

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/callback/github".to_string());

    let github_provider = GithubProvider::new(client_id, client_secret, redirect_uri);

    // Initialize Authkestra in stateless mode (JWT only).
    let auth_engine = AkBase::builder()
        .provider(OAuth2Flow::new(github_provider))
        .jwt_secret(b"your-256-bit-secret-key-at-least-32-bytes-long")
        .build();

    let state = AppState {
        authkestra: auth_engine,
    };

    let app = Router::new()
        .route("/api/user", get(get_user))
        // Login route
        .route("/auth/:provider", get(login_handler))
        // Callback route (stateless)
        .route("/auth/callback/{provider}", get(callback_handler))
        .layer(tower_cookies::CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Axum Stateless OAuth running on http://localhost:3000");
    println!("1. Login: http://localhost:3000/auth/github");
    println!("2. The callback will return a JSON with a JWT.");
    println!("3. Use the JWT in the 'Authorization: Bearer <token>' header for /api/user");
    axum::serve(listener, app).await.unwrap();
}

/// Custom login handler using AkBase helpers.
async fn login_handler(
    Path(provider): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<helpers::OAuthLoginParams>,
    cookies: Cookies,
) -> impl IntoResponse {
    helpers::axum_login_handler::<AppState, Missing, Configured<Arc<TokenManager>>>(
        Path(provider),
        State(state),
        Query(params),
        cookies,
    )
    .await
}

/// Custom callback handler for stateless mode (returns JWT).
async fn callback_handler(
    Path(provider): Path<String>,
    State(state): State<AppState>,
    Query(params): Query<helpers::OAuthCallbackParams>,
    cookies: Cookies,
) -> Result<impl IntoResponse, AkAxumError> {
    let token_manager = <Result<Arc<TokenManager>, AkAxumError>>::from_ref(&state)?;

    let flow =
        state.authkestra.providers.get(&provider).ok_or_else(|| {
            AkAxumError::Internal(format!("Provider {} not found", provider))
        })?;

    // We use the JWT-specific callback helper
    helpers::handle_oauth_callback_jwt_erased(
        flow.as_ref(),
        cookies,
        params,
        token_manager,
        3600, // 1 hour
        state.authkestra.session_config.clone(),
    )
    .await
    .map_err(|(status, msg)| {
        if status == StatusCode::UNAUTHORIZED {
            AkAxumError::Unauthorized(msg)
        } else {
            AkAxumError::Internal(msg)
        }
    })
}

/// Protected endpoint using `AuthToken` extractor.
async fn get_user(auth: Result<AuthToken, AkAxumError>) -> impl IntoResponse {
    match auth {
        Ok(AuthToken(claims)) => {
            let identity = claims.identity.as_ref().unwrap();
            (
                StatusCode::OK,
                Json(json!({
                    "id": identity.external_id,
                    "username": identity.username,
                    "email": identity.email,
                    "provider": identity.provider_id,
                })),
            )
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Not authenticated" })),
        ),
    }
}
