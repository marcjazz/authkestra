//! # Axum Stateless OAuth Example
//!
//! This example demonstrates how to set up Engine for OAuth2 in stateless mode,
//! where the callback returns a JWT instead of creating a server-side session.
//!
//! To run this example, you'll need:
//! - `AUTHKESTRA_GITHUB_CLIENT_ID`
//! - `AUTHKESTRA_GITHUB_CLIENT_SECRET`

use authkestra::flow::{Engine, OAuth2Flow};
use authkestra_axum::{helpers, AuthToken, AxumError, AxumState};
use authkestra_engine::{token::TokenManager, AkApiEngine, Configured, Missing};
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

/// Engine state with support for tokens (stateless mode).
#[derive(Clone, AxumState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkApiEngine,
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

    // Support E2E tests pointing to a local mock server
    let github_provider = match std::env::var("AUTHKESTRA_GITHUB_BASE_URL") {
        Ok(base_url) => {
            let api_url =
                std::env::var("AUTHKESTRA_GITHUB_API_URL").unwrap_or_else(|_| base_url.clone());
            GithubProvider::new(client_id, client_secret, redirect_uri).with_test_urls(
                format!("{base_url}/login/oauth/authorize"),
                format!("{base_url}/login/oauth/access_token"),
                format!("{api_url}/user"),
            )
        }
        Err(_) => GithubProvider::new(client_id, client_secret, redirect_uri),
    };

    // Initialize Authkestra in stateless mode (JWT only).
    let auth_engine = Engine::builder()
        .provider(OAuth2Flow::new(github_provider))
        .jwt_secret(b"your-256-bit-secret-key-at-least-32-bytes-long")
        .build();

    let state = AppState { auth: auth_engine };

    let app = Router::new()
        .route("/api/user", get(get_user))
        // Login route
        .route("/auth/{provider}", get(login_handler))
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

/// Custom login handler using Engine helpers.
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
) -> Result<impl IntoResponse, AxumError> {
    let token_manager = <Result<Arc<TokenManager>, AxumError>>::from_ref(&state)?;

    let flow = state
        .auth
        .providers
        .get(&provider)
        .ok_or_else(|| AxumError::Internal(format!("Provider {} not found", provider)))?;

    // We use the JWT-specific callback helper
    helpers::handle_oauth_callback_jwt_erased(
        flow.as_ref(),
        cookies,
        params,
        token_manager,
        3600, // 1 hour
        state.auth.session_config.clone(),
    )
    .await
    .map_err(|(status, msg)| {
        if status == StatusCode::UNAUTHORIZED {
            AxumError::Unauthorized(msg)
        } else {
            AxumError::Internal(msg)
        }
    })
}

/// Protected endpoint using `AuthToken` extractor.
async fn get_user(auth: Result<AuthToken, AxumError>) -> impl IntoResponse {
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
