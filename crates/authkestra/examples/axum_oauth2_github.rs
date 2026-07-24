//! # Axum GitHub OAuth2 Example
//!
//! This example demonstrates how to set up Engine with Axum for GitHub OAuth2 login.
//!
//! To run this example, you'll need:
//! - `AUTHKESTRA_GITHUB_CLIENT_ID`
//! - `AUTHKESTRA_GITHUB_CLIENT_SECRET`

use authkestra::flow::{Engine, OAuth2Flow};
use authkestra_axum::{AxumError, AxumExt, AxumState, AuthSession};
use authkestra_engine::auth::SessionStore;
use authkestra_engine::{Configured, SessionConfig};
use authkestra_providers::github::GithubProvider;
use axum::{
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

/// Engine state with support for session only.
type AppState = AxumState<Configured<Arc<dyn SessionStore>>>;

#[tokio::main]
async fn main() {
    // =========================================================================
    // Initialize tracing subscriber for logging
    // =========================================================================
    // This allows the user to capture logs emitted by Authkestra via `tracing`.
    // You can customize the log level by setting the `RUST_LOG` environment
    // variable (e.g., `RUST_LOG=debug`, `RUST_LOG=authkestra=info,my_app=debug`).
    // `tracing_subscriber::fmt::init()` installs a global default subscriber
    // that formats logs to standard output.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra=debug".into()),
        )
        .init();

    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());

    let github_provider = GithubProvider::new(client_id, client_secret, redirect_uri);

    // Session Store
    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::default());

    let auth_engine = Engine::builder()
        .provider(OAuth2Flow::new(github_provider))
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build();

    let state = AppState {
        authkestra: auth_engine.clone(),
    };

    let app = Router::new()
        .fallback_service(ServeDir::new("authkestra-examples/static"))
        .route("/api/user", get(get_user))
        .merge(auth_engine.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Axum GitHub OAuth2 running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn get_user(session: Result<AuthSession, AxumError>) -> impl IntoResponse {
    match session {
        Ok(AuthSession(session)) => Json(json!({
            "id": session.identity.external_id,
            "username": session.identity.username,
            "email": session.identity.email,
            "provider": session.identity.provider_id,
        })),
        Err(_) => Json(json!({ "error": "Not authenticated" })),
    }
}
