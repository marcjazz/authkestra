//! # Axum Google OIDC Example
//!
//! This example demonstrates how to set up AuthEngine with Axum for Google OIDC login.
//!
//! To run this example, you'll need:
//! - `AUTHKESTRA_GOOGLE_CLIENT_ID`
//! - `AUTHKESTRA_GOOGLE_CLIENT_SECRET`

use authkestra::flow::{AuthEngine, OAuth2Flow};
use authkestra_axum::{AuthSession, AuthkestraAxumError, AuthkestraAxumExt, AuthkestraState};
use authkestra_engine::{Configured, SessionConfig};
use authkestra_providers::google::GoogleProvider;
use authkestra_session::SessionStore;
use axum::{
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::services::ServeDir;

/// AuthEngine state with support for session only.
type AppState = AuthkestraState<Configured<Arc<dyn SessionStore>>>;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHKESTRA_GOOGLE_CLIENT_ID")
        .expect("AUTHKESTRA_GOOGLE_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GOOGLE_CLIENT_SECRET")
        .expect("AUTHKESTRA_GOOGLE_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GOOGLE_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());

    let google_provider = GoogleProvider::new(client_id, client_secret, redirect_uri);

    // Session Store
    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra_session::memory::MemoryStore::default());

    let auth_engine = AuthEngine::builder()
        .provider(OAuth2Flow::new(google_provider))
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
    println!("🚀 Axum Google OIDC running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn get_user(session: Result<AuthSession, AuthkestraAxumError>) -> impl IntoResponse {
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
