//! # Axum Redis Session Example
//!
//! This example demonstrates how to use Redis as a session store with Axum.
//!
//! To run this example, you'll need:
//! - A running Redis instance
//! - `REDIS_URL` environment variable (e.g., `redis://127.0.0.1/`)

use authkestra::flow::AuthEngine;
use authkestra_axum::{AuthSession, AuthkestraAxumError, AuthkestraAxumExt, AuthkestraState};
use authkestra_engine::{Configured, SessionConfig};
use authkestra_session::SessionStore;
use authkestra_session_redis::RedisStore;
use axum::{
    http::StatusCode,
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

    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");

    // Redis Session Store
    let session_store: Arc<dyn SessionStore> = Arc::new(
        RedisStore::new(&redis_url, "authkestra_example".into())
            .expect("Failed to connect to Redis"),
    );

    let auth_engine = AuthEngine::builder()
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
    println!("🚀 Axum Redis Session Example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn get_user(session: Result<AuthSession, AuthkestraAxumError>) -> impl IntoResponse {
    match session {
        Ok(AuthSession(session)) => (
            StatusCode::OK,
            Json(json!({
                "id": session.identity.external_id,
                "username": session.identity.username,
                "email": session.identity.email,
                "provider": session.identity.provider_id,
            })),
        ),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Not authenticated" })),
        ),
    }
}
