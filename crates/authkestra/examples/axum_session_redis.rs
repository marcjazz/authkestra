//! # Axum Redis Session Example
//!
//! This example demonstrates how to use Redis as a session store with Axum.
//!
//! To run this example, you'll need:
//! - A running Redis instance
//! - `REDIS_URL` environment variable (e.g., `redis://127.0.0.1/`)

use authkestra::flow::Engine;
use authkestra_axum::{AxumError, AxumExt, AxumState, AuthSession};
use authkestra_engine::auth::SessionStore;
use authkestra_engine::store::redis::RedisStore;
use authkestra_engine::{Configured, SessionConfig};
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
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");

    // Redis Session Store
    let session_store: Arc<dyn SessionStore> = Arc::new(
        RedisStore::new(&redis_url, "authkestra_example".into())
            .expect("Failed to connect to Redis"),
    );

    let auth_engine = Engine::builder()
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
