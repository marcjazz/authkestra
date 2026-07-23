//! # Axum Basic Setup Example
//!
//! This example demonstrates the most basic setup of AkBase with Axum.
//! It uses an in-memory session store and a mock authentication provider.

use authkestra::flow::AkBase;
use authkestra_axum::{AuthSession, AkAxumError, AkAxumExt, AkState};
use authkestra_engine::auth::SessionStore;
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

/// AkBase state with support for session only.
type AppState = AkState<Configured<Arc<dyn SessionStore>>>;

#[tokio::main]
async fn main() {
    // Session Store
    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::default());

    let auth_engine = AkBase::builder()
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // For local development
            ..Default::default()
        })
        .build();

    let state = AppState {
        authkestra: auth_engine.clone(),
    };

    let app = Router::new()
        // Serve static files from the 'static' directory
        .fallback_service(ServeDir::new("authkestra-examples/static"))
        // API for checking current user status
        .route("/api/user", get(get_user))
        .merge(auth_engine.axum_router())
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Axum Basic Setup running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}

/// API endpoint to get current user info from session
async fn get_user(session: Result<AuthSession, AkAxumError>) -> impl IntoResponse {
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
