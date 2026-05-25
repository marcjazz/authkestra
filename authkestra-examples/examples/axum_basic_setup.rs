//! # Axum Basic Setup Example
//!
//! This example demonstrates the most basic setup of AuthEngine with Axum.
//! It uses an in-memory session store and a mock authentication provider.

use authkestra::flow::AuthEngine;
use authkestra_axum::{AuthSession, AuthkestraAxumError, AuthkestraAxumExt, AuthkestraState};
use authkestra_engine::{
    auth::{
        error::AuthError,
        state::{Identity, OAuthToken},
        ErasedOAuthFlow,
    },
    Configured, SessionConfig,
};
use authkestra_session::SessionStore;
use async_trait::async_trait;
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

/// A mock authentication flow for testing.
struct MockFlow;

#[async_trait]
impl ErasedOAuthFlow for MockFlow {
    fn provider_id(&self) -> String {
        "mock".to_string()
    }

    fn initiate_login(&self, _scopes: &[&str], _pkce_challenge: Option<&str>) -> (String, String) {
        // In a real OAuth flow, this would redirect to the provider.
        // For the mock, we redirect back to the callback immediately.
        ("/auth/callback/mock?code=mock_code&state=mock_state".to_string(), "mock_state".to_string())
    }

    async fn finalize_login(
        &self,
        _code: &str,
        _received_state: &str,
        _expected_state: &str,
        _pkce_verifier: Option<&str>,
    ) -> Result<(Identity, OAuthToken), AuthError> {
        Ok((
            Identity {
                external_id: "mock_user_123".to_string(),
                username: Some("mock_user".to_string()),
                email: Some("mock@example.com".to_string()),
                provider_id: "mock".to_string(),
                attributes: Default::default(),
            },
            OAuthToken {
                access_token: "mock_access_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: Some(3600),
                refresh_token: None,
                scope: None,
                id_token: None,
            },
        ))
    }
}

/// AuthEngine state with support for session only.
type AppState = AuthkestraState<Configured<Arc<dyn SessionStore>>>;

#[tokio::main]
async fn main() {
    // Session Store
    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra_session_memory::MemoryStore::default());

    let auth_engine = AuthEngine::builder()
        .provider(MockFlow)
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
