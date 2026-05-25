//! # Actix Basic Setup Example
//!
//! This example demonstrates the most basic setup of AuthEngine with Actix.
//! It uses an in-memory session store.

use actix_files::Files;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra::flow::AuthEngine;
use authkestra_actix::{AuthSession, AuthkestraActixExt};
use authkestra_engine::{
    auth::{
        error::AuthError,
        state::{Identity, OAuthToken},
        ErasedOAuthFlow,
    },
    SessionConfig,
};
use authkestra_session::SessionStore;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

/// A mock authentication flow for testing.
struct MockFlow;

#[async_trait]
impl ErasedOAuthFlow for MockFlow {
    fn provider_id(&self) -> String {
        "mock".to_string()
    }

    fn initiate_login(&self, _scopes: &[&str], _pkce_challenge: Option<&str>) -> (String, String) {
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
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

    println!("🚀 Actix Basic Setup running on http://localhost:3000");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(auth_engine.clone()))
            .service(get_user)
            .service(auth_engine.actix_scope())
            .service(Files::new("/", "authkestra-examples/static").index_file("index.html"))
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}

/// API endpoint to get current user info from session
#[get("/api/user")]
async fn get_user(session: Option<AuthSession>) -> impl Responder {
    match session {
        Some(AuthSession(session)) => HttpResponse::Ok().json(json!({
            "id": session.identity.external_id,
            "username": session.identity.username,
            "email": session.identity.email,
            "provider": session.identity.provider_id,
        })),
        None => HttpResponse::Unauthorized().json(json!({ "error": "Not authenticated" })),
    }
}
