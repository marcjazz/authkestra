//! # Actix Basic Setup Example
//!
//! This example demonstrates the most basic setup of AuthEngine with Actix.
//! It uses an in-memory session store.

use actix_files::Files;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra::flow::AuthEngine;
use authkestra_actix::{AuthSession, AuthkestraActixExt};
use authkestra_engine::SessionConfig;
use authkestra_engine::auth::SessionStore;
use serde_json::json;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Session Store
    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::default());

    let auth_engine = AuthEngine::builder()
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
