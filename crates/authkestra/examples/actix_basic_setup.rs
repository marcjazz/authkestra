//! # Actix Basic Setup Example
//!
//! This example demonstrates the most basic setup of Engine with Actix.
//! It uses an in-memory session store.

use actix_files::Files;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra::flow::Engine;
use authkestra_actix::{ActixExt, AuthSession, State};
use authkestra_engine::auth::SessionStore;
use authkestra_engine::{Configured, Missing, SessionConfig};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone, State)]
struct AppState {
    #[authkestra(engine)]
    auth: Engine<Configured<Arc<dyn SessionStore>>, Missing>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Session Store
    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::default());

    let auth_engine = Engine::builder()
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false, // For local development
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: auth_engine.clone(),
    };

    println!("🚀 Actix Basic Setup running on http://localhost:3000");

    HttpServer::new(move || {
        let app_state = state.clone();
        let config_state = app_state.clone();
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .configure(move |cfg| config_state.configure_authkestra(cfg))
            .service(get_user)
            .service(app_state.auth.actix_scope())
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
