//! # Actix Google OIDC Example
//!
//! This example demonstrates how to set up Engine with Actix for Google OIDC login.
//!
//! To run this example, you'll need:
//! - `AUTHKESTRA_GOOGLE_CLIENT_ID`
//! - `AUTHKESTRA_GOOGLE_CLIENT_SECRET`

use actix_files::Files;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra::flow::{Engine, OAuth2Flow};
use authkestra_actix::{ActixExt, ActixState, AuthSession};
use authkestra_engine::auth::SessionStore;
use authkestra_engine::{AkWebAppEngine, SessionConfig};
use authkestra_providers::google::GoogleProvider;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone, ActixState)]
struct AppState {
    #[authkestra(engine)]
    auth: AkWebAppEngine,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // =========================================================================
    // Initialize tracing subscriber for logging
    // =========================================================================
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,authkestra=debug".into()),
        )
        .init();

    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHKESTRA_GOOGLE_CLIENT_ID")
        .expect("AUTHKESTRA_GOOGLE_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GOOGLE_CLIENT_SECRET")
        .expect("AUTHKESTRA_GOOGLE_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GOOGLE_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());

    let mut google_provider = GoogleProvider::new(client_id, client_secret, redirect_uri);
    // Support E2E tests pointing to a local mock server
    if let Ok(base_url) = std::env::var("AUTHKESTRA_GOOGLE_BASE_URL") {
        let api_url =
            std::env::var("AUTHKESTRA_GOOGLE_API_URL").unwrap_or_else(|_| base_url.clone());
        google_provider = google_provider.with_test_urls(
            format!("{base_url}/login/oauth/authorize"),
            format!("{base_url}/login/oauth/access_token"),
            format!("{api_url}/user"),
        );
    }

    // Session Store
    // TIP: authkestra uses traits (like `SessionStore`) for storage.
    // This makes it easy to swap out backends! You could easily replace `MemoryStore`
    // with `SqlKvStore` or `RedisStore` simply by changing the struct instantiated here.
    let session_store: Arc<dyn SessionStore> =
        Arc::new(authkestra_engine::store::memory::MemoryStore::default());

    let auth_engine = Engine::builder()
        .provider(OAuth2Flow::new(google_provider))
        .session_store(session_store)
        .session_config(SessionConfig {
            secure: false,
            ..Default::default()
        })
        .build();

    let state = AppState {
        auth: auth_engine.clone(),
    };

    println!("🚀 Actix Google OIDC running on http://localhost:3000");

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
