//! # Actix GitHub OAuth2 Example
//!
//! This example demonstrates how to set up Engine with Actix for GitHub OAuth2 login.
//!
//! To run this example, you'll need:
//! - `AUTHKESTRA_GITHUB_CLIENT_ID`
//! - `AUTHKESTRA_GITHUB_CLIENT_SECRET`

use actix_files::Files;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra::flow::{Engine, OAuth2Flow};
use authkestra_actix::{ActixExt, ActixState, AuthSession};
use authkestra_engine::auth::SessionStore;
use authkestra_engine::{AkWebAppEngine, SessionConfig};
use authkestra_providers::github::GithubProvider;
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

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());

    let github_provider = GithubProvider::new(client_id, client_secret, redirect_uri);

    // Session Store
    // TIP: authkestra uses traits (like `SessionStore`) for storage.
    // This makes it easy to swap out backends! You could easily replace `MemoryStore`
    // with `SqlKvStore` or `RedisStore` simply by changing the struct instantiated here.
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
        auth: auth_engine.clone(),
    };

    println!("🚀 Actix GitHub OAuth2 running on http://localhost:3000");

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
