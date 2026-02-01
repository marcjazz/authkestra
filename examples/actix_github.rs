use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authly_actix::{AuthSession, AuthlyActixExt};
use authly_core::{SessionConfig, SessionStore};
use authly_flow::{Authly, OAuth2Flow};
use authly_providers_github::GithubProvider;
use authly_session::SqlStore;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;

struct AppState {
    authly: Authly,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Welcome! Go to /auth/github to login (Session mode).")
}

#[get("/protected")]
async fn protected(session: AuthSession) -> impl Responder {
    let name = session
        .0
        .identity
        .username
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());

    HttpResponse::Ok().body(format!(
        "Hello, {}! Your ID is {}. You are authenticated via the new AuthSession extractor.",
        name, session.0.identity.external_id
    ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let client_id =
        std::env::var("AUTHLY_GITHUB_CLIENT_ID").expect("AUTHLY_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHLY_GITHUB_CLIENT_SECRET")
        .expect("AUTHLY_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHLY_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:8080/auth/github/callback".to_string());

    let provider = GithubProvider::new(client_id, client_secret, redirect_uri);

    // For this example, we'll use SQLite for session persistence.
    let db_url = "sqlite::memory:";
    let pool = SqlitePool::connect(db_url)
        .await
        .expect("Failed to connect to SQLite");

    // Initialize the sessions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS authly_sessions (
            id VARCHAR(128) PRIMARY KEY,
            provider_id VARCHAR(255) NOT NULL,
            external_id VARCHAR(255) NOT NULL,
            email VARCHAR(255),
            name VARCHAR(255),
            claims TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create sessions table");

    let session_store: Arc<dyn SessionStore> = Arc::new(SqlStore::new(pool));

    let authly = Authly::builder()
        .provider(OAuth2Flow::new(provider))
        .session_store(session_store.clone())
        .build();

    let app_state = web::Data::new(AppState { authly });

    // We also need to register the store and config separately for the extractor
    let store_data: web::Data<Arc<dyn SessionStore>> = web::Data::new(session_store.clone());
    let config_data: web::Data<SessionConfig> = web::Data::new(SessionConfig::default());
    let authly_data = web::Data::new(app_state.authly.clone());

    println!("Starting server on http://localhost:3000");
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(store_data.clone())
            .app_data(config_data.clone())
            .app_data(authly_data.clone())
            .service(index)
            .service(app_state.authly.actix_scope())
            .service(protected)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
