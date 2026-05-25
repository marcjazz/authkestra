use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use authkestra_actix::{AuthEngineActixExt, AuthSession};
use authkestra_engine::{AuthEngine, Missing, OAuth2Flow};
use authkestra_providers_github::GithubProvider;
use authkestra_session::SqlStore;
use authkestra_session::{SessionConfig, SessionStore};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;

#[allow(dead_code)]
struct AppState<S = Missing, T = Missing> {
    auth_engine: AuthEngine<S, T>, // can be staleless or statefull
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Welcome! Go to /auth/github to login (Session mode).")
}

#[get("/protected")]
async fn protected(AuthSession(session): AuthSession) -> impl Responder {
    let name = session
        .identity
        .username
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());

    HttpResponse::Ok().body(format!(
        "Hello, {}! Your ID is {}. You are authenticated via the new AuthSession extractor.",
        name, session.identity.external_id
    ))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let client_id = std::env::var("AUTHKESTRA_GITHUB_CLIENT_ID")
        .expect("AUTHKESTRA_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHKESTRA_GITHUB_CLIENT_SECRET")
        .expect("AUTHKESTRA_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHKESTRA_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:3000/auth/github/callback".to_string());

    let provider = GithubProvider::new(client_id, client_secret, redirect_uri);

    // For this example, we'll use SQLite for session persistence.
    let db_url = "sqlite::memory:";
    let pool = SqlitePool::connect(db_url)
        .await
        .expect("Failed to connect to SQLite");

    // Initialize the sessions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS authkestra_sessions (
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

    let authkestra = AuthEngine::builder()
        .provider(OAuth2Flow::new(provider))
        .session_store(session_store.clone())
        .build();

    let app_state = web::Data::new(AppState {
        auth_engine: authkestra.clone(),
    });

    println!("Starting server on http://localhost:3000");
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(web::Data::new(authkestra.clone()))
            .app_data(web::Data::new(session_store.clone()))
            .app_data(web::Data::new(SessionConfig::default()))
            .service(index)
            .service(authkestra.actix_scope())
            .service(protected)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
