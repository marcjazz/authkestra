use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use authly_actix::{
    handle_oauth_callback, initiate_oauth_login, logout, AuthSession, OAuthCallbackParams,
    SessionConfig,
};
use authly_flow::OAuth2Flow;
use authly_providers_github::GithubProvider;
use authly_session::{SessionStore, SqlStore};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;

struct AppState {
    github_flow: Arc<OAuth2Flow<GithubProvider>>,
    session_store: Arc<dyn SessionStore>,
    session_config: SessionConfig,
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Welcome! Go to /auth/github to login (Session mode).")
}

#[get("/auth/github")]
async fn github_login(data: web::Data<AppState>) -> impl Responder {
    initiate_oauth_login(&data.github_flow, &["user:email"])
}

#[get("/auth/github/callback")]
async fn github_callback(
    req: HttpRequest,
    data: web::Data<AppState>,
    params: web::Query<OAuthCallbackParams>,
) -> actix_web::Result<impl Responder> {
    handle_oauth_callback(
        req,
        &data.github_flow,
        params.into_inner(),
        data.session_store.clone(),
        data.session_config.clone(),
        "/protected",
    )
    .await
}

#[get("/auth/logout")]
async fn github_logout(req: HttpRequest, data: web::Data<AppState>) -> actix_web::Result<impl Responder> {
    logout(
        req,
        data.session_store.clone(),
        data.session_config.clone(),
        "/",
    )
    .await
}

#[get("/protected")]
async fn protected(session: AuthSession) -> impl Responder {
    let name = session.0.identity
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

    let client_id = std::env::var("AUTHLY_GITHUB_CLIENT_ID").expect("AUTHLY_GITHUB_CLIENT_ID must be set");
    let client_secret = std::env::var("AUTHLY_GITHUB_CLIENT_SECRET").expect("AUTHLY_GITHUB_CLIENT_SECRET must be set");
    let redirect_uri = std::env::var("AUTHLY_GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:8080/auth/github/callback".to_string());

    let provider = GithubProvider::new(client_id, client_secret, redirect_uri);
    let github_flow = Arc::new(OAuth2Flow::new(provider));
    
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
    let session_config = SessionConfig::default();

    let app_state = web::Data::new(AppState {
        github_flow,
        session_store: session_store.clone(),
        session_config: session_config.clone(),
    });

    // We also need to register the store and config separately for the extractor
    let store_data: web::Data<Arc<dyn SessionStore>> = web::Data::new(session_store.clone());
    let config_data: web::Data<SessionConfig> = web::Data::new(session_config.clone());

    println!("Starting server on http://localhost:3000");
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .app_data(store_data.clone())
            .app_data(config_data.clone())
            .service(index)
            .service(github_login)
            .service(github_callback)
            .service(github_logout)
            .service(protected)
    })
    .bind(("0.0.0.0", 3000))?
    .run()
    .await
}
